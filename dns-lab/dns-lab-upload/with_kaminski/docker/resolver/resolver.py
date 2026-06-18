#!/usr/bin/env python3
import random
import select
import socket
import time
from dnslib import A, DNSHeader, DNSRecord, QTYPE, RR

LISTEN_IP = "0.0.0.0"
CLIENT_PORT = 53
UPSTREAM_IP = "10.19.0.153"
UPSTREAM_PORT = 53
UPSTREAM_SRC_PORT = 33333
TXID_MIN = 10000
TXID_MAX = 10005
PENDING_TIMEOUT = 2.0
UPSTREAM_REPLY_DELAY = 0.08

cache = {}
pending = {}


def now():
    return time.time()


def normalize_name(name):
    return str(name).rstrip(".").lower()


def pick_txid():
    for _ in range((TXID_MAX - TXID_MIN) + 1):
        txid = random.randint(TXID_MIN, TXID_MAX)
        if txid not in pending:
            return txid
    return None


def add_cache_record(rr):
    if rr.rtype != QTYPE.A:
        return
    qname = normalize_name(rr.rname)
    ttl = 60 # hardcoded 60 seconds, otherwiseint(rr.ttl)
    if ttl <= 0:
        return
    cache[(qname, QTYPE.A)] = (str(rr.rdata), now() + ttl)


def add_cache_records_from_section(section):
    for rr in section:
        add_cache_record(rr)


def lookup_cache(qname, qtype):
    key = (normalize_name(qname), qtype)
    entry = cache.get(key)
    if not entry:
        return None
    ip, expires = entry
    if now() >= expires:
        del cache[key]
        return None
    return ip, max(1, int(expires - now()))


def prune_pending():
    t = now()
    stale = [txid for txid, (_, _, _, _, ts) in pending.items() if t - ts > PENDING_TIMEOUT]
    for txid in stale:
        del pending[txid]


def build_cached_response(req, ip, ttl):
    reply = DNSRecord(
        DNSHeader(id=req.header.id, qr=1, aa=0, ra=1, rd=req.header.rd),
        q=req.q,
    )
    reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.A, rclass=1, ttl=ttl, rdata=A(ip)))
    return reply.pack()


def main():
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.bind((LISTEN_IP, CLIENT_PORT))

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.bind((LISTEN_IP, UPSTREAM_SRC_PORT))

    print("[*] Vulnerable resolver started")
    print(f"[*] Listening on udp/{CLIENT_PORT}, upstream source port fixed to {UPSTREAM_SRC_PORT}")
    print(f"[*] TXID range limited to [{TXID_MIN}, {TXID_MAX}]")

    while True:
        prune_pending()
        readable, _, _ = select.select([client_sock, upstream_sock], [], [], 0.25)

        for sock in readable:
            data, addr = sock.recvfrom(4096)

            if sock is client_sock:
                try:
                    req = DNSRecord.parse(data)
                except Exception:
                    continue

                if req.header.q == 0:
                    continue

                q = req.questions[0]
                qname = q.qname
                qtype = q.qtype

                cached = lookup_cache(qname, qtype)
                if cached:
                    ip, ttl = cached
                    client_sock.sendto(build_cached_response(req, ip, ttl), addr)
                    continue

                txid = pick_txid()
                if txid is None:
                    continue

                forwarded = DNSRecord(DNSHeader(id=txid, qr=0, rd=req.header.rd), q=req.q)
                pending[txid] = (addr, req.header.id, qname, qtype, now())
                upstream_sock.sendto(forwarded.pack(), (UPSTREAM_IP, UPSTREAM_PORT))

            else:
                if addr[0] == UPSTREAM_IP and addr[1] == UPSTREAM_PORT:
                    # Demo-only: widen race window so forged replies can arrive first.
                    time.sleep(UPSTREAM_REPLY_DELAY)

                try:
                    resp = DNSRecord.parse(data)
                except Exception:
                    continue

                txid = resp.header.id
                pend = pending.pop(txid, None)
                if not pend:
                    continue

                client_addr, original_id, _, _, _ = pend

                # Cache only validated responses tied to an outstanding txid.
                add_cache_records_from_section(resp.rr)
                add_cache_records_from_section(resp.auth)
                add_cache_records_from_section(resp.ar)

                resp.header.id = original_id
                resp.header.ra = 1
                client_sock.sendto(resp.pack(), client_addr)


if __name__ == "__main__":
    main()
