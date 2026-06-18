"""
How to use:  python3 my_dig.py <domain> <dns_server> [query_type]

"""

import sys
import random
from scapy.all import IP, UDP, TCP, DNS, DNSQR, sr1

DNS_PORT = 53
TIMEOUT = 5  # seconds to wait for a UDP response

# Map numeric RTYPE to human-readable string for display
RTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def decode_name(raw):
    """
    Decode a DNS name field (bytes or str) to a clean dotted string.

    Input:  raw - bytes or str, possibly trailing with a dot or b'.'
    Output: str  - lowercase domain name without trailing dot
    """
    if isinstance(raw, bytes):
        return raw.decode(errors="replace").rstrip(".")
    return str(raw).rstrip(".")


def rtype_str(rtype_int):
    """
    Convert a numeric DNS record type to its string abbreviation.

    Input:  rtype_int - int, e.g. 1
    Output: str       - e.g. "A"
    """
    return RTYPE_NAMES.get(rtype_int, str(rtype_int))


def send_query_udp(domain, dns_server, qtype):
    """
    Send a single DNS query over UDP and return the raw response packet.

    Input:
        domain     - str, domain name to query
        dns_server - str, IP of the resolver
        qtype      - str, record type (e.g. "A")
    Output:
        Scapy packet (with DNS layer) on success, or None on timeout/error
    """
    txid = random.randint(0, 65535)
    sport = random.randint(1024, 65535)

    pkt = (
        IP(dst=dns_server)
        / UDP(sport=sport, dport=DNS_PORT)
        / DNS(
            id=txid,
            rd=1,  # Recursion Desired - ask resolver to recurse for us
            qd=DNSQR(
                qname=domain,
                qtype=qtype,
                qclass="IN",
            ),
        )
    )

    return sr1(pkt, timeout=TIMEOUT, verbose=0)


def print_question_section(dns_layer, qtype):
    """
    Print the QUESTION section of the DNS response in dig-like format.

    Input:
        dns_layer - Scapy DNS object from the response
        qtype     - str, the query type we requested
    Output: None (prints to stdout)
    """
    print(";; QUESTION SECTION:")
    if dns_layer.qd:
        qname = decode_name(dns_layer.qd.qname)
        print(f";{qname}.\t\t\tIN\t{qtype}")
    print()


def print_answer_section(dns_layer):
    """
    Print the ANSWER section of the DNS response.

    Iterates over all resource records in the answer section and prints
    each record's name, TTL, class, type, and rdata.

    Input:  dns_layer - Scapy DNS object from the response
    Output: None (prints to stdout)
    """
    print(";; ANSWER SECTION:")
    if not dns_layer.ancount:
        print(";; (no records)")
        print()
        return

    rr = dns_layer.an
    while rr and rr != b"":
        try:
            name = decode_name(rr.rrname)
            ttl = rr.ttl
            rtype = rtype_str(rr.type)
            rdata = rr.rdata

            # Decode rdata: bytes -> str, objects -> str, strip trailing dot
            if isinstance(rdata, bytes):
                rdata = rdata.decode(errors="replace").rstrip(".")
            else:
                rdata = str(rdata).rstrip(".")

            print(f"{name}.\t\t{ttl}\tIN\t{rtype}\t{rdata}")
            rr = rr.payload
        except Exception:
            break
    print()


def print_response(response, domain, qtype):
    """
    Print a full dig-style report for the given DNS response.

    Outputs the header (flags, counts), QUESTION, and ANSWER sections.

    Input:
        response - Scapy packet (may be None if timeout)
        domain   - str, originally queried domain
        qtype    - str, query type
    Output: None (prints to stdout)
    """
    if response is None:
        print(f";; connection timed out; no servers could be reached")
        return

    if not response.haslayer(DNS):
        print(";; ERROR: response contains no DNS layer")
        return

    dns = response[DNS]

    # --- Header ---
    rcode_map = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                 4: "NOTIMP", 5: "REFUSED"}
    rcode = rcode_map.get(dns.rcode, str(dns.rcode))

    print(f";; Got answer:")
    print(f";; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: {dns.id}")

    flags = []
    if dns.qr:  flags.append("qr")   # Query Response
    if dns.aa:  flags.append("aa")   # Authoritative Answer
    if dns.tc:  flags.append("tc")   # Truncated
    if dns.rd:  flags.append("rd")   # Recursion Desired
    if dns.ra:  flags.append("ra")   # Recursion Available
    print(
        f";; flags: {' '.join(flags)}; "
        f"QUERY: {dns.qdcount}, ANSWER: {dns.ancount}, "
        f"AUTHORITY: {dns.nscount}, ADDITIONAL: {dns.arcount}"
    )
    print()

    print_question_section(dns, qtype)
    print_answer_section(dns)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python3 {sys.argv[0]} <domain> <dns_server> [query_type]")
        sys.exit(1)

    domain = sys.argv[1]
    dns_server = sys.argv[2]
    qtype = sys.argv[3].upper() if len(sys.argv) > 3 else "A"

    print(f"; <<>> my_dig <<>> {domain} @{dns_server} {qtype}")

    response = send_query_udp(domain, dns_server, qtype)
    print_response(response, domain, qtype)
