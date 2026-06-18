"""How to use:  python3 my_dig.py <domain> <dns_server> [query_type] """

import sys
import random
from scapy.all import IP, UDP, DNS, DNSQR, sr1

DNS_PORT = 53
TIMEOUT = 5  # seconds to wait for a UDP response

# Mapping the numeric RTYPE to human-readable string for display
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
    """
    if isinstance(raw, bytes):
        return raw.decode(errors="replace").rstrip(".")
    return str(raw).rstrip(".")


#Convert a numeric DNS record type to its string abbreviation. Eg: rtype:1 then output(str): A
def rtype_str(rtype_int):
    return RTYPE_NAMES.get(rtype_int, str(rtype_int))


# sending a single DNS query over UDP and return the raw response packet.
def send_query_udp(domain, dns_server, qtype):
    txid = random.randint(0, 65535)
    sport = random.randint(1024, 65535)

    pkt = (
        IP(dst=dns_server)
        / UDP(sport=sport, dport=DNS_PORT)
        / DNS(
            id=txid,
            rd=1,  # We ask resolver to recurse for us
            qd=DNSQR(
                qname=domain,
                qtype=qtype,
                qclass="IN",
            ),
        )
    )

    return sr1(pkt, timeout=TIMEOUT, verbose=0)


## Print the QUESTION section of the DNS response in dig-like format.
def print_question_section(dns_layer, qtype):

    print("QUESTION SECTION:")
    if dns_layer.qd:
        qname = decode_name(dns_layer.qd.qname)
        print(f";{qname}.\t\t\tIN\t{qtype}")
    print()



#### Print the ANSWER section of the DNS response.
def print_answer_section(dns_layer):
    """
    I iterates over all resource records in the answer section and prints
    each record's name, TTL, class, type, and rdata.
    """
    print("ANSWER SECTION:")
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



### Print a full dig-style report for the given DNS response.
def print_response(response, qtype):

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
