# DNS Security Lab — Attack & Defence

This is a Hands-on study of DNS cache poisoning (classic + Kaminsky) and DNSSEC hardening, which is built inside an isolated Docker environment on Ubuntu 24.04.

This is a university project on the ongoing practice in **DevSecOps · AI Security · Cloud Security Engineering** — understanding how infrastructure-level protocols 
can be exploited, and how to harden them, is foundational to securing modern cloud-native and AI-driven systems.

---

## What this lab covers

| Task | Topic | Outcome |
|------|-------|---------|
| 1 | Custom DNS query tool (Scapy) | Understand DNS packet structure at the byte level |
| 2 | Classic cache poisoning via ARP MITM | Poison resolver cache → redirect traffic |
| 3 | DNSSEC deployment | Cryptographically sign zone, defeat poisoning |
| 4 | Kaminsky cache poisoning | Zone-wide poisoning without MITM access |

---

## Why this matters for me in my Devsecops & Cloud Security Journey.

DNS is the first link in every service's trust chain — APIs, microservices, cloud endpoints, AI model registries. A poisoned resolver means:

- Traffic silently redirected to attacker-controlled infrastructure
- TLS certificates issued for the wrong host (BGP + DNS hijack pattern)
- AI pipelines pulling models or data from malicious sources
- Cloud workloads (EKS, GKE, AKS) contacting attacker IPs instead of internal services

This lab builds the muscle memory to **spot DNS weaknesses in infrastructure reviews** and **enforce DNSSEC as a baseline control** in cloud security posture management.

---

## Environment

```
┌─────────────────────────────────────────────┐
│           Docker Bridge 10.9.0.0/24          │
│                                              │
│  client       10.9.0.2    DNS queries        │
│  attacker     10.9.0.10   Scapy / ARP spoof  │
│  resolver     10.9.0.53   BIND9 (vulnerable) │
│  authoritative 10.9.0.153 BIND9 (example.com)│
└─────────────────────────────────────────────┘

Kaminsky variant: 10.19.0.0/24
  wk_resolver runs a custom Python resolver
  TXID range limited to 10000–10005 (intentionally weak)
```

Resolver weaknesses used in the lab (intentional):
- Fixed upstream source port: `33333`
- DNSSEC validation: disabled by default
- Kaminsky resolver: TXID range of only 6 values

---

## Task 1 — Custom `dig` with Scapy

Built `my_dig.py`: a DNS query tool that constructs raw packets (IP / UDP / DNS),
sends them with a random Transaction ID, and parses the response — printing the
QUESTION and ANSWER sections in `dig`-style format.

```bash
python3 my_dig.py www.example.com 10.9.0.53 A
```

Key learning: DNS has no built-in authentication — any reply with a matching
Transaction ID is accepted. This is the root cause of Tasks 2 and 4.

---

## Task 2 — Classic Cache Poisoning

**Attack chain:**

1. ARP-poison both resolver and authoritative server (become the MITM)
2. Drop the real authoritative reply via `iptables FORWARD DROP`
3. Sniff the forwarded query, read the Transaction ID directly
4. Send a burst of 64 forged replies with `FAKE_IP = 6.6.6.6`

```bash
# Attacker container
python3 /solutions/cache_poisoning.py

# Client — verify poisoning
dig @10.9.0.53 www.example.com +short
# → 6.6.6.6
```

Because the resolver uses a **fixed source port (33333)**, the only unknown
is the 16-bit Transaction ID — which we read directly from the intercepted
packet, making the attack deterministic.

---

## Task 3 — DNSSEC Deployment

Hardened the authoritative server and resolver against poisoning:

```bash
# Step 1 — Generate ZSK + KSK
dnssec-keygen -a RSASHA256 -b 1024 -n ZONE example.com          # ZSK
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK example.com  # KSK

# Step 2 — Sign zone (NSEC3 to prevent zone walking)
dnssec-signzone -A -3 <salt> -N INCREMENT -o example.com example.com.zone

# Step 3 — Enable validation on resolver with KSK trust anchor
# named.conf.options:
#   dnssec-validation auto;
#   trusted-keys { "example.com." 257 3 8 "<KSK_BASE64>"; };
```

**Result:** Re-running the Task 2 attack with DNSSEC active produced:

```
broken trust chain resolving 'www.example.com/A/IN': 10.9.0.153#53
```

The resolver detected the missing RRSIG on the forged reply and returned
`SERVFAIL` instead of caching `6.6.6.6`. Attack defeated.

Automated deployment script: [`deploy_dnssec.sh`](./deploy_dnssec.sh)

---

## Task 4 — Kaminsky Cache Poisoning

**The insight:** Instead of targeting a cached domain directly, query random
subdomains (`mrrcikdx.example.com`) that are never cached — forcing a fresh
upstream query every attempt.

**Attack loop:**
1. Trigger a query for `<random>.example.com` → resolver asks authoritative
2. Flood forged replies across all 6 TXID values (10000–10005) simultaneously
3. Forged AUTHORITY section: `example.com NS → ns.attacker.example.com`
4. Forged ADDITIONAL: glue `ns.attacker.example.com → 6.6.6.6` + `www.example.com → 6.6.6.6`
5. One TXID match → entire zone poisoned

```bash
python3 /solutions/kaminsky_poisoning.py
# [*] Attempt 1/30: mrrcikdx.example.com
# [+] SUCCESS: www.example.com -> 6.6.6.6
```

Succeeded on **attempt 1** — demonstrating how trivially broken a resolver
with a predictable TXID range is.

**Real-world implication:** In 2008, Kaminsky discovered that most resolvers
were vulnerable because source ports were also predictable. The fix — port
randomisation — increased the search space from 65,535 to ~4.2 billion combinations.
DNSSEC remains the only cryptographic defence.

---

## Running the lab

```bash
# Clone and enter lab
git clone <this-repo>
cd dns-security-lab

# Install dependencies (Ubuntu/Debian)
sudo apt install -y docker.io docker-compose-v2 python3-pip dnsutils
pip3 install scapy dnspython cryptography --break-system-packages

# Tasks 1–3
cd no_kaminski
sudo docker compose up -d --build

# Task 4
cd ../with_kaminski
sudo docker compose up -d --build
```

---

## Skills demonstrated

- Raw packet crafting with **Scapy** (DNS / UDP / IP / Ethernet)
- **ARP spoofing** and Layer 2 MITM positioning
- **iptables** traffic manipulation in Docker networks
- **DNSSEC** key management (ZSK/KSK), zone signing, trust anchor configuration
- **BIND9** configuration and hardening
- **Docker** multi-container lab orchestration
- Protocol-level understanding of DNS (RFC 1035) and DNSSEC (RFC 4033–4035)

---

## Stack

`Python 3` · `Scapy` · `BIND9` · `Docker` · `Ubuntu 24.04` · `iptables` · `dnslib`

---

## Background

I'm building toward a career at the intersection of **DevSecOps**, **AI Security**,
and **Cloud Security Engineering** — focusing on the security of infrastructure
that underpins AI systems and cloud-native workloads. This lab is part of a broader
practice of understanding attacks at the protocol level before applying controls
at the platform level (AWS Route 53 DNSSEC, GCP Cloud DNS, Azure DNS, Kubernetes CoreDNS hardening).

Connect with me on [LinkedIn](#) or follow my security write-ups here on GitHub.
