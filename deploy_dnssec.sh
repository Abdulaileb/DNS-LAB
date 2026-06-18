#!/usr/bin/env bash
# deploy_dnssec.sh - Automate DNSSEC key generation, zone signing, and
#                    resolver trust-anchor configuration for the lab.
#
# Run from the no_kaminski/ directory on the host VM:
#     bash solutions/deploy_dnssec.sh
#
# What this script does (Task 3 steps):
#   3.1  Generate ZSK (Zone Signing Key) and KSK (Key Signing Key) inside
#        the authoritative container.
#   3.2  Append the public keys to the zone file and sign the zone with
#        dnssec-signzone, producing example.com.zone.signed.
#   3.3  Switch named.conf.local inside the authoritative container to use
#        the signed zone file and restart named.
#   3.4  Extract the KSK public key, inject it as a trust anchor in the
#        resolver's named.conf.options, switch validation to "auto", and
#        restart named.
#   3.5  Verify DNSSEC with a +dnssec query and confirm poisoning now fails.

set -euo pipefail

AUTHORITATIVE="authoritative"
RESOLVER="resolver"
ZONE="example.com"
ZONE_FILE="/etc/bind/example.com.zone"
SIGNED_FILE="${ZONE_FILE}.signed"

echo "=== Step 3.1: Generate DNSSEC keys on ${AUTHORITATIVE} ==="

# ZSK (Zone Signing Key): 1024-bit RSA, signs individual RRsets
docker exec "${AUTHORITATIVE}" bash -c "
  cd /etc/bind
  dnssec-keygen -a RSASHA256 -b 1024 -n ZONE ${ZONE}
"

# KSK (Key Signing Key): 2048-bit RSA with -f KSK flag, signs the DNSKEY RRset
docker exec "${AUTHORITATIVE}" bash -c "
  cd /etc/bind
  dnssec-keygen -a RSASHA256 -b 2048 -n ZONE -f KSK ${ZONE}
"

# Append both public keys to the zone file so dnssec-signzone can embed them
docker exec "${AUTHORITATIVE}" bash -c "
  cd /etc/bind
  cat K${ZONE}.*.key >> ${ZONE_FILE}
"

echo "Keys generated and appended to zone file."

echo ""
echo "=== Step 3.2: Sign the zone ==="

# dnssec-signzone options:
#   -A         include all DNSKEY records (ZSK + KSK) in the signed zone
#   -3 <salt>  enable NSEC3 with a random 16-hex-char salt (hides zone walking)
#   -N INCREMENT  auto-increment the SOA serial
#   -o <zone>  origin (zone name)
#   -t         print timing stats
SALT=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-16)

docker exec "${AUTHORITATIVE}" bash -c "
  cd /etc/bind
  dnssec-signzone -A -3 ${SALT} -N INCREMENT -o ${ZONE} -t ${ZONE_FILE}
"

echo "Zone signed -> ${SIGNED_FILE}"

echo ""
echo "=== Step 3.3: Switch authoritative to signed zone ==="

# sed -i fails on Docker volume mounts ("Device or resource busy") because it
# creates a temp file and renames it, which is blocked on bind-mounted files.
# Writing directly with cat > overwrites in-place and works correctly.
docker exec "${AUTHORITATIVE}" bash -c "cat > /etc/bind/named.conf.local << 'EOF'
zone \"example.com\" {
    type master;
    file \"/etc/bind/example.com.zone.signed\";
};
EOF"

# Use docker restart instead of 'service named restart' inside the container.
# named is PID 1 in the container — killing it stops the container entirely.
# docker restart sends SIGTERM to PID 1, waits, then starts a fresh container.
docker restart "${AUTHORITATIVE}"
sleep 3  # wait for named to fully start
echo "Authoritative nameserver restarted with signed zone."

echo ""
echo "=== Step 3.4: Configure resolver trust anchor ==="

# Extract the full KSK public key material (flag 257 = KSK, algorithm 8 = RSASHA256).
# awk '{print $NF}' only gets the LAST space-separated field, which is wrong —
# the base64 key spans multiple fields separated by spaces.
# sed 's/.*DNSKEY 257 3 8 //' strips everything up to and including the type
# field, leaving the complete multi-chunk key string intact.
KSK_KEY=$(docker exec "${AUTHORITATIVE}" bash -c \
  "grep -h 'DNSKEY 257 3 8' /etc/bind/K${ZONE}.*.key | sed 's/.*DNSKEY 257 3 8 //'")

echo "KSK public key (base64): ${KSK_KEY}"

# Write the full resolver config with validation enabled and trust anchor injected.
# Again using cat > instead of sed -i to avoid the volume-mount rename failure.
docker exec "${RESOLVER}" bash -c "cat > /etc/bind/named.conf.options << EOF
options {
    directory \"/var/cache/bind\";
    dnssec-validation auto;
    listen-on-v6 { any; };
    allow-query { any; };
    query-source port 33333;
};

trusted-keys {
    \"${ZONE}.\" 257 3 8 \"${KSK_KEY}\";
};
EOF"

# Use docker restart for the same PID 1 reason as above.
docker restart "${RESOLVER}"
sleep 3  # wait for named to fully start
echo "Resolver restarted with DNSSEC validation enabled."

echo ""
echo "=== Step 3.5: Verify DNSSEC ==="

sleep 2  # give named a moment to come up

echo ">>> Querying www.example.com with +dnssec flag (should show 'ad' flag):"
docker exec client dig @10.9.0.53 www.example.com +dnssec +short

echo ""
echo ">>> Flushing resolver cache and re-running cache poisoning to confirm it fails..."
docker exec "${RESOLVER}" rndc flush
echo "(Run 'python3 cache_poisoning.py' from the attacker container and then"
echo " check 'dig @10.9.0.53 www.example.com +short' - it should still return 1.2.3.4)"

echo ""
echo "=== DNSSEC deployment complete ==="