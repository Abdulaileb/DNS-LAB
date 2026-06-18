FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-netifaces \
        tcpdump \
        dnsutils \
        iputils-ping \
        iptables \
    && pip3 install --no-cache-dir scapy \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
