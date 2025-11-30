# traffic-lab: Packet replay / PCAP manipulation environment
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    tcpreplay \
    wireshark-common tshark \
    tcpdump \
    iproute2 \
    iputils-ping \
    ca-certificates && \
    pip3 install --no-cache-dir scapy && \
    rm -rf /var/lib/apt/lists/*

# Your dataset will be mounted here by docker-compose
WORKDIR /pcaps

# Keep container running; exec in to use tools
CMD ["tail", "-f", "/dev/null"]

