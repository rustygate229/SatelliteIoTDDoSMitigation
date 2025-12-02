#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <pcap-file-name>"
  echo "Example: $0 mirai_sample.pcap"
  exit 1
fi

PCAP_FILE="$1"

replay_pcap.py \
    /pcaps/iot_23_small/${PCAP_FILE} \
    --iface eth0 \
    --pps 3000 \
    --src-ip 172.28.10.10 \
    --dst-ip 172.28.10.20

