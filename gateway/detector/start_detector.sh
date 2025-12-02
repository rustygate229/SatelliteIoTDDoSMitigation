#!/usr/bin/env bash
set -euo pipefail

cd /opt/detector

python3 gateway_detector.py \
    --iface eth0 \
    --log-file /opt/detector/gateway_detector.log

