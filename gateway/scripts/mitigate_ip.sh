#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-block}"   # block | unblock
IP="${2:-}"
CHAIN="${3:-INPUT}"    # or FORWARD depending on your rules

if [ -z "$IP" ]; then
  echo "Usage: $0 block|unblock <IP> [CHAIN]" >&2
  exit 2
fi

case "$ACTION" in
  block)
    echo "[mitigate_ip] Blocking $IP in chain ${CHAIN}"
    iptables -I "$CHAIN" -s "$IP" -j DROP
    ;;
  unblock)
    echo "[mitigate_ip] Unblocking $IP from chain ${CHAIN}"
    # Remove ALL DROP rules for this IP in that chain
    while iptables -C "$CHAIN" -s "$IP" -j DROP >/dev/null 2>&1; do
      iptables -D "$CHAIN" -s "$IP" -j DROP
    done
    ;;
  *)
    echo "Unknown action: $ACTION" >&2
    exit 3
    ;;
esac

