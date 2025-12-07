#!/usr/bin/env python3
"""
gateway_detector.py
-----------------------------------------
Sniffer-based packet detector for the IoT gateway.

This version:
  • sniffs packets from the IoT subnet
  • applies a userspace LEO link model (delay + jitter + loss)
  • feeds packets into a LEO-aware EWMA + DDoS monitor (detection_algo.py)
  • logs window-level stats + alerts
  • optionally writes per-window metrics to a CSV file
  • DOES NOT forward packets (no NFQUEUE / no tc)

Architecture:
  traffic-lab (PCAP replay)
      → (simulated LEO link in this process)
          → gateway_detector (LEO-aware detection + logging)

To run inside the gateway container:

  python3 gateway_detector.py --iface eth0 \
      --log-file /opt/detector/gateway_detector.log \
      --csv-stats /opt/detector/window_stats.csv
"""

import argparse
import random
import time

from scapy.all import sniff

import detection_algo


# ---------------------------------------------------------------------------
# LEO satellite link model (userspace simulation)
# ---------------------------------------------------------------------------

LEO_ENABLED = True

# One-way base delay (seconds)
LEO_DELAY = 0.045  # 45 ms

# Jitter (seconds): actual delay uniformly in [DELAY - JITTER, DELAY + JITTER]
LEO_JITTER = 0.015  # ±15 ms

# Independent per-packet loss probability
LEO_LOSS_PROB = 0.05


class LEOLink:
    """Simple userspace model of a LEO satellite link (delay + jitter + loss)."""

    def __init__(self, delay: float, jitter: float, loss_prob: float, enabled: bool = True):
        self.delay = delay
        self.jitter = jitter
        self.loss_prob = loss_prob
        self.enabled = enabled

    def apply(self) -> bool:
        """
        Apply the link model to a single packet.

        Returns:
            True  → packet passes through the link (after delay)
            False → packet is dropped by the link
        """
        if not self.enabled:
            return True

        # Random loss
        if random.random() < self.loss_prob:
            return False

        # Delay + jitter
        if self.delay > 0 or self.jitter > 0:
            low = self.delay - self.jitter
            high = self.delay + self.jitter
            wait = random.uniform(low, high)
            if wait < 0:
                wait = 0
            time.sleep(wait)

        return True


# Single global instance used by all packets
LEO_LINK = LEOLink(
    delay=LEO_DELAY,
    jitter=LEO_JITTER,
    loss_prob=LEO_LOSS_PROB,
    enabled=LEO_ENABLED,
)


# ---------------------------------------------------------------------------
# Sniffer handler wiring
# ---------------------------------------------------------------------------

def make_handler(packet_callback):
    """
    Wrap the detection_algo packet_callback with the LEO link model.

    The order is:
      replay_pcap → sniffed by gateway → LEO_LINK.apply() → packet_callback(pkt)
    """
    def handler(pkt):
        # Apply LEO link behavior before the detection engine "sees" the packet.
        if not LEO_LINK.apply():
            return
        packet_callback(pkt)

    return handler


def main():
    parser = argparse.ArgumentParser(description="IoT Gateway LEO-aware Packet Detector")
    parser.add_argument(
        "--iface",
        required=True,
        help="Interface to sniff on (e.g., eth0)",
    )
    parser.add_argument(
        "--log-file",
        default="/var/log/gateway_detector.log",
        help="Where to log detection window summaries and alerts.",
    )
    parser.add_argument(
        "--window-size",
        type=float,
        default=1.0,
        help="Window size in seconds for EWMA/DDoS aggregation (default: 1.0s).",
    )
    parser.add_argument(
        "--csv-stats",
        default=None,
        help=(
            "Optional path to a CSV file where per-window statistics will be written. "
            "If omitted, no CSV stats are generated."
        ),
    )
    args = parser.parse_args()

    print(f"[INFO] Starting gateway_detector on iface={args.iface}")
    print(f"[INFO] Logging to {args.log_file}")
    if args.csv_stats:
        print(f"[INFO] Writing per-window statistics to CSV: {args.csv_stats}")
    if LEO_ENABLED:
        print(
            "[INFO] LEO link model enabled: "
            f"delay={LEO_DELAY*1000:.1f}ms ±{LEO_JITTER*1000:.1f}ms, "
            f"loss={LEO_LOSS_PROB*100:.1f}%"
        )
    else:
        print("[INFO] LEO link model DISABLED")

    # Open log file and (optionally) CSV stats file, then initialize engine
    with open(args.log_file, "a", buffering=1) as log_file:
        csv_file = None
        try:
            if args.csv_stats:
                # newline="" is important for correct CSV formatting on all platforms
                csv_file = open(args.csv_stats, "w", newline="")
            packet_cb = detection_algo.init_leo_engine(
                log_file=log_file,
                window_size=args.window_size,
                csv_file=csv_file,
            )
            handler = make_handler(packet_cb)

            try:
                sniff(
                    iface=args.iface,
                    store=False,
                    prn=handler,
                )
            except KeyboardInterrupt:
                print("\n[INFO] KeyboardInterrupt received; stopping sniffer.")
        finally:
            detection_algo.shutdown_leo_engine()
            if csv_file is not None:
                csv_file.close()
            print("[INFO] gateway_detector shutdown complete.")


if __name__ == "__main__":
    main()

