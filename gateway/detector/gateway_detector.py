#!/usr/bin/env python3
"""
Sniffer-based packet detector for the IoT gateway

This version:
  - sniffs packets from the IoT subnet
  - applies a LEO link model (delay, jitter, loss)
  - feeds packets into a LEO-aware EWMA and DDoS monitor (detection_algo.py)
  - logs window-level stats and alerts
  - DOES NOT forward packets since no NFQUEUE or tc

Architecture:
  traffic-lab (PCAP replay)
     - simulated LEO link in this process
         - gateway_detector (LEO-aware detection + logging)

To run inside the gateway container:

  python3 gateway_detector.py --iface eth0 \
      --log-file /opt/detector/gateway_detector.log
"""

import argparse
import random
import time

from scapy.all import sniff

import detection_algo

LEO_ENABLED = True

# One-way base delay (seconds)
LEO_DELAY = 0.045

# Jitter (seconds) actual delay uniformly in range [delay - jitter, delay + jitter] (+-15)
LEO_JITTER = 0.015

# Independent per packet loss probability
LEO_LOSS_PROB = 0.05

# Model of a LEO satellite link with delay, jitter and loss
class LEOLink:

    def __init__(self, delay: float, jitter: float, loss_prob: float, enabled: bool = True):
        self.delay = delay
        self.jitter = jitter
        self.loss_prob = loss_prob
        self.enabled = enabled

    def apply(self) -> bool:
        # Applies link model to a single packet
        
		if not self.enabled:
            return True

        # Randomized loss
        if random.random() < self.loss_prob:
            return False

        # Delay and jitter
        if self.delay > 0 or self.jitter > 0:
            low = self.delay - self.jitter
            high = self.delay + self.jitter
            wait = random.uniform(low, high)
            if wait < 0:
                wait = 0
            time.sleep(wait)

        return True


# Global instance used by all packets
LEO_LINK = LEOLink(
    delay=LEO_DELAY,
    jitter=LEO_JITTER,
    loss_prob=LEO_LOSS_PROB,
    enabled=LEO_ENABLED,
)


# Wraps detection algorithm into LEO link model
def make_handler(packet_callback):
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
    args = parser.parse_args()

    print(f"[INFO] Starting gateway_detector on iface={args.iface}")
    print(f"[INFO] Logging to {args.log_file}")
    if LEO_ENABLED:
        print(
            "[INFO] LEO link model enabled: "
            f"delay={LEO_DELAY*1000:.1f}ms ±{LEO_JITTER*1000:.1f}ms, "
            f"loss={LEO_LOSS_PROB*100:.1f}%"
        )
    else:
        print("[INFO] LEO link model DISABLED")

    # Open log file and initialize engine
    with open(args.log_file, "a", buffering=1) as log_file:
        packet_cb = detection_algo.init_leo_engine(
            log_file=log_file,
            window_size=args.window_size,
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
            print("[INFO] gateway_detector shutdown complete.")


if __name__ == "__main__":
    main()
