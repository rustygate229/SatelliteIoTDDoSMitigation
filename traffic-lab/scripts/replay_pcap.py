#!/usr/bin/env python3
import argparse
import time
from scapy.all import PcapReader, IP, TCP, UDP, send

def main():
    parser = argparse.ArgumentParser(
        description="Simple Scapy-based PCAP replayer for traffic-lab -> gateway."
    )
    parser.add_argument("pcap", help="Path to PCAP file (inside container, e.g. /pcaps/...)")
    parser.add_argument(
        "--pps", type=float, default=400.0,
        help="Packets per second (approximate). Default: 400."
    )
    parser.add_argument(
        "--iface", default="eth0",
        help="Interface to send on (default: eth0)."
    )
    parser.add_argument(
        "--src-ip", default="172.28.10.10",
        help="Rewrite source IP to this (default: traffic-lab IP on iot_local)."
    )
    parser.add_argument(
        "--dst-ip", default="172.28.10.20",
        help="Rewrite dest IP to this (default: gateway IP on iot_local)."
    )

    args = parser.parse_args()

    interval = 1.0 / args.pps if args.pps > 0 else 0.0

    print(f"[INFO] Replaying {args.pcap}")
    print(f"[INFO] iface={args.iface}, pps={args.pps}, src_ip={args.src_ip}, dst_ip={args.dst_ip}")

    count = 0
    with PcapReader(args.pcap) as pcap:
        for pkt in pcap:
            # Only send packets that contain an IP layer
            if IP not in pkt:
                continue

            ip = pkt[IP]

            # Rewrite IPs into our lab topology
            ip.src = args.src_ip
            ip.dst = args.dst_ip

            # Force Scapy to recompute length and checksums
            if hasattr(ip, "len"):
                del ip.len
            if hasattr(ip, "chksum"):
                del ip.chksum
            if TCP in ip and hasattr(ip[TCP], "chksum"):
                del ip[TCP].chksum
            if UDP in ip and hasattr(ip[UDP], "chksum"):
                del ip[UDP].chksum

            # Send IP-layer only; kernel will handle Ethernet/MAC using ARP
            send(ip, verbose=False)

            count += 1
            if interval > 0:
                time.sleep(interval)

    print(f"[INFO] Done. Sent {count} IP packets.")

if __name__ == "__main__":
    main()

