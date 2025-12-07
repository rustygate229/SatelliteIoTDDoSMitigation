#!/usr/bin/env python3
"""
detection_algo.py
-----------------------------------------
LEO-aware congestion + DDoS detector used by gateway_detector.py.

This is adapted from the dynamic_leo_monitor_ddos.py design, but:
  - Uses a "virtual" rate limiter (no tc / qdisc, just logs actions)
  - Exposes an engine-style API instead of being a standalone script
  - Is driven by gateway_detector's sniffer and LEO link model
  - Optionally writes per-window statistics to a CSV file for analysis

Public API used by gateway_detector:
  init_leo_engine(log_file, window_size: float = TIME_WINDOW_SECONDS,
                  csv_file: Optional[TextIO] = None) -> callable
      Returns a packet callback that accepts a Scapy Packet.

  shutdown_leo_engine() -> None
      Stops the background polling thread cleanly.

The old analyze(flow) API is kept as a stub for compatibility, but
the real LEO-aware logic is in LEOLiveMonitorState.
"""

from __future__ import annotations

import sys
import time
import threading
import csv
from typing import Dict, Any, Optional, Tuple, List, TextIO

import numpy as np
from scapy.all import Packet, IP, TCP, UDP, ICMP

# ---------------------------------------------------------------------------
# 1. Configuration Constants (LEO-aware)
# ---------------------------------------------------------------------------

# LEO Satellite Characteristics (used for baseline)
LEO_BASE_LATENCY_MS = 45  # 45 ms one-way
LEO_TYPICAL_RTT_MS = (LEO_BASE_LATENCY_MS * 2) + 20  # ~110 ms RTT estimate

# EWMA Parameters (tuned for LEO)
EWMA_ALPHA = 0.1            # Slower smoothing for intermittent LEO links
THRESHOLD_MULTIPLIER = 1.8  # Higher threshold for burst tolerance
TIME_WINDOW_SECONDS = 1.0   # 1-second windows

# Mitigation / anomaly behavior
CONSECUTIVE_ANOMALIES_REQUIRED = 3   # sustained violations
MIN_TIME_BETWEEN_MITIGATIONS = 10.0  # seconds between congestion "events"

# --- DDoS Detection Parameters (L4/L7) ---

# SYN Flood (protocol attack) – make it *very* sensitive
DDoS_SYN_RATIO_THRESHOLD = 0.05      # 5% of packets are SYN
DDoS_MIN_PACKETS_PER_WINDOW = 5      # only need 5 packets in a window

# UDP Flood (volumetric)
DDoS_UDP_RATE_THRESHOLD = 5.0        # >= 5 UDP packets per second

# ICMP Flood (volumetric)
DDoS_ICMP_RATE_THRESHOLD = 2.0       # >= 2 ICMP packets per second

# HTTP Flood (application-layer)
DDoS_HTTP_RATE_THRESHOLD = 1.0       # >= 1 HTTP request per second

# “Mitigation” rates – here they are *virtual* (no tc called)
DEFAULT_RATE_LIMIT_MBPS = 5.0  # congestion limit
DDoS_RATE_LIMIT_MBPS = 1.0     # aggressive DDoS limit


# ---------------------------------------------------------------------------
# 2. Virtual Rate Limiter (no tc, no subprocess)
# ---------------------------------------------------------------------------

class VirtualRateLimiter:
    """
    A tc-free stand-in for TCRateLimiter.

    It keeps track of an imaginary rate limit and logs when that limit would
    be applied or cleared. This preserves the structure of the original LEO
    algorithm without requiring tc/netem in the container.
    """

    def __init__(self, log: callable):
        self.limit_active: bool = False
        self.current_rate_mbps: float = 0.0
        self._log = log

    def apply_limit(self, rate_mbps: float) -> None:
        if self.limit_active and self.current_rate_mbps == rate_mbps:
            return
        self.limit_active = True
        self.current_rate_mbps = rate_mbps
        self._log(f"[VIRTUAL MITIGATION] Set rate limit to {rate_mbps:.1f} Mbps")

    def clear_limit(self) -> None:
        if not self.limit_active:
            return
        self._log("[VIRTUAL MITIGATION] Clearing rate limit (back to normal).")
        self.limit_active = False
        self.current_rate_mbps = 0.0


# ---------------------------------------------------------------------------
# 3. LEO-Aware EWMA Monitor (Congestion Detection)
# ---------------------------------------------------------------------------

class LEO_EWMA_Monitor:
    """EWMA monitor with LEO-specific tolerance and RTT-based dynamic thresholds."""

    def __init__(self, alpha: float, threshold_multiplier: float, typical_rtt_ms: float):
        self.alpha = alpha
        self.threshold_multiplier_base = threshold_multiplier
        self.threshold_multiplier = threshold_multiplier
        self.typical_rtt_ms = typical_rtt_ms

        self.ewma: float = -1.0
        self.anomaly_count: int = 0
        self.consecutive_anomalies: int = 0
        self.last_mitigation_time: float = 0.0

        self.rtt_estimates: List[float] = []
        self.leo_state: str = "normal"
        self.burst_allowance: int = 5
        self.max_rtt_samples: int = 100

    def update(self, new_value: float, current_time: float) -> Tuple[float, Optional[str]]:
        """Updates EWMA and checks for anomalies with LEO-aware tolerance."""
        if self.ewma < 0:
            self.ewma = new_value
            return self.ewma, None

        self.ewma = (self.alpha * new_value) + ((1.0 - self.alpha) * self.ewma)
        alert_message = self._check_leo_anomaly(new_value, current_time)
        return self.ewma, alert_message

    def _check_leo_anomaly(self, instantaneous_rate: float, current_time: float) -> Optional[str]:
        """LEO-aware check for sustained congestion using EWMA + burst allowance."""
        upper_control_limit = self.ewma * self.threshold_multiplier

        # Allow a small number of benign bursts (LEO links can be spiky)
        if self.burst_allowance > 0 and instantaneous_rate < (upper_control_limit * 1.5):
            self.burst_allowance -= 1
            return None

        if instantaneous_rate > upper_control_limit:
            self.consecutive_anomalies += 1

            if (
                self.consecutive_anomalies >= CONSECUTIVE_ANOMALIES_REQUIRED
                and (current_time - self.last_mitigation_time) > MIN_TIME_BETWEEN_MITIGATIONS
            ):
                self.anomaly_count += 1
                self.last_mitigation_time = current_time
                self.leo_state = "congested"

                return (
                    f"LEO CONGESTION! Rate={instantaneous_rate:.2f} Bps > "
                    f"UCL={upper_control_limit:.2f} Bps for "
                    f"{self.consecutive_anomalies} windows."
                )
        else:
            # Recovery tracking
            if self.consecutive_anomalies > 0:
                self.consecutive_anomalies = 0
                if self.leo_state == "congested":
                    self.leo_state = "recovering"
                    self.burst_allowance = 5  # allow bursts again during recovery

        return None

    def update_rtt_estimate(self, rtt_ms: float) -> None:
        """Update RTT estimates and adjust threshold tolerance dynamically."""
        self.rtt_estimates.append(rtt_ms)
        if len(self.rtt_estimates) > self.max_rtt_samples:
            self.rtt_estimates.pop(0)

        avg_rtt = np.mean(self.rtt_estimates) if self.rtt_estimates else self.typical_rtt_ms

        # If RTT blows up relative to nominal LEO RTT, tighten threshold
        if avg_rtt > self.typical_rtt_ms * 1.5:
            self.threshold_multiplier = max(1.5, self.threshold_multiplier * 0.95)
        # If RTT recovers back toward baseline, relax threshold
        elif avg_rtt < self.typical_rtt_ms * 1.1 and self.threshold_multiplier < self.threshold_multiplier_base:
            self.threshold_multiplier = min(self.threshold_multiplier_base, self.threshold_multiplier * 1.02)

    def get_leo_status(self) -> Dict[str, Any]:
        """Returns LEO-specific status information."""
        avg_rtt = np.mean(self.rtt_estimates) if self.rtt_estimates else self.typical_rtt_ms
        return {
            "state": self.leo_state,
            "consecutive_anomalies": self.consecutive_anomalies,
            "avg_rtt_ms": float(avg_rtt),
            "current_multiplier": float(self.threshold_multiplier),
        }


# ---------------------------------------------------------------------------
# 4. DDoS Detection Module (UDP, ICMP, SYN, HTTP)
# ---------------------------------------------------------------------------

class DDoSDetection:
    """
    Comprehensive module for detecting UDP, ICMP, SYN Flood, and HTTP Flood attacks.
    """

    def __init__(
        self,
        syn_ratio_threshold: float,
        min_packets: int,
        udp_rate_threshold: float,
        icmp_rate_threshold: float,
        http_rate_threshold: float,
    ):
        self.syn_ratio_threshold = syn_ratio_threshold
        self.min_packets = min_packets
        self.udp_rate_threshold = udp_rate_threshold
        self.icmp_rate_threshold = icmp_rate_threshold
        self.http_rate_threshold = http_rate_threshold

        # Counters for current window
        self.syn_count: int = 0
        self.udp_count: int = 0
        self.icmp_count: int = 0
        self.http_request_count: int = 0
        self.total_packets: int = 0

        self.lock = threading.Lock()

    def process_packet(self, packet: Packet) -> None:
        """Processes a packet to count all relevant DDoS indicators."""
        with self.lock:
            self.total_packets += 1

            # ICMP Flood (L3 volumetric)
            if packet.haslayer(ICMP):
                self.icmp_count += 1
                return

            if not packet.haslayer(IP):
                return

            # UDP Flood (L4 volumetric)
            if packet.haslayer(UDP):
                self.udp_count += 1
                return

            # SYN + HTTP Flood (TCP L4/L7)
            if packet.haslayer(TCP):
                tcp = packet[TCP]

                # SYN set, ACK not set → connection attempt
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                    self.syn_count += 1

                # Lightweight HTTP request detection on ports 80/443
                if (tcp.dport in (80, 443) or tcp.sport in (80, 443)) and packet.haslayer("Raw"):
                    try:
                        payload = packet["Raw"].load.upper()
                        if payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"HEAD "):
                            self.http_request_count += 1
                    except Exception:
                        # Ignore malformed payloads
                        pass

    def check_status(self, time_elapsed: float) -> Dict[str, Any]:
        """Compute rates/ratios for this window and decide if DDoS is suspected."""
        with self.lock:
            results: Dict[str, Any] = {
                "is_ddos_suspected": False,
                "syn_suspected": False,
                "syn_ratio": None,
                "udp_suspected": False,
                "udp_rate": None,
                "icmp_suspected": False,
                "icmp_rate": None,
                "http_suspected": False,
                "http_rate": None,
                "alert_type": "None",
            }

            if time_elapsed <= 0.0:
                return results

            # UDP rate
            udp_rate = self.udp_count / time_elapsed
            results["udp_rate"] = udp_rate
            if udp_rate >= self.udp_rate_threshold:
                results["udp_suspected"] = True
                results["alert_type"] = "UDP Flood"

            # ICMP rate
            icmp_rate = self.icmp_count / time_elapsed
            results["icmp_rate"] = icmp_rate
            if icmp_rate >= self.icmp_rate_threshold:
                results["icmp_suspected"] = True
                results["alert_type"] = "ICMP Flood"

            # SYN ratio
            if self.total_packets >= self.min_packets:
                syn_ratio = self.syn_count / self.total_packets
                results["syn_ratio"] = syn_ratio
                if syn_ratio >= self.syn_ratio_threshold:
                    results["syn_suspected"] = True
                    results["alert_type"] = "SYN Flood"

            # HTTP rate
            http_rate = self.http_request_count / time_elapsed
            results["http_rate"] = http_rate
            if http_rate >= self.http_rate_threshold:
                results["http_suspected"] = True
                results["alert_type"] = "HTTP Flood"

            # Overall DDoS suspicion
            results["is_ddos_suspected"] = (
                results["udp_suspected"]
                or results["icmp_suspected"]
                or results["syn_suspected"]
                or results["http_suspected"]
            )

            return results

    def reset_window(self) -> None:
        """Reset counters for next time window."""
        with self.lock:
            self.syn_count = 0
            self.udp_count = 0
            self.icmp_count = 0
            self.http_request_count = 0
            self.total_packets = 0


# ---------------------------------------------------------------------------
# 5. RTT Monitor (SYN/SYN-ACK based)
# ---------------------------------------------------------------------------

class RTTMonitor:
    """Basic RTT monitoring using TCP packet analysis (SYN/SYN-ACK)."""

    def __init__(self):
        # key: (src, dst, sport, dport) → SYN timestamp
        self.tcp_sessions: Dict[Tuple[str, str, int, int], float] = {}
        self.rtt_samples: List[float] = []
        self.max_rtt_samples: int = 100

    def process_packet(self, packet: Packet) -> Optional[float]:
        """Process TCP packets and return RTT (ms) when a SYN/SYN-ACK pair completes."""
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return None

        ip = packet[IP]
        tcp = packet[TCP]
        current_time = float(packet.time)

        key = (ip.src, ip.dst, tcp.sport, tcp.dport)
        reverse_key = (ip.dst, ip.src, tcp.dport, tcp.sport)

        # SYN (no ACK) – start timing
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):
            if key not in self.tcp_sessions:
                self.tcp_sessions[key] = current_time

        # SYN-ACK – finish timing
        elif tcp.flags & 0x12:
            if reverse_key in self.tcp_sessions:
                syn_time = self.tcp_sessions.pop(reverse_key)
                rtt_ms = (current_time - syn_time) * 1000.0
                self.rtt_samples.append(rtt_ms)
                if len(self.rtt_samples) > self.max_rtt_samples:
                    self.rtt_samples.pop(0)
                return rtt_ms

        return None


# ---------------------------------------------------------------------------
# 6. LEO Live Monitor State (background polling)
# ---------------------------------------------------------------------------

class LEOLiveMonitorState:
    """LEO-aware live monitor integrating EWMA, RTT, and DDoS detection."""

    def __init__(
        self,
        monitor: LEO_EWMA_Monitor,
        limiter: VirtualRateLimiter,
        ddos_detector: DDoSDetection,
        window_size: float,
        log_file: Optional[TextIO],
        csv_file: Optional[TextIO],
    ):
        self.monitor = monitor
        self.limiter = limiter
        self.ddos_detector = ddos_detector
        self.window_size = window_size

        self.current_window_bytes: int = 0
        self.last_update_time: float = time.time()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.window_count: int = 0
        self.rtt_monitor = RTTMonitor()
        self.thread = threading.Thread(target=self._polling_loop, daemon=True)
        self.is_ddos_active: bool = False
        self.log_file = log_file

        # CSV logging setup
        self.csv_file = csv_file
        self.csv_writer: Optional[csv.writer] = None
        if self.csv_file is not None:
            self.csv_writer = csv.writer(self.csv_file)
            # Header row for analysis
            self.csv_writer.writerow([
                "window",
                "epoch_time",
                "bytes_in_window",
                "time_elapsed_s",
                "rate_Bps",
                "ewma_Bps",
                "avg_rtt_ms",
                "leo_state",
                "leo_consecutive_anomalies",
                "leo_threshold_multiplier",
                "syn_ratio",
                "udp_rate_pps",
                "icmp_rate_pps",
                "http_rate_rps",
                "syn_suspected",
                "udp_suspected",
                "icmp_suspected",
                "http_suspected",
                "is_ddos_suspected",
                "ddos_alert_type",
                "congestion_alert",
                "rate_limit_active",
                "rate_limit_mbps",
                "is_ddos_active",
            ])
            self.csv_file.flush()

    # ---- logging helper -------------------------------------------------

    def _log(self, msg: str) -> None:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} {msg}"
        # Log file (if provided)
        if self.log_file is not None:
            try:
                self.log_file.write(line + "\n")
            except Exception:
                pass
        # Also mirror to stdout for docker logs
        print(line)

    # ---- external API called by sniffer --------------------------------

    def packet_callback(self, packet: Packet) -> None:
        """Feeds packets to RTT, DDoS, and EWMA modules."""
        try:
            packet_size = len(packet)

            # 1. RTT monitoring (TCP only)
            rtt_ms = self.rtt_monitor.process_packet(packet)
            if rtt_ms is not None:
                self.monitor.update_rtt_estimate(rtt_ms)

            # 2. DDoS counters
            self.ddos_detector.process_packet(packet)

            # 3. EWMA byte counter for this window
            with self.lock:
                self.current_window_bytes += packet_size

        except Exception as e:
            self._log(f"[ERROR] Packet processing failed: {e}")

    # ---- background polling loop ---------------------------------------

    def _polling_loop(self) -> None:
        self._log(f"[LEO Monitor] Polling started. Interval={self.window_size:.1f}s")

        while not self.stop_event.is_set():
            time.sleep(self.window_size)

            with self.lock:
                time_elapsed = time.time() - self.last_update_time
                bytes_in_window = self.current_window_bytes
                self.current_window_bytes = 0
                self.last_update_time = time.time()

            if time_elapsed <= 0.0:
                continue

            instantaneous_rate = bytes_in_window / time_elapsed
            current_time = time.time()
            self.window_count += 1

            # 1. DDoS status for this window
            ddos_results = self.ddos_detector.check_status(time_elapsed)
            self.ddos_detector.reset_window()

            ddos_suspected = ddos_results["is_ddos_suspected"]
            alert_type = ddos_results["alert_type"]

            # 2. EWMA congestion status
            new_ewma, congestion_alert = self.monitor.update(instantaneous_rate, current_time)
            leo_status = self.monitor.get_leo_status()
            avg_rtt = leo_status["avg_rtt_ms"]

            # Pretty-print metrics
            syn_out = (
                f"{ddos_results['syn_ratio'] * 100:4.1f}%"
                if ddos_results["syn_ratio"] is not None
                else " N/A"
            )
            udp_out = (
                f"{ddos_results['udp_rate']:5.1f} pps"
                if ddos_results["udp_rate"] is not None
                else " N/A"
            )
            icmp_out = (
                f"{ddos_results['icmp_rate']:5.1f} pps"
                if ddos_results["icmp_rate"] is not None
                else " N/A"
            )
            http_out = (
                f"{ddos_results['http_rate']:5.1f} req/s"
                if ddos_results["http_rate"] is not None
                else " N/A"
            )

            self._log(
                "Window {w:03d} | Rate: {rate:8.2f} Bps | EWMA: {ewma:8.2f} Bps | "
                "RTT: {rtt:6.1f}ms | SYN: {syn} | UDP: {udp} | "
                "ICMP: {icmp} | HTTP: {http} | State: {state:>8}".format(
                    w=self.window_count,
                    rate=instantaneous_rate,
                    ewma=new_ewma,
                    rtt=avg_rtt,
                    syn=syn_out,
                    udp=udp_out,
                    icmp=icmp_out,
                    http=http_out,
                    state=leo_status["state"],
                )
            )

            # 3. “Mitigation” (virtual) decisions

            if ddos_suspected:
                # DDoS wins over congestion
                self.is_ddos_active = True
                self._log(f"*** DDoS ALERT *** Suspected {alert_type}.")
                self.limiter.apply_limit(DDoS_RATE_LIMIT_MBPS)

            elif congestion_alert:
                # Congestion only; apply standard limit
                self.is_ddos_active = False
                self._log(f"--> {congestion_alert}")
                self.limiter.apply_limit(DEFAULT_RATE_LIMIT_MBPS)

            elif self.limiter.limit_active:
                # Clear virtual limit once everything looks safe again

                syn_safe = (
                    ddos_results["syn_ratio"] is None
                    or ddos_results["syn_ratio"] < (self.ddos_detector.syn_ratio_threshold * 0.5)
                )
                udp_safe = (
                    ddos_results["udp_rate"] is None
                    or ddos_results["udp_rate"] < (self.ddos_detector.udp_rate_threshold * 0.5)
                )
                icmp_safe = (
                    ddos_results["icmp_rate"] is None
                    or ddos_results["icmp_rate"] < (self.ddos_detector.icmp_rate_threshold * 0.5)
                )
                http_safe = (
                    ddos_results["http_rate"] is None
                    or ddos_results["http_rate"] < (self.ddos_detector.http_rate_threshold * 0.5)
                )
                all_ddos_safe = syn_safe and udp_safe and icmp_safe and http_safe

                if self.is_ddos_active and all_ddos_safe:
                    self.limiter.clear_limit()
                    self.is_ddos_active = False
                    self.monitor.leo_state = "normal"

                elif (
                    not self.is_ddos_active
                    and instantaneous_rate < (self.monitor.ewma * 1.1)
                    and leo_status["state"] == "recovering"
                ):
                    self.limiter.clear_limit()
                    self.monitor.leo_state = "normal"

            # 4. CSV logging for this window
            if self.csv_writer is not None:
                try:
                    syn_ratio_csv = ddos_results["syn_ratio"] if ddos_results["syn_ratio"] is not None else ""
                    udp_rate_csv = ddos_results["udp_rate"] if ddos_results["udp_rate"] is not None else ""
                    icmp_rate_csv = ddos_results["icmp_rate"] if ddos_results["icmp_rate"] is not None else ""
                    http_rate_csv = ddos_results["http_rate"] if ddos_results["http_rate"] is not None else ""
                    congestion_alert_flag = 1 if congestion_alert else 0

                    self.csv_writer.writerow([
                        self.window_count,
                        current_time,
                        bytes_in_window,
                        time_elapsed,
                        instantaneous_rate,
                        new_ewma,
                        avg_rtt,
                        leo_status["state"],
                        leo_status["consecutive_anomalies"],
                        leo_status["current_multiplier"],
                        syn_ratio_csv,
                        udp_rate_csv,
                        icmp_rate_csv,
                        http_rate_csv,
                        int(ddos_results["syn_suspected"]),
                        int(ddos_results["udp_suspected"]),
                        int(ddos_results["icmp_suspected"]),
                        int(ddos_results["http_suspected"]),
                        int(ddos_suspected),
                        alert_type,
                        congestion_alert_flag,
                        int(self.limiter.limit_active),
                        self.limiter.current_rate_mbps,
                        int(self.is_ddos_active),
                    ])
                    if self.csv_file is not None:
                        self.csv_file.flush()
                except Exception as e:
                    self._log(f"[ERROR] Failed to write CSV stats: {e}")

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2.0)
        self._log("[LEO Monitor] Stopped.")


# ---------------------------------------------------------------------------
# 7. Engine-style API used by gateway_detector
# ---------------------------------------------------------------------------

_ENGINE: Optional[LEOLiveMonitorState] = None
_ENGINE_LOCK = threading.Lock()


def init_leo_engine(
    log_file: Optional[TextIO],
    window_size: float = TIME_WINDOW_SECONDS,
    csv_file: Optional[TextIO] = None,
):
    """
    Initialize the LEO-aware monitoring engine and return a packet callback
    suitable for Scapy's sniff(prn=...) argument.

    Args:
        log_file: Text file object for human-readable log lines.
        window_size: Aggregation window in seconds.
        csv_file: Optional text file object for per-window CSV statistics.
    """
    global _ENGINE

    with _ENGINE_LOCK:
        if _ENGINE is not None:
            return _ENGINE.packet_callback

        monitor = LEO_EWMA_Monitor(
            alpha=EWMA_ALPHA,
            threshold_multiplier=THRESHOLD_MULTIPLIER,
            typical_rtt_ms=LEO_TYPICAL_RTT_MS,
        )

        # Virtual rate limiter that logs actions
        # Logging function will be stitched in after we know log_file.
        def _limiter_log(msg: str):
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            line = f"{ts} {msg}"
            if log_file is not None:
                try:
                    log_file.write(line + "\n")
                except Exception:
                    pass
            print(line)

        limiter = VirtualRateLimiter(log=_limiter_log)

        ddos_detector = DDoSDetection(
            syn_ratio_threshold=DDoS_SYN_RATIO_THRESHOLD,
            min_packets=DDoS_MIN_PACKETS_PER_WINDOW,
            udp_rate_threshold=DDoS_UDP_RATE_THRESHOLD,
            icmp_rate_threshold=DDoS_ICMP_RATE_THRESHOLD,
            http_rate_threshold=DDoS_HTTP_RATE_THRESHOLD,
        )

        _ENGINE = LEOLiveMonitorState(
            monitor=monitor,
            limiter=limiter,
            ddos_detector=ddos_detector,
            window_size=window_size,
            log_file=log_file,
            csv_file=csv_file,
        )
        _ENGINE.start()

        return _ENGINE.packet_callback


def shutdown_leo_engine() -> None:
    """Stop the background monitoring thread (if running)."""
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is not None:
            _ENGINE.stop()
            _ENGINE = None

