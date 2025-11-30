# LEO-Aware IoT DDoS Detection Testbed
A Docker-Based Satellite Network Simulation with Userspace LEO Link Modeling and DDoS Detection

## Overview
This project provides a fully containerized testbed for **IoT DDoS detection over Low Earth Orbit (LEO) satellite networks**. It simulates:

- Replay of real IoT traffic
- A gateway performing:
  - Userspace LEO link emulation (delay, jitter, packet loss)
  - LEO-aware congestion detection
  - Multi-protocol DDoS detection (SYN/UDP/ICMP/HTTP floods)
- Logging of detection events and virtual mitigation decisions

No kernel-level shaping, NFQUEUE, or `tc/netem` are used — the entire LEO link model and detection logic run **purely in userspace**.

## System Architecture

### Docker Services
```
traffic-lab
 └─ Replays PCAPs using replay_pcap.py
 └─ IP: 172.28.10.10

gateway
 └─ Sniffer + LEO emulator + detection engine
 └─ IP: 172.28.10.20
 └─ Runs gateway_detector.py + detection_algo.py
```

### Docker Network
```
iot_local (bridge, internal)
 └─ Subnet: 172.28.10.0/24
```

## Directory Structure
```
traffic-lab/
  scripts/
    replay_pcap.py
  datasets/
    iot_23_small/...

gateway/
  detector/
    gateway_detector.py
    detection_algo.py
  Dockerfile
```

## Userspace LEO Link Model
Implemented inside `gateway_detector.py`, the `LEOLink` class simulates:

| Parameter | Meaning |
|----------|---------|
| `LEO_DELAY = 0.045s` | Base one-way propagation delay (45 ms) |
| `LEO_JITTER = 0.015s` | ±15 ms jitter |
| `LEO_LOSS_PROB = 0.05` | 5% packet loss |

## Detection Engine (LEO-Aware)

### 1. EWMA Congestion Monitor
- LEO-tuned EWMA smoothing
- Dynamic thresholds using RTT inflation
- States: `normal → congested → recovering → normal`
- Burst allowance for natural LEO traffic spikes

### 2. RTTMonitor
- Estimates RTT via SYN → SYN-ACK handshake timing
- RTT inflation dynamically tightens congestion thresholds

### 3. DDoS Sub-detectors
Detects per-window flood patterns:
- SYN Flood
- UDP Flood
- ICMP Flood
- HTTP Request Flood (simple GET/POST/HEAD parsing)

### 4. Virtual Rate Limiter
- Logs mitigation actions
- Does not modify kernel qdiscs

### 5. LEOLiveMonitorState
- Central orchestrator linking all modules
- Receives packets from sniffer
- Updates RTT, EWMA, and DDoS statistics
- Logs per-window metrics
- Applies virtual mitigations

## Getting Started

### 1. Build and Start Docker
```
docker-compose down -v
docker-compose up --build -d
```

### 2. Start Gateway Detector
```
docker exec -it gateway bash
cd /opt/detector
python3 gateway_detector.py --iface eth0 --log-file /opt/detector/gateway_detector.log
```

### 3. Replay IoT Traffic
```
docker exec -it traffic-lab bash
replay_pcap.py /pcaps/iot_23_small/<file>.pcap --iface eth0 --pps 400 --src-ip 172.28.10.10 --dst-ip 172.28.10.20
```

### 4. Monitor Logs
```
docker exec -it gateway bash
cd /opt/detector
tail -f gateway_detector.log
```

## Log Examples

### Normal Window
```
Window 005 | Rate: 4200 Bps | EWMA: 3100 Bps | RTT: 112 ms | SYN: 5% | UDP: 50 pps | ICMP: 0 pps | HTTP: 0 req/s | State: normal
```

### LEO Congestion
```
--> LEO CONGESTION! Rate=30000 Bps > UCL=15500 Bps for 3 windows.
[VIRTUAL MITIGATION] Set rate limit to 5.0 Mbps
```

### DDoS Detection
```
*** DDoS ALERT *** Suspected SYN Flood.
[VIRTUAL MITIGATION] Set rate limit to 1.0 Mbps
```

## Novel Features
- Traffic runs through a userspace LEO link emulator (delay + jitter + loss)
- EWMA thresholds adapt to LEO RTT inflation
- DDoS detection is interpreted in the context of satellite congestion
- Fully Dockerized reproducible environment
- No reliance on tc, NFQUEUE, or kernel qdiscs
- Clean module-based detection architecture suitable for research writeups

