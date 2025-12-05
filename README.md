# LEO-Aware IoT DDoS Detection Testbed

A Docker-Based Satellite Network Simulation with Userspace LEO Link
Modeling and DDoS Detection

## Overview

This project provides a fully containerized testbed for **IoT DDoS
detection over Low Earth Orbit (LEO) satellite networks**. It simulates:

-   Replay of real IoT traffic
-   A gateway performing:
    -   Userspace LEO link emulation (delay, jitter, packet loss)
    -   LEO-aware congestion detection
    -   Multi-protocol DDoS detection (SYN/UDP/ICMP/HTTP floods)
-   Logging of detection events and virtual mitigation decisions

No kernel-level shaping, NFQUEUE, or `tc/netem` are used --- the entire
LEO link model and detection logic run **purely in userspace**.

## System Architecture

### Docker Services

    traffic-lab
     └─ Replays PCAPs using replay_pcap.py and replay_iot.sh
     └─ IP: 172.28.10.10

    gateway
     └─ Sniffer + LEO emulator + detection engine
     └─ IP: 172.28.10.20
     └─ Runs gateway_detector.py + detection_algo.py via start_detector.sh

### Docker Network

    iot_local (bridge, internal)
     └─ Subnet: 172.28.10.0/24

## Directory Structure

    traffic-lab/
      scripts/
        replay_pcap.py
        replay_iot.sh
      datasets/
        iot_23_small/...   # PCAP files must be manually downloaded and placed here

    gateway/
      detector/
        gateway_detector.py
        detection_algo.py
        start_detector.sh
      Dockerfile

------------------------------------------------------------------------

## Userspace LEO Link Model

Implemented inside `gateway_detector.py`, the `LEOLink` class simulates:

  Parameter                Meaning
  ------------------------ ----------------------------------------
  `LEO_DELAY = 0.045s`     Base one-way propagation delay (45 ms)
  `LEO_JITTER = 0.015s`    ±15 ms jitter
  `LEO_LOSS_PROB = 0.05`   5% packet loss

## Detection Engine (LEO-Aware)

### 1. EWMA Congestion Monitor

-   LEO-tuned EWMA smoothing\
-   Dynamic thresholds using RTT inflation\
-   States: `normal → congested → recovering → normal`\
-   Burst allowance for natural LEO traffic spikes

### 2. RTTMonitor

-   Estimates RTT via SYN → SYN-ACK handshake timing\
-   RTT inflation dynamically tightens congestion thresholds

### 3. DDoS Sub-detectors

Detects per-window flood patterns: - SYN Flood\
- UDP Flood\
- ICMP Flood\
- HTTP Request Flood (simple GET/POST/HEAD parsing)

### 4. Virtual Rate Limiter

-   Logs mitigation actions\
-   Does not modify kernel qdiscs

### 5. LEOLiveMonitorState

-   Central orchestrator linking all modules\
-   Receives packets from sniffer\
-   Updates RTT, EWMA, and DDoS statistics\
-   Logs per-window metrics\
-   Applies virtual mitigations

------------------------------------------------------------------------

# Getting Started

## Dataset Requirement

PCAP files from the **IoT-23 Dataset** cannot be stored in this GitHub
repository due to size limits.

### You must manually download the PCAP files from:

📥 **https://www.stratosphereips.org/datasets-iot23**

Then place the selected `.pcap` files into:

    traffic-lab/datasets/iot_23_small/

Example:

    traffic-lab/datasets/iot_23_small/mirai-sample.pcap

These files are required for traffic replay in the testbed.

## 1. Build and Start Docker

``` bash
docker-compose down -v
docker-compose up --build -d
```

## 2. Start the Gateway Detector

From inside the **gateway container**:

``` bash
docker exec -it gateway bash
cd /opt/detector
./start_detector.sh
```

## 3. Replay IoT Traffic

Before replaying, ensure your **PCAP files are downloaded** from the
IoT-23 dataset and placed into:

    traffic-lab/datasets/iot_23_small/

Then from inside the **traffic-lab container**:

``` bash
docker exec -it traffic-lab bash
replay_iot.sh <pcap-file-name>
```

Example:

``` bash
replay_iot.sh mirai_sample.pcap
```

## 4. Monitor Logs

From inside the **gateway container**:

``` bash
docker exec -it gateway bash
cd /opt/detector
tail -f gateway_detector.log
```

------------------------------------------------------------------------

## Log Examples

### Normal Window

    Window 005 | Rate: 4200 Bps | EWMA: 3100 Bps | RTT: 112 ms | SYN: 5% | UDP: 50 pps | ICMP: 0 pps | HTTP: 0 req/s | State: normal

### LEO Congestion

    --> LEO CONGESTION! Rate=30000 Bps > UCL=15500 Bps for 3 windows.
    [VIRTUAL MITIGATION] Set rate limit to 5.0 Mbps

### DDoS Detection

    *** DDoS ALERT *** Suspected SYN Flood.
    [VIRTUAL MITIGATION] Set rate limit to 1.0 Mbps

------------------------------------------------------------------------

## Novel Features

-   Traffic runs through a userspace LEO link emulator (delay + jitter +
    loss)\
-   EWMA thresholds adapt to LEO RTT inflation\
-   DDoS detection is interpreted in the context of satellite
    congestion\
-   Fully Dockerized reproducible environment\
-   No reliance on tc, NFQUEUE, or kernel qdiscs\
-   Clean module-based detection architecture suitable for research
    writeups

