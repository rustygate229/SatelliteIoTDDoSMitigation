# ------------------------------------------------------------
# Minimal Docker image for the gateway detector
# Python 3.11 + Scapy + NumPy + required system libs
# ------------------------------------------------------------

FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------
# Install required OS packages
# ------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        libffi-dev \
        libpcap-dev \
        build-essential \
        && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# Install Python dependencies
# ------------------------------------------------------------
# Scapy needs libpcap headers
# NumPy is required for LEO EWMA RTT logic
RUN pip install --no-cache-dir \
        scapy \
        numpy

# ------------------------------------------------------------
# Detector code lives in /opt/detector
# (docker-compose mounts ./gateway/detector → /opt/detector)
# ------------------------------------------------------------
WORKDIR /opt/detector

# ------------------------------------------------------------
# Keep container alive; you run gateway_detector.py manually
# inside the container (docker exec)
# ------------------------------------------------------------
CMD ["tail", "-f", "/dev/null"]

