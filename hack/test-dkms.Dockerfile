FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dkms build-essential linux-headers-generic && \
    rm -rf /var/lib/apt/lists/*

COPY src/ /usr/src/lbd-0.1.0/

# Resolve the installed kernel headers version (no running kernel in Docker)
RUN KVER=$(ls /lib/modules) && \
    dkms add lbd/0.1.0 && \
    dkms build lbd/0.1.0 -k "$KVER" && \
    dkms status
