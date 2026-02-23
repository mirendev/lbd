FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dkms build-essential linux-headers-generic dpkg-dev && \
    rm -rf /var/lib/apt/lists/*

COPY src/ /build/src/
COPY packaging/ /build/packaging/

RUN cd /build && packaging/build-deb.sh

# Install the .deb (postinst builds for uname -r which won't have headers
# in Docker — that's fine, it's a no-op with || true)
RUN dpkg -i /build/dist/lbd-dkms_0.1.0_all.deb

# Verify source was installed and DKMS registered the module
RUN test -f /usr/src/lbd-0.1.0/dkms.conf && \
    test -f /usr/src/lbd-0.1.0/Makefile && \
    test -f /usr/src/lbd-0.1.0/lbd_main.c && \
    dkms status | grep "lbd.*0.1.0.*added"

# Explicitly build for the available kernel headers
RUN KVER=$(ls /lib/modules | grep generic) && \
    dkms build lbd/0.1.0 -k "$KVER" && \
    dkms install lbd/0.1.0 -k "$KVER" && \
    dkms status | grep "lbd.*0.1.0.*installed"
