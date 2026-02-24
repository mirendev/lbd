ARG BASE_IMAGE
FROM ${BASE_IMAGE}

RUN if command -v apt-get >/dev/null; then \
      apt-get update && apt-get install -y --no-install-recommends dkms build-essential linux-headers-generic; \
    elif command -v dnf >/dev/null; then \
      dnf install -y dkms gcc make kernel-devel && \
      KVER=$(ls /usr/src/kernels/) && \
      mkdir -p /lib/modules/$KVER && \
      ln -s /usr/src/kernels/$KVER /lib/modules/$KVER/build; \
    fi

COPY src/ /usr/src/lbd-0.1.0/

RUN KVER=$(ls /lib/modules) && \
    dkms add lbd/0.1.0 && \
    dkms build lbd/0.1.0 -k "$KVER" && \
    mkdir /out && \
    cp /var/lib/dkms/lbd/0.1.0/$KVER/*/module/lbd.ko* /out/ && \
    echo "$KVER" > /out/KVER
