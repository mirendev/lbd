ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG INSTALL_CMD
RUN ${INSTALL_CMD}

COPY src/ /usr/src/lbd-0.1.0/

RUN KVER=$(ls /lib/modules) && \
    dkms add lbd/0.1.0 && \
    dkms build lbd/0.1.0 -k "$KVER" && \
    mkdir /out && \
    cp /var/lib/dkms/lbd/0.1.0/$KVER/*/module/lbd.ko* /out/
