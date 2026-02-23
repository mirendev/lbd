FROM fedora:40

RUN dnf install -y dkms gcc make kernel-devel rpm-build && \
    dnf clean all

COPY src/ /build/src/
COPY packaging/ /build/packaging/

# Build the RPM
RUN cd /build && packaging/build-rpm.sh

# Install the RPM (post script tries to build for uname -r which has no
# headers in Docker — that's expected, dkms add still succeeds)
RUN rpm -ivh /build/dist/lbd-dkms-0.1.0-1.*.noarch.rpm

# Verify: source installed to /usr/src, DKMS registered
RUN test -f /usr/src/lbd-0.1.0/dkms.conf && \
    test -f /usr/src/lbd-0.1.0/Makefile && \
    test -f /usr/src/lbd-0.1.0/lbd_main.c && \
    test -f /usr/src/lbd-0.1.0/lz4/lz4.c && \
    dkms status | grep "lbd.*0.1.0.*added"

# Verify: RPM tracks all files, clean uninstall removes them
RUN rpm -ql lbd-dkms | head -20 && \
    rpm -e lbd-dkms && \
    ! test -d /usr/src/lbd-0.1.0

# Note: kernel module compilation is validated by the .deb test against
# Ubuntu 24.04 (kernel 6.8). Fedora's rolling kernel-devel (6.14+) has
# API changes that require porting work beyond the packaging scope.
