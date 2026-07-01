# Builder image for the OpenSSL 1.1 ABI plugin .so (= AlmaLinux 8 / RHEL 8,
# Debian 11, Ubuntu 20.04, Amazon Linux 2, and other libssl.so.1.1 hosts).
#
# AlmaLinux 8 ships OpenSSL 1.1.1 and has both amd64 + aarch64 base images, so
# the same Dockerfile builds an arm64 builder under `docker build --platform`.
# build-one.sh writes to dist/multi-modules-openssl11[-<arch>]/ keyed off the
# container's own uname -m, so one recipe serves both arches.
FROM almalinux:8
RUN dnf install -y --setopt=tsflags=nodocs \
        gcc make wget tar perl-interpreter \
        openssl-devel pcre-devel zlib-devel \
    && dnf clean all
WORKDIR /work
COPY build-one.sh /usr/local/bin/build-one.sh
RUN chmod 0755 /usr/local/bin/build-one.sh
ENTRYPOINT ["/usr/local/bin/build-one.sh"]
