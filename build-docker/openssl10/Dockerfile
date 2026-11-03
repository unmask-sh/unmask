# Builder image for the OpenSSL 1.0 ABI plugin .so (= CentOS 7 / RHEL 7 /
# Oracle Linux 7 and other libcrypto.so.10 hosts).  x86_64 only: this ABI
# has no arm64 install base.
#
# CentOS 7 reached end of life on 2024-06-30 and its mirror network was
# retired, so the stock repo files are pointed at vault.centos.org, the
# frozen 7.9.2009 tree.  The mirror is read over http, which this 2020 TLS
# stack reaches without trouble; gpgcheck stays on, so yum verifies every
# package against the CentOS 7 key the base image carries.
#
# The base image is pinned by digest.  The tag no longer moves, and a rebuild
# from this file has to produce the toolchain the shipped modules were linked
# with -- gcc 4.8, OpenSSL 1.0.2k, glibc 2.17 -- not whatever the tag
# resolves to one day.
#
#   docker build --platform=linux/amd64 -t unmask-builder-openssl10 build-docker/openssl10/
#   docker run --rm --platform=linux/amd64 -v "$PWD:/work" unmask-builder-openssl10 <nginx-version>
#
# `make build-module-multi-openssl10` does both, for every shipped version.
FROM centos:7@sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4
RUN sed -i -e 's|^mirrorlist=|#mirrorlist=|g' \
           -e 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' \
           /etc/yum.repos.d/CentOS-*.repo \
    && yum install -y --setopt=tsflags=nodocs \
        gcc make wget tar perl \
        openssl-devel pcre-devel zlib-devel \
    && yum clean all
WORKDIR /work
COPY build-one.sh /usr/local/bin/build-one.sh
RUN chmod 0755 /usr/local/bin/build-one.sh
ENTRYPOINT ["/usr/local/bin/build-one.sh"]
