# Builder image for the glibc 2.12 / OpenSSL 1.0 ABI plugin .so (= CentOS 6 /
# RHEL 6 hosts).  x86_64 only: CentOS 6 never had an aarch64 build.
#
# CentOS 6 reached end of life on 2020-11-30 and vault.centos.org no longer
# carries it, so the repositories come from the kernel.org mirror of the
# vault (the frozen 6.10 tree).  The stock repo files are replaced because
# they name mirrors that are gone.  The mirror is read over http -- this
# 2018 TLS stack and CA bundle do not reach today's HTTPS sites -- and
# gpgcheck is on, so yum verifies every package against the CentOS 6 key the
# base image carries.
#
# The base image is pinned by digest.  The tag no longer moves, and a rebuild
# from this file has to produce the toolchain the shipped modules were linked
# with -- gcc 4.4, OpenSSL 1.0.1e, glibc 2.12 -- not whatever the tag
# resolves to one day.
#
#   docker build --platform=linux/amd64 -t unmask-builder-centos6 build-docker/centos6/
#   docker run --rm --platform=linux/amd64 -v "$PWD:/work" unmask-builder-centos6 <nginx-version>
#
# `make build-module-multi-glibc212` does both, for every shipped version.
FROM centos:6@sha256:a93df2e96e07f56ea48f215425c6f1673ab922927894595bb5c0ee4c5a955133
RUN rm -f /etc/yum.repos.d/*.repo \
    && printf '%s\n' \
        '[base]' \
        'name=CentOS-6 Base' \
        'baseurl=http://archive.kernel.org/centos-vault/6.10/os/x86_64/' \
        'gpgcheck=1' \
        'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6' \
        'enabled=1' \
        '' \
        '[updates]' \
        'name=CentOS-6 Updates' \
        'baseurl=http://archive.kernel.org/centos-vault/6.10/updates/x86_64/' \
        'gpgcheck=1' \
        'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6' \
        'enabled=1' \
        '' \
        '[extras]' \
        'name=CentOS-6 Extras' \
        'baseurl=http://archive.kernel.org/centos-vault/6.10/extras/x86_64/' \
        'gpgcheck=1' \
        'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-6' \
        'enabled=1' \
        > /etc/yum.repos.d/centos6-archive.repo \
    && yum install -y --setopt=tsflags=nodocs \
        gcc make wget tar perl \
        openssl-devel pcre-devel zlib-devel \
    && yum clean all
WORKDIR /work
COPY build-one.sh /usr/local/bin/build-one.sh
RUN chmod 0755 /usr/local/bin/build-one.sh
ENTRYPOINT ["/usr/local/bin/build-one.sh"]
