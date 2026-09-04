# Minimal SONiC library builder container (Debian 12 "bookworm")
#
# The full sonic-slave-bookworm dev image is ~10GB and needs far more RAM
# than this host has (8GB). This image contains exactly the toolchain
# needed to build the SONiC debs that sai_cap_query links against:
#     libnl-3, libyang, libswsscommon, libsairedis(+libsaimeta/libsaimetadata)
#
# It is used by ../build_in_mini.sh together with the canonical
# `make -f slave.mk` deb rules from sonic-buildimage.
FROM debian:bookworm

# The official sonic-slave-bookworm image ships this so that pip can install
# into the system site-packages (PEP 668)
RUN printf '[global]\nbreak-system-packages = true\n' > /etc/pip.conf

ENV DEBIAN_FRONTEND=noninteractive

# Use the Microsoft Debian mirror (same as the official sonic-slave image);
# direct deb.debian.org access is very slow from this network.
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf 'deb [arch=amd64] http://debian-archive.trafficmanager.net/debian/ bookworm main contrib non-free-firmware\ndeb [arch=amd64] http://debian-archive.trafficmanager.net/debian/ bookworm-updates main contrib non-free-firmware\ndeb [arch=amd64] http://debian-archive.trafficmanager.net/debian-security/ bookworm-security main contrib non-free-firmware\n' > /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        make \
        autoconf \
        autoconf-archive \
        automake \
        libtool \
        m4 \
        perl \
        python3 \
        python3-dev \
        python3-pip \
        python3-wheel \
        python3-setuptools \
        swig \
        quilt \
        patch \
        diffutils \
        stgit \
        devscripts \
        debhelper \
        dpkg-dev \
        fakeroot \
        dh-exec \
        sudo \
        ca-certificates \
        lsb-release \
        lsof \
        wget \
        curl \
        git \
        make \
        texinfo \
        libssl-dev \
        zlib1g-dev \
        libzmq5-dev \
        libhiredis-dev \
        libboost-dev \
        libboost-serialization-dev \
        libgtest-dev \
        libgmock-dev \
        nlohmann-json3-dev \
        libpcre2-dev \
        gperf \
        libedit-dev \
        libcap-dev \
        bison \
        flex \
        libpcre3-dev \
        autogen \
        help2man \
        libxml2-dev \
        cmake \
        doxygen \
        graphviz \
        libcmocka-dev \
        libxxhash-dev \
        tcl-expect \
        tclsh \
        dh-python \
        python3-all-dev \
        python3-cffi \
        cython3 \
        default-libmysqlclient-dev \
        libperl-dev \
        libpci-dev \
        libpci3 \
        libsensors5 \
        libsensors4-dev \
        libwrap0-dev \
        libc-ares-dev \
        libjson-c-dev \
        libsystemd-dev \
        libprotobuf-c-dev \
        protobuf-c-compiler \
        python3-all-dbg \
        install-info \
        logrotate \
        git-buildpackage \
        cdbs \
        bc \
        libxml-simple-perl \
        aspell \
        aspell-en \
        chrpath \
        gawk \
        libelf-dev \
        libpam0g-dev \
        libreadline-dev \
        python3-pytest \
        python3-sphinx \
        librtr-dev \
        libssh-dev \
        python3-build \
        rustc \
        cargo \
        uuid-dev \
        libzmq3-dev \
        cppzmq-dev \
        iproute2 \
        lockfile-progs \
        debian-keyring \
        debian-archive-keyring \
    && rm -rf /var/lib/apt/lists/*

# NOTE: bookworm split the zmq C++ header out of libzmq3-dev into the
# cppzmq-dev package (provides /usr/include/zmq.hpp), which is what
# sonic-swss-common's unit tests include.

# dget (used by the libnl3 build rule) verifies .dsc signatures against the
# system keyrings in /usr/share/keyrings
RUN cp -n /etc/apt/trusted.gpg.d/*.gpg /usr/share/keyrings/ 2>/dev/null || true

# some build rules do `git init && git commit` on extracted sources
RUN git config --global user.email "sonic-build@localhost" \
    && git config --global user.name "SONiC Build" \
    && git config --global init.defaultBranch master

# "For sonic_yang_model build" in the official slave image:
# pyang also installs IETF yang models to /usr/local/share/yang/modules/ietf
RUN pip3 install pyang==2.4.0

# wheel builds run `python3 -m build -n` (--no-build-isolation),
# so the PEP 517 build requires must be preinstalled (official slave does this too)
RUN pip3 install pytest-runner==5.2

# bookworm's distro rustc (1.63) is too old for current crates (e.g. quote
# needs >=1.71). The official slave image uses rustup too; mirror that.
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && ln -sf /root/.cargo/bin/rustc /usr/local/bin/rustc \
    && ln -sf /root/.cargo/bin/cargo /usr/local/bin/cargo \
    && rustc --version

WORKDIR /sonic
