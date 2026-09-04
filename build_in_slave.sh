#!/bin/bash
#
# build_in_slave.sh
#
# 1) Builds the SONiC SAI Redis client stack inside the sonic-slave-bookworm
#    dev container (the canonical SONiC build environment):
#        libswsscommon, libnl-3, libyang, libsaimeta, libsaimetadata, libsairedis
# 2) Collects all resulting runtime shared libraries into ./lib
# 3) Compiles sai_cap_query against them (host g++, headers in ./include/sai)
#
# Prerequisite: the slave dev image must already be built:
#     cd /home/y20wu/SONiC/sonic-buildimage
#     make configure PLATFORM=vs BLDENV=bookworm NOTRIXIE=1
#
set -eo pipefail
export PATH="$PATH:$HOME/.local/bin"

BUILDIR=/home/y20wu/SONiC/sonic-buildimage
DEVDIR=$(cd "$(dirname "$0")" && pwd)
DEBS=target/debs/bookworm
LIBSAIREDIS_DEB=libsairedis_1.0.0_amd64.deb
LIBSWSSCOMMON_DEB=libswsscommon_1.0.0_amd64.deb

cd "$BUILDIR"

# --- 1. Resolve the dev container image name:tag --------------------------
SLAVE_IMAGE=$(make showtag BLDENV=bookworm NOTRIXIE=1 2>/dev/null | head -1)
if [ -z "$SLAVE_IMAGE" ]; then
    echo "ERROR: could not resolve the slave dev image. Run:" >&2
    echo "  cd $BUILDIR && make configure PLATFORM=vs BLDENV=bookworm NOTRIXIE=1" >&2
    exit 1
fi
echo "==> Using dev container image: $SLAVE_IMAGE"

# The SAI submodule of sonic-sairedis must be checked out
if [ ! -f src/sonic-sairedis/SAI/meta/saibuild.xml ]; then
    echo "==> Initializing SAI submodule of sonic-sairedis ..."
    (cd src/sonic-sairedis && git submodule update --init SAI)
fi

# --- 2. Build the SONiC debs inside the dev container ---------------------
echo "==> Building $LIBSAIREDIS_DEB (and dependencies) inside the dev container ..."
docker run --rm --privileged \
    -v "$BUILDIR:/sonic" -w /sonic \
    "$SLAVE_IMAGE" \
    bash -c "make -f slave.mk PLATFORM=vs $DEBS/$LIBSAIREDIS_DEB"

# --- 3. Collect runtime shared libraries into ./lib -----------------------
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "==> Extracting built libraries ..."
dpkg-deb -x "$DEBS/$LIBSAIREDIS_DEB"      "$STAGE"
dpkg-deb -x "$DEBS/$LIBSWSSCOMMON_DEB"    "$STAGE"
for d in "$DEBS"/libnl-3-200_*.deb \
         "$DEBS"/libnl-genl-3-200_*.deb \
         "$DEBS"/libnl-route-3-200_*.deb \
         "$DEBS"/libnl-nf-3-200_*.deb \
         "$DEBS"/libnl-cli-3-200_*.deb \
         "$DEBS"/libyang_*.deb; do
    [ -e "$d" ] && dpkg-deb -x "$d" "$STAGE"
done

mkdir -p "$DEVDIR/lib"
cp -a "$STAGE"/usr/lib/x86_64-linux-gnu/. "$DEVDIR/lib/"

echo "==> Copying system runtime deps (zmq/hiredis) from the dev container ..."
docker run --rm -v "$DEVDIR/lib:/out" "$SLAVE_IMAGE" bash -c '
    cd /usr/lib/x86_64-linux-gnu
    for f in libzmq.so.5* libhiredis.so*; do
        [ -e "$f" ] || continue
        if [ -L "$f" ]; then cp -P "$f" /out/; else cp "$f" /out/; fi
    done'

echo "==> Libraries collected into $DEVDIR/lib:"
ls -la "$DEVDIR/lib"

# --- 4. Compile the tool ---------------------------------------------------
echo "==> Compiling sai_cap_query ..."
make -C "$DEVDIR" clean all

echo
echo "Done. Runtime dependencies:"
ldd "$DEVDIR/sai_cap_query" | sed 's/^/    /'
echo
echo "Run it (example):  $DEVDIR/sai_cap_query 0x21000000000000"
