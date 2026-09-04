#!/bin/bash
# ============================================================================
# 直接构建 sonic-sairedis (跳过 slave.mk 里 libsairedis -> libsai(DASH) ->
# p4lang 的依赖链 —— 那条链要编译整个 P4 工具链, 与本工具无关)。
#
# sairedis 的 dpkg 构建本身只依赖 libswsscommon-dev (已安装) +
# SAI 头文件 (src/sonic-sairedis/SAI 子模块, v1.17.5)。
#
# 前置: build_in_mini.sh 已经跑过且 libswsscommon/libswsscommon-dev 已安装。
# ============================================================================
set -euo pipefail

BUILDIR=/home/y20wu/SONiC/sonic-buildimage
MINI_IMAGE=sonic-mini-builder:bookworm
MAKE_JOBS=4

echo "==> 1/3 在容器内直接 dpkg-buildpackage sonic-sairedis ..."
docker run --rm --privileged \
    -v "$BUILDIR:/sonic" -w /sonic/src/sonic-sairedis \
    "$MINI_IMAGE" \
    bash -c "
        set -euo pipefail
        # 容器是临时的: 把前面构建好的依赖 debs 装进来
        dpkg -i /sonic/target/debs/bookworm/libnl-3-200_*.deb \
                /sonic/target/debs/bookworm/libnl-genl-3-200_*.deb \
                /sonic/target/debs/bookworm/libnl-route-3-200_*.deb \
                /sonic/target/debs/bookworm/libnl-nf-3-200_*.deb \
                /sonic/target/debs/bookworm/libnl-cli-3-200_*.deb \
                /sonic/target/debs/bookworm/libnl-3-dev_*.deb \
                /sonic/target/debs/bookworm/libnl-genl-3-dev_*.deb \
                /sonic/target/debs/bookworm/libnl-route-3-dev_*.deb \
                /sonic/target/debs/bookworm/libnl-nf-3-dev_*.deb \
                /sonic/target/debs/bookworm/libnl-cli-3-dev_*.deb \
                /sonic/target/debs/bookworm/libyang_1.0.*_amd64.deb \
                /sonic/target/debs/bookworm/libyang-cpp_1.0.*_amd64.deb \
                /sonic/target/debs/bookworm/libyang-dev_1.0.*_amd64.deb \
                /sonic/target/debs/bookworm/libswsscommon_1.0.0_amd64.deb \
                /sonic/target/debs/bookworm/libswsscommon-dev_1.0.0_amd64.deb

        # 前置检查
        dpkg -s libswsscommon-dev >/dev/null 2>&1 || { echo 'ERROR: libswsscommon-dev 未安装, 请先跑 build_in_mini.sh'; exit 1; }
        test -f SAI/inc/sai.h || { echo 'ERROR: SAI 子模块缺失'; exit 1; }

        # 清掉之前的构建残留
        make distclean >/dev/null 2>&1 || true
        rm -f ../libsairedis_*.deb ../libsaivs*.deb ../libsaimetadata*.deb ../python3-pysairedis*.deb

        ./autogen.sh
        DEB_BUILD_PROFILES=\"nopython2\" DEB_BUILD_OPTIONS=\"nocheck\" \
        dpkg-buildpackage -rfakeroot -b -us -uc -tc -j$MAKE_JOBS

        # 收集产物
        mkdir -p /sonic/target/debs/bookworm
        mv ../*.deb /sonic/target/debs/bookworm/
        ls -la /sonic/target/debs/bookworm/libsairedis_*.deb
    "

echo "==> 2/3 完成。产物:"
ls -la "$BUILDIR/target/debs/bookworm/"libsairedis_*.deb "$BUILDIR/target/debs/bookworm/"libsaivs*.deb "$BUILDIR/target/debs/bookworm/"libsaimetadata*.deb 2>/dev/null

echo "==> 3/3 全部 sairedis 相关的 deb:"
ls "$BUILDIR/target/debs/bookworm/" | grep -E "libsairedis|libsaivs|libsaimetadata|pysairedis" || true
