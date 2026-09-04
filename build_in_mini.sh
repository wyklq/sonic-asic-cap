#!/bin/bash
#
# build_in_mini.sh
#
# 在最小化 bookworm 构建容器里, 用 sonic-buildimage 的标准 slave.mk 规则
# 编译 SONiC SAI Redis 客户端库 (libswsscommon / libsaimeta / libsaimetadata
# / libsairedis 及其依赖 libnl-3 / libyang), 然后把所有运行期 .so 收集到
# ./lib, 最后在宿主机上编译 sai_cap_query。
#
# 为什么不用完整的 sonic-slave-bookworm 镜像:
#   该镜像 ~10GB, 构建过程 (2000+ 包的 apt 层) 在 8GB 内存的机器上会 OOM。
#   本脚本只用它编译我们的 C/C++ 组件所需的最小工具链, 结果完全等价
#   (同样的 Debian 12 工具链, 同样的源码与构建规则)。
#
# 用法:  ./build_in_mini.sh
#
set -eo pipefail
export PATH="$PATH:$HOME/.local/bin"

BUILDIR=/home/y20wu/SONiC/sonic-buildimage
DEVDIR=$(cd "$(dirname "$0")" && pwd)
MINI_IMAGE=sonic-mini-builder:bookworm
DEBS=target/debs/bookworm
LIBSAIREDIS_DEB=libsairedis_1.0.0_amd64.deb
LIBSWSSCOMMON_DEB=libswsscommon_1.0.0_amd64.deb
MAKE_JOBS=${MAKE_JOBS:-4}

cd "$BUILDIR"

# --- 0. 前置状态文件 (正常由 make configure 生成, 这里直接写入) ------------
[ "$(cat .platform 2>/dev/null)" = "vs" ]    || echo "vs"    > .platform
[ "$(cat .arch 2>/dev/null)" = "amd64" ]     || echo "amd64" > .arch

# SAI 子模块必须已 checkout
if [ ! -f src/sonic-sairedis/SAI/inc/sai.h ]; then
    (cd src/sonic-sairedis && git submodule update --init --force SAI)
fi

# --- 1. 构建最小构建容器 ----------------------------------------------------
if ! docker image inspect "$MINI_IMAGE" >/dev/null 2>&1; then
    echo "==> 构建最小构建容器 $MINI_IMAGE ..."
    docker build -t "$MINI_IMAGE" "$DEVDIR/mini-builder"
fi

# --- 2. 容器内用标准规则构建 debs -------------------------------------------
# 注意: 不能每次都跑 `configure` —— 它无条件重写 .platform/.arch,
# 时间戳变新会让所有已构建的 deb 判定过期、全部重编。
# 目录结构只需引导一次。
if [ ! -d target/debs/bookworm ]; then
    echo "==> 首次运行: 引导目录结构 ..."
    docker run --rm --privileged \
        -v "$BUILDIR:/sonic" -w /sonic \
        "$MINI_IMAGE" \
        bash -c "mkdir -p /dpkg_cache && chmod 777 /dpkg_cache && \
            make -f slave.mk PLATFORM=vs BLDENV=bookworm configure"
fi

# 防御: 宿主机上清理残留的 libnl3 展开源码 (容器内 rm -rf 在 WSL2 上偶发失败)
rm -rf "$BUILDIR/src/libnl3/libnl3-3.7.0" 2>/dev/null || true

echo "==> 在容器内构建 $DEBS/$LIBSAIREDIS_DEB (含全部依赖, 已构建的会自动跳过) ..."
docker run --rm --privileged \
    -v "$BUILDIR:/sonic" -w /sonic \
    "$MINI_IMAGE" \
    bash -c "mkdir -p /dpkg_cache && chmod 777 /dpkg_cache && \
        make -f slave.mk PLATFORM=vs BLDENV=bookworm \
        SONIC_CONFIG_MAKE_JOBS=$MAKE_JOBS \
        $DEBS/$LIBSAIREDIS_DEB"

# --- 3. 收集运行期共享库到 ./lib --------------------------------------------
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "==> 从构建产物 debs 提取共享库 ..."
dpkg-deb -x "$DEBS/$LIBSAIREDIS_DEB"   "$STAGE"
dpkg-deb -x "$DEBS/$LIBSWSSCOMMON_DEB" "$STAGE"
for d in "$DEBS"/libnl-3-200_*.deb \
         "$DEBS"/libnl-genl-3-200_*.deb \
         "$DEBS"/libnl-route-3-200_*.deb \
         "$DEBS"/libnl-nf-3-200_*.deb \
         "$DEBS"/libnl-cli-3-200_*.deb \
         "$DEBS"/libyang_1*.deb; do
    [ -e "$d" ] && dpkg-deb -x "$d" "$STAGE"
done

mkdir -p "$DEVDIR/lib"
cp -a "$STAGE"/usr/lib/x86_64-linux-gnu/. "$DEVDIR/lib/"

echo "==> 从容器拷贝系统运行库 (zmq/hiredis) ..."
docker run --rm -v "$DEVDIR/lib:/out" "$MINI_IMAGE" bash -c '
    cd /usr/lib/x86_64-linux-gnu
    for f in libzmq.so.5* libhiredis.so*; do
        [ -e "$f" ] || continue
        if [ -L "$f" ]; then cp -P "$f" /out/; else cp "$f" /out/; fi
    done'

echo "==> ./lib 内容:"
ls -la "$DEVDIR/lib"

# --- 4. 宿主机上编译工具 -----------------------------------------------------
echo "==> 编译 sai_cap_query ..."
make -C "$DEVDIR" clean all

echo
echo "运行期依赖检查:"
ldd "$DEVDIR/sai_cap_query" | sed 's/^/    /'
echo
echo "完成。运行示例: $DEVDIR/sai_cap_query 0x21000000000000"
