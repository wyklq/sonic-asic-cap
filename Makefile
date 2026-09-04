# Makefile for sai_cap_query
#
# 头文件:  include/sai/ + SAI/meta/ (SAI v1.17.x, 与 lib 中的库配套)
# 库文件:  lib/           (libsairedis / libsaimeta / libsaimetadata /
#                         libswsscommon / libnl-3 系列 / libzmq / libhiredis ...)
#
# lib/ 的生成流程 (本机 7G 内存, 用 mini 容器):
#   1. docker build -t sonic-mini-builder:bookworm mini-builder
#   2. ./build_in_mini.sh          # 构建 libswsscommon / libnl3 / libyang / frr 等 debs
#   3. ./build_sairedis_direct.sh  # 直建 sairedis (跳过 DASH-SAI/p4lang 依赖链)
#   4. 从 debs + 容器里把 .so 收集到 lib/ (见下方备注)
#   高内存机器可用 ./build_in_slave.sh 走完整 slave 镜像。
#
# 链接说明:
#   -rpath,$ORIGIN/lib  + --disable-new-dtags:  运行时从 lib/ 找库,
#     用 DT_RPATH(而非 RUNPATH) 使其对传递依赖 (libswsscommon 等) 也生效。
#   -rpath-link,lib:    链接期解析 libsairedis 的 NEEDED 链。
#   -lsaimeta -lsaimetadata: libsairedis 的 sai_serialize_*/saimeta::* 符号
#     由这两个库提供 (官方 deb 也不在 libsairedis 的 Depends 里, 使用方需显式链接)。
#
CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
CPPFLAGS := -Iinclude/sai -ISAI/meta
LDFLAGS  := -Llib -Wl,-rpath,'$$ORIGIN/lib' -Wl,--disable-new-dtags -Wl,-rpath-link,lib
LIBS     := -lsairedis -lsaimeta -lsaimetadata

TARGET   := sai_cap_query
SRC      := sai_cap_query.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)
