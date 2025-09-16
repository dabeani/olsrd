#!/bin/bash

ARCH="edgerouter"

# Path to musl cross-compiler
MUSL_PREFIX=/olsrd-output/compiler/musl-cross-make/output/bin
export CC=$MUSL_PREFIX/mipsel-linux-musl-gcc
export CXX=$MUSL_PREFIX/mipsel-linux-musl-g++
export AR=$MUSL_PREFIX/mipsel-linux-musl-gcc-ar
export LD=$MUSL_PREFIX/mipsel-linux-musl-ld

# Work from the repo root (script may be invoked from docker/container)
REPO_ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$REPO_ROOT"

source ./cp_common.sh

run_make mipsel

echo "[info] copying olsrd -> /olsrd-output/$ARCH/usr/sbin/"
cp olsrd /olsrd-output/$ARCH/

# copy plugin libraries using the shared helper
cp lib/httpinfo/olsrd_* /olsrd-output/$ARCH/
cp lib/txtinfo/olsrd_* /olsrd-output/$ARCH/
cp lib/jsoninfo/olsrd_* /olsrd-output/$ARCH/
cp lib/watchdog/olsrd_* /olsrd-output/$ARCH/
cp lib/pgraph/olsrd_* /olsrd-output/$ARCH/
cp lib/netjson/olsrd_* /olsrd-output/$ARCH/
cp lib/olsrd-status-plugin/build/olsrd_* /olsrd-output/$ARCH/
