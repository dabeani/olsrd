#!/bin/bash

git pull

ARCH="x86"

export CC=gcc
export CXX=g++
export LD=ld
export AR=ar

# Work from the repo root (script may be invoked from docker/container)
REPO_ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$REPO_ROOT"

# bring in common helper functions
source "$REPO_ROOT/cp_common.sh"

echo "[info] Running build with: $BUILD_VARS"

# Build using run_make helper which handles clean and plugin selection.
# You can override MAKE_PLUGINS in the environment when cross-building to limit plugins.
run_make $ARCH

echo "[info] copying olsrd -> /olsrd-output/$ARCH/usr/sbin/"
cp olsrd /olsrd-output/$ARCH/usr/sbin/

# copy plugin libraries using the shared helper
cp lib/httpinfo/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/txtinfo/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/jsoninfo/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/watchdog/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/pgraph/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/netjson/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/olsrd-status-plugin/build/olsrd_* /olsrd-output/$ARCH/usr/lib/

cp -r /work/olsrd/lib/olsrd-status-plugin/www /olsrd-output/$ARCH/usr/share/olsrd-status-plugin/www