#!/bin/bash

#cd /workspace/olsrd/lib/olsrd-status-plugin/
#git pull
#cd /workspace/olsrd/

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

# Build for edgerouter with static flags

# For edgerouter we still want static main binary flags, but build shared plugins with cross toolchain
BUILD_VARS="BUILD_TYPE=shared"
if [ -n "$CC" ]; then BUILD_VARS="$BUILD_VARS CC=$CC"; fi
if [ -n "$CXX" ]; then BUILD_VARS="$BUILD_VARS CXX=$CXX"; fi
if [ -n "$SYSROOT" ]; then BUILD_VARS="$BUILD_VARS CFLAGS=--sysroot=$SYSROOT LDFLAGS=--sysroot=$SYSROOT"; fi

run_make "" CFLAGS="-static" LDFLAGS="-static" status_plugin

# Destination root for edgerouter
DEST_ROOT="/olsrd-output/edgerouter"

ensure_dir "$DEST_ROOT/usr/sbin/"
ensure_dir "$DEST_ROOT/usr/lib/"

if [ -f "$REPO_ROOT/olsrd" ]; then
	echo "[info] copying olsrd -> $DEST_ROOT/usr/sbin/"
	cp "$REPO_ROOT/olsrd" "$DEST_ROOT/usr/sbin/"
else
	echo "[warn] olsrd binary not found in $REPO_ROOT"
fi

copy_matches "$REPO_ROOT/lib/httpinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/txtinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/jsoninfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/watchdog/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/pgraph/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/netjson/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/olsrd-status-plugin/build/olsrd_*" "$DEST_ROOT/usr/lib"

install_web "$DEST_ROOT/usr/share/olsrd-status-plugin/www"
