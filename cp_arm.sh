#!/bin/bash

#cd /workspace/olsrd/lib/olsrd-status-plugin/
#git pull
#cd /workspace/olsrd/

#curl https://toolchains.bootlin.com/downloads/releases/toolchains/armv5-eabi/tarballs/armv5-eabi--glibc--bleeding-edge-2023.08-1.tar.bz2 -o armv5-eabi--glibc--bleeding-edge-2023.08-1.tar.bz2
# tar -xjf armv5-eabi--glibc--stable-2023.11-1.tar.bz2 -C /opt

# PATH
export PATH=$PATH:/opt/armv5-eabi--glibc--bleeding-edge-2023.08-1/bin

# prepare cross compiler
export CC=arm-linux-gcc
export CXX=arm-linux-g++
export LD=arm-linux-ld
export AR=arm-linux-ar

# remove all compiled sources
make clean_all

# prerpare to compile files
make olsrd httpinfo jsoninfo txtinfo watchdog pgraph netjson olsrd-status-plugin OS=linux CPU=arm

# Work from the repo root (script may be invoked from docker/container)
REPO_ROOT=$(cd "$(dirname "$0")" && pwd)

# Build shared plugins and the main binary using provided cross toolchain and optional SYSROOT
PLUGIN_LIST=(olsrd-status-plugin httpinfo txtinfo jsoninfo watchdog pgraph netjson)


echo "[info] Running build with: $BUILD_VARS"
cd "$REPO_ROOT"

# Destination root as requested (absolute path under /olsrd-output/arm)
DEST_ROOT="/olsrd-output/arm"

ensure_dir "$DEST_ROOT/usr/sbin/"
ensure_dir "$DEST_ROOT/usr/lib/"

# Copy exactly the files you requested (no double copies)
# cp olsrd ../output/arm/usr/sbin/
if [ -f "$REPO_ROOT/olsrd" ]; then
	echo "[info] copying olsrd -> $DEST_ROOT/usr/sbin/"
	cp "$REPO_ROOT/olsrd" "$DEST_ROOT/usr/sbin/"
else
	echo "[warn] olsrd binary not found at $REPO_ROOT/olsrd"
fi

# helper to copy matching files only if they exis
copy_matches() {
	src_pattern="$1"
	dst_dir="$2"
	shopt -s nullglob
	files=( $src_pattern )
	shopt -u nullglob
	if [ ${#files[@]} -gt 0 ]; then
		echo "[info] copying ${#files[@]} file(s) -> $dst_dir"
		cp "${files[@]}" "$dst_dir/"
	else
		echo "[info] no files matching $src_pattern"
	fi
}

# cp lib/httpinfo/olsrd_* ../output/arm/usr/lib/
copy_matches "$REPO_ROOT/lib/httpinfo/olsrd_*" "$DEST_ROOT/usr/lib"
# cp lib/txtinfo/olsrd_* ../output/arm/usr/lib/
copy_matches "$REPO_ROOT/lib/txtinfo/olsrd_*" "$DEST_ROOT/usr/lib"
# cp lib/jsoninfo/olsrd_* ../output/arm/usr/lib/
copy_matches "$REPO_ROOT/lib/jsoninfo/olsrd_*" "$DEST_ROOT/usr/lib"
# cp lib/watchdog/olsrd_* ../output/arm/usr/lib/
copy_matches "$REPO_ROOT/lib/watchdog/olsrd_*" "$DEST_ROOT/usr/lib"
# cp lib/pgraph/olsrd_* ../output/arm/usr/lib/
copy_matches "$REPO_ROOT/lib/pgraph/olsrd_*" "$DEST_ROOT/usr/lib"
# cp lib/netjson/olsrd_* ../output/arm/usr/lib/
copy_matches "$REPO_ROOT/lib/netjson/olsrd_*" "$DEST_ROOT/usr/lib"
# cp lib/olsrd-status-plugin/build/olsrd_* ../output/arm/usr/lib/
copy_matches "$REPO_ROOT/lib/olsrd-status-plugin/build/olsrd_*" "$DEST_ROOT/usr/lib"

install_web "$DEST_ROOT/usr/share/olsrd-status-plugin/www"
