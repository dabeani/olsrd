#!/bin/bash

#cd /workspace/olsrd/lib/olsrd-status-plugin/
#git pull
#cd /workspace/olsrd/

# PATH
export PATH=$PATH:/opt/armv5-eabi--glibc--stable-2024.05-1/bin


# Preferred sysroot and toolchain location (adjust if you installed elsewhere)
export SYSROOT="/opt/armv5-eabi--glibc--stable-2024.05-1/arm-buildroot-linux-gnueabi/sysroot"

# Detect a usable cross-compile prefix from common candidates and PATH
if [ -z "$CROSS_PREFIX" ]; then
	for p in arm-linux-gnueabihf- arm-linux-gnueabi- armv5-eabi- arm-none-eabi-; do
		if command -v ${p}gcc >/dev/null 2>&1; then
			CROSS_PREFIX=$p
			break
		fi
	done
fi

# Fallback to explicit names if CROSS_PREFIX not detected
if [ -n "$CROSS_PREFIX" ]; then
	export CC=${CROSS_PREFIX}gcc
	export CXX=${CROSS_PREFIX}g++
	export AR=${CROSS_PREFIX}ar
	export RANLIB=${CROSS_PREFIX}ranlib
	export STRIP=${CROSS_PREFIX}strip
	export LD=${CROSS_PREFIX}ld
else
	# keep older explicit names as last resort
	export CC=arm-linux-gcc
	export CXX=arm-linux-g++
	export LD=arm-linux-ld
	export AR=arm-linux-ar
fi

source ./cp_common.sh

# Work from the repo root (script may be invoked from docker/container)
REPO_ROOT=$(cd "$(dirname "$0")" && pwd)

# Build shared plugins and the main binary using provided cross toolchain and optional SYSROOT
PLUGIN_LIST=(olsrd-status-plugin httpinfo txtinfo jsoninfo watchdog pgraph netjson)

# Pass the cross-toolchain variables explicitly to recursive make calls
BUILD_VARS="BUILD_TYPE=shared"
BUILD_VARS="$BUILD_VARS CC=$CC CXX=$CXX AR=$AR RANLIB=$RANLIB STRIP=$STRIP LD=$LD"
if [ -n "$SYSROOT" ]; then
	BUILD_VARS="$BUILD_VARS CFLAGS=--sysroot=$SYSROOT LDFLAGS=--sysroot=$SYSROOT"
fi

echo "[info] Running build with: $BUILD_VARS"
cd "$REPO_ROOT"
run_make arm $BUILD_VARS


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

# Ensure .so plugin files are available for the config loader (LoadPlugin uses dlopen)
# Build shared plugin artifacts and copy them into the target usr/lib so dlopen succeeds
for p in "${PLUGIN_LIST[@]}"; do
	pd="$REPO_ROOT/lib/$p"
	if [ -d "$pd" ]; then
		echo "[info] building shared plugin for $p (for LoadPlugin)"
		(cd "$pd" && make BUILD_TYPE=shared $BUILD_VARS >/dev/null 2>&1 || true)
		sofile=$(ls "$pd"/build/*.so* 2>/dev/null | head -n1 || true)
		if [ -n "$sofile" ]; then
			# detect GLIBC tags if possible
			if command -v readelf >/dev/null 2>&1; then
				glibc_tags=$(readelf -V "$sofile" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
			else
				glibc_tags=$(strings "$sofile" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
			fi
			echo "[info] GLIBC tags in $sofile: ${glibc_tags:-none detected}"

			# Copy only if SYSROOT is provided or force copy explicitly
			if [ -n "$SYSROOT" ] || [ "$FORCE_COPY" = "1" ]; then
				echo "[info] installing $sofile -> $DEST_ROOT/usr/lib/"
				ensure_dir "$DEST_ROOT/usr/lib/"
				cp "$sofile" "$DEST_ROOT/usr/lib/"
			else
				echo "[warn] SYSROOT not set — skipping copy of $sofile to avoid packaging incompatible glibc (set SYSROOT or FORCE_COPY=1 to override)"
			fi
		else
			echo "[info] no shared object produced for $p, skipping"
		fi
	fi
done
