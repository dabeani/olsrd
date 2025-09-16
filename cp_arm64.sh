#!/bin/bash

#cd /workspace/olsrd/lib/olsrd-status-plugin/
#git pull
#cd /workspace/olsrd/

# prepare cross compiler
export CC=aarch64-linux-gnu-gcc
export LD=aarch64-linux-gnu-ld
export AR=aarch64-linux-gnu-ar

source ./cp_common.sh

# Build and install for arm64 (run_make will clean and build)
# prepare build vars
BUILD_VARS="BUILD_TYPE=shared"
if [ -n "$CC" ]; then BUILD_VARS="$BUILD_VARS CC=$CC"; fi
if [ -n "$CXX" ]; then BUILD_VARS="$BUILD_VARS CXX=$CXX"; fi
if [ -n "$SYSROOT" ]; then BUILD_VARS="$BUILD_VARS CFLAGS=--sysroot=$SYSROOT LDFLAGS=--sysroot=$SYSROOT"; fi

run_make arm64 $BUILD_VARS

# Destination root for arm64
DEST_ROOT="/olsrd-output/arm64"

ensure_dir "$DEST_ROOT/usr/sbin/"
ensure_dir "$DEST_ROOT/usr/lib/"

if [ -f "$(pwd)/olsrd" ]; then
	echo "[info] copying olsrd -> $DEST_ROOT/usr/sbin/"
	cp "$(pwd)/olsrd" "$DEST_ROOT/usr/sbin/"
else
	echo "[warn] olsrd binary not found in $(pwd)"
fi

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

copy_matches "$(pwd)/lib/httpinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$(pwd)/lib/txtinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$(pwd)/lib/jsoninfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$(pwd)/lib/watchdog/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$(pwd)/lib/pgraph/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$(pwd)/lib/netjson/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$(pwd)/lib/olsrd-status-plugin/build/olsrd_*" "$DEST_ROOT/usr/lib"

install_web "$DEST_ROOT/usr/share/olsrd-status-plugin/www"

# Ensure .so plugin files are available for the config loader (LoadPlugin uses dlopen)
PLUGIN_LIST=(olsrd-status-plugin httpinfo txtinfo jsoninfo watchdog pgraph netjson)
for p in "${PLUGIN_LIST[@]}"; do
	pd="$(cd "$(dirname "$0")" && pwd)/lib/$p"
	if [ -d "$pd" ]; then
		echo "[info] building shared plugin for $p (for LoadPlugin)"
		(cd "$pd" && make BUILD_TYPE=shared CC="$CC" CXX="$CXX" >/dev/null 2>&1 || true)
		sofile=$(ls "$pd"/build/*.so* 2>/dev/null | head -n1 || true)
			if [ -n "$sofile" ]; then
				if command -v readelf >/dev/null 2>&1; then
					glibc_tags=$(readelf -V "$sofile" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
				else
					glibc_tags=$(strings "$sofile" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -u | tr '\n' ' ')
				fi
				echo "[info] GLIBC tags in $sofile: ${glibc_tags:-none detected}"
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

