#!/usr/bin/env bash
# Lightweight armv5 cross-build wrapper for OLSRd
# Sets the environment you provided and runs make with forwarded TOOL variables.

set -eu -o pipefail

# User-configurable: path to repo root (default: script location)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"


# Cross-toolchain environment: prefer existing environment values when present.
CT_VERSION=${CT_VERSION:-crosstool-ng-1.25.0}
LESS=${LESS:-' -iJr'}
GREP_COLOR=${GREP_COLOR:-01;32}
PKG_CONFIG_PATH=${PKG_CONFIG_PATH:-/usr/lib/arm-linux-gnueabihf/}
HISTSIZE=${HISTSIZE:-3000}
HOSTNAME=${HOSTNAME:-$(hostname 2>/dev/null || echo container)}
TZ=${TZ:-Europe/Vienna}
HOME=${HOME:-/root}
ARCH=${ARCH:-arm}
DEFAULT_DOCKCROSS_IMAGE=${DEFAULT_DOCKCROSS_IMAGE:-dockcross/linux-armv5-musl:20250913-6ea98ba}

# If CC (or CROSS_COMPILE) provided by environment, keep it; otherwise try common prefixes
if [ -z "${CC:-}" ]; then
  # detect cross prefix from PATH
  for p in arm-linux-gnueabihf- arm-linux-gnueabi- armv5-unknown-linux-musleabi- arm-none-eabi-; do
    if command -v ${p}gcc >/dev/null 2>&1; then
      CROSS_PREFIX=${p}
      break
    fi
  done

  if [ -n "${CROSS_PREFIX:-}" ]; then
    CC=${CC:-${CROSS_PREFIX}gcc}
    CXX=${CXX:-${CROSS_PREFIX}g++}
    AR=${AR:-${CROSS_PREFIX}ar}
    RANLIB=${RANLIB:-${CROSS_PREFIX}ranlib}
    STRIP=${STRIP:-${CROSS_PREFIX}strip}
    LD=${LD:-${CROSS_PREFIX}ld}
    CROSS_COMPILE=${CROSS_COMPILE:-${CROSS_PREFIX}}
  fi
fi

# Provide sensible Debian/apt cross-sysroot defaults if not set
CROSS_ROOT=${CROSS_ROOT:-/usr}
SYSROOT=${SYSROOT:-/usr/arm-linux-gnueabihf}

# If CC still not set, fall back to explicit known paths (last resort)
CC=${CC:-/usr/bin/arm-linux-gnueabihf-gcc}
CXX=${CXX:-/usr/bin/arm-linux-gnueabihf-g++}
AR=${AR:-/usr/bin/arm-linux-gnueabihf-ar}
RANLIB=${RANLIB:-/usr/bin/arm-linux-gnueabihf-ranlib}
STRIP=${STRIP:-/usr/bin/arm-linux-gnueabihf-strip}
LD=${LD:-/usr/bin/arm-linux-gnueabihf-ld}

# Export the variables so downstream commands inherit them
export CT_VERSION LESS GREP_COLOR PKG_CONFIG_PATH HISTSIZE HOSTNAME TZ HOME ARCH DEFAULT_DOCKCROSS_IMAGE
export CC CXX AR RANLIB STRIP LD CROSS_COMPILE CROSS_ROOT SYSROOT

# Useful defaults for make
BUILD_TYPE=${BUILD_TYPE:-shared}
VERBOSE=${VERBOSE:-0}

usage() {
  cat <<EOF
Usage: $0 [make-args...]

This script sets up an armv5 cross-compilation environment and forwards any
arguments to make. Example:

  ./build_armv5.sh -C lib/jsoninfo BUILD_TYPE=$BUILD_TYPE VERBOSE=1

EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

# Print a short header
cat <<EOF
Starting armv5 build wrapper
REPO_ROOT: $REPO_ROOT
CC: $CC
CROSS_ROOT: $CROSS_ROOT
BUILD_TYPE: $BUILD_TYPE
EOF


# Source common helpers (ensure path exists)
if [ -f "$REPO_ROOT/cp_common.sh" ]; then
  # shellcheck disable=SC1090
  source "$REPO_ROOT/cp_common.sh"
else
  echo "[warn] cp_common.sh not found in repo root; some helpers will be missing"
fi

# If SYSROOT wasn't provided, attempt a reasonable default inside CROSS_ROOT
SYSROOT=${SYSROOT:-"$CROSS_ROOT/${CROSS_TRIPLE}/sysroot"}

# Mirror cp_arm.sh behavior: build olsrd + common plugins and copy artifacts
PLUGIN_LIST=(olsrd-status-plugin httpinfo txtinfo jsoninfo watchdog pgraph netjson)

# Prepare build variables to forward into make
BUILD_VARS="BUILD_TYPE=$BUILD_TYPE"
BUILD_VARS="$BUILD_VARS CC=$CC CXX=$CXX AR=$AR RANLIB=${RANLIB:-ranlib} STRIP=${STRIP:-strip} LD=$LD"
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
if [ -f "$REPO_ROOT/olsrd" ]; then
  echo "[info] copying olsrd -> $DEST_ROOT/usr/sbin/"
  cp "$REPO_ROOT/olsrd" "$DEST_ROOT/usr/sbin/"
else
  echo "[warn] olsrd binary not found at $REPO_ROOT/olsrd"
fi

# helper to copy matching files only if they exist
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

copy_matches "$REPO_ROOT/lib/httpinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/txtinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/jsoninfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/watchdog/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/pgraph/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/netjson/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/olsrd-status-plugin/build/olsrd_*" "$DEST_ROOT/usr/lib"

install_web "$DEST_ROOT/usr/share/olsrd-status-plugin/www" || true

# Build each plugin with BUILD_TYPE=shared and copy produced .so if available
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

      if [ -n "$SYSROOT" ] || [ "${FORCE_COPY:-0}" = "1" ]; then
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

echo "armv5 build wrapper finished"
