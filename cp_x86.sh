#!/bin/bash

git pull

# prepare cross compiler (for x86, use native or x86 toolchain)
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
run_make x86

# Destination root as requested (absolute path under /olsrd-output/x86)
DEST_ROOT="/olsrd-output/x86"

ensure_dir "$DEST_ROOT/usr/sbin/"
ensure_dir "$DEST_ROOT/usr/lib/"

# copy main binary
if [ -f "$REPO_ROOT/olsrd" ]; then
  echo "[info] copying olsrd -> $DEST_ROOT/usr/sbin/"
  cp "$REPO_ROOT/olsrd" "$DEST_ROOT/usr/sbin/"
else
  echo "[warn] olsrd binary not found at $REPO_ROOT/olsrd"
fi

# copy plugin libraries using the shared helper
copy_matches "$REPO_ROOT/lib/httpinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/txtinfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/jsoninfo/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/watchdog/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/pgraph/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/netjson/olsrd_*" "$DEST_ROOT/usr/lib"
copy_matches "$REPO_ROOT/lib/olsrd-status-plugin/build/olsrd_*" "$DEST_ROOT/usr/lib"

install_web "$DEST_ROOT/usr/share/olsrd-status-plugin/www"