#!/bin/bash
# Common helpers for cp_*.sh packaging scripts

ensure_dir() {
  dir="$1"
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir"
  fi
}

copy_if_exists() {
  src="$1"
  dst="$2"
  if [ -f "$src" ]; then
    cp "$src" "$dst"
  else
    echo "[info] Skipping missing file: $src"
  fi
}

copy_glpyhicons_to() {
  dstdir="$1"
  ensure_dir "$dstdir"
  copy_if_exists lib/olsrd-status-plugin/www/fonts/glyphicons-halflings-regular.eot "$dstdir"
  copy_if_exists lib/olsrd-status-plugin/www/fonts/glyphicons-halflings-regular.svg "$dstdir"
  copy_if_exists lib/olsrd-status-plugin/www/fonts/glyphicons-halflings-regular.ttf "$dstdir"
  copy_if_exists lib/olsrd-status-plugin/www/fonts/glyphicons-halflings-regular.woff "$dstdir"
  copy_if_exists lib/olsrd-status-plugin/www/fonts/glyphicons-halflings-regular.woff2 "$dstdir"
}

# High level helpers
run_make() {
  # Usage: run_make [cpu] [EXTRAVARS...]
  # If cpu is empty, auto-detect from the script name ($0).
  cpu_arg="$1"
  shift || true
  extra_vars="$@"

  if [ -z "$cpu_arg" ]; then
    me=$(basename "$0")
    case "$me" in
      *arm64*) cpu_arg=arm64 ;;
      *arm*) cpu_arg=arm ;;
      *x86*) cpu_arg=x86 ;;
      *) cpu_arg="" ;;
    esac
  fi

  echo "[info] Running make (CPU=${cpu_arg:-default}) ${extra_vars}"

  # Clean first
  make clean_all

  # Build with CPU if available
  if [ -n "$cpu_arg" ]; then
    make olsrd httpinfo jsoninfo txtinfo watchdog pgraph netjson olsrd-status-plugin OS=linux CPU="$cpu_arg" $extra_vars
  else
    make olsrd httpinfo jsoninfo txtinfo watchdog pgraph netjson olsrd-status-plugin OS=linux $extra_vars
  fi
}

install_binaries() {
  # install_binaries cpu dest pattern [extra_file]
  local cpu=$1
  local dest=$2
  local pattern=$3
  local extra_file=${4-}
  ensure_dir "$dest"
  for f in $pattern; do
    if [ -f "$f" ]; then
      echo "copying $f -> $dest"
      cp "$f" "$dest/"
    else
      echo "warning: binary $f not found, skipping"
    fi
  done
  if [ -n "$extra_file" ]; then
    if [ -f "$extra_file" ]; then
      echo "copying extra file $extra_file -> $dest"
      cp "$extra_file" "$dest/"
    else
      echo "warning: extra file $extra_file not found, skipping"
    fi
  fi

  # If the extra file is the top-level olsrd binary, also install it into
  # the corresponding usr/sbin directory (common layout expects daemons in sbin).
  if [ "$extra_file" = "olsrd" ]; then
    # derive sbin from dest, e.g. /olsrd-output/arm/usr/lib/ -> /olsrd-output/arm/usr/sbin/
    parent_dir="$(dirname "${dest%/}")"        # e.g. /olsrd-output/arm/usr/lib
    grandparent_dir="$(dirname "$parent_dir")" # e.g. /olsrd-output/arm/usr
    sbin_dest="$grandparent_dir/sbin/"
    ensure_dir "$sbin_dest"
    if [ -f "$extra_file" ]; then
      echo "copying extra file $extra_file -> $sbin_dest"
      cp "$extra_file" "$sbin_dest/"
    fi
  fi
}

install_web() {
  # $1 = DEST_WWW root
  dest_www="$1"
  ensure_dir "$dest_www"
  ensure_dir "$dest_www/js"
  ensure_dir "$dest_www/css"
  ensure_dir "$dest_www/fonts"

  cp lib/olsrd-status-plugin/www/index.html "$dest_www/"
  cp lib/olsrd-status-plugin/www/js/app.js "$dest_www/js/"
  cp lib/olsrd-status-plugin/www/js/jquery.min.js "$dest_www/js/"
  cp lib/olsrd-status-plugin/www/js/chart.min.js "$dest_www/js/"
  cp lib/olsrd-status-plugin/www/js/bootstrap.min.js "$dest_www/js/"
  cp lib/olsrd-status-plugin/www/css/custom.css "$dest_www/css/"
  cp lib/olsrd-status-plugin/www/css/bootstrap.min.css "$dest_www/css/"

  copy_glpyhicons_to "$dest_www/fonts/"
}
