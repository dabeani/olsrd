#!/bin/bash

git pull

ARCH="arm"

# PATH
export PATH=$PATH:/opt/armv5-eabi--glibc--bleeding-edge-2023.08-1/bin

# prepare cross compiler
export CC=arm-linux-gcc
export CXX=arm-linux-g++
export LD=arm-linux-ld
export AR=arm-linux-ar

# remove old output for ARCH
rm -rf /olsrd-output/$ARCH

# create output folders
mkdir -p /olsrd-output/$ARCH/usr/sbin
mkdir -p /olsrd-output/$ARCH/usr/lib
mkdir -p /olsrd-output/$ARCH/usr/share/olsrd-status-plugin

# copy Dockerfile
cp docker/arm/Dockerfile /olsrd-output/$ARCH/Dockerfile

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

# === Option B: build self-contained static curl (mbedTLS) for embedded target ===
# This builds and installs a static curl linked against a statically-built mbedTLS.
# The build is performed under $REPO_ROOT/build_external and the resulting
# curl binary is copied into the output image at usr/bin. Cross-toolchain
# environment variables (CC, AR) are used above.
BUILD_EXTERNAL_DIR="$REPO_ROOT/build_external"
EXTERNAL_DIR="$REPO_ROOT/lib/extern"
MBEDTLS_REPO="https://github.com/ARMmbed/mbedtls.git"
# Prefer submodule path under lib/extern if present, otherwise fall back to build_external
MBEDTLS_SUBDIR="$EXTERNAL_DIR/mbedtls"
MBEDTLS_DIR="$BUILD_EXTERNAL_DIR/mbedtls"
MBEDTLS_INSTALL="$BUILD_EXTERNAL_DIR/install/mbedtls"
CURL_REPO="https://github.com/curl/curl.git"
CURL_SUBDIR="$EXTERNAL_DIR/curl"
CURL_DIR="$BUILD_EXTERNAL_DIR/curl"
CURL_INSTALL="$BUILD_EXTERNAL_DIR/install/curl"

export RANLIB=${RANLIB:-arm-linux-ranlib}
export STRIP=${STRIP:-arm-linux-strip}

mkdir -p "$BUILD_EXTERNAL_DIR"
mkdir -p "$EXTERNAL_DIR"

# If submodule directories exist use them directly (recommended workflow with git submodules)

# First-time initialization: if required submodules are not present, attempt to init them once.
if [ ! -d "$MBEDTLS_SUBDIR" ] || [ ! -d "$CURL_SUBDIR" ]; then
  echo "[info] One-time init: initializing git submodules (this may take a while)";
  git submodule update --init --recursive || true
fi

if [ -d "$MBEDTLS_SUBDIR" ]; then
	echo "[info] using mbedTLS from submodule: $MBEDTLS_SUBDIR"
	MBEDTLS_DIR="$MBEDTLS_SUBDIR"
else

if [ -d "$CURL_SUBDIR" ]; then
	exit 1
fi
if [ -d "$CURL_SUBDIR" ]; then
	echo "[info] using curl from submodule: $CURL_SUBDIR"
	CURL_DIR="$CURL_SUBDIR"
else
	echo "[error] required submodule lib/extern/curl not found. Please run: git submodule update --init --recursive" >&2
	exit 1
fi

echo "[info] Building mbedTLS and static curl for $ARCH (this may take a while)"
# submodules are required and already located at MBEDTLS_DIR and CURL_DIR

# Build mbedTLS (prefer cmake if available, fallback to Makefile)
pushd "$MBEDTLS_DIR" >/dev/null || exit 1
if command -v cmake >/dev/null 2>&1; then
	mkdir -p build && cd build
	CC=$CC AR=$AR RANLIB=$RANLIB CFLAGS="-Os -fPIC" \
		cmake -DENABLE_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX="$MBEDTLS_INSTALL" ..
	make -j$(sysctl -n hw.ncpu)
	make install
	cd ..
else
	# fallback: use bundled make rules
	make SHARED=0 CC=$CC AR=$AR RANLIB=$RANLIB CFLAGS="-Os -fPIC" -j$(sysctl -n hw.ncpu)
	mkdir -p "$MBEDTLS_INSTALL"/lib "$MBEDTLS_INSTALL"/include
	# copy static libs and public headers
	cp library/libmbedtls.a "$MBEDTLS_INSTALL"/lib/ || true
	cp library/libmbedx509.a "$MBEDTLS_INSTALL"/lib/ || true
	cp library/libmbedcrypto.a "$MBEDTLS_INSTALL"/lib/ || true
	cp -r include/mbedtls "$MBEDTLS_INSTALL"/include/ || true
fi
popd >/dev/null

# Build curl statically and link against the built mbedTLS
pushd "$CURL_DIR" >/dev/null || exit 1
./buildconf
PKG_CONFIG_PATH= \
CC=$CC AR=$AR RANLIB=$RANLIB \
./configure --host=arm-linux --disable-shared --enable-static \
	--with-mbedtls="$MBEDTLS_INSTALL" \
	--without-ssl --without-zlib --without-libidn2 --without-nghttp2 --without-brotli --without-libssh2 --without-librtmp \
	--disable-ldap --disable-rtsp --disable-manual --enable-ipv6=no --prefix="$CURL_INSTALL"
make -j$(sysctl -n hw.ncpu)
make install
popd >/dev/null

# copy resulting curl binary into output filesystem
mkdir -p /olsrd-output/$ARCH/usr/bin
if [ -x "$CURL_INSTALL/bin/curl" ]; then
	echo "[info] copying static curl -> /olsrd-output/$ARCH/usr/bin/"
	cp "$CURL_INSTALL/bin/curl" /olsrd-output/$ARCH/usr/bin/
	if command -v "$STRIP" >/dev/null 2>&1; then
		"$STRIP" --strip-unneeded /olsrd-output/$ARCH/usr/bin/curl || true
	else
		strip --strip-unneeded /olsrd-output/$ARCH/usr/bin/curl || true
	fi
else
	echo "[warn] static curl was not found at $CURL_INSTALL/bin/curl; skipping copy"
fi


# copy plugin libraries using the shared helper
cp lib/httpinfo/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/txtinfo/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/jsoninfo/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/watchdog/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/pgraph/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/netjson/olsrd_* /olsrd-output/$ARCH/usr/lib/
cp lib/olsrd-status-plugin/build/olsrd_* /olsrd-output/$ARCH/usr/lib/

rm -rf /olsrd-output/$ARCH/usr/share/olsrd-status-plugin/www

# Copy the www folder with all subfolders
cp -rf /work/olsrd/lib/olsrd-status-plugin/www /olsrd-output/$ARCH/usr/share/olsrd-status-plugin/www