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