#!/bin/sh
set -eu

# remove old docker image
docker rmi olsrd-arm || true
rm -f ./olsrd-arm.tar || true

# refresh init.sh into the build context
rm -f arm/init.sh
cp /home/ubnt/olsrd/docker/init.sh arm/init.sh

# add olsrd2 stuff
rm arm/usr/sbin/olsrd2*
cp olsrd2/arm/usr/sbin/olsrd2* arm/usr/sbin/

rm -R arm/olsrd2
mkdir arm/olsrd2
mkdir arm/olsrd2/www
cp olsrd2/globals/*.js arm/olsrd2/www/
cp olsrd2/globals/*.html arm/olsrd2/www/
cp olsrd2/globals/*.css arm/olsrd2/www/

# build (note: fixed the 'docker -v build' typo)
docker build \
  --platform linux/arm/v5 \
  -t olsrd-arm \
  -f arm/Dockerfile \
  ./arm/

# save docker image into a tar file
docker save olsrd-arm > ./olsrd-arm.tar

# (optional) show the resulting tar size for visibility
wc -c ./olsrd-arm.tar

# compute sha256 hash and save to text file
sha256sum ./olsrd-arm.tar | cut -d' ' -f1 > ./olsrd-arm.txt

# (optional) show the hash
cat ./olsrd-arm.txt



