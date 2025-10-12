#!/bin/sh

# remove old docker image
docker rmi olsrd-arm64 || true
rm -f ./olsrd-arm64.tar || true

# refresh init.sh into the build context
rm -f arm64/init.sh
cp docker/init.sh arm64/init.sh

# add olsrd2 stuff
rm arm64/usr/sbin/olsrd2*
cp olsrd2/arm64/usr/sbin/olsrd2* arm64/usr/sbin/

rm -R arm64/olsrd2
mkdir arm64/olsrd2
mkdir arm64/olsrd2/www
cp olsrd2/globals/*.js arm64/olsrd2/www/
cp olsrd2/globals/*.html arm64/olsrd2/www/
cp olsrd2/globals/*.css arm64/olsrd2/www/

# build (note: fixed the 'docker -v build' typo)
docker build \
  --platform linux/arm64 \
  -t olsrd-arm64 \
  -f arm64/Dockerfile \
  ./arm64/

# save docker image into a tar file
docker save olsrd-arm64 > ./olsrd-arm64.tar

# (optional) show the resulting tar size for visibility
wc -c ./olsrd-arm64.tar

# compute sha256 hash and save to text file
sha256sum ./olsrd-arm64.tar | cut -d' ' -f1 > ./olsrd-arm64.txt

# (optional) show the hash
cat ./olsrd-arm64.txt
