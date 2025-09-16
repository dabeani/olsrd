#!/bin/sh

# remove old docker image
docker rmi olsrd-arm

# remove old exported docker container
rm ./olsrd-arm.tar

rm arm/init.sh
cp globals/init.sh arm/init.sh

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

