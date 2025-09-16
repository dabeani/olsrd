#!/bin/sh

# remove old docker image
docker rmi olsrd-arm64

# remove old exported docker container
rm ./olsrd-arm64.tar

rm arm64/init.sh
cp globals/init.sh arm64/init.sh

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
