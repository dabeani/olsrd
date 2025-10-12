#!/bin/sh

# clean up prior artifacts (ignore errors if missing)
docker rmi olsrd-x86 2>/dev/null || true
rm -f ./olsrd-x86.tar || true

# refresh init.sh into the build context
rm -f x86/init.sh
cp docker/init.sh x86/init.sh

# add olsrd2 stuff
rm x86/usr/sbin/olsrd2*
cp olsrd2/x86/usr/sbin/olsrd2* x86/usr/sbin/

rm -R x86/olsrd2
mkdir x86/olsrd2
mkdir x86/olsrd2/www
cp olsrd2/globals/*.js x86/olsrd2/www/
cp olsrd2/globals/*.html x86/olsrd2/www/
cp olsrd2/globals/*.css x86/olsrd2/www/

# build (note: fixed the 'docker -v build' typo)
docker build \
  --platform linux/amd64 \
  -t olsrd-x86 \
  -f x86/Dockerfile \
  ./x86/

# save docker image into a tar file
docker save olsrd-x86 > ./olsrd-x86.tar

# (optional) show the resulting tar size for visibility
wc -c ./olsrd-x86.tar

# compute sha256 hash and save to text file
sha256sum ./olsrd-x86.tar | cut -d' ' -f1 > ./olsrd-x86.txt

# (optional) show the hash
cat ./olsrd-x86.txt
