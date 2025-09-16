#!/bin/sh

# build container, if exists it will be updated!
sudo docker build -t olsrd-sdk .

# start ash into container
docker run -it --rm -v ~/olsrd:/workspace -v ~/olsrd-output:/olsrd-output olsrd-sdk