#!/usr/bin/env sh

# build the softether container image
docker build -t jasonthc/apptraffic-softether-vpncmd:0.0.1a .
docker build -t jasonthc/apptraffic-softether-vpncmd:latest .
