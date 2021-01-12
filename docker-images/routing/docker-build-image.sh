#!/usr/bin/env sh

# build the softether container image
docker build -t jasonthc/apptraffic-routing:0.0.1a .
docker build -t jasonthc/apptraffic-routing:latest .
