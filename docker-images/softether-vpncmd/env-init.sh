#!/usr/bin/env sh

# update the local software repository
apt-get update -y

# install software packages required to set up softether
apt-get install locales build-essential wget -y

exit 0
