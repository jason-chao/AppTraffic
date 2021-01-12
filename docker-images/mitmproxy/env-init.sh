#!/usr/bin/env sh

# update the local software repository
apt-get update -y

# install software packages required to set up softether
apt-get install locales python3-pip -y

exit 0
