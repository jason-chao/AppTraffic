#!/usr/bin/env sh

# update the local software repository
apt-get update -y

# install software packages required to set up softether
apt-get install iproute2 iptables tcpdump -y

exit 0
