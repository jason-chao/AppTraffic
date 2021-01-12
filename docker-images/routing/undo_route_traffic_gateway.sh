#!/usr/bin/env sh

# ./undo_route_traffic_gateway.sh [IP/CIRD] [interface_in] [interface_ext]

# [IP/CIRD] : the IP address of this machine on the internal interface with subnet mask in CIRD notation
# [interface_in] : the internal network interface bridged to the VPN hub (usually started with "tap_")
# [interface_ext] : the network interface connected to the Internet


ip_cird=$1
interface_in=$2
interface_ext=$3

iptables -D FORWARD -i $interface_in -o $interface_ext -s $ip_cird -m conntrack --ctstate NEW -j ACCEPT
iptables -D FORWARD -i $interface_ext -o $interface_in -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

exit 0
