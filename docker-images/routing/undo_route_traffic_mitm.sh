#!/usr/bin/env sh

# ./undo_route_traffic_mitm.sh [IP/CIRD] [interface_in] [interface_ext] [mitmproxy_port]

# [IP/CIRD] : the IP address of this machine on the internal interface with subnet mask in CIRD notation
# [interface_in] : the internal network interface bridged to the VPN hub (usually started with "tap_")
# [interface_ext] : the network interface connected to the Internet
# [mitmproxy_port] : the port at which MITMProxy/MITMWeb/MITMDump is listening

ip_cird=$1
interface_in=$2
interface_ext=$3
mitmproxy_port=$4

iptables -t nat -D PREROUTING -i $interface_in -p tcp --dport 80 -j REDIRECT --to-port $mitmproxy_port
iptables -t nat -D PREROUTING -i $interface_in -p tcp --dport 443 -j REDIRECT --to-port $mitmproxy_port

exit 0
