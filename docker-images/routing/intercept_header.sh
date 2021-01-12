#!/usr/bin/env sh

# ./intercept_header.sh [interface_id] [output_file]

interface_in=$1
output_file=$2

#tcpdump -i $interface_in -s96 -v -w $output_file
tcpdump -i $interface_in -s96 -w $output_file
