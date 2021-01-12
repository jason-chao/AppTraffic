#!/usr/bin/env sh

# ./intercept_raw.sh [interface_id] [output_file]

interface_in=$1
output_file=$2

# tcpdump -i $interface_in -s0 -v -w $output_file
tcpdump -i $interface_in -w $output_file
