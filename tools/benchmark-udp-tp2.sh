#!/usr/bin/env bash

# Expects to have an echoserver running on the other side.

set -eE

if [ $# -ne 3 ]; then
	printf "%s\n" "Usage: $0 <port> <count> <rate>" >&2
	exit 1
fi

port="$1"
count="$2"
rate="$3"
ip='10.0.0.2'

printf "%s\n" 'Measuring loss in percent...' >&2
percent="$(nping -c "$count" --udp -p "$port" --rate "$rate" "$ip" 2> /dev/null | awk '/Lost:/ {print substr($NF, 2, length($NF) - 3)}')"

python3 -c "print($percent / 100)"
