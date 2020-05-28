#!/usr/bin/env bash

# Does neither expect an echoserver nor a udpsender.

set -eE

if [ $# -ne 1 ]; then
	printf "%s\n" "Usage: $0 <count>" >&2
	exit 1
fi

count="$1"
ip='10.0.0.2'

printf "%s\n" 'Starting nping...' >&2
stdout="$(sudo nping -c "$count" --icmp --delay '0.2' "$ip" 2> /dev/null)"

# Make sure we didn't lose anything.
echo "$stdout" | grep -e 'Lost: 0' > /dev/null

times="$(echo "$stdout" | grep -e 'RCVD\|SENT' | awk '{print substr($2, 2, length($2) - 3)}' | paste -d " "  - - | awk '{print $2 - $1}')"

echo "$times"

printf "%s\n" 'Calculating median and mean...' >&2
echo "$times" | datamash median 1 mean 1 >&2
