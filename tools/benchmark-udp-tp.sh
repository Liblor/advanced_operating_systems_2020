#!/usr/bin/env bash

# Expects to have a udpsender running on the other side.

set -eE

if [ $# -ne 3 ]; then
	printf "%s\n" "Usage: $0 <port> <count> <size>" >&2
	exit 1
fi

port="$1"
count="$2"
size="$3"

ip='10.0.0.2'

directory="$(mktemp -d)"

printf "%s\n" 'Listening for packets...' >&2
(tshark -i enp6s0 -f "udp port $port" -a duration:120 -c "$((count + 1))") > $directory/measure &
pid_tshark="$!"

sleep 1

printf "%s\n" 'Sending start signal...' >&2
echo "start" | nc -u -p 50000 "$ip" "$port"

printf "%s\n" 'Setup receiver...' >&2
nc --recv-only -l -u 50000 > /dev/null 2>&1 &
pid_nc="$!"

printf "%s\n" 'Waiting for packets...' >&2
wait "$pid_tshark"

times="$(tail -n +2 "$directory/measure" | awk '{print $2}')"
first_ts="$(echo "$times" | head -n 1)"
last_ts="$(echo "$times" | tail -n 1)"

bps="$(python3 -c "print(str($count * $size / ($last_ts - $first_ts)))")"

printf "%s\n" "$bps"

printf "%s\n" 'Cleaning up...' >&2
pkill -P $$
rm -r "$directory"
