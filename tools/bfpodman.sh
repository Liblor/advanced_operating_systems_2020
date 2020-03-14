#!/usr/bin/env bash

BF_SOURCE="$(git rev-parse --show-toplevel)"
BF_BUILD=$BF_SOURCE/build
BF_PODMAN=achreto/barrelfish-ci
BF_CMD="$@"

if [ -z "$BF_CMD" ]; then
	printf "%s\n" 'No command given. Aborting.'
	exit 1
fi

mkdir -p "$BF_BUILD"

podman run --rm -u "$(id -u)" -i -t \
	--security-opt label=disable \
	--mount "type=bind,source=$BF_SOURCE,target=/source" \
	--mount "type=bind,source=$BF_BUILD,target=/source/build" \
	$BF_PODMAN /bin/bash -c "(cd /source/build && $BF_CMD)"
