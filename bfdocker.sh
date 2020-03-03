#!/bin/bash

##########################################################################
# Copyright (c) 2019, ETH Zurich.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.
# If you do not find this file, copies can be found by writing to:
# ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
##########################################################################

# configuragion. Note BF_SOURCE and BF_BUILD must be absolute paths!
BF_SOURCE=$(readlink -f `dirname $0`)
BF_BUILD="$1"
BF_DOCKER=achreto/barrelfish-ci
BF_CMD="${@:2}"

echo "bfdocker: $BF_DOCKER"
echo "bfsrc: $BF_SOURCE  build: $BF_BUILD"
echo "bfcmd: $BF_CMD"

if [ -z "$BF_CMD" ]; then
	printf "%s\n" 'No command given. Aborting.'
	exit 1
fi

# create the build directory
mkdir -p $BF_BUILD

podman run --rm -u $(id -u) -i -t \
	--security-opt label=disable \
	--mount type=bind,source=$BF_SOURCE,target=/source \
	--mount type=bind,source=$BF_BUILD,target=/build \
	$BF_DOCKER /bin/bash -c "(cd /build && $BF_CMD)"
