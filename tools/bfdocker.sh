#!/bin/bash

##########################################################################
# Copyright (c) 2019,2020 ETH Zurich.
# All rights reserved.
#
# This file is distributed under the terms in the attached LICENSE file.
# If you do not find this file, copies can be found by writing to:
# ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
##########################################################################

# configuragion. Note BF_SOURCE and BF_BUILD must be absolute paths!
BF_SOURCE=$(readlink -f `dirname $0`)/../
BF_BUILD="$HOME/aos-m1-build"
BF_DOCKER=achreto/barrelfish-ci
BF_CMD="$@"

echo "bfdocker: $BF_DOCKER"
echo "bfsrc: $BF_SOURCE  build: $BF_BUILD"
echo "bfcmd: $BF_CMD"

# pull the docker image
#docker pull $BF_DOCKER

# create the build directory
mkdir -p $BF_BUILD

if [ $# == 0 ]; then
    exit
fi

# run the command in the docker image
docker run --rm -u $(id -u) -t \
    --mount type=bind,source="$BF_SOURCE",target=/source \
    --mount type=bind,source="$BF_BUILD",target=/source/build \
    $BF_DOCKER /bin/bash -c "(cd /source/build && $BF_CMD)"
