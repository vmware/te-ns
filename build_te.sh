#!/bin/bash

#**********************************************************************************************
# Traffic Emulator for Network Services
# Copyright 2020 VMware, Inc
# The BSD-2 license (the "License") set forth below applies to all parts of
# the Traffic Emulator for Network Services project. You may not use this file
# except in compliance with the License.
#
# BSD-2 License
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE
#**********************************************************************************************

set -e

GREEN='\033[0;32m'
NC='\033[0m'
PATH_TO_TE=$(git rev-parse --show-toplevel)

#BUILD AND SAVE TEDP DOCKER
docker container prune -f && docker image prune -f
docker build -t tedp_bin:v2.0 -f $PATH_TO_TE/te/tedp_docker/tedp_bin_builder.dockerfile $PATH_TO_TE/
docker build -t tedp:v2.0 -f $PATH_TO_TE/te/tedp_docker/Dockerfile $PATH_TO_TE/
docker save -o $PATH_TO_TE/te/tedp_docker.tar tedp:v2.0
IMAGE_ID_TEDP=`docker images -q -a tedp:v2.0`
echo -e "${GREEN}Perfomed a Docker save of TE_DP Docker ${NC}"

#BUILD AND SAVE TE DOCKER
docker build -t te:v2.0 --build-arg IMAGE_ID=$IMAGE_ID_TEDP -f $PATH_TO_TE/te/te_docker/Dockerfile $PATH_TO_TE/te/
echo -e "${GREEN} Built TE Docker Image ${NC}"

# Remove the tedp:v2.0 saved image
rm -f $PATH_TO_TE/te/tedp_docker.tar
