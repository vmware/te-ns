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

if [[ $# -ne 3 && $# -ne 4 ]] ; then
    echo "Improper Input"
    echo "$0 <REPO_NAME> <REPO_IP> <PATH TO TRAFFIC ENGINE> <SWAGGER_PORT>(optional -- default 4000)"
    exit 1
fi

GREEN='\033[0;32m'
NC='\033[0m'
USER=root
PASSWORD=avi123
REPO_NAME=$1
TARGET=/usr/share/nginx/html/$1/
IP=$2
PATH_TO_TE=$3

if [[ $# -eq 4 ]] ; then
    SWAGGER_PORT=$4
else
    SWAGGER_PORT=4000
fi

#BUILD AND SAVE TEDP DOCKER
docker container prune -f && docker image prune -f
docker build -t tedp_bin:v2.0 -f $PATH_TO_TE/te/tedp_docker/tedp_bin_builder.dockerfile $PATH_TO_TE/
docker build -t tedp:v2.0 -f $PATH_TO_TE/te/tedp_docker/Dockerfile $PATH_TO_TE/
docker save -o $PATH_TO_TE/te/tedp_docker.tar tedp:v2.0
IMAGE_ID_TEDP=`docker images -q -a tedp:v2.0`
echo -e "${GREEN}Perfomed a Docker save of TE_DP Docker ${NC}"

#BUILD AND SAVE TE DOCKER
docker build -t te:v2.0 --build-arg IMAGE_ID=$IMAGE_ID_TEDP -f $PATH_TO_TE/te/te_docker/Dockerfile $PATH_TO_TE/te/
docker save -o $PATH_TO_TE/te/te_docker.tar te:v2.0
IMAGE_ID_TE=`docker images -q -a te:v2.0`
echo -e "${GREEN}Performed a Docker save of TE Docker ${NC}"

#COPY TE DOCKER TO /etc/nginx/html of maintained REPO
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "mkdir -p ${TARGET}; mkdir -p ${TARGET}static"
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/te_docker.tar $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/TE_WRAP.py $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/GET_AND_RUN_DOCKER_IMAGE.py $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/TE_SWAGGER.py $USER@$IP:$TARGET
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/setup_te_swagger.json $USER@$IP:$TARGET/static/
echo -e "${GREEN}Saved the TE docker tar to ${TARGET} in machine ${IP} ${NC}"

sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "md5sum ${TARGET}/te_docker.tar > ${TARGET}/check.sum"
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "echo ${IMAGE_ID_TE} > ${TARGET}/image.id; chmod -R 755 ${TARGET}"
echo -e "${GREEN}Computed and save the check.sum and contents of ${TARGET} are ${NC}"
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "ls -l ${TARGET}"

#START SERVICE TO DEPLOY TE CONTROLLER
sshpass -p $PASSWORD scp -o "StrictHostKeyChecking no" $PATH_TO_TE/te/te-swagger* $USER@$IP:/etc/systemd/system/
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "echo \"export IP='${IP}'\" > /etc/te-swagger@${REPO_NAME}.conf"
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "echo \"export PORT='${SWAGGER_PORT}'\" >> /etc/te-swagger@${REPO_NAME}.conf"
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "systemctl daemon-reload"
sshpass -p $PASSWORD ssh -o "StrictHostKeyChecking no" -t $USER@$IP "systemctl restart te-swagger@${REPO_NAME}.service && systemctl status te-swagger@${REPO_NAME}.service"
