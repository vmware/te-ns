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

if [ "$EUID" -ne 0 ]
    then echo "Please run as root"
    exit 1
fi

GREEN='\033[0;32m'
NC='\033[0m'
NGINX_ROOT=$1

if [[ $# -eq 1 ]] ; then
    SWAGGER_PORT=$1
else
    SWAGGER_PORT=4000
fi

#START SERVICE TO DEPLOY TE CONTROLLER
base_path=$(git rev-parse --show-toplevel)
te_path=$base_path/te/
cp ${te_path}/te-swagger* /etc/systemd/system/
echo "export PORT=${SWAGGER_PORT}" > /etc/te-swagger.conf
echo "export BASE_PATH=${te_path}" >> /etc/te-swagger.conf
systemctl daemon-reload
systemctl restart te-swagger.service

sleep 5
echo "Checking if service is active"
is_active=$(systemctl is-active te-swagger.service)
if [[ ${is_active} != "active" ]]; then
    echo "Unable to bring up te-swagger.service service"
    echo "Please check journalctl -u te-swagger.service"
    exit 1
fi

echo "Go the to UI at <IP>:${SWAGGER_PORT}/swagger !!!"
