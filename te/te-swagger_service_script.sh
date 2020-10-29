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

start()
{
    if [[ $IP == "NULL" ]]; then
        exit 1
    fi
    python3 $NGINX_ROOT/$REPO_NAME/TE_SWAGGER.py -rp $REPO_NAME -fp $PORT -ip $IP
}

REPO_NAME=$2
envfile="/etc/te-swagger@${REPO_NAME}.conf"
if [ -f "$envfile" ]
then
    echo "$envfile found, sourcing.."
    source $envfile
fi

case "$1" in
    "start")
    start
    ;;
esac
