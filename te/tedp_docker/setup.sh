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

#!/bin/bash
cd /tmp/
sed -i '/deb-src/s/^# //' /etc/apt/sources.list && apt update
apt install automake libtool m4 -y
apt install libjson0 libjson0-dev -y
apt build-dep curl -y
apt install wget -y
apt install build-essential nghttp2 libnghttp2-dev -y

###################### Download all first ######################

#OPENSSL 1.1.1a
wget --no-check-certificate https://www.openssl.org/source/openssl-1.1.1a.tar.gz
tar -zxf openssl-1.1.1a.tar.gz && rm openssl-1.1.1a.tar.gz

#ZeroMQ
#Ref: https://github.com/zeromq/libzmq
wget https://github.com/zeromq/libzmq/releases/download/v4.3.4/zeromq-4.3.4.tar.gz
tar -xf zeromq-4.3.4.tar.gz && rm zeromq-4.3.4.tar.gz

#LIBCURL
wget --no-check-certificate https://curl.haxx.se/download/curl-7.67.0.tar.gz
tar -xvf curl-7.67.0.tar.gz && rm curl-7.67.0.tar.gz

#LIBUV
wget --no-check-certificate https://dist.libuv.org/dist/v1.27.0/libuv-v1.27.0.tar.gz
tar xvf libuv-v1.27.0.tar.gz && rm libuv-v1.27.0.tar.gz

###################### purge libssl1.0 ######################
apt remove --purge -y libssl-dev libssl-doc libssl1.0.0 openssl

###################### Install them ######################

#OPENSSL 1.1.1a
cd openssl-1.1.1a
./config && make -j$(nproc) && make install
ldconfig
cd /tmp/
rm -rf openssl*

#LIBCURL
cd curl-7.67.0
#For openssl 1.1.1 support (TLSv1.3)
./configure --with-nghttp2 --prefix=/usr/local --with-default-ssl-backend=openssl --enable-ipv6
make -j$(nproc) && make install
ldconfig
cd /tmp/
rm -rf curl*

#LIBUV
cd libuv-v1.27.0/
./autogen.sh
./configure
make -j$(nproc) && make install
ldconfig
cd /tmp/
rm -rf libuv*

#ZMQ
apt install -y cmake
cd zeromq-4.3.4/
mkdir build && cd build
cmake -DWITH_PERF_TOOL=OFF -DZMQ_BUILD_TESTS=OFF -DENABLE_CPACK=OFF -DCMAKE_BUILD_TYPE=Release ../
make -j$(nproc) && make install
ldconfig
cd /tmp/
rm -fr zeromq-4.3.4
