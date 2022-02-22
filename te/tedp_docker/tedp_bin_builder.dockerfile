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


# Stage 1 (Build tedp binaries)
FROM ubuntu:16.04 as build_stage
ENV WORKDR=/opt/te/
ENV TZ=UTC
ARG usr_lib_path=/usr/local/lib
ARG usr_lib64_path=/usr/lib/x86_64-linux-gnu
ARG lib64_path=/lib/x86_64-linux-gnu

# basic library and pkg install
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt update && \
    apt install -y cmake && \
    apt install -y libboost-dev

# library install to make te_dp and te_stats_collector
COPY te/tedp_docker/setup.sh /tmp/
RUN chmod 755 /tmp/setup.sh
RUN /bin/bash -e /tmp/setup.sh

# uninstall libssl1.0 if any
RUN apt remove --purge -y libssl-dev libssl-doc libssl1.0.0 openssl

RUN mkdir -pv $WORKDR/bin && mkdir $WORKDR/obj
ADD te_dp/Makefile $WORKDR
ADD te_dp/src $WORKDR/src
RUN cd $WORKDR && make all

# bundle all necessary dep libraries
RUN tar -czf $WORKDR/usr_lib_deps.tar.gz \
    ${usr_lib_path}/libcurl.so* \
    ${usr_lib_path}/libuv.so.1* \
    ${usr_lib_path}/libssl.so.1* \
    ${usr_lib_path}/libzmq.so* \
    ${usr_lib_path}/libcrypto.so.1*

RUN tar -czf $WORKDR/usr_lib64_deps.tar.gz \
    ${usr_lib64_path}/*

RUN tar -czf $WORKDR/lib64_deps.tar.gz \
    ${lib64_path}/libjson-c.so.2*
