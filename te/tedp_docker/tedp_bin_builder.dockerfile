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
FROM ubuntu:22.04 as build_stage
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

# Deprecating usage of setup.sh - using ubuntu-22.04 lib-dev modules
RUN sed -i '/deb-src/s/^# //' /etc/apt/sources.list && apt update
RUN apt install automake libtool m4 -y
RUN apt install libjson-c-dev -y
RUN apt build-dep curl -y
RUN apt install wget -y
RUN apt install build-essential nghttp2 libnghttp2-dev -y


##########################################################
#  Purging openssl
RUN apt remove --purge -y libssl-dev libssl-doc openssl

# Custom install openssl 1.1.1
RUN cd /tmp \
    && wget --no-check-certificate https://www.openssl.org/source/openssl-1.1.1n.tar.gz \
    && tar -xzvf openssl-1.1.1n.tar.gz \
    && cd openssl-1.1.1n \
    && ./config --prefix=/usr/local --openssldir=/usr/local/ssl \
    && make -j$(nproc) && make install \
    && cd /tmp \
    && rm -rf openssl-1.1.1* \
    && ldconfig

# Install Zlib
RUN cd /tmp \
    && wget --no-check-certificate https://zlib.net/zlib-1.2.13.tar.gz \
    && tar -xzvf zlib-1.2.13.tar.gz \
    && cd zlib-1.2.13 \
    && ./configure --prefix=/usr/local \
    && make -j$(nproc) && make install \
    && cd /tmp \
    && rm -rf zlib-1.2.13* \
    && ldconfig

# Install curl-7.83
RUN cd /tmp \
    && wget --no-check-certificate https://curl.se/download/curl-7.83.0.tar.gz \
    && tar -xzvf curl-7.83.0.tar.gz \
    && cd curl-7.83.0 \
    && ./configure --prefix /usr/local --with-openssl=/usr/local --with-zlib=/usr/local --enable-ipv6 --with-nghttp2 \
    && make -j$(nproc) && make install \
    && cd /tmp \
    && rm -rf curl-7.83.0* \
    && ldconfig

RUN apt install -y libuv1-dev
RUN apt install -y libzmq3-dev

RUN mkdir -pv $WORKDR/bin && mkdir $WORKDR/obj
ADD te_dp/Makefile $WORKDR
ADD te_dp/src $WORKDR/src
RUN cd $WORKDR && make all

RUN tar -czf $WORKDR/usr_lib_deps.tar.gz \
    ${usr_lib_path}/libcurl.so* \
    ${usr_lib_path}/libssl.so.1* \
    ${usr_lib_path}/libz.so* \
    ${usr_lib_path}/libcrypto.so.1*

RUN tar -czf $WORKDR/usr_lib64_deps.tar.gz \
    ${usr_lib64_path}/*

RUN tar -czf $WORKDR/lib64_deps.tar.gz \
    ${lib64_path}/libjson-c.so.5* \
    ${lib64_path}/libuv.so.1* \
    ${lib64_path}/libzmq.so*
