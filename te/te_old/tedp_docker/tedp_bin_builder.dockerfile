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
    apt install -y libssl-dev -y libffi-dev  && \
    apt install -y libcurl3 && \
    apt install -y cmake && \
    apt purge -y libssl-dev && \
    apt install -y libboost-dev

# library install to make te_dp and te_stats_collector
COPY te/tedp_docker/setup.sh /tmp/
RUN chmod 755 /tmp/setup.sh
RUN /tmp/setup.sh

# make the binary
RUN mkdir -pv $WORKDR/bin && mkdir $WORKDR/obj
ADD te_dp/Makefile $WORKDR
ADD te_dp/src $WORKDR/src
RUN cd $WORKDR && make all

# bundle all necessary dep libraries
RUN tar -czvf $WORKDR/usr_lib_deps.tar.gz \
    ${usr_lib_path}/libcurl.so.4* \
    ${usr_lib_path}/libuv.so.1* \
    ${usr_lib_path}/libssl.so.1* \
    ${usr_lib_path}/libcrypto.so.1*

RUN tar -czvf $WORKDR/usr_lib64_deps.tar.gz \ 
    ${usr_lib64_path}/libnghttp2.so.14* \
    ${usr_lib64_path}/libldap_r-2.4.so.2* \
    ${usr_lib64_path}/libzmq.so.5* \
    ${usr_lib64_path}/libsodium.so.18*

RUN tar -czvf $WORKDR/lib64_deps.tar.gz \
    ${lib64_path}/libjson-c.so.2*
