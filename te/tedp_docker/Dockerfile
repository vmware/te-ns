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

# Stage 2 (Build final image)
FROM ubuntu:16.04
ENV WORKDR=/opt/te/
ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8
ENV IPADDRESS=127.0.0.1
ENV CTRL_IPADDRESS=127.0.0.1
ENV CTRL_FLASK_PORT=5000
ARG usr_lib_path=/usr/local/lib
ARG usr_lib64_path=/lib/x86_64-linux-gnu

# basic library and pkg install
RUN apt update && \
    apt install -y vim && \
    apt install -y python3 && \
    apt install -y python3-pip --reinstall && \
    apt install -y sshpass && \
    apt install -y logrotate && \
    apt install -y libffi-dev && \
    apt install -y cron && \
    apt install -y supervisor

# python related requirements
COPY te/tedp_docker/requirements.txt /tmp/
RUN pip3 install --upgrade "pip < 21.0"
RUN pip3 install --requirement /tmp/requirements.txt

COPY te/open_source_licenses.tar.bz2 /

# service file for te_stats_collector
RUN echo "[Unit] \n\
Description=stat collector service \n\
[Service] \n\
Type=simple \n\
Restart=always \n\
RestartSec=1 \n\
ExecStart=/opt/te/bin/te_stats_collector /te_host/stat_collector_config.json  \n\
" > /etc/systemd/system/te_stats_collector.service
RUN chmod 644 /etc/systemd/system/te_stats_collector.service

# memory mount dir with appropriate perm for root to rotate logs
RUN mkdir /tmp/ramcache && chmod -R 755 /tmp/ramcache

# logrotate for csv of process in ramcache and log files in /tmp/
RUN echo "/tmp/ramcache/*.csv { \n\
su root root \n\
size 5M \n\
rotate 5 \n\
compress \n\
copytruncate \n\
missingok \n\
}\n\
/tmp/*.log { \n\
su root root \n\
size 100M \n\
rotate 5 \n\
compress \n\
copytruncate \n\
missingok \n\
}\n" > /etc/logrotate.d/te-logs && chmod 0644 /etc/logrotate.d/te-logs

# cron job every 2 mins -- logrotate
RUN echo "*/2 * * * * /usr/sbin/logrotate /etc/logrotate.d/te-logs" > /etc/cron.d/cron_logrotate_te_logs && \
    chmod 0644 /etc/cron.d/cron_logrotate_te_logs && crontab /etc/cron.d/cron_logrotate_te_logs

# stat collector queue size config - maximum of 1000 messages each of size 10K can be sent in a queue
RUN echo "kernel.msgmax = 10240 //Size of each message in bytes (10K)" >> /etc/sysctl.conf && \
    echo "kernel.msgmnb = 10485760 //Size of the queue (10M)" >> /etc/sysctl.conf && \
    echo "net.ipv4.tcp_tw_recycle = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf && \
    echo "net.ipv4.ip_local_port_range = 2048 65535" >> /etc/sysctl.conf && \
    echo "fs.inotify.max_user_watches = 524288" >> /etc/sysctl.conf

# add python files
ADD te/TE_UTILS.py \
    te/TE_WORK.py \
    te/RQ_CONNECTOR.py \
    $WORKDR

# copy binary and library from previous stage
RUN mkdir -pv $WORKDR/bin
COPY --from=tedp_bin:v2.0 $WORKDR/bin $WORKDR/bin
COPY --from=tedp_bin:v2.0 $WORKDR/usr_lib64_deps.tar.gz ${usr_lib64_path}/usr_lib64_deps.tar.gz
COPY --from=tedp_bin:v2.0 $WORKDR/usr_lib_deps.tar.gz ${usr_lib_path}/usr_lib_deps.tar.gz
COPY --from=tedp_bin:v2.0 $WORKDR/lib64_deps.tar.gz ${lib64_path}/lib64_deps.tar.gz
RUN tar -xvf ${usr_lib_path}/usr_lib_deps.tar.gz -C / && rm ${usr_lib_path}/usr_lib_deps.tar.gz && \
    tar -xvf ${usr_lib64_path}/usr_lib64_deps.tar.gz -C / && rm ${usr_lib64_path}/usr_lib64_deps.tar.gz && \
    tar -xvf ${lib64_path}/lib64_deps.tar.gz -C / && rm ${lib64_path}/lib64_deps.tar.gz && \
    ldconfig -v

# add rq.service
RUN echo "[supervisord]" >> /etc/supervisord.conf && \
    echo "nodaemon=true" >> /etc/supervisord.conf && \
    echo "[program:RQ_CONNECTOR]" >> /etc/supervisord.conf && \
    echo "command=python3 /opt/te/RQ_CONNECTOR.py" >> /etc/supervisord.conf

# Add te/tedp_docker/clean_tedp.sh (used to clean tedp without ssh)
ADD te/tedp_docker/clean_tedp.sh $WORKDR/

# copy src and makefile for debug purpose
ADD te_dp/src $WORKDR/src
ADD te_dp/Makefile $WORKDR

RUN echo "Done TE_DP Dockerization!!"

ENTRYPOINT service cron restart && /usr/bin/supervisord
