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

FROM ubuntu:16.04

ENV IPADRESS=127.0.0.1
ENV FLASK_PORT=5000
ENV NGINX_PORT=5001
ENV GRAFANA_PORT=5002
ENV REDIS_PORT=6379
ENV POSTGRES_PORT=5432
ENV ZMQ_PORT=5555
ENV STAT_COLLECT_INTERVAL=15
ENV STAT_DUMP_INTERVAL=15
ENV WORKDR=/app/
ENV TZ=UTC
ENV LOGPATH=/tmp/
ENV LOGLEVEL=10
ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update && \
    apt-get install -y redis-server && \
    apt-get install -y python3 && \
    apt-get install -y supervisor && \
    apt-get -y install python3-pip --reinstall && \
    apt-get install -y nginx && \
    apt-get install -y net-tools && \
    apt-get install -y openssh-server && \
    apt-get install -y vim && \
    apt-get install -y sshpass && \
    apt-get install -y logrotate && \
    apt install -y libffi-dev && \
    wget --no-check-certificate https://dl.grafana.com/oss/release/grafana_7.0.1_amd64.deb && \
    dpkg -i grafana_7.0.1_amd64.deb && \
    rm grafana_7.0.1_amd64.deb

RUN echo "/tmp/*.log { \n\
su root root \n\
size 100M \n\
rotate 5 \n\
compress \n\
copytruncate \n\
missingok \n\
}\n" > /etc/logrotate.d/te-logs
RUN chmod 0644 /etc/logrotate.d/te-logs

#Creating a cron (Running cron job every 2 mins -- logrotate)
RUN echo "*/2 * * * * /usr/sbin/logrotate /etc/logrotate.d/te-logs" > /etc/cron.d/cron_logrotate_te_logs
RUN chmod 0644 /etc/cron.d/cron_logrotate_te_logs
RUN crontab /etc/cron.d/cron_logrotate_te_logs

COPY te_docker/requirements.txt /tmp/
RUN pip3 install --upgrade "pip < 21.0"
RUN pip3 install --requirement /tmp/requirements.txt

COPY te_docker/setup_postgres.sh /tmp/
RUN chmod 755 /tmp/setup_postgres.sh
RUN /tmp/setup_postgres.sh

COPY open_source_licenses.tar.bz2 /

COPY te_docker/te.conf /etc/nginx/sites-available/default
COPY te_docker/postgres_grafana_config.yaml /etc/grafana/provisioning/datasources/
COPY te_docker/grafana_dashboard_config.yaml /etc/grafana/provisioning/dashboards/
COPY te_docker/udp_client_metrics_dashboard.json /var/lib/grafana/dashboards/
COPY te_docker/tcp_client_metrics_dashboard.json /var/lib/grafana/dashboards/

ADD TE.py \
    TE_CLASS.py \
    TE_UTILS.py \
    TE_WORK.py \
    TE_DP_CONFIG.py \
    GET_AND_RUN_DOCKER_IMAGE.py \
    te_json_schema.py \
    TE_METRICS.py \
    $WORKDR

RUN mkdir $WORKDR/static
COPY te_swagger.json $WORKDR/static/

COPY tedp_docker.tar \
    /var/www/html/
RUN md5sum /var/www/html/tedp_docker.tar > /var/www/html/check.sum
ARG IMAGE_ID=-1
RUN echo $IMAGE_ID > /var/www/html/image.id
RUN chmod -R 755 /var/www/html/

RUN echo "Done TE Dockerization!\n"

ENTRYPOINT sed -i "s/5001/$NGINX_PORT/g" /etc/nginx/sites-available/default && \
    redis-server --port $REDIS_PORT --daemonize yes && /etc/init.d/nginx restart && \
    sed -i "s/5432/$POSTGRES_PORT/g" /etc/postgresql/*/main/postgresql.conf && \
    service postgresql restart && \
    service cron start && \
    sed -i "s/url: localhost:[0-9]*/url: localhost:$POSTGRES_PORT/g" /etc/grafana/provisioning/datasources/postgres_grafana_config.yaml && \
    echo "[supervisord]" >> /etc/supervisord.conf && \
    echo "nodaemon=true" >> /etc/supervisord.conf && \
    echo "[program:TE]" >> /etc/supervisord.conf && \
    echo "command=python3 $WORKDR/TE.py -m $IPADRESS -fp $FLASK_PORT -rp $REDIS_PORT -np $NGINX_PORT \
    -pp $POSTGRES_PORT -zp $ZMQ_PORT -gp $GRAFANA_PORT -ct $STAT_COLLECT_INTERVAL -dt $STAT_DUMP_INTERVAL \
    -lp $LOGPATH -ll $LOGLEVEL" >> /etc/supervisord.conf && /usr/bin/supervisord
