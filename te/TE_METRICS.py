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

"""
#SAMPLE VIP METRICS QUERY
WITH vip_stats AS (
    SELECT vip AS vip_,
    sum(connections) AS connections,
    sum(sessions) AS sessions,
    sum(connections)/NULLIF(EXTRACT(EPOCH FROM max(tcp_client_vip_metrics.ts_ctrl)-min(tcp_client_vip_metrics.ts_ctrl)+15*'1 second'::interval),0) AS cps
    FROM tcp_client_vip_metrics WHERE (id > 0)
    GROUP BY vip
), url_stats AS (
    WITH temp AS (
        SELECT tcp_client_url_metrics.vip, tcp_client_url_metrics.method, tcp_client_url_metrics.uri,
        sum(mean_latency * resp_rcvd) / NULLIF(sum(resp_rcvd), 0) AS net_mean
        FROM tcp_client_url_metrics  WHERE (id > 0 )
        GROUP BY tcp_client_url_metrics.vip, tcp_client_url_metrics.method, tcp_client_url_metrics.uri
    )
    SELECT tcp_client_url_metrics.vip, tcp_client_url_metrics.method, tcp_client_url_metrics.uri,
    sum(http_gets_sent) AS http_gets_sent,
    sum(http_gets_rcvd) AS http_gets_rcvd,
    sum(http_posts_sent) AS http_posts_sent,
    sum(http_posts_rcvd) AS http_posts_rcvd,
    sum(reqs_sent) AS reqs_sent,
    sum(resp_rcvd) AS resp_rcvd,
    sum(responses_1xx) AS responses_1xx,
    sum(responses_2xx) AS responses_2xx,
    sum(responses_200) AS responses_200,
    sum(responses_3xx) AS responses_3xx,
    sum(responses_4xx) AS responses_4xx,
    sum(responses_404) AS responses_404,
    sum(responses_5xx) AS responses_5xx,
    sum(failed_reqs) AS failed_reqs,
    sum(len_fail) AS len_fail,
    sum(persist_fail) AS persist_fail,
    sum(tcp_failures) AS tcp_failures,
    min(latency_min) AS latency_min,
    max(latency_max) AS latency_max,
    sum(bytes_download) AS bytes_download,
    sum(responses_200)/NULLIF(EXTRACT(EPOCH FROM max(tcp_client_url_metrics.ts_ctrl)-min(tcp_client_url_metrics.ts_ctrl)+15*'1 second'::interval),0) AS rps,
    sum(bytes_download)/NULLIF(EXTRACT(EPOCH FROM max(tcp_client_url_metrics.ts_ctrl)-min(tcp_client_url_metrics.ts_ctrl)+15*'1 second'::interval),0) AS tput,
    sum(mean_latency * resp_rcvd) / NULLIF(sum(resp_rcvd), 0) AS mean_latency,
    sqrt(sum(resp_rcvd * (power(mean_latency - temp.net_mean, 2) + var_latency)) / NULLIF(sum(resp_rcvd), 0)) AS sd_latency
    FROM tcp_client_url_metrics
    INNER JOIN temp ON tcp_client_url_metrics.vip = temp.vip AND tcp_client_url_metrics.method = temp.method AND tcp_client_url_metrics.uri = temp.uri
    WHERE (tcp_client_url_metrics.id > 0)
    GROUP BY tcp_client_url_metrics.vip, tcp_client_url_metrics.method, tcp_client_url_metrics.uri
) SELECT * from url_stats INNER JOIN vip_stats ON url_stats.vip = vip_stats.vip_;

#SAMPLE QUERY TO MEMORY METRICS
https://stackoverflow.com/a/26388845
SELECT temp.index, SUM(malloc[temp.index]), SUM(free[temp.index]) FROM memory_metrics
JOIN (select generate_subscripts(malloc, 1) AS index, id AS iter FROM memory_metrics) AS temp
ON temp.iter = memory_metrics.id
GROUP BY temp.index;

#SAMPLE QUERY TO ERROR METRICS
https://dba.stackexchange.com/questions/100965/combining-separate-ranges-into-largest-possible-contiguous-ranges
WITH a AS (
    SELECT vip, res_tag, ses_tag, error_type, counter, ts_range,
    COALESCE(lower(ts_range),'-infinity') AS startdate,
    max(COALESCE(upper(ts_range), 'infinity')) OVER (ORDER BY ts_range) AS enddate
    FROM error_metrics
    INNER JOIN resource_configs ON resource_configs.res_hash = error_metrics.res_hash
    INNER JOIN session_configs ON session_configs.ses_hash = error_metrics.ses_hash
    WHERE vip='http://10.52.180.160'
),
b AS (
    SELECT *, lag(enddate) OVER (ORDER BY ts_range) < (startdate - (15 * interval '1 second')) OR NULL AS step
    FROM a
),
c AS (
    SELECT *, count(step) OVER (ORDER BY ts_range) AS grp
    FROM b
)
SELECT vip, res_tag, ses_tag, error_type, sum(counter), tsrange(min(startdate), max(enddate)) AS ts_range
FROM c
GROUP  BY vip, res_tag, ses_tag, error_type, grp;
"""


######################### ZMQ #########################
import asyncio, uvloop
import zmq, aiozmq

####################### FOR POSTGRES #####################
from psycopg2 import connect
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from psycopg2.extras import DictCursor

######################### GENERIC #########################
import traceback
import time, os
from concurrent import futures
import json
from collections import OrderedDict
from datetime import datetime
from copy import copy
import decimal
import numpy as np
from multiprocessing import Process
from threading import Thread

######################### TE IMPORTS #########################
from TE_UTILS import Logger, dict_merge, convert

######################### GLOBAL DEFs #########################
# Metrics Profile message
# NOTE: Metrics Profile message is shared with te_stat_collector.h and TE_WRAP.py
# Changes must be reflected at both the places
HTTP_PROFILE        = 1
UDP_CLIENT_PROFILE  = 2
UDP_SERVER_PROFILE  = 3

class TE_POSTGRES:
    def __init__(self, postgres_port, logpath, loglevel, stat_collect_interval):

        #LOGGER
        log_file = os.path.join(logpath, 'te-postgres.log')
        self.__lgr = Logger('[ TE POSTGRES ]', log_file, loglevel).getLogger()
        self.__lgr.info("Init Of TE_POSTGRES")
        self.__stat_collect_interval = stat_collect_interval

        try:
            self.__config = {
                'user'       : 'te',
                'password'   : 'te',
                'db'         : 'te',
                'host'       : 'localhost',
                'port'       : int(postgres_port),
            }

            init_connection = connect(dbname="postgres", user="postgres", password="postgres", \
                port=self.__config['port'])
            init_connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            try:
                with init_connection.cursor() as cursor:
                    cursor.execute("create user te with password 'te'")
                    cursor.execute("create database te")
                    cursor.execute("grant all privileges on database te to te")
                    init_connection.commit()
                    self.__lgr.info("Initialized database for te")
            except:
                init_connection.rollback()
                self.__lgr.error("Initial rollback %s" %traceback.format_exc())
            finally:
                init_connection.close()

            #Setting basic configuration for Postgres
            self.__configure_db()

            self.__configure_queries()

        except:
            self.__lgr.error("ERROR in __init__: %s" %traceback.format_exc())

    def alter_stat_collect_interval(self, stat_collect_interval):
        self.__stat_collect_interval = stat_collect_interval
        return

    def get_configs(self):
        return self.__config

    def __configure_queries(self):
        try:
            self.__metric_keys_as_csv = {}
            self.__metric_keys = {}

            #TCP CLIENT VIP METRICS
            self.__metric_keys['tcp_client_vip_metrics'] = ['connections', 'sessions']
            #'good_connections', 'failed_connections' ==> Has problem in TE_DP (ONly for TCP CLIENT)
            query_metric_list = []
            for number_key in self.__metric_keys['tcp_client_vip_metrics']:
                query_metric_list.append("sum(%s) AS %s" %(number_key, number_key))
            self.__metric_keys['tcp_client_vip_metrics'].append("cps")
            query_metric_list.append("sum(connections)/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS cps" %self.__stat_collect_interval)
            self.__metric_keys_as_csv["tcp_client_vip_metrics"] = ", ".join(query_metric_list)

            #UDP CLIENT VIP METRICS
            self.__metric_keys['udp_client_vip_metrics'] = ['good_connections', 'failed_connections', 'sessions']
            query_metric_list = []
            for number_key in self.__metric_keys['udp_client_vip_metrics']:
                query_metric_list.append("sum(%s) AS %s" %(number_key, number_key))
            self.__metric_keys['udp_client_vip_metrics'].append("cps")
            query_metric_list.append("sum(good_connections)/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS cps" %self.__stat_collect_interval)
            self.__metric_keys_as_csv["udp_client_vip_metrics"] = ", ".join(query_metric_list)

            #UDP SERVER VIP METRICS
            self.__metric_keys['udp_server_vip_metrics'] = ["dg_rcvd", "dg_recv_timedout",
                "dg_size_rcvd", "dg_sent", "dg_send_fail", "dg_size_sent", "request_rcvd", 
                "request_recv_timedout", "response_sent", "response_send_fail"]
            query_metric_list = []
            # Common Queries
            for number_key in self.__metric_keys['udp_server_vip_metrics']:
                query_metric_list.append("sum(%s) AS %s" %(number_key, number_key))
            # RPS
            self.__metric_keys['udp_server_vip_metrics'].append("rps")
            query_metric_list.append("(sum(request_rcvd)+sum(response_sent))/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS rps" %self.__stat_collect_interval)
            # DPS
            self.__metric_keys['udp_server_vip_metrics'].append("dps")
            query_metric_list.append("(sum(dg_sent)+sum(dg_rcvd))/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS dps" %self.__stat_collect_interval)
            # TPUT
            self.__metric_keys['udp_server_vip_metrics'].append("tput")
            query_metric_list.append("(sum(dg_size_sent)+sum(dg_size_rcvd))/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS tput" %self.__stat_collect_interval)
            # Add to __metric_keys_as_csv
            self.__metric_keys_as_csv["udp_server_vip_metrics"] = ", ".join(query_metric_list)

            #TCP CLIENT URL METRICS
            # Wait for the code to mature and clean up the mess below
            self.__metric_keys['tcp_client_url_metrics'] = \
                ["http_gets_sent", "http_gets_rcvd", "http_posts_sent", "http_posts_rcvd", "reqs_sent", \
                "resp_rcvd", "responses_1xx", "responses_2xx", "responses_200", "responses_3xx", \
                "responses_4xx", "responses_404", "responses_5xx", "failed_reqs", "len_fail", \
                "persist_fail", "tcp_failures", "bytes_download"]
            query_metric_list = []
            # Common queries
            for number_key in self.__metric_keys['tcp_client_url_metrics']:
                query_metric_list.append("sum(%s) AS %s" %(number_key, number_key))
            # Minimum Latency
            self.__metric_keys['tcp_client_url_metrics'].append("latency_min")
            query_metric_list.append("min(latency_min) AS latency_min")
            # Maximum Latency
            self.__metric_keys['tcp_client_url_metrics'].append("latency_max")
            query_metric_list.append("max(latency_max) AS latency_max")
            # RPS
            self.__metric_keys['tcp_client_url_metrics'].append("rps")
            query_metric_list.append("sum(responses_200)/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS rps" %self.__stat_collect_interval)
            # TPUT
            self.__metric_keys['tcp_client_url_metrics'].append("tput")
            query_metric_list.append("sum(bytes_download)/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS tput" %self.__stat_collect_interval)
            # Add to __metric_keys_as_csv
            self.__metric_keys_as_csv["tcp_client_url_metrics"] = ", ".join(query_metric_list)
            #Derived Keys (Not as a part of the table) -- seperate handling
            self.__metric_keys['tcp_client_url_metrics'].append("mean_latency")
            self.__metric_keys['tcp_client_url_metrics'].append("sd_latency")

            #UDP CLIENT URL METRICS
            self.__metric_keys['udp_client_url_metrics'] = \
                ["reqs_sent", "reqs_failed", "dg_sent", "dg_size_sent", "dg_send_fail",
                "resp_rcvd", "resp_timedout", "dg_recd", "dg_size_recd", "dg_recv_timedout",
                "latency_min", "latency_max", "mean_latency", "var_latency"]
            query_metric_list = []
            # Common queries
            for number_key in self.__metric_keys['udp_client_url_metrics']:
                query_metric_list.append("sum(%s) AS %s" %(number_key, number_key))
            # Minimum Latency
            self.__metric_keys['udp_client_url_metrics'].append("latency_min")
            query_metric_list.append("min(latency_min) AS latency_min")
            # Maximum Latency
            self.__metric_keys['udp_client_url_metrics'].append("latency_max")
            query_metric_list.append("min(latency_max) AS latency_max")
            # RPS
            self.__metric_keys['udp_client_url_metrics'].append("rps")
            query_metric_list.append("sum(resp_rcvd)/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS rps" %self.__stat_collect_interval)
            # TPUT
            self.__metric_keys['udp_client_url_metrics'].append("tput")
            query_metric_list.append("(sum(dg_size_sent)+sum(dg_size_recd))/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS tput" %self.__stat_collect_interval)
            #Datagrams Per Second
            self.__metric_keys['udp_client_url_metrics'].append("dps")
            query_metric_list.append("(sum(dg_sent)+sum(dg_recd))/NULLIF(EXTRACT(EPOCH FROM " \
                "max(ts_ctrl)-min(ts_ctrl)+%d*'1 second'::interval),0) AS dps" %self.__stat_collect_interval)
            # Add to __metric_keys_as_csv
            self.__metric_keys_as_csv['udp_client_url_metrics'] = ", ".join(query_metric_list)
            #Derived Keys (Not as a part of the table) -- seperate handling
            self.__metric_keys['udp_client_url_metrics'].append("mean_latency")
            self.__metric_keys['udp_client_url_metrics'].append("sd_latency")

            # TCP CLIENT SES METRICS
            self.__metric_keys['tcp_client_ses_metrics'] = \
                ['sessions','total_connections','cycles_complete','reqs_sent',\
                'resp_rcvd','http_gets_sent','http_gets_rcvd','http_posts_sent','http_posts_rcvd',\
                'failed_reqs','len_fail','persist_fail','post_fnf','bytes_download','complete_time',
                'open_connections']
            query_metric_list = []
            for number_key in self.__metric_keys['tcp_client_ses_metrics']:
                query_metric_list.append("sum(%s) AS %s" %(number_key, number_key))
            self.__metric_keys_as_csv["tcp_client_ses_metrics"] = ", ".join(query_metric_list)

            # UDP CLIENT SES METRICS
            self.__metric_keys['udp_client_ses_metrics'] = \
                ["sessions", "cycles_complete", "good_connections", "failed_connections", "reqs_sent",
                "reqs_failed", "dg_sent", "dg_size_sent", "dg_send_fail", "resp_rcvd", "resp_timedout",
                "dg_recd", "dg_size_recd", "dg_recv_timedout"]
            query_metric_list = []
            for number_key in self.__metric_keys['udp_client_ses_metrics']:
                query_metric_list.append("sum(%s) AS %s" %(number_key, number_key))
            self.__metric_keys_as_csv["udp_client_ses_metrics"] = ", ".join(query_metric_list)

            #MEMORY
            self.__metric_keys['memory_metrics'] = ['free', 'malloc']
            self.__metric_keys_as_csv["memory_metrics"] = ", ".join(query_metric_list)

            #Session and Resource Configs
            self.__metric_keys['session_configs'] = ['ses_config']
            self.__metric_keys['resource_configs'] = ['res_config']

        except:
            self.__lgr.error(traceback.format_exc())

    def __configure_db(self):
        self.__tables = {}
        self.__tables['resource_configs'] = """CREATE TABLE resource_configs (
            res_hash    VARCHAR(64) NOT NULL PRIMARY KEY,
            res_tag     VARCHAR(64) NOT NULL,
            res_config  JSON        NOT NULL )"""

        self.__tables['session_configs'] = """CREATE TABLE session_configs (
            ses_hash    VARCHAR(64) NOT NULL PRIMARY KEY,
            ses_tag     VARCHAR(64) NOT NULL,
            ses_config  JSON        NOT NULL )"""

        #RUNNING CONFIG TABLE (Holds the entire history of run)
        self.__tables['running_configs'] = """CREATE TABLE running_configs (
            res_hash        VARCHAR(64)  NOT NULL,
            ses_hash        VARCHAR(64)  NOT NULL,
            traffic_mode    VARCHAR(7)   NOT NULL,
            traffic_profile VARCHAR(4)   NOT NULL,
            host_ip         VARCHAR(128) NOT NULL,
            cpu             INTEGER      NOT NULL,
            start_time      TIMESTAMP    NOT NULL,
            end_time        TIMESTAMP    )"""

        self.__tables['tcp_client_vip_metrics'] = """CREATE TABLE tcp_client_vip_metrics (
            id                 BIGSERIAL,
            ts_ctrl            TIMESTAMP      NOT NULL,
            ts                 TIMESTAMP      NOT NULL,
            host_ip            VARCHAR(128)   NOT NULL,
            vip                VARCHAR(128)   NOT NULL,
            res_hash           VARCHAR(64)    NOT NULL,
            ses_hash           VARCHAR(64)    NOT NULL,
            connections        NUMERIC(20,1)  NOT NULL,
            good_connections   NUMERIC(20,1)  NOT NULL,
            failed_connections NUMERIC(20,1)  NOT NULL,
            sessions           NUMERIC(20,1)  NOT NULL,
            PRIMARY KEY(ts, host_ip, vip, res_hash, ses_hash) )"""

        self.__tables['udp_client_vip_metrics'] = """CREATE TABLE udp_client_vip_metrics (
            id                 BIGSERIAL,
            ts_ctrl            TIMESTAMP      NOT NULL,
            ts                 TIMESTAMP      NOT NULL,
            host_ip            VARCHAR(128)   NOT NULL,
            vip                VARCHAR(128)   NOT NULL,
            res_hash           VARCHAR(64)    NOT NULL,
            ses_hash           VARCHAR(64)    NOT NULL,
            good_connections   NUMERIC(20,1)  NOT NULL,
            failed_connections NUMERIC(20,1)  NOT NULL,
            sessions           NUMERIC(20,1)  NOT NULL,
            PRIMARY KEY(ts, host_ip, vip, res_hash, ses_hash) )"""

        self.__tables['udp_server_vip_metrics'] = """CREATE TABLE udp_server_vip_metrics (
            id                    BIGSERIAL,
            ts_ctrl               TIMESTAMP      NOT NULL,
            ts                    TIMESTAMP      NOT NULL,
            host_ip               VARCHAR(128)   NOT NULL,
            vip                   VARCHAR(128)   NOT NULL,
            dg_rcvd               NUMERIC(20,1)  NOT NULL,
            dg_recv_timedout      NUMERIC(20,1)  NOT NULL,
            dg_size_rcvd          NUMERIC(20,1)  NOT NULL,
            dg_sent               NUMERIC(20,1)  NOT NULL,
            dg_send_fail          NUMERIC(20,1)  NOT NULL,
            dg_size_sent          NUMERIC(20,1)  NOT NULL,
            request_rcvd          NUMERIC(20,1)  NOT NULL,
            request_recv_timedout NUMERIC(20,1)  NOT NULL,
            response_sent         NUMERIC(20,1)  NOT NULL,
            response_send_fail    NUMERIC(20,1)  NOT NULL,
            PRIMARY KEY(ts, host_ip, vip) )"""

        self.__tables['ses_bucket_metrics'] = """CREATE TABLE ses_bucket_metrics (
            id                BIGSERIAL,
            ts_ctrl           TIMESTAMP      NOT NULL,
            ts                TIMESTAMP      NOT NULL,
            host_ip           VARCHAR(128)   NOT NULL,
            vip               VARCHAR(128)   NOT NULL,
            res_hash          VARCHAR(64)    NOT NULL,
            ses_hash          VARCHAR(64)    NOT NULL,
            metrics           JSON           NOT NULL,
            PRIMARY KEY(ts, host_ip, vip, res_hash, ses_hash) )"""

        self.__tables['tcp_client_url_metrics'] = """CREATE TABLE tcp_client_url_metrics (
            id                BIGSERIAL,
            ts_ctrl           TIMESTAMP      NOT NULL,
            ts                TIMESTAMP      NOT NULL,
            host_ip           VARCHAR(128)   NOT NULL,
            vip               VARCHAR(128)   NOT NULL,
            method            VARCHAR(10)    NOT NULL,
            uri               VARCHAR(128)   NOT NULL,
            res_hash          VARCHAR(64)    NOT NULL,
            ses_hash          VARCHAR(64)    NOT NULL,
            http_gets_sent    NUMERIC(20,1) NOT NULL,
            http_gets_rcvd    NUMERIC(20,1) NOT NULL,
            http_posts_sent   NUMERIC(20,1) NOT NULL,
            http_posts_rcvd   NUMERIC(20,1) NOT NULL,
            reqs_sent         NUMERIC(20,1) NOT NULL,
            resp_rcvd         NUMERIC(20,1) NOT NULL,
            responses_1xx     NUMERIC(20,1) NOT NULL,
            responses_2xx     NUMERIC(20,1) NOT NULL,
            responses_200     NUMERIC(20,1) NOT NULL,
            responses_3xx     NUMERIC(20,1) NOT NULL,
            responses_4xx     NUMERIC(20,1) NOT NULL,
            responses_404     NUMERIC(20,1) NOT NULL,
            responses_5xx     NUMERIC(20,1) NOT NULL,
            failed_reqs       NUMERIC(20,1) NOT NULL,
            len_fail          NUMERIC(20,1) NOT NULL,
            persist_fail      NUMERIC(20,1) NOT NULL,
            tcp_failures      NUMERIC(20,1) NOT NULL,
            mean_latency      NUMERIC(20,15) NOT NULL,
            var_latency       NUMERIC(20,15) NOT NULL,
            latency_min       NUMERIC(20,15) NOT NULL,
            latency_max       NUMERIC(20,15) NOT NULL,
            bytes_download    NUMERIC(30,10) NOT NULL,
            PRIMARY KEY(ts, host_ip, vip, method, uri, res_hash, ses_hash) )"""

        self.__tables['udp_client_url_metrics'] = """CREATE TABLE udp_client_url_metrics (
            id                BIGSERIAL,
            ts_ctrl           TIMESTAMP      NOT NULL,
            ts                TIMESTAMP      NOT NULL,
            host_ip           VARCHAR(128)   NOT NULL,
            vip               VARCHAR(128)   NOT NULL,
            method            VARCHAR(10)    NOT NULL,
            res_hash          VARCHAR(64)    NOT NULL,
            ses_hash          VARCHAR(64)    NOT NULL,
            reqs_sent         NUMERIC(20,1)  NOT NULL,
            reqs_failed       NUMERIC(20,1)  NOT NULL,
            dg_sent           NUMERIC(20,1)  NOT NULL,
            dg_size_sent      NUMERIC(20,1)  NOT NULL,
            dg_send_fail      NUMERIC(20,1)  NOT NULL,
            resp_rcvd         NUMERIC(20,1)  NOT NULL,
            resp_timedout     NUMERIC(20,1)  NOT NULL,
            dg_recd           NUMERIC(20,1)  NOT NULL,
            dg_size_recd      NUMERIC(20,1)  NOT NULL,
            dg_recv_timedout  NUMERIC(20,1)  NOT NULL,
            latency_min       NUMERIC(20,15) NOT NULL,
            latency_max       NUMERIC(20,15) NOT NULL,
            mean_latency      NUMERIC(20,15) NOT NULL,
            var_latency       NUMERIC(20,15) NOT NULL,
            PRIMARY KEY(ts, host_ip, vip, method, res_hash, ses_hash) )"""

        self.__tables['url_bucket_metrics'] = """CREATE TABLE url_bucket_metrics (
            id                BIGSERIAL,
            ts_ctrl           TIMESTAMP      NOT NULL,
            ts                TIMESTAMP      NOT NULL,
            host_ip           VARCHAR(128)   NOT NULL,
            vip               VARCHAR(128)   NOT NULL,
            method            VARCHAR(10)    NOT NULL,
            uri               VARCHAR(128)   NOT NULL,
            res_hash          VARCHAR(64)    NOT NULL,
            ses_hash          VARCHAR(64)    NOT NULL,
            metrics           JSON           NOT NULL,
            PRIMARY KEY(ts, host_ip, vip, method, uri, res_hash, ses_hash) )"""

        self.__tables['tcp_client_ses_metrics'] = """CREATE TABLE tcp_client_ses_metrics (
            id                BIGSERIAL,
            ts_ctrl           TIMESTAMP      NOT NULL,
            ts                TIMESTAMP      NOT NULL,
            host_ip           VARCHAR(128)   NOT NULL,
            res_hash          VARCHAR(64)    NOT NULL,
            ses_hash          VARCHAR(64)    NOT NULL,
            sessions          NUMERIC(20,1)  NOT NULL,
            open_connections  NUMERIC(20,1)  NOT NULL,
            total_connections NUMERIC(20,1)  NOT NULL,
            cycles_complete   NUMERIC(20,1)  NOT NULL,
            reqs_sent         NUMERIC(20,1)  NOT NULL,
            resp_rcvd         NUMERIC(20,1)  NOT NULL,
            http_gets_sent    NUMERIC(20,1)  NOT NULL,
            http_gets_rcvd    NUMERIC(20,1)  NOT NULL,
            http_posts_sent   NUMERIC(20,1)  NOT NULL,
            http_posts_rcvd   NUMERIC(20,1)  NOT NULL,
            failed_reqs       NUMERIC(20,1)  NOT NULL,
            len_fail          NUMERIC(20,1)  NOT NULL,
            persist_fail      NUMERIC(20,1)  NOT NULL,
            post_fnf          NUMERIC(20,1)  NOT NULL,
            bytes_download    NUMERIC(30,10) NOT NULL,
            complete_time     NUMERIC(30,15) NOT NULL,
            PRIMARY KEY(ts, host_ip, res_hash, ses_hash) )"""

        self.__tables['udp_client_ses_metrics'] = """CREATE TABLE udp_client_ses_metrics (
            id                  BIGSERIAL,
            ts_ctrl             TIMESTAMP      NOT NULL,
            ts                  TIMESTAMP      NOT NULL,
            host_ip             VARCHAR(128)   NOT NULL,
            res_hash            VARCHAR(64)    NOT NULL,
            ses_hash            VARCHAR(64)    NOT NULL,
            sessions            NUMERIC(20,1)  NOT NULL,
            cycles_complete     NUMERIC(20,1)  NOT NULL,
            good_connections    NUMERIC(20,1)  NOT NULL,
            failed_connections  NUMERIC(20,1)  NOT NULL,
            reqs_sent           NUMERIC(20,1)  NOT NULL,
            reqs_failed         NUMERIC(20,1)  NOT NULL,
            dg_sent             NUMERIC(20,1)  NOT NULL,
            dg_size_sent        NUMERIC(20,1)  NOT NULL,
            dg_send_fail        NUMERIC(20,1)  NOT NULL,
            resp_rcvd           NUMERIC(20,1)  NOT NULL,
            resp_timedout       NUMERIC(20,1)  NOT NULL,
            dg_recd             NUMERIC(20,1)  NOT NULL,
            dg_size_recd        NUMERIC(20,1)  NOT NULL,
            dg_recv_timedout    NUMERIC(20,1)  NOT NULL,
            PRIMARY KEY(ts, host_ip, res_hash, ses_hash) )"""


        self.__tables['memory_metrics'] = """CREATE TABLE memory_metrics (
            id                BIGSERIAL,
            ts_ctrl           TIMESTAMP      NOT NULL,
            ts                TIMESTAMP      NOT NULL,
            host_ip           VARCHAR(128)   NOT NULL,
            res_hash          VARCHAR(64)    NOT NULL,
            ses_hash          VARCHAR(64)    NOT NULL,
            pid               INTEGER        NOT NULL,
            malloc            INTEGER[]      NOT NULL,
            free              INTEGER[]      NOT NULL,
            PRIMARY KEY(ts, host_ip, res_hash, ses_hash, pid) )"""

        self.__tables['error_metrics'] = """CREATE TABLE error_metrics (
            id                BIGSERIAL,
            ts_ctrl           TIMESTAMP      NOT NULL,
            ts                TIMESTAMP      NOT NULL,
            host_ip           VARCHAR(128)   NOT NULL,
            vip               VARCHAR(128)   NOT NULL,
            method            VARCHAR(10)    NOT NULL,
            uri               VARCHAR(128)   NOT NULL,
            res_hash          VARCHAR(64)    NOT NULL,
            ses_hash          VARCHAR(64)    NOT NULL,
            error_type        VARCHAR(128)   NOT NULL,
            ts_range          TSRANGE        NOT NULL,
            counter           NUMERIC(20,1)  NOT NULL,
            PRIMARY KEY(ts, host_ip, vip, method, uri, res_hash, error_type, ses_hash) )"""

        create_table_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
            password=self.__config['password'], port=self.__config['port'])
        try:
            with create_table_connection.cursor() as cursor:
                for table_name, query_to_create in self.__tables.items():
                    cursor.execute(query_to_create)
                    create_table_connection.commit()
                    self.__lgr.info("Created table {}".format(table_name))
        except:
            create_table_connection.rollback()
            self.__lgr.error("Rollback during creation of {} ERROR={}".format(table_name, \
                traceback.format_exc()))
        finally:
            create_table_connection.close()

        try:
            self.__intialize_row_counters()
            #Specifies the keys that are grouped by, by default
            self.__default_select_keys = {}
            self.__default_select_keys['tcp_client_vip_metrics'] = ['vip']
            self.__default_select_keys['tcp_client_url_metrics'] = ['vip']
            self.__default_select_keys['udp_client_vip_metrics'] = ['vip']
            self.__default_select_keys['udp_server_vip_metrics'] = ['vip']
            self.__default_select_keys['udp_client_url_metrics'] = ['vip']
            self.__default_select_keys['error_metrics'] = ['vip', 'error_type']
            self.__default_select_keys['memory_metrics'] = ['index']
            self.__default_select_keys['tcp_client_ses_metrics'] = []
            self.__default_select_keys['udp_client_ses_metrics'] = []

            #Specifies the order in which the group by operation has to be performed
            self.__ORDER_OF_GROUP_BY = ['res_hash', 'res_tag', 'ses_hash', 'ses_tag', 'host_ip', 'vip',
                    'method', 'uri', #Only for tcp_client_url_metrics
                    'error_type', #Only for error_metrics
                    'pid', 'index' #Only for memory_metrics
                ]

            self.__lgr.debug("ORDER: %s" %str(self.__ORDER_OF_GROUP_BY))

        except:
            self.__lgr.error(traceback.format_exc())

    def __intialize_row_counters(self):
        self.__last_read_row = {}
        for key in self.__tables:
            self.__last_read_row[key] = 0

    def __insert_with_ts(self, conn, table_name, *args):
        try:
            values = ", ".join(map(str,args))
            insert_query = "INSERT INTO {} VALUES (DEFAULT, {}, {})".format(table_name,
                "'{}'".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), values)
            self.__lgr.debug("__insert_with_ts={}".format(insert_query))
            with conn.cursor() as cursor:
                cursor.execute(insert_query)
                conn.commit()
            return True
        except:
            self.__lgr.error(traceback.format_exc())
            conn.rollback()
            return False
    
    def __insert(self, conn, table_name, *args):
        try:
            values = ", ".join(map(str,args))
            insert_query = "INSERT INTO {} VALUES ({})".format(table_name, values)
            with conn.cursor() as cursor:
                cursor.execute(insert_query)
                conn.commit()
            return True
        except:
            self.__lgr.error(traceback.format_exc())
            conn.rollback()
            return False

    def __execute_query(self, conn, query, fetch=True):
        try:
            with conn.cursor(cursor_factory=DictCursor) as cursor:
                cursor.execute(query)
                if not fetch:
                    return True
                else:
                    result = cursor.fetchall()
            conn.commit()
            return result
        except:
            conn.rollback()
            self.__lgr.error("Error during executing {}. ERROR={}".format(query, traceback.format_exc()))
            return None

    def __insert_server_vip_metrics(self, db_connection, ts, host_ip, metrics_dict):
        table_name = 'udp_server_vip_metrics'
        for vip, metric_json in metrics_dict.items():
            self.__insert_with_ts(db_connection, table_name,
                "'{}'".format(ts), "'{}'".format(host_ip), "'{}'".format(vip), \
                metric_json['dg_rcvd'], metric_json['dg_recv_timedout'], metric_json['dg_size_rcvd'],
                metric_json['dg_sent'], metric_json['dg_send_fail'], metric_json['dg_size_sent'],
                metric_json['request_rcvd'], metric_json['request_recv_timedout'],
                metric_json['response_sent'], metric_json['response_send_fail'])

    def __insert_vip_metrics(self, db_connection, ts, host_ip, metrics_dict, is_bucketed=False):
        try:
            if(is_bucketed):
                table_name = 'ses_bucket_metrics'
            else:
                table_name = {
                    HTTP_PROFILE       : 'tcp_client_vip_metrics',
                    UDP_CLIENT_PROFILE : 'udp_client_vip_metrics'
                }
            for res_hash, res_hash_values in metrics_dict.items():
                for ses_hash, ses_hash_values in res_hash_values.items():
                    for vip, metric_json in ses_hash_values.items():
                        profile_type = metric_json.get("profile_type", -1)

                        if(profile_type == UDP_CLIENT_PROFILE):
                            self.__insert_with_ts(db_connection, table_name[profile_type],
                                "'{}'".format(ts), "'{}'".format(host_ip), "'{}'".format(vip), \
                                res_hash, ses_hash, metric_json['good_connections'], \
                                metric_json['failed_connections'], metric_json['sessions'])

                        elif(profile_type == HTTP_PROFILE):
                            if is_bucketed:
                                metric_json = {"buckets" : metric_json}
                                self.__insert_with_ts(db_connection, table_name[profile_type],
                                    "'{}'".format(ts), "'{}'".format(host_ip), "'{}'".format(vip), \
                                    res_hash, ses_hash, "'{}'".format(metric_json))
                            else:
                                self.__insert_with_ts(db_connection, table_name[profile_type],
                                    "'{}'".format(ts), "'{}'".format(host_ip), "'{}'".format(vip), \
                                    res_hash, ses_hash, metric_json['connections'], \
                                    metric_json['good_connections'], metric_json['failed_connections'], \
                                    metric_json['sessions'])
        except:
            self.__lgr.error("%s: %s" %(table_name, traceback.format_exc()))

    def __insert_memory_metrics(self, db_connection, ts, host_ip, metrics_dict):
        try:
            table_name = 'memory_metrics'
            for res_hash, res_hash_values in metrics_dict.items():
                for ses_hash, ses_hash_values in res_hash_values.items():
                    for pid, metric_json in ses_hash_values.items():
                        self.__insert_with_ts(db_connection, table_name,
                                "'{}'".format(ts), "'{}'".format(host_ip), res_hash, ses_hash, pid,
                                "array{}".format(metric_json['malloc_metric']),
                                "array{}".format(metric_json['free_metric']))
        except:
            self.__lgr.error("%s: %s" %(table_name, traceback.format_exc()))

    def __insert_error_metrics(self, db_connection, ts, host_ip, metrics_dict):
        try:
            table_name = 'error_metrics'
            for res_hash, res_hash_values in metrics_dict.items():
                for ses_hash, ses_hash_values in res_hash_values.items():
                    for vip, vip_values in ses_hash_values.items():
                        for method, method_values in vip_values.items():
                            for uri, error_values in method_values.items():
                                for error_type, metric_json in error_values.items():
                                    self.__insert_with_ts(db_connection, table_name,
                                        "'{}'".format(ts), "'{}'".format(host_ip), \
                                        "'{}'".format(vip), "'{}'".format(method), \
                                        "'{}'".format(uri), res_hash, ses_hash, \
                                        "'{}'".format(error_type.replace("'",'')), "'[{}, {}]'".format(
                                            metric_json['start_time'].rstrip(),
                                            metric_json['end_time'].rstrip()),
                                        metric_json['counter'])
        except:
            self.__lgr.error("%s: %s" %(table_name, traceback.format_exc()))

    def __insert_url_metrics(self, db_connection, ts, host_ip, metrics_dict, is_bucketed=False):
            try:
                if(is_bucketed):
                    table_name = 'url_bucket_metrics'
                else:
                    table_name = {
                        HTTP_PROFILE       : 'tcp_client_url_metrics',
                        UDP_CLIENT_PROFILE : 'udp_client_url_metrics'
                    }
                for res_hash, res_hash_values in metrics_dict.items():
                    for ses_hash, ses_hash_values in res_hash_values.items():
                        for vip, vip_values in ses_hash_values.items():
                            for method, method_values in vip_values.items():
                                for uri, metric_json in method_values.items():
                                    profile_type = metric_json.get("profile_type", -1)
                                    if(profile_type == UDP_CLIENT_PROFILE):
                                        self.__insert_with_ts(db_connection, table_name[profile_type],
                                                "'{}'".format(ts), "'{}'".format(host_ip),
                                                "'{}'".format(vip), "'{}'".format(method),
                                                res_hash, ses_hash,
                                                metric_json['reqs_sent'], metric_json['reqs_failed'],
                                                metric_json['dg_sent'], metric_json['dg_size_sent'],
                                                metric_json['dg_send_fail'], metric_json['resp_recd'],
                                                metric_json['resp_timedout'], metric_json['dg_recd'],
                                                metric_json['dg_size_recd'], metric_json['dg_recv_timedout'],
                                                "'{}'".format(metric_json.get('min_latency','NaN')),
                                                metric_json.get('max_latency', 0),
                                                metric_json.get('mean_latency', 0),
                                                metric_json.get('var_latency', 0))
                                    elif(profile_type == HTTP_PROFILE):
                                        if is_bucketed:
                                            metric_json = {"buckets" : metric_json}
                                            self.__insert_with_ts(db_connection, table_name[profile_type],
                                                "'{}'".format(ts), "'{}'".format(host_ip), \
                                                "'{}'".format(vip), "'{}'".format(method), \
                                                "'{}'".format(uri), res_hash, ses_hash, \
                                                "'{}'".format(metric_json))
                                        else:
                                            # mean and var latency are calculalted on the fly by
                                            # stat_collector and can be potentially be unavailable
                                            self.__insert_with_ts(db_connection, table_name[profile_type], 
                                                "'{}'".format(ts), "'{}'".format(host_ip),
                                                "'{}'".format(vip), "'{}'".format(method),
                                                "'{}'".format(uri), res_hash, ses_hash,
                                                metric_json['http_gets_sent'],
                                                metric_json['http_gets_rcvd'],
                                                metric_json['http_posts_sent'],
                                                metric_json['http_posts_rcvd'],
                                                metric_json['reqs_sent'], metric_json['resp_rcvd'],
                                                metric_json['responses_1xx'],
                                                metric_json['responses_2xx'],
                                                metric_json['responses_200'],
                                                metric_json['responses_3xx'],
                                                metric_json['responses_4xx'],
                                                metric_json['responses_404'],
                                                metric_json['responses_5xx'],
                                                metric_json['failed_reqs'],
                                                metric_json['len_fail'],
                                                metric_json['persist_fail'],
                                                metric_json['tcp_failures'],
                                                metric_json.get('mean_latency', 0),
                                                metric_json.get('var_latency', 0),
                                                metric_json['min_time'], metric_json['max_time'],
                                                metric_json['bytes_download'])
            except:
                self.__lgr.error("%s: %s" %(table_name, traceback.format_exc()))

    def __insert_ses_metrics(self, db_connection, ts, host_ip, metrics_dict):
        try:
            for res_hash, res_hash_values in metrics_dict.items():
                for ses_hash, metric_json in res_hash_values.items():
                    profile_type = metric_json.get("profile_type", -1)
                    if(profile_type == UDP_CLIENT_PROFILE):
                        table_name = 'udp_client_ses_metrics'
                        self.__insert_with_ts(db_connection, table_name,
                            "'%s'"%ts, "'%s'"%host_ip, res_hash, ses_hash,
                            metric_json['sessions'], metric_json['cycles_complete'],
                            metric_json['good_connections'], metric_json['failed_connections'],
                            metric_json['reqs_sent'], metric_json['reqs_failed'],
                            metric_json['dg_sent'], metric_json['dg_size_sent'],
                            metric_json['dg_send_fail'], metric_json['resp_recd'],
                            metric_json['resp_timedout'], metric_json['dg_recd'],
                            metric_json['dg_size_recd'], metric_json['dg_recv_timedout'])
                    elif(profile_type == HTTP_PROFILE):
                        table_name =  'tcp_client_ses_metrics'
                        self.__insert_with_ts(db_connection, table_name,
                            "'%s'"%ts, "'%s'"%host_ip, res_hash, ses_hash,
                            metric_json['sessions'], metric_json['open_connections'],
                            metric_json['total_connections'], metric_json['cycles_complete'],
                            metric_json['reqs_sent'], metric_json['resp_rcvd'],
                            metric_json['http_gets_sent'], metric_json['http_gets_rcvd'],
                            metric_json['http_posts_sent'], metric_json['http_posts_rcvd'],
                            metric_json['failed_reqs'], metric_json['len_fail'],
                            metric_json['persist_fail'], metric_json['post_fnf'],
                            metric_json['bytes_download'], metric_json['complete_time'])
        except:
            self.__lgr.error("%s: %s" %(table_name, traceback.format_exc()))

    def clear_tables(self):
        clear_table_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
            password=self.__config['password'], port=self.__config['port'])
        delete_tables = ", ".join(self.__tables.keys())
        delete_query = "TRUNCATE TABLE {} RESTART IDENTITY CASCADE".format(delete_tables)
        self.__lgr.debug("Trying to TRUNCATE table with command {}".format(delete_query))
        try:
            with clear_table_connection.cursor() as cursor:
                cursor.execute(delete_query)
                clear_table_connection.commit()
                self.__intialize_row_counters()
            return True
        except:
            clear_table_connection.rollback()
            self.__lgr.error(traceback.format_exc())
            return False
        finally:
            clear_table_connection.close()

    def insert_metrics_to_db(self, metrics):
        try:
            db_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
                password=self.__config['password'], port=self.__config['port'])
            ts = metrics['ts']
            host_ip = metrics['host_ip']

            #CLIENT VIP METRICS
            metric_json = metrics.get('vip_metrics', {})
            if(bool(metric_json)):
                self.__insert_vip_metrics(db_connection, ts, host_ip, metric_json)
            metric_json = metrics.get('ses_bucket_metrics', {})
            if(bool(metric_json)):
                self.__insert_vip_metrics(db_connection, ts, host_ip, metric_json, True)

            #SERVER VIP METRICS
            metric_json = metrics.get('server_vip_metrics', {})
            if(bool(metric_json)):
                self.__insert_server_vip_metrics(db_connection, ts, host_ip, metric_json)

            #URL METRICS
            metric_json = metrics.get('url_metrics', {})
            if(bool(metric_json)):
                self.__insert_url_metrics(db_connection, ts, host_ip, metric_json)
            metric_json = metrics.get('url_bucket_metrics', {})
            if(bool(metric_json)):
                self.__insert_url_metrics(db_connection, ts, host_ip, metric_json, True)

            #SES METRICS
            metric_json = metrics.get('ses_metrics', {})
            if(bool(metric_json)):
                self.__insert_ses_metrics(db_connection, ts, host_ip, metric_json)

            #ERROR METRICS
            metric_json = metrics.get('error_metrics', {})
            if(bool(metric_json)):
                self.__insert_error_metrics(db_connection, ts, host_ip, metric_json)

            #MEMORY METRICS
            metric_json = metrics.get('memory_metrics', {})
            if(bool(metric_json)):
                self.__insert_memory_metrics(db_connection, ts, host_ip, metric_json)

        except:
            self.__lgr.error(traceback.format_exc())

    def insert_configs(self, res_tag, res_hash, res, ses_tag, ses_hash, ses):
        conn = connect(dbname=self.__config['db'], user=self.__config['user'], \
            password=self.__config['password'], port=self.__config['port'])
        try:
            check_query = "SELECT EXISTS(SELECT 1 FROM {} WHERE {}='{}')"

            result = self.__execute_query(conn, check_query.format("resource_configs", "res_hash", res_hash))
            if bool(result[0]) and not(bool(result[0][0])):
                self.__insert(conn, "resource_configs", res_hash, "'{}'".format(res_tag), \
                    "'{}'".format(json.dumps(res)))
            elif not(bool(result[0])):
                self.__lgr.error("Wrong DB Query")

            result = self.__execute_query(conn, check_query.format("session_configs", "ses_hash", ses_hash))
            if bool(result[0]) and not(bool(result[0][0])):
                self.__insert(conn, "session_configs", ses_hash, "'{}'".format(ses_tag), \
                    "'{}'".format(json.dumps(ses)))
            elif not(bool(result[0])):
                self.__lgr.error("Wrong DB Query")
        except:
            self.__lgr.error(traceback.format_exc())
        finally:
            conn.close()

    def insert_running_configs(self, host_ip, cpu, res_hash, ses_hash, traffic_mode, traffic_profile):
        conn = connect(dbname=self.__config['db'], user=self.__config['user'], \
            password=self.__config['password'], port=self.__config['port'])
        try:
            self.__lgr.debug("insert_running_configs Called")
            self.__insert(conn, "running_configs", res_hash, ses_hash, "'{}'".format(traffic_mode),
                "'{}'".format(traffic_profile), "'{}'".format(host_ip), cpu, \
                "'{}'".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), "NULL")
        except:
            self.__lgr.error(traceback.format_exc())
        finally:
            conn.close()

    def update_stop_time_running_configs(self, host_ip, cpu):
        conn = connect(dbname=self.__config['db'], user=self.__config['user'], \
            password=self.__config['password'], port=self.__config['port'])
        try:
            self.__lgr.debug("update_stop_time_running_configs Called")
            update_query = """UPDATE running_configs SET end_time = {} WHERE
                host_ip={} AND cpu={} AND end_time is NULL"""
            result = self.__execute_query(conn, update_query.format(
                "'{}'".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")), \
                "'{}'".format(host_ip), cpu), False)
            if not bool(result):
                self.__lgr.error("Wrong DB Query")
        except:
            self.__lgr.error(traceback.format_exc())

    def update_running_configs(self, host_ip, cpu, res_hash, ses_hash, traffic_mode, traffic_profile):
        self.__lgr.debug("update_running_configs Called")
        self.update_stop_time_running_configs(host_ip, cpu)
        self.insert_running_configs(host_ip, cpu, res_hash, ses_hash, traffic_mode, traffic_profile)

    def __query_last_row(self, conn, cmd_last_row_number):
        last_row = self.__execute_query(conn, cmd_last_row_number)
        for details in last_row:
            self.__lgr.debug("LAST ROW={}".format(details))
            return details['id']

    def __query_db(self, conn, cmd_query, cmd_last_row_number=None):
        last_row_id = None
        result = None
        result = self.__execute_query(conn, cmd_query)
        if cmd_last_row_number is not None:
            last_row_id = self.__query_last_row(conn, cmd_last_row_number)
        return result, last_row_id

    def __get_sql_statements(self, mode, table_name, filter_clauses_param):
        try:
            where_clause = OrderedDict()
            custom_keys = []
            keys_list = []
            filter_clauses = copy(filter_clauses_param)

            self.__lgr.debug("%s filter_clauses => %s" %(table_name, str(filter_clauses)))

            #Doesn't make sense to filter on both res_tag and res_hash at once
            #Similar case with ses_tag and ses_hash
            is_res_hash_filter_present = filter_clauses.get('res_hash',None)
            is_res_tag_filter_present = filter_clauses.get('res_tag',None)
            if is_res_hash_filter_present is not None and is_res_tag_filter_present is not None:
                return False, "Not possible to filter on both res_hash and res_tag at once"

            is_ses_hash_filter_present = filter_clauses.get('ses_hash',None)
            is_ses_tag_filter_present = filter_clauses.get('ses_tag',None)
            if is_ses_hash_filter_present is not None and is_ses_tag_filter_present is not None:
                return False, "Not possible to filter on both ses_hash and ses_tag at once"

            if(filter_clauses.get('ts_range', None) is not None):
                start_appended = False
                if(bool(filter_clauses['ts_range'])):
                    if(len(filter_clauses['ts_range']) != 2):
                        return False, "ts_range filter must possess start and end timestamps"
                    start, end = filter_clauses['ts_range']
                    if(start is not None):
                        where_clause['ts_range'] = "ts_ctrl >= '%s' " %start
                        start_appended = True
                    if(end is not None):
                        if(start_appended):
                            where_clause['ts_range'] += "AND ts_ctrl <= '%s' " %end
                        else:
                            where_clause['ts_range'] = "ts_ctrl <= '%s' " %end

            filter_clauses.pop('ts_range', None)

            for key, value in filter_clauses.items():
                if value is None:
                    continue
                if not isinstance(value, list):
                    return False, "%s filter must be a list" %key
                custom_keys.append(key)
                if(bool(value)):
                    where_clause[key] = ''
                    counter = 0
                    length = len(value)
                    for val in value:
                        if key == 'res_tag':
                            where_clause[key] += "resource_configs.%s = '%s' " %(key, str(val))
                        elif key == 'ses_tag':
                            where_clause[key] += "session_configs.%s = '%s' " %(key, str(val))
                        else:
                            where_clause[key] += "%s.%s = '%s' " %(table_name, key, str(val))
                        counter += 1
                        if(counter != length):
                            where_clause[key] += "OR "

            join_statement = ''
            if(filter_clauses.get('res_tag') is not None):
                join_statement += \
                    "INNER JOIN resource_configs ON resource_configs.res_hash = %s.res_hash " %table_name
            if(filter_clauses.get('ses_tag') is not None):
                join_statement += \
                    "INNER JOIN session_configs ON session_configs.ses_hash = %s.ses_hash " %table_name

            if(mode == "LAST_DIFF"):
                where_clause['row_number'] = "id > %d " %self.__last_read_row[table_name]

            if(bool(where_clause.values())):
                where_statement = "WHERE (%s)" %(") AND (".join(where_clause.values()))
            else:
                where_statement = ''

            for key in self.__ORDER_OF_GROUP_BY:
                if(key in custom_keys or key in self.__default_select_keys[table_name]):
                    keys_list.append(key)

            return True, (where_statement, join_statement, keys_list)
        except:
            return False, traceback.format_exc()

    def __get_ses_metrics(self, db_connection, mode, table_name, filter_clauses_param):
        status, statements = self.__get_sql_statements(mode, table_name, filter_clauses_param)
        if(not(status)):
            return False, statements

        where_statement, join_statement, keys_list = statements
        if(bool(keys_list)):
            select_keys = ", ".join(keys_list)
            group_by_statement = "GROUP BY %s" %select_keys
            select_keys += ","
        else:
            group_by_statement = ""
            select_keys = ""

        sql_query = "SELECT %s %s FROM %s %s %s %s" \
        %(select_keys, self.__metric_keys_as_csv[table_name], table_name, join_statement, where_statement,
            group_by_statement)

        sql_last_line = "SELECT max(id) AS id FROM %s;" %table_name
        self.__lgr.debug("%s cmd='%s'" %(table_name, sql_query))

        result, last_row =  self.__query_db(db_connection, sql_query, sql_last_line)
        if(result is None):
            self.__lgr.error("TE_METRICS Unable to get result of query")
            return False, "Got None during Query"

        if(mode == "LAST_DIFF"):
            if(last_row is None):
                self.__lgr.error("TE_METRICS Unable to get last row id")
                return False, "Got None as the last row ID"
            else:
                self.__last_read_row[table_name] = last_row
                self.__lgr.debug("Last read row for %s is %d"
                    %(table_name, self.__last_read_row[table_name]))

        return True, (keys_list, result)


    def __get_vip_metrics(self, db_connection, mode, vip_table_name, url_table_name, filter_clauses_param):

        url_keys_list = None
        if(bool(url_table_name)):
            status, statements = self.__get_sql_statements(mode, url_table_name, filter_clauses_param)
            if(not(status)):
                return False, statements

            url_where_statement, url_join_statement, url_keys_list = statements
            if(bool(url_keys_list)):
                url_select_keys = []
                url_join_statement_internal = []
                for i in url_keys_list:
                    if i == "res_tag":
                        url_select_keys.append("resource_configs.res_tag")
                    elif i == "ses_tag":
                        url_select_keys.append("session_configs.ses_tag")
                    else:
                        url_select_keys.append("%s.%s" %(url_table_name, i))
                        url_join_statement_internal.append("%s.%s = temp.%s" %(url_table_name, i, i))
                url_select_keys = ", ".join(url_select_keys)
                url_group_by_statement = "GROUP BY %s" %url_select_keys
                url_select_keys += ","
                url_join_statement_internal = " AND ".join(url_join_statement_internal)
            else:
                url_group_by_statement = ""
                url_select_keys = ""
                url_join_statement_internal = ""

        #Popping is necessary as `vip_metrics` table doesn't have those key fields
        filter_clauses_param.pop('uri', None)
        filter_clauses_param.pop('method', None)

        status, statements = self.__get_sql_statements(mode, vip_table_name, filter_clauses_param)
        if(not(status)):
            return False, statements

        vip_where_statement, vip_join_statement, vip_keys_list = statements
        if(bool(vip_keys_list)):
            vip_select_keys = ", ".join(vip_keys_list)
            vip_group_by_statement = "GROUP BY %s" %vip_select_keys
            vip_select_keys += ","
        else:
            vip_group_by_statement = ""
            vip_select_keys = ""

        if(bool(url_table_name)):
            # URL metrics is not available for UDP SERVER
            # and for UDP SERVER, the url_table_name will be None
            sql_query = """
                WITH vip_stats AS (
                    SELECT  {} {} FROM {} {} {} {}
                ), url_stats AS (
                    WITH temp AS (
                    SELECT {}
                    sum(mean_latency * resp_rcvd) / NULLIF(sum(resp_rcvd), 0) AS net_mean
                    FROM {} {} {} {})
                    SELECT {} {},
                    sum(mean_latency * resp_rcvd) / NULLIF(sum(resp_rcvd), 0) AS mean_latency,
                    sqrt(sum(resp_rcvd * (power(mean_latency - temp.net_mean, 2) + var_latency)) /
                        NULLIF(sum(resp_rcvd), 0)) AS sd_latency
                    FROM {}
                    INNER JOIN temp ON {}
                    {} {} {}
                ) SELECT * from url_stats INNER JOIN vip_stats ON url_stats.vip = vip_stats.vip;
                """.format(vip_select_keys, self.__metric_keys_as_csv[vip_table_name], vip_table_name, \
                vip_join_statement, vip_where_statement, vip_group_by_statement,
                url_select_keys, url_table_name, url_join_statement, url_where_statement, url_group_by_statement, \
                url_select_keys, self.__metric_keys_as_csv[url_table_name], url_table_name, \
                url_join_statement_internal,
                url_join_statement, url_where_statement, url_group_by_statement)
        else:
            sql_query = """SELECT  {} {} FROM {} {} {} {}""".format(vip_select_keys, \
                self.__metric_keys_as_csv[vip_table_name], vip_table_name, \
                vip_join_statement, vip_where_statement, vip_group_by_statement)


        self.__lgr.debug("SQL command to get vip metrics={}".format(sql_query))

        result, last_row =  self.__query_db(db_connection, sql_query)
        if(result is None):
            self.__lgr.error("TE_METRICS Unable to get result of query")
            return False, "Got None during Query"

        if(mode == "LAST_DIFF"):
            if(bool(url_table_name)):
                # url_table_name will be None for UDP SERVER, and there is no `url_metrics`
                # for UDP SERVER and so we are not querying
                sql_last_line = "SELECT max(id) AS id FROM %s;" %url_table_name
                last_row = self.__query_last_row(db_connection, sql_last_line)
                if(last_row is None):
                    self.__lgr.error("TE_METRICS Unable to get last row id for {}",format(url_table_name))
                    return False, "Got None as the last row ID"
                else:
                    self.__last_read_row[url_table_name] = last_row
                    self.__lgr.debug("Last read row for %s is %d"
                        %(url_table_name, self.__last_read_row[url_table_name]))

            sql_last_line = "SELECT max(id) AS id FROM %s;" %vip_table_name
            last_row = self.__query_last_row(db_connection, sql_last_line)
            self.__lgr.debug("%s cmd='%s'" %(vip_table_name, sql_query))
            if(last_row is None):
                self.__lgr.error("TE_METRICS Unable to get last row id for {}",format(vip_table_name))
                return False, "Got None as the last row ID"
            else:
                self.__last_read_row[vip_table_name] = last_row
                self.__lgr.debug("Last read row for %s is %d"
                    %(vip_table_name, self.__last_read_row[vip_table_name]))

        return True, (vip_keys_list, url_keys_list, result)

    def __get_error_metrics(self, db_connection, mode, filter_clauses_param, error_group_interval):
        table_name = "error_metrics"

        status, statements = self.__get_sql_statements(mode, table_name, filter_clauses_param)

        if(not(status)):
            return False, statements

        where_statement, join_statement, keys_list = statements
        select_group_keys = ", ".join(keys_list)

        sql_query = \
        "WITH \
        a AS ( \
            SELECT %s, counter, ts_range \
            , COALESCE(lower(ts_range),'-infinity') AS startdate \
            , max(COALESCE(upper(ts_range), 'infinity')) OVER (ORDER BY ts_range) AS enddate \
        FROM %s %s %s), \
        b AS( \
            SELECT *, lag(enddate) OVER (ORDER BY ts_range) < (startdate - (%d * interval '1 second')) \
            OR NULL AS step FROM a), \
        c AS ( \
             SELECT *, count(step) OVER (ORDER BY ts_range) AS grp FROM b) \
        SELECT %s, sum(counter), min(startdate) AS start_date, max(enddate) AS end_date FROM c\
        GROUP BY %s, grp ORDER BY start_date;" \
        %(select_group_keys, table_name, join_statement, where_statement, error_group_interval,
        select_group_keys, select_group_keys)

        sql_last_line = "SELECT max(id) AS id FROM %s;" %table_name
        self.__lgr.debug("%s cmd='%s'" %(table_name, sql_query))

        result, last_row =  self.__query_db(db_connection, sql_query, sql_last_line)
        if(result is None):
            self.__lgr.error("TE_METRICS Unable to get result of query")
            return False, "Got None during Query"

        if(mode == "LAST_DIFF"):
            if(last_row is None):
                self.__lgr.error("TE_METRICS Unable to get last row id")
                return False, "Got None as the last row ID"
            else:
                self.__last_read_row[table_name] = last_row
                self.__lgr.debug("Last read row for %s is %d"
                    %(table_name, self.__last_read_row[table_name]))

        return True, (keys_list, result)


    def __get_memory_metrics(self, db_connection, mode, filter_clauses_param):

        table_name = "memory_metrics"
        status, statements = self.__get_sql_statements(mode, table_name, filter_clauses_param)

        if(not(status)):
            return False, statements

        where_statement, join_statement, keys_list = statements
        select_group_keys = ", ".join(keys_list)

        sql_query = \
        "SELECT %s, SUM(malloc[index]) AS malloc, SUM(free[index]) AS free FROM memory_metrics \
        JOIN (select generate_subscripts(malloc, 1) AS index, id AS iter FROM memory_metrics) AS temp \
        ON temp.iter = memory_metrics.id %s %s \
        GROUP BY %s;" \
        %(select_group_keys, join_statement, where_statement, select_group_keys)

        sql_last_line = "SELECT max(id) AS id FROM %s;" %table_name
        self.__lgr.debug("%s cmd='%s'" %(table_name, sql_query))

        result, last_row =  self.__query_db(db_connection, sql_query, sql_last_line)
        if(result is None):
            self.__lgr.error("TE_METRICS Unable to get result of query")
            return False, "Got None during Query"

        if(mode == "LAST_DIFF"):
            if(last_row is None):
                self.__lgr.error("TE_METRICS Unable to get last row id")
                return False, "Got None as the last row ID"
            else:
                self.__last_read_row[table_name] = last_row
                self.__lgr.debug("Last read row for %s is %d"
                    %(table_name, self.__last_read_row[table_name]))

        return True, (keys_list, result)

    def __get_latency_percentile(self, metric_json):
        mean_lat = metric_json.pop("mean_latency", None)
        sd_lat = metric_json.pop("sd_latency", None)

        mean_lat = None if mean_lat == 'None' else mean_lat
        sd_lat = None if sd_lat == 'None' else sd_lat

        if bool(mean_lat) and bool(sd_lat):
            mean_lat = float(mean_lat)
            sd_lat = float(sd_lat)
            values = np.random.normal(mean_lat, sd_lat, 10000)

            metric_json['latency_mean'] = round(mean_lat, 5)
            metric_json['latency_sd'] = round(sd_lat, 5)
            metric_json['latency_p10'] = round(np.percentile(values, 10), 5)
            metric_json['latency_p90'] = round(np.percentile(values, 90), 5)
            metric_json['latency_p95'] = round(np.percentile(values, 95), 5)
            metric_json['latency_p99'] = round(np.percentile(values, 99), 5)
            metric_json['latency_p99.9'] = round(np.percentile(values, 99.9), 5)

            #We know the absolute mean and calculated mean of gaussian
            #The diff is reported as possible error in reporting
            metric_json['latency-error-percentage'] = "%s%%" \
                %str(round(abs(mean_lat - round(np.percentile(values, 50), 5)) * 100 / mean_lat, 5))

    def __get_nested_dict(self, keys_list, metrics, is_named, table_name, result=None, get_latency_stats=False):
        # Not a really a pythonic way to do things!
        # Any changes to the logic is welcome!
        fmt = '%Y-%m-%d %H:%M:%S'
        num_levels = len(keys_list)
        if result is None:
            result = {}

        #Has some special handlings
        is_get_latency_stats_needed=False
        is_error_metrics=False
        is_url_metrics=False
        if(table_name == "error_metrics"):
            is_error_metrics=True
        if("url_metrics" in table_name):
            is_get_latency_stats_needed=get_latency_stats
            is_url_metrics = True

        for data in metrics:
            current = result
            counter = 0
            for key in keys_list:
                counter += 1
                if(is_named):
                    dict_key = "%s=%s" %(key, data[key])
                else:
                    dict_key = data[key]
                if(dict_key not in current):
                    #To add a new key
                    if(counter!=num_levels):
                        current[dict_key] = {}
                    else:
                        #At the last level the only entry is metrics
                        if(is_error_metrics):
                            current[dict_key] = [{'error_count' : int(data['sum']),
                                        'time-stamp-range' : [data['start_date'],
                                                            data['end_date']]}]
                        else:
                            metric_json = {}
                            for key in self.__metric_keys[table_name]:
                                if data[key]:
                                    metric_json[key] = float(data[key])
                                else:
                                    metric_json[key] = 0.0
                            if is_get_latency_stats_needed:
                                self.__get_latency_percentile(metric_json)
                            current[dict_key] = metric_json
                        continue

                #ERROR Metrics can have multiple entries for same key at the last level
                elif(counter==num_levels and is_error_metrics):
                    current[dict_key].append({'error_count' : int(data['sum']),
                                'time-stamp-range' : [data['start_date'],
                                                    data['end_date']]})

                # tcp_client_url_metrics / udp_client_url_metrics updates the result of
                # tcp_client_vip_metrics / udp_client_vip_metrics and so can have more than 1 at last level
                elif(counter==num_levels and is_url_metrics):
                    metric_json = {}
                    for key in self.__metric_keys[table_name]:
                        if data[key]:
                            metric_json[key] = float(data[key])
                        else:
                            metric_json[key] = 0.0
                    if is_get_latency_stats_needed:
                        self.__get_latency_percentile(metric_json)
                    current[dict_key].update(metric_json)

                #Step through the dict levels (Similar to LL iterations)
                current = current[dict_key]
            # To handle cases where there are no grouping (i.e keys_list is empty)
            if(not(bool(result))):
                metric_json = {}
                for key in self.__metric_keys[table_name]:
                    if data[key]:
                        metric_json[key] = float(data[key])
                    else:
                        metric_json[key] = 0.0
                if is_get_latency_stats_needed:
                    self.__get_latency_percentile(metric_json)
                result = metric_json
        return result

    def query_vip_metrics(self, mode, traffic_profile, traffic_mode, filter_clauses, is_named):
        try:
            db_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
                password=self.__config['password'], port=self.__config['port'])

            get_latency_stats_needed = filter_clauses.pop('get_latency_stats',False)

            if traffic_profile == "TCP" and traffic_mode == "CLIENT":
                traffic_filter = HTTP_PROFILE
            elif traffic_profile == "UDP" and traffic_mode == "CLIENT":
                traffic_filter = UDP_CLIENT_PROFILE
            elif traffic_profile == "UDP" and traffic_mode == "SERVER":
                traffic_filter = UDP_SERVER_PROFILE
            else:
                return False, "TCP SERVER metrics is not supported"

            if(traffic_filter == HTTP_PROFILE):
                url_table_name = "tcp_client_url_metrics"
                vip_table_name = "tcp_client_vip_metrics"
            elif(traffic_filter == UDP_CLIENT_PROFILE):
                # The following filters are not available for udp_client_vip_metrics
                url_table_name = "udp_client_url_metrics"
                vip_table_name = "udp_client_vip_metrics"
                filter_clauses.pop("uri", None)
            else:
                url_table_name = None
                vip_table_name = "udp_server_vip_metrics"
                # The following filters are not available for udp_server_vip_metrics
                filter_clauses.pop("method", None)
                filter_clauses.pop("uri", None)
                filter_clauses.pop("ses_hash", None)
                filter_clauses.pop("ses_tag", None)
                filter_clauses.pop("res_hash", None)
                filter_clauses.pop("res_tag", None)

            #get vip metrics
            status, result_vip = self.__get_vip_metrics(db_connection, mode, vip_table_name, \
                url_table_name, filter_clauses)
            self.__lgr.debug("Step 1/3 Got Result from Postgres for vip_metrics")
            if(not(status)):
                return status, result_vip
            keys_vip, keys_url, orm_obj_vip = result_vip

            result_dict_vip = self.__get_nested_dict(keys_vip, orm_obj_vip, is_named, vip_table_name)
            number_of_vips = len(result_dict_vip)
            if(number_of_vips < 10):
                get_latency_stats_needed =True
            self.__lgr.debug("Step 2/3 Got nested dict of vip_metrics")

            if(bool(url_table_name)):
                result_dict = self.__get_nested_dict(keys_url, orm_obj_vip, is_named, url_table_name,\
                    result_dict_vip, get_latency_stats_needed)
                self.__lgr.debug("Step 3/3 Got nested dict of url_metrics")
                return True, result_dict
            else:
                return True, result_dict_vip
        except:
            self.__lgr.error(traceback.format_exc())
            return False, traceback.format_exc()
        finally:
            db_connection.close()

    def query_ses_metrics(self, mode, traffic_profile, traffic_mode, filter_clauses, is_named):

        if traffic_profile == "TCP" and traffic_mode == "CLIENT":
            traffic_filter = HTTP_PROFILE
        elif traffic_profile == "UDP" and traffic_mode == "CLIENT":
            traffic_filter = UDP_CLIENT_PROFILE
        elif traffic_profile == "UDP" and traffic_mode == "SERVER":
            return False, "UDP SERVER ses metrics is not supported"
        else:
            return False, "TCP SERVER ses metrics is not supported"

        try:
            if(traffic_filter == HTTP_PROFILE):
                table_name = "tcp_client_ses_metrics"
            elif(traffic_filter == UDP_CLIENT_PROFILE):
                table_name = "udp_client_ses_metrics"

            db_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
                password=self.__config['password'], port=self.__config['port'])
            status, result_url = self.__get_ses_metrics(db_connection, mode, table_name, filter_clauses)
            if(not(status)):
                return status, result_url

            keys_url, orm_obj_url = result_url

            result_dict_ses = self.__get_nested_dict(keys_url, orm_obj_url, is_named, table_name)

            return True, result_dict_ses
        except:
            self.__lgr.error(traceback.format_exc())
            return False, traceback.format_exc()
        finally:
            db_connection.close()

    def query_error_metrics(self, mode, filter_clauses, is_named, error_group_interval):
        try:
            db_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
                password=self.__config['password'], port=self.__config['port'])
            status, result_error = self.__get_error_metrics(db_connection, \
                mode, filter_clauses, error_group_interval)
            if(not(status)):
                return status, result_error
            keys_error, orm_obj_error = result_error

            result_dict_error = self.__get_nested_dict(keys_error, orm_obj_error, is_named, "error_metrics")

            return True, result_dict_error
        except:
            self.__lgr.error(traceback.format_exc())
            return False, traceback.format_exc()
        finally:
            db_connection.close()

    def query_memory_metrics(self, mode, filter_clauses, is_named):
        try:
            db_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
                password=self.__config['password'], port=self.__config['port'])
            status, result_memory = self.__get_memory_metrics(db_connection, mode, filter_clauses)
            if(not(status)):
                return status, result_memory
            keys_memory, orm_obj_memory = result_memory

            result_dict_memory = self.__get_nested_dict(keys_memory, orm_obj_memory, is_named, \
                                "memory_metrics")

            return True, result_dict_memory
        except:
            self.__lgr.error(traceback.format_exc())
            return False, traceback.format_exc()
        finally:
            db_connection.close()


    def query_client_history(self, filter_clauses):
        try:
            db_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
                password=self.__config['password'], port=self.__config['port'])
            table_name = "running_configs"
            start_appended = False
            where_clause = {}
            if(filter_clauses.get('ts_range', None) is not None):
                if(len(filter_clauses['ts_range']) != 2):
                    return False, "ts_range filter must possess start and end timestamps"
                start, end = filter_clauses['ts_range']
                if(start is not None):
                    where_clause['ts_range'] = "start_time >= '%s' " %start
                    start_appended = True
                if(end is not None):
                    if(start_appended):
                        where_clause['ts_range'] += "AND end_time <= '%s' " %end
                    else:
                        where_clause['ts_range'] = "end_time <= '%s' " %end

            if(filter_clauses.get('host_ip', None) is not None):
                client_filter = filter_clauses.get('host_ip', None)
                if not isinstance(client_filter, list):
                    return False, "host_ip filter must be a list"
                if(bool(client_filter)):
                    where_clause['host_ip'] = ''
                    counter = 0
                    length = len(client_filter)
                    for ip in client_filter:
                        where_clause['host_ip'] += "host_ip = '%s' " %ip
                        counter += 1
                        if(counter != length):
                            where_clause['host_ip'] += "OR "

            if(bool(where_clause)):
                where_statement = "WHERE (%s)" %(") AND (".join(where_clause.values()))
                sql_statement = """SELECT res_hash, ses_hash, traffic_mode, traffic_profile,
                    host_ip, cpu, start_time, end_time FROM {} {} ORDER BY start_time""".format(
                    table_name, where_statement)
            else:
                sql_statement = "SELECT res_hash, ses_hash, traffic_mode, traffic_profile, "\
                    "host_ip, cpu, start_time, end_time FROM {} ORDER BY start_time".format(table_name)

            self.__lgr.debug("get_history_of_run: %s" %sql_statement)
            running_config_orm, _ = self.__query_db(db_connection, sql_statement)
            if(running_config_orm is None):
                return False, "Unable to retreive history of configs that ran"

            result = []
            for data in running_config_orm:
                temp_dict = {"res_hash"       : data['res_hash'],
                            "ses_hash"        : data['ses_hash'],
                            "traffic_mode"    : data['traffic_mode'],
                            "traffic_profile" : data['traffic_profile'],
                            "host_ip"       : data['host_ip'],
                            "cpu"             : data['cpu'],
                            "start_time"      : data['start_time'],
                            "end_time"        : data['end_time'] }
                result.append(temp_dict)

            return True, result

        except:
            return False, traceback.format_exc()
        finally:
            db_connection.close()


    def query_and_get_configs(self, res_hash_list, ses_hash_list, is_named):
        try:
            db_connection = connect(dbname=self.__config['db'], user=self.__config['user'], \
                password=self.__config['password'], port=self.__config['port'])
            res_hash_result = None
            ses_hash_result = None
            if res_hash_list is not None:
                if(bool(res_hash_list)):
                    where_clause = []
                    for res_hash in res_hash_list:
                        where_clause.append("res_hash = '%s' " %str(res_hash))
                    where_statement = "WHERE (%s)" %(") OR (".join(where_clause))
                    sql_statement = "SELECT res_hash, res_config FROM \
                        resource_configs %s;" %where_statement
                else:
                    sql_statement = "SELECT res_hash, res_config FROM resource_configs;"

                self.__lgr.debug("res_hash_list: %s" %sql_statement)
                res_table_orm, _ = self.__query_db(db_connection, sql_statement)
                if(res_table_orm is None):
                    return False, "Unable to retreive res_hash(es)"
                res_hash_result = self.__get_nested_dict(["res_hash"], res_table_orm, is_named, \
                                "resource_configs")

            if ses_hash_list is not None:
                if(bool(ses_hash_list)):
                    where_clause = []
                    for ses_hash in ses_hash_list:
                        where_clause.append("ses_hash = '%s' " %str(ses_hash))
                    where_statement = "WHERE (%s)" %(") OR (".join(where_clause))
                    sql_statement = "SELECT ses_hash, ses_config FROM \
                        session_configs %s;" %where_statement
                else:
                    sql_statement = "SELECT ses_hash, ses_config FROM session_configs;"

                self.__lgr.debug("ses_hash_list: %s" %sql_statement)
                ses_table_orm, _ = self.__query_db(db_connection, sql_statement)
                if(ses_table_orm is None):
                    return False, "Unable to retreive ses_hash(es)"
                ses_hash_result = self.__get_nested_dict(["ses_hash"], ses_table_orm, is_named,
                                "session_configs")

            return True, {"res" : res_hash_result, "ses" : ses_hash_result}
        except:
            return False, traceback.format_exc()
        finally:
            db_connection.close()


class TE_ZMQ:

    def __init__(self, host, postgres_obj, zmq_port, logpath, loglevel, stat_collect_interval):
        if(stat_collect_interval != 0):
            p = Process(target=self.__runner, args=(host, postgres_obj, zmq_port, logpath, loglevel))
            p.start()

    async def __recv_and_process(self):
        try:
            host_ip_port = "tcp://0.0.0.0:" + self.__ZMQ['port']
            self.__socket = await aiozmq.create_zmq_stream(zmq.PULL, bind=host_ip_port)
        except:
            self.__lgr.error(traceback.format_exc())
        while True:
            try:
                messages = await self.__socket.read()
                for message in messages:
                    metrics = json.loads(convert(message))
                    t = Thread(target=self.__postgres_obj.insert_metrics_to_db, args=(metrics,))
                    t.start()
            except:
                self.__lgr.debug(traceback.format_exc())
                pass

    def __runner(self, host, postgres_obj, zmq_port, logpath, loglevel):
        #LOGGER
        log_file = os.path.join(logpath, 'te-zmq.log')
        self.__lgr = Logger('[ TE ZMQ ]', log_file, loglevel).getLogger()
        self.__lgr.info("Init Of TE_ZMQ")
        self.__postgres_obj = postgres_obj

        try:
            self.__ZMQ = {
                'host'       : host,
                'port'       : str(zmq_port),
            }

            self.__lgr.info("Starting ZMQ Listener Process")
        except:
            self.__lgr.error("Unable to start to listen. ERROR={}".format(traceback.format_exc()))

        try:
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            self.__loop = asyncio.get_event_loop()
            self.__loop.run_until_complete(self.__recv_and_process())
        except:
            self.__lgr.error(traceback.format_exc())
