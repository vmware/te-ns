#!/usr/bin/python

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

EXIT_DUMP_ERROR              = 10
EXIT_STARTED_LESS            = 11
EXIT_DOCKER_NOT_UP           = 12
EXIT_STAT_COLLECTOR          = 13
EXIT_SUCCESS                 = 200

import logging,sys,time,json, hashlib, ast
import argparse,time,os, commands
import subprocess, os
from subprocess import PIPE
import traceback

class Logger:
    def __init__(self, name, logFilePath, level=10):
        try:
            if level == None:
                level = 10 #DEBUG
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

            self.lgr = logging.getLogger(name)
            self.lgr.setLevel(level)

            fileHandler = logging.FileHandler(logFilePath)
            fileHandler.setLevel(level)
            fileHandler.setFormatter(formatter)

            self.lgr.addHandler(fileHandler)

        except Exception as e:
            print("ERROR IN logging_init %s" %str(e) )

    def getLogger(self):
        return self.lgr


class TE_AGENT():
    def __init__(self, broker, queue, workdir):
        self.config={}
        self.broker = broker
        self.workdir = workdir
        self.queue = queue
        cmd =  "rm -f ~/connector.log && touch ~/connector.log"
        self.__exec_cmd(cmd)
        self.lgr = Logger("init", "connector.log").getLogger()

    def clean(self):
        cmd = "ps aux | grep 'rq worker' | awk '{print $2}'| xargs kill -9; \
            pgrep 'te_dp' | xargs kill -9; \
            rm -rf /tmp/*.csv; \
            rm -rf /tmp/wrk*.log"
        (out, err) = self.__exec_cmd(cmd)

    def __exec_cmd(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        # Both Python 2 & 3 compliant
        if out is not None:
            out = out.decode('utf-8')
        if err is not None:
            err = err.decode('utf-8')
        return (out, err)

    def makeQueues(self):

        command = 'echo "/opt/te/core.%e.%p.%h.%t" > /proc/sys/kernel/core_pattern'
        commands.getstatusoutput(command)

        std_que_str = ' '.join(self.queue.split('?')[:-1])
        inst_que_str = ''.join(self.queue.split('?')[-1])
        inst_que_list  = inst_que_str[1:-1].split(',')

        expectedCount = len(inst_que_list)
        cmd_to_check = "sleep 0.5 && docker exec tedpv2.0 bash -c 'ps aux | grep rq | grep -v grep | wc -l'"
        cmd_to_kill = "docker exec tedpv2.0 pkill -f rq"

        for retry_cnt in range(5):

            #RQ creation
            for each_inst_que in inst_que_list:
                total_queue = std_que_str + ' ' + each_inst_que.strip()
                command = 'docker exec tedpv2.0 nohup rq worker -v --name ' + \
                    str(each_inst_que.strip()) + ' -P '+ self.workdir+ ' -u '+ self.broker +  '  ' \
                    +total_queue + ' 1>/dev/null 2>/dev/null & echo $!'
                self.lgr.debug("Running command ='%s'" %command)
                pid = subprocess.Popen(command, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
                self.lgr.debug("The Task PID is {}".format((pid.pid)))

            #RQ Check
            for check_cnt in range(5):
                (out, err) = self.__exec_cmd(cmd_to_check)
                self.lgr.debug("Retry=%d, Check=%d: makeQueues out=%s err=%s" \
                    %(retry_cnt, check_cnt, str(out), str(err)))
                try:
                    out = int(out)
                except:
                    self.lgr.error("Exception Occurred %s" %traceback.format_exc())
                    sys.exit(EXIT_DOCKER_NOT_UP)

                self.lgr.error("Retry=%d, Check=%d: Number of RQ's connected in the machine is %d "\
                    "and expected is %d" %(retry_cnt, check_cnt, out, expectedCount))

                if(out == expectedCount):
                    return

            #To kill any partially created RQ if any
            (out,err) = self.__exec_cmd(cmd_to_kill)

        sys.exit(EXIT_STARTED_LESS)

    def start_stat_collector(self, stat_collect_interval, te_daemon_ip, te_zmq_port, my_ip):
        if (stat_collect_interval <= 0):
            self.lgr.error("Not started te_stats_collector as stat_collect_interval=%d" \
                %stat_collect_interval)
            return

        cmd = "docker exec tedpv2.0 service te_stats_collector stop"
        (out, err) = self.__exec_cmd(cmd)

        stat_collector_config = {
            "te_ip" : te_daemon_ip,
            "my_ip" : my_ip,
            "stat_collect_interval" : int(stat_collect_interval),
            "te_zmq_port" : te_zmq_port
        }

        json_object = json.dumps(stat_collector_config, indent=2)
        with open("stat_collector_config.json", "w") as handle:
            handle.write(json_object)

        cmd = "docker cp ~/stat_collector_config.json tedpv2.0:/te_host/stat_collector_config.json && \
                docker exec tedpv2.0 service te_stats_collector start"
        (out, err) = self.__exec_cmd(cmd)

        stat = os.system("docker exec tedpv2.0 service te_stats_collector status")
        if(stat != 0):
            sys.exit(EXIT_STAT_COLLECTOR)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-te','--TE_MGMT_IP',type=str, required=True,
            help='Mgmt IP of the TE')
    parser.add_argument('-b','--broker',type=str, required=True,
            help='Broker for Task')
    parser.add_argument('-w','--workdir', type=str,required=True,
            help='Workdir for Task App')
    parser.add_argument('-Q','--queue', type=str,required=True,
            help='Queue for Task Worker')
    parser.add_argument('-un','--uniq_name', type=str,default='TE_DP_TASK',
            help='Queue for Task Worker')
    parser.add_argument('-l','--loglevel', type=int, default=10,
            help='Log Level for Task Worker')
    parser.add_argument('-s','--stat_collect_interval', type=int, default=15,
            help='Time Interval at which stat collection must take place')
    parser.add_argument('-z','--te_zmq_port', type=str, required=True,
            help='ZMQ Port to send the metrics over to')
    parser.add_argument('-ip','--my_ip', type=str, required=True,
            help='Client identifier IP')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = parse_args()
    te_daemon_ip = args.TE_MGMT_IP
    broker = args.broker
    workdir = args.workdir
    queue = args.queue
    uniq_name = args.uniq_name
    loglevel = args.loglevel
    stat_collect_interval = args.stat_collect_interval
    te_zmq_port = args.te_zmq_port
    my_ip = args.my_ip

    te_agent = TE_AGENT(broker, queue, workdir)
    te_agent.clean()
    te_agent.makeQueues()
    te_agent.start_stat_collector(stat_collect_interval, te_daemon_ip, te_zmq_port, my_ip)
    sys.exit(EXIT_SUCCESS)
