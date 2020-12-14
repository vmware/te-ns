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

import argparse
import requests
import os
import subprocess
from TE_UTILS import *
import time, sys, json
import errno

class RedisConnector:
    def __init__(self, ip, ctrl_ip, ctrl_flask_port):
        self.ip = ip
        self.ctrl_ip = ctrl_ip
        self.ctrl_flask_port = ctrl_flask_port
        self.cpus = os.cpu_count()
        self.lgr = Logger('[  RQ  ]', "/tmp/rq.log", 10).getLogger()
        os.system("sysctl -p")

    def __url(self, path):
        url = "http://{}:{}/api/v1.0/te/{}".format(self.ctrl_ip, self.ctrl_flask_port, path)
        return url

    def __exec_cmd(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        # Both Python 2 & 3 compliant
        if out is not None:
            out = out.decode('utf-8')
        if err is not None:
            err = err.decode('utf-8')
        return (out, err)

    def __is_running(self, pid_list):
        for pid in pid_list:
            try:
                os.kill(pid, 0)
            except OSError as err:
                if err.errno == errno.ESRCH:
                    self.lgr.error("========= {} GOT KILLED =========".format(pid))
                    return False
        return True

    def clean(self):
        cmd = "ps aux | grep 'rq worker' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill; \
            pgrep 'te_dp' | xargs kill -9; \
            rm -rf /tmp/*.csv; \
            rm -rf /tmp/wrk*.log"
        (out, err) = self.__exec_cmd(cmd)

    def get_rq_details(self):
        self.lgr.info("In get_rq_details")
        url = self.__url('get_rq_details')
        resp = requests.post(url, json={'ip':self.ip, 'cpus':self.cpus})
        self.lgr.info("Status code for get_rq_details = {}".format(resp.status_code))
        if resp.status_code == 200:
            data = resp.json()
            self.lgr.info("data for get_rq_details = {}".format(data))
            if data.get('status', False):
                message = data.get('statusmessage', {})
                self.broker = message.get("broker","")
                self.stat_collect_interval = message.get("stat_collect_interval", 15)
                self.ctrl_zmq_port = message.get("zmq", 5555)
                self.queue = message.get("queue_csv","")
                return True
        return False

    def establish_rq(self):
        self.lgr.info("In establish_rq")
        url = self.__url('establish_rq')
        resp = requests.post(url, json={'ip':self.ip})
        self.lgr.info("Status code for establish_rq = {}".format(resp.status_code))
        if resp.status_code == 200:
            data = resp.json()
            self.lgr.info("data for establish_rq = {}".format(data))
            return data.get('status', False)
        return False

    def makeQueues(self):
        command = 'echo "/opt/te/core.%e.%p.%h.%t" > /proc/sys/kernel/core_pattern'
        os.system(command)

        std_que_str = ' '.join(self.queue.split('?')[:-1])
        inst_que_str = ''.join(self.queue.split('?')[-1])
        inst_que_list  = inst_que_str[1:-1].split(',')

        expectedCount = len(inst_que_list)
        cmd_to_check = "sleep 0.5 && ps aux | grep 'rq worker' | grep -v grep | wc -l"
        cmd_to_kill = "ps aux | grep 'rq worker' | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill"

        for retry_cnt in range(5):

            #RQ creation
            for each_inst_que in inst_que_list:
                total_queue = std_que_str + ' ' + each_inst_que.strip()
                command = 'nohup rq worker -v --name ' + \
                    str(each_inst_que.strip()) + ' -P '+ self.workdir+ ' -u '+ self.broker +  '  ' \
                    +total_queue + ' 1>/dev/null 2>/dev/null &'
                self.lgr.debug("Running command ='%s'" %command)
                os.system(command)

            #RQ Check
            for check_cnt in range(5):
                (out, err) = self.__exec_cmd(cmd_to_check)
                self.lgr.debug("Retry=%d, Check=%d: makeQueues out=%s err=%s" \
                    %(retry_cnt, check_cnt, str(out), str(err)))
                out = int(out)

                self.lgr.error("Retry=%d, Check=%d: Number of RQ's connected in the machine is %d "\
                    "and expected is %d" %(retry_cnt, check_cnt, out, expectedCount))

                if(out == expectedCount):
                    return True

            #To kill any partially created RQ if any
            (out,err) = self.__exec_cmd(cmd_to_kill)

        return False

    def start_stat_collector(self):
        cmd = "ps aux | grep te_stats_collector | grep -v grep | awk '{print $2}' | xargs --no-run-if-empty kill -9"
        (out, err) = self.__exec_cmd(cmd)

        if (self.stat_collect_interval <= 0):
            self.lgr.error("Not started te_stats_collector as self.stat_collect_interval=%d" \
                %self.stat_collect_interval)
            return

        stat_collector_config = {
            "te_ip" : self.ctrl_ip,
            "my_ip" : self.ip,
            "self.stat_collect_interval" : int(self.stat_collect_interval),
            "te_zmq_port" : self.ctrl_zmq_port
        }

        json_object = json.dumps(stat_collector_config, indent=2)
        with open("/te_host/stat_collector_config.json", "w") as handle:
            handle.write(json_object)

        cmd = "nohup /opt/te/bin/te_stats_collector /te_host/stat_collector_config.json &"
        self.lgr.info("Starting {}".format(cmd.split()))
        os.system(cmd)

    def run_connector(self):
        self.lgr.info("In run_connector")
        self.workdir = "/opt/te/"
        self.clean()
        while True:
            if self.makeQueues():
                break
        self.start_stat_collector()
        return True

    def wait_for_pids(self, pid_list):
        while self.__is_running(pid_list):
            sleep(15)

    def get_pids(self):
        cmd = "ps aux | grep 'rq worker' | grep -v grep | awk '{print $2}'"
        (out, err) = self.__exec_cmd(cmd)
        rq_pid_list = [int(i) for i in out.split("\n") if i]

        cmd = "ps aux | grep te_stats_collector | grep -v grep | awk '{print $2}'"
        (out, err) = self.__exec_cmd(cmd)
        stat_collector_pid_list = [int(i) for i in out.split("\n") if i]

        self.lgr.info("RQ pids = {} stat_collector_pid = {}".format(rq_pid_list, stat_collector_pid_list))
        return rq_pid_list + stat_collector_pid_list

    def run(self):
        while(True):
            self.lgr.info("========= STARTING RQ RUN =========")
            if self.get_rq_details() and self.run_connector() and self.establish_rq():
                self.lgr.info("========= ESTABLISHED RQ CONN =========")
                pid_list = self.get_pids()
                self.lgr.info(" ========= POLLING FOR PIDs={} =========".format(pid_list))
                self.wait_for_pids(pid_list)
            else:
                self.lgr.info("========= SLEEPING FOR 5s DUE TO FAILURE =========")
                time.sleep(5)

if __name__ == "__main__":
    env_vars = os.environ
    my_ip = env_vars.get("IPADDRESS", "127.0.0.1")
    controller_ip = env_vars.get("CTRL_IPADDRESS", "127.0.0.1")
    controller_flask_port = env_vars.get("CTRL_FLASK_PORT", "6379")
    redis_conn_obj = RedisConnector(my_ip, controller_ip, controller_flask_port)
    redis_conn_obj.run()
