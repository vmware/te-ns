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

import sys
import os
import subprocess
import re
import time
import logging
from random import randrange
import traceback
import argparse
import time

EXIT_DOCKER_V                  = 10
EXIT_PIP_REQUESTS_INSTALL      = 11
EXIT_WGET_INSTALL              = 12
EXIT_MACHINE_PREP              = 13
EXIT_WGET_TAR                  = 14
EXIT_LOAD_CONTAINER            = 15
EXIT_RUN_CONTAINER             = 16
EXIT_FREE_PORTS                = 17
EXIT_WRONG_PARAM               = 18
EXIT_CHECKSUM                  = 19
EXIT_NO_PORT                   = 20
EXIT_NO_NETSTAT_CMD            = 21
EXIT_NO_SYSCTL_OR_SERVICE_CMD  = 22
EXIT_SUCCESS                   = 200
EXIT_FAILURE                   = 404

'''
#TO INSTALL DOCKER
apt-get update && \
apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
apt-get update && \
apt-get install -y --force-yes docker-ce
'''

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


class DOCKER_INITIALIZER:

    def __init__(self, pathToDocker, ip, nginxPort, stat_collect_interval, stat_dump_interval, \
        basePath, typeOfDocker, te_controller_ip, te_logpath, te_loglevel):
        self.pathToDocker = pathToDocker
        self.ip = ip
        self.nginxPort = nginxPort
        self.basePath = basePath
        self.te_controller_ip = te_controller_ip
        self.stat_collect_interval = stat_collect_interval
        self.stat_dump_interval = stat_dump_interval
        self.te_logpath = te_logpath
        self.te_loglevel = te_loglevel
        self.typeOfDocker = typeOfDocker
        self.__docker_load_reqd = False
        docker_type_map = {
            'TE' : {
                'docker_file_name'    : 'te_docker.tar',
                'image_name'          : 'te:v2.0',
                'container_name'      : 'tev2.0',
                'repo_name'           : 'te',
            },
            'TE_DP' : {
                'docker_file_name'    : 'tedp_docker.tar',
                'image_name'          : 'tedp:v2.0',
                'container_name'      : 'tedpv2.0',
                'repo_name'           : 'tedp',
                'run_cmd'             : "docker run --privileged --cap-add=SYS_PTRACE --security-opt " \
                                        "seccomp=unconfined -v /tmp/:/te_host/ -v $HOME:/te_root/ " \
                                        "-v /var/run/netns:/var/run/netns " \
                                        "--ulimit core=9999999999 --name tedpv2.0 --net=host -d -it " \
                                        "--tmpfs /tmp/ramcache:rw,size=104857600 tedp:v2.0 /sbin/init"
            }
        }
        self.docker_detials = docker_type_map[typeOfDocker]
        cmd =  "rm -f ~/download_docker.log && touch ~/download_docker.log"
        self.__exec_cmd(cmd)
        self.lgr = Logger("init", "download_docker.log").getLogger()

    def __exec_cmd(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        # Both Python 2 & 3 compliant
        if out is not None:
            out = out.decode('utf-8')
        if err is not None:
            err = err.decode('utf-8')
        return (out, err)

    def __update_run_cmd(self):
        try:
            DICT_OF_SERVICES = {"flask"    : "5000",
                                "nginx"    : "5001",
                                "redis"    : "6379",
                                "postgres" : "5432",
                                "zmq"      : "5555"}

            assignedPorts = []
            (out, err) = self.__exec_cmd("which netstat")
            self.lgr.debug("Output of executing 'which netstat' out%s= err=%s" %(out,err))
            if(bool(err) or not(bool(out))):
                sys.exit(EXIT_NO_NETSTAT_CMD)
            (out, err) = self.__exec_cmd("netstat -ltn | awk '{print $4}' | grep '[0-9]' | cut -d ':' -f2  | uniq")
            if(bool(err)):
                print("Unable to get used up port in remote machine %s" %str(err))
                return False

            #Find a random port for every servicea
            listOut = out.split("\n")
            for service, port in DICT_OF_SERVICES.items():

                # If the port of interest is already available, grab it
                if port not in listOut and port not in assignedPorts:
                    assignedPorts.append(port)
                    continue

                randomPort = str(randrange(1100, 8000))
                counter = 0
                while randomPort in assignedPorts or randomPort in listOut:
                    randomPort = str(randrange(1100, 8000))
                    counter += 1
                    if counter == 20:
                        self.lgr.error("assignedPorts={} DICT_OF_SERVICES={}".format(assignedPorts, DICT_OF_SERVICES))
                        sys.exit(EXIT_NO_PORT)
                assignedPorts.append(randomPort)
                DICT_OF_SERVICES[service] = randomPort
            self.lgr.debug("pre-occupied ports in controller machine were %s" %(str(listOut)))
            self.lgr.debug("Chosen ports for services are %s " %(str(DICT_OF_SERVICES)))
            self.docker_detials['run_cmd'] = "docker run --privileged -d -it --name %s " \
                                    "--net=host -v /tmp/:/te_host/ "\
                                    "-e PYTHONUNBUFFERED=0 -e IPADRESS=%s -e FLASK_PORT=%s "\
                                    "-e REDIS_PORT=%s -e NGINX_PORT=%s -e POSTGRES_PORT=%s "\
                                    "-e ZMQ_PORT=%s -e STAT_COLLECT_INTERVAL=%d "\
                                    "-e STAT_DUMP_INTERVAL=%d -e LOGPATH=%s -e LOGLEVEL=%d %s" \
                                    %(self.docker_detials["container_name"], \
                                    self.te_controller_ip, DICT_OF_SERVICES['flask'], \
                                    DICT_OF_SERVICES['redis'], DICT_OF_SERVICES['nginx'], \
                                    DICT_OF_SERVICES['postgres'], DICT_OF_SERVICES['zmq'], \
                                    self.stat_collect_interval, \
                                    self.stat_dump_interval, self.te_logpath, self.te_loglevel,
                                    self.docker_detials["image_name"])
            print("flask=%s" %DICT_OF_SERVICES['flask'])
            print("postgres=%s" %DICT_OF_SERVICES['postgres'])
            print("nginx=%s" %DICT_OF_SERVICES['nginx'])
            print("zmq=%s" %DICT_OF_SERVICES['zmq'])
            print("redis=%s" %DICT_OF_SERVICES['redis'])
            return True
        except:
            self.lgr.error(traceback.format_exc())

    def isAllEssentialsInstalled(self):
        (out, err) = self.__exec_cmd("docker -v")
        if(not(bool(out))):
            self.lgr.error("NO DOCKER %s" %str(err))
            sys.exit(EXIT_DOCKER_V)

        (out, err) = self.__exec_cmd("which wget")
        if(not(bool(out))):
            self.lgr.error("NO WGET %s" %str(err))
            sys.exit(EXIT_WGET_INSTALL)

        try:
            import requests
        except:
            self.lgr.error("NO PYTHON REQUESTS")
            sys.exit(EXIT_PIP_REQUESTS_INSTALL)

        self.lgr.debug("All essentials Present")
        return True

    def __start_docker(self):
        try:
            cmd = "service docker restart"
            (out, err) = self.__exec_cmd(cmd)
            if(err):
                self.lgr.error("Error while trying to start docker. Out=%s Err=%s" %(out,err))
                return False
        except:
            self.lgr.error("Error while Trying to get docker status. Out=%s Err=%s" %(out,err))
            return False

        return True

    def prepareBed(self):
        cmd = "systemctl show --property ActiveState docker"
        (out, err) = self.__exec_cmd(cmd)
        self.lgr.debug("Executing %s and out=%s" %(cmd, str(out)))

        if(bool(out)):
            try:
                _, state = out.replace("\n","").split("=")
                if(state == "inactive"):
                    status_of_docker_start = self.__start_docker()
                    if(not(status_of_docker_start)):
                        return False
            except:
                self.lgr.error("Error while Trying to get docker status. Out=%s Err=%s" %(out,err))
                return False

        #If there is no output/error then systemctl command doesn't exist
        else:
            self.lgr.error("Unable to find systemctl Command")
            cmd = "service docker status"
            (out_status, err_status) = self.__exec_cmd(cmd)
            self.lgr.debug("Executing %s and out=%s" %(cmd, str(out_status)))

            #If there is no output/error then service command also doesn't exist
            if(not(bool(out_status))):
                self.lgr.error("Unable to find both systemctl and service")
                sys.exit(EXIT_NO_SYSCTL_OR_SERVICE_CMD)
            else:
                if(out_status.find('stop') != -1):
                    status_of_docker_start = self.__start_docker()
                    if(not(status_of_docker_start)):
                        return False

        cmd = "docker ps -a | grep -w %s | awk '{ print $1 }' | xargs -I {} docker rm -f {}" \
                %self.docker_detials['container_name']
        (out, err) = self.__exec_cmd(cmd)

        if self.typeOfDocker == 'TE':
            if(not(self.__update_run_cmd())):
                sys.exit(EXIT_FREE_PORTS)

        self.lgr.debug("Prepared the machine")
        return True

    def getTarImage(self):

        try:
            #This import has been made here, for a specific reason
            #If the host doesn't have request and pip installed already
            #preparebed() call takes cares of it (called before this call)
            import requests

            checkSumLink = "http://"+self.ip+":"+self.nginxPort+self.basePath+"check.sum"
            dockerTarLink = "http://"+self.ip+":"+self.nginxPort+self.basePath+self.docker_detials['docker_file_name']
            imageIdLink = "http://"+self.ip+":"+self.nginxPort+self.basePath+"image.id"

            # Check if docker load is needed in the first place
            response = requests.get(imageIdLink, stream=True)
            if response.status_code != 200:
                self.__docker_load_reqd = True
                self.lgr.debug("Unable to get image.id from remote")
            else:
                ImageIdOfRemoteTar = (response.content.split(' ')[0]).strip()
                (out, err) = self.__exec_cmd("docker images -q -a {}".format(
                    self.docker_detials['image_name']))
                ImageIdOfLocal = out.replace("\n", "").strip()
                if ImageIdOfRemoteTar != ImageIdOfLocal:
                    self.__docker_load_reqd = True
                    self.lgr.debug("ImageIdOfLocal={} and ImageIdOfRemoteTar={}".format(
                        ImageIdOfLocal, ImageIdOfRemoteTar))
                else:
                    self.lgr.debug("Skipping docker load and check.sum get as the image_id={} matches".format(ImageIdOfLocal))
                    return True

            # If image id doesn't match, let us then try for getting the check.sum of tar file
            tarFile = os.path.join(self.pathToDocker, self.docker_detials['docker_file_name'])
            if os.path.exists(tarFile):
                self.lgr.debug("FILE Exists")
                cmd = "md5sum %s" %tarFile
                (out, err) = self.__exec_cmd(cmd)
                if(out != ""):
                    checksum = out.split(' ')[0]
                    self.lgr.debug("checksum %s" %checksum)
                else:
                    self.lgr.error("Unable to calc checksum")
                    sys.exit(EXIT_CHECKSUM)
                response = requests.get(checkSumLink, stream=True)
                checkSumOfRemoteTar = response.content.split(' ')[0]
                self.lgr.debug("checkSumOfRemoteTar %s" %checkSumOfRemoteTar)
                if(checksum == checkSumOfRemoteTar):
                    self.lgr.debug("Matches")
                    return True
                else:
                    # If check.sum also doesn't match, then get the tar
                    cmd = "rm -f " + tarFile + "; wget -q -T90 " + dockerTarLink + " -P " + self.pathToDocker
                    self.lgr.debug("GETTING THE UPDATED IMAGE WITH CMD='%s'" %cmd)
                    (out, err) = self.__exec_cmd(cmd)
                    if err:
                        self.lgr.debug("ERROR in installing Docker image %s" %str(err))
                        sys.exit(EXIT_WGET_TAR)
                    self.lgr.debug("Downloaded TAR Image")
                    return True
            else:
                cmd = "wget -q -T90 " + dockerTarLink + " -P " + self.pathToDocker
                self.lgr.debug("GETTING THE NEW IMAGE WITH CMD='%s'" %cmd)
                (out, err) = self.__exec_cmd(cmd)
                if(err):
                    self.lgr.debug("ERROR in installing Docker image %s" %str(err))
                    sys.exit(EXIT_WGET_TAR)

                return True
        except:
            self.lgr.error(traceback.format_exc())
            sys.exit(EXIT_WGET_TAR)

    def loadAndStartTheContainer(self):
        try:
            if self.__docker_load_reqd:
                cmd="docker images | grep -w %s | awk '{print $3}' | xargs -I {} docker rmi -f {} && \
                    docker load -i %s" %(self.docker_detials['repo_name'],\
                    os.path.join(self.pathToDocker, self.docker_detials['docker_file_name']))
                self.lgr.debug("PERFORMING A DOCKER LOAD USING CMD=%s" %cmd)
                (out, err) = self.__exec_cmd(cmd)

                try:
                    imageTag = out.split("\n")[-2]
                except:
                    self.lgr.error("Unable to load the image! ERROR: %s " %str(out))
                    sys.exit(EXIT_LOAD_CONTAINER)

                expectedOutput = r'Loaded image'
                isMatching = re.match(expectedOutput, imageTag)
                if(isMatching is None):
                    self.lgr.debug("Unable to load the image. ERROR: %s " %str(out))
                    sys.exit(EXIT_LOAD_CONTAINER)

            cmd = self.docker_detials['run_cmd']
            self.lgr.debug("PERFORMING A DOCKER RUN USING CMD=%s" %cmd)
            (out, err) = self.__exec_cmd(cmd)

            # Post run command, the docker is expected to be up
            cmd = "docker ps | grep {} | wc -l".format(self.docker_detials['container_name'])
            sleep_time = 1
            for sleep_cntr in range(5):
                (out, err) = self.__exec_cmd(cmd)
                if out.replace("\n","") == "1":
                    return True
                sleep_time = sleep_time * 2
                if sleep_cntr != 4:
                    self.lgr.debug("docker container is yet to be up, retrying after sleeping for {}s".format(sleep_time))
                    time.sleep(sleep_time)
            sys.exit(EXIT_RUN_CONTAINER)
        except:
            self.lgr.error(traceback.format_exc())
            sys.exit(EXIT_RUN_CONTAINER)

    def run(self):
        if self.isAllEssentialsInstalled() and self.prepareBed() and self.getTarImage() and self.loadAndStartTheContainer():
            self.lgr.debug("SUCCESS")
            sys.exit(EXIT_SUCCESS)
        else:
            self.lgr.debug ("FAILURE")
            sys.exit(EXIT_FAILURE)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w','--path_to_docker',type=str, required=True,
            help='Path to save the docker tar')
    parser.add_argument('-ip','--ip',type=str, required=True,
            help='IP to pull the tar file from')
    parser.add_argument('-p','--nginx_port',type=str, required=True,
            help='Nginx Port of remote machine serving the tar')
    parser.add_argument('-b','--base_path',type=str, default="/",
            help='Path of the the Docker Image location')
    parser.add_argument('-t','--type_of_docker',type=str, required=True,
            help='Type of Docker (TE/TE_DP)')
    parser.add_argument('-h_ip','--host_ip',type=str, default="",
            help='Host IP of TE Controller if type_of_docker=TE')
    parser.add_argument('-ct','--stat_collect_interval',type=int, default=15,
            help='Stat Collection Time in the Clients')
    parser.add_argument('-dt','--stat_dump_interval',type=int, default=15,
            help='Stat Dump Time in the Clients')
    parser.add_argument('-lp','--logpath',type=str, default='/tmp/',
            help='Log Path for TE')
    parser.add_argument('-ll','--loglevel',type=int, default=10,
        help='Log Level for TE')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    pathToDocker = args.path_to_docker
    ip = args.ip
    nginxPort = args.nginx_port
    basePath = args.base_path
    typeOfDocker = args.type_of_docker
    stat_collect_interval = args.stat_collect_interval
    stat_dump_interval = args.stat_dump_interval
    te_logpath = args.logpath
    te_loglevel = args.loglevel

    if typeOfDocker == "TE":
        te_controller_ip = args.host_ip
        if te_controller_ip == "":
            sys.exit(EXIT_WRONG_PARAM)
    else:
        te_controller_ip = None

    obj = DOCKER_INITIALIZER(pathToDocker, ip, nginxPort, stat_collect_interval, \
        stat_dump_interval, basePath, typeOfDocker, te_controller_ip, te_logpath, te_loglevel)
    obj.run()

