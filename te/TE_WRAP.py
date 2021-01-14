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

import logging
import requests
import re, json
from random import randrange
import os, sys
import paramiko
from scp import SCPClient
import sys, time, subprocess
import logging, logging.handlers
from threading import Timer

class Logger:
    def __init__(self, name, logFilePath, level=None, bufferSize=1024*1000*5):
        try:
            if level == None:
                level = 10 #DEBUG
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

            self.lgr = logging.getLogger(name)
            self.lgr.setLevel(level)

            fileHandler = logging.FileHandler(logFilePath)
            fileHandler.setLevel(level)
            fileHandler.setFormatter(formatter)

            memoryHandler = logging.handlers.MemoryHandler(bufferSize,level,fileHandler) #Flushes out on htting buffer size to the fileHandler
            memoryHandler.setFormatter(formatter)
            memoryHandler.setLevel(level)

            self.lgr.addHandler(memoryHandler)

        except Exception as e:
            print("ERROR IN logging_init %s" %str(e) )

    def getLogger(self):
        return self.lgr

wrap_log_file = "/tmp/wrk.te_wrap.log"
if os.path.exists(wrap_log_file):
    os.remove(wrap_log_file)
loglevel = 10
lgr = Logger('[ TE WRAP ]', wrap_log_file, loglevel).getLogger()
lgr.info("Starting the TE Process")
lgr.info("ALL INIT DONE IN the TE Process")

class TensTE():
    """Tens TE implentation of the Stress Traffic Tool."""
    def __init__(self, te_controller):
        """Tens TE Traffic Tool Constructor.

		Args:
            te_controller: dict, required
                The Controller Credientials which includes
                    host_ip    : On which the Controller runs
                    user       : Must be a user with password-less docker access
                    passwd     : Password of the user
                    flask_port : If TE is already running, provide the flask port
        Returns:
            None
		"""

        self.__te_controller=te_controller
        self.__OUT = 0
        self.__ERR = 1
        self.__retry_sleeper = 1
        self.__max_retry = 5
        if "flask_port" in self.__te_controller:
            self.set_controller_flask_port(self.__te_controller["flask_port"])

    def __retry_wrapper(function_to_call, *args, **kwargs):
        def caller(self, *args, **kwargs):
            multiplying_factor = 1
            for retry_counter in range(self.__max_retry + 1):
                try:
                    #Actual Caller
                    result = function_to_call(self, *args, **kwargs)
                    return result

                except OSError as e:
                    found_err_no = re.findall(r'Errno \d+', str(e))
                    if(bool(found_err_no)):
                        try:
                            num = int(found_err_no[0].split()[1])
                        except:
                            pass
                    else:
                        num = 4

                    #Handling Last Retry to raise the same error (Debuggability)
                    if(retry_counter == self.__max_retry):
                        raise OSError(num, os.strerror(num))

                    #Signal Error (Retry)
                    elif num==4:
                        sleeping_for = self.__retry_sleeper * multiplying_factor
                        print("Caught Exception: %s and sleeping for %s" %(
                            str(OSError(num, os.strerror(num))), str(sleeping_for)))
                        time.sleep(sleeping_for)
                        multiplying_factor *= 2

                    #Unknown OS errors (Raise the same error)
                    else:
                        raise OSError(num, str(e))

                #Handling Connection Error
                except requests.ConnectionError as e:
                    #Handling Last Retry to raise the same error (Debuggability)
                    if(retry_counter == self.__max_retry):
                        raise e

                    #Retry (Temporary N/W Glitch)
                    else:
                        sleeping_for = self.__retry_sleeper * multiplying_factor
                        print("Caught Exception: %s and sleeping for %s" %(
                            str(e), str(sleeping_for)))
                        time.sleep(sleeping_for)
                        multiplying_factor *= 2

                #Other Unknown errors (Raise the same error)
                except Exception as e:
                    raise e
        caller.__name__=function_to_call.__name__
        caller.__doc__=function_to_call.__doc__
        return caller

    def alter_retry(self, sleep_time, number_of_retries):
        self.__retry_sleeper = sleep_time
        self.__max_retry = number_of_retries

    def set_controller_flask_port(self, port):
        '''
            Comes in handy if there is a need to connect to Running TE Controller
            Params:
                port: Sets up the flask port to connect, to make futher api calls
        '''
        self.__te_controller['hostport'] = str(port)

    def set_controller_credentials(self, user="root", passwd=None):
        self.__te_controller['user'] = user
        self.__te_controller['passwd'] = passwd

    def __url(self, path):
        if self.__te_controller.get('hostport',None) is not None:
            path = "http://{}:{}/api/v1.0/te/{}".format(self.__te_controller['host'],
                self.__te_controller['hostport'], path)
            return path
        else:
            return None


    def __exec_cmd_remote(self, cmd, ssh):
        stdin, stdout, stderr = ssh.exec_command(cmd)
        err = stderr.readlines()
        if(err != []):
            return self.__ERR, err
        return self.__OUT, stdout.readlines()

    def __exec_cmd_local(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        # Both Python 2 & 3 compliant
        if out is not None:
            out = out.decode('utf-8')
        if err is not None:
            err = err.decode('utf-8')
        return (out, err)

    def __kill_setup_te(self, ssh, time_to_wait):
        ssh.close()
        lgr.error("TE didn't come up even after waiting for {}".format(time_to_wait))

    def __checkIfContainerIsUp(self, DICT_OF_SERVICES, maxTolerableDelay, maxRetry, ssh):
        failedService = []
        cmd = "which netstat"
        (type, listOut) = self.__exec_cmd_remote(cmd, ssh)
        if(type == self.__ERR or not(bool(listOut))):
            return False, "Please install netstat in remote TE Controller machine"

        for i in range(maxRetry):
            failedService = []
            for service, port in DICT_OF_SERVICES.items():
                cmd = "netstat -lanet | grep %s | wc -l" %(port)
                (type, listOut) = self.__exec_cmd_remote(cmd, ssh)
                if(type == self.__ERR):
                    return False, "Error while checking if port is up. ERROR: %s" %str(listOut)
                try:
                    if int(listOut[0]) == 0:
                        failedService.append((service, port))
                except:
                    return False, "Unable to start container. %s" %listOut
            time.sleep(maxTolerableDelay/maxRetry)
            print('.')
            if not failedService:
                self.__te_controller['hostport'] = DICT_OF_SERVICES['flask']
                return True, DICT_OF_SERVICES
        return False, "Unable to bring services ports: %s" %str(failedService)

    def __setup_te_from_docker_file(self, pathToTrafficEngine, stat_collect_interval, \
        stat_dump_interval, maxTolerableDelay, maxRetry, logpath, loglevel):
        DICT_OF_SERVICES = {"flask"    : "5000",
                            "nginx"    : "5001",
                            "grafana"  : "5002",
                            "redis"    : "6379",
                            "postgres" : "5432",
                            "zmq"      : "5555"}
        host = self.__te_controller['host']
        uname = self.__te_controller.get('user', 'root')
        pwd = self.__te_controller.get('passwd', None)
        self.TE_IMAGE_ID = None

        buildImages = {
            'TE' : {
                'docker_file_name'    : 'te_docker.tar',
                'image_name'          : 'te:v2.0',
                'container_name'      : 'tev2.0',
                'path_to_docker_file' : os.path.join(pathToTrafficEngine, "te/te_docker/Dockerfile"),
                'path_to_base_dir'    : os.path.join(pathToTrafficEngine, "te/"),
                'repo_name'           : 'te'
            },
            'TE_DP' : {
                'docker_file_name'    : os.path.join(pathToTrafficEngine, 'te/tedp_docker.tar'),
                'image_name'          : 'tedp:v2.0',
                'image_name_bin'     : 'tedp_bin:v2.0',
                'container_name'      : 'tedpv2.0',
                'path_to_docker_file' : os.path.join(pathToTrafficEngine, 'te/tedp_docker/Dockerfile'),
                'path_to_docker_file_bin' : \
                    os.path.join(pathToTrafficEngine, "te/tedp_docker/tedp_bin_builder.dockerfile"),
                'path_to_base_dir'    : os.path.join(pathToTrafficEngine, ''),
                'repo_name'           : 'tedp'
            }
        }

        def __update_free_port():
            assignedPorts = []
            cmd = "which netstat"
            (type, listOut) = self.__exec_cmd_remote(cmd, ssh)
            if(type == self.__ERR or not(bool(listOut))):
                return False, "Please install netstat in remote TE Controller machine"
            cmd = "netstat -ltn | awk '{print $4}' | grep '[0-9]' | cut -d ':' -f2  | uniq"
            (type, listOut) = self.__exec_cmd_remote(cmd, ssh)
            if type == self.__ERR:
                return False, "Unable to get used up port in remote machine %s" %str(listOut)

            #Find a random port for every servicea
            listOut = [s.replace("\n","") for s in listOut]
            for service, port in DICT_OF_SERVICES.items():
                randomPort = str(randrange(1100, 8000))
                counter = 0

                # If the port of interest is already available, grab it
                if port not in listOut and port not in assignedPorts:
                    assignedPorts.append(port)
                    continue

                while randomPort in assignedPorts or randomPort in listOut:
                    randomPort = str(randrange(1100, 8000))
                    counter += 1
                    if counter % 10 == 0:
                        print("Unable to find a random available port even after 10 more tries")
                        mustExit = int(input("Please enter 1 to continue a further search or 0 to abort and debug manually"))
                        if not(mustExit):
                            return False, "Unable to find a random available port even after 10 more tries"
                assignedPorts.append(randomPort)
                DICT_OF_SERVICES[service] = randomPort

            print("pre-occupied ports in controller machine were {}".format(listOut))
            print("Chosen ports for services are {}".format(DICT_OF_SERVICES))
            return True, None

        def __clean():
            cmd = "docker container prune -f && \
                    docker image prune -f"
            (out, err) = self.__exec_cmd_local(cmd)
            print("PRUNING THE CONTAINERS AND IMAGES")

        def __getCurrentImageID(type):
            if(type == "TE"):
                cmd = "docker images | grep -w te | awk '{print $3}'"
            elif(type == "TE_DP"):
                cmd = "docker images | grep -w tedp | awk '{print $3}'"
            else:
                print("IMPROPER TYPE PASSED. SHOULD NEVER GET THE MESSAGE. xxxx FATAL xxxx")
                return
            (out, err) = self.__exec_cmd_local(cmd)
            if(err is not None):
                return (True, out)
            else:
                return (False, err)

        def __performDockerSave(type):
            cmd = "docker save -o " + os.path.join(pathToTrafficEngine, "te", buildImages[type]['docker_file_name']) +\
                    " " + buildImages[type]['image_name']
            print("PERFORMING A DOCKER SAVE IN LOCAL MACHINE USING CMD='%s'" %cmd)
            (out, err) = self.__exec_cmd_local(cmd)
            if err:
                print("Unable to do a docker save and generate checksum. ERROR:" + str(err))
                return False
            return True

        def __buildDocker(type, image_id=None):
            '''
                Checks for the current image ID
                Does a docker build
                Checks for the image id again
                If image ID has changed, performs a docker save
            '''

            status, oldImageID = __getCurrentImageID(type)
            if not status:
                print("Error while trying to find image ID of {}: {}".format(type, oldImageID))
                return False

            cmd = ""
            if type == "TE_DP":
                cmd = "docker build -t {} -f {} {} && ".format(buildImages[type]['image_name_bin'],
                    buildImages[type]['path_to_docker_file_bin'],
                    buildImages[type]['path_to_base_dir'])

            cmd += "docker build -t " + buildImages[type]['image_name'] + " -f " + \
                buildImages[type]['path_to_docker_file'] + " " + buildImages[type]['path_to_base_dir']

            if image_id:
                cmd += " --build-arg IMAGE_ID={}".format(image_id)

            print("PERFORMING A DOCKER BUILD OF %s IN LOCAL MACHINE USING CMD '%s'" %(type, cmd))

            (out, err) = self.__exec_cmd_local(cmd)
            if(err is None):
                output = out.split("\n")
                if(len(output) < 3):
                    print("ERROR IN DOCKER BUILD OF {} and output={}".format(type, output))
                    return
                buildList, tagList, _ = output[-3:]
                imageID = buildList.split(" ")[-1]
                imageNameProduced = tagList.split(" ")[-1]
                if(imageNameProduced != buildImages[type]['image_name']):
                    print("Error in building Docker. Dockerfile Problem", output[-3:])
                    return False

            status, newImageID = __getCurrentImageID(type)
            if not status:
                print("Error while trying to find image ID of {}: {}".format(type, newImageID))
                return False

            if(newImageID != oldImageID or newImageID is None):
                if(not(__performDockerSave(type))):
                    return False

            self.TE_IMAGE_ID = newImageID
            return True

        #Do a prune of containers and images to free up disk in local machine
        __clean()

        #Building Docker Image Of TE_DP and doing a 'docker save' if the build has altered
        if(not(__buildDocker("TE_DP"))):
            return

        (out, err) = self.__exec_cmd_local("docker images -q -a tedp:v2.0")
        tedp_image_id = out.replace("\n", "")

        if(not(__buildDocker("TE", tedp_image_id))):
            return

        #Making SSH Connection to the TE-Controller Machine
        print("Establishing a ssh conn with %s on user %s with pwd: %s" %(host, uname, pwd) )
        logging.getLogger("paramiko").setLevel(logging.ERROR)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if pwd:
            ssh.connect(host, username=uname, password=pwd)
        else:
            ssh.connect(host, username=uname)

        #Check if docker is installed (else install it)
        cmd = "docker -v"
        type, listOut = self.__exec_cmd_remote(cmd, ssh)
        if(type == self.__ERR):
            print("INSTALLING DOCKER AND NET-TOOLS IN REMOTE MACHINE")
            cmd = ' apt-get update && \
            		apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
            		curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
            		add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
             		apt-get update && \
            		apt-get install -y --force-yes docker-ce && \
            		service docker restart && \
                    service redis stop && \
            		apt-get install net-tools'
            type, listOut = self.__exec_cmd_remote(cmd, ssh)
            if(type == self.__ERR):
                print("Unable to install docker and nettools. ERROR: %s " %str(listOut))
                return


        #Check if a container of the tag is running if so stop it
        print("WARNING: REMOVING ANY EXISTING RUNNING TE-CONTROLLER CONTAINER")
        cmd = "docker ps -a | grep -w " + buildImages["TE"]["container_name"] + " | awk '{ print $1 }' | xargs -I {} docker rm -f {}"
        type, listOut = self.__exec_cmd_remote(cmd, ssh)
        if(type == self.__ERR):
            print("Unable to remove the running containers of the image. ERROR: %s " %str(listOut))
            return

        #Check if the image IDs matches
        cmd = "docker images | grep -w %s" %self.TE_IMAGE_ID
        type, listOut = self.__exec_cmd_remote(cmd, ssh)
        if(type == self.__ERR):
            print("Unable to get existing TE images. ERROR: %s " %str(listOut))
            return

        #Image ID is not matching
        if(listOut == []):
            print("IMAGES IN LOCAL AND REMOTE MACHINES ARE NOT THE SAME")
            cmd = "docker image prune -f && docker images | grep -w " + \
                    buildImages["TE"]["repo_name"] + \
                    " | awk '{ print $3 }' | xargs -I {} docker rmi -f {}"

            type, listOut = self.__exec_cmd_remote(cmd, ssh)
            scp = SCPClient(ssh.get_transport())
            scp.put(os.path.join(pathToTrafficEngine, "te", buildImages["TE"]["docker_file_name"]), '~/')

            cmd = "docker images"
            type, listOut = self.__exec_cmd_remote(cmd, ssh)

            #Load the container
            print("PERFORMING A DOCKER LOAD IN REMOTE MACHINE")
            cmd='docker load -i %s' %os.path.join('~/' ,buildImages["TE"]["docker_file_name"])
            (type, listOut) = self.__exec_cmd_remote(cmd, ssh)
            expectedOutput = r'Loaded image: te:v2.0'
            isMatching = re.match(expectedOutput, listOut[-1])
            if(type == self.__ERR or isMatching is None):
                print("Unable to load the image. ERROR: %s " %str(listOut))
                return

        status, message = __update_free_port()
        if(not(status)):
            return {'status':status, 'statusmessage':message}
        cmd = "docker run --privileged -d -it --name %s --net=host -v /tmp/:/te_host/ -v $HOME/.ssh/:/root/.ssh/"\
               "-e PYTHONUNBUFFERED=0 -e IPADRESS=%s -e FLASK_PORT=%s -e REDIS_PORT=%s "\
               "-e NGINX_PORT=%s -e POSTGRES_PORT=%s -e ZMQ_PORT=%s -e GRAFANA_PORT=%s "\
               "-e STAT_COLLECT_INTERVAL=%d -e STAT_DUMP_INTERVAL=%d "\
               "-e LOGPATH=%s -e LOGLEVEL=%d %s"\
               %(buildImages["TE"]["container_name"], host, \
                DICT_OF_SERVICES['flask'], DICT_OF_SERVICES['redis'], DICT_OF_SERVICES['nginx'],
                DICT_OF_SERVICES['postgres'], DICT_OF_SERVICES['zmq'], DICT_OF_SERVICES['grafana'],
                stat_collect_interval, stat_dump_interval, logpath, loglevel,
                buildImages["TE"]["image_name"])

        print("DOCKER RUN CMD=%s" %cmd)
        (type, listOut) = self.__exec_cmd_remote(cmd, ssh)
        if(type == self.__ERR):
            print("Unable to start container in remote. ERROR: %s " %str(listOut))
            return

        status, message = self.__checkIfContainerIsUp(DICT_OF_SERVICES, maxTolerableDelay, maxRetry, ssh)
        ssh.close()
        return {'status':status, 'statusmessage':message}

    def __setup_te_from_repo(self, repo_details, stat_collect_interval, stat_dump_interval, \
        maxTolerableDelay, maxRetry, logpath, loglevel):

        EXIT_STATUS = {
                10 : "Unable to find docker",
                11 : "Unable to find python-requests",
                12 : "Unable to find wget",
                13 : "Unable to prepare the appropriate conditions needed to start the container (redis stop, docker start)",
                14 : "Unable to download the te_docker.tar from Repo",
                15 : "Unable to load the container",
                16 : "Unable to run the container",
                17 : "Unable to get free ports",
                18 : "Wrong parameters passed",
                19 : "Unable to calculate the checksum of Tar File",
                20  : "Unable to find free port even after several tries",
                21  : "Unable to find netstat command",
                22  : "Unable to find both systemctl and service commands",
                200 : "Success",
                404 : "Fatal: unknown reason"
        }
        CLEAN_EXIT = 200

        host = self.__te_controller['host']
        uname = self.__te_controller.get('user', 'root')
        pwd = self.__te_controller.get('passwd', None)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if pwd:
            ssh.connect(host, username=uname, password=pwd)
        else:
            ssh.connect(host, username=uname)

        # SCPCLient takes a paramiko transport as an argument
        scp = SCPClient(ssh.get_transport())
        fileToSCP = os.path.join(repo_details['path_to_python_file_to_copy'],'GET_AND_RUN_DOCKER_IMAGE.py')
        scp.put(fileToSCP, 'GET_AND_RUN_DOCKER_IMAGE.py')
        cmd = "python ~/GET_AND_RUN_DOCKER_IMAGE.py -w ~/ -ip %s -p %s -b %s -t TE -h_ip %s \
            -ct %d -dt %d -lp %s -ll %d" %(repo_details['ip'], repo_details['port'], repo_details['path'], \
            host, stat_collect_interval, stat_dump_interval, logpath, loglevel)

        stdin, stdout, stderr = ssh.exec_command(cmd)
        print("Executing command = '%s'" %cmd)
        time_to_wait = 600
        thread_to_kill = Timer(time_to_wait, self.__kill_setup_te, args=[ssh, time_to_wait])
        thread_to_kill.start()
        exit_code = stdout.channel.recv_exit_status()
        thread_to_kill.cancel()
        print("Exit code is %d" %exit_code)

        if exit_code != CLEAN_EXIT:
            exit_error = EXIT_STATUS.get(exit_code, "Unknown Exit Code. Please examine download_docker.log in the target Controller machine")
            print(exit_error)
            return {'status':False, 'statusmessage':exit_error}
        else:
            count = 0
            DICT_OF_SERVICES = {}
            for port_details in stdout.readlines():
                service, port_taken = port_details.split("=")
                port_taken = port_taken.replace("\n","")
                if service == "flask":
                    self.__te_controller['hostport'] = port_taken
                print("%s ==> %s" %(service, port_taken))
                DICT_OF_SERVICES[service] = port_taken
                count += 1
                if count == 3:
                    break

            status, message = self.__checkIfContainerIsUp(DICT_OF_SERVICES, maxTolerableDelay, maxRetry, ssh)
            ssh.close()
            return {'status':status, 'statusmessage':message}


    @__retry_wrapper
    def setup_te(self, pathToTrafficEngine=None, repo_ip='10.79.171.71', repo_port='80', \
    repo_path=None, stat_collect_interval=15, stat_dump_interval=15, logpath='/tmp/', loglevel=10,
    maxTolerableDelay=60, path_to_python_file_to_copy=None):
        """
        Bring up the TE Controller in the host machine as a docker container as specified in the constructor argument

        Args:
            pathToTrafficEngine: str, optional (Either pathToTrafficEngine or repo_path; not both)
                Path to local `te` folder to build repo from scratch
            repo_path: str, optional (Either pathToTrafficEngine or repo_path; not both)
                HTTP get path to wget the docker image from the TE Controller.
            path_to_python_file_to_copy: str, optional(To be given compulsarily with repo_path)
                Local path to `GET_AND_RUN_DOCKER_IMAGE.py` file to bring up TE Controller from repo
            repo_ip: string, default '10.52.0.185', optional(To be given compulsarily with repo_path)
                IP reachable to wget the docker image from the TE Controller.
            repo_port: str, default '80', optional(To be given compulsarily with repo_path)
                Port reachable to wget the docker image from the TE Controller.
            stat_collect_interval: int, default 15s
                How often must the stats in Client must be push to TE Controller.
            stat_dump_interval: int, default 15s
                How often must the stats in Client must be dumped from datapath process.
            logpath: str, default '/tmp'
                Log path to write logs in TE Controller docker
            loglevel: int, default 10
                Python Log Level to write logs in TE Controller docker
            maxTolerableDelay: int, default 10
                Maximum delay to wait before the TE docker image comes up

        Returns:
            dict: status and statumessage describing the status of bringing up the Controller
        """

        if pathToTrafficEngine is None and repo_path is None:
            print("Please provide with either the path to Traffic Engine Code Repository or provide with repo name to pull the docker image from")

        elif pathToTrafficEngine is not None and repo_path is not None:
            print("You have provided both the path to Traffic Engine Code Repository and repo name to pull the docker image from. Please specify one")

        elif pathToTrafficEngine is not None:
            return self.__setup_te_from_docker_file(pathToTrafficEngine, stat_collect_interval, \
                stat_dump_interval, maxTolerableDelay, int(maxTolerableDelay), logpath, loglevel)

        elif repo_path is not None:
            repo_path = os.path.join('/',repo_path,'')
            repo_details = {'ip':repo_ip, 'port':str(repo_port), 'path':repo_path, 'path_to_python_file_to_copy':path_to_python_file_to_copy}
            print("TE Docker Image is hosted in %s" %repo_details)
            if path_to_python_file_to_copy is None:
                return {'status':False, 'statusmessage':'Passed None as path_to_python_file_to_copy'}
            if repo_ip is None:
                return {'status':False, 'statusmessage':'Passed None as IP'}
            if repo_port is None:
                return {'status':False, 'statusmessage':'Passed None as Port'}
            return self.__setup_te_from_repo(repo_details, stat_collect_interval, \
                stat_dump_interval, maxTolerableDelay, int(maxTolerableDelay), logpath, loglevel)


    @__retry_wrapper
    def setup_tedp(self, te_dp_dict):
        """
        Sets up the Docker Container for TE_DP Clients by pulling the docker image from TE Controller

        Args:
            te_dp_dict: dict, required
                The TE_DP client credientials which includes:
                    host_ip : Keys to te_dp_dict (Client mgmt IP) whose values includes:
                        user : User to the host_ip with passwordless docker privilege
                        passwd : Password to the host_ip's above user
        Example:
            te_dp_dict = {
                '1.1.1.1' : {'passwd': '', 'user': 'root'},
                '2.2.2.2' : {'passwd': '', 'user': 'root'}
            }

        Returns:
            dict: status and statumessage describing the status of bringing up the Clients
        """
        url = self.__url('setup_tedp')
        if url is not None:
            resp = requests.post(url, json={'te_dp_dict': te_dp_dict})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST setup_tedp/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("setup_tedp: Response is %s" % Jdata)
            return Jdata
        return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def connect(self, te_dp_dict):
        """
        Makes a communication channel establishment b/w TE Controller and TE_DP machines (Uses REDIS Queues)

        Args:
            te_dp_dict: dict, required
                The TE_DP client credientials which includes:
                    host_ip : Keys to te_dp_dict (Client mgmt IP) whose values includes:
            te_dp_dict's type is kept as disct for consistency purpose
        Example:
            te_dp_dict = {
                '1.1.1.1' : {},
                '2.2.2.2' : {}
            }

        Returns:
            dict: status and statumessage describing the status of connect the clients with controller
        """
        url = self.__url('connect')
        if url is not None:
            resp = requests.post(url, json={'te_dp_dict': te_dp_dict})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST connect/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("connect: Response is %s" % Jdata)
            return Jdata
        return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def start(self, resource_config, session_config, instanceProfileConfig, te_dp_dict, client_cert_bundle=None, max_tolerable_delay=120):
        """
        Starts the traffic on te_dp clients

        Args :
            resource_config: dict, required
                Configuration describing to whom the traffic is to be sent
            session_config: dict, required
                Configuration describing how the traffic is to be sent
            instanceProfileConfig: dict, required
                Maintains the mapping between te_dp instance and resource and session config
            client_cert_bundle: dict, optional
                Used for Mutual Authentication using pvt and public certs for HTTP(S) VIPs
                NOTE: Path specified works at host level (not docker paths)
            te_dp_dict: dict, required
                The TE_DP client mapping between te_dp hosts which includes:
                    host_ip : Keys to te_dp_dict (Client mgmt IP) whose values includes:
                        'instance_profile' : whose values include:
                            NOTE: None is used as wildcard and facilitates state machine transfer (This does not start traffic)
                                instance_profile_tag (key): Tag to any of the config in instanceProfileConfig
                                count (value): Number of such process to run in TE_DP clients
                                    NOTE: (Count of #process in a client) <= (#vCPU in that client - 1)

        Example:
            resource_config = {
                'res' : {
                    'default-get-post-ratio': '1:0',
                    'get-profiles': {
                        'g1': [{'uri': '128b.txt'}]
                    },
                    'http-version': '1.1',
                    'vip-list': [
                        {'vip': 'http://10.10.10.10', 'get-profile': 'g1'},
                        {'vip': 'https://20.20.20.20', 'get-profile': 'g1'}
                    ]
                }
            }

            session_config = {
                'ses' : {
                    'connection-range': [1, 1],
                    'cycle-type': 'restart',
                    'num-sessions' : 4,
                    'requests-range': [10, 10],
                    'session-type': 'MaxPerf'
                }
            }

            instanceProfileConfig = {'tedp_inst1' : {'res-tag': 'res', 'ses-tag': 'ses'}}

            Start Traffic => te_dp_dict = {
                '1.1.1.1' : {'instance_profile': {'tedp_inst1': 3}},
                '2.2.2.2' : {'instance_profile': {'tedp_inst2': 3}}
            } (OR)
            State Transition only => te_dp_dict = {
                '1.1.1.1' : {'instance_profile': None},
                '2.2.2.2' : {'instance_profile': None}
            }

            client_cert_bundle = {
                "https://20.20.20.20" : {
                    "default" : [
                        {
                            "ca-cert-path" : "/root/te-cert-key/ca-chain.cert.pem",
                            "enable-cname-verification" : false,
                            "cert-path" : "/root/te-cert-key/client.cert.pem",
                            "passphrase" : "client_key",
                            "key-path" : "/root/te-cert-key/client.key.pem",
                            "type" : "PEM"
                        }
                    ]
                }
            }

        Returns:
            dict, status and statumessage describing the status of starting the traffic in clients
        """
        url = self.__url('start')
        if url is not None:
            resp = requests.post(url, json={'resource_config': resource_config, 'session_config': session_config,\
                    'instanceProfileConfig':instanceProfileConfig, 'te_dp_dict':te_dp_dict, \
                    'max_tolerable_delay':max_tolerable_delay, 'client_cert_bundle':client_cert_bundle})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST start/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("start: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def stop(self, by_instance_profile_tag=None, by_host_and_instance_profile_tag=None, max_tolerable_delay=120):
        """
        Stops the traffic on te_dp clients

        Args :
            by_instance_profile_tag: str, optional
                To stop traffic on all te_dp instances running the profiles in the list specified
                NOTE: Does not move the state machine of the TE Controller
            by_host_and_instance_profile_tag : str, optional
                To stop traffic on specified host and profile_tag.
                NOTE: None is used as wildcard for stop_all in the current level of usage
                    Does not move the state machine of the TE Controller
            No Args (Other than max_tolerable_delay)
                Does a stop all => Affects the FSM of TE to come back to init

        Example:
            by_instance_profile_tag = ['inst_prof1', 'inst_prof2', 'inst_prof3']
            by_host_and_instance_profile_tag =  {
                'x.y.z.w' : None,
                'a.b.c.d' : {'tedp_inst1':2, 'tedp_inst2':1}
                'm.n.o.p' : {'tedp_inst1':None},
                'p.q.r.s' : {'tedp_inst1':None, 'tedp_inst2':1}
            }

        Returns:
            dict, status and statumessage describing the status of stopping the traffic in clients
        """
        url = self.__url('stop')
        if url is not None:
            resp = requests.post(url, json={'by_instance_profile_tag':by_instance_profile_tag, \
            'by_host_and_instance_profile_tag':by_host_and_instance_profile_tag, 'max_tolerable_delay':max_tolerable_delay})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST stop/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("stop: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def getStates(self):
        """
        For debugging purpose, returns the variable values and state of the objects maitained

        No Args

        Returns:
            dict, status and statumessage describing the current states of the TE Controller
        """
        url = self.__url('get_states')
        if url is not None:
            resp = requests.post(url, json={'no_args':'no_args'})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_states/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("getStates: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def update_config(self, resource_config, session_config, instanceProfileConfig, te_dp_dict, client_cert_bundle=None, max_tolerable_delay=120):
        """
        Updates the traffic on te_dp clients. Works as diff.

        Args:
        resource_config: dict, required
            Configuration describing to whom the traffic is to be sent
        session_config: dict, required
            Configuration describing how the traffic is to be sent
        instanceProfileConfig: dict, required
            Maintains the mapping between te_dp instance and resource and session config
        client_cert_bundle: dict, optional
            Used for Mutual Authentication using pvt and public certs for HTTP(S) VIPs
            NOTE: Path specified works at host level (not docker paths)
        te_dp_dict: dict, required
            The TE_DP client mapping between te_dp hosts which includes:
                host_ip : Keys to te_dp_dict (Client mgmt IP) whose values includes:
                    'instance_profile' : whose values include:
                        NOTE: None can't be used at this level
                            instance_profile_tag (key): Tag to any of the config in instanceProfileConfig
                            count (value): Number of such process to run in TE_DP clients
                                NOTE: (Count of #process in a client) <= (#vCPU in that client - 1)

        Example:
            resource_config = {
                'res' : {
                    'default-get-post-ratio': '1:0',
                    'get-profiles': {
                        'g1': [{'uri': '128b.txt'}]
                    },
                    'http-version': '1.1',
                    'vip-list': [
                        {'vip': 'http://10.10.10.10', 'get-profile': 'g1'},
                        {'vip': 'https://20.20.20.20', 'get-profile': 'g1'}
                    ]
                }
            }

            session_config = {
                'ses' : {
                    'connection-range': [1, 1],
                    'cycle-type': 'restart',
                    'num-sessions' : 4,
                    'requests-range': [10, 10],
                    'session-type': 'MaxPerf'
                }
            }

            instanceProfileConfig = {'tedp_inst1' : {'res-tag': 'res', 'ses-tag': 'ses'}}

            Start Traffic => te_dp_dict = {
                '1.1.1.1' : {'instance_profile': {'tedp_inst1': 3}},
                '2.2.2.2' : {'instance_profile': {'tedp_inst2': 3}}
            } (OR)
            State Transition only => te_dp_dict = {
                '1.1.1.1' : {'instance_profile': None},
                '2.2.2.2' : {'instance_profile': None}
            }

            client_cert_bundle = {
                "https://20.20.20.20" : {
                    "default" : [
                        {
                            "ca-cert-path" : "/root/te-cert-key/ca-chain.cert.pem",
                            "enable-cname-verification" : false,
                            "cert-path" : "/root/te-cert-key/client.cert.pem",
                            "passphrase" : "client_key",
                            "key-path" : "/root/te-cert-key/client.key.pem",
                            "type" : "PEM"
                        }
                    ]
                }
            }

        Returns:
            dict, status and statumessage describing the status of starting the traffic in clients
        """
        url = self.__url('update_config')
        if url is not None:
            resp = requests.post(url, json={'resource_config': resource_config, 'session_config': session_config,\
                        'instanceProfileConfig':instanceProfileConfig, 'te_dp_dict': te_dp_dict, 'client_cert_bundle':client_cert_bundle,
                        'max_tolerable_delay':max_tolerable_delay})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST update_config/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("update_config: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def clear_config(self, remove_containers=False):
        """
        Clears the te_dp process, metrics database and rq connection and removes client dockers (optional)

        Args:
            remove_containers: bool, default False
                To remove the te_dp containers as well

        Returns:
            dict, status and statumessage describing the status of clearing.
        """
        url = self.__url('clean')
        if url is not None:
            resp = requests.post(url, json={'remove_containers':remove_containers})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST clean/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("clear_config: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_active_tedp(self, tedps_to_query={}):
        """
        Gets the number of active tedp processes running on te_dp machines

        Args:
            tedps_to_query: dict, default all connected te_dp machines
                Subset of connected te_dp machines whose active processes are of interest

        Returns:
            dict, status and statumessage describing the number of active te_dp process in each client
        """
        url = self.__url('get_active_tedp')
        if url is not None:
            resp = requests.post(url, json={'tedps_to_query':tedps_to_query})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_active_tedp/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_active_tedp: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_cpu_count(self, te_dp_dict):
        """
        To get the number of vCPU cores available in each of the clients.

        Args:
            te_dp_dict: dict, required
                host_ip: Keys to te_dp_dict (Client mgmt IP) whose values includes:
                        user: User to the host_ip
                        passwd: Password to the host_ip
        Example:
            te_dp_dict = {
                '1.1.1.1' : {'passwd': '', 'user': 'root'},
                '2.2.2.2' : {'passwd': '', 'user': 'root'}
            }

        Returns:
            dict, status and statusmessage describing the number of vCPUs in each client
        """
        url = self.__url('get_cpu_count')
        if url is not None:
            resp = requests.post(url, json={'te_dp_dict':te_dp_dict})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_cpu_count/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_cpu_count: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def alter_stat_dump_interval(self, stat_dump_interval=None):
        """
        To change the interval at which the TE_DP process dumps the metrics

        The change will get reflected from the very next update_config/start after this call

        Args:
            stat_dump_interval: int, required
                Altered time

        Returns:
            dict, status and statusmessage describing the whether the call to alter was successful
        """
        url = self.__url('alter_stat_dump_interval')
        if url is not None:
            if(stat_dump_interval is None):
                return "Please provide stat_dump_interval"
            resp = requests.post(url, json={'stat_dump_interval':stat_dump_interval})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST alter_stat_dump_interval/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("alter_stat_dump_interval: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def alter_stat_collect_interval(self, stat_collect_interval=None):
        """
        To change the interval at which the Daemon process at TE_DP machine collects stats

        The change will get reflected from upon the next successful connect()

        Args:
            stat_collect_interval: int, required
                Altered time

        Returns:
            dict, status and statusmessage describing the whether the call to alter was successful
        """
        url = self.__url('alter_stat_collect_interval')
        if url is not None:
            if(stat_collect_interval is None):
                return "Please provide stat_collect_interval"
            resp = requests.post(url, json={'stat_collect_interval':stat_collect_interval})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST alter_stat_collect_interval/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("alter_stat_collect_interval: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def alter_metrics_collection(self, state):
        """
        To change the state of metrics collection

        The change will get reflected from the very next update_config/start after this call

        Args:
            state: bool, required
                True / False corresponding to metrics enabled / disabled

        Returns:
            dict, status and statusmessage describing the whether the call to alter was successful
        """
        url = self.__url('alter_metrics_collection')
        if url is not None:
            resp = requests.post(url, json={'state':state})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST alter_metrics_collection/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("alter_metrics_collection: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def alter_memory_metrics_collection(self, state):
        """
        To change the state of memory metrics collection

        It is used to figure out the presence of mem leaks if any (Used by trst suites)
        The change will get reflected from the very next update_config/start after this call

        Args:
            state : bool, required
                True / False corresponding to metrics enabled / disabled

        Returns:
            dict, status and statusmessage describing the whether the call to alter was successful
        """
        url = self.__url('alter_memory_metrics_collection')
        if url is not None:
            resp = requests.post(url, json={'state':state})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST alter_memory_metrics_collection/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("alter_memory_metrics_collection: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_current_te_time(self):
        """
        To get the current time stamp in TE. Useful in metric collection.

        No Args

        Returns:
            dict, status and statusmessage giving the current time of the controller
        """
        url = self.__url('get_current_te_time')
        if url is not None:
            resp = requests.post(url, json={'no_args':'no_args'})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_current_te_time/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_current_te_time: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_vip_metrics(self, type_of_metrics, traffic_profile="TCP", traffic_mode="CLIENT",
            is_named=True, filter_host_ip = None, filter_vip = None, filter_method=None,
            filter_uri=None, filter_ts_range=None, filter_res_hash=None, filter_ses_hash=None,
            filter_res_tag=None, filter_ses_tag=None, get_latency_stats=False):
        """
        Gets the metrics pertaining to the vips hit

        Args:
            type_of_metrics: str, required
                Get the metrics from the moment TE was setup, till this point ('TOTAL') (or)
                to get metrics from last time 'LAST_DIFF' was queried till this point ('LAST_DIFF')
            traffic_profile: str, defaults to "TCP"
                Allowed values are TCP and UDP
            traffic_mode: str, defaults to "CLIENT"
                Allowed values are SERVER and CLIENT
            is_named: bool, default True
                Name the return keys.
            get_latency_stats: bool, defaults to False
                To get the derived stats for latencies for each vip / uri / method
                When number of VIPs is < 10, by default the latency metrics are also retreived
            filter_ts_range: list of 2, optional
                Filters b/w time ranges. Give None if no limit is needed
                Examples: ['2019-05-20 10:05:24',None], [None,'2019-05-20 10:05:24']
            filter_host_ip: list, optional
                List of Client IPs interested
                When given an empty list, Metrics will be grouped
                Examples: ['a.b.c.d','q.w.e.r'], []
            filter_res_hash: list, optional
                List of Resource Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Examples: [-6286088396459832094, -62860883964598332322], []
            filter_res_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Examples: ['http_res_1','spl_http_res2'], []
            filter_ses_hash: list, optional
                List of Session Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Examples: [-6286088396459832094, -62860883964598332322], []
            filter_ses_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Examples: ['http_ses_1','spl_http_ses2'], []
            filter_vip: list, optional
                List of VIPs interested
                When given an empty list, Metrics will be grouped
                Examples: ['http://1.1.1.1','https://2.2.2.2'], []
            filter_method: list, optional
                List of Methods to filter upon (GET,POST)
                When given an empty list, Metrics will be grouped
                Examples: ['GET', 'POST'],['GET'],['POST'],[]
            filter_uri:
                List of Methods to filter upon (GET,POST)
                When given an empty list, Metrics will be grouped
                Examples: ['index.html', '128b.txt'],[]

        Returns:
            dict, status and statusmessage listing out metrics pertaining to each vips after applying mentioned filters and groupings
        """

        url = self.__url('get_vip_metrics')
        if url is not None:
            if(type_of_metrics != "TOTAL" and type_of_metrics != "LAST_DIFF"):
                return "Allowed values for type_of_metrics are TOTAL and LAST_DIFF"
            if(traffic_profile != "TCP" and traffic_profile != "UDP"):
                return "Allowed values for traffic_profile are TCP and UDP"
            if(traffic_mode != "CLIENT" and traffic_mode != "SERVER"):
                return "Allowed values for traffic_mode are TCP and CLIENT and SERVER"

            if(traffic_profile == "TCP"):
                pass
            elif(traffic_mode == "CLIENT"):
                if filter_uri is not None:
                    print("WARNING: filter_uri field is not applicable to UDP CLIENT")
                    lgr.warning("WARNING: filter_uri is not applicable for UDP CLIENT")
                    filter_uri = None
            else:
                not_applicable_list = []
                if filter_uri is not None:
                    not_applicable_list.append('filter_uri')
                    filter_uri = None
                if filter_method is not None:
                    not_applicable_list.append('filter_method')
                    filter_method = None
                if filter_ses_hash is not None:
                    not_applicable_list.append('filter_ses_hash')
                    filter_ses_hash = None
                if filter_ses_tag is not None:
                    not_applicable_list.append('filter_ses_tag')
                    filter_ses_tag = None
                if filter_res_hash is not None:
                    not_applicable_list.append('filter_res_hash')
                    filter_ses_hash = None
                if filter_res_tag is not None:
                    not_applicable_list.append('filter_res_tag')
                    filter_ses_tag = None
                if(bool(not_applicable_list)):
                    not_applicable_str = ",".join(not_applicable_list)
                    print("WARNING: {} is not applicable for UDP SERVER".format(not_applicable_str))
                    lgr.warning("WARNING: {} is not applicable for UDP SERVER".format(not_applicable_str))

            filter_clauses = {
                'host_ip' : filter_host_ip,
                'vip' : filter_vip,
                'method' : filter_method,
                'uri' : filter_uri,
                'ts_range' : filter_ts_range,
                'res_hash' : filter_res_hash,
                'ses_hash' : filter_ses_hash,
                'res_tag'  : filter_res_tag,
                'ses_tag'  : filter_ses_tag,
                'get_latency_stats' : get_latency_stats
            }

            resp = requests.post(url, json={'type':type_of_metrics,
                                    'traffic_profile' : traffic_profile,
                                    'traffic_mode' : traffic_mode,
                                    'filter_clauses':filter_clauses,
                                    'is_named' : is_named})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_vip_metrics/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_vip_metrics: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_ses_metrics(self, type_of_metrics, traffic_profile="TCP", traffic_mode="CLIENT",
            is_named=True, filter_host_ip = None, filter_ts_range=None, filter_res_hash=None,
            filter_ses_hash=None, filter_res_tag=None, filter_ses_tag=None):
        """
        Gets the overall metrics across VIPs hits

        Args:
            type_of_metrics: str, required
                Get the metrics from the moment TE was setup, till this point ('TOTAL') (or)
                to get metrics from last time 'LAST_DIFF' was queried till this point ('LAST_DIFF')
            traffic_profile: str, defaults to "TCP"
                Allowed values are TCP and UDP
            traffic_mode: str, defaults to "CLIENT"
                Allowed values are SERVER and CLIENT
            is_named: bool, default True
                Name the return keys.
            filter_ts_range: list of 2, optional
                Filters b/w time ranges. Give None if no limit is needed
                Examples: ['2019-05-20 10:05:24',None], [None,'2019-05-20 10:05:24']
            filter_host_ip: list, optional
                List of Client IPs interested
                When given an empty list, Metrics will be grouped
                Example: ['a.b.c.d','q.w.e.r'], []
            filter_res_hash: list, optional
                List of Resource Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Example: [-6286088396459832094, -62860883964598332322], []
            filter_res_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Example: ['http_res_1','spl_http_res2'], []
            filter_ses_hash: list, optional
                List of Session Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Example: [-6286088396459832094, -62860883964598332322], []
            filter_ses_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Example: ['http_ses_1','spl_http_ses2'], []

        Returns:
            dict, status and statusmessage listing out metrics pertaining to each vips after applying mentioned filters and groupings
        """

        url = self.__url('get_ses_metrics')
        if url is not None:
            if(type_of_metrics != "TOTAL" and type_of_metrics != "LAST_DIFF"):
                return "Allowed values for type_of_metrics are TOTAL and LAST_DIFF"
            if(traffic_profile != "TCP" and traffic_profile != "UDP"):
                return "Allowed values for traffic_profile are TCP and UDP"
            if(traffic_mode != "CLIENT" and traffic_mode != "SERVER"):
                return "Allowed values for traffic_mode are TCP and CLIENT and SERVER"

            filter_clauses = {
                'host_ip'        : filter_host_ip,
                'ts_range'       : filter_ts_range,
                'res_hash'       : filter_res_hash,
                'ses_hash'       : filter_ses_hash,
                'res_tag'        : filter_res_tag,
                'ses_tag'        : filter_ses_tag
            }

            resp = requests.post(url, json={'type':type_of_metrics,
                                    'traffic_profile' : traffic_profile,
                                    'traffic_mode' : traffic_mode,
                                    'filter_clauses':filter_clauses,
                                    'is_named' : is_named})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_ses_metrics/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_ses_metrics: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_memory_metrics(self, type_of_metrics, is_named=True, filter_host_ip = None,
            filter_pid = None, filter_ts_range=None, filter_res_hash=None, filter_ses_hash=None,
            filter_res_tag=None, filter_ses_tag=None):
        """
        Gets metrics regarding the memory utlization of various processes

        Args:
            type_of_metrics: str, required
                Get the metrics from the moment TE was setup, till this point ('TOTAL') (or)
                to get metrics from last time 'LAST_DIFF' was queried till this point ('LAST_DIFF')
            is_named: bool, default True
                Name the return keys.
            filter_ts_range: list of 2, optional
                Filters b/w time ranges. Give None if no limit is needed
                Examples: ['2019-05-20 10:05:24',None], [None,'2019-05-20 10:05:24']
            filter_host_ip: list, optional
                List of Client IPs interested
                When given an empty list, Metrics will be grouped
                Example: ['a.b.c.d','q.w.e.r'], []
            filter_res_hash: list, optional
                List of Resource Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Example: [-6286088396459832094, -62860883964598332322], []
            filter_res_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Example: ['http_res_1','spl_http_res2'], []
            filter_ses_hash: list, optional
                List of Session Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Example: [-6286088396459832094, -62860883964598332322], []
            filter_ses_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Example: ['http_ses_1','spl_http_ses2'], []
            filter_pid: list, optional
                List of PIDs interested
                When given an empty list, Metrics will be grouped
                Ex: ['125','122'], []

        Returns:
            dict, status and statusmessage listing out metrics pertaining to malloc and free of various processes
        """

        url = self.__url('get_memory_metrics')
        if url is not None:
            if(type_of_metrics != "TOTAL" and type_of_metrics != "LAST_DIFF"):
                return "Allowed types are TOTAL and LAST_DIFF"

            filter_clauses = {
                'host_ip' : filter_host_ip,
                'pid'       : filter_pid,
                'ts_range'  : filter_ts_range,
                'res_hash'  : filter_res_hash,
                'ses_hash'  : filter_ses_hash,
                'res_tag'   : filter_res_tag,
                'ses_tag'   : filter_ses_tag,
            }

            resp = requests.post(url, json={'type':type_of_metrics,
                                    'filter_clauses':filter_clauses,
                                    'is_named' : is_named})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_memory_metrics/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_memory_metrics: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_error_metrics(self, type_of_metrics, is_named=True, error_group_interval=15,
            filter_host_ip = None, filter_vip = None, filter_method=None, filter_uri=None,
            filter_ts_range=None, filter_res_hash=None, filter_ses_hash=None, filter_res_tag=None,filter_ses_tag=None):
        """
        Gets metrics regarding various errors

        Args:
            type_of_metrics: str, required
                Get the metrics from the moment TE was setup, till this point ('TOTAL') (or)
                to get metrics from last time 'LAST_DIFF' was queried till this point ('LAST_DIFF')
            is_named: bool, default True
                Name the return keys.
            error_group_interval: int, default 15s
                Maximum interval after which the subsequent error of same type is put into next bucket
            filter_ts_range: list of 2, optional
                Filters b/w time ranges. Give None if no limit is needed
                Examples: ['2019-05-20 10:05:24',None], [None,'2019-05-20 10:05:24']
            filter_host_ip: list, optional
                List of Client IPs interested
                When given an empty list, Metrics will be grouped
                Example: ['a.b.c.d','q.w.e.r'], []
            filter_res_hash: list, optional
                List of Resource Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Example: [-6286088396459832094, -62860883964598332322], []
            filter_res_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either res_tag (or) res_hash in an api call (not both)
                Example: ['http_res_1','spl_http_res2'], []
            filter_ses_hash: list, optional
                List of Session Config Hashes interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Example: [-6286088396459832094, -62860883964598332322], []
            filter_ses_tag: list, optional
                List of resource tag interested
                When given an empty list, Metrics will be grouped
                NOTE: Can filter by either ses_tag (or) ses_hash in an api call (not both)
                Example: ['http_ses_1','spl_http_ses2'], []
            filter_vip: list, optional
                List of VIPs interested
                When given an empty list, Metrics will be grouped
                Examples: ['http://1.1.1.1','https://2.2.2.2'], []
            filter_method: list, optional
                List of Methods to filter upon (GET,POST)
                When given an empty list, Metrics will be grouped
                Examples: ['GET', 'POST'],['GET'],['POST'],[]
            filter_uri:
                List of Methods to filter upon (GET,POST)
                When given an empty list, Metrics will be grouped
                Examples: ['index.html', '128b.txt'],[]

        Returns:
            dict, status and statusmessage listing out metrics pertaining to various errors across VIPs targetted
        """
        url = self.__url('get_error_metrics')
        if url is not None:
            if(type_of_metrics != "TOTAL" and type_of_metrics != "LAST_DIFF"):
                return "Allowed types are TOTAL and LAST_DIFF"

            filter_clauses = {
                'host_ip' : filter_host_ip,
                'vip' : filter_vip,
                'method' : filter_method,
                'uri' : filter_uri,
                'ts_range' : filter_ts_range,
                'res_hash' : filter_res_hash,
                'ses_hash' : filter_ses_hash,
                'res_tag'  : filter_res_tag,
                'ses_tag'  : filter_ses_tag,
            }

            resp = requests.post(url, json={'type':type_of_metrics,
                                    'filter_clauses':filter_clauses,
                                    'is_named' : is_named,
                                    "error_group_interval" : \
                                        error_group_interval})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_error_metrics/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_error_metrics: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def get_configs(self, is_named=True, res_hash_list=None, ses_hash_list=None):
        """
        Retrieves the configuration given the hash

        Args:
            is_named: bool, default True
                Name the return keys.
            res_hash_list: list, optional
                List of res_hash to retreive the corresponding configs
                Empty List retrieves everything
            ses_hash_list: list, optional
                List of ses_hash to retreive the corresponding configs
                Empty List retrieves everything

        Returns:
            dict, status and statusmessage describing the hashes and their correspoding configurations
        """
        url = self.__url('get_configs')
        if res_hash_list is None and ses_hash_list is None:
            return {'status':False, 'statusmessage' : 'Both res_hash_list and ses_hash_list cannot be None'}

        if url is not None:
            resp = requests.post(url, json={'res_hash_list' : res_hash_list,
                                            'ses_hash_list' : ses_hash_list,
                                            'is_named' : is_named})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_configs/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_configs: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"

    @__retry_wrapper
    def get_client_history(self, filter_host_ip=None, filter_ts_range=None):
        """
        Retrieves the hashes of configurations which various clients ran at various points of time

        Args:
            filter_ts_range: list of 2, optional
                Filters b/w time ranges. Give None if no limit is needed
                Examples: ['2019-05-20 10:05:24',None], [None,'2019-05-20 10:05:24']
            filter_host_ip: list, optional
                List of Client IPs interested
                When given an empty list, Metrics will be grouped
                Example: ['a.b.c.d','q.w.e.r'], []

        Returns:
            dict, status and statusmessage describing the history of run across client machines
        """
        url = self.__url('get_client_history')
        if url is not None:
            filter_clauses = {
                'host_ip' : filter_host_ip,
                'ts_range' : filter_ts_range
            }

            resp = requests.post(url, json={'filter_clauses':filter_clauses})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST get_client_history/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("get_client_history: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def update_dns(self, global_dns=None, te_dp_dict=None, overwrite=True):
        """
        Updates the /etc/resolv.conf entries within the docker container

        Args:
            overwrite: bool, default True
                True overwrite the details in resolv.conf of docker and
                False append the details in resolv.conf of docker
            global_dict: dict, optional (Either global_dict or te_dp_dict (Not Bioth))
                To update all the connected te_dp clients with the specified dict
            te_dp_dict: dict, optional (Either global_dict or te_dp_dict (Not Bioth))
                To update all the few selected te_dp clients with the specified dict

        Examples:
            global_dns = [
                ("nameserver", "192.168.0.100"),
                ("domain", "domain1.com")
            ]

            te_dp_dict = {
                "a.b.c.d" : [
                    ("nameserver", "192.168.0.100"),
                    ("domain", "domain1.com")
                ],
                "p.q.r.s" : [
                    ("nameserver", "192.168.0.101"),
                    ("domain", "domain2.com")
                ]
            }

        Returns:
            dict, status and statusmessage describing the status of updating the DNS
        """
        url = self.__url('update_dns')
        if url is not None:

            resp = requests.post(url, json={"global_dns":global_dns,
                                            "te_dp_dict":te_dp_dict,
                                            "overwrite":overwrite})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST update_dns/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("update_dns: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"


    @__retry_wrapper
    def reset_dns(self, te_dp_dict=None):
        """
        Resets the /etc/resolv.conf of te_dp clients

        Args:
            te_dp_dict: dict, required
                Empty dict will reset all connected te_dp, else selected dict's /etc/resolv.conf within container will be reset

        Returns:
            dict, status and statusmessage describing the status of reseting the DNS
        """
        url = self.__url('reset_dns')
        if url is not None:

            resp = requests.post(url, json={"te_dp_dict":te_dp_dict})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST reset_dns/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("reset_dns: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"

    @__retry_wrapper
    def execute_cmd(self, cmd, te_dp_dict={}, job_timeout=None):
        """
        Executes any custom commands within container

        Args:
            te_dp_dict: dict, default {}
                To run commands on selected te_dp clients alone
                Empty dict will run on all connected te_dps
            cmd: str, required
                Command to execute
            job_timeout: int, default Redis Queue Timeout
                Max time to wait before timing out

        Returns:
            dict, status and statusmessage with output and error of the commands run
        """
        url = self.__url('execute_cmd')
        if url is not None:

            resp = requests.post(url, json={"te_dp_dict":te_dp_dict, \
                "cmd":cmd, "job_timeout":job_timeout})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST execute_cmd/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("execute_cmd: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"

    @__retry_wrapper
    def tech_support(self, te_dp_dict={}, log_type="all", max_tolerable_delay=120):
        """
        To get the logs to specified scp_ip with the given credentials

        Args:
            te_dp_dict: dict, default {}
                If connect step is completed and if te_dp_dict is empty, logs are pulled from all clients
                Else if connect step is yet to be completed only setup_logs can be got from passed te_dp_dict
            log_type: str, default 'all'
                Types of logs to scp
                    > setup: Includes controller.log and download_docker.log
                    > process: Logs of TE_DP processes
                    > core: Core dumps of the TE_DP processes
                    > all: All the above logs
            max_tolerable_delay: int, default 120s
                Time to wait till scp completes

        Returns:
            dict, status and statusmessage describing the stats of completion of SCP
        """
        url = self.__url('tech_support')
        scp_user = self.__te_controller.get('user', 'root')
        scp_passwd = self.__te_controller.get('passwd', None)

        if url is not None:
            resp = requests.post(url, json={'te_dp_dict':te_dp_dict,
                'log_type':log_type, 'max_tolerable_delay':max_tolerable_delay,
                'scp_user':scp_user, 'scp_passwd':scp_passwd})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST tech_support/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("tech_support: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"

    @__retry_wrapper
    def grafana(self, state):
        """
        To visualize, monitor and analyze traffic patterns.
        Collect the metrics from Postgres database after every n seconds(default is 30s) and display in dashboard.
        Args:
            State: True/False
                True: Start the Grafana service
                False: Stop the Grafana service
        Returns
            An Url (containing Ip address with Port number e.g (127.0.0.1:3000) )
            hit this url on your browser to visualize metrics on grafana dashboard.
        """
        url = self.__url('grafana')
        if url is not None:
            resp = requests.post(url, json={'state':state})
            Jdata = resp.json()
            if resp.status_code not in [200, 201]:
                raise Exception('POST grafana/ {} {}'.format(resp.status_code, Jdata))
            lgr.debug("grafana: Response is %s" % Jdata)
            return Jdata
        else:
            return "TE Controller flask port not known. Please set it using the call set_controller_flask_port(port)"
