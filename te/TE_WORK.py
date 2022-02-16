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

import sys, os
from TE_UTILS import convert, Logger, SysVQ
from sysv_ipc import ftok
import traceback
from collections import defaultdict
import paramiko
from scp import SCPClient

LOG_PATH = '/tmp/'
LOG_PATH_TE_DP = '/tmp/ramcache/'


# Check for the correctness of the LOG_PATH_TE_DP!
if(not(os.path.exists(LOG_PATH_TE_DP))):
    print({'status'        : False,
            'statusmessage' : 'LOG_PATH_TE_DP does not exist'})

try:
    lgr = Logger(' [ TE_WORKER ] ', os.path.join(LOG_PATH,'wrk.te.log')).getLogger()
    lgr.info("Starting the TE WORK Process")
except:
    with open('error.txt','a') as h:
        h.write("Unable to get a Logger Object %s" %traceback.format_exc())


try:
    import glob
    import json, time, re, subprocess
    import ast, string
    import signal
    from collections import OrderedDict
    from rq.decorators import job as tejob
    from rq import get_current_job

except Exception as e:
    lgr.error("Import Failed.... %s" %traceback.format_exc() )
    sys.exit(1)

# Needed for Root in Celery
os.environ.setdefault('C_FORCE_ROOT', 'true')

def __exec_cmd(cmd, stderr=True):
    if stderr:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    else:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    out, err = proc.communicate()
    # Both Python 2 & 3 compliant
    if bool(out):
        out = out.decode()
    if bool(err):
        err = err.decode()
    return (out, err)

@tejob('te_broadcast_q')
def run_mgmt_command_te_dp(cmd=None):
    try:
        if cmd is None:
            return {"status" : False, "statusmessage":"Command cannot be none"}
        (out, err) = __exec_cmd(cmd)
        lgr.info("Cmd=%s, Output=%s and err=%s" %(cmd, str(out), str(err)))
        return  {"status" : True, "statusmessage" : {"err" : err, "out": out}}
    except:
        return {"status" : False, "statusmessage" : "Exception Occurred: %s" %traceback.format_exc()}

@tejob('te_broadcast_q')
def tech_support(my_ip, remote_ip, remote_user, remote_pwd, remote_path, type_of_logs):
    try:
        folders_to_make = [os.path.join("/te_host/", 'te_%s_logs' %my_ip)]
        files_to_send = []
        tar_file = "te_{}_logs.tar.gz".format(my_ip)
        tar_file_with_path = os.path.join("/te_host/", tar_file)

        if(type_of_logs == "all" or type_of_logs == "setup"):
            destination = os.path.join(folders_to_make[0], 'setup_logs/')
            make_folder = False
            #rq.log
            file_interested = '/tmp/rq.log'
            if(os.path.exists(file_interested)):
                files_to_send.append((file_interested, destination))
                make_folder = True

            #download_docker.log
            file_interested = '/te_root/download_docker.log'
            if(os.path.exists(file_interested)):
                files_to_send.append((file_interested, destination))
                make_folder = True

            if(make_folder):
                folders_to_make.append(destination)

        if(type_of_logs == "all" or type_of_logs == "process"):
            destination = os.path.join(folders_to_make[0], 'process_logs/')
            file_interested = '/tmp/ramcache/te_*.csv'
            if(bool(glob.glob(file_interested))):
                files_to_send.append((file_interested, destination))
                folders_to_make.append(destination)

            file_interested = '/tmp/*.log'
            if(bool(glob.glob(file_interested))):
                files_to_send.append((file_interested, destination))
                folders_to_make.append(destination)

        if(type_of_logs == "all" or type_of_logs == "core"):
            destination = os.path.join(folders_to_make[0], 'core_logs/')
            file_interested = '/opt/te/core.*'
            if(bool(glob.glob(file_interested))):
                files_to_send.append((file_interested, destination))
                folders_to_make.append(destination)

        if(type_of_logs == "all" or type_of_logs == "process" or type_of_logs=='core'):
            file_interested_bin='/opt/te/bin/'
            file_interested_src='/opt/te/src/'
            file_interested_makefile='opt/te/Makefile'
            destination=os.path.join(folders_to_make[0],'bin_src_file_dir/')
            files_to_send.append((file_interested_bin, destination))
            files_to_send.append((file_interested_src, destination))
            files_to_send.append((file_interested_makefile, destination))
            folders_to_make.append(destination)

        if(bool(folders_to_make)):
            str_folder_to_make = " ".join(folders_to_make)
            cmd = "rm -rf %s; mkdir -p %s" %(folders_to_make[0], str_folder_to_make)
            (out, err) = __exec_cmd(cmd)
            lgr.info("Executing cmd=%s, out=%s, err=%s" %(cmd, out, err))

        for (src, dest) in files_to_send:
            cmd = "cp -r %s %s" %(src, dest)
            (out, err) = __exec_cmd(cmd)
            lgr.info("Executing cmd=%s, out=%s, err=%s" %(cmd, out, err))

        cmd = "tar -zcvf {} {}/*; rm -rf {}".format(tar_file_with_path, folders_to_make[0], folders_to_make[0])
        (out, err) = __exec_cmd(cmd)
        lgr.info("Executing cmd=%s, out=%s, err=%s" %(cmd, out, err))

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if remote_pwd:
                ssh.connect(remote_ip, username=remote_user, password=remote_pwd)
            else:
                ssh.connect(remote_ip, username=remote_user)
            scp = SCPClient(ssh.get_transport())
            scp.put(tar_file_with_path, remote_path)
        except:
            lgr.error(traceback.format_exc())
            return {"status" : False,
                    "statusmessage" : "Unable to SCP but logs are available at /tmp/{} in {}".format(
                        tar_file, my_ip)}
        return {'status':True, 'statusmessage':'Sent requested files'}
    except:
        lgr.error(traceback.format_exc())
        return {'status':False, 'statusmessage':traceback.format_exc()}

@tejob('te_broadcast_q')
def start_te_dp(resource_config=None, session_config=None, resource_hash=None, session_hash=None, \
    client_mgmt_ip=None, traffic_mode=None, traffic_profile=None, stat_dump_interval=None, \
    metrics_enabled=False, memory_metrics_enabled=False, uniq_name=None, cpu=None, log_level=None):

    #Utility Function Used By createPostFiles()
    def isFilePresent(dockerPath, file):
        return os.path.exists(dockerPath+file) or os.path.exists(file)

    #Utility Function Used By createPostFiles()
    def getSizeAndPathOfFile(dockerPath, fileName):
        pathInDocker = dockerPath + fileName
        sizeOfFile, extn = fileName.split('.')
        sizeOfFile, denom = sizeOfFile.split('_')

        # truncate doesn't accept B as a valid size
        if(denom == 'B'):
            return sizeOfFile, pathInDocker
        else:
            return sizeOfFile + denom, pathInDocker

    def get_global_ns_if_available(resconv_sort):
        set_of_pointed_if_profiles = set()
        set_of_pointed_nses        = set()
        ns_to_if_profile_mapping   = defaultdict(lambda: defaultdict(list))
        if_prof_to_vip_idx_mapping = defaultdict(list)
        any_default_ns             = False

        # Make a set of interface profile names that are pointed by various VIP object
        counter = 0
        for vip_obj in resconv_sort['resource-config']['vip-list']:
            if_profile = vip_obj.get('interface-profile', None)
            if if_profile is not None:
                if_prof_to_vip_idx_mapping[if_profile].append(counter)
                set_of_pointed_if_profiles.add(if_profile)
            else:
                any_default_ns = True
            counter += 1

        # If there are vips that are not pointing to any profile
        # Then by default it is in root's namespace
        if(any_default_ns):
            set_of_pointed_nses.add("root")

        # Parse through the above set, and get the unique n/w namespace names
        # Stop the parse and return, if the number of unique n/w namespaces > 1
        # If there is no namespace mentioned, it means we got to use 'root' ns, for that profile
        for if_profile in set_of_pointed_if_profiles:
            list_of_if_objs = resconv_sort['resource-config']['interface-profiles'].get(if_profile)
            counter = 0
            unique_nses = 0
            for if_obj in list_of_if_objs:
                ns_name = if_obj.get('ns', 'root')
                set_of_pointed_nses.add(ns_name)
                if(len(set_of_pointed_nses) > 1):
                    return None
                ns_to_if_profile_mapping[ns_name][if_profile].append(counter)
                counter += 1

        # If we have only one namespace that is uniquely pointed then pop all the references of that namespace,
        # and return True to start the process in that namespace, if the namespace is not `root`
        if len(set_of_pointed_nses) == 1:
            global_ns = set_of_pointed_nses.pop()
            profile_to_if_idx_mapping = ns_to_if_profile_mapping.get(global_ns, None)

            if(isinstance(profile_to_if_idx_mapping, dict)):
                for profile_name, list_of_if_idx in profile_to_if_idx_mapping.items():
                    for if_idx in reversed(list_of_if_idx):
                        resconv_sort['resource-config']['interface-profiles'][profile_name][if_idx].pop('ns', None)
                        # If the `ns` is popped and if there no `if` field as well, there is no point having the obj
                        if 'if' not in resconv_sort['resource-config']['interface-profiles'][profile_name][if_idx]:
                            resconv_sort['resource-config']['interface-profiles'][profile_name].pop(if_idx)

                    # If by the above process, the list becomes empty, we got to delete all refs of the profile
                    if(not(bool(resconv_sort['resource-config']['interface-profiles'][profile_name]))):
                        for vip_idx in if_prof_to_vip_idx_mapping[profile_name]:
                            resconv_sort['resource-config']['vip-list'][vip_idx].pop('interface-profile')
                        resconv_sort['resource-config']['interface-profiles'].pop(profile_name)

                # If by the above process, the `interface-profiles` becomes empty, we got to delete it
                if(not(bool(resconv_sort['resource-config']['interface-profiles']))):
                    resconv_sort['resource-config'].pop('interface-profiles')

            # If the unique namespace is root, then it is not a unique case, but rather a normal te_dp run
            if global_ns == 'root':
                return None
            return global_ns

        # More than 1 n/w namespace / ni mention of n/w namespaces
        # Nothing fancy has to be done
        return None

    #Utility Function Used By start_te_dp() to make post files
    def createPostFiles(resource_config, dockerPath = "/te_host/"):
        '''
            > Files name must be <size>_<denomination>.txt
            > Floating numbers of size is not allowed (Use lower denominations instead)
            > Denominations are:
                B ==> Byte
                K ==> kiloByte
                M ==> megaByte
                G ==> gigaByte
        '''
        try:
            post_profiles = resource_config.get('post-profiles',{})
            creationSuccess = True

            for profile_name, post_list in post_profiles.items():
                #Changes the path and saves it!!!
                for req in post_list:
                    file = req.get('file',None)
                    if file is not None:
                        if re.match('^\d+_[B,K,M,G]\.txt$',file) is None:
                            # If file is not of the specified format, it must be already created at /tmp of host
                            # Else throw an error
                            if(not(isFilePresent(dockerPath, file))):
                                lgr.error("Post Files can be created having a name convention of <size>_<B/K/M/G>.txt and so %s not created" %file)
                                creationSuccess = False
                            else:
                                if(os.path.exists(file)):
                                    req['file'] = file
                                elif(os.path.exists(dockerPath+file)):
                                    req['file'] = dockerPath + file

                        # If File is present => Skip
                        elif(isFilePresent(dockerPath,file)):
                            lgr.debug("Skipping creation of Post File %s as it already exists" %file)
                            req['file'] = dockerPath + file


                        # Create File if file format is valid and it doesn't exist
                        else:
                            size, pathInDocker = getSizeAndPathOfFile(dockerPath, file)
                            cmd = "truncate -s " + size + " " + pathInDocker
                            lgr.info("Making Post File %s with cmd '%s'"  %(file, cmd))
                            (out, err) = __exec_cmd(cmd)
                            req['file'] = dockerPath + file

            if(creationSuccess and 'post-profiles' in resource_config):
                resource_config['post-profiles'] = post_profiles

        except:
            lgr.error("ERROR IN CREATE POST FILES %s" %traceback.format_exc())
            creationSuccess = False

        return creationSuccess


    try:
        lgr.info("Start Called")
        if resource_config is None or session_config is None or uniq_name is None or cpu is None:
            return {'status'        : False,
                    'statusmessage' : 'resource_config (or) session_config (or) uniq_name (or) cpu cannot be None'}

        if(log_level is not None):
            lgr.setLevel(log_level)
        lgr.debug("resource config is %s session config is %s uniq_name is %s CPU %s"% (resource_config, session_config, uniq_name, cpu))
        folderpath = os.path.join(LOG_PATH,uniq_name)

        # Deleting any existing file/folder of name 'LOG_PATH+uniq_name'
        if os.path.exists(folderpath):
            lgr.debug( "Folder " + str(folderpath) + "is being removed")
            cmd = 'rm -rf ' + str(folderpath)
            (out, err) = __exec_cmd(cmd)
            if os.path.exists(folderpath):
                lgr.error( "Folder %s could not be deleted" %str(folderpath))

        # Create a folder of name LOG_PATH+uniq_name and dumping resource-config
        os.makedirs(folderpath)

        resconv_sort = ast.literal_eval('{ \"resource-config\": ' + str(convert(resource_config)) + '}')
        resconv_new = OrderedDict()
        resconv = OrderedDict()

        # If the all the vips point to the same namespace, then move the process to that namespace
        # Valid only for TCP CLIENT
        lgr.info("traffic_profile={}, traffic_mode={}".format(traffic_profile, traffic_mode))
        if(traffic_profile == "TCP"):
            global_ns_name = get_global_ns_if_available(resconv_sort)
            if global_ns_name is not None:
                resconv_new['global-ns']=global_ns_name

        if 'interface-profiles' in resconv_sort['resource-config']:
            resconv_new['interface-profiles']=resconv_sort['resource-config']['interface-profiles']

        if 'get-profiles' in resconv_sort['resource-config']:
            resconv_new['get-profiles']=resconv_sort['resource-config']['get-profiles']

        if 'post-profiles' in resconv_sort['resource-config']:
            resconv_new['post-profiles']=resconv_sort['resource-config']['post-profiles']

        if 'udp-profiles' in resconv_sort['resource-config']:
            resconv_new['udp-profiles']=resconv_sort['resource-config']['udp-profiles']

        if 'default-get-post-ratio' in resconv_sort['resource-config']:
            resconv_new['default-get-post-ratio'] = \
                resconv_sort['resource-config']['default-get-post-ratio']

        if 'set-cookies-resend' in resconv_sort['resource-config']:
            resconv_new['set-cookies-resend'] = \
                resconv_sort['resource-config']['set-cookies-resend']

        if 'default-download-upload-ratio' in resconv_sort['resource-config']:
            resconv_new['default-download-upload-ratio'] = \
                resconv_sort['resource-config']['default-download-upload-ratio']

        if 'vip-list' in resconv_sort['resource-config']:
            resconv_new['vip-list']=resconv_sort['resource-config']['vip-list']

        if 'port-list' in resconv_sort['resource-config']:
            resconv_new['port-list']=resconv_sort['resource-config']['port-list']

        if 'port-range' in resconv_sort['resource-config']:
            resconv_new['port-range']=resconv_sort['resource-config']['port-range']

        ######### TCP PARAMS

        if 'vip-selection-rr' in resconv_sort['resource-config']:
            resconv_new['vip-selection-rr']=resconv_sort['resource-config']['vip-selection-rr']

        if 'log-level' in resconv_sort['resource-config']:
        	resconv_new['log-level']=resconv_sort['resource-config']['log-level']

        if 'tcp-keepalive-timeout' in resconv_sort['resource-config']:
            resconv_new['tcp-keepalive-timeout']=resconv_sort['resource-config']['tcp-keepalive-timeout']

        if 'tcp-connect-timeout' in resconv_sort['resource-config']:
            resconv_new['tcp-connect-timeout']=resconv_sort['resource-config']['tcp-connect-timeout']

        if 'disable-tcp-nagle' in resconv_sort['resource-config']:
            resconv_new['disable-tcp-nagle']=resconv_sort['resource-config']['disable-tcp-nagle']

        if 'http-version' in resconv_sort['resource-config']:
            resconv_new['http-version']=resconv_sort['resource-config']['http-version']

        if 'ssl-version' in resconv_sort['resource-config']:
            resconv_new['ssl-version']=resconv_sort['resource-config']['ssl-version']

        if 'ssl-groups' in resconv_sort['resource-config']:
            resconv_new['ssl-groups']=resconv_sort['resource-config']['ssl-groups']

        if 'cipher-suites' in resconv_sort['resource-config']:
            resconv_new['cipher-suites']=resconv_sort['resource-config']['cipher-suites']

        if 'ssl-session-reuse' in resconv_sort['resource-config']:
            resconv_new['ssl-session-reuse']=resconv_sort['resource-config']['ssl-session-reuse']

        if 'http-pipeline' in resconv_sort['resource-config']:
            resconv_new['http-pipeline']=resconv_sort['resource-config']['http-pipeline']

        if 'send-tcp-resets' in resconv_sort['resource-config']:
            resconv_new['send-tcp-resets']=resconv_sort['resource-config']['send-tcp-resets']

        if 'tcp-connect-only' in resconv_sort['resource-config']:
            resconv_new['tcp-connect-only']=resconv_sort['resource-config']['tcp-connect-only']
        """
        # Unsupported knobs as of today
        # Lot of the knobs can be used to simulate attacks
        if 'pipelen' in resconv_sort['resource-config']:
            resconv_new['pipelen']=resconv_sort['resource-config']['pipelen']

        if 'connect-only' in resconv_sort['resource-config']:
            resconv_new['connect-only']=resconv_sort['resource-config']['connect-only']

        if 'socket-linger' in resconv_sort['resource-config']:
            resconv_new['socket-linger']=resconv_sort['resource-config']['socket-linger']

        if 'enable-addr-reuse' in resconv_sort['resource-config']:
            resconv_new['enable-addr-reuse']=resconv_sort['resource-config']['enable-addr-reuse']

        if 'tcp-fastopen' in resconv_sort['resource-config']:
            resconv_new['tcp-fastopen']=resconv_sort['resource-config']['tcp-fastopen']

        if 'tcp-noclose' in resconv_sort['resource-config']:
            resconv_new['tcp-noclose']=resconv_sort['resource-config']['tcp-noclose']

        if 'app-timeout' in resconv_sort['resource-config']:
            resconv_new['app-timeout']=resconv_sort['resource-config']['app-timeout']

        if 'http-keep-alives' in resconv_sort['resource-config']:
            resconv_new['http-keep-alives']=resconv_sort['resource-config']['http-keep-alives']
        """

        resconv_new['log-path']=LOG_PATH_TE_DP
        resconv['resource-config']=resconv_new

        #Creates postfiles if not present in /te_host/ of the docker
        #If the file has to be created on the fly, the naming conventions is "<size>_<denomination - B,K,M,G>.txt" (No decimal values are allowed)
        #Path must not be mentioned for on the fly creation.
        #If file is already present, the absolute path to the file must be given .
        isPostFilesCreated = createPostFiles(resconv['resource-config'])

        # Write the configs
        resourceFile = os.path.join(folderpath,'resourceConfig.json')
        fd_res = open(resourceFile, 'w')
        fd_res.write(json.dumps(resconv,indent=3))
        fd_res.close()

        if(bool(session_config)):
            sesconv = ast.literal_eval('{ \"session-config\": [' + str(convert(session_config)) + '] }')
            sessionFile = os.path.join(folderpath,'sessionConfig.json')
            fd_ses = open(sessionFile, 'w')
            fd_ses.write(json.dumps(sesconv,indent=3))
            fd_ses.close()
        else:
            sessionFile = None

        result = {}
        if(not(isPostFilesCreated)):
            result['status']        = False
            result['statusmessage'] = 'Unable to create post files'
            result['result']        = None
            return result

        result['cpu_result'] = {}

        # Get the TE_DP's info
        LaunchPassed = False

        #General command to start te_dp
        """
        bin/te_dp -a CLIENT/SERVER -p TCP/UDP -i <client_ip> -c <cpu> \
        -r resource_config -j resource_config's hash \
        -s session_config -k session_config's hash \
        -d stats_dump_interval -m(Optional to enable metrics) -t(Optional to memory metrics)
        """

        if(bool(sessionFile)):
            cmd = """nohup taskset -c {} /opt/te/bin/te_dp -a {} -p {} -i {} -c {} -r {} -j {} \
                -s {} -k {}""".format(cpu, traffic_mode, traffic_profile, client_mgmt_ip, \
                cpu, resourceFile, resource_hash, sessionFile, session_hash)
        else:
            cmd = "nohup taskset -c {} /opt/te/bin/te_dp -a {} -p {} -i {} -c {} -r {} -j {}".format(
                cpu, traffic_mode, traffic_profile, client_mgmt_ip, cpu, resourceFile, resource_hash)

        if(stat_dump_interval != 0):

            if(memory_metrics_enabled):
                cmd += " -t"

            if(metrics_enabled):
                cmd += " -m"

            cmd += " -d {}".format(stat_dump_interval)

        cmd += " > /dev/null & echo $!"

        lgr.info("Starting TE_DP process using cmd='%s'" %cmd)
        (out, err) = __exec_cmd(cmd, stderr=False)
        try:
            pid = int(out)
            LaunchPassed = True
        except:
            pass

        if LaunchPassed:
            result['pid'] = pid
            result['status'] = True
            result['statusmessage'] = "Started TEDP in cpu=%d" %cpu
            lgr.info("Launched the TEDP Process PID and TE_WORK's %d "%(pid))
            lgr.info("Start Succeeded on cpu=%d pid=%d" %(cpu, pid))
            if(stat_dump_interval != 0):
                msg_q = SysVQ(1)
                msg_q.send(str(pid))
            return result

        else:
            result['status'] = False
            result['statusmessage'] = "Unable to start te_dp in cpu={}".format(cpu)
            lgr.info("Start Failed on cpu=%d" %cpu)
            return result


    except:
        lgr.error( 'Exception Occured , Trace : %s' %traceback.format_exc() )
        result = {
            'status'        : False,
            'statusmessage' : 'Exception Occured , Trace : %s' %traceback.format_exc()
        }
        return result


def checkRequestValidity(pid):

    # Check if all necessary params are given
    if pid is None:
        return {'status'        : False,
                'statusmessage' : "pid=" + str(pid) + " cannot be None"}

    # Check if the te_dp process is actually running
    tedp_alive = len(os.popen('ps -p '+str(pid)+'| grep te_dp').read())
    if not tedp_alive:
        return {'status'        : False,
                'statusmessage' : 'TEDP not alive'}

    # If all Requests pass
    return None

def remove_queue(q_id):
    cmd = 'ipcrm -Q ' + str(q_id)
    (out, err) = __exec_cmd(cmd)

def stop_te_dp_helper(pid):
    #Tries to do a stop
    #Does a soft kill
    #Checks if the process is kill and queues are removed
    #Else does a hard kill and removes the queues

    def kill_process(sigID):
        '''
        Args:
            sigID: Signal used to kill the process
            Use signal 1(or)2 for softkill
            Use signal 9 for hard kill
        '''
        cmd = 'kill -' + str(sigID) + ' ' + str(pid)
        (out, err) = __exec_cmd(cmd)

    def isProcessAlive():
        return len(os.popen('ps -p '+str(pid)+'| grep te_dp').read())

    #Soft Kill
    #Make Queues and stop te_dp process

    kill_process(signal.SIGINT) #Soft kill
    time.sleep(2)
    if(isProcessAlive()):
        #Hard Kill
        kill_process(9)
        remove_queue(ftok("/tmp", pid, True))
        time.sleep(2)

    return not(isProcessAlive())


@tejob('te_broadcast_q')
def stop_te_dp(pid=None, uniq_name='TE_DP'):

    try:
        lgr.info("Stop Called")
        isValidRequest = checkRequestValidity(pid)
        if isValidRequest is not None:
            lgr.warning("Dp process had already crashed %s" %str(pid))
            if pid is not None:
                remove_queue(ftok("/tmp", pid, True))
            return {
                'status' : True,
                'statusmessage' : 'Dp process had already crashed'
            }

        #If 0 is returned, then no process of passed pid exist
        if(stop_te_dp_helper(pid)):
            lgr.info("Stop Succeeded %d" %pid)
            return {
                'status'        : True,
                'statusmessage' : 'te_dp of PID=' + str(pid) + ' is stopped',
                'uniq-name'     : uniq_name,
                }
        else:
            lgr.info("Stop Failed %s" %str(pid))
            return {
                'status' : False,
                'statusmessage' : 'Unable to kill the process %s' %str(pid)
            }
    except:
        return_dict = {'status'         : False,
                        'statusmessage' : 'Exception: %s' %traceback.format_exc()}
        return return_dict



@tejob('te_broadcast_q')
def raw_update_te_dp(resource_config=None, session_config=None, resource_hash=None, session_hash=None, \
    client_mgmt_ip=None, traffic_mode=None, traffic_profile=None, stat_dump_interval=None, \
    metrics_enabled=False, memory_metrics_enabled=False, uniq_name=None, pid=None, cpu=None, log_level=None):

    try:
        lgr.info("Update Called")

        stop_return_dict = stop_te_dp(pid=pid, uniq_name=uniq_name)
        if(stop_return_dict['status'] == False):
            lgr.info("Update's Stop Failed")
            return stop_return_dict

        start_return_dict = start_te_dp(resource_config=resource_config, session_config=session_config, \
            resource_hash=resource_hash, session_hash=session_hash, \
            client_mgmt_ip=client_mgmt_ip, traffic_mode=traffic_mode, \
            traffic_profile=traffic_profile, stat_dump_interval=stat_dump_interval, \
            metrics_enabled=metrics_enabled, memory_metrics_enabled=memory_metrics_enabled, \
            uniq_name=uniq_name, cpu=cpu, log_level=log_level)

        if(start_return_dict['status'] == False):
            lgr.info("Update's Start Failed")
            return start_return_dict

        lgr.info("Update Suceeded")
        return start_return_dict

    except Exception as e:
        return {'status'         : False,
                'statusmessage' : 'Exception: %s' %traceback.format_exc()}
