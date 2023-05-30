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

from rq import Queue as rqQueue
from rq.results import Result as rqResult
import time
import traceback
from collections import defaultdict
from copy import copy

class TE_DP_CONFIG:

    ######################## BASIC FUNCTION CALLS ########################
    def __init__(self, host_ip, cpu_count, TEbrokerHandle, lgr, te_metrics_object):

        self.lgr = lgr

        try:
            cpuList                     = list(range(1,cpu_count))
            self.__STATES               = { 'CONNECT' : 0, 'START' : 1,  'STOP' : 2 }

            self.__IS_STATE_ALLOWED     = { "START"      : [self.__STATES['CONNECT'], self.__STATES['STOP']],
                                            "STOP"       : [self.__STATES['START']],
                                            "UPDATE"     : [self.__STATES['START'], self.__STATES['STOP']] }

            self.__resultEvaluator      = { "START"            : self.__result_evaluator_start_tedp,
                                            "STOP"             : self.__result_evaluator_stop_tedp,
                                            "UPDATE"           : self.__result_evaluator_update_tedp,
                                            "GET_ACTIVE_TEDP"  : self.__result_evaluator_get_active_tedp,
                                            "RESET_DNS"        : self.__result_evaluator_default,
                                            "CLEAN_TEDP"       : self.__result_evaluator_default,
                                            "UPDATE_DNS"       : self.__result_evaluator_default,
                                            "EXECUTE_CMD"      : self.__result_evaluator_default,
                                            "TECH_SUPPORT"     : self.__result_evaluator_tech_support}

            self.__host_ip              = host_ip
            self.__cpu                  = { 'count':cpu_count,
                                            'free_cpu_list':cpuList,
                                            'usedup_cpu_list':[],
                                            'mgmt_core':0 }
            self.__queues               = []
            self.__cpu_to_queue_mapping = {}
            self.__cpu_to_tedp_mapping  = {}
            self.__cpu_to_hash_mapping = {}
            self.__task_mapping         = defaultdict(dict)
            self.__te_metrics_object    = te_metrics_object

            for cpu in range(0,cpu_count):
                te_r_queue = self.__makeQueue(cpu,TEbrokerHandle)
                self.__queues.append(te_r_queue.name)
                self.__cpu_to_queue_mapping[cpu] = te_r_queue
                if cpu != self.__cpu['mgmt_core']:
                    self.__cpu_to_tedp_mapping[cpu]  = { 'state'  : self.__STATES['CONNECT'],
                                                         'instance_profile_tag' : None,
                                                         'resource_config_tag'  : None,
                                                         'session_config_tag'   : None,
                                                         'pid'                  : None }

            self.lgr.debug("TE_DP_CONFIG INIT Success! host_ip=%s" %self.__host_ip)

        except:
            self.lgr.error("Error in __init__ of TE_DP_CONFIG: %s" %traceback.format_exc())


    def get_cpu_count(self):
        return self.__cpu["count"]

    def __init_error_queue_list(self):
        self.__queue_task_info = {}
        self.__queue_task_info['VIPSTATS']={}
        self.__queue_task_info['SESSTATS']={}
        self.__queue_task_info['ERRORSTATS']={}
        self.__queue_task_info['URLSTATS']={}
        self.__queue_task_info['VIPBUCKET']={}

        for key in self.__queue_task_info:
            self.__queue_task_info[key]['FINISHED']=[]
            self.__queue_task_info[key]['QUEUED']=[]
            self.__queue_task_info[key]['FAILED']=[]
            self.__queue_task_info[key]['STARTED']=[]

        self.lgr.debug("error_queue_list INIT Success in host_ip=%s" %self.__host_ip)

    def __makeQueue(self, cpu, TEbrokerHandle):
        queue_name = str("TE%")+self.__host_ip+str("%")+str(cpu)+str("_QUEUE")
        self.lgr.debug("Making queue for the host=%s cpu=%d q_name=%s" %(self.__host_ip, cpu, queue_name))
        return rqQueue(queue_name, connection=TEbrokerHandle, default_timeout=180)

    def __del__(self):
        for cpu, te_r_queue in self.__cpu_to_queue_mapping.items():
            te_r_queue.empty()
        del self.__host_ip
        del self.__STATES
        del self.__cpu
        del self.__queues
        del self.__cpu_to_queue_mapping
        del self.__cpu_to_tedp_mapping
        del self.__task_mapping

    def getStates(self):
        return {'host_ip': self.__host_ip, 'cpu': self.__cpu, '__cpu_to_tedp_mapping' : self.__cpu_to_tedp_mapping}

    ########################### GET AND SET FUNCTION CALLS ########################
    def get_queue_names(self):
        return self.__queues

    def get_number_of_free_cpus(self):
        return len(self.__cpu['free_cpu_list'])

    def get_used_up_cpus(self):
        return self.__cpu['usedup_cpu_list']

    def get_rq_object_name(self, cpu):
        return self.__cpu_to_queue_mapping[cpu].name

    def get_instance_profile_tag(self, cpu):
        return self.__cpu_to_tedp_mapping[cpu]['instance_profile_tag']

    def get_pid_of_running_tedps(self):
        listOfPids = []
        for cpu, details in self.__cpu_to_tedp_mapping.items():
            pid = details.get('pid', None)
            if pid is not None and details.get('state', -1) == self.__STATES["START"]:
                listOfPids.append(pid)
        #A small Change in debug (Delete the comment later)
        self.lgr.debug("List of pid running tedps is %s in host_ip=%s" %(str(listOfPids), self.__host_ip) )
        return listOfPids

    def get_pid_of_running_profiles(self, profile_tags_list):
        listOfPids = []
        for cpu, details in self.__cpu_to_tedp_mapping.items():
            if details.get('instance_profile_tag',None) in profile_tags_list:
                pid = details.get('pid',None)
                if pid is not None and details.get('state', -1) == self.__STATES["START"]:
                    listOfPids.append(pid)
        self.lgr.debug("List of pid running tedps of profile=%s is %s in host=%s" %(profile_tags_list, str(listOfPids), self.__host_ip))
        return listOfPids

    def __get_cpu_running_pids(self, listOfPids):
        pid_to_cpu = {}
        for cpu, details in self.__cpu_to_tedp_mapping.items():
            pid = details.get('pid',None)
            if pid in listOfPids:
                pid_to_cpu[pid] = cpu
                listOfPids.remove(pid)
        if(not(bool(listOfPids))):
            self.lgr.debug("pid_to_cpu mapping is %s in host_ip=%s" %(str(pid_to_cpu), self.__host_ip))
            return pid_to_cpu
        else:
            self.lgr.error("Unable to get cpu associated with pids=%s" %(str(listOfPids)))
            return {}

    def __get_n_cpu_pid_map_running_profile(self, profile_tag, count):
        cpu_pid_map_running_profile = {}
        running_count = 0

        for cpu, details in self.__cpu_to_tedp_mapping.items():
            if details.get('instance_profile_tag',None) == profile_tag:
                pid = details.get('pid',None)
                if pid is not None and details.get('state',-1) == self.__STATES["START"]:
                    cpu_pid_map_running_profile[cpu] = pid
                    running_count += 1
            if running_count == count:
                return cpu_pid_map_running_profile

        return None

    ################################ IS POSSIBLE ###############################
    def is_spinning_new_tedps_possible(self, num_tedps_to_spawn):
        freeCPUs = self.get_number_of_free_cpus()
        if num_tedps_to_spawn > freeCPUs:
            return {'currently-available':freeCPUs, 'currently-needed':num_tedps_to_spawn}
        return None

    def is_update_possible(self, numberOfTEDPsToStop, numberOfTEDPsToSpawn):
        freeCPUs = self.get_number_of_free_cpus()
        if(freeCPUs + numberOfTEDPsToStop - numberOfTEDPsToSpawn < 0):
            return {"Free CPUs":freeCPUs, "TEDPs requested to stop":numberOfTEDPsToStop, \
            "TEDPs requested to spawn":numberOfTEDPsToSpawn}
        return None

    ############################################# START TE DP #############################################
    def assignCpuAndProfiles(self, instance_profile_tag, resource_config_tag, session_config_tag):
        try:
            #Assigning CPUS
            assignedCPU = self.__cpu['free_cpu_list'].pop(0)
            self.__cpu['usedup_cpu_list'].append(assignedCPU)

            #Assigning Profile-Tags
            self.__cpu_to_tedp_mapping[assignedCPU]['instance_profile_tag'] = instance_profile_tag
            self.__cpu_to_tedp_mapping[assignedCPU]['resource_config_tag'] = resource_config_tag
            self.__cpu_to_tedp_mapping[assignedCPU]['session_config_tag'] = session_config_tag

            self.lgr.debug("Assigning Cpus for %s: assignedCPU=%d \
            instance_profile_tag=%s resource_config_tag=%s session_config_tag=%s cpus=%s" \
            %(self.__host_ip, assignedCPU, instance_profile_tag, resource_config_tag, session_config_tag, str(self.__cpu)))
            return assignedCPU
        except:
            self.lgr.error("Error in assignCpuAndQueue for host_ip=%s of TE_DP_CONFIG: %s" %(self.__host_ip, traceback.format_exc()))
            return None

    ############################################# MGMT CALLS #############################################
    def run_mgmt_command_helper(self, run_mgmt_command_te_dp, args, job_timeout):
        try:
            self.lgr.debug("run_mgmt_command_helper for host_ip=%s Called!" %self.__host_ip)
            successDict = {"Success": 0, "Failure":[]}

            cpu = self.__cpu["mgmt_core"]

            #Make the call enqueue the start
            rq_obj_name = self.get_rq_object_name(cpu)
            paramPassed = {'cmd':args['cmd']}

            status, error = self.enqueueCall(cpu, args['task'], run_mgmt_command_te_dp, \
                paramPassed, job_timeout)
            return status

        except:
            self.lgr.error("Error in run_mgmt_command_helper %s" %traceback.format_exc())
            return False

    def __result_evaluator_get_active_tedp(self, result):
        if result is None:
            return False, "No result obtained"
        elif result.get('status',False):
            try:
                statusmessage = result.get("statusmessage", {})
                if(not(bool(statusmessage))):
                    self.lgr.error("TE_WORK return didn't posses statusmessage key")
                    return False, "TE_WORK return didn't posses statusmessage key"
                num_process_runnning = int(statusmessage.get('out', 0))
            except:
                self.lgr.warning("Unable to convert the out statement to int %s" \
                    %str(statusmessage.get('out', 0)))
                num_process_runnning = 0
            num_process_expected = len(self.__cpu["usedup_cpu_list"])
            if num_process_runnning == num_process_expected:
                return True, {"expected" : num_process_expected, "actual" : num_process_runnning}
            else:
                return False, {"expected" : num_process_expected, "actual" : num_process_runnning}
        else:
            return False, result.get("statusmessage", "No statusmessage in response")

    def __result_evaluator_default(self, result):
        if result is None:
            return False, "No result obtained"
        elif result.get('status',False):
            statusmessage = result.get("statusmessage", {})
            if(not(bool(statusmessage))):
                self.lgr.error("TE_WORK return didn't posses statusmessage key")
                return False, "TE_WORK return didn't posses statusmessage key"
            elif(bool(statusmessage['err'])):
                return False, {"Error" : statusmessage['err'], \
                                "Output": statusmessage['out']}
            else:
                return True, {"Task Completed": statusmessage['out']}
        else:
            return False, result.get("statusmessage", "No statusmessage in response")


    ############################################# TECH SUPPORT CALLS #############################################
    def tech_support_helper(self, tech_support, args):
        try:
            self.lgr.debug("tech_support_helper for host_ip=%s Called!" %self.__host_ip)
            successDict = {"Success": 0, "Failure":[]}
            cpu = self.__cpu["mgmt_core"]
            #Make the call enqueue the start
            rq_obj_name = self.get_rq_object_name(cpu)

            status, error = self.enqueueCall(cpu, "TECH_SUPPORT", tech_support, args)
            return status

        except:
            self.lgr.error("Error in tech_support_helper %s" %traceback.format_exc())
            return False

    def __result_evaluator_tech_support(self, result):
        if result is None:
            return False, "No result obtained"
        elif result.get('status',False):
            return True, {"SCPed logs" : True}
        else:
            return False, result.get('statusmessage', "Unable to scp")

    ############################################# START #############################################

    def start_te_dp_helper(self, start_te_dp, args):
        try:
            self.lgr.debug("start_te_dp_helper for host_ip=%s Called!" %self.__host_ip)
            successDict = {"Success": 0, "Failure":[]}

            for _ in range(args['count_of_tedps']):
                cpu = self.assignCpuAndProfiles(args['profile_tag'], args['res_tag'], args['ses_tag'])
                if cpu is None:
                    self.lgr.error("Unable to get the CPU to assign for the task %s" %traceback.format_exc())
                    successDict["Failure"].append("Unable to get the CPU to assign for the task %s" %traceback.format_exc())
                    continue

                #Make the call enqueue the start
                rq_obj_name = self.get_rq_object_name(cpu)
                paramPassed = {'resource_config':args['client_res_cfg'], \
                            'session_config': args['client_ses_cfg'], \
                            'resource_hash' : args['client_res_hash'], \
                            'session_hash' : args['client_ses_hash'], \
                            'traffic_mode' : args['traffic_mode'], \
                            'traffic_profile' : args['traffic_profile'], \
                            'client_mgmt_ip' : args['client_mgmt_ip'], \
                            'stat_dump_interval' : args['stat_dump_interval'], \
                            'metrics_enabled' : args['metrics_enabled'], \
                            'memory_metrics_enabled' : args['memory_metrics_enabled'], \
                            'uniq_name': rq_obj_name,'cpu':cpu, 'log_level':args['loglevel']}

                status, error = self.enqueueCall(cpu, "START", start_te_dp, paramPassed)
                if status:
                    successDict["Success"] += 1
                    self.__cpu_to_hash_mapping[cpu] = {
                        'res' : args['client_res_hash'],
                        'ses' : args['client_ses_hash'],
                        'traffic_mode' : args['traffic_mode'],
                        'traffic_profile' : args['traffic_profile']
                    }
                else:
                    successDict["Failure"].append(error)

            self.lgr.debug("start_te_dp_helper for %s's result %s" %(self.__host_ip, str(successDict)) )
            return successDict

        except:
            self.lgr.error("Error in start_te_dp_helper %s" %traceback.format_exc())
            return"Error in start_te_dp_helper %s" %traceback.format_exc()

    def __result_evaluator_start_tedp(self, result, cpu):
        if result is None:
            profileToReturn = self.__modify_state_on_start_failure(cpu)
            return False, profileToReturn
        elif result.get('status',False):
            profileToReturn = self.__modify_state_on_start_success(cpu, result['pid'])
            return True, profileToReturn
        else:
            profileToReturn = self.__modify_state_on_start_failure(cpu)
            return False, profileToReturn

    #modification happens on both failure and success
    def __modify_state_on_start_failure(self, cpu):
        self.lgr.debug("__modify_state_on_start_failure cpu=%d host=%s cpu_dict=%s" %(cpu,self.__host_ip,str(self.__cpu)))
        self.__cpu['usedup_cpu_list'].remove(cpu)
        self.__cpu['free_cpu_list'].append(cpu)
        profileTagToReturn = self.get_instance_profile_tag(cpu)
        self.__cpu_to_tedp_mapping[cpu]['instance_profile_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['resource_config_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['session_config_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['pid'] = None
        self.__cpu_to_tedp_mapping[cpu]['state'] = self.__STATES["CONNECT"]
        self.__cpu_to_hash_mapping.pop(cpu)
        return profileTagToReturn

    def __modify_state_on_start_success(self, cpu, pid):
        self.__cpu_to_tedp_mapping[cpu]['pid'] = pid
        self.__cpu_to_tedp_mapping[cpu]['state'] = self.__STATES["START"]
        config_hash = self.__cpu_to_hash_mapping[cpu]
        self.__te_metrics_object.insert_running_configs(self.__host_ip, cpu,
            config_hash['res'], config_hash['ses'], config_hash['traffic_mode'],
            config_hash['traffic_profile'])
        return self.get_instance_profile_tag(cpu)

    ############################################# STOP #############################################

    def stop_te_dp_helper(self, stop_te_dp, args):
        try:
            self.lgr.debug("stop_te_dp_helper for host_ip=%s Called!" %self.__host_ip)
            successDict = {"Success": 0, "Failure":[]}
            pid_to_cpu = self.__get_cpu_running_pids(args['listOfPid'])
            for pid, cpu in pid_to_cpu.items():
                rq_obj_name = self.get_rq_object_name(cpu)
                paramPassed = {'pid':pid, 'uniq_name':rq_obj_name}
                success, error = self.enqueueCall(cpu, "STOP", stop_te_dp, paramPassed)
                if success:
                    successDict["Success"] += 1
                else:
                    successDict["Failure"].append(error)
            return successDict
        except:
            self.lgr.error("Error in stop_te_dp_helper %s" %traceback.format_exc())
            return "Error in stop_te_dp_helper %s" %traceback.format_exc()

    def __result_evaluator_stop_tedp(self, result, cpu):
        if result is None:
            profileToReturn = self.get_instance_profile_tag(cpu)
            return False, profileToReturn
        elif result.get('status',False):
            profileToReturn = self.__modify_state_on_stop_success(cpu)
            return True, profileToReturn
        else:
            profileToReturn = self.get_instance_profile_tag(cpu)
            return False, profileToReturn

    def __modify_state_on_stop_success(self, cpu):
        self.lgr.debug("__modify_state_on_stop_success cpu=%d host=%s" %(cpu, self.__host_ip) )
        self.__cpu['usedup_cpu_list'].remove(cpu)
        self.__cpu['free_cpu_list'].append(cpu)
        profile_tag_to_return = self.__cpu_to_tedp_mapping[cpu]['instance_profile_tag']
        self.__cpu_to_tedp_mapping[cpu]['state'] = self.__STATES["STOP"]
        self.__cpu_to_tedp_mapping[cpu]['pid'] = None
        self.__cpu_to_tedp_mapping[cpu]['instance_profile_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['resource_config_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['session_config_tag'] = None
        self.__te_metrics_object.update_stop_time_running_configs(self.__host_ip, cpu)
        self.__cpu_to_hash_mapping.pop(cpu)
        return profile_tag_to_return

    ############################################# UPDATE #############################################

    def update_te_dp_helper(self, raw_update_te_dp, args):
        try:
            self.lgr.debug("update_te_dp_helper for host_ip=%s Called!" %self.__host_ip)
            successDict = {"Success": 0, "Failure":[]}

            cpu_pid_map_to_update = self.__get_n_cpu_pid_map_running_profile(args['profile_tag'], \
                args['count_of_tedps'])

            #If should never run (As update_api must have done a check)
            if cpu_pid_map_to_update is None:
                return "Unable to get %d processes running tag=%s" %(args['count_of_tedps'], args['profile_tag'])
                self.lgr.error("Unable to get %d processes running tag=%s" %(args['count_of_tedps'], args['profile_tag']))

            for cpu, pid in cpu_pid_map_to_update.items():
                if cpu is None:
                    self.lgr.error("Unable to get the CPU to assign for the task %s" %traceback.format_exc())
                    successDict["Failure"].append("Unable to get the CPU to assign for the task %s" %traceback.format_exc())
                    continue

                #Make the call enqueue
                rq_obj_name = self.get_rq_object_name(cpu)
                paramPassed = {'resource_config':args['client_res_cfg'], \
                                'session_config': args['client_ses_cfg'], \
                                'resource_hash' : args['client_res_hash'], \
                                'session_hash' : args['client_ses_hash'], \
                                'traffic_mode' : args['traffic_mode'], \
                                'traffic_profile' : args['traffic_profile'], \
                                'client_mgmt_ip' : args['client_mgmt_ip'], \
                                'stat_dump_interval' : args['stat_dump_interval'], \
                                'metrics_enabled' : args['metrics_enabled'], \
                                'memory_metrics_enabled' : args['memory_metrics_enabled'], \
                                'uniq_name': rq_obj_name, 'pid':pid, 'cpu':cpu, \
                                'log_level':args['loglevel']}
                status, error = self.enqueueCall(cpu, "UPDATE", raw_update_te_dp, paramPassed)
                if status:
                    successDict["Success"] += 1
                    self.__cpu_to_hash_mapping[cpu] = {
                        'res' : args['client_res_hash'],
                        'ses' : args['client_ses_hash'],
                        'traffic_mode' : args['traffic_mode'],
                        'traffic_profile' : args['traffic_profile']
                    }
                else:
                    successDict["Failure"].append(error)
            self.lgr.debug("update_te_dp_helper for %s's result %s" %(self.__host_ip, str(successDict)) )
            return successDict

        except:
            self.lgr.error("Error in update_te_dp_helper %s" %traceback.format_exc())
            return "Error in update_te_dp_helper %s" %traceback.format_exc()

    def __result_evaluator_update_tedp(self, result, cpu):
        if result is None:
            profileToReturn = self.__modify_state_on_update_failure(cpu)
            return False, profileToReturn
        elif result.get('status', False):
            profileToReturn = self.__modify_state_on_update_success(cpu, result['pid'])
            return True, profileToReturn
        else:
            profileToReturn = self.__modify_state_on_update_failure(cpu)
            return False, profileToReturn

    def __modify_state_on_update_success(self, cpu, pid):
        self.lgr.debug("__modify_state_on_update_success cpu=%d host=%s" %(cpu, self.__host_ip) )
        self.__cpu_to_tedp_mapping[cpu]['state'] = self.__STATES["START"]
        self.__cpu_to_tedp_mapping[cpu]['pid'] = pid
        config_hash = self.__cpu_to_hash_mapping[cpu]
        self.__te_metrics_object.update_running_configs(self.__host_ip, cpu,
            config_hash['res'], config_hash['ses'], config_hash['traffic_mode'],
            config_hash['traffic_profile'])
        return self.get_instance_profile_tag(cpu)

    def __modify_state_on_update_failure(self, cpu):
        self.lgr.debug("__modify_state_on_update_failure cpu=%d host=%s cpu_dict=%s" %(cpu,self.__host_ip,str(self.__cpu)))
        #Ambiguous Situation
        self.__cpu['usedup_cpu_list'].remove(cpu)
        self.__cpu['free_cpu_list'].append(cpu)
        profileTagToReturn = self.get_instance_profile_tag(cpu)
        self.__cpu_to_tedp_mapping[cpu]['instance_profile_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['resource_config_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['session_config_tag'] = None
        self.__cpu_to_tedp_mapping[cpu]['pid'] = None
        self.__cpu_to_tedp_mapping[cpu]['state'] = self.__STATES["CONNECT"]
        self.__cpu_to_hash_mapping.pop(cpu)
        return profileTagToReturn

    ############# DUMMY ##############
    """def __result_evaluator_dummy(self):
        return "No_Profile"""

    ##################### ENQUEUE CALL AND VERIFY STATUS #####################
    def enqueueCall(self, assignedCPU, typeOfTask, callToMake, args, job_timeout=None):
        try:
            rq_obj = self.__cpu_to_queue_mapping[assignedCPU]
            if job_timeout is not None:
                task_obj = rq_obj.enqueue_call(callToMake, kwargs=args, timeout=job_timeout)
            else:
                task_obj = rq_obj.enqueue_call(callToMake, kwargs=args)
            self.__task_mapping[typeOfTask][assignedCPU] = task_obj
            self.lgr.debug("Enqueued %s to %s in host_ip=%s and cpu=%d" %(str(callToMake), \
                str(rq_obj), self.__host_ip, assignedCPU))
            return True, None
        except:
            #LOCK NEEDED (Unlock)
            reason = "Error in enqueueCall for host_ip=%s of TE_DP_CONFIG: %s" \
                %(self.__host_ip, traceback.format_exc())
            self.lgr.error(reason)
            return False, reason

    def clean_task_details(self, type_of_task):
        try:
            self.__task_mapping[type_of_task] = {}
        except:
            self.lgr.error(traceback.format_exc())


    def __clean_task_result(self, taskResult):
        #Promotes better return values to the end user
        list_of_keys = copy(list(taskResult.keys()))
        for key in list_of_keys:
            if(not(bool(taskResult[key]))):
                taskResult.pop(key)

        #if status had been true, the above for, would have popped it
        if taskResult.get('status', False):
            return taskResult["Success"]

        #Else add a False, that way the TE.py can figure out failure
        taskResult["status"] = False
        return taskResult

    def get_mgmt_task_status_and_result(self, typeOfTask, resultDict, lock, max_tolerable_delay):
        '''
        Iterate through all the mgmt_cpu Rq-object into which the mgmt_task is enqueued to
        and returns a dict as result
        If status is either finished or failed => pop the object from the dict
        '''

        taskResult = {"RQ-Failure": 0, "Success":{}, "Failure": {}, "Incomplete": 0, "status" : True}

        try:
            time_to_sleep_bw_retires = 1
            maxRetries = max_tolerable_delay//time_to_sleep_bw_retires

            for i in range(maxRetries+1):
                self.lgr.debug("get_mgmt_task_status_and_result Retry=%d/%d in host_ip=%s" %(i+1, maxRetries, self.__host_ip))
                cpu = self.__cpu["mgmt_core"]
                task_obj = self.__task_mapping[typeOfTask][cpu]
                #Task Completed
                status = task_obj.get_status()
                if status == "finished":
                    result = task_obj.latest_result()
                    if result.type == rqResult.Type.SUCCESSFUL: #for SUCCESSFUL:
                        status, result_after_evaluation = self.__resultEvaluator[typeOfTask](result.return_value)
                        self.lgr.debug("get_mgmt_task_status_and_result in host_ip {}, result {}".format(self.__host_ip, result.return_value))
                        if status: #Task Success
                            taskResult["Success"] = result_after_evaluation
                            self.lgr.debug("Success in host_ip=%s is %s" %(self.__host_ip, \
                                str(result_after_evaluation)))
                        else: #Task Failed
                            taskResult["Failure"] = result_after_evaluation
                            taskResult["status"] = False
                            self.lgr.debug("Failure in host_ip={} is {}, return value {}".format(self.__host_ip, \
                                result_after_evaluation, result.return_value))
                    elif result == rqResult.Type.FAILED: #for FAILED
                        taskResult["RQ-Failure"] += 1
                        taskResult["status"] = False
                        self.lgr.debug("RQ-result-Failure in host_ip={} and result={}".format(
                            self.__host_ip, result.exc_string))
                    self.__task_mapping[typeOfTask].pop(cpu)

                #Task Failed due to RQ Error
                elif status == "failed":
                    taskResult["RQ-Failure"] += 1
                    taskResult["status"] = False
                    self.lgr.debug("RQ-Failure in host_ip={} and result={}".format(
                        self.__host_ip, task_obj.exc_info()))
                    self.__task_mapping[typeOfTask].pop(cpu)

                #If the tasks has been completed in all CPUs
                if(not(bool(self.__task_mapping[typeOfTask].keys()))):
                    self.lgr.debug("All cpus have completed the task in %s" %self.__host_ip)
                    taskResult = self.__clean_task_result(taskResult)
                    lock.acquire()
                    resultDict[self.__host_ip] = taskResult
                    lock.release()
                    return

                if i == maxRetries:
                    taskResult["Incomplete"]+=1
                    taskResult["status"] = False
                    self.lgr.warning("Task %s was incomplete in cpu=%d and host_ip=%s" %(typeOfTask, cpu, self.__host_ip))
                    self.__task_mapping[typeOfTask].pop(cpu)

                #Wait for max_tolerable_delay/maxRetries time before giving next retry
                else:
                    time.sleep(time_to_sleep_bw_retires)

            taskResult = self.__clean_task_result(taskResult)
            lock.acquire()
            resultDict[self.__host_ip] = taskResult
            lock.release()
            return
        except:
            self.lgr.error("Error in get_mgmt_task_status_and_result %s" %traceback.format_exc())
            lock.acquire()
            resultDict[self.__host_ip] = "Error in get_mgmt_task_status_and_result %s" %traceback.format_exc()
            lock.release()
            return



    def get_task_status_and_result(self, typeOfTask, resultDict, lock, max_tolerable_delay):
        '''
        Iterate through all the cpus into which the task is enqueued to
        and returns a dict as result
        If status is either finished or failed => pop the object from the dict
        '''

        taskResult = {"RQ-Failure": defaultdict(int), "Success":defaultdict(int),\
                    "Failure":defaultdict(list), "Incomplete":defaultdict(int),
                    "status" : True}
        try:
            time_to_sleep_bw_retires = 1
            maxRetries = max_tolerable_delay//time_to_sleep_bw_retires

            for i in range(maxRetries+1):
                self.lgr.debug("get_task_status_and_result Retry=%d/%d in host_ip=%s" %(i+1, maxRetries, self.__host_ip))

                #Iterate through the cpu-task mapping
                list_of_cpus = copy(list(self.__task_mapping[typeOfTask].keys()))
                for cpu in list_of_cpus:
                    task_obj = self.__task_mapping[typeOfTask][cpu]

                    #Task Completed
                    status = task_obj.get_status()
                    if status == "finished":
                        result = task_obj.latest_result()
                        if result.type == rqResult.Type.SUCCESSFUL: #for SUCCESSFUL
                            self.lgr.debug("get_task_status_and_result: host_ip {}, status {} result {}".format(self.__host_ip, status, result.return_value))
                            status, task_profile_tag = self.__resultEvaluator[typeOfTask](result.return_value, cpu)
                            if status: #Task Success
                                taskResult["Success"][task_profile_tag] += 1
                                self.lgr.debug("Success for task_profile_tag=%s in host_ip=%s" %(task_profile_tag, self.__host_ip))
                            else: #Task Failed
                                taskResult["Failure"][task_profile_tag].append(result)
                                taskResult["status"] = False
                                self.lgr.debug("Failure for task_profile_tag={} in host_ip={} and result={}".format(task_profile_tag, self.__host_ip, result.return_value))
                        elif result.type == rqResult.Type.FAILED: #for FAILED
                            status, task_profile_tag = self.__resultEvaluator[typeOfTask](None, cpu)
                            taskResult["RQ-Failure"][task_profile_tag] += 1
                            taskResult["status"] = False
                            self.lgr.debug("RQ-result-Failure in host_ip={} task_profile_tag={} result={}".format(
                                self.__host_ip, task_profile_tag, result.exc_string))
                        self.__task_mapping[typeOfTask].pop(cpu)

                    #Task Failed due to RQ Error
                    elif status == "failed":
                        status, task_profile_tag = self.__resultEvaluator[typeOfTask](None, cpu)
                        taskResult["RQ-Failure"][task_profile_tag] += 1
                        taskResult["status"] = False
                        self.lgr.debug("RQ-Failure in host_ip={} task_profile_tag={} and result={}".format(
                            self.__host_ip, task_profile_tag, task_obj.exc_info()))

                    #If the tasks has been completed in all CPUs
                    if(not(bool(self.__task_mapping[typeOfTask].keys()))):
                        task_profile_tag = self.get_instance_profile_tag(cpu)
                        self.lgr.debug("All cpus have completed the task in %s" %self.__host_ip)
                        taskResult = self.__clean_task_result(taskResult)
                        lock.acquire()
                        resultDict[self.__host_ip] = taskResult
                        lock.release()
                        return

                    if i == maxRetries:
                        status, task_profile_tag = self.__resultEvaluator[typeOfTask](None, cpu)
                        taskResult["Incomplete"][task_profile_tag]+=1
                        taskResult["status"] = False
                        self.lgr.warning("Task %s was incomplete in cpu=%d and host_ip=%s" %(typeOfTask,cpu, self.__host_ip))
                        self.__task_mapping[typeOfTask].pop(cpu)

                #Wait for max_tolerable_delay/maxRetries time before giving next retry
                if i != maxRetries:
                    time.sleep(time_to_sleep_bw_retires)

            taskResult = self.__clean_task_result(taskResult)
            lock.acquire()
            resultDict[self.__host_ip] = taskResult
            lock.release()
            return
        except:
            self.lgr.error("Error in get_task_status_and_result %s" %traceback.format_exc())
            lock.acquire()
            resultDict[self.__host_ip] = "Error in get_task_status_and_result %s" %traceback.format_exc()
            lock.release()
            return
