################################# MY IMPORTS ################################
from TE_UTILS import *
from TE_WORK import *
from TE_CLASS import *
from TE_DP_CONFIG import *
from TE_METRICS import *
from te_json_schema import *

# Import for the DB related stuff
# from models import * (GET BACK TO THIS)


################################# IMPORTS ####################################
try:
    from copy import deepcopy, copy
    import inspect
    import argparse,json
    from threading import Thread, Lock
    import traceback
    import paramiko
    from flask_swagger_ui import get_swaggerui_blueprint

    # Import for all the Flask library
    from flask import Flask, jsonify, request
    from flask import make_response,url_for
    from flask_restful import Api, Resource, reqparse, fields, marshal
    from flask_inputs.validators import JsonSchema
    from pssh.clients import ParallelSSHClient
    from pssh.exceptions import ConnectionErrorException, SSHException, AuthenticationException, UnknownHostException
    from rq import Queue as rqQueue
    from redis import Redis
    from gevent import joinall
    import time, os, re
    from collections import defaultdict, OrderedDict
    from datetime import datetime
    import subprocess
    import random

except Exception as e:
    print("ERROR in importing: " + str(e))
    print("TRACE: %s" %(traceback.format_exc()))
    exit(1)

################################# TE REST ENDPOINT ####################################
class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

TE_API = {
    'setup_tedp' : 'Brings up TE data path containers',
    'connect' : 'Connects TE Controller with datapath containers over redis',
    'start' : 'Starts traffic on the data path containers based on the input knobs',
    'stop' : 'Stops the traffic',
    'get_states' : 'To get the current variable states (Developer Debugging)',
    'update_config'  : 'Updates the system to a new running Config',
    'clean' : 'Clears the connection b/w Controller and datapath, clears metrics collected and removes datapath container(if specified)',
    'get_active_tedp' : 'Provides with dictionary mapping from host to number of active tedp processes',
    'get_cpu_count' : 'Provides with host vs cpu mapping',
    'alter_stat_dump_interval' : 'Alters the stat dump interval in TE_DP',
    'alter_stat_collect_interval' : 'Alters the stat collect interval in TE_DP',
    'alter_metrics_collection' : 'Alters if Error, Session and VIP Metrics are to be collected ot not',
    'alter_memory_metrics_collection' : 'Enable Memory Metrics (Developer Debugging)',
    'get_vip_metrics' : 'Provides the VIP metrics',
    'get_ses_metrics' : 'Provides with overall session metrics',
    'get_error_metrics' : 'Provides with ERROR metrics',
    'get_memory_metrics' : 'Provides with MEMORY metrics of allocs and deallocs (Developer Debugging)',
    'get_client_history' : 'Provides with historical details on run',
    'get_current_te_time' : 'Provides with current time of TE',
    'get_configs' : 'Provides with resource and session configs given the hash',
    'update_dns'  : 'Appends/overwrite DNS entry within TE_DP docker',
    'reset_dns'  : 'Reset DNS entry within TE_DP docker',
    'execute_cmd': 'Executes the command given across te_dp machines (Must not block, use &)',
    'tech_support' : 'Provides with tech support details for debugging',
    'grafana' : 'To visualize, monitor and analyse metrics values',
}

TE_SUB_API = {
    'stop' : ['by_profile_tag', 'by_tedp_dict']
}

def abort_if_not_found(api, sub_api=None):
    if api in TE_API:
        return flask_obj.modules[api+'_api']
    if sub_api and sub_api in TE_SUB_API.get(api, []):
        return flask_obj.modules[api+'_api']
    return None

def make_request_data(req_json, req_arg):
    if req_json and req_arg:
        return req_json.update(req_arg)
    if req_json:
        return req_json
    if req_arg:
        return req_arg
    return {}

class TE_REST_ENDPOINT(Resource):
    def __init__(self):
        global flask_obj

    def post(self, te_api_name):
        functionToCall = abort_if_not_found(te_api_name)
        if functionToCall is None:
            return make_response(jsonify({'error': "{} Not found in API List : {}".format(
                te_api_name, TE_API.keys())}), 404)
        data = make_request_data(request.json, request.args.to_dict())
        result = functionToCall(flask_obj, data)
        return result

class TE_REST_ENDPOINT_SUB_API(Resource):
    def __init__(self):
        global flask_obj

    def post(self, te_api_name, te_sub_api_name):
        lgr.info("Got api call to api={} sub_api={}".format(te_api_name, te_sub_api_name))
        functionToCall = abort_if_not_found(te_api_name, te_sub_api_name)
        if functionToCall is None:
            return make_response(jsonify({'error': "{}/{} Not found in API List : {}".format(
                te_api_name, te_sub_api_name, TE_API.keys())}), 404)
        data = make_request_data(request.json, request.args.to_dict())
        result = functionToCall(flask_obj, data)
        return result

################################# ALL THE END POINTS TO FLASK APPLICATION ####################################

class FlaskApplicationWrapper:
    __metaclass__ = Singleton
    modules = locals()

    ################################# BASIC FUNCTIONS ####################################

    def __init__(self, te_daemon_ip, flask_port, redis_port, nginx_port, \
        postgres_port, zmq_port, stat_collect_interval, stat_dump_interval, logpath,
        loglevel):

        #LOGGER
        log_file = os.path.join(logpath, 'te.log')
        self.lgr = Logger('[  TE  ]', log_file, loglevel).getLogger()
        self.lgr.info("Starting the TE.py Process")

        try:
            #TE CLASS OBJECT
            self.__te_controller_obj = TE(te_daemon_ip, flask_port, redis_port, nginx_port, \
                postgres_port, zmq_port, loglevel)

            #ALL STATES OF TE-FSM
            self.__TE_STATE = { 'INIT' : 0,  'RUNNING' : 1 }

            #To avoid 2 overlapping calls to the same function call
            self.__IS_RUNNING = defaultdict(bool)

            self.__IS_STATE_ALLOWED = {
                "START"      : [self.__TE_STATE['INIT']],
                "STOP"       : [self.__TE_STATE['RUNNING']],
                "UPDATE"     : [self.__TE_STATE['RUNNING']]
            }

            #Any call that flows to tedp using core 0 must have an entry here
            self.__MGMT_CALLS = ["GET_ACTIVE_TEDP", "UPDATE_DNS", "RESET_DNS", "EXECUTE_CMD", "TECH_SUPPORT"]

            #PERMITTED STATES OF TE-FSM
            self.__CURRENT_STATE = self.__TE_STATE['INIT']

            #To validate the parameters passed
            self.__SCHEMA = {'te_dp_dict' : te_dp_dict_json_schema}

            #To clean all the pre-existing redis handles
            self.TE_BROKER_HANDLE = Redis(te_daemon_ip,int(redis_port))
            self.TE_BROKER_HANDLE.flushall()

            #Task Details
            self.__TASK_DETAILS = defaultdict(list)

            self.__setup_completed_tedps = set()
            self.__connect_completed_tedps = set()
            self.__all_te_dp_dict_credentials = {}
            self.__tedp_config = {}

            #PostgresDB is started always
            postgres_port = self.__te_controller_obj.get_postgres_port()
            zmq_port = self.__te_controller_obj.get_zmq_port()
            self.__te_postgres_object = TE_POSTGRES(postgres_port, logpath, loglevel, \
                                            stat_collect_interval)
            self.__te_zmq_object = TE_ZMQ(te_daemon_ip, self.__te_postgres_object, zmq_port, \
                            logpath, loglevel, stat_collect_interval)

            #Stat collection is started by default and can be switched alternatively
            self.__stat_collect_interval = stat_collect_interval
            self.__stat_dump_interval = stat_dump_interval
            if(stat_dump_interval != 0):
                self.__metrics_enabled = True
            self.__memory_metrics_enabled = False

            self.lgr.info("FlaskApplicationWrapper init Success")
        except:
            self.lgr.error("UNABLE TO INIT FlaskApplicationWrapper %s" %traceback.format_exc())

    def __not_found(self, err_message):
        return make_response(jsonify({'status': False, 'Error': err_message}),404)

    def __exception_occured(self, function, err_message):
        try:
            return jsonify({'status': False, 'function':function, 'exception': err_message})
        except:
            self.lgr.error("__Unable to return __exception_occured %s" %traceback.format_exc())
            return jsonify({'status':False, 'unable to return':traceback.format_exc()})

    def __success(self, result):
        try:
            return jsonify({'status': True, 'statusmessage': result})
        except:
            self.lgr.warning("Return without convert() failed in __success")
            try:
                return jsonify({'status': True, 'statusmessage': convert(result)})
            except:
                self.lgr.error("__Unable to return __success %s" %traceback.format_exc())
                return jsonify({'status':False, 'unable to return':traceback.format_exc()})

    def __failure(self, result):
        try:
            self.lgr.error("Failure. result={}, type(result)={}".format(result, type(result)))
            return jsonify({'status': False, 'statusmessage': result})
        except:
            self.lgr.warning("Return without convert() failed in __failure")
            try:
                return jsonify({'status': False, 'statusmessage': convert(result)})
            except:
                self.lgr.error("__Unable to return __failure %s" %traceback.format_exc())
                return jsonify({'status':False, 'unable to return':traceback.format_exc()})

    def __api_state_decorator(typeOfTask):
        def decorator_method(func):
            def caller_func(self, json_content):
                try:
                    #VALIDATING STATE MACHINE
                    validState = self.__isStateValid(typeOfTask)
                    if validState is not None:
                        return validState

                    #CHECKING IF THERE IS NO DOUBLE RUN
                    if(self.__IS_RUNNING[typeOfTask]):
                        self.__IS_RUNNING[typeOfTask] = False
                        return self.__failure('Previous call of %s not exited' %typeOfTask)
                    self.__IS_RUNNING[typeOfTask] = True

                    #MAKING THE ACTUAL API CALL
                    try:
                        self.lgr.debug("Making the call to %s api" %typeOfTask)
                        result_of_api_call = func(self, json_content)
                    #CATCHING EXCEPTION IF ANY AND THROWING BACK TO FRONTEND
                    except:
                        self.lgr.error("ERROR IN %s: %s" %(typeOfTask, traceback.format_exc()))
                        result_of_api_call = self.__exception_occured(str(func).split(' ')[1], traceback.format_exc())

                    #CLEANING UPON API COMPLETION
                    self.__IS_RUNNING[typeOfTask] = False
                    return result_of_api_call
                except:
                    return self.__exception_occured(str(func).split(' ')[1], traceback.format_exc())
            return caller_func
        return decorator_method


    def __isStateValid(self, typeOfTask):
        allowedStates = self.__IS_STATE_ALLOWED.get(typeOfTask, None)
        if allowedStates is None:
            return None

        if self.__CURRENT_STATE not in allowedStates:

            #INVERTING (k,v) FOR THE PURPOSE OF BETTER ERROR UNDERSTANDING
            currStateInText = None
            allowedStatesInText = []
            for k, v in self.__TE_STATE.items():
                if v == self.__CURRENT_STATE:
                    currStateInText = k
                if v in allowedStates:
                    allowedStatesInText.append(k)

            #MAKING AN ENTRY IN LOG AND RETURNING
            self.lgr.error('STATE MACHINE ERROR Current State:%s and ALLOWED STATE to make the call are %s' %(str(currStateInText),
                                    str(allowedStatesInText)))
            return self.__not_found('STATE MACHINE ERROR Current State:%s and ALLOWED STATE to make the call are %s' %(str(currStateInText),
                                    str(allowedStatesInText)))

        return None

    #Does the request validation, by looking at the current state, allowed calls to make from the current state
    #requiredKeys Param check if the jsonContent has all the required params passed to it
    def __checkForRequiredArgument(self, jsonContent, requiredKeys=[]):
        '''
            Args:
                jsonContent: All the passed argument with which the REST API Call was made
                requiredKeys: List of required params that must be present in jsonContent
            Returns:
                None if no error
                Else return the error
        '''
        for key in requiredKeys:
            if key not in jsonContent or jsonContent[key]==None:
                self.lgr.error("Required parameter: %s NOT FOUND" %key)
                return self.__not_found('%s is not found' %key)
        return None

    def __validate_schema(self, jsonContent, keyToValidate):
        try:
            inputToValidate = convert(jsonContent[keyToValidate])
            valid_status = validate(inputToValidate, self.__SCHEMA[keyToValidate])
            return (True, inputToValidate)
        except Exception as e:
            return (False, str(e))

    def __are_all_tedps_connected(self, te_dp_dict):
        set_of_host_ips = set(te_dp_dict.keys())
        if(not(set_of_host_ips.issubset(self.__connect_completed_tedps))):
            return False, list(set_of_host_ips - self.__connect_completed_tedps)
        return True, []

    #It is a wrapper around PSSH Client which validates for for exit_codes and exception and populates the problematicHost (dict)
    #It retries to a default of 10 times if an SSHException is faced
    #It also return a stdout dict if getStdOut is set to True
    def __run_command_and_validate_output(self, client, te_dp_hosts, cmd=None, host_args={},
        cleanExitCode=0, possibleExitCodesDict={}, max_retries=10, getStdOut=False,
        validate_exit_codes=True):

        '''
        Args:
            client: The PSSH client object
            te_dp_hosts: A dict of tedp_host which has the mapping from host to user and password (It is used to make a new client if there is an exception raised) cmd=Same Command that has to be executed on all the clients
            host_args=Dictionary of command if each client take something different. (Ex: CONNECTOR.py need different rqueue that will be passed to it). This was initially a list in your implementation, now has been changed to dict, so that retries on the particular client alone will be possible.
            max_retries=Defaults to 10
            xxxxxxxxx NOTE: cmd and host_args must not be passed in the same call xxxxxxxxx

        Return:
            stdOut(if getStdOut is True), problematicHost
        '''

        def __run_command(client, cmd=None, host_args={}):
            '''
            Args:
                cmd: Command to run on all hosts
                host_args: Dictionary of args that is to be run on all machines which has a mapping from host_ip to command
            '''
            if ((cmd is None and host_args == {}) or (cmd is not None and host_args != {})):
                return None
            if host_args == {}:
                self.lgr.debug("Running Command=%s" %cmd)
                output = client.run_command(cmd, stop_on_errors=False)
            if cmd == None:
                host_args_values = list(host_args.values())
                self.lgr.debug("Running Similar Command=%s and length=%d" %(host_args_values[0], \
                    len(host_args_values)))
                output = client.run_command("%s", host_args=host_args_values, stop_on_errors=False)

            client.join(output)
            return output


        def __validateOutput(output):
            '''
                Args:
                    output: Output to evaluate
                    Uses getStdOut Flag to populate stdOut dictionary that is returned to the user
                Returns:
                    stdOut
                    exceptionHostTohandle
                    problematicHost
            '''
            stdOut = {}
            problematicHost = {}
            exceptionHostTohandle = []
            for host, runDetails in output.items():
                exitCodeHost = runDetails.exit_code
                exceptionHost = runDetails.exception
                if(isinstance(exceptionHost, SSHException)):
                    self.lgr.debug("Got Exception %s in host %s" %(str(runDetails.exception), host))
                    exceptionHostTohandle.append(host)
                elif(isinstance(exceptionHost, ConnectionErrorException)):
                    problematicHost[host] = "Connection refused/timed out"
                elif(isinstance(exceptionHost, AuthenticationException)):
                    problematicHost[host] = "Authentication error (user/password/ssh key error)"
                elif(isinstance(exceptionHost, UnknownHostException)):
                    problematicHost[host] = "Host is unknown (dns failure)"
                elif(exitCodeHost is not None and validate_exit_codes and exitCodeHost != cleanExitCode):
                    problematicHost[host] = possibleExitCodesDict.get(exitCodeHost, "Exit Code: %d" %exitCodeHost)

                #If stdout is needed
                if getStdOut:
                    gotOut = runDetails.stdout
                    if gotOut is None:
                        self.lgr.error("Unable to get response from the client host_ip="%host)
                        if host not in problematicHost:
                            problematicHost[host] = gotOut
                    else:
                        stdOut[host] = gotOut
            return stdOut, exceptionHostTohandle, problematicHost

        #Run the command for the first time
        output = {}
        output = __run_command(client, cmd=cmd, host_args=host_args)
        out, exceptionHostTohandle, problematicHost = __validateOutput(output)
        output.update(out)
        if exceptionHostTohandle == []:
            return ((output, problematicHost) if getStdOut else problematicHost)

        #Retries for possible failures till max_retries
        for i in range(max_retries-1):
            retryExceptionPresent = False
            retryHostConfig = OrderedDict()
            retryHostArgs = OrderedDict()

            if exceptionHostTohandle != []:
                self.lgr.info("Retrying=%d/%d due to exception of Busy Client in host=%s" %(i+2,max_retries,str(exceptionHostTohandle)))

            #Iterate through all exception hosts
            for host in exceptionHostTohandle:
                retryExceptionPresent = True
                retryHostConfig[host] = te_dp_hosts[host]
                if host in host_args.keys():
                    retryHostArgs[host] = host_args[host]

            #Exit if no such unexpected exception is seen
            if not(retryExceptionPresent):
                return ((output, problematicHost) if getStdOut else problematicHost)

            #Create New retry client and repeat the process
            retryClient = ParallelSSHClient(retryHostConfig.keys(), host_config=retryHostConfig, timeout = 240)
            output = __run_command(retryClient, cmd=cmd, host_args=retryHostArgs)
            out, exceptionHostTohandle, retryProblematicHost = __validateOutput(output)
            output.update(out)
            problematicHost.update(retryProblematicHost)
            del retryClient

        if exceptionHostTohandle != []:
            self.lgr.error("Unabe to resolve for %s even after %d retries" %(str(retryProblematicHost), max_retries))
            exceptionDict = {"Running into exception" : exceptionHostTohandle}
            return ((output, exceptionDict) if getStdOut else exceptionDict)

        return ((output, problematicHost) if getStdOut else problematicHost)


    def __verify_task_status(self, typeOfTask, max_tolerable_delay):

        '''
        Args:
            typeOfTask: Indicates the type of task which has to be validated
            max_tolerable_delay: Maximum time within which all the results are to be fetche
        '''
        try:
            self.lgr.debug("__verify_task_status Called")
            resultDict = {}
            taskVerificationThreads = []
            lock = Lock()

            #Iterate through all the host into which the job was assigned to
            for host_ip in self.__TASK_DETAILS[typeOfTask]:
                self.lgr.debug("Checking task status for %s" %host_ip)

                if typeOfTask in self.__MGMT_CALLS:
                    taskVerificationThreads.append(Thread(target=self.__tedp_config[host_ip].get_mgmt_task_status_and_result, \
                        args=(typeOfTask, resultDict, lock, max_tolerable_delay)))
                else:
                    taskVerificationThreads.append(Thread(target=self.__tedp_config[host_ip].get_task_status_and_result, \
                        args=(typeOfTask, resultDict, lock, max_tolerable_delay)))
                taskVerificationThreads[-1].start()

            for t in taskVerificationThreads:
                t.join()

            self.__TASK_DETAILS[typeOfTask] = []
            del taskVerificationThreads

            for host_ip, result in resultDict.items():
                #There will be no "status in result if `status` was True (or) rather the call succeeded!"
                status = isinstance(result, dict) and result.get("status", True)
                if(not(status)):
                    return False, resultDict
            return True, resultDict

        except:
            self.__TASK_DETAILS[typeOfTask] = []
            del taskVerificationThreads
            self.lgr.error("ERROR IN verify_task_status: %s" %traceback.format_exc())
            return False, "Check logs for error. Bad Code/param passed %s" %traceback.format_exc()


    ################################# RUN THE FLASK APPLICATION ###################################
    #Starts the TE Application to serve the REST Requests
    def run(self):

        self.__te_app = Flask(__name__)
        self.__te_app.config["SWAGGER"] = {"title": "Swagger-UI", "uiversion": 2}
        self.__te_app.config['BROKER_URL'] = 'redis://{}:{}/'.format(
            self.__te_controller_obj.get_daemon_ip(), self.__te_controller_obj.get_redis_port())
        self.__te_app.config['RESULT_BACKEND'] = 'redis://{}:{}/'.format(
            self.__te_controller_obj.get_daemon_ip(), self.__te_controller_obj.get_redis_port()
        )

        api = Api(self.__te_app)

        swagger_url = "/swagger"
        api_url = "/static/te_swagger.json"
        swagger_ui_blueprint = get_swaggerui_blueprint(
            swagger_url, api_url, config={'app_name': "Traffic Engine"})
        self.__te_app.register_blueprint(swagger_ui_blueprint, url_prefix=swagger_url)
        api.add_resource(TE_REST_ENDPOINT, '/api/v1.0/te/<te_api_name>')
        api.add_resource(TE_REST_ENDPOINT_SUB_API, '/api/v1.0/te/<te_api_name>/<te_sub_api_name>')

        self.lgr.debug("About to run Flask ApplicationWrapper on %s:%s" \
            %(self.__te_controller_obj.get_daemon_ip(), self.__te_controller_obj.get_flask_port()))
        self.__te_app.run(host=self.__te_controller_obj.get_daemon_ip(),\
            port=int(self.__te_controller_obj.get_flask_port()), debug=False)

    ################################# CHANGE STAT DUMP TIME API ###################################
    @__api_state_decorator("CURRENT_TIME")
    def get_current_te_time_api(self, jsonContent):
        curr_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.lgr.debug("get_current_te_time Called and returned %s" %curr_time)
        return self.__success(curr_time)

    ################################# CHANGE STAT DUMP TIME API ###################################
    @__api_state_decorator("STAT_DUMP_INTERVAL")
    def alter_stat_dump_interval_api(self, jsonContent):
        self.lgr.debug("alter_stat_dump_interval Called")
        self.__stat_dump_interval = convert(jsonContent['stat_dump_interval'])
        self.lgr.debug("altered stat_dump_interval is %d" %self.__stat_dump_interval)
        return self.__success("Altered stat_dump_interval is %d" %self.__stat_dump_interval)

    ################################# CHANGE STAT DUMP TIME API ###################################
    @__api_state_decorator("STAT_COLLECT_INTERVAL")
    def alter_stat_collect_interval_api(self, jsonContent):
        self.lgr.debug("alter_stat_collect_interval Called")
        self.__stat_collect_interval = convert(jsonContent['stat_collect_interval'])
        self.lgr.debug("altered stat_collect_interval is %d" %self.__stat_collect_interval)
        return self.__success("Altered stat_collect_interval is %d" %self.__stat_collect_interval)

    ############################### CHANGE METRICS COLLECTION STATE ###############################
    @__api_state_decorator("METRICS_ENABLED")
    def alter_metrics_collection_api(self, jsonContent):
        self.lgr.debug("alter_metrics_collection_api Called")
        self.__metrics_enabled = convert(jsonContent['state'])
        return self.__success("Altered metrics_enabled state is %s" %str(self.__metrics_enabled))

    ########################### CHANGE MEMORY METRICS COLLECION STATE  #############################
    @__api_state_decorator("MEMORY_METRICS_ENABLED")
    def alter_memory_metrics_collection_api(self, jsonContent):
        self.lgr.debug("alter_memory_metrics_collection_api Called")
        self.__memory_metrics_enabled = convert(jsonContent['state'])
        return self.__success("Altered memory_metrics_enabled state is %s" \
            %str(self.__memory_metrics_enabled))

    ################################# GET VIP METRICS ###################################
    @__api_state_decorator("GET_VIP_METRICS")
    def get_vip_metrics_api(self, jsonContent):
        self.lgr.debug("get_vip_metrics Called")
        type_of_metric = convert(jsonContent['type'])
        traffic_profile = convert(jsonContent['traffic_profile'])
        traffic_mode = convert(jsonContent['traffic_mode'])
        filter_clauses = convert(jsonContent.get('filter_clauses', {}))
        is_named = convert(jsonContent.get('is_named', True))
        if(type_of_metric == "TOTAL" or type_of_metric == "LAST_DIFF"):
            status, result = self.__te_postgres_object.query_vip_metrics(type_of_metric, \
                            traffic_profile, traffic_mode, filter_clauses, is_named)
            if(status):
                return self.__success(result)
            else:
                return self.__failure(result)
        else:
            return self.__failure("type must either be TOTAL or LAST_DIFF")

    ################################# GET ERROR METRICS ###################################
    @__api_state_decorator("GET_ERROR_METRICS")
    def get_error_metrics_api(self, jsonContent):
        self.lgr.debug("get_error_metrics Called")
        type_of_metric = convert(jsonContent['type'])
        filter_clauses = convert(jsonContent.get('filter_clauses', {}))
        is_named = convert(jsonContent.get('is_named', True))
        error_group_interval = \
            convert(jsonContent.get('error_group_interval', 15))
        if(type_of_metric == "TOTAL" or type_of_metric == "LAST_DIFF"):
            status, result = self.__te_postgres_object.query_error_metrics(type_of_metric, \
                            filter_clauses, is_named, error_group_interval)
            if(status):
                return self.__success(result)
            else:
                return self.__failure(result)
        else:
            return self.__failure("type must either be TOTAL or LAST_DIFF")

    ################################# GET SES METRICS ###################################
    @__api_state_decorator("GET_SES_METRICS")
    def get_ses_metrics_api(self, jsonContent):
        self.lgr.debug("get_ses_metrics Called")
        type_of_metric = convert(jsonContent['type'])
        traffic_profile = convert(jsonContent['traffic_profile'])
        traffic_mode = convert(jsonContent['traffic_mode'])
        filter_clauses = convert(jsonContent.get('filter_clauses', {}))
        is_named = convert(jsonContent.get('is_named', True))
        if(type_of_metric == "TOTAL" or type_of_metric == "LAST_DIFF"):
            status, result = self.__te_postgres_object.query_ses_metrics(type_of_metric, \
                            traffic_profile, traffic_mode, filter_clauses, is_named)
            if(status):
                return self.__success(result)
            else:
                return self.__failure(result)
        else:
            return self.__failure("type must either be TOTAL or LAST_DIFF")

    ################################# GET MEMORY METRICS ###################################
    @__api_state_decorator("GET_MEMORY_METRICS")
    def get_memory_metrics_api(self, jsonContent):
        self.lgr.debug("get_memory_metrics Called")
        type_of_metric = convert(jsonContent['type'])
        filter_clauses = convert(jsonContent.get('filter_clauses', {}))
        is_named = convert(jsonContent.get('is_named', True))
        if(type_of_metric == "TOTAL" or type_of_metric == "LAST_DIFF"):
            status, result = self.__te_postgres_object.query_memory_metrics(type_of_metric, \
                            filter_clauses, is_named)
            if(status):
                return self.__success(result)
            else:
                return self.__failure(result)
        else:
            return self.__failure("type must either be TOTAL or LAST_DIFF")

    ################################# GET CONFIG HISTORY ###################################
    @__api_state_decorator("GET_CLIENT_HISTORY")
    def get_client_history_api(self, jsonContent):
        self.lgr.debug("get_client_history_api Called")
        filter_clauses = convert(jsonContent.get('filter_clauses', {}))
        status, result = self.__te_postgres_object.query_client_history(filter_clauses)
        if(status):
            return self.__success(result)
        else:
            return self.__failure(result)

    ################################# GET CONFIGS ###################################
    @__api_state_decorator("GET_CONFIGS")
    def get_configs_api(self, jsonContent):
        self.lgr.debug("get_configs_api Called")
        res_hash_list = convert(jsonContent['res_hash_list'])
        ses_hash_list = convert(jsonContent['ses_hash_list'])
        is_named = convert(jsonContent.get('is_named', True))
        if res_hash_list is None and ses_hash_list is None:
            return self.__failure('Both res_hash_list and ses_hash_list cannot be None')

        status, result = self.__te_postgres_object.query_and_get_configs(
                        res_hash_list, ses_hash_list, is_named)
        if(status):
            return self.__success(result)
        else:
            return self.__failure(result)

    ################################# GET STATES API ###################################
    @__api_state_decorator("GET_STATES")
    def get_states_api(self, jsonContent):
        self.lgr.debug("get_tedp_states_api Called")
        #TEDP STATES
        tedp_states = {}
        if self.__tedp_config is not None:
            for host_ip, object in self.__tedp_config.items():
                tedp_states[host_ip] = object.getStates()
        te_flask_api_states = {'current_te_state' : self.__CURRENT_STATE,
                                'current_te_task_details' : self.__TASK_DETAILS,
                                'te_daemon_ip' : self.__te_controller_obj.get_daemon_ip(),
                                'flask_port' : self.__te_controller_obj.get_flask_port(),
                                'redis_port' : self.__te_controller_obj.get_redis_port(),
                                'nginx_port' : self.__te_controller_obj.get_nginx_port(),
                                'loglevel' : self.__te_controller_obj.get_loglevel(),
                                'te_dp_dict' : self.__te_controller_obj.get_te_dp(),
                                'connect_completed_tedps':list(self.__connect_completed_tedps),
                                '__setup_completed_tedps' : list(self.__setup_completed_tedps)}
        statesToReturn = {'te_dp_states': tedp_states, 'te_flask_api_states':te_flask_api_states}
        return self.__success(statesToReturn)

    ################################# GET CPU COUNT API ###################################

    def __get_cpu_count_tedps(self, te_dp_hosts, client):
        try:
            output, problematicHost = self.__run_command_and_validate_output(client=client, \
                te_dp_hosts=te_dp_hosts, cmd="nproc", getStdOut=True)
            if(bool(problematicHost)):
                return False, "Error while ssh-ing into clients", problematicHost

            cpu_result = {}
            problematicHost = {}
            for host, linesOfOutput in output.items():
                for line in linesOfOutput:
                    try:
                        cpus = int(line)
                        cpu_result[host] = cpus
                    except:
                        problematicHost[host] = line
                    break
            if(bool(problematicHost)):
                return False, "Got unexpected Response", problematicHost
            return True, "Got CPU Count", cpu_result

        except:
            return False, "Exception Occured", traceback.format_exc()

    @__api_state_decorator("GET_CPU_COUNT")
    def get_cpu_count_api(self, jsonContent):
        self.lgr.debug("get_cpu_count_api Called")
        te_dp_dict = convert(jsonContent['te_dp_dict'])

        if(not(bool(te_dp_dict))):
            return self.__failure("No te_dp_dict Passed")

        te_dp_hosts = {}
        for host_ip, details in te_dp_dict.items():
            te_dp_hosts[host_ip] = {'user': details.get('user','root'),
                                    'password':details.get('passwd', 'avi123')}

        client = ParallelSSHClient(te_dp_hosts.keys(), host_config=te_dp_hosts, timeout = 240)
        status, msg, result = self.__get_cpu_count_tedps(te_dp_hosts, client)
        del client

        if(not(status)):
            return self.__failure({msg:result})

        return self.__success(result)

    def __run_mgmt_command(self, te_dp_hosts, global_cmd=None, per_host_cmd=None, task=None, \
        job_timeout=None, max_tolerable_delay=120):
        try:
            problematicHost = []
            CURRENT_TASK = task
            for host_ip in te_dp_hosts:
                enqueuedCall = False

                if(bool(global_cmd)):
                    enqueuedCall = self.__tedp_config[host_ip].run_mgmt_command_helper(
                        run_mgmt_command_te_dp, {"cmd":global_cmd, "task":task}, job_timeout)

                elif(bool(per_host_cmd)):
                    cmd_to_enqueue = per_host_cmd.get(host_ip,None)
                    if(bool(cmd_to_enqueue)):
                        enqueuedCall = self.__tedp_config[host_ip].run_mgmt_command_helper(
                            run_mgmt_command_te_dp, {"cmd":cmd_to_enqueue, "task":task})
                    else:
                        problematicHost.append(host_ip)

                else:
                    problematicHost.append(host_ip)

                #Add to Assigned TASK_DETAILS
                if enqueuedCall:
                    self.__TASK_DETAILS[CURRENT_TASK].append(host_ip)
                else:
                    problematicHost.append(host_ip)

            if(bool(problematicHost)):
                self.__tedp_config[host_ip].clean_task_details(CURRENT_TASK)
                self.__TASK_DETAILS[CURRENT_TASK] = []
                return False, "Unable to perform mgmt_call TEDPs (Fail at enqueue level)", problematicHost

            if(job_timeout is not None):
                max_time_wait = max(max_tolerable_delay, job_timeout)
            else:
                max_time_wait = max_tolerable_delay

            status, result = self.__verify_task_status(task, max_time_wait)
            if status:
                return True, "Success", result

            #RQ Failure / Incomplete task / bad code
            return False, "Unexpected result", result
        except:
            return False, "Exception Occured", traceback.format_exc()

    ################################# GET ACTIVE TEDP API ###################################

    @__api_state_decorator("GET_ACTIVE_TEDP")
    def get_active_tedp_api(self, jsonContent):

        self.lgr.debug("get_active_tedp_api Called")
        #Get the current te_dp_dict maintined if param passed is empty
        te_dp_dict = convert(jsonContent['tedps_to_query'])

        if(bool(te_dp_dict)):
            set_of_passed_dict = set(te_dp_dict.keys())
            if(not(set_of_passed_dict.issubset(self.__connect_completed_tedps))):
                return self.__failure({"Passed te_dp dict is not a subset of Connected TEDP" : \
                    list(self.__connect_completed_tedps)})

        else:
            self.lgr.debug("get_active_tedp: No param passed")
            te_dp_dict = self.__te_controller_obj.get_te_dp()

        #If still empty, return
        if(not(bool(te_dp_dict))):
            return self.__failure("No te_dps are running")

        cmd = "ps aux | grep te_dp | grep -v grep | wc -l"
        status, msg, result = self.__run_mgmt_command(te_dp_dict.keys(), global_cmd=cmd, task="GET_ACTIVE_TEDP")

        if(status):
            return self.__success(result)
        else:
            return self.__failure({msg:result})

    @__api_state_decorator("UPDATE_DNS")
    def update_dns_api(self, jsonContent):

        self.lgr.debug("update_dns_api Called")
        #Get the current te_dp_dict maintined if param passed is empty
        te_dp_dict = convert(jsonContent.get('te_dp_dict', {}))
        global_dns = convert(jsonContent.get('global_dns', []))
        overwrite = convert(jsonContent['overwrite'])
        problematicHost = []

        if(overwrite):
            redirector = ">"
        else:
            redirector = ">>"

        if(bool(te_dp_dict)):
            #If te_dp_dict is present, update the DNS only in those Clients
            set_of_passed_dict = set(te_dp_dict.keys())
            per_host_cmd = {}

            #Check if all the passed clients are connected
            if(not(set_of_passed_dict.issubset(self.__connect_completed_tedps))):
                return self.__failure({"Passed te_dp dict is not a subset of Connected TEDP" : \
                    list(self.__connect_completed_tedps)})

            else:
                #Iterate through all the clients and frame the appropriate command
                for host_ip, details in te_dp_dict.items():
                    cmd = ""
                    for tuple_item in details:
                        if(len(tuple_item) == 2):
                            cmd += "%s    %s\n" %(str(tuple_item[0]), str(tuple_item[1]))
                        else:
                            problematicHost.append(host_ip)
                    if(bool(cmd)):
                        cmd = "printf '%s' %s /etc/resolv.conf" %(cmd, redirector)
                        self.lgr.debug("Command for %s is %s" %(host_ip, cmd))
                        per_host_cmd[host_ip] = cmd

                if(bool(problematicHost)):
                    return self.__failure({"improper input": problematicHost})

                if(bool(per_host_cmd)):
                    status, msg, result = self.__run_mgmt_command(te_dp_dict.keys(), \
                                        per_host_cmd=per_host_cmd, task="UPDATE_DNS")
                else:
                    return self.__failure("Nothing to add/append")

        elif(bool(global_dns)):
            #If global_dns is present add the same DNS to all TE-DP Clients
            cmd = ""
            for tuple_item in global_dns:
                if(len(tuple_item) == 2):
                    cmd += "%s    %s\n" %(str(tuple_item[0]), str(tuple_item[1]))
                else:
                    problematicHost.append(tuple_item)

            if(bool(problematicHost)):
                return self.__failure({"improper input": problematicHost})

            if(bool(cmd)):
                cmd = "printf '%s' %s /etc/resolv.conf" %(cmd, redirector)
                self.lgr.debug("Command is %s" %(cmd))

            status, msg, result = self.__run_mgmt_command(self.__connect_completed_tedps, \
                global_cmd=cmd, task="UPDATE_DNS")

        else:
            #If both are absent, throw an error
            self.__failure("Both global_dns and te_dp_dict cannot be empty")

        if(status):
            return self.__success(result)
        else:
            return self.__failure({msg:result})

    @__api_state_decorator("RESET_DNS")
    def reset_dns_api(self, jsonContent):

        self.lgr.debug("reset_dns_api Called")
        #Get the current te_dp_dict maintined if param passed is empty
        te_dp_dict = convert(jsonContent['te_dp_dict'])

        if(bool(te_dp_dict)):
            #If te_dp_dict is passed, reset only in those clients
            set_of_passed_dict = set(te_dp_dict.keys())

            #Check if all the passed clients are connected
            if(not(set_of_passed_dict.issubset(self.__connect_completed_tedps))):
                return self.__failure({"Passed te_dp dict is not a subset of Connected TEDP" : \
                    list(self.__connect_completed_tedps)})

        else:
            #If nothing is passed, reset DNS on all clients
            self.lgr.debug("reset_dns: No param passed")
            te_dp_dict = self.__connect_completed_tedps
            if(not(bool(te_dp_dict))):
                return self.__failure("No TEDPs connected")

        #Command to clean /etc/resolv.conf
        cmd = "> /etc/resolv.conf"
        status, msg, result = self.__run_mgmt_command(te_dp_dict, global_cmd=cmd, task="RESET_DNS")

        if(status):
            return self.__success(result)
        else:
            return self.__failure({msg:result})


    @__api_state_decorator("EXECUTE_CMD")
    def execute_cmd_api(self, jsonContent):

        self.lgr.debug("execute_cmd_api Called")
        #Get the current te_dp_dict maintined if param passed is empty
        te_dp_dict = convert(jsonContent.get('te_dp_dict', {}))
        cmd = convert(jsonContent['cmd'])
        job_timeout = convert(jsonContent.get('job_timeout', 180))

        if(bool(te_dp_dict)):
            #If te_dp_dict is passed, reset only in those clients
            set_of_passed_dict = set(te_dp_dict.keys())

            #Check if all the passed clients are connected
            if(not(set_of_passed_dict.issubset(self.__connect_completed_tedps))):
                return self.__failure({"Passed te_dp dict is not a subset of Connected TEDP" : \
                    list(self.__connect_completed_tedps)})

        else:
            #If nothing is passed, reset DNS on all clients
            self.lgr.debug("execute_cmd: No param passed")
            te_dp_dict = self.__connect_completed_tedps
            if(not(bool(te_dp_dict))):
                return self.__failure("No TEDPs connected")

        status, msg, result = self.__run_mgmt_command(te_dp_dict, global_cmd=cmd, task="EXECUTE_CMD", job_timeout=job_timeout)

        if(status):
            return self.__success(result)
        else:
            return self.__failure({msg:result})


    def __tech_support_helper(self, tedp_host, scp_ip, scp_user, scp_passwd, scp_path, \
        type_of_logs, max_tolerable_delay):
        try:
            CURRENT_TASK = "TECH_SUPPORT"
            self.lgr.debug("__tech_support_helper Called")
            state_error = {}
            numberOfCallsMade = 0
            enqueuedHosts = []
            resultDict = {}
            bin_src_flag = True

            for host in tedp_host:
                argsPassed = {'my_ip':host, 'remote_ip':scp_ip, 'remote_user':scp_user, \
                        'remote_pwd':scp_passwd, 'remote_path':scp_path, \
                        'type_of_logs':type_of_logs,'bin_src_flag':bin_src_flag}
                self.lgr.debug("Passing args to tech_support=%s" %str(argsPassed))
                resultDict[host] = \
                    self.__tedp_config[host].tech_support_helper(tech_support, argsPassed)

                #Add to Assigned TASK_DETAILS
                self.__TASK_DETAILS[CURRENT_TASK].append(host) 
                bin_src_flag = False

            self.lgr.debug("result of tech_support tedp %s" %(str(resultDict)))
            
            status, result = self.__verify_task_status(CURRENT_TASK, max_tolerable_delay)
            if status:
                return True, "SCP-ed files", result
            #RQ Failure / Incomplete task / bad code
            return False, "No Files SCP-ed", result
        except:
            return False, "Exception Occured:", traceback.format_exc()
 
    @__api_state_decorator("TECH_SUPPORT")
    def tech_support_api(self, jsonContent):
        self.lgr.debug("tech_support_api Called")
        scp_ip = convert(jsonContent['scp_ip'])
        te_dp_dict = convert(jsonContent['te_dp_dict'])
        scp_user = convert(jsonContent['scp_user'])
        scp_passwd = convert(jsonContent['scp_passwd'])
        scp_path = convert(jsonContent['scp_path'])
        log_type = convert(jsonContent['log_type'])
        max_tolerable_delay = convert(jsonContent.get('max_tolerable_delay', 120))

        if scp_ip is None:
            scp_ip = self.__te_controller_obj.get_daemon_ip()

        if(log_type!="all" and log_type!="setup" and log_type!="process" and log_type!="core"):
            self.__failure("Only accepted types of log_types are all, setup, process or core")

        #If connect step is yet to be completed
        if(not(bool(self.__connect_completed_tedps))):
            if(not(bool(te_dp_dict))):
                return self.__failure("Connect step incomplete and no te_dp dict is passed to get logs from")
            self.lgr.debug("Using parallel_ssh to get the tech_support")
            te_dp_hosts = OrderedDict()
            host_specific_cmd = OrderedDict()
            for host_ip in te_dp_dict:
                te_dp_hosts[host_ip] = {'user': te_dp_dict[host_ip].get('user','root'),
                                        'password':te_dp_dict[host_ip].get('passwd', 'avi123')}
            client = ParallelSSHClient(te_dp_hosts.keys(), host_config=te_dp_hosts, timeout = 240)            
            for host in te_dp_hosts:
                path_for_host = os.path.join(scp_path, "te_%s_logs" %host)
                host_specific_cmd[host] = \
                    "sshpass -p %s ssh -o 'StrictHostKeyChecking no' -t %s@%s 'rm -rf %s; mkdir -p %s/setup_logs';" \
                    " sshpass -p %s scp -o 'StrictHostKeyChecking no' /root/connector.log " \
                    "/root/download_docker.log %s@%s:%s/setup_logs" \
                    %(scp_passwd, scp_user, scp_ip, path_for_host, path_for_host,\
                    scp_passwd, scp_user, scp_ip, path_for_host)

            problematicHost = self.__run_command_and_validate_output(client=client, \
                te_dp_hosts=te_dp_hosts, host_args=host_specific_cmd, validate_exit_codes=False)

            if(bool(problematicHost)):
                return self.__failure(problematicHost)

            return self.__success("SCPed setup_logs to %s of %s" %(scp_path, scp_ip))

        else:
            self.lgr.debug("Using RQs to get the tech_support")
            if(bool(te_dp_dict)):
                te_dps = te_dp_dict.keys()
            else:
                te_dps = self.__connect_completed_tedps
            status, msg, result = self.__tech_support_helper(te_dps, scp_ip, scp_user, scp_passwd, \
                scp_path, log_type, max_tolerable_delay)
            if status:
                date_time = str(datetime.now()).replace(' ','-').replace(':','-')
                tar_file = "techsupportlogs-{}.tar.gz".format(date_time)
                scp_path = os.path.join('/',scp_path) 
                interested_files = "te_*_logs bin_src_file_dir"
                cmd = "cd {} && tar -zcvf {} {} && rm -rf {}; ls {}".format(scp_path, tar_file, interested_files, interested_files, tar_file)
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(scp_ip, username=scp_user, password=scp_passwd,timeout=10)
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.readlines()
                if(bool(output)):
                    if(output[-1].replace('\n','')==tar_file):
                        return self.__success(result)
                    else:
                        return self.__success("Tar ball not generated but tech support logs scp-ed successfuly")
                else:
                    return self.__failure({msg:"Unable to scp techsupport logs"})
            return self.__failure({msg:result})

    ################################# SETUP TEDP API ####################################

    def __setup_tedps(self, te_dp_hosts, client):

        EXIT_STATUS = {
                10 : "Unable to find docker",
                11 : "Unable to find python-requests",
                12 : "Unable to find wget",
                13 : "Unable to prepare the appropriate conditions needed to start the container (redis stop, docker start)",
                14 : "Unable to download the tedp_docker.tar from TE-Controller",
                15 : "Unable to load the container",
                16 : "Unable to run the container",
                17 : "Unable o get free ports",
                18 : "Wrong parameters passed",
                19 : "Unable to calculate checksum of Tar file",
                20  : "Unable to find free port even after several tries",
                21  : "Unable to find netstat command",
                22  : "Unable to find both systemctl and service commands",
                200 : "Success",
                404 : "Fatal: unknown reason"
        }
        CLEAN_EXIT = 200

        #SCP GET_AND_RUN_DOCKER_IMAGE.py to all the hosts' /root/
        greenlets = client.scp_send('/app/GET_AND_RUN_DOCKER_IMAGE.py', '/root/GET_AND_RUN_DOCKER_IMAGE.py')
        try:
            joinall(greenlets, raise_error=True)
        except:
            return False, "Unable to scp GET_AND_RUN_DOCKER_IMAGE.py", traceback.format_exc()
        self.lgr.debug("SCP-ed /app/GET_AND_RUN_DOCKER_IMAGE.py to TEDP containers")

        #Run GET_AND_RUN_DOCKER_IMAGE.py to all the hosts' /root/
        command = "python /root/GET_AND_RUN_DOCKER_IMAGE.py -w /root/ -ip %s -p %s -t TE_DP" \
            %(self.__te_controller_obj.get_daemon_ip(), self.__te_controller_obj.get_nginx_port())
        problematicHost = self.__run_command_and_validate_output(client=client, \
            te_dp_hosts=te_dp_hosts, cmd=command, cleanExitCode=CLEAN_EXIT,\
            possibleExitCodesDict=EXIT_STATUS)
        if problematicHost != {}:
            self.lgr.error("Unable to run GET_AND_RUN_DOCKER_IMAGE.py to TEDP containers. %s" \
                %str(problematicHost))
            return False, "Unable to setup tedp on all machines. Exit Codes", problematicHost
        else:
            return True, "Launched TEDPs", []

    @__api_state_decorator("SETUP")
    def setup_tedp_api(self, jsonContent):
        '''
            Args:
                jsonContent: Must Posses te_dp_dict
        '''
        self.lgr.debug("setup_tedp_api Called")
        isRequestValid = self.__checkForRequiredArgument(jsonContent, ['te_dp_dict'])
        if isRequestValid is not None:
            return isRequestValid

        self.lgr.debug("Validation of Request Success {}".format(jsonContent['te_dp_dict']))
        start_time = time.time()

        te_dp_dict = convert(jsonContent['te_dp_dict'])
        if not isinstance(te_dp_dict, dict):
            return self.__failure("te_dp_dict must be a dict")

        te_dp_hosts = {}
        host_ips_to_setup = set(te_dp_dict.keys()) - self.__setup_completed_tedps

        invalid_input = {}
        for host_ip in host_ips_to_setup:

            value = te_dp_dict[host_ip]
            if value is None:
                invalid_input[host_ip] = "Value cannot be None"
                continue
            user = value.get('user',None)
            if user is None:
                invalid_input[host_ip] = "user cannot be None"
                continue
            passwd = value.get('passwd',None)
            if passwd is None:
                invalid_input[host_ip] = "passwd cannot be None"
                continue

            te_dp_hosts[host_ip] = {'user': user, 'password':passwd}
            self.__all_te_dp_dict_credentials[host_ip] = te_dp_hosts[host_ip]

        if(bool(invalid_input)):
            return self.__failure(invalid_input)

        if(not(te_dp_hosts)):
            return self.__failure({"TEPDs already setup" : list(self.__setup_completed_tedps)})

        self.lgr.debug("Running setup_tedp on {}".format(te_dp_hosts))
        client = ParallelSSHClient(te_dp_hosts.keys(), host_config=te_dp_hosts, timeout = 240)
        self.lgr.debug("Creation of ParallelSSHClient Success")
        status, msg, result = self.__setup_tedps(te_dp_hosts, client)
        del client

        if status:
            self.__setup_completed_tedps.update(host_ips_to_setup)
            return self.__success(msg)
        else:
            # if we have partial success, add to the list to avoid re-init of setup_tedp
            # for the successful host
            if isinstance(result, dict):
                failed_hosts = list(result.keys())
                for tedp_host in host_ips_to_setup:
                    if tedp_host not in failed_hosts:
                        self.__setup_completed_tedps.add(tedp_host)
            return self.__failure({msg:result})

    ################################# CONNECT API ####################################

    def __connect_tedps(self, te_dp_hosts, client):
        try:
            def __del(host_ip_list):
                for host_ip in host_ip_list:
                    try:
                        del self.__tedp_config[host_ip]
                    except:
                        pass

            EXIT_CODES = {
                10 : "Unable to dummp configs",
                11 : "Connect R-Queues started lesser than expected",
                12 : "Docker container is not up. Please do a setup_tedp()",
                13 : "Unable to start stat_collector daemon",
                14 : "Unable to find python-redis package"
            }
            CLEAN_EXIT = 200

            self.lgr.debug("__connect_tedps Called")
            broker = deepcopy(self.__te_app.config['BROKER_URL'])
            banckend = deepcopy(self.__te_app.config['RESULT_BACKEND'])
            host_command = OrderedDict()

            #Find the resource of CPUs
            output, problematicHost = self.__run_command_and_validate_output(client=client, \
                te_dp_hosts=te_dp_hosts, cmd="nproc", getStdOut=True)
            if(bool(problematicHost)):
                return False, "Improper Exit code", problematicHost
            cpu_result = {}
            for host, linesOfOutput in output.items():
                for line in linesOfOutput:
                    cpus = int(line)
                    if cpus > 1:
                        te_dp_hosts[host]['cpus'] = cpus
                    else:
                        cpu_result[host] = {'available-cpus': cpus, 'minimum-number-of-cpus-required' : 2}
                    break
            if(bool(cpu_result)):
                return False, "Resource Error", cpu_result

            #Run CONNECTOR.py

            greenlets = client.scp_send('/app/CONNECTOR.py', '/root/CONNECTOR.py')
            joinall(greenlets, raise_error=True)
            zmq_port = self.__te_controller_obj.get_zmq_port()
            for host, details in te_dp_hosts.items():
                self.__tedp_config[host] = TE_DP_CONFIG(host, details['user'], details['password'],\
                    details['cpus'], self.TE_BROKER_HANDLE, self.lgr, self.__te_postgres_object)
                queue_csv = 'TE?' + str(self.__tedp_config[host].get_queue_names())
                self.lgr.debug("%s queue_csv=%s" %(host, queue_csv))
                command = "python /root/CONNECTOR.py -b " + broker + \
                    " -l "+ str(self.__te_controller_obj.get_loglevel()) + \
                    " -s " + str(self.__stat_collect_interval) + \
                    " -ip " + host + \
                    " -z " + zmq_port + \
                    " -te " + self.__te_controller_obj.get_daemon_ip() + \
                    " -w /opt/te/ -Q \"" + str(queue_csv)+'\"'
                host_command[host]=command
            problematicHost = self.__run_command_and_validate_output(client=client, \
                te_dp_hosts=te_dp_hosts, host_args=host_command, cleanExitCode=CLEAN_EXIT, \
                possibleExitCodesDict=EXIT_CODES)
            if(bool(problematicHost)):
                __del(problematicHost.keys())
                return False, "Improper Exit codes", problematicHost
            else:
                return True, "Connected to Hosts", problematicHost
        except:
            self.lgr.error("Exception in connect_tedps %s" %traceback.format_exc())
            __del(te_dp_hosts.keys())
            return False, "Exception in connect_tedps", traceback.format_exc()


    @__api_state_decorator("CONNECT")
    def connect_api(self, jsonContent):

        self.lgr.debug("connect_api Called")

        isRequestValid = self.__checkForRequiredArgument(jsonContent, ['te_dp_dict'])
        if isRequestValid is not None:
            return isRequestValid

        te_dp_dict = convert(jsonContent['te_dp_dict'])
        if not isinstance(te_dp_dict, dict):
            return self.__failure("te_dp_dict must be a dict")

        te_dp_hosts = OrderedDict()
        tedps_to_connect = set(te_dp_dict.keys())
        host_ips_to_connect = tedps_to_connect - self.__connect_completed_tedps

        invalid_input = {}
        for host_ip in host_ips_to_connect:

            value = te_dp_dict[host_ip]
            if value is None:
                invalid_input[host_ip] = "Value cannot be None"
                continue
            user = value.get('user',None)
            if user is None:
                invalid_input[host_ip] = "user cannot be None"
                continue
            passwd = value.get('passwd',None)
            if passwd is None:
                invalid_input[host_ip] = "passwd cannot be None"
                continue
            te_dp_hosts[host_ip] = {'user': user, 'password':passwd}
            self.__all_te_dp_dict_credentials[host_ip] = te_dp_hosts[host_ip]

        if(bool(invalid_input)):
            return self.__failure(invalid_input)

        if(not(bool(te_dp_hosts))):
            return self.__failure({"No tedps to connect. Already connected tedps": \
                list(self.__connect_completed_tedps)})

        client = ParallelSSHClient(te_dp_hosts.keys(), host_config=te_dp_hosts, timeout = 240)
        status, message, result = self.__connect_tedps(te_dp_hosts, client)
        del client

        if status:
            self.__connect_completed_tedps.update(host_ips_to_connect)
            #Change of collect interval has to be reflected at metrics object to accurate rate computation
            self.__te_postgres_object.alter_stat_collect_interval(self.__stat_collect_interval)
            return self.__success('Connected all TEs and TEDPs')
        else:
            #If Failed result.keys() are the only failed guys, rest all are connected
            self.__connect_completed_tedps.update(
                set(host_ips_to_connect) - set(result.keys())
            )
            return self.__failure({message:result})

    ################################# CLEAN API ####################################

    def __disconnect_tedps(self, te_dp_hosts, client, remove_containers=False):
        try:
            cmd = "docker exec tedpv2.0 bash -c '(kill_proc=$(pgrep te_dp) && kill -9 $kill_proc)'; \
            docker exec tedpv2.0 bash -c '(kill_proc=$(pgrep rq) && kill -9 $kill_proc)'; \
            docker exec tedpv2.0 bash -c 'ipcrm --all=msg'; \
            docker exec tedpv2.0 bash -c 'ls -d /tmp/* | grep -v ramcache | xargs rm -rf'; \
            docker exec tedpv2.0 bash -c 'ls -d /opt/te/* | grep core | xargs rm -rf'; \
            docker exec tedpv2.0 bash -c 'rm -rf /te_host/*'; \
            docker exec tedpv2.0 bash -c 'ps aux | grep -e te_dp -e rq | grep -v grep | wc -l'; \
            docker exec tedpv2.0 bash -c 'service te_stats_collector stop'; \
            exit 0"

            (output, problematicHost) = self.__run_command_and_validate_output(client=client, \
                te_dp_hosts=te_dp_hosts, cmd=cmd, getStdOut=True)
            if(bool(problematicHost)):
                return False, "Unable to disconnect from hosts", problematicHost

            unableToStop = {}
            disconnectedHosts = []
            for host_ip, linesOfOutput in output.items():
                for line in linesOfOutput:
                    try:
                        processRunning = int(line)
                    except:
                        disconnectedHosts.append(host_ip)
                        break
                    if processRunning != 0:
                        unableToStop[host_ip] = processRunning
                    else:
                        del self.__tedp_config[host_ip]
                        disconnectedHosts.append(host_ip)
                    break

            if(bool(unableToStop)):
                return False, "Unable to stop running processes in hosts", unableToStop

            if remove_containers:
                cmd = "docker rm -f tedpv2.0 || true"
                problematicHost = self.__run_command_and_validate_output(client=client, \
                    te_dp_hosts=te_dp_hosts, cmd=cmd)
                if(bool(problematicHost)):
                    return False, "Unable to disconnect from hosts", problematicHost
                return True, "Disconnected and removed containers in hosts", disconnectedHosts
            else:
                return True, "Disconnected containers in hosts", disconnectedHosts

        except:
            return False, "Exception Occured", traceback.format_exc()


    @__api_state_decorator("CLEAN")
    def clean_api(self, jsonContent):

        isRequestValid = self.__checkForRequiredArgument(jsonContent, ['remove_containers'])
        if isRequestValid is not None:
            return isRequestValid

        remove_containers = convert(jsonContent['remove_containers'])

        te_dp_hosts = {}
        for host_ip in self.__connect_completed_tedps:
            te_dp_hosts[host_ip] = {'user': self.__all_te_dp_dict_credentials[host_ip].get('user','root'),
                                    'password':self.__all_te_dp_dict_credentials[host_ip].get('passwd', 'avi123')}

        if(not(bool(te_dp_hosts))):
            return self.__failure("No connected te dps to disconnect")

        client = ParallelSSHClient(te_dp_hosts.keys(), host_config=te_dp_hosts, timeout = 240)
        status, msg, result = self.__disconnect_tedps(te_dp_hosts, client, remove_containers)
        del client

        if status:
            self.__connect_completed_tedps.clear()
            if remove_containers:
                self.__setup_completed_tedps.clear()
            self.__te_controller_obj.unset_te_dp()
            self.__te_controller_obj.unset_resource_config()
            self.__te_controller_obj.unset_session_config()
            self.__te_controller_obj.unset_instance_profile_config()
            self.__te_controller_obj.unset_client_cert_bundle()
            self.__CURRENT_STATE = self.__TE_STATE["INIT"]
            self.TE_BROKER_HANDLE.flushall()
            if(self.__te_postgres_object.clear_tables()):
                return self.__success(result)
            else:
                return self.__failure("Unable to clear metrics table in TE")
        else:
            return self.__failure({msg:result})

    ################################# START API ####################################

    def __spawn_or_update_tedps(self, resource_config, sessionConfig, instanceProfileConfig, \
            tedp_dict, max_tolerable_delay, is_cert_replaced, updateFlag=False, verify_result=True):
        #AK: What does the below line mean??
        # Multiple Src IPs Code will break, because the current implementation depends on TEDP_INFO, which is not yet updated in the connect step in this design due to obvious reasons
        try:
            if updateFlag:
                CURRENT_TASK = "UPDATE"
            else:
                CURRENT_TASK = "START"
            self.lgr.debug("__spawn_or_update_tedps Called")
            state_error = {}
            numberOfCallsMade = 0
            enqueuedHosts = []
            resultDict = defaultdict(dict)

            for host_ip, instance_profile in tedp_dict.items():
                enqueuedCall = False

                for profile_tag, count in instance_profile.items():
                    profileToGet = instanceProfileConfig.get(profile_tag, None)

                    #Should never get into the if-block, if user-side validation is completed
                    if profileToGet is None:
                        self.lgr.error("%s instance_profile_tag is not present in instanceProfileConfig" %(profile_tag))
                        return False, "%s instance_profile_tag is not present in instanceProfileConfig" %(profile_tag), instanceProfileConfig

                    res_tag = profileToGet['res-tag']
                    ses_tag = profileToGet.get('ses-tag', None)
                    traffic_mode     = profileToGet.get('traffic-mode', 'CLIENT').upper()
                    traffic_profile  = profileToGet.get('traffic-profile', 'TCP').upper()

                    if is_cert_replaced:
                        client_res_cfg =  resource_config[host_ip][res_tag]
                    else:
                        client_res_cfg = resource_config[res_tag]

                    # UDP Server can have ses_tag as None
                    if ses_tag is not None:
                        client_ses_cfg = sessionConfig[ses_tag]
                    else:
                        client_ses_cfg = {}

                    res_hash = str(hash(json.dumps(client_res_cfg)))
                    ses_hash = str(hash(json.dumps(client_ses_cfg)))

                    self.__te_postgres_object.insert_configs(res_tag, res_hash, client_res_cfg,
                                            ses_tag, ses_hash, client_ses_cfg)

                    argsPassed = {'profile_tag':profile_tag, 'res_tag':res_tag, 'ses_tag':ses_tag, \
                            'client_res_cfg':client_res_cfg, 'client_ses_cfg':client_ses_cfg, \
                            'client_res_hash':res_hash, 'client_ses_hash':ses_hash, \
                            'stat_dump_interval' : self.__stat_dump_interval, \
                            'metrics_enabled' : self.__metrics_enabled, \
                            'memory_metrics_enabled' : self.__memory_metrics_enabled, \
                            'loglevel' : self.__te_controller_obj.get_loglevel(), \
                            'count_of_tedps':count, 'traffic_mode' : traffic_mode, \
                            'traffic_profile' : traffic_profile, 'client_mgmt_ip' : host_ip}
                    self.lgr.debug("Passing args to spawn/update=%s" %str(argsPassed))

                    if updateFlag:
                        resultDict[host_ip][profile_tag] = \
                            self.__tedp_config[host_ip].update_te_dp_helper(raw_update_te_dp, argsPassed)
                    else:
                        resultDict[host_ip][profile_tag] = \
                            self.__tedp_config[host_ip].start_te_dp_helper(start_te_dp, argsPassed)
                    enqueuedCall = True

                #Add to Assigned TASK_DETAILS
                if enqueuedCall:
                    self.__TASK_DETAILS[CURRENT_TASK].append(host_ip)

            self.lgr.debug("result of spawning/updating tedp %s" %(str(resultDict)))
            success = True
            atLeastOneTEDP = False
            for host_ip, profile in resultDict.items():
                atLeastOneTEDP = True
                for result in profile.values():
                    if not(isinstance(result, dict)) or result.get("Success",0) == 0 or result.get("Failure",[]) != []:
                        success = False
                        break

            if not(atLeastOneTEDP):
                return True, "", {"State transition is completed":True}

            #Can fail only if TEDP state transition fails / exceptions
            if(not(success)):
                self.__tedp_config[host_ip].clean_task_details(CURRENT_TASK)
                self.__TASK_DETAILS[CURRENT_TASK] = []
                return False, "Unable to stop TEDPs (Fail at enqueue level)", resultDict

            if verify_result:
                status, result = self.__verify_task_status(CURRENT_TASK, max_tolerable_delay)
                if status:
                    return True, "All TEDPs Spawed", result
                #RQ Failure / Incomplete task / bad code
                return False, "No TEDP Spawed", result
            else:
                return True, "Given RQ Object to execute", resultDict

        except:
            self.lgr.error("ERROR IN spawn_tedp: %s" %traceback.format_exc())
            return False, "Exception occured in %s" %inspect.stack()[0][3], traceback.format_exc()

    def __generate_client_res_cfg(self, te_dp_dict, resource_config, instance_profile_config, \
        cert_profile):
        try:
            problematicCert = []
            client_res_config = {}
            self.lgr.debug("__generate_client_res_cfg Called")

            for client_ip, client_dict in cert_profile.items():
                for vip, cert_list in client_dict.items():
                    for cert in cert_list:
                        if 'ca-cert-path' in cert:
                            cert['ca-cert-path'] = re.sub("^/root/", "/te_root/", cert['ca-cert-path'])
                        if 'cert-path' in cert:
                            cert['cert-path'] = re.sub("^/root/", "/te_root/", cert['cert-path'])
                        if 'key-path' in cert:
                            cert['key-path'] = re.sub("^/root/", "/te_root/", cert['key-path'])

            for host_ip, instance_profile_dict in te_dp_dict.items():

                #Get the mapping for the current host_ip
                vip_to_cert_map = cert_profile.get(host_ip, cert_profile.get('default', None))
                client_res_config[host_ip] = {}

                for instance_profile_tag in instance_profile_dict.keys():
                    res_tag = instance_profile_config[instance_profile_tag]['res-tag']
                    client_res = copy(resource_config[res_tag])
                    for vip_obj in client_res['vip-list']:
                        auth = vip_obj.get('auth',False)
                        vip = vip_obj['vip']
                        if auth:
                            if vip_to_cert_map is None:
                                problematicCert.append("Neither the mapping found for host_ip=%s not the 'default'" %host_ip)
                                continue
                            cert_list = vip_to_cert_map.get(vip, vip_to_cert_map.get('default', None))
                            if cert_list is None:
                                problematicCert.append("Neither the mapping found for vip=%s not the 'default' for host_ip=%s"\
                                    %(vip, host_ip))
                                continue
                            vip_obj['certs'] = cert_list
                        vip_obj.pop('auth',None)
                    client_res_config[host_ip][res_tag] = client_res

            if(bool(problematicCert)):
                self.lgr.error("Problem with certs %s" %str(problematicCert))
                return False, "Problem with certs", problematicCert

            return True, "", client_res_config

        except:
            return False, "Exception Occurred", traceback.format_exc()

    def __input_validation(self, te_dp_dict, instanceProfileConfig, resourceConfig, sessionConfig,
        is_update=True):

        if not(isinstance(te_dp_dict, dict)):
            return False, "te_dp_dict must be a dictionary"
        if not(isinstance(instanceProfileConfig, dict)):
            return False, "instanceProfileConfig must be a dictionary"
        if not(isinstance(resourceConfig, dict)):
            return False, "resourceConfig must be a dictionary"
        if not(isinstance(sessionConfig, dict)):
            return False, "sessionConfig must be a dictionary"

        reason_dict = {}
        checked_profile = {}

        for key, value in te_dp_dict.items():
            if not(isinstance(value, dict)):
                reason_dict[key] = "Value of the key must be a dict"
                continue

            instance_profile = value.get("instance_profile", None)
            if instance_profile is None and is_update:
                # Check is only for update_config
                reason_dict[key] = "instance_profile key cannot be None during update"
                continue

            elif instance_profile is not None:
                if not(isinstance(instance_profile, dict)):
                    # If it is not None, it must be a dictionary
                    reason_dict[key] = "Value of instance_profile must be a dict"
                    continue

                for instance_tag, count in instance_profile.items():

                    profile = instanceProfileConfig.get(instance_tag, None)
                    if profile is None:
                        reason_dict[key] = "instance_profile={} is not found in " \
                                            "instanceProfileConfig or is None".format(instance_tag)
                        break
                    if not isinstance(count, int):
                        reason_dict[key] = "Count in instance_profile must be integer"
                        break

                    # Profile is already checked
                    if checked_profile.get(instance_tag, False):
                        continue

                    if not isinstance(profile, dict):
                        reason_dict[key] = "{} tag in instanceProfileConfig must be " \
                                        "dict".format(instance_tag)
                        break
                    # res-tag and ses-tag can never be None in case of CLIENT
                    # ses-tag is not present in UDP SERVER
                    res_key = profile.get('res-tag', None)
                    ses_key = profile.get('ses-tag', None)
                    traffic_mode = profile.get('traffic-mode', "CLIENT").upper()
                    traffic_profile = profile.get('traffic-profile', "TCP").upper()

                    if traffic_profile == "TCP" and traffic_mode == "SERVER":
                        reason_dict[key] == "instance_profile={}: TCP SERVER is not supported by TE"

                    if res_key is None or (ses_key is None and traffic_mode == "CLIENT"):
                        reason_dict[key] = "Value of res-tag and ses-tag cannot be None in "\
                                        "instance_profile={}".format(instance_tag)
                        break
                    if(not(isinstance(res_key, str)) or \
                        (traffic_mode == "CLIENT" and not(isinstance(ses_key, str)))):
                        reason_dict[key] = "Value of res-tag and ses-tag must be str in "\
                                        "instance_profile={} res_key={} ses_key={}".format(\
                                        instance_tag, res_key, ses_key)
                        break
                    if resourceConfig.get(res_key, None) is None:
                        reason_dict[key] = "instance_profile={} had res-tag={} but was not found "\
                                            "in resourceConfig".format(instance_tag, res_key)
                        break
                    if ses_key is not None and sessionConfig.get(ses_key, None) is None:
                        reason_dict[key] = "instance_profile={} had ses-tag={} but was not found "\
                                            "in sessionConfig".format(instance_tag, ses_key)
                        break

                    # Compulsary params check (very basic, at best)
                    # Any Client must possess a vip-list to target
                    if traffic_profile == "CLIENT":
                        if(not(bool(resourceConfig[res_key].get('vip-list', None)))):
                            reason_dict[key] = "res-tag={} traffic-profile={} does not possess "\
                                "'vip-list'".format(res_key, traffic_profile)

                    #TCP Client
                    if traffic_mode == "TCP":
                        if(not(bool(resourceConfig[res_key].get('get-profiles', None)) or
                            bool(resourceConfig[res_key].get('post-profiles', None)))):
                            reason_dict[key] = "res-tag={} traffic-mode={} neither possess "\
                                "'get-profiles' nor 'post-profiles".format(res_key, traffic_mode)

                    #UDP Client
                    if traffic_mode == "UDP" and traffic_profile == "CLIENT":
                        if(not(bool(resourceConfig[res_key].get('udp-profiles', None)))):
                            reason_dict[key] = "res-tag={} traffic-mode={} traffic-profile={} "\
                                "does not possess 'udp-profiles'".format(res_key, traffic_mode,
                                traffic_profile)

                    #UDP Server
                    if traffic_mode == "UDP" and traffic_profile == "CLIENT":
                        if(not(bool(resourceConfig[res_key].get('port-list', None)) or
                            bool(resourceConfig[res_key].get('port-range', None)))):
                            reason_dict[key] = "res-tag={} traffic-mode={} neither possess "\
                                "'port-list' nor 'port-range".format(res_key, traffic_mode)
                    checked_profile[instance_tag] = True

        if bool(reason_dict):
            self.lgr.error("__input_validation: is_update={} \tte_dp_dict={} \t" \
                "instanceProfileConfig={} \tresourceConfig={} \tsessionConfig={} \t" \
                "reason_dict={}".format(is_update, te_dp_dict, instanceProfileConfig, \
                resourceConfig, sessionConfig, reason_dict))
            return False, reason_dict
        return True, reason_dict

    def __is_spawning_new_tedps_possible(self, te_dp_dict):
        resource_insuffcient_hosts = {}
        dict_after_validation = {}

        for host_ip, host_properties in te_dp_dict.items():
            if host_properties is None or host_properties.get('instance_profile',None) is None:
                continue
            inst_prof = host_properties['instance_profile']
            number_of_tedp_to_spawn = sum(host_properties['instance_profile'].values())
            notPossible = self.__tedp_config[host_ip].is_spinning_new_tedps_possible(number_of_tedp_to_spawn)
            if(notPossible is not None):
                resource_insuffcient_hosts[host_ip] = notPossible
                continue
            dict_after_validation[host_ip] = inst_prof

        if(bool(resource_insuffcient_hosts)):
            return False, "Resource insuffient to run te_dps", resource_insuffcient_hosts
        return True, "All conditions passed to spawn tedps", dict_after_validation

    def __get_udp_server_dict(self, te_dp_dict, instanceProfileConfig):
        if(not(bool(te_dp_dict))):
            return {}

        udp_server_tedp_dict = defaultdict(dict)
        for host in list(te_dp_dict.keys()):
            instance_profile_dict = te_dp_dict[host]
            for tag in list(instance_profile_dict.keys()):
                if(instanceProfileConfig[tag].get('traffic-mode', 'CLIENT').upper() == "SERVER"):
                    udp_server_tedp_dict[host][tag] = instance_profile_dict[tag]
                    te_dp_dict[host].pop(tag)
                    if(not(bool(te_dp_dict[host]))):
                        te_dp_dict.pop(host)

        return udp_server_tedp_dict

    @__api_state_decorator("START")
    def start_api(self, jsonContent):

        self.lgr.debug("start_api Called")

        isRequestValid = self.__checkForRequiredArgument(jsonContent, 
            ['te_dp_dict','resource_config','session_config','instanceProfileConfig'])
        if isRequestValid is not None:
            return isRequestValid

        resourceConfig = convert(jsonContent['resource_config'])
        sessionConfig = convert(jsonContent['session_config'])
        instanceProfileConfig = convert(jsonContent['instanceProfileConfig'])
        te_dp_dict = convert(jsonContent['te_dp_dict'])
        te_dp_dict_to_save = deepcopy(te_dp_dict)
        client_cert_bundle = convert(jsonContent.get('client_cert_bundle',None))
        max_tolerable_delay = int(convert(jsonContent.get('max_tolerable_delay', 120)))

        possible, reason = self.__are_all_tedps_connected(te_dp_dict)
        if(not(possible)):
            return self.__failure({"Unable to start on unconnected tedp machines":reason})

        possible, reason = self.__input_validation(te_dp_dict, instanceProfileConfig, \
            resourceConfig, sessionConfig, False)
        if(not(possible)):
            return self.__failure(reason)

        #DND important logic out there
        status, statusmessage, te_dp_dict_reduced = self.__is_spawning_new_tedps_possible(te_dp_dict)
        if(not(status)):
            return self.__failure({statusmessage:te_dp_dict_reduced})

        if(not(bool(te_dp_dict_reduced))):
            self.__CURRENT_STATE = self.__TE_STATE["RUNNING"]
            self.__success("Only state transition effected from INIT to RUNNING")

        if(client_cert_bundle is not None):
            status, msg, result = self.__generate_client_res_cfg(te_dp_dict_reduced, resourceConfig, \
                instanceProfileConfig, client_cert_bundle)
            if(not(status)):
                return self.__failure({msg:result})
            resource_config_to_spawn = result
            is_cert_replaced = True
        else:
            resource_config_to_spawn = resourceConfig
            is_cert_replaced = False

        # Start of the UDP server has to be done before starting the clients
        # Though the start of servers will run in parallel, starting of clients will
        # happen only after starting the clients (Sequential)
        result = {}
        udp_server_tedp_dict_to_start = \
            self.__get_udp_server_dict(te_dp_dict_reduced, instanceProfileConfig)
        self.lgr.debug("START UDP SERVER IN START_API %s" %str(udp_server_tedp_dict_to_start))
        if(bool(udp_server_tedp_dict_to_start)):
            status, msg_server_start, result_server_start = self.__spawn_or_update_tedps(\
                resource_config_to_spawn, sessionConfig, instanceProfileConfig, \
                udp_server_tedp_dict_to_start, max_tolerable_delay, is_cert_replaced)
            if(not(status)):
                return self.__failure({msg_server_start:result_server_start})
            result["server-start"] = result_server_start

        # As above iteration could have removed the the hosts from the dict all together
        if(bool(te_dp_dict_reduced)):
            status, msg, result_start = self.__spawn_or_update_tedps(resource_config_to_spawn, sessionConfig,\
                instanceProfileConfig, te_dp_dict_reduced, max_tolerable_delay, is_cert_replaced)
            result["client-start"] = result_start

        if status:
            self.__CURRENT_STATE = self.__TE_STATE["RUNNING"]
            self.__te_controller_obj.set_resource_config(resourceConfig)
            self.__te_controller_obj.set_session_config(sessionConfig)
            self.__te_controller_obj.set_instance_profile_config(instanceProfileConfig)
            self.__te_controller_obj.set_te_dp(te_dp_dict_to_save)
            if client_cert_bundle is not None:
                self.__te_controller_obj.set_client_cert_bundle(client_cert_bundle)
            return self.__success(result)
        else:
            return self.__failure({msg:result})

    ################################# STOP API ####################################

    def __stop_tedps(self, paramDict, max_tolerable_delay):
        try:

            CURRENT_TASK = "STOP"
            resultDict = {}
            for host_ip, listOfPid in paramDict.items():
                resultDict[host_ip] = self.__tedp_config[host_ip].stop_te_dp_helper(stop_te_dp, \
                    {'listOfPid':listOfPid})
                self.__TASK_DETAILS[CURRENT_TASK].append(host_ip)

            self.lgr.debug("result of stopping tedp %s" %(str(resultDict)))
            success = True
            for host_ip, result in resultDict.items():
                if not(isinstance(result, dict)) or result.get("Success",0) <= 0:
                    success = False
                    break
            if(not(success)):
                self.__tedp_config[host_ip].clean_task_details(CURRENT_TASK)
                self.__TASK_DETAILS[CURRENT_TASK] = []
                return False, "Unable to stop TEDPs (Fail at enqueue level)", resultDict

            status, result = self.__verify_task_status(CURRENT_TASK, max_tolerable_delay)
            if status:
                return True, "Stopped TEDPs", result
            return False, "Unable to stop TEDPs", result
        except:
            return False, "Exception Occured in __stop_tedps", traceback.format_exc()

    def __get_new_te_dp_to_set(self, te_dp_dict_stopped=None, list_of_profiles=None):
        if te_dp_dict_stopped is not None and list_of_profiles is not None:
            return None

        if te_dp_dict_stopped is None and list_of_profiles is None:
            return {}

        if list_of_profiles is not None:
            te_dp_dict_to_set = deepcopy(self.__te_controller_obj.get_te_dp())

            for host_ip in te_dp_dict_to_set.keys():
                profile = te_dp_dict_to_set[host_ip]['instance_profile']
                for profile_tag in profile.keys():
                    if profile_tag in list_of_profiles:
                        profile.pop(profile_tag)
                if(not(bool(profile))):
                    te_dp_dict_to_set.pop(host_ip)
            return te_dp_dict_to_set

        if te_dp_dict_stopped is not None:
            te_dp_dict_to_set = deepcopy(self.__te_controller_obj.get_te_dp())

            old_hosts = set(te_dp_dict_to_set.keys())
            stopped_hosts = set(te_dp_dict_stopped.keys())
            common_hosts = old_hosts.intersection(stopped_hosts)

            for host_ip in common_hosts:
                if te_dp_dict_stopped[host_ip] is None or \
                    te_dp_dict_stopped[host_ip]['instance_profile'] is None:
                    te_dp_dict_to_set.pop(host_ip)
                else:
                    profile_stopped = te_dp_dict_stopped[host_ip]['instance_profile']
                    to_set_profile_dict = te_dp_dict_to_set[host_ip]['instance_profile']
                    for profile_tag in profile_stopped.keys():
                        to_set_profile_dict = te_dp_dict_to_set[host_ip]['instance_profile']
                        to_set_profile_dict[profile_tag] -= profile_stopped[profile_tag]
                        if to_set_profile_dict[profile_tag] == 0:
                            to_set_profile_dict.pop(profile_tag)
                    if(not(bool(to_set_profile_dict))):
                        te_dp_dict_to_set.pop(host_ip)
            return te_dp_dict_to_set

    @__api_state_decorator("STOP")
    def stop_api(self, jsonContent):
        '''
            Integrate the stats collection logic to the code
            Args:
                by_instance_profile_tag: A dictionary mapping from host_ip to instance_profile to count to stop
        '''

        self.lgr.debug("stop_api Called")
        change_state_to_init = False

        by_host_and_instance_profile_tag = convert(jsonContent.get('by_host_and_instance_profile_tag',None))
        by_instance_profile_tag = convert(jsonContent.get('by_instance_profile_tag',None))
        max_tolerable_delay = int(convert(jsonContent.get('max_tolerable_delay', 120)))
        numberOfCallsMade = 0
        paramDict = defaultdict(set)

        if by_host_and_instance_profile_tag is not None and by_instance_profile_tag is not None:
            return self.__failure("Both params of by_host_and_instance_profile_tag and by_instance_profile_tag cannot be passed")

        elif by_host_and_instance_profile_tag is None and by_instance_profile_tag is None:
            change_state_to_init = True
            te_dp_dict = self.__te_controller_obj.get_te_dp()
            for host_ip in te_dp_dict.keys():
                listOfPidsRunningProfile = self.__tedp_config[host_ip].get_pid_of_running_tedps()
                if(bool(listOfPidsRunningProfile)):
                    paramDict[host_ip] = paramDict[host_ip].union(listOfPidsRunningProfile)
                else:
                    self.lgr.warning("No tedps is been run on %s" %host_ip)


        elif by_host_and_instance_profile_tag is not None:
            self.lgr.debug("Host Specific stop_api params population")

            possible, reason = self.__are_all_tedps_connected(by_host_and_instance_profile_tag)
            if(not(possible)):
                return self.__failure({"Unable to stop on unconnected tedp machines":reason})

            for host_ip, profile_map in by_host_and_instance_profile_tag.items():
                if profile_map is None or profile_map['instance_profile'] is None:
                    listOfPidsRunningProfile = self.__tedp_config[host_ip].get_pid_of_running_tedps()
                    self.lgr.debug("listOfPidsRunningProfile for by_host_and_instance_profile_tag=%s" \
                        %str(listOfPidsRunningProfile))
                    if(bool(listOfPidsRunningProfile)):
                        paramDict[host_ip] = paramDict[host_ip].union(listOfPidsRunningProfile)
                else:
                    for profile_name, count in profile_map['instance_profile'].items():
                        if count == 0:
                            continue
                        listOfPidsRunningProfile = \
                            self.__tedp_config[host_ip].get_pid_of_running_profiles([profile_name])
                        numberOfRunningProcess = len(listOfPidsRunningProfile)
                        #If count is None, delete all running profiles of the specific host
                        if count is None:
                            paramDict[host_ip] = paramDict[host_ip].union(listOfPidsRunningProfile)

                        #if numberOfRunningProcess is 0, then no process of that profile_name is running
                        elif numberOfRunningProcess == 0:
                            error_str = "stop_api uninitiated. Requested to kill %d instances of %s\
                                        but no process of that instance is running in host_ip= %s" \
                                        %(count, profile_name, host_ip)

                        #If count > numberOfRunningProcess, Improper parameter
                        elif count > numberOfRunningProcess:
                            error_str = "stop_api uninitiated. Requested to kill %d instances of %s\
                                but only %d running in host_ip=%s" \
                                %(count, profile_name, numberOfRunningProcess, host_ip)
                            self.lgr.errorerror_str
                            return self.__failure(error_str)

                        #Else stop count process running in the host_ip
                        else:
                            paramDict[host_ip] = paramDict[host_ip].union(listOfPidsRunningProfile[:count])

        elif by_instance_profile_tag is not None:
            self.lgr.debug("profile_tag Specific stop_api params population")
            for host_ip in self.__tedp_config:
                listOfPidsRunningProfile = \
                    self.__tedp_config[host_ip].get_pid_of_running_profiles(by_instance_profile_tag)
                if(bool(listOfPidsRunningProfile)):
                    paramDict[host_ip] = paramDict[host_ip].union(listOfPidsRunningProfile)

        if(bool(paramDict)):
            status, message, result = self.__stop_tedps(paramDict, max_tolerable_delay)
        else:
            return self.__failure("No tedps to stop")
        if(status):

            #Alter te_dp_dict for every stop
            self.lgr.debug("by_host_and_instance_profile_tag=%s"%str(by_host_and_instance_profile_tag))
            self.lgr.debug("by_instance_profile_tag=%s"%str(by_instance_profile_tag))
            te_dp_dict_to_set = self.__get_new_te_dp_to_set(te_dp_dict_stopped=by_host_and_instance_profile_tag, list_of_profiles=by_instance_profile_tag)
            self.lgr.debug("Final set te_dp_dict_to_set is %s" %str(te_dp_dict_to_set))
            self.__te_controller_obj.set_te_dp(te_dp_dict_to_set)

            #Unset others only on stop all call
            if change_state_to_init:
                self.__CURRENT_STATE = self.__TE_STATE["INIT"]
                self.__te_controller_obj.unset_resource_config()
                self.__te_controller_obj.unset_session_config()
                self.__te_controller_obj.unset_instance_profile_config()
                self.__te_controller_obj.unset_client_cert_bundle()
            else:
                self.__CURRENT_STATE = self.__TE_STATE["RUNNING"]
            return self.__success(result)
        return self.__failure({message:result})

    ################################# UPDATE API ####################################
    def __getModifiedConfigs(self, newConfig, oldConfig):
        try:
            self.lgr.debug("__getModifiedConfigs Called")
            newKeys = set(newConfig.keys())
            oldKeys = set(oldConfig.keys())
            modifiedKeys = newKeys - oldKeys
            intersectionKeys = newKeys.intersection(oldKeys)

            self.lgr.debug("newKeys = %s" %str(newKeys))
            self.lgr.debug("oldKeys = %s" %str(oldKeys))
            self.lgr.debug("modifiedKeys = %s" %str(modifiedKeys))
            self.lgr.debug("intersectionKeys = %s" %str(intersectionKeys))


            for key in intersectionKeys:
                if newConfig[key] != oldConfig[key]:
                    self.lgr.debug("Adding Key=%s" %key)
                    modifiedKeys.add(key)

            return modifiedKeys
        except:
            self.lgr.error("ERROR in __getModifiedConfigs: %s" %traceback.format_exc())
            return None

    def __getModifiedProfiles(self, oldInstanceProfileConfig, newInstanceProfileConfig, modifiedRes, \
        modifiedSes):
        try:
            self.lgr.debug("__getModifiedProfiles Called")
            oldKeys = set(oldInstanceProfileConfig.keys())
            newKeys = set(newInstanceProfileConfig.keys())
            commonKeys = newKeys.intersection(oldKeys)
            modifiedProfiles = newKeys - oldKeys

            self.lgr.debug("newKeys = %s" %str(newKeys))
            self.lgr.debug("oldKeys = %s" %str(oldKeys))
            self.lgr.debug("modifiedProfiles = %s" %str(modifiedProfiles))
            self.lgr.debug("commonKeys = %s" %str(commonKeys))

            for profile in commonKeys:
                res_tag = newInstanceProfileConfig[profile]['res-tag']
                ses_tag = newInstanceProfileConfig[profile].get('ses-tag', None)
                if res_tag in modifiedRes or (ses_tag is not None and ses_tag in modifiedSes):
                    self.lgr.debug("Adding Key=%s" %profile)
                    modifiedProfiles.add(profile)

            return modifiedProfiles
        except:
            self.lgr.error("ERROR in __getModifiedProfiles: %s" %traceback.format_exc())
            return None

    @__api_state_decorator("UPDATE")
    def update_config_api(self, jsonContent):
        self.lgr.debug("update_config_api Called")
        start_update_api_time = time.time()
        isRequestValid = self.__checkForRequiredArgument(jsonContent, ['resource_config',\
            'session_config','instanceProfileConfig','te_dp_dict'])
        if isRequestValid is not None:
            return isRequestValid

        resourceConfig = convert(jsonContent['resource_config'])
        sessionConfig = convert(jsonContent['session_config'])
        instanceProfileConfig = convert(jsonContent['instanceProfileConfig'])
        te_dp_dict = convert(jsonContent['te_dp_dict'])
        client_cert_bundle = convert(jsonContent.get('client_cert_bundle',None))
        max_tolerable_delay = int(convert(jsonContent.get('max_tolerable_delay', 120)))

        possible, reason = self.__are_all_tedps_connected(te_dp_dict)
        if(not(possible)):
            return self.__failure({"Unable to update on unconnected tedp machines":reason})

        possible, reason = self.__input_validation(te_dp_dict, instanceProfileConfig, \
            resourceConfig, sessionConfig)
        if(not(possible)):
            return self.__failure(reason)

        if not self.__te_controller_obj:
            self.lgr.errror("te_class object not found")
            return self.__failure('te_class object not found')

        old_resource_cfg = self.__te_controller_obj.get_resource_config()
        if old_resource_cfg is None:
            self.__failure("old resource cfg is None")

        old_session_cfg = self.__te_controller_obj.get_session_config()
        if old_session_cfg is None:
            self.__failure("old session cfg is None")

        old_instance_profile_config = self.__te_controller_obj.get_instance_profile_config()
        if old_instance_profile_config is None:
            self.__failure("old instance profile cfg is None")

        old_te_dp_dict = self.__te_controller_obj.get_te_dp()
        if old_te_dp_dict is None:
            self.__failure("old tedp dict is None")

        modifiedRes = self.__getModifiedConfigs(resourceConfig, old_resource_cfg)
        if modifiedRes is None:
            return self.__failure(traceback.format_exc())

        modifiedSes = self.__getModifiedConfigs(sessionConfig, old_session_cfg)
        if modifiedSes is None:
            return self.__failure(traceback.format_exc())

        modifiedProfiles = self.__getModifiedProfiles(old_instance_profile_config, \
            instanceProfileConfig, modifiedRes, modifiedSes)
        if modifiedProfiles is None:
            return self.__failure(traceback.format_exc())


        self.lgr.debug("modifiedRes=%s" %str(modifiedRes))
        self.lgr.debug("modifiedSes=%s" %str(modifiedSes))
        self.lgr.debug("modifiedProfiles=%s" %str(modifiedProfiles))

        oldTEDPhosts = set(old_te_dp_dict.keys())
        newTEDPhosts = set(te_dp_dict.keys())
        tedpsToStop   = oldTEDPhosts - newTEDPhosts
        tedpsToModify = newTEDPhosts.intersection(oldTEDPhosts)
        tedpsToSpawn = newTEDPhosts - oldTEDPhosts

        te_dp_dict_to_stop = defaultdict(set)
        te_dp_dict_to_spawn = defaultdict(dict)
        te_dp_dict_to_update = defaultdict(dict)
        problematicHost = {}

        for host_ip in tedpsToStop:
            listOfPidsRunningProfile = self.__tedp_config[host_ip].get_pid_of_running_tedps()
            if(bool(listOfPidsRunningProfile)):
                te_dp_dict_to_stop[host_ip] = te_dp_dict_to_stop[host_ip].union(listOfPidsRunningProfile)

        for host_ip in tedpsToSpawn:
            instance_profile = te_dp_dict[host_ip]['instance_profile']
            number_of_tedps_to_spawn = sum(instance_profile.values())
            notPossible = self.__tedp_config[host_ip].is_spinning_new_tedps_possible(number_of_tedps_to_spawn)
            if(notPossible is not None):
                problematicHost[host_ip] = notPossible
                continue
            te_dp_dict_to_spawn[host_ip] = instance_profile

        self.lgr.debug("Old tedp dict was %s" %str(old_te_dp_dict))
        for host_ip in tedpsToModify:
            '''
                Possible cases:
                    1) Modification of profile with Increase/Decrease in count
                    2) Unmodified Profile with Increase/Decrease in count
                    5) Presence of a new tag(in tedp_dict) in te_dp_dict
                    4) Deletion of a tag(in tedp_dict) from old te_dp_dict
            '''
            newProfileDict = te_dp_dict[host_ip]['instance_profile']
            old_value_of_host = old_te_dp_dict.get(host_ip, None)
            if old_value_of_host is not None:
                oldProfileDict = old_value_of_host.get('instance_profile',{})
                if oldProfileDict is None:
                    oldProfileDict = {}
            else:
                oldProfileDict = {}

            newKeys = set(newProfileDict.keys())
            oldKeys = set(oldProfileDict.keys())

            addedTags = newKeys - oldKeys
            deletedTags = oldKeys - newKeys
            commonTags = newKeys.intersection(oldKeys)

            numberOfTEDPsToStop = 0
            numberOfTEDPsToSpawn = 0

            for profile in addedTags:
                count = te_dp_dict[host_ip]['instance_profile'][profile]
                te_dp_dict_to_spawn[host_ip][profile] = count
                numberOfTEDPsToSpawn += count

            for profile in deletedTags:
                listOfPidsRunningProfile = self.__tedp_config[host_ip].get_pid_of_running_profiles([profile])
                if(listOfPidsRunningProfile):
                    te_dp_dict_to_stop[host_ip] = te_dp_dict_to_stop[host_ip].union(listOfPidsRunningProfile)
                    numberOfTEDPsToStop += len(listOfPidsRunningProfile)

            for profile in commonTags:
                updateFlag = False
                if profile in modifiedProfiles:
                    updateFlag = True

                listOfPidsRunningProfile = self.__tedp_config[host_ip].get_pid_of_running_profiles([profile])
                number_of_new_tedps_to_run = te_dp_dict[host_ip]['instance_profile'][profile]
                number_of_tedps_running = len(listOfPidsRunningProfile)
                difference = abs(number_of_new_tedps_to_run - number_of_tedps_running)

                #SPAWN AND UPDATE
                if number_of_new_tedps_to_run > number_of_tedps_running:
                    te_dp_dict_to_spawn[host_ip][profile] = difference
                    numberOfTEDPsToSpawn += difference
                    if updateFlag:
                        te_dp_dict_to_update[host_ip][profile] = number_of_tedps_running

                #STOP AND UPDATE
                elif number_of_new_tedps_to_run < number_of_tedps_running:
                    if(bool(listOfPidsRunningProfile)):
                        te_dp_dict_to_stop[host_ip] = te_dp_dict_to_stop[host_ip].union(listOfPidsRunningProfile[:difference])
                        numberOfTEDPsToStop += difference
                    if updateFlag:
                        te_dp_dict_to_update[host_ip][profile] = number_of_new_tedps_to_run
                #UPDATE (No change in count)
                elif updateFlag:
                    te_dp_dict_to_update[host_ip][profile] = number_of_tedps_running

            notPossibleToRun = self.__tedp_config[host_ip].is_update_possible(numberOfTEDPsToStop, \
                numberOfTEDPsToSpawn)
            if(bool(notPossibleToRun)):
                problematicHost[host_ip] = notPossibleToRun

        if(bool(problematicHost)):
            return self.__failure(problematicHost)

        self.lgr.debug("STOP IN UPDATE_API %s" %str(te_dp_dict_to_stop))
        self.lgr.debug("START IN UPDATE_API %s" %str(te_dp_dict_to_spawn))
        self.lgr.debug("UPDATE IN UPDATE_API %s" %str(te_dp_dict_to_update))
        self.lgr.debug("TIME TAKEN FOR PREPROCESSING %s" %str(time.time() - start_update_api_time))

        #GENERATE CLIENT RES CONFIG
        if(bool(client_cert_bundle)):
            gen_start = time.time()
            dict_to_update_and_spawn = deepcopy(te_dp_dict_to_spawn)
            dict_merge(dict_to_update_and_spawn, te_dp_dict_to_update)
            status, msg, result = self.__generate_client_res_cfg(dict_to_update_and_spawn, \
                resourceConfig, instanceProfileConfig, client_cert_bundle)
            if(not(status)):
                return self.__failure({msg:result})
            resource_config_to_spawn_and_update = result
            is_cert_replaced = True
            self.lgr.debug("Time taken to GEN CERT PROFILE %s" %str(time.time() - gen_start))
        else:
            resource_config_to_spawn_and_update = resourceConfig
            is_cert_replaced = False

        result = {}
        #STOP TEDPs
        if(bool(te_dp_dict_to_stop)):
            stop_start = time.time()
            status, msg_stop, result_stop = self.__stop_tedps(te_dp_dict_to_stop, max_tolerable_delay)
            if(not(status)):
                return self.__failure({msg_stop:result_stop})
            result["stop"] = {msg_stop:result_stop}
            self.lgr.debug("Time taken to STOP %s" %str(time.time() - stop_start))

        # Servers will have to be started / updated before starting / updating the client
        # So a separate call has to be made to make sure Servers are up and running, before the client starts

        # Calls to verify_task status is avoided in both spawn and update methods
        # This is done to quicken the process of enqueuing task, without worrying about the result
        # We later make a call to verify the task status

        #UPDATE UDP SERVER TEDPs
        is_udp_servers_updated = False
        udp_server_tedp_dict_to_update = \
            self.__get_udp_server_dict(te_dp_dict_to_update, instanceProfileConfig)
        self.lgr.debug("UPDATE UDP SERVER IN UPDATE_API %s" %str(udp_server_tedp_dict_to_update))
        if(bool(udp_server_tedp_dict_to_update)):
            is_udp_servers_updated = True
            status, msg_update, result_update = self.__spawn_or_update_tedps(\
                resource_config_to_spawn_and_update, sessionConfig, instanceProfileConfig, \
                udp_server_tedp_dict_to_update, max_tolerable_delay, is_cert_replaced, updateFlag=True, \
                verify_result=False)
            if(not(status)):
                return self.__failure({msg_update:result_update})

        #START UDP SERVER TEDPs
        is_udp_servers_spawned = False
        udp_server_tedp_dict_to_start = \
            self.__get_udp_server_dict(te_dp_dict_to_spawn, instanceProfileConfig)
        self.lgr.debug("START UDP SERVER IN UPDATE_API %s" %str(udp_server_tedp_dict_to_start))
        if(bool(udp_server_tedp_dict_to_start)):
            is_udp_servers_spawned = True
            status, msg_start, result_start = self.__spawn_or_update_tedps(\
                resource_config_to_spawn_and_update, sessionConfig, instanceProfileConfig, \
                udp_server_tedp_dict_to_start, max_tolerable_delay, is_cert_replaced, verify_result=False)
            if(not(status)):
                return self.__failure({msg_start:result_start})

        #Verifying the task status for update of UDP SERVER
        if(is_udp_servers_updated):
            status, result_update = self.__verify_task_status("UPDATE", max_tolerable_delay)
            if(not(status)):
                return self.__failure({"Error in __verify_task_status of update of UDP SERVER":result_update})
            if(bool(result_update)):
                result["server-update"] = result_update

        #Verifying the task status for spawn of UDP SERVER
        if(is_udp_servers_spawned):
            status, result_start = self.__verify_task_status("START", max_tolerable_delay)
            if(not(status)):
                return self.__failure({"Error in __verify_task_status of start of UDP SERVER":result_start})
            if(bool(result_start)):
                result["server-start"] = result_start

        #UPDATE TEDPs (All except UDP SERVERS)
        if(bool(te_dp_dict_to_update)):
            status, msg_update, result_update = self.__spawn_or_update_tedps(\
                    resource_config_to_spawn_and_update, sessionConfig, instanceProfileConfig, \
                    te_dp_dict_to_update, max_tolerable_delay, is_cert_replaced, updateFlag=True, \
                    verify_result=False)
            if(not(status)):
                return self.__failure({msg_update:result_update})

        #SPAWN TEDPS (All except UDP SERVERS)
        if(bool(te_dp_dict_to_spawn)):
            status, msg_start, result_start = self.__spawn_or_update_tedps(
                    resource_config_to_spawn_and_update, sessionConfig, instanceProfileConfig, \
                    te_dp_dict_to_spawn, max_tolerable_delay, is_cert_replaced, verify_result=False)
            if(not(status)):
                return self.__failure({msg_start:result_start})

        #Verifying the task status for update (All except UDP SERVERS)
        status, result_update = self.__verify_task_status("UPDATE", max_tolerable_delay)
        if(not(status)):
            return self.__failure({"Error in __verify_task_status of update":result_update})
        if(bool(result_update)):
            result["client-update"] = result_update

        #Verifying the task status for spawn (All except UDP SERVERS)
        status, result_start = self.__verify_task_status("START", max_tolerable_delay)
        if(not(status)):
            return self.__failure({"Error in __verify_task_status of start":result_start})
        if(bool(result_start)):
            result["client-start"] = result_start

        self.lgr.debug("Setup Completed tedps after update is: %s" %str(self.__setup_completed_tedps))

        if(bool(result)):
            self.__CURRENT_STATE = self.__TE_STATE["RUNNING"]
            self.__te_controller_obj.set_resource_config(resourceConfig)
            self.__te_controller_obj.set_session_config(sessionConfig)
            self.__te_controller_obj.set_instance_profile_config(instanceProfileConfig)
            self.__te_controller_obj.set_te_dp(te_dp_dict)
            if client_cert_bundle is not None:
                self.__te_controller_obj.set_client_cert_bundle(client_cert_bundle)
            return self.__success(result)
        else:
            return self.__failure("Nothing to update")

    def __execute_command(self, cmd):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        # Both Python 2 & 3 compliant
        if out is not None:
            out = out.decode('utf-8')
        if err is not None:
            err = err.decode('utf-8')
        return (out,err)

    def grafana_api(self, jsonContent):
        self.lgr.info("Grafana api is called.")
        grafana_service_state = convert(jsonContent['state'])

        if grafana_service_state == False or grafana_service_state == 'False' or grafana_service_state == 'false':
            cmd = "service grafana-server stop"
            (out, err) = self.__execute_command(cmd)
            if err is None:
                return self.__success("Grafana sevice stopped successfully")
        else:
            # Default port for grafana
            grafana_port = "5002"
            
            #Uncomment this line in grafana.in config file, to set the the port number
            subprocess.call("sed -i 's/;http_port/http_port/g' /etc/grafana/grafana.ini" , shell=True)

            #Check if the default port is pre-occupied or not, if occupied assign a random port
            cmd_check_port = "netstat -planet | grep -x {} | wc -l".format(grafana_port)
            (count, err) = self.__execute_command(cmd_check_port)
            if err is not None:
                return self.__failure("ERROR Occured with netstat command! {}".format(err))
            
            tries_limit = 0
            available = True
            if int(count) > 0:
                # Assign a random port
                while available:
                    grafana_port = str(random.randrange(1100, 8000))
                    cmd_check_port = "netstat -planet | grep -x {} | wc -l".format(grafana_port)
                    (count_val, err) = self.__execute_command(cmd_check_port)
                    if tries_limit<10:
                        if int(count_val) > 0:
                            tries_limit = tries_limit + 1
                            continue
                        if int(count_val) == 0:
                            available =  False
                            break
                    else:
                        return self.__failure("Maximum try exceeded Port ain't avaialbe, plz restart the service or free up some port!!")

            return_val = subprocess.call("sed -i 's/http_port = [0-9]*/http_port = {}/g' /etc/grafana/grafana.ini".format(grafana_port) , shell=True)
            if return_val != 0:
                return self.__failure("Grafana Port Not Intialized Error occured!!")

            url = str(self.__te_controller_obj.get_daemon_ip()) + ":" + grafana_port

            cmd = "service grafana-server start"
            (out, err) = self.__execute_command(cmd)
            if err is None:
                return self.__success("Grafana Service Started ,Hit this url ( {} ) on your browser, Enter User name and Password as 'admin' on login page ".format(url))
            else:
                self.lgr.debug("Grafana server failed to start {}".format(err))
                self.__failure("Grafana server failed to start {}".format(err))
                

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m','--Mgmt_IP',type=str, required=True,
            help='Mgmt IP for the TE and Redis to use for all TE_DP')
    parser.add_argument('-np','--nginx_port',type=str, required=True,
            help='Port for nginx to bind')
    parser.add_argument('-rp','--redis_port',type=str, required=True,
            help='Port for redis to bind')
    parser.add_argument('-fp','--flask_port',type=str, required=True,
            help='Port for flask to bind')
    parser.add_argument('-pp','--postgres_port',type=str, required=True,
            help='Port for postgres to bind')
    parser.add_argument('-zp','--zmq_port',type=str, required=True,
        help='Port for zmq to bind')
    parser.add_argument('-lp','--logpath',type=str, default='/tmp/',
            help='Log Path for TE')
    parser.add_argument('-ll','--loglevel',type=int, default=10,
            help='Log Level for TE')
    parser.add_argument('-ct','--stat_collect_interval',type=int, default=15,
            help='Time Interval at which Stat Collection must take place')
    parser.add_argument('-dt','--stat_dump_interval',type=int, default=15,
            help='Time Interval at which Stat Dumping by TEDP must take place')

    args = parser.parse_args()
    return args

def dump(te_daemon_ip, nginx_port, redis_port, flask_port, postgres_port, zmq_port, \
    stat_collect_interval, stat_dump_interval, loglevel):
    tedatajson = {
        'te_daemon_ip'          : te_daemon_ip,
        'nginx_ip'              : nginx_port,
        'redis_port'            : redis_port,
        'flask_port'            : flask_port,
        'postgres_port'         : postgres_port,
        'zmq_port'              : zmq_port,
        'stat_collect_interval' : stat_collect_interval,
        'stat_dump_interval'    : stat_dump_interval,
        'logpath'               : logpath,
        'loglevel'              : loglevel
    }
    te_file = open('/tmp/te-data.json', 'w')
    json.dump(tedatajson,te_file)
    te_file.close()


if __name__ == '__main__':
    args = parse_args()
    te_daemon_ip = args.Mgmt_IP
    nginx_port = args.nginx_port
    redis_port = args.redis_port
    flask_port = args.flask_port
    postgres_port = args.postgres_port
    zmq_port = args.zmq_port
    stat_collect_interval = args.stat_collect_interval
    stat_dump_interval = args.stat_dump_interval
    logpath = args.logpath
    loglevel = args.loglevel


    dump(te_daemon_ip, nginx_port, redis_port, flask_port, postgres_port, zmq_port, \
        stat_collect_interval, stat_dump_interval, loglevel)
    flask_obj = FlaskApplicationWrapper(te_daemon_ip, flask_port, redis_port, nginx_port, \
        postgres_port, zmq_port, stat_collect_interval, stat_dump_interval, logpath, loglevel)
    flask_obj.run()
