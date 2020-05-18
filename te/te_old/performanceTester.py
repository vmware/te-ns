from perf_test.json_input import *
from TE_WRAP import *
import traceback
import json
import sys, os, time, subprocess
from random import choice, randint
from copy import deepcopy


class Test_Scale:
    def __init__(self, te_target, pathToTrafficEngine=None, repo_path=None, repo_ip=None, repo_port=None, path_to_python_file_to_copy=None):
        self.__OUTPUT_DIR = os.path.join('perf_test','')
        self.__OUTPUT_FILE = os.path.join(self.__OUTPUT_DIR,'calls_and_output.json')
        self.__PRINT_FILE = os.path.join(self.__OUTPUT_DIR,'stdout_statements.txt')

        cmd = 'mkdir -p %s; rm -f %s; rm -f %s; touch %s; touch %s' %(self.__OUTPUT_DIR, self.__OUTPUT_FILE, self.__PRINT_FILE,\
        self.__OUTPUT_FILE, self.__PRINT_FILE)
        out, err = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True).communicate()
        if err:
            print("Unable to create %s to dump outputs" %self.__OUTPUT_FILE)
            sys.exit(1)

        self.__aviTE = AviTE(te_target)
        result = self.__aviTE.setup_te(pathToTrafficEngine=pathToTrafficEngine, repo_path=repo_path, repo_port=repo_port,
        repo_ip=repo_ip, path_to_python_file_to_copy=path_to_python_file_to_copy)
        if(not(result.get('status', False))):
            sys.exit(1)
        self.__printer("SETUP TE SUCCESSFUL")

    def __printer(self, string_to_write):
        with open(self.__PRINT_FILE,'a') as h:
            h.write("{}\n".format(str(string_to_write)))

    def __dump_details(self, type_of_call, result, input, time_taken):
        status = result.get('status',False)
        if(not(status)):
            self.__printer("ERROR in %s" %type_of_call)
            self.__printer(result)
            sys.exit(1)
        else:
            self.__printer("It took %ss to complete the call to %s" %(str(time_taken), type_of_call))
            active_te_dp = self.get_active_tedp()
            with open(self.__OUTPUT_FILE,'a') as h:
                h.write("\n######################## %s ########################\nINPUT => \n" %type_of_call)
                h.write(json.dumps(input, sort_keys=True, indent=4))
                h.write("\nRESULT => \n")
                h.write(json.dumps(result, sort_keys=True, indent=4))
                h.write("\nACTIVE => \n")
                h.write(json.dumps(active_te_dp, sort_keys=True, indent=4))
            if(not(active_te_dp['status']) and active_te_dp['statusmessage']!="No te_dps are running"):
                self.__printer("COUNT NOT RELIABLE")
                sys.exit(1)

    def set_controller_flask_port(self, port):
        self.__aviTE.set_controller_flask_port(port)

    def setup_tedp(self, te_dp_dict):
        start = time.time()
        result = self.__aviTE.setup_tedp(te_dp_dict)
        self.__dump_details("SETUP_TE_DP", result, te_dp_dict, time.time() - start)

    def connect_tedp(self, te_dp_dict):
        start = time.time()
        result = self.__aviTE.connect(te_dp_dict)
        self.__dump_details("CONNECT", result, te_dp_dict, time.time() - start)

    def start_tedp(self, resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle):
        start = time.time()
        result = self.__aviTE.start(resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle)
        self.__dump_details("START", result, te_dp_dict, time.time() - start)

    def update_config(self, resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle):
        start = time.time()
        result = self.__aviTE.update_config(resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle)
        self.__dump_details("UPDATE", result, te_dp_dict, time.time() - start)

    def stop_tedp(self, temp_te_dp_dict=None):
        start = time.time()
        result = self.__aviTE.stop(by_host_and_instance_profile_tag=temp_te_dp_dict)
        self.__dump_details("STOP", result, {'Stop':'No param'}, time.time() - start)

    def get_active_tedp(self):
        return self.__aviTE.get_active_tedp()


    def clear_config(self, clean):
        start = time.time()
        result = self.__aviTE.clear_config(clean)
        self.__dump_details("CLEAR_CONFIG", result, {'clear_config':'No param'}, time.time() - start)
        with open(self.__OUTPUT_FILE,'a') as h:
            h.write("\n\n######################## COMPLETED CYCLE ########################\n\n")

    def run(self, resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle):

        cycles = 3
        num_of_updates_in_a_cycle = 20
        delay_bw_each_update = 20
        MAX_PROC = 3

        for count in range(cycles):
            self.__printer("STARTING THE RUN")
            self.setup_tedp(te_dp_dict)
            self.__printer("SETUP COMPLETETED")
            self.connect_tedp(te_dp_dict)
            self.start_tedp(resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle)

            #Just for the sake of it
            if count == 0:
                time.sleep(10)
                self.stop_tedp()
                self.clear_config(False)
                time.sleep(5)
                self.connect_tedp(te_dp_dict)
                self.start_tedp(resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle)

            num_of_updates = 0

            for i in range(num_of_updates_in_a_cycle):
                num_sess = randint(1,10)
                session_config['ses_1']['num-sessions'] = int(num_sess)
                num_reqs = randint(1,100)
                session_config['ses_1']['requests-range'] = [int(num_reqs),int(num_reqs)]
                num_conns = 1
                session_config['ses_1']['connection-range'] = [int(num_conns),int(num_conns)]

                url = choice([True, False])
                if url:
                    resource_config['res_1']['url-list'][0]['url'] = '128kb.txt'
                else:
                    resource_config['res_1']['url-list'][0]['url'] = '128b.txt'

                temp_te_dp_dict = deepcopy(te_dp_dict)
                number_of_tedps_to_reduce = randint(0,2)
                popped_items = []
                for _ in range(number_of_tedps_to_reduce):
                    key_to_pop = choice(temp_te_dp_dict.keys())
                    temp_te_dp_dict.pop(key_to_pop)
                    popped_items.append(key_to_pop)

                for client, details in temp_te_dp_dict.items():
                    num_proc = randint(1,MAX_PROC)
                    instance_profile_choice = choice([1,2,3])
                    if instance_profile_choice == 1: #Only instance 1
                        details['instance_profile'] = {'tedp_inst1' : num_proc}
                    elif instance_profile_choice == 2: #Only instance 2
                        details['instance_profile'] = {'tedp_inst2' : num_proc}
                    elif instance_profile_choice == 3:  #Instance 1 and 2
                        if num_proc != MAX_PROC:
                            details['instance_profile'] = {'tedp_inst1' : num_proc, 'tedp_inst2' : MAX_PROC - num_proc}
                        else:
                            details['instance_profile'] = {'tedp_inst2' : num_proc}
                    else:
                        self.__printer("Unknown choice to select instance_profile instance_profile_choice=" %instance_profile_choice)
                        sys.exit()

                self.__printer("Calling Update with removing the hosts %s" %popped_items)
                self.update_config(resource_config, session_config, instanceProfileConfig, temp_te_dp_dict, cert_bundle)
                self.__printer("SLEEPING FOR %d SECS" %delay_bw_each_update)
                time.sleep(delay_bw_each_update)
                self.stop_tedp(temp_te_dp_dict)
                num_of_updates += 1
                self.__printer("Completed %d updates" %num_of_updates)

            self.clear_config(True)
            time.sleep(5)
            self.__printer("########### Completed %d Cycles ##########" %num_of_updates)



if __name__ == "__main__":
    te_target = {'host': '10.52.0.184',
                'user': 'root',
                'passwd':'avi123'}
    #obj = Test_Scale(te_target, repo_path='stable-repo', repo_ip='10.52.0.185', repo_port='80', path_to_python_file_to_copy='/home/aravindhankrishnan/TE/test/TrafficEngine/te')
    obj = Test_Scale(te_target, pathToTrafficEngine='/home/aravindhankrishnan/TE/test/TrafficEngine')
    obj.run(resource_config, session_config, instanceProfileConfig, te_dp_dict, cert_bundle)

    print("DONE BROOOOOO")
