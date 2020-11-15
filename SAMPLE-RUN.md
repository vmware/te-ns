A sample and simple get start of TE-NS
======================================

* TE-NS works as a single controller, multi-client traffic generator based on SDN paradigm
* The User interacts with the controller to start / stop / update traffic from the clients
* Pre-requisites on the user end
  - python3
  - pip3 installed paramiko, flask-swagger-ui, scp
* Pre-requisites on the client and controller VMs
  - community edition of docker version (preferrably 18.06+)
  - wget
  - python3
  - python3 / pip3 requests library
* To setup TE-NS Controller from UI, hit (REPO_IP):(REPO_PORT)/swagger
  Eg: http://127.0.0.1:4000/swagger
* To use TE-NS further, visit (TE_CONTROLLER_IP):(FLASK_PORT)/swagger
  eg: http://127.0.0.1:5000/swagger
* To use from the ipython3 / python3 shell
  - To use from python shell one would need TE_WRAP.py and GET_AND_RUN_DOCKER_IMAGE.py
  - The files are available in $git_repo/te (or) (TE-NS-REPO)
```
In [1]: from TE_WRAP import *

#BUILDING CONFIGS
In [2]: resource_config = {'res' : {
    'default-get-post-ratio': '1:0',
    'get-profiles': {'g1': [{'uri': '/index.html'}]},
    'http-version': '1.1',
    'vip-list': [{'get-profile': 'g1', 'vip': 'http://www.example.com'}]
}}

In [3]: session_config = {'ses'  : {
     'connection-range': [1, 1],
     'cycle-type': 'restart',
     'num-sessions': 4,
     'requests-range': [10, 10],
     'session-type' : 'MaxPerf'
    }
}

In [4]: instanceProfileConfig = {'tedp_inst1' : {'res-tag': 'res', 'ses-tag': 'ses'}}

In [5]: te_controller = {'host': '127.0.0.1',
            'user': 'root',
            'passwd':'tens123'}

In [6]: te_dp_dict = {
    '127.0.0.1': {'instance_profile': {'tedp_inst1': 1},
                    'passwd': 'tens123',
                    'tag': 'telocal1',
                    'user': 'root'}}

#MAKING AVI TE OBJECT
In [7]: te_ns_obj = TensTE(te_controller)

#SETUP TE
In [8]: te_ns_obj.setup_te(repo_ip='127.0.0.1', repo_path='te-ns-repo', path_to_python_file_to_copy='.')
TE Docker Image is hosted in {'ip': '127.0.0.1', 'port': '80', 'path_to_python_file_to_copy': '/root/ws/avi-dev/test/TrafficEngine/te', 'path': '/stable-repo/'}
Executing command = 'python /root/GET_AND_RUN_DOCKER_IMAGE.py -w /root/ -ip 127.0.0.1 -p 80 -b /stable-repo/ -t TE -h_ip 127.0.0.1             -ct 15 -dt 15 -lp /tmp/ -ll 10'
Exit code is 200
flask ==> 5000
postgres ==> 5432
nginx ==> 5001
.
.
.
.
.
.
Out[9]:
{'status': True,
 'statusmessage': {u'flask': u'5000',
  u'nginx': u'5001',
  u'postgres': u'5432'}}

#SETUP TEDP
In [10]: te_ns_obj.setup_tedp(te_dp_dict)
Out[10]: {u'status': True, u'statusmessage': u'Launched TEDPs'}

#CONNECT TE AND TEDP
In [11]: te_ns_obj.connect(te_dp_dict)
Out[11]: {u'status': True, u'statusmessage': u'Connected all TEs and TEDPs’}

#START TRAFFIC
In [12]: te_ns_obj.start(resource_config, session_config, instanceProfileConfig, te_dp_dict)
Out[12]: {u'status': True, u'statusmessage': {u'127.0.0.1': {u'tedp_inst1': 1}}}

#AT LEAST WAIT FOR 15 SECS BEFORE GETTING THE 1ST METRICS
In [13]: time.sleep(15)

#GET VIP METRICS
In [14]: te_ns_obj.get_vip_metrics("TOTAL")
Out[14]:
{u'status': True,
 u'statusmessage': {u'vip=http://www.example.com': {u'bytes_download': 2042256.0,
   u'connections': 160.0,
   u'cps': 10.6666666666667,
   u'failed_reqs': 0.0,
   u'http_gets_rcvd': 1626.0,
   u'http_gets_sent': 1640.0,
   u'http_posts_rcvd': 0.0,
   u'http_posts_sent': 0.0,
   u'latency-error-percentage': u'0.50696%',
   u'latency_max': 0.464061,
   u'latency_mean': 0.21264,
   u'latency_min': 0.031111,
   u'latency_p10': 0.08119,
   u'latency_p90': 0.34602,
   u'latency_p95': 0.38477,
   u'latency_p99': 0.45804,
   u'latency_p99.9': 0.53939,
   u'latency_sd': 0.10243,
   u'len_fail': 0.0,
   u'persist_fail': 0.0,
   u'reqs_sent': 1640.0,
   u'resp_rcvd': 1626.0,
   u'responses_1xx': 0.0,
   u'responses_200': 1626.0,
   u'responses_2xx': 1626.0,
   u'responses_3xx': 0.0,
   u'responses_404': 0.0,
   u'responses_4xx': 0.0,
   u'responses_5xx': 0.0,
   u'rps': 108.4,
   u'sessions': 0.0,
   u'tcp_failures': 0.0,
   u'tput': 136150.4}}}

#Updating Configs
In [15]: r = {
    u'default-get-post-ratio': u'1:0',
     u'get-profiles': {u'g1': [{u'uri': u'128b.txt'}]},
     u'http-version': u'1.1',
     u'vip-list': [{u'get-profile': u'g1', u'vip': u'http://www.example.com'}]
}

In [16]: s = {
    u'connection-range': [1, 1],
     u'cycle-type': u'restart',
     u'num-sessions': 4,
     u'requests-range': [1, 1],
     u'session-type': u'MaxPerf'
}

In [17]: resource_config = {'res' : r}

In [18]: session_config = {'ses'  :s}

#GETTING CURRENT TE TIME FOR FILTERING METRICS
In [19]: te_ns_obj.get_current_te_time()
Out[19]: {u'status': True, u'statusmessage': u'2019-05-27 09:51:09'}

#UPDATING TRAFFIC
In [20]: te_ns_obj.update_config(resource_config, session_config, instanceProfileConfig, te_dp_dict)
Out[20]:
{u'status': True,
 u'statusmessage': {u'Update': {u'All TEDPs Updated': {u'127.0.0.1': {u'tedp_inst1': 1}}}}}

#GETTING METRICS FOR ONLY THE UPDATED CONFIGS
In [21]: te_ns_obj.get_vip_metrics("TOTAL",filter_ts_range=['2019-05-27 09:51:09',None])
Out[21]:
{u'status': True,
 u'statusmessage': {u'vip=http://www.example.com': {u'bytes_download': 2110080.0,
   u'connections': 168.0,
   u'cps': 11.2,
   u'failed_reqs': 0.0,
   u'http_gets_rcvd': 1680.0,
   u'http_gets_sent': 1680.0,
   u'http_posts_rcvd': 0.0,
   u'http_posts_sent': 0.0,
   u'latency-error-percentage': u'1.01935%',
   u'latency_max': 0.376445,
   u'latency_mean': 0.20582,
   u'latency_min': 0.030962,
   u'latency_p10': 0.08128,
   u'latency_p90': 0.32927,
   u'latency_p95': 0.36412,
   u'latency_p99': 0.43115,
   u'latency_p99.9': 0.50419,
   u'latency_sd': 0.09876,
   u'len_fail': 0.0,
   u'persist_fail': 0.0,
   u'reqs_sent': 1680.0,
   u'resp_rcvd': 1680.0,
   u'responses_1xx': 0.0,
   u'responses_200': 1680.0,
   u'responses_2xx': 1680.0,
   u'responses_3xx': 0.0,
   u'responses_404': 0.0,
   u'responses_4xx': 0.0,
   u'responses_5xx': 0.0,
   u'rps': 112.0,
   u'sessions': 0.0,
   u'tcp_failures': 0.0,
   u'tput': 140672.0}}}

In [22]: te_ns_obj.stop()
Out[22]: {u'status': True, u'statusmessage': {u'127.0.0.1': {u'tedp_inst1': 1}}}
```
