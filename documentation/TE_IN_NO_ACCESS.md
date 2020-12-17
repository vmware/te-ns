Without SSH password / certs (No access manual approach)
========================================================

## Bring up TE
* Remove older containers if any
docker rm -f tev2.0

* ssh to controller machine and set the following variables
```
export CTRL_IP="10.79.169.156"
export FLASK_PORT="5000"
export REDIS_PORT="6378"
export NGINX_PORT="5001"
export POSTGRES_PORT="5432"
export ZMQ_PORT="5555"
export PATH_TO_IMAGE="/root"
```

* Please make sure the ports are not occupied using netstat / ss commands (if) not change the variables
```
netstat -planet | egrep "$FLASK_PORT|$REDIS_PORT|$NGINX_PORT|$POSTGRES_PORT|$ZMQ_PORT"
```

* Run the following commands:
```
docker images | grep -w te | awk '{print $3}' | xargs -I {} docker rmi -f {} && \
	docker load -i $PATH_TO_IMAGE/te_docker.tar
docker run --privileged -d -it --name tev2.0 --net=host -v /tmp/:/te_host/ \
	-v $HOME/.ssh/:/root/.ssh/ -e PYTHONUNBUFFERED=0 -e IPADRESS=$CTRL_IP \
	-e FLASK_PORT=$FLASK_PORT -e REDIS_PORT=$REDIS_PORT -e NGINX_PORT=$NGINX_PORT \
	-e POSTGRES_PORT=$POSTGRES_PORT -e ZMQ_PORT=$ZMQ_PORT te:v2.0
```

* Wait till all the above specified ports are up and listening
```
netstat -planet | egrep "$FLASK_PORT|$REDIS_PORT|$NGINX_PORT|$POSTGRES_PORT|$ZMQ_PORT"
```

## Bring up TEDP
* ssh to datapath machine

* Remove older containers if any
```
docker rm -f tedpv2.0
```

* Set the following variables
```
export DP_IP="10.79.169.150"
export CTRL_IP="10.79.169.156"
export FLASK_PORT="5000"
export PATH_TO_IMAGE="/root"
```

NOTE: Make sure the CTRL_IP and FLASK_PORT variables are same as that given to controller

* Run the following commands
```
rm -f /root/tedp_docker.tar; wget -q -T90 http://$CTRL_IP:$NGINX_PORT/tedp_docker.tar -P $PATH_TO_IMAGE
docker images | grep -w tedp | awk '{print $3}' | xargs -I {} docker rmi -f {} && \
	docker load -i $PATH_TO_IMAGE/tedp_docker.tar
docker run --privileged --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
	-v /tmp/:/te_host/ -v $HOME:/te_root/ -v $HOME/.ssh/:/root/.ssh/ \
	-v /var/run/netns:/var/run/netns \
	-e IPADDRESS=$DP_IP -e CTRL_IPADDRESS=$CTRL_IP \
	-e CTRL_FLASK_PORT=$FLASK_PORT --ulimit core=9999999999 \
	--name tedpv2.0 --net=host -d -it \
	--tmpfs /tmp/ramcache:rw,size=104857600 tedp:v2.0
```

Start the Traffic
=================

* Clone the repo from https://github.com/vmware/te-ns
* cd te/
* pip install scp requests
* ipython

```
In [1]: from TE_WRAP import TensTE

In [2]: flask_port = "5000"

In [3]: tec = {'host':'10.79.169.156', 'flask_port' : flask_port, 'user':'root'}

In [4]: obj = TensTE(tec)

In [5]: tedp_dict = {"10.79.169.156" : {}}

In [6]: obj.connect(tedp_dict)
Out[6]:
{'status': True,
 'statusmessage': "Initiated objects for TEDPs=['10.79.169.156'] to connect"}


In [7]: resource_config = {'res' : {
    'default-get-post-ratio': '1:0',
    'get-profiles': {'g1': [{'uri': '/index.html'}]},
    'http-version': '1.1',
    'vip-list': [{'get-profile': 'g1', 'vip': 'http://www.example.com'}]
}}

In [8]: session_config = {'ses'  : {
          'connection-range': [1, 1],
          'cycle-type': 'restart',
          'num-sessions': 4,
          'requests-range': [10, 10],
          'session-type' : 'MaxPerf'
         }
     }

In [9]: instanceProfileConfig = {'inst1' : {'res-tag': 'res', 'ses-tag': 'ses'}}

In [10]: tedp_dict = {
        "10.79.169.156" : {
            "instance_profile" : {"inst1" : 1}
        }
    }

In [11]: obj.start(resource_config, session_config, instanceProfileConfig, tedp_dict)
Out[11]:
{'status': True,
 'statusmessage': {'client-start': {'10.79.169.156': {'inst1': 1}}}}

## Increase number of client proceses (max is #cpu - 1)
In [12]: tedp_dict = {
        "10.79.169.156" : {
            "instance_profile" : {"inst1" : 3}
        }
    }

In [13]: obj.update_config(resource_config, session_config, instanceProfileConfig, tedp_dict)
Out[13]:
{'status': True,
 'statusmessage': {'client-start': {'10.79.169.156': {'inst1': 2}}}}

In [14]: obj.get_vip_metrics("TOTAL")
Out[14]:
{'status': True,
 'statusmessage': {'vip=http://www.example.com': {'bytes_download': 177317056.0,
 ..
 ..
}

In [15]: obj.stop()
Out[15]: {'status': True, 'statusmessage': {'10.79.169.156': {'inst1': 3}}}
```
