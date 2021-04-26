# Traffic Emulator for Network Service (TENS)

> Traffic Emulator for Network Service (henceforth abbreviated as TENS) is a distributed traffic generator tool having a separate data and control planes aimed at providing with extensive abilities to stress, validate, and report metrics and errors regarding various load balancing and server functionalities emulating multiple Browser sessions, clients, connections and requests at layers of L4 and L7 in a distributed fashion across multiple computes with a single endpoint of control.

## Why TENS?
* There are existing tools which does bits and pieces of what TENS can do, but have different ways of operation. TENS operates as a single end point with uniformly exposed APIs to orchestrate and validate traffic.
* Existing open source tools have different set of limitations, and none has all the features to validate a fully blown load balancer
* Commercial tools are expensive

## What it can do?
* Generate real world workloads by emulating multiple users, multiple sessions per user and multiple connections & requests per session across multiple computes.
* Provide with extensive metrics and error reporting at configurable intervals and at layers of L4(TCP/UDP), and L7(HTTP HTTPS).
* Detailed failure reporting with configurable sampled 5 tuple and reason of failure.
* Ability to support traffic generation from multiple source IPs and namespaces.
* Ability to stress the environment in dimensions of RPS, TPS, TPUT and CPS, apart from configurable large header sizes.
* Configurable mechanism to ramp up the number of users and sessions, simulating a real world traffic behavior.
* Ability to run across multiple computes and controlled by single end point of APIs.
* Ability to control the traffic via APIs to start, stop and update.
* Get detailed metrics at a single endpoint at a granularity of what happened during any specified interval of time and space including but not limited to the 5 tuple of generated traffic at a level of a URI of an app hit by a client.
* Generate traffic with embedded cookies, headers, query parameters at a very large scales at L7.
* Evaluation of persistant decision making capabilities of load balancer utilizing cookie, session id and client ip persistence at L7.
* Ability to send HTTP(S) traffic across versions of HTTP/1, HTTP/1.1 and HTTP/2 at L7.
* Ability to send traffic with various cipher suites and SSL versions of SSLv2, SSLv3, TLSv1, TLSv1.0, TLSv1.1, TLSv1.2 and TLSv1.3 at L7.
* Ability to perform mutual client-server authentication by providing and veryfying certificates at L7.
* Ability to emulate uploads and downloads of large number of UDP datagrams at L4, with multiple concurrent connections.

## Libraries and Utilities Used
TENS functions with specific set of libraries and we are thankful to the maintainers and active contributors to the below mentioned libraries and utilities.

|   Libraries   |   Version  |       | Utilities  |
| :-----------: | :--------: | :---: | :--------: |
|   libcurl     |   7.67.0   |       | Postgresql |
|    libuv      |   1.27.0   |       |   ZeroMQ   |
|   openssl     |   1.1.1a   |       |     RQ     |
|   libjson     |   1.7.2-1  |       |   Flask    |
|               |            |       |    Nginx   |
|               |            |       |   Docker   |
## Compiling the datapath process
* Move to te_dp folder
	* `cd <work-space>/te_dp/`
* Install the necessary libraries (Only for debian)
	* `./setup.sh`
* Clean any existing binary
	* `make clean`
* Make the datapath and statistics collector process
	* `make all`

## How to access TENS
* As of today one can access the codes from the repository of github.`
	* Using the code, one can build and use TENS with 1 Controller and as many datapaths as required

## How to get a fully fledged TENS (With Controller)
* TENS has 2 parts to it. One is the TENS Controller and the other is TENS Datapath
* The Controller acts as a single point of access which exposes various apis to start, stop, update and get metrics from the data path process
* To get a sample run, please refer to SAMPLE-RUN.md in home directory:
       <work-space>/SAMPLE-RUN.md

## How to run a standalone datapath process
* bin/te_dp [options]

        -r resource_config         -- path to the resource configuration describing what traffic to send
        -j resource_config's-hash  -- hash/unique-identifier of the resource configuration
        [-s session_config]        -- path to the session configuration describing how to send the traffic
                                   -- To be used only in case of CLIENT
        [-k session_config's-hash] -- hash/unique-identifier of the session configuration
                                   -- To be used only in case of CLIENT

        [-p TCP/UDP]               -- profile of process
                                   -- UDP / TCP
                                   -- defaults to `TCP`

        [-a CLIENT/SERVER]         -- mode of the process
                                   -- CLIENT / SERVER
                                   -- defaults to `CLIENT`

        [-c pinned-cpu]            -- cpu to which the process is pinnned to
                                   -- compulsary argument only in case of UDP CLIENT profile

        [-i mgmt-ip]               -- management ip of the host
                                   -- compulsary argument only in case of UDP profile, both CLIENT AND SERVER

        [-d stats_dump_interval]   -- interval at which the collected metrics has to be dumped in seconds
                                   -- has to be used in conjuncture of options like [-m] and/or [-t]
                                   -- defaults to `NO` metrics dumping

        [-m]                       -- to enable collection of metrics
                                   -- enabling this option doesn't collect metrics regarding memory utilization
                                   -- defaults to `NO` metrics collection

        [-t]                       -- to enable collection of memory utilization metrics
                                   -- defaults to `NO` memory metrics collection

## What are resource and session configurations:
* Resource Configuration describes on *WHAT* to do. This includes details as what app to send traffic to, what HTTP version to use, what certificates to use for authentication, how many datagrams to send, etc.
* Session Configuration describes *HOW* to stress the app. How many concurrent sessions has to be maintained, how many connections to open per session, how many requests to send per session, should the session be alive for ever, if the sessions has to be ramped up slowly, if there must be delay induced between sessions, etc
* The options available in the TCP and UDP parts of the configurations are descibed seperately as RESOURCE_CONFIGURATION.md and SESSION_CONFIGURATION.md.


## Appendix
* In order for the datapath to work at maximum efficiency add the following knob in /etc/sysctl.conf
  ```
    net.ipv4.tcp_tw_recycle = 1
    net.ipv4.tcp_tw_reuse = 1
    net.ipv4.ip_local_port_range = 2048 65000
  ```
  * Run `sysctl -p` to reflect it.

* For a fully fledged TENS (with Controller), make sure the following are installed in the bare metal / VM
  * wget
  * python
  * python requests library
  * Docker (> v17.09.0-ce)
  * Base kernel (>3.15 of Ubuntu (or) equivalent)

* Install docker in ubuntu:
  ```
  apt-get update && \
  apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common && \
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
  add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" && \
  apt-get update && \
  apt-get install -y --force-yes docker-ce
  ```
