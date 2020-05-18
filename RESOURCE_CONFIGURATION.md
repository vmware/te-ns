## Resource Configurations
* Resource Configuration describes on **WHAT** to do. This includes details as what app to send traffic to, what HTTP version to use, what certificates to use for authentication, how many datagrams to send, etc.
* Resource Configuration is the required configuration for both TCP (Client) and UDP (Client and Server)
* The Resource configuration revolves around the vip-list, which is the list of vips to target. These vips are associated with post, get, upload, download, inteface profiles etc based on whether the process is running as UDP / TCP.


### COMMON PARAMETERS FOR RESOURCE CONFIGURATION
* **log-level** : String describing the level at which the logs of the process has to be written. (Defaults to "default"). The values can be
  * all
  * debug
  * screen
  * test
  * default

* **log-path** : String describing the path for the logs.


### COMMON PARAMETERS FOR RESOURCE CONFIGURATION FOR CLIENTS
* **vip-selection-rr** : Boolean desciribing how the VIPs have to be fired from the list of VIPs. Defaults to True. If False, VIPs are selected in random.


### TCP CLIENT RESOURCE CONFIGURATION EXPLANATION
* **get-profiles** : A map with custom name and value which is a list of object describing what to _GET_. It is tagged in the vip-list object with the key `get-profile`. Each object in the list can include:
  * headers : An object describing the HTTP headers to send (Defaults to nothing)
  * query-params : An object describing the parameters on which the destination app has to be queried (Defaults to nothing)
  * rate : Rate at which the get request must be capped at. (Defaults to inf) (in Bytes per Second)
  * size : Expected content length (Optional) (in Bytes)
  * uri : URI to get from (Required)
  * max-redirects : Maximum number of redirects that can be tolerated. (Defaults to 0)


* **post-profiles** : A map with custom name and value which is a list of object describing what to _POST_. It is tagged in the vip-list object with the key `post-profile`. Each object in the list can include:
  * headers : An object describing the HTTP headers to send (Defaults to nothing)
  * query-params : An object describing the parameters on which the destination app has to be queried (Defaults to nothing)
  * rate : Rate at which the post request must be capped at. (Defaults to inf) (in Bytes per Second)
  * size : Expected content length (Optional) (in Bytes)
  * uri : URI to post to (Required)
  * file : Local file that has to be posted (Either file or data)
  * data : Data that has to be posted (Either file or data)
  * max-redirects : Maximum number of redirects that can be tolerated. (Defaults to 0)

* **interface-profiles** : A map with custom name and value which is a list of object describing the source traffic of traffic. It is tagged in the vip-list object with the key `interface-profile`. Each object in the list can include:
  * if : Source interface to send out from (Optional - defaults to any interface)
  * ns : Source namespace to send out from (Optional - defaults to root namespace)

* **default-get-post-ratio** : The value specifies ratio at which the target vip must be targetted with GETs and POSTs. This value is used only if nothing is specified at the vip level. If one has to specify the ratio at vip level it must be specified using the key `get-post-profile`(Optional)

* **send-tcp-resets** : Boolean specifying if the client must send RST instead of FIN, where ever applicable

* **tcp-keepalive-timeout** : Value is seconds specifying the intervals at which TCP keep alive has to be sent. This value must be ideally be less than the TCP timeout at the server end.
  * Defaults to 20s.
  * 0 specifies to avoid sending TCP keep-alives

* **http-version** : String specifying the version of HTTP. Accepted values are:
  * 1.0
  * 1.1
  * 2.0tls
  * 2.0pk
  * 2.0

* **http-pipeline** : String specifying if pipelining has to be enabled. Applicable only in cases of HTTP/1.1 and HTTP/2.0. Accepted values are
  * HTTP1_PIPELINE
  * HTTP2_MULTIPLEX

* **ssl-version** : String specifying the version of SSL to use. Applicable only in case of HTTPS VIP. Accepted values are:
  * ssl
  * tlsv1.0
  * tlsv1.1
  * tlsv1.2
  * tlsv1.3

* **cipher-suites** : String seperated by colons specifying the cipher suites to use during the SSL handshake.

* **ssl-groups** : String specifying the SSL groups which will be sent during the Client Hello of SSL Handshake

* **ssl-session-reuse** : Boolean specifying if the SSL session has to be reused. This is implemented by caching the server response session id. Defaults to False.

* **cert** : It can be defined within each object within the `vip-list` as in input to the te_dp process. But if it is fed from TE Controller, in the interested VIPs where the certs has to be used one has to give the key `"auth" : True` and must seperately pass the cert profile during the start() or update() api call. The certs filed can contain the following fields:
  * "ca-cert-path" : Path to the CA Certifying authority. Passing this would verify the server end.
  * "cert-path" : Path to the client public certificate. Passing this would send the certificate to the server for its validation.
  * "key-path" : Path to the private key of the client. This must be passed along with "cert-path"
  * "passphrase" : Passphrase to open the private key of the client, if any.
  * "type" : Type of the certs and keys. Defaults to "PEM".
  * "enable-cname-verification" : Boolean to verify the cname of the server. Defaults to False.

* **set-cookies-resend** : Boolean specifying if the client must save the Set-Cookie sent by the server and resend it in future requests. This is used by server to understand the user and by Load balancer to make decisions on Load Balancing. Defaults to False.

### TCP CLIENT RESOURCE CONFIGURATION SAMPLE (COMPLETE LIST)

```
{
  "resource-config" : {
    "log-path"  : "/tmp/ramcache",
    "log-level" : "debug",

    "http-version"  : "1.1",
    "http-pipeline" : "HTTP1_PIPELINE",

    "ssl-groups"    : "prime256v1",
    "ssl-version"   : "tlsv1.3",
    "cipher-suites" : "NULL-MD5:NULL-SHA:RC4-MD5:RC4-SHA:IDEA-CBC-SHA"
    "ssl-session-reuse" : false,
    "set-cookies-reuse" : true,

    "tcp-keepalive-timeout" : 15,
    "send-tcp-resets"       : false,

    "default-get-post-ratio" : "1:1",
    "get-profiles" : {
      "g1" : [
        { "uri" : "index.html", "rate" : "10", "max-redirects" : 5, "size" : 128},
        { "uri" : "gmail", "query-params": { "cm": "true", "network": "u" },
          "headers" : {
            "X-AUSERNAME": "zhiqian.liu",
            "Cookie" : { "user" : "ak", "id" : "asdfas^er34123wsdas@#3q4343432"}
          }
        },
      ]
      "g2" : [{"uri" : "10KB.txt"}]
    },

    "post-profiles" : {
      "p1" : [{"uri" : "/post_destination.txt", "file" : "file_to_post.txt"}]
    },

    "interface-profiles" : {
      "i1" : [
        {"if" : "eth1", "ns" : "ns1"}, {"if" : "eth2.1"}, {"ns" : "ns2"}
      ]
    }

    "vip-list" : [
      {
        "vip"               : "https://www.google.com",
        "get-profile"       : "g1",
        "interface-profile" : "i1",
        "get-post-ratio"    : "1:0",
        "certs" : [{
          "ca-cert-path"              : "/root/te-cert-key/ca-chain.cert.pem",
          "enable-cname-verification" : false,
          "cert-path"                 : "/root/te-cert-key/client.cert.pem",
          "passphrase"                : "client_key",
          "key-path"                  : "/root/te-cert-key/client.key.pem",
          "type"                      : "PEM"
        }]
      },
      {
        "vip"          : "http://172.198.12.32",
        "get-profile"  : "g2",
        "post-profile" : "p1"
      }
    ]
  }
}
```


### UDP CLIENT RESOURCE CONFIGURATION EXPLANATION
* **udp-profiles** : A map with custom name and value which is a list of object describing what to what kind of udp datagrams to send. It is tagged at the vip-list's object using the key `udp-profile`. The value of the map is an object which has `download` and `upload` parts (at least one). Each of the upload and download further has request and response parts to it as:
  * request : An object describing the datagram details of the request. It comprises of:
    * num-datagram-range : A range between which a random number of datagrams is sent per request (boundaries inclusive)
    * datagram-size-range : A range between which a random size is chosen and all datagrams in that request is fired.
  * response : An object describing the datagram details of the expected response. It comprises of:
    * num-datagram-range : A range between which a random number of datagrams is expected per response (boundaries inclusive)
    * datagram-size-range : A range between which a random size is chosen and all datagrams in that response is expected of that size.
    * timeout : Number of milli seconds to wait before the request timeout. Defaults to 10000 ms.

* **default-download-upload-ratio** : The value specifies ratio at which the target vip must be targetted with DOWNLOADs and UPLOADs. This value is used only if nothing is specified at the vip level. If one has to specify the ratio at vip level it must be specified using the key `download-upload-profile`(Optional)

* **default-response-timeout** : The value specifies the timeout of a UDP request. It works on override mode, that is, if timeout is specified under `udp-profile`'s response then that is preferred.

### UDP CLIENT RESOURCE CONFIGURATION SAMPLE (COMPLETE LIST)
```
{
  "resource-config" : {
    "log-path" : "/tmp/ramcache/",
    "log-level" : "default"

    "default-download-upload-ratio" : "1:0",
    "default-response-timeout" : 20000
    "udp-profiles" : {
      "profile-1" : {
        "upload" : {
          "request" : {
            "num-datagram-range" : [10,10],
            "datagram-size-range" : [10,10]
          },
          "response" : {
            "num-datagram-range" : [1,1],
            "datagram-size-range" : [10,10]
          }
        },
        "download" : {
          "request" : {
            "num-datagram-range" : [1,1],
            "datagram-size-range" : [10,10]
          },
          "response" : {
            "num-datagram-range" : [10,10],
            "datagram-size-range" : [10,10],
            "timeout" : 10000
          }
        }
      },
      "profile-2" : {
        "download" : {
          "request" : {
            "num-datagram-range" : [2,5],
            "datagram-size-range" : [10,20]
          },
          "response" : {
            "num-datagram-range" : [100,100],
            "datagram-size-range" : [700,1000],
            "timeout" : 10000
          }
        }
      }
    },

    "vip-selection-rr" : true,
    "vip-list" : [
      {
        "vip"                   : "192.178.165.5:5003",
        "udp-profile"           : "profile-1",
        "download-upload-ratio" : "1:1"
      },
      {
        "vip"                   : "192.178.165.51:5001",
        "udp-profile"           : "profile-2"
      }
    ]
  }
}
```

### UDP SERVER RESOURCE CONFIGURATION EXPLANATION
* **port-range** : Range of ports to listen to. It includes both start and end ports. (port-range (or) port-list)
* **port-list** : List of ports to listen to. (port-range  (or) port-list)
* Only one of port-range / port-list can be used at once.

### UDP SERVER RESOURCE CONFIGURATION SAMPLE
```
{
  "resource-config" : {
    "type" : "server",
    "port-list" : [5003, 5004, 50010, 6001],
    "log-level" : "default",
    "log-path" : "/tmp/ramcache/"
  }
}
```
