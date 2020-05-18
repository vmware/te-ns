## Session Configurations
* Session Configuration describes HOW to stress the app. How many concurrent sessions has to be maintained, how many connections to open per session, how many requests to send per session, should the session be alive for ever, if the sessions has to be ramped up slowly, if there must be delay induced between sessions, etc
* Session Configuration is the required configuration for CLIENTS only (TCP and UDP).
* Most parameters of session-configuration is same for both UDP and TCP Clients, so let us discuss the common parameters first and further follow it up with special parameters

### COMMON PARAMETERS FOR SESSION CONFIGURATION FOR CLIENTS
* **session-type** : String describing what is the type of the session. All persistance related details are shared across a session. Values include:
  * `Browser` :
    * In Browser mode the very 1st request is special and a failure of this request (non 2xx in HTTP(S) and timedout out in UDP) would stop and try to restart the session again.
    * Why is the 1st request so special:
      * The 1st request is used to get few persistence data in order to enable it from the client. This can include Cookies, Session ID, Headers etc, which shall be used to evaluate the persistance decision of the LB, to perform SSL session resumption and resend the cookies back to the server in order to enable the server to take persistance related decisions in the LB.
      * Also this helps in avoiding sending a known all failure requests.
  * `MaxPerf` :
    * This mode has no special 1st request feature in it, which means it can't do persistence evaluation, SSL session resumption, but can do large loads.

* **num-sessions** : Number of concurrent sessions to run of the above specified `session-type`. Please note than sessions are independant of each other (i.e) a failure or success of one session does not affect the other.

* **requests-range** : Range specifying number of requests to send in random per session. What will the type of these requests must be defined in the `resource-config` along with the ratio.

* **connection-range** : Range specifying number of connections to open in random at maximum per session. No more than `connection-range` connections will be concurrently opened at any given point in time per session. But in total a session can end up opening more than connection-range number of connection due to various failures.

* **cycle-type** : String describing what must the opened connections to after completing the given number of requests. The accepted values are:
  * `restart` : Close all the connections and restart the connection establishment.
  * `resume` : Avoid connection closure but continue with the opened connection till `num-cycles`.

* **num-cycles** : Number specifying how long must a session prevail.
  * A counter per session gets incremented whenever the specified requests are completed in that session.
  * The requests are resent till the counter reaches `num-cycles` either by restarting new connections or by resuming the connections as specified in `cycle-type`
  * Upon the counter reaching `num-cycles`, a session is cleared.
  * 0 specifies that a session never ceases to stop. (Default)

* **target-cycles** : Number specifying how many times must a session be restarted.
  * A counter per session gets incremented whenever the `num-cycles` is reached in that session.
  * The session is reset and restarted till counter reaches `target-cycles`.
  * Upon reaching `target-cycles` across sessions, the process ceases to exist.
  * 0 specifies that a process is ever running. (Default)

* **cycle-delay** : Range of time in milli-second using which there is a random delay induced between the cycles of a session. During this delay there is no requests sent over the wire from that session.

* **session-ramp-step** : In a real world scenario all the clients do not hit the endpoint at once. So in order to facilitate simulation of real world traffic, the sessions are started not at once, but in the steps mentioned here. Defaults to open all at one shot.

* **session-ramp-delay** : The sessions opened in the above said ramp up steps are opened wach between a delay (in seconds) specified in `session-ramp-delay`.


### CLIENT SESSION CONFIGURATION SAMPLE (COMPLETE LIST)

```
{
  "session-config" : [{
    "session-type"       : "Browser",
    "num-sessions"       : 20,
    "session-ramp-step"  : 2,
    "session-ramp-delay" : 15,

    "connection-range" : [5,10],
    "requests-range"   : [10,25],
    "cycle-type"       : "resume",
    "cycle-delay"      : [5000,7000],

    "num-cycles"   : 50,
    "taget-cycles" : 10,
  }]
}
```


### PARAMETER ONLY FOR SESSION CONFIGURATION FOR TCP CLIENT:
* **persistance** : Boolean describing if the client must check for persistance in it's end. By persistance we mean if the client is hitting the same server in the backend. In order to check for persistance, do the following in all the backend servers:
  * Inside `http {` of nginx.conf, add `add_header avi_srv_ip <your_ip>;`. This header will be set by the server in the response which is used by TE to evaluate for the same.
