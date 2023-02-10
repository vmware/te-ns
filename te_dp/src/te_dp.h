//**********************************************************************************************
// Traffic Emulator for Network Services
// Copyright 2020 VMware, Inc
// The BSD-2 license (the "License") set forth below applies to all parts of
// the Traffic Emulator for Network Services project. You may not use this file
// except in compliance with the License.
//
// BSD-2 License
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
// OF SUCH DAMAGE
//**********************************************************************************************

#ifndef TE_DP_H
#define TE_DP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <float.h>
#include "string.h"

#include <uv.h>
#include <curl/curl.h>

#define TEDP_MAX_STR_LEN 128

// For optimizations
#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

// UDP SERVER METRICS COLLECTION KNOB
// set to 1 to collect metrics from the perspective of vip
// set to 0 to collect metrics from the perspective of back end server
#define UDP_SERVER_VIP_END_METRICS 1

//TEDP PROFILE
//SUPPORTS TCP/UDP
typedef enum {TCP, UDP} tedp_profile_t;
typedef enum {CLIENT, SERVER} tedp_mode_t;

// Both tedp_profile and tedp_mode defaults to TE_UNDEFINED
// If not specified or understood during the input parsing, error is thrown
#define TE_UNDEFINED -1

//HASH TABLE SIZE
#define TE_SOCKET_HASH_TABLE_SIZE               10021
#define TE_UDP_SERVER_METRICS_HASH_TABLE_SIZE   23

//HTTP VERSION HASH DEFINITIONS
#define HTTP_1_0 143
#define HTTP_1_1 144
#define HTTP_2_0 145
#define HTTP_2_0_TLS 483
#define HTTP_2_0_PK 363

//HTTP PIPELINING HASH DEFINITIONS
#define HTTP_NOTHING 0
#define HTTP1_PIPELINE 1
#define HTTP2_MULTIPLEX 2

//SSL VERSIONS
#define SSL_DEFAULT 0
#define SSL_V1 1
#define TLS_V1_0 2
#define TLS_V1_1 3
#define TLS_V1_2 4
#define TLS_V1_3 5

#define TCP_ERR 0
#define INFO_RESP 1
#define SUCCESS 2
#define REDIRECTION 3
#define CLIENT_ERR 4
#define SERVER_ERR 5

#define TE_SESSION_STATE_CYCLE_START    0x0000
#define TE_SESSION_STATE_SEND_1ST_REQ   0x0001
#define TE_SESSION_STATE_SEND_ALL_REQ   0x0002
#define TE_SESSION_STATE_CYCLE_SLEEP    0x0003
#define TE_SESSION_STATE_CYCLE_END      0x0004
#define TE_SESSION_STATE_PAUSE          0x0005    //UNUSED
#define TE_SESSION_STATE_CYCLE_REMOVED  0x0006    //UNUSED
typedef unsigned short TE_SESSION_STATE;

//config states of session config.
#define TE_SESSION_CONFIG_STATE_START       0x0000
#define TE_SESSION_CONFIG_STATE_STOP        0x0001
#define TE_SESSION_CONFIG_STATE_RESUME      0x0002
#define TE_SESSION_CONFIG_STATE_PAUSE       0x0003  //NON-FUNCTIONAL
#define TE_SESSION_CONFIG_STATE_UPDATE_SESS 0x0004  //NON-FUNCTIONAL
#define TE_SESSION_CONFIG_STATE_UPDATE      0x0005  //NON-FUNCTIONAL
typedef unsigned short TE_SESSION_CONFIG_STATE;

//running states of session config.
#define TE_SESSION_CONFIG_STATE_READY   0x0008
#define TE_SESSION_CONFIG_STATE_RUNNING 0x0009
#define TE_SESSION_CONFIG_STATE_PENDING 0x000a

typedef unsigned short TE_SESSION_REQ;
//TCP
#define TE_SESSION_REQ_GET   0x0001
#define TE_SESSION_REQ_POST  0x0002
//UDP
#define TE_SESSION_REQ_UPLOAD  0x0003
#define TE_SESSION_REQ_DOWNLOAD  0x0004

typedef unsigned short TE_SESSION_PROTOCOL;
#define TE_SESSION_PROTOCOL_HTTP         0x0001
#define TE_SESSION_PROTOCOL_HTTPS        0x0002

typedef unsigned short TE_SESSION_TYPE;
#define TE_SESSION_TYPE_MAX_CONN_REQS      0x0001
#define TE_SESSION_TYPE_BROWSER            0x0002

typedef unsigned short TE_SESSION_CYCLE_TYPE;
#define TE_SESSION_CYCLE_RESUME    0x0001
#define TE_SESSION_CYCLE_RESTART   0x0002

//Inputs to te_dp
extern char res_cfg_path[TEDP_MAX_STR_LEN];
extern char session_cfg_path[TEDP_MAX_STR_LEN];
extern char res_hash[TEDP_MAX_STR_LEN];
extern char ses_hash[TEDP_MAX_STR_LEN];
extern char tedp_mgmt_ip_str[TEDP_MAX_STR_LEN];
extern unsigned int tedp_mgmt_ip;
extern short pid;
extern int stats_timer;
extern bool metrics_enabled;
extern bool memory_metrics_enabled;

//Definitions regarding Metrics
extern uv_timer_t dump_metrics_timer;

/////////////// ERROR METRICS ///////////////

//Custom TE ERRORS
//CURLE ERRORS is 0-93
//https://curl.haxx.se/libcurl/c/libcurl-errors.html
#define LENGTH_CHECK_FAIL   130
#define RESP_UNKNOWN        131
#define URL_TIME_EXCEEDED   132
#define PERSIST_CHECK_FAIL  133
#define POST_FILE_NOT_FOUND 134
#define RES_NOT_FOUND       404

typedef struct te_error_metrics_s {
    int    error_int;
    char   *error_name;
    time_t start_time;
    time_t end_time;
    int    err_counter;
    int    height;
    struct te_error_metrics_s *left, *right;
} te_error_metrics_t;

enum te_error_metrics_types {
    TCP_ERROR,
    HTTP_ERROR,
    SSL_ERROR
};

#define NUM_TYPES_OF_ERR 3

/////////////// URL METRICS ///////////////

typedef struct te_http_url_stats_s {
    unsigned int    reqs_sent;
    unsigned int    resp_rcvd;
    unsigned int    http_gets_sent;
    unsigned int    http_gets_rcvd;
    unsigned int    http_posts_sent;
    unsigned int    http_posts_rcvd;
    unsigned int    failed_reqs;
    unsigned int    len_fail;
    unsigned int    persist_fail;           //persist mismatches
    unsigned int    tcp_failures;           //TCP Connection Failures
    unsigned int    responses_1xx;          //Server processing or waiting for multiple responses
    unsigned int    responses_200;          //Default HTTP OK
    unsigned int    responses_2xx;          //Success
    unsigned int    responses_3xx;          //Resource moved or redirected
    unsigned int    responses_404;          //HTTP Res Not Found
    unsigned int    responses_4xx;          //CLient side error
    unsigned int    responses_5xx;          //Server side error e.g. server busy/under maintainence
    double          bytes_download;
    double          sum_latency;            //Total complete time
    double          sum_square_latency;     //Sum of squares of compute time (to calc variance)
    double          min_time;
    double          max_time;
} te_http_url_stats_t;

typedef struct te_udp_url_metrics_s {
    unsigned short  reqs_sent;
    unsigned short  reqs_failed;
    unsigned long   dg_sent;
    unsigned long   dg_size_sent;
    unsigned long   dg_send_fail;

    unsigned short  resp_recd;
    unsigned short  resp_timedout;
    unsigned long   dg_recd;
    unsigned long   dg_size_recd;
    unsigned long   dg_recv_timedout;

    double          sum_latency;
    double          sum_square_latency;
    double          min_latency;
    double          max_latency;
} te_udp_url_metrics_t;

typedef struct te_http_url_bucket_metrics_s {
    unsigned int bucket;
    double total_time;
    double bucket_start_time;
    double bucket_end_time;
} te_http_url_bucket_metrics_t;

typedef struct te_http_url_metrics_s {
    te_http_url_stats_t      url_stats;
    bool                     stats_present;
    short                    num_error_buckets;
    te_error_metrics_t*      error_metrics[NUM_TYPES_OF_ERR];
    //Session Bucket Stats (Buckets on how long a request take)
    short                         num_url_buckets;
    te_http_url_bucket_metrics_t* url_buckets;
} te_http_url_metrics_t;

/////////////// VIP METRICS ///////////////

typedef struct te_udp_vip_stats_s {
    unsigned int    sessions;
    unsigned int    good_connections;        /*Incremented for every new tuple that succeedes*/
    unsigned int    failed_connections;      /*Incremented for every new tuple that failes*/
} te_udp_vip_stats_t;

typedef struct te_http_vip_stats_s {
    unsigned int    sessions;
    unsigned int    connections;
    unsigned int    good_connections;
    unsigned int    failed_connections;
} te_http_vip_stats_t;

typedef struct te_http_session_bucket_metrics_s {
    unsigned int bucket;
    double total_time;
    double bucket_start_time;
    double bucket_end_time;
} te_http_session_bucket_metrics_t;

typedef struct te_http_vip_metrics_s {
    te_http_vip_stats_t               vip_stats;
    bool                              stats_present;
    //Session Bucket Stats (Buckets on how long a session last)
    short                             num_session_buckets;
    te_http_session_bucket_metrics_t* session_buckets;
    //URL Metrics for GET
    short                             num_url_get_metrics;
    te_http_url_metrics_t*            url_get_metrics;
    //URL Metrics for POST
    short                             num_url_post_metrics;
    te_http_url_metrics_t*            url_post_metrics;
} te_http_vip_metrics_t;

typedef struct te_udp_vip_metrics_s {
    te_udp_vip_stats_t                udp_vip_stats;
    bool                              stats_present;

    te_udp_url_metrics_t*             udp_download_metrics;
    bool                              download_stats_present;

    te_udp_url_metrics_t*             udp_upload_metrics;
    bool                              upload_stats_present;

    //Session Bucket Stats (Buckets on how long a session last)
    short                             num_session_buckets;
    te_http_session_bucket_metrics_t* session_buckets;
} te_udp_vip_metrics_t;

typedef struct udp_server_metrics_s {
    unsigned int dg_rcvd;             // dgs received from clients
    unsigned int dg_recv_timedout;    // dgs timedout before receiving from clients
    unsigned int dg_size_rcvd;        // size of dgs received from clients

    unsigned int dg_sent;             // dgs sent back to clients as response
    unsigned int dg_send_fail;        // dgs failed to send back to clients
    unsigned int dg_size_sent;        // size of dgs sent back to clients

    unsigned int request_rcvd;          // Total number of request received from the clients
    unsigned int request_recv_timedout; // Total number of requests timedout
    unsigned int response_sent;         // Responses sent back to clients
    unsigned int response_send_fail;    // Responses sent back to clients

    double       sum_latency;
    double       sum_square_latency;
    double       max_latency;
    double       min_latency;

    // dgs refer to datagrams and a bunch of dgs put together represent a request / response
} udp_server_metrics_t;

/////////////// SES METRICS ///////////////

typedef struct te_http_session_metrics_s {
    unsigned int    num_sessions;
    unsigned int    cycles_complete;
    unsigned int    open_connections;
    unsigned int    total_connections;
    unsigned int    reqs_sent;
    unsigned int    resp_rcvd;
    unsigned int    http_gets_sent;
    unsigned int    http_gets_rcvd;
    unsigned int    http_posts_sent;
    unsigned int    http_posts_rcvd;
    unsigned int    failed_reqs;
    unsigned int    len_fail;
    unsigned int    persist_fail; //persist mismatches
    unsigned int    post_fnf;     //POST Files Not Found
    double          bytes_download;
    double          complete_time;
}te_http_session_metrics_t;

typedef struct te_udp_session_metrics_s {
    unsigned int    num_sessions;
    unsigned int    cycles_complete;
    unsigned int    good_connections;
    unsigned int    failed_connections;

    unsigned short  reqs_sent;
    unsigned short  reqs_failed;
    unsigned long   dg_sent;
    unsigned long   dg_size_sent;
    unsigned long   dg_send_fail;

    unsigned short  resp_recd;
    unsigned short  resp_timedout;
    unsigned long   dg_recd;
    unsigned long   dg_size_recd;
    unsigned long   dg_recv_timedout;
} te_udp_session_metrics_t;

/////////////// CONFIGURATIONS /////////////// 

typedef struct te_session_config_s te_session_config_t;
typedef struct te_tcp_request_s te_tcp_request_t;
typedef struct te_session_s te_session_t;
typedef struct te_resource_config_s te_resource_config_t;

//Callbacks to move state of a session
void te_session_start(te_session_t*);
void te_session_send_1_st_request(te_session_t*);
void te_session_send_all_request(te_session_t*);
void te_session_sleep(te_session_t*);
void te_session_end(te_session_t*);

//Callbacks to move the state of a session_config
bool te_session_config_start(te_session_config_t*, TE_SESSION_CONFIG_STATE);
bool te_session_config_stop_or_update(te_session_config_t*, TE_SESSION_CONFIG_STATE);
bool te_session_config_resume(te_session_config_t*, TE_SESSION_CONFIG_STATE);
bool te_session_config_pause(te_session_config_t*, TE_SESSION_CONFIG_STATE);

typedef struct te_update_context_s {
    int diff; //calculate it on update
    unsigned short ramp_step_ctxt;
    unsigned int to_start;
} te_update_context_t;

#ifndef TE_UDP_LIB_H
#include "te_udp_lib.h"
#endif

#ifndef TE_SOCK_H
#include "te_sock.h"
#endif

#ifndef TE_AGENT_H
#include "te_agent.h"
#endif

#ifndef TE_UTILS_H
#include "te_utils.h"
#endif

#ifndef TE_TCP_DP_H
#include "te_tcp_dp.h"
#endif

#ifndef TE_UDP_DP_H
#include "te_udp_dp.h"
#endif

typedef struct te_write_context_s
{
    char *full_data;
    uv_stream_t *client;
    uv_buf_t buf;
} te_write_context_t;


typedef struct te_req_write_memory_s{
   char *memory;
   size_t size;
}te_req_write_memory_t;

typedef struct te_session_file_data_s {
   char trace_ascii; /* 1 or 0 */
   FILE *fdebug_handle;
   FILE *fdownload_handle;
   te_tcp_request_t *req;
} te_session_file_data_t;

typedef struct te_interface_s {
    char* nw_interface;
    char* nw_namespace;
    char* ns_descriptor;
} te_interface_t;

typedef struct te_tcp_request_s {
   unsigned int         prof_index;      // chosen index in requests list
   unsigned int         url_index;       // index of url chosen to update metrics.
   unsigned int         id;              // request_id for this session.
   TE_SESSION_REQ       req_type;        // request_type whether GET/POST.
   CURL                 *ce_handle;      // curl easy handle for opened conn.
   struct curl_httppost *formpost;       // post related request info
   struct curl_httppost *lastptr;        // post related request info
   struct curl_slist    *headerlist;     // post related request info.
   te_session_t         *sessionp;       // Back pointer for session.
   unsigned long        content_length;  // content length for each connection request.
} te_tcp_request_t;

typedef struct te_udp_request_s {
    //AK Revisit
    TE_SESSION_REQ    req_type;              // Type of datagram (UPLOAD / DOWNLOAD)
    unsigned int      dg_to_send;            // dgs to send to the server
    unsigned int      dg_sent;               // dgs sent (success + failure)
    unsigned int      dg_size_to_send;       // size of each datagram to send to the server
    unsigned int      dg_to_recv;            // dgs to receive from the server
    unsigned int      dg_rcvd;               // dgs rcvd (success + timedout)
    unsigned int      dg_size_to_recv;       // size of datagrams to expect from the server
    te_session_t*     session;               // back pointer to the session where the request belongs to
    udp_easy_handle_t *easy_handle;          // back pointer to the easy handle to which the request is associated to

    // Note that, session -> request is a 1 to many mapping, meaning 1 session can have multiple concurrent request
    // and easy_handle -> request is 1-to-1 mapping and easy_handle is a udp_library notation of the same request

} te_udp_request_t;

typedef struct te_tcp_session_s {
    CURLM                   *cm_handle;         // Multi handle associated with each session.
    CURLSH                  *share_handle;      // Share Interface for this session.
    uv_timer_t              cm_timer;           // uv timer handle for curl multi handle.

    te_interface_t          *interface_obj;     // a TCP session can choose to hit from a interface

    unsigned short          num_gets;           // number of get requests sent per session.
    unsigned short          num_posts;          // number of post requests per session.
    unsigned short          pending_gets;       // pending gets to be sent.
    unsigned short          pending_posts;      // pending posts to be sent.
    unsigned short          reqs_sent;          // requests sent per cycle.
    unsigned short          resp_recd;          // resp rcvd per request in cycle.
    bool                    is_get;             // To decide whether to perform get/post

    char                    persist_str[64];    // server ip received from 1st request on session.
    unsigned short          pdata_exists;       // if persist_data exists.
} te_tcp_session_t;

typedef struct te_udp_session_s {
    udp_multi_handle_t*     um_handle;

    unsigned short          num_uploads;        // number of get requests sent per session.
    unsigned short          num_downloads;      // number of post requests per session.
    unsigned short          pending_uploads;    // pending gets to be sent.
    unsigned short          pending_downloads;  // pending posts to be sent.
    unsigned short          reqs_sent;          // requests sent per cycle.
    unsigned short          reqs_failed;        // requests failed per cycle
    unsigned short          resp_recd;          // resp rcvd per request in cycle.
    unsigned short          resp_not_needed;    // responses not neeeded
    unsigned short          resp_timedout;      // resp timed per request in cycle.
    bool                    is_download;        // To decide whether to perform download/upload

} te_udp_session_t;

typedef struct te_session_s {
    unsigned short          id;                 // session_id.
    TE_SESSION_STATE        state;              // session_state.
    te_session_config_t     *session_cfg_p;     // Back pointer for session config.
    struct timespec         start_time;         // start_time of the cycle.
    struct timespec         end_time;           // end_time of the cycle.

    unsigned long           cycle_iter;         // current cycle iteration.
    unsigned short          total_cycle_iter;   // Total number of cycles completed by the session
    unsigned short          good_1st_response;  // Flag for atleast one good 1st response in browser.
                                                // This flag is per session across all cycles.
    bool                    is_completed;
    uv_async_t              fsm_handler;        // uv async handle for reviewing sessions.
    uv_timer_t              cycle_timer;        // uv timer handle for curl multi handle.

    unsigned short          vip_index;          // maintain 1 vip per session.
    unsigned short          num_connections;    // number of connections per session.
    unsigned short          num_requests;       // number of connection requests.
    unsigned short          failed_conns;       // num_failed_connections.

    unsigned short          pending_uv_deletes; // pending uv_handles to be deleted.

	//Only one of the pointer will be used in a te_dp process
    te_tcp_session_t*       tcp;
    te_udp_session_t*       udp;
} te_session_t;

typedef struct te_session_config_s {
   TE_SESSION_TYPE              type;                   // session type indicating MAX_OPEN_CONNS/REQS_PER_CONN/BROWSER.
   te_resource_config_t         *res_cfg;               // resource object for sessn
   unsigned long long int       cycles_complete;        // Running counter across session
   unsigned short               num_cycles;             // number of times the whole session-cycle to be run again.
   unsigned short               target_cycles;          // number of cycles, after which sessions to be end.
   unsigned short               cycle_delay;            // intercycle delay.
   unsigned int                 min_cycle_delay;        // min intercycle delay.
   unsigned int                 max_cycle_delay;        // max intercycle delay.
   TE_SESSION_CYCLE_TYPE        cycle_type;             // RESTART / RESUME session.
   unsigned short               min_connections;        // minimum limit for num_connections.
   unsigned short               max_connections;        // max limit for num_connections.
   unsigned short               min_requests;           // min limit for num_requests_per_session.
   unsigned short               max_requests;           // max limit for num_requests_per_session.
   bool                         persist_flag;           // flag to check if persistence to be verified.
   unsigned short               num_sessions;           // number of sessions to be opened in parallel.
   unsigned short               num_gets;               // num-gets in get-post ratio.
   unsigned short               num_posts;              // num-posts in get-post ratio.
   unsigned short               id;                     // session config id.
   short                        pending_sessions;       // pending sessions to be processed.
   TE_SESSION_CONFIG_STATE      config_state;           // configure the state of session config.
   TE_SESSION_CONFIG_STATE      running_state;          // running state of session config.
   te_http_session_metrics_t    http_metrics;           // http metrics for session.
   te_udp_session_metrics_t     udp_metrics;            // udp metrics for session.
   uv_timer_t                   ramp_timer;             // uv timer handle for session ramp stuff.
   uv_async_t                   session_signal_handler; // uv async handle for create/delete/pause/resume sessions.
   unsigned short               pending_uv_deletes;     // pending uv_handles to be deleted.
   unsigned short               update_flag;            // if session_config_needs to be updated.
   unsigned short               session_ramp_delay;     // delay after which next session_ramp_step number of sessions to be started.
   unsigned short               session_ramp_step;      // given session ramp step size
   unsigned short               ramped_sessions;        // to keep track of how many sessions alredy started.
   unsigned short               completed_sessions;     // sessions which meet the target flag.
   te_session_t                 *te_sessions;           // opened session list info.
} te_session_config_t;

typedef struct te_url_random_map_s {
    short size;
    short *te_url_random_array;
} te_url_random_map_t;

extern te_url_random_map_t *te_url_random_map;

typedef struct te_uri_s {
    bool    has_uri;
    char    *uri;
    short   weight;
    double  size;
    double  threshold_time;    //in seconds.
}te_uri_t;

typedef struct te_request_object_s {
    te_uri_t request_uri;

    // RATE OF SENDING
    int rate;

    //REDIRECTIONS
    int max_redirects;

    //HEADERS
    bool has_headers;
    int num_headers;
    char** headers;

    //COOKIES
    bool has_cookies;
    char* cookies;

    //QUERY PARAMS
    bool has_query_params;
    int num_qparams;
    int len_qparams;
    char** query_params;

    //POST_FILE
    bool has_postfile;
    char* postfile;

    //POST_DATA
    bool has_postdata;
    char* postdata;
} te_request_object_t;

typedef struct te_udp_datagram_s {

    //Datagram range to send/recv
    unsigned int min_datagram;
    unsigned int max_datagram;

    //Size of datagram to send/recv
    unsigned int min_datagram_size;
    unsigned int max_datagram_size;

    //Timeout of response
    unsigned long timeout;
} te_udp_datagram_t;

typedef struct te_udp_request_object_s {
    te_udp_datagram_t* download_req;
    te_udp_datagram_t* download_resp;

    te_udp_datagram_t* upload_req;
    te_udp_datagram_t* upload_resp;

    unsigned long min_timeout;
} te_udp_request_object_t;

typedef struct te_cert_s {
    char *ca_cert_path;     //Path to ca cert
    char *client_cert_path; //Path to client cert
    char *cert_type;        //type of cert - default it is PEM
    char *client_pvt_key;   //private key of client cert
    char *client_pass;      //passphrase for client pvt key
    bool cname_verify;      //Indicates strict checking on server CName
} te_cert_t;

typedef struct te_vip_s {

    // Common Datastructs
    char* vip;

    // Interface Datastructs
    int interface_profile_index;
    unsigned short rr_interface_counter;

    //TCP Only
    int get_profile_index;
    int post_profile_index;
    int num_certs;      //number of certificates in that client bundle
    te_cert_t* certs;   //ptr to certs for that specific host

    //UDP Only
    unsigned short vport;
    int udp_profile_index;
} te_vip_t;

typedef struct te_log_files_s {
   char *log_file_path;
   FILE *debug_logger;
   FILE *error_logger;
   FILE *test_logger;
   bool logs_open;
   bool headers_printed;
} te_log_files_t;

typedef struct get_post_s {
    unsigned short get_ratio;
    unsigned short post_ratio;
} get_post_t;

typedef struct download_upload_s {
    unsigned short download_ratio;
    unsigned short upload_ratio;
} download_upload_t;

typedef struct te_ssl_s {
    unsigned short version;
    char* cipher_list;
    char* groups;
    bool session_reuse; // to reuse ssl session id
} te_ssl_t;

typedef struct te_vip_end_metrics_node_s {
    unsigned int                      vip;
    unsigned short                    vport;
    bool                              stats_present;
    udp_server_metrics_t              vip_end_metrics;
    struct te_vip_end_metrics_node_s  *next;
} te_vip_end_metrics_node_t;

typedef struct te_udp_server_metrics_hash_s {
    te_vip_end_metrics_node_t   *head;  // Array of head pointers of socket_nodes.
    unsigned int                count;  // Elements in Hash table.
} te_udp_server_metrics_hash_t;

typedef struct te_server_metrics_hash_table_s {
	te_udp_server_metrics_hash_t  *buckets;      // Array of hash buckets.
	unsigned int                  size;          // num of hash buckets.
    unsigned int                  num_entries;   // num_entries in hash table.
} te_server_metrics_hash_table_t;

typedef struct te_udp_listen_handle_s {
    unsigned short            port;

    // Metrics are collected either from the perspective of server's listening handles (or) 
    // from the perspective of what was received from the virtual service in between
    // For vip level metrics there is a metrics collection done by DS `udp_vip_metrics_hash_map`
    // and for each listening handle below is the ds of collected metrics
    bool                      stats_present;
    udp_server_metrics_t      server_end_metrics;

    // Back pointer to server's easy handle
    udp_server_easy_handle_t* server_easy_handle;
} te_udp_listen_handle_t;

typedef struct te_resource_config_s {

    //VIP DS
    unsigned short total_vips;
    te_vip_t *vips;
    bool vip_selection_rr;
    unsigned int vip_rr_counter;

    unsigned short num_session_cfgs;
    unsigned short update_flag;

    //*************************************//
    //           HTTP(S) PROFILE           //
    //*************************************//
    //Requests DS
    int num_get_list_profile;
    int num_post_list_profile;
    int* num_get_reqs_in_profile;
    int* num_post_reqs_in_profile;
    get_post_t* get_post_ratio;
    te_request_object_t** preqs;
    te_request_object_t** greqs;

    // Interface details
    // Valid only for tcp
    int *num_interfaces_in_profiles;
    te_interface_t** interface_obj;

    //HTTP DS
    unsigned short http_version;
    unsigned short http_pipeline;
    bool is_pipelined;

    //SSL DS
    te_ssl_t ssl_details;

    // If Set-Cookies are to be used and sent back to server
    bool set_cookies;

    //TCP (or) CURL Params
    bool is_verbose;
    bool send_tcp_resets;       //To enable TE to send tcp resets
    bool tcp_connect_only;       //Establish a connection and exit
    int tcp_keepalive_timeout;  //To send a keep-alive to server
    int tcp_connect_timeout;

    //Metrics DS
    te_http_vip_metrics_t* http_vip_metrics;

    //*************************************//
    //             UDP PROFILE             //
    //*************************************//
    //Requests DS
    int num_udp_list_profile;                 //Number of UDP profiles
    int udp_resp_default_timeout;             //Response timeout to be used in UDP Client

    //Definition of each datagram profile
    download_upload_t* download_upload_ratio; //Ratio of download to upload
    te_udp_request_object_t* udp_reqs;        //Definition of datagram profile in every UDP profile

    //Listening sockets (only for TE_DP UDP SERVER)
    te_udp_listen_handle_t*  udp_listen_handle;
    unsigned short num_udp_listen_handle;
    unsigned long  server_socket_ds_parse_timeout;

    //Metrics DS
    te_udp_vip_metrics_t* udp_vip_metrics;

} te_resource_config_t;

extern te_update_context_t   *te_update_context;
extern te_resource_config_t  *res_cfg_updated;
extern te_session_config_t   *te_session_cfgs_updated;
extern te_log_files_t        *te_log_files;

// process all connections in session.
void create_te_sessions(te_session_config_t *session_cfg);
void delete_te_sessions(te_session_config_t *session_cfg);
void resume_te_sessions(te_session_config_t *session_cfg);

void te_push_session_sm(te_session_t* session);
void send_pending_requests(te_session_t *session);
void delete_session(te_session_t *session);
void te_process_session_state(te_session_t * session, TE_SESSION_STATE state);

// uv timeout for curl idle connections per session.
void on_session_cycle_timeout(uv_timer_t *session);
void push_session_sm_uv_async(uv_async_t *session);

//cleanup functions
void te_cleanup_res_cfg();
void te_clenup_ses_cfg();

//Call back to ramp sessions
void session_ramp_timer_cb(uv_timer_t*);

//UDP Callbacks
void te_udp_datagram_alloc_buffer(uv_handle_t*, size_t, uv_buf_t*);
void te_udp_on_read(uv_udp_t*, ssize_t, const uv_buf_t*, const struct sockaddr*, unsigned);

#endif
