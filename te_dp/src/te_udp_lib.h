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

#ifndef TE_UDP_LIB_H
#define TE_UDP_LIB_H

#include <stdarg.h>
#include <uv.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define BILLION 1000000000.0
#define DEFAULT_RESP_DG_TIMEOUT 10000
#define DEFAULT_SERVER_DS_PARSE_INTERVAL 15*1000 //Parse every 15 s, by default

// For optimizations
#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)

//A collection of connections is referred as multi_handle
typedef struct udp_multi_handle_s udp_multi_handle_t;
//A request, which is essentially a collection of datagrams is referred as easy_handle
typedef struct udp_easy_handle_s udp_easy_handle_t;
//A server listener handle
typedef struct udp_server_easy_handle_s udp_server_easy_handle_t;
//Each yet-to-be fired request is held in the linked list
typedef struct udp_pending_handle_node_s udp_pending_handle_node_t;
//Each fired datagram is of the type te_udp_message_header_t with ad
typedef struct udp_message_header_s udp_message_header_t;
//Connection status and uv_udp_t handle
typedef struct udp_connection_s udp_connection_t;

#ifndef TE_DP_H
#include "te_dp.h"
#endif

#ifndef TE_SOCK_H
#include "te_sock.h"
#endif

//UDP Connection handle states
#define CONN_UNINITED            0
#define CONN_INITED              1
#define CONN_CONNECTED_AND_FREE  2
#define CONN_CONNECTED_AND_BUSY  3

//UDP MULTI ERROR CODES
typedef enum UDPMcode_s {
    UDPM_OK                      = 0,

    UDPM_OK_PENDING_TO_SEND      = 1,
    UDPM_UNABLE_TO_SEND          = 2,

    UDPM_NULL_MULTI_HANDLE       = 3,
    UDPM_NULL_EASY_HANDLE        = 4,
    UDPM_NULL_IP                 = 5,
    UDPM_INVALID_PORT            = 6,

    UDP_INVALID_PORT             = 7,
    UDPM_INVALID_OPT             = 8,
    UDPM_UNABLE_TO_CLEANUP       = 9,

    UDPM_UNABLE_TO_INIT_CONN     = 10,
    UDPM_UNABLE_TO_BIND_CONN     = 11,
    UDPM_UNABLE_TO_CONNECT_CONN  = 12,
    UDPM_IMPROPER_CONN_STATE     = 13
} UDPMcode;

//UDP MULTI OPTS
#define UDP_MAX_CONNECTS          0
#define UDP_SEND_CALLBACK         1
#define UDP_RECV_CALLBACK         2
#define UDP_IP                    3
#define UDP_PORT                  4
#define UDP_SOCKET_TIMEOUT        5

//UDP EASY ERROR CODES
typedef enum UDPEcode_s {
    UDPE_OK                        = 0,
    UDPE_NULL_EASY_HANDLE          = 1,
    UDPE_NULL_SERVER_EASY_HANDLE   = 2,
    UDPE_INVALID_OPT               = 3,
    UDPE_UNABLE_TO_INIT_LISTENER   = 4,
    UDPE_UNABLE_TO_BIND_LISTENER   = 5,
    UDPE_UNABLE_TO_START_LISTENER  = 6,
    UDPE_UNABLE_TO_SEND            = 7
} UDPEcode;

//UDP EASY OPTS
#define UDP_DG_NUM_TO_SEND            0
#define UDP_DG_SIZE_TO_SEND           1
#define UDP_DG_NUM_TO_RECV            2
#define UDP_DG_SIZE_TO_RECV           3
#define UDP_RECV_TIMEOUT              4
#define UDP_PRIVATE                   5
#define UDP_LISTEN_PORT               6
#define UDP_LISTEN_PRIVATE            7
#define UDP_LISTEN_SEND_CALLBACK      8
#define UDP_LISTEN_RECV_CALLBACK      9

// Metrics for the send and receive handle of both client and server of UDP
typedef struct udp_send_metrics_s {
    // Connection related metrics are populated only by client in case of send metrics
    // This indicates the number of new connections opened by the client
    unsigned int new_conn_opened;
    unsigned int conn_open_fail;

    unsigned int dg_sent;
    unsigned int dg_size_sent;
    unsigned int dg_send_fail;

    // Latency is populated at the sending end by the server process
    double latency;
} udp_send_metrics_t;

typedef struct udp_recv_metrics_s {
    unsigned int dg_rcvd;
    unsigned int dg_size_rcvd;
    unsigned int dg_recv_timedout;

    // Latency is populated at the receiving end by the client process
    double latency;
} udp_recv_metrics_t;

typedef struct __attribute__ ((__packed__)) udp_message_header_s {
    unsigned short sequence_number;    //Request Number
    bool           respond_now;        //Whether to respond now
    unsigned long  unique_stream_id;   //Stream Identifier
    unsigned short total_request_dg;   //Total request to make
    unsigned int   response_size_dg;   //Size of each dg in response
    unsigned short response_num_dg;    //Number of dg to respond
    unsigned long  timeout;            //Timeout to stop listening
    unsigned int   vip, client_ip;     //vip can be different from the target server ip
    unsigned short vport, client_port; // similarly vport can be different from server port

    // vip and vport are added in order to collect metric at the back end server w.r.t to the vip
    // vip and vport are set as of now only by the client
} udp_message_header_t;

typedef struct udp_server_easy_handle_s {
    //UDP's listening port
    unsigned short      d_port;
    //UDP's listening address
    struct sockaddr_in  recv_addr;
    //uv_udp's listening handle
    uv_udp_t            uv_udp_handle;
    //User pointer to be passed along with the callbacks
    void*               usr_ptr;
    //User callback function pointer for send callback
    void (*user_send_callback_fptr)(unsigned long, unsigned short, udp_send_metrics_t, void*);
    //User callback function pointer for recv callback
    void (*user_recv_callback_fptr)(unsigned long, unsigned short, udp_recv_metrics_t, void*);
} udp_server_easy_handle_t;

// We have a global timer which will kick in when there is at least one listener
typedef struct udp_server_socket_ds_parser_s {
    unsigned long  timeout;
    uv_timer_t     timer;
    bool           timer_started;
} udp_server_socket_ds_parser_t;

typedef struct udp_easy_handle_s {
    //Datagram details to send
    //EXPECTED
    unsigned int dg_to_send;
    unsigned int dg_size_to_send;
    //ACTUAL
    unsigned int dg_sent;
    unsigned int dg_size_sent;
    unsigned int dg_send_fail;

    //Datagram details to recv
    //EXPECTED
    unsigned int dg_to_recv;
    unsigned int dg_size_to_recv;
    //ACTUAL
    unsigned int dg_rcvd;
    unsigned int dg_size_rcvd;
    unsigned int dg_recv_timedout;

    // Connection related counters
    unsigned int new_conn_opened;
    unsigned int conn_open_fail;

    //Timeout of response
    unsigned long timeout;
    double        last_sent_ts;

    // dg sent and rcvd timestamp -- to calculate latency
    struct timespec first_dg_sent_ts;

    //Back pointer to the connection handle
    udp_connection_t *conn_handle_back_ptr;

    //Back pointer to multi_handle
    udp_multi_handle_t* multi_handle_back_ptr;

    //User Pointer for the callbacks
    void* usr_ptr;
} udp_easy_handle_t;

typedef struct udp_pending_handle_node_s {
    //Pointer to the easy handle
    udp_easy_handle_t                 *easy_handle;
    //Pointer to the next node
    struct udp_pending_handle_node_s  *next;
} udp_pending_handle_node_t;

typedef struct udp_connection_s {
    unsigned int      client_ip;
    unsigned short    client_port;
    uv_udp_t          stream;
    unsigned short    fd;
    unsigned long     unique_id;
    unsigned short    status;
    unsigned short    array_pos;
    udp_easy_handle_t *easy_handle_back_ptr;
    void              *base;
} udp_connection_t;

typedef struct udp_multi_handle_s {
    // number of connections to open at max
    unsigned short           max_connects;
    // Number of uv_handle_t opened that needs to be deleted while during multi_cleanup
    unsigned short           opened_udp_uv_handles;
    // Running counter of open connections 
    // (increments and decrements based on addition and removal of easy_handle)
    unsigned short           curr_used_conn;
    // Connection handle having the udp handle
    udp_connection_t         *conn_handle;

    //Timeout for sockets
    uv_timer_t       udp_socket_timer;
    unsigned long    socket_timeout;

    //IP which is a string
    char*            str_ip;
    //IP from which the request was sent
    unsigned long    ip;
    //Port from which the request was sent
    unsigned short   port;
    //Combination of str_ip:port of remote address
    struct sockaddr_in *remote_sock_addr;

    //User callback function pointer for send callback
    void (*user_send_callback_fptr)(udp_send_metrics_t, void*);
    //User callback function pointer for recv callback
    void (*user_recv_callback_fptr)(udp_recv_metrics_t, void*);

    //Points to the head and tail of the pending easy_handle's linked list
    //Consider the LL to act as a FIFO queue
    udp_pending_handle_node_t *pending_handle_head, *pending_handle_tail;
} udp_multi_handle_t;

//Multi Setopts
udp_multi_handle_t* udp_multi_init(void);
UDPMcode udp_multi_cleanup(udp_multi_handle_t*);
UDPMcode udp_multi_setopt_integer(udp_multi_handle_t*, unsigned short, short unsigned int);
UDPMcode udp_multi_setopt_ptr(udp_multi_handle_t*, unsigned short, void*);
UDPMcode udp_multi_add_handle(udp_multi_handle_t*, udp_easy_handle_t*);

//Easy Setopts
udp_easy_handle_t* udp_easy_init(void);
udp_server_easy_handle_t* udp_server_easy_init();
UDPEcode udp_easy_cleanup(udp_easy_handle_t*);
UDPEcode udp_server_easy_setopt_integer(udp_server_easy_handle_t*, unsigned short, short unsigned int);
UDPEcode udp_server_easy_setopt_ptr(udp_server_easy_handle_t*, unsigned short, void*);
UDPEcode udp_easy_setopt_integer(udp_easy_handle_t*, unsigned short, short unsigned int);
UDPEcode udp_easy_setopt_ptr(udp_easy_handle_t*, unsigned short, void*);
UDPEcode udp_server_easy_start_listen(udp_server_easy_handle_t*);
UDPEcode udp_server_socket_parser(unsigned long);

//Function overloading for setopt
//Similar to cURL setopt, you can now set opts for different types
#define udp_multi_setopt(multi_handle, opt ,val) _Generic((val), \
    void (*)(udp_recv_metrics_t, void*) : udp_multi_setopt_ptr, \
    void (*)(udp_send_metrics_t, void*) : udp_multi_setopt_ptr, \
    unsigned int                                    : udp_multi_setopt_integer, \
    long unsigned int                               : udp_multi_setopt_integer, \
    short unsigned int                              : udp_multi_setopt_integer, \
    te_session_t*                                   : udp_multi_setopt_ptr, \
    char*                                           : udp_multi_setopt_ptr)(multi_handle, opt ,val)

#define udp_easy_setopt(easy_handle, opt ,val) _Generic((val), \
    unsigned int                                    : udp_easy_setopt_integer, \
    short unsigned int                              : udp_easy_setopt_integer, \
    long unsigned int                               : udp_easy_setopt_integer, \
    te_udp_request_t*                               : udp_easy_setopt_ptr)(easy_handle, opt ,val)

#define udp_server_easy_setopt(server_easy_handle, opt ,val) _Generic((val), \
    void (*)(unsigned long, unsigned short, udp_recv_metrics_t, void*) : udp_server_easy_setopt_ptr, \
    void (*)(unsigned long, unsigned short, udp_send_metrics_t, void*) : udp_server_easy_setopt_ptr, \
    unsigned int                                    : udp_server_easy_setopt_integer, \
    short unsigned int                              : udp_server_easy_setopt_integer, \
    long unsigned int                               : udp_server_easy_setopt_integer, \
    te_udp_listen_handle_t*                         : udp_server_easy_setopt_ptr)(server_easy_handle, opt ,val)

#endif
