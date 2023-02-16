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
#include "te_udp_lib.h"
#endif

extern unsigned short pinned_cpu;
extern uv_loop_t *loop;
extern int IPC_QUEUE_ID;

//DS related to the socket ds parser for UDP
udp_server_socket_ds_parser_t udp_server_socket_ds_parser = {
    .timeout = DEFAULT_SERVER_DS_PARSE_INTERVAL,
    .timer_started = false};

//For internal library use only
static UDPMcode send_client_udp_datagrams(udp_connection_t*, udp_easy_handle_t*);
static void server_socket_init(te_socket_node_t*, udp_server_easy_handle_t*, udp_message_header_t*, \
                                ssize_t, double);
static void server_socket_recv_dg(te_socket_node_t*, udp_server_easy_handle_t*, \
                                udp_message_header_t*, ssize_t, double);
static void server_socket_send_dg(te_socket_node_t*, udp_server_easy_handle_t*, udp_message_header_t*, \
                                ssize_t, double);
static void udp_datagram_server_send_callback(uv_udp_send_t*, int);

//To cycle through various states of server socket
void (*te_server_socket_state_switcher[])(te_socket_node_t*, \
    udp_server_easy_handle_t*, udp_message_header_t*, ssize_t, double) = {
    server_socket_init,
    server_socket_recv_dg,
    server_socket_send_dg
};

//********************************************************************//
//   CALLBACK TO ALLOCATE BUFFER TO SEND AND RECIEVE AND ON TIMEOUTS  //
//********************************************************************//
// The memory allocated is utilized in 2 parts
// A) Static overhead memory, which posses the headers we add as a part of UDP TE's lib
// B) Dynamic user input alloc, this is the actual payload that is either intended to go out or come in
void udp_datagram_alloc_buffer(uv_handle_t *easy_handle, size_t size_to_alloc, uv_buf_t *buf) {
    te_malloc(buf->base, size_to_alloc, TE_MTYPE_VOID);
    buf->len = size_to_alloc;
}

//************************************************************************************************//
//                             SERVER STATE TRANSITION CALLBACK                                   //
//************************************************************************************************//

/*
         /-----------/
    |--->/   INIT    /
    |    /-----------/
    |         |
    |         *
    |    /-----------/<========== Client dg receive point
    |    /   RECV    /      |
    |    /-----------/      |
    |         |           Keep receving till
    |         |           all dgs are received
    |         |_____________|
    |         |
    |      If all dgs
    |      are received
    |         |
    |      If there is
    |<-No-- response
    |       to be sent
    |         |
    |        Yes
    |         |
    |         *
    |    /-----------/==========> Client dg send point
    |    /   SEND    /
    |    /-----------/
    |         |
    |         *
    |    /-----------/
    |    /           /
    |    /  BUFFER   /
    |    /  TILL     /
    |    /  SEND CB  /
    |    /-----------/
    |
    |
    |<---------------* (Upon completion of all sends)
    |
    |<---------------* (Upon timeout of the socket, timer triggered)
*/

static void server_empty_send_cb_to_indicate_latency(te_socket_node_t* socket_node) {
    udp_send_metrics_t send_metrics;
    struct timespec current_time_struct;
    clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);

    send_metrics.dg_sent       = 0;
    send_metrics.dg_size_sent  = 0;
    send_metrics.dg_send_fail  = 0;
    send_metrics.latency       = (current_time_struct.tv_sec)*1000 + \
            (double)(current_time_struct.tv_nsec)/BILLION - \
            socket_node->state.first_dg_rcvd_ts;

    socket_node->udp_server_easy_handle_back_ptr->user_send_callback_fptr(\
        socket_node->state.vip, socket_node->state.vport,
        send_metrics, socket_node->udp_server_easy_handle_back_ptr->usr_ptr);
}

static void server_socket_init(te_socket_node_t* socket_node, \
    udp_server_easy_handle_t* server_easy_handle, \
    udp_message_header_t* udp_msg_header, ssize_t nread, double current_time) {

    snprintf(socket_node->state.vip, sizeof(socket_node->state.vip), "%s", udp_msg_header->vip);
    socket_node->state.vport = udp_msg_header->vport;
    socket_node->state.client_ip = udp_msg_header->client_ip;
    socket_node->state.client_port = udp_msg_header->client_port;
    socket_node->state.status = SERVER_SOCKET_RECV_DG;
    socket_node->state.last_ts = current_time;
    socket_node->state.timeout = udp_msg_header->timeout;
    // dg sent and rcvd timestamp -- to calculate latency from the server perspective
    socket_node->state.first_dg_rcvd_ts = current_time;
    tprint("Socket init-ed making a callback to state=%d from state=%d\n", \
        socket_node->state.status, SERVER_SOCKET_INIT);
    server_socket_recv_dg(socket_node, server_easy_handle, udp_msg_header, nread, current_time);
}

static void make_serv_recv_cb_and_move_state(te_socket_node_t* socket_node, \
    udp_server_easy_handle_t* server_easy_handle, double current_time) {
    tprint("All dg received and making user level cb from state=%d\n", socket_node->state.status);

    // Make user level receive callback if available
    if(socket_node->udp_server_easy_handle_back_ptr->user_recv_callback_fptr) {
        udp_recv_metrics_t recv_metrics;
        recv_metrics.dg_rcvd          = socket_node->metric.dg_rcvd;
        recv_metrics.dg_size_rcvd     = socket_node->metric.dg_size_rcvd;
        recv_metrics.dg_recv_timedout = 0;

        socket_node->udp_server_easy_handle_back_ptr->user_recv_callback_fptr(
            socket_node->state.vip, socket_node->state.vport,
            recv_metrics, socket_node->udp_server_easy_handle_back_ptr->usr_ptr);
    }

    // If there is anything to send, send the dgs back
    if(socket_node->metric.dg_to_send != 0) {
        socket_node->state.status = SERVER_SOCKET_SEND_DG;
        tprint("All DG rcvd and making a callback to state=%d from state=%d\n", \
            socket_node->state.status, SERVER_SOCKET_RECV_DG);
        server_socket_send_dg(socket_node, server_easy_handle, NULL, 0, current_time);
    } else {
        // Nothing to send, so making an empty callback to indicate latency
        if(socket_node->udp_server_easy_handle_back_ptr->user_send_callback_fptr) {
            server_empty_send_cb_to_indicate_latency(socket_node);
        }
        tprint("Nothing to respond and nothing buffered and so cleaning socket_node " \
            "in state=%d\n", socket_node->state.status);
        te_remove_udp_server_socket_node(socket_node);
    }
}

static void server_socket_recv_dg(te_socket_node_t* socket_node, \
    udp_server_easy_handle_t* server_easy_handle, \
    udp_message_header_t* udp_msg_header, ssize_t nread, double current_time) {

    if(likely(socket_node->state.timeout == 0 || \
        socket_node->state.last_ts + socket_node->state.timeout > (long)current_time)) {
        // timeout = 0 signifies inf timeout
        // OR clause in the `IF` signifies continuation of the same stream without timeout
        tprint("DG recvd and not timdeout in state=%d\n", socket_node->state.status);
        socket_node->state.respond_now_recd |= udp_msg_header->respond_now;
        socket_node->state.last_ts = current_time;

        // Timeout value can't be changed in between
        assert(socket_node->state.timeout == udp_msg_header->timeout);

        socket_node->metric.dg_to_recv = udp_msg_header->total_request_dg;
        socket_node->metric.dg_rcvd++;
        socket_node->metric.dg_size_rcvd += nread - sizeof(udp_message_header_t);
        socket_node->metric.dg_to_send = udp_msg_header->response_num_dg;
        socket_node->metric.dg_size_to_send = udp_msg_header->response_size_dg;
        assert(socket_node->metric.dg_rcvd <= udp_msg_header->total_request_dg);

        if(socket_node->metric.dg_to_recv == socket_node->metric.dg_rcvd) {
            // Since all dgs are received, we must make appropriate callbacks
            // And start sending reply back, if need be
            make_serv_recv_cb_and_move_state(socket_node, server_easy_handle, current_time);
        }
    } else {
        // Highly unlikely scenario in which
        // client_ip, client_port and unique stream id happened to be an exact match
        // but the stream had timed out
        eprint("Resetting the socket node due to timeout in state=%d for unique_stream_id=%lu as "
            "last_ts=%lu timeout=%lu current_time=%lf\n", socket_node->state.status, \
            udp_msg_header->unique_stream_id, socket_node->state.last_ts, socket_node->state.timeout,
            current_time);

        // Make a user level callback for receive and change state
        if(socket_node->udp_server_easy_handle_back_ptr->user_recv_callback_fptr) {
            socket_node->metric.dg_recv_timedout = socket_node->metric.dg_to_recv - \
                socket_node->metric.dg_rcvd;

            udp_recv_metrics_t recv_metrics;
            recv_metrics.dg_rcvd          = socket_node->metric.dg_rcvd;
            recv_metrics.dg_size_rcvd     = socket_node->metric.dg_size_rcvd;
            recv_metrics.dg_recv_timedout = socket_node->metric.dg_recv_timedout;

            socket_node->udp_server_easy_handle_back_ptr->user_recv_callback_fptr(
                socket_node->state.vip, socket_node->state.vport, recv_metrics, \
                socket_node->udp_server_easy_handle_back_ptr->usr_ptr);
        }

        //Re-init the socket DS for the new socket connection
        socket_node->state.respond_now_recd = udp_msg_header->respond_now;
        socket_node->state.last_ts = current_time;
        socket_node->state.timeout = udp_msg_header->timeout;
        snprintf(socket_node->state.vip, sizeof(socket_node->state.vip), "%s", udp_msg_header->vip);
        socket_node->state.vport = udp_msg_header->vport;

        socket_node->metric.dg_to_recv = udp_msg_header->total_request_dg;
        socket_node->metric.dg_rcvd = 1;
        socket_node->metric.dg_size_rcvd = nread - sizeof(udp_message_header_t);
        socket_node->metric.dg_to_send = udp_msg_header->response_num_dg;
        socket_node->metric.dg_size_to_send = udp_msg_header->response_size_dg;
        assert(socket_node->metric.dg_rcvd <= udp_msg_header->total_request_dg);

        if(socket_node->metric.dg_to_recv == socket_node->metric.dg_rcvd) {
            make_serv_recv_cb_and_move_state(socket_node, server_easy_handle, current_time);
        }
        socket_node->state.status = SERVER_SOCKET_RECV_DG;
    }

    return;
}

static void server_socket_send_dg(te_socket_node_t* socket_node, \
    udp_server_easy_handle_t* server_easy_handle, \
    udp_message_header_t* udp_msg_header_from_cb, ssize_t nread, double current_time) {

    if(unlikely(socket_node == NULL || socket_node->udp_server_easy_handle_back_ptr == NULL)) {
        abort();
    }

    int assert_code;

    // LIBUV understandable message to send out
    uv_buf_t buffer;
    size_t size_to_alloc = socket_node->metric.dg_size_to_send + \
                            sizeof(udp_message_header_t);
    udp_datagram_alloc_buffer(NULL, size_to_alloc, &buffer);
    socket_node->base = buffer.base;

    udp_message_header_t udp_msg_header;
    udp_msg_header.total_request_dg = socket_node->metric.dg_to_send;
    udp_msg_header.response_num_dg = 0;
    udp_msg_header.response_size_dg = 0;
    udp_msg_header.respond_now = false;
    udp_msg_header.timeout = 0;
    udp_msg_header.unique_stream_id = socket_node->state.unique_stream_id;

    //copy the data from the header  to the base struct of the buffer
    memcpy(buffer.base, &udp_msg_header, sizeof(udp_message_header_t));

    for (int i=0; i<socket_node->metric.dg_to_send; i++) {

        //Update the sequence number of the buffer
        ((udp_message_header_t*)buffer.base)->sequence_number = i;

        //Send the datagram
        uv_udp_send_t* send_req;
        te_malloc(send_req, sizeof(uv_udp_send_t), TE_MTYPE_UDP_SEND_DATAGRAM);
        send_req->data = socket_node;
        if (socket_node->remote_sock_addr.sin_addr.s_addr) {
            assert_code = uv_udp_send(send_req, &(server_easy_handle->uv_udp_handle), &buffer, 1, \
                (const struct sockaddr *)(&socket_node->remote_sock_addr), \
                udp_datagram_server_send_callback);
        } else {
            assert_code = uv_udp_send(send_req, &(server_easy_handle->uv_udp_handle), &buffer, 1, \
                (const struct sockaddr *)(&socket_node->remote_sock_addr_v6), \
                udp_datagram_server_send_callback);
        }

        if(unlikely(assert_code != 0)) {
            eprint("Unable to send %s\n", uv_err_name(assert_code));
            udp_datagram_server_send_callback(send_req, assert_code);
        }
    }
    // Don't make a call to it, to the function, it is used upon receiving a new dg from a new stream
    socket_node->state.status = SERVER_SOCKET_BUFFER_DG;
    tprint("All DG sent and moving to state=%d from state=%d\n", \
        socket_node->state.status, SERVER_SOCKET_SEND_DG);
}

static void udp_datagram_server_recv_v6_callback(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,\
    const struct sockaddr *from_addr, unsigned flags) {

    //Size to read can't be negative
    if (unlikely(nread < 0)) {
        //AK Revisit UDP Metrics
        eprint("Read error %s\n", uv_err_name(nread));
    } else if(unlikely(flags != 0)) {
        //Partial receive
        eprint("Partial recv %d\n", flags);
    }

    //Read the message sent
    if (likely(from_addr != NULL && nread > 0)) {
        struct sockaddr_in6 *from_addr_in = (struct sockaddr_in6*)(from_addr);
        udp_server_easy_handle_t* server_easy_handle = (udp_server_easy_handle_t*)req->data;
        udp_message_header_t* udp_msg_header = (udp_message_header_t*)buf->base;
        te_socket_node_t* socket_node = te_create_or_retrieve_udp_server_socket_v6(*from_addr_in, \
            udp_msg_header->client_ip, udp_msg_header->client_port, udp_msg_header->unique_stream_id, \
            server_easy_handle);

        struct timespec current_time_struct;
        clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);
        double current_time =  (current_time_struct.tv_sec)*1000 + \
                                (double)(current_time_struct.tv_nsec)/BILLION;

        if(likely(socket_node->state.status >= SERVER_SOCKET_INIT && \
            socket_node->state.status <= SERVER_SOCKET_SEND_DG)) {
            (*te_server_socket_state_switcher[socket_node->state.status])(socket_node, \
                server_easy_handle, udp_msg_header, nread, current_time);
        } else {
            eprint("Unknown socket state\n");
            abort();
        }
    }

    //Free the memory of the message got upon completion
    if(likely(buf->base != NULL)) {
        te_free(buf->base, TE_MTYPE_VOID);
    }
}

static void udp_datagram_server_recv_callback(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf,\
    const struct sockaddr *from_addr, unsigned flags) {

    //Size to read can't be negative
    if (unlikely(nread < 0)) {
        //AK Revisit UDP Metrics
        eprint("Read error %s\n", uv_err_name(nread));
    } else if(unlikely(flags != 0)) {
        //Partial receive
        eprint("Partial recv %d\n", flags);
    }

    //Read the message sent
    if (likely(from_addr != NULL && nread > 0)) {
        struct sockaddr_in *from_addr_in = (struct sockaddr_in*)(from_addr);
        udp_server_easy_handle_t* server_easy_handle = (udp_server_easy_handle_t*)req->data;
        udp_message_header_t* udp_msg_header = (udp_message_header_t*)buf->base;
        te_socket_node_t* socket_node = te_create_or_retrieve_udp_server_socket(*from_addr_in, \
            udp_msg_header->client_ip, udp_msg_header->client_port, udp_msg_header->unique_stream_id, \
            server_easy_handle);

        struct timespec current_time_struct;
        clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);
        double current_time =  (current_time_struct.tv_sec)*1000 + \
                                (double)(current_time_struct.tv_nsec)/BILLION;

        if(likely(socket_node->state.status >= SERVER_SOCKET_INIT && \
            socket_node->state.status <= SERVER_SOCKET_SEND_DG)) {
            (*te_server_socket_state_switcher[socket_node->state.status])(socket_node, \
                server_easy_handle, udp_msg_header, nread, current_time);
        } else {
            eprint("Unknown socket state\n");
            abort();
        }
    }

    //Free the memory of the message got upon completion
    if(likely(buf->base != NULL)) {
        te_free(buf->base, TE_MTYPE_VOID);
    }
}

//************************************************************************************************//
// Callback is made for every sent out datagram                                                   //
// We then defer the callback to the user defined callback defined at udp_multi_setopt() (if any) //
//************************************************************************************************//
static void udp_datagram_server_send_callback(uv_udp_send_t* sent_req, int status) {
    te_socket_node_t* socket_node = (te_socket_node_t*)sent_req->data;
    if(likely(sent_req != NULL)) {
        if(likely(status == 0)) {
            socket_node->metric.dg_sent++;
            socket_node->metric.dg_size_sent += socket_node->metric.dg_size_to_send;
        } else {
            socket_node->metric.dg_send_fail++;
        }
        te_free(sent_req, TE_MTYPE_UDP_SEND_DATAGRAM);
        sent_req = NULL;
    } else {
        return;
    }

    //Upon completing all send of datagrams
    if(socket_node->metric.dg_sent + socket_node->metric.dg_send_fail == \
        socket_node->metric.dg_to_send) {
        //Free the memory of the message sent upon completion
        if(likely(socket_node->base != NULL)) {
            te_free(socket_node->base, TE_MTYPE_VOID);
            socket_node->base = NULL;
        }
        if(socket_node->udp_server_easy_handle_back_ptr->user_send_callback_fptr) {
            udp_send_metrics_t send_metrics;
            send_metrics.dg_sent       = socket_node->metric.dg_sent;
            send_metrics.dg_size_sent  = socket_node->metric.dg_size_sent;
            send_metrics.dg_send_fail  = socket_node->metric.dg_send_fail;
            struct timespec current_time_struct;
            clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);
            send_metrics.latency       = (current_time_struct.tv_sec)*1000 + \
                    (double)(current_time_struct.tv_nsec)/BILLION - \
                    socket_node->state.first_dg_rcvd_ts;

            socket_node->udp_server_easy_handle_back_ptr->user_send_callback_fptr(\
                socket_node->state.vip, socket_node->state.vport,
                send_metrics, socket_node->udp_server_easy_handle_back_ptr->usr_ptr);
        }
        //Remove the socket upon completion of all sends
        te_remove_udp_server_socket_node(socket_node);
    }
}

//*************************************************************//
// The callbacks are made on timeouts                          //
// This avoid hogging of memory on the server end and          //
// helps in timely reporting of metrics of timeouts            //
// This not the only place of catching a timeout though        //
// Both the recv callbacks of server and client have logics    //
// to detect timeouts if any                                   //
//*************************************************************//
static void udp_datagram_server_socket_timeout(uv_timer_t *udp_socket_timer) {
    // Get current time
    struct timespec current_time_struct;
    // Reference - https://www.cs.rutgers.edu/~pxk/416/notes/c-tutorials/gettime.html
    clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);
    double current_ts =  (current_time_struct.tv_sec)*1000 + \
                            (double)(current_time_struct.tv_nsec)/BILLION;
    te_udp_sock_parse_on_timeout(current_ts);
}

//************************************************************************************************//
//                       SERVER LIBRARY FUNCTIONS TO INIT AND SET OPTS                            //
//************************************************************************************************//
udp_server_easy_handle_t* udp_server_easy_init(void) {
    tprint("MULTI UDP HANDLE: INIT\n");
    udp_server_easy_handle_t* server_multi_handle;
    te_malloc(server_multi_handle, sizeof(udp_server_easy_handle_t), \
        TE_MTYPE_UDP_SERVER_EASY_HANDLE);
    if(likely(server_multi_handle != NULL)) {
        memset(server_multi_handle, 0, sizeof(udp_server_easy_handle_t));
    }
    return server_multi_handle;
}

UDPEcode udp_server_easy_setopt_integer(udp_server_easy_handle_t* server_easy_handle, \
                        unsigned short opt, \
                        unsigned short val) {
    if(unlikely(!server_easy_handle)) {
        return UDPE_NULL_SERVER_EASY_HANDLE;
    }

    UDPEcode return_code = UDPE_OK;
    switch(opt) {

        //UDP port to connect to
        case UDP_LISTEN_PORT: {
            if(likely(val > 0))
                server_easy_handle->d_port = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        //Anyother option passed to this function is invalid
        default: {
            return_code = UDPE_INVALID_OPT;
        } break;
    }
    return return_code;
}

// The below function sets opts that has the value passed to it that are of pointer type
UDPEcode udp_server_easy_setopt_ptr(udp_server_easy_handle_t* server_easy_handle, \
    unsigned short opt, void* val) {
    if(!server_easy_handle) {
        return UDPE_NULL_SERVER_EASY_HANDLE;
    }

    UDPEcode return_code = UDPE_OK;
    switch(opt) {

        // Private pointer to call the send and receive callbacks
        case UDP_LISTEN_PRIVATE: {
            if(likely(val))
                server_easy_handle->usr_ptr = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        //Send callback to call. The function pointer is called for every sent out response
        case UDP_LISTEN_SEND_CALLBACK: {
            if(likely(val))
                server_easy_handle->user_send_callback_fptr = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        //Receive callback to call. The function pointer is called for every received request
        case UDP_LISTEN_RECV_CALLBACK: {
            if(likely(val))
                server_easy_handle->user_recv_callback_fptr = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        //Anyother option passed to the function is invalid
        default: {
            return_code = UDPE_INVALID_OPT;
        } break;
    }
    return return_code;
}

UDPEcode udp_server_easy_start_listen_v6(udp_server_easy_handle_t* server_easy_handle){
    int assert_code;
    uv_ip6_addr("::", server_easy_handle->d_port, &(server_easy_handle->recv_addr_v6));
    //Init the UDP socket to listen
    assert_code = uv_udp_init(loop, &(server_easy_handle->uv_udp6_handle));
    if(unlikely(assert_code != 0)) {
        return UDPE_UNABLE_TO_INIT_LISTENER;
    }
    //Bind to the listening port (If port is used by another process - steal it)
    assert_code = uv_udp_bind(&(server_easy_handle->uv_udp6_handle) , \
                    (const struct sockaddr *)&(server_easy_handle->recv_addr_v6), \
                    UV_UDP_REUSEADDR);
    if(unlikely(assert_code != 0)) {
        return UDPE_UNABLE_TO_BIND_LISTENER;
    }

    server_easy_handle->uv_udp6_handle.data = server_easy_handle;

    //Add to the event loop and start listening
    assert_code = uv_udp_recv_start(&(server_easy_handle->uv_udp6_handle), \
        udp_datagram_alloc_buffer, udp_datagram_server_recv_v6_callback);
    if(unlikely(assert_code != 0)) {
        return UDPE_UNABLE_TO_START_LISTENER;
    }
    return UDPE_OK;
}

UDPEcode udp_server_easy_start_listen(udp_server_easy_handle_t* server_easy_handle) {
    int assert_code; UDPEcode ecode;
    //Update the handle on the port to listen on v6
    ecode = udp_server_easy_start_listen_v6(server_easy_handle);
    if(unlikely(ecode != UDPE_OK))
        eprint("UDP6_LISTEN_START, %d\n", ecode);

    uv_ip4_addr("0.0.0.0", server_easy_handle->d_port, &(server_easy_handle->recv_addr));

    //Init the UDP socket to listen
    assert_code = uv_udp_init(loop, &(server_easy_handle->uv_udp_handle));
    if(unlikely(assert_code != 0)) {
        return UDPE_UNABLE_TO_INIT_LISTENER;
    }

    //Bind to the listening port (If port is used by another process - steal it)
    assert_code = uv_udp_bind(&(server_easy_handle->uv_udp_handle) , \
                    (const struct sockaddr *)&(server_easy_handle->recv_addr), \
                    UV_UDP_REUSEADDR);
    if(unlikely(assert_code != 0)) {
        return UDPE_UNABLE_TO_BIND_LISTENER;
    }

    server_easy_handle->uv_udp_handle.data = server_easy_handle;

    //Add to the event loop and start listening
    assert_code = uv_udp_recv_start(&(server_easy_handle->uv_udp_handle), \
        udp_datagram_alloc_buffer, udp_datagram_server_recv_callback);
    if(unlikely(assert_code != 0)) {
        return UDPE_UNABLE_TO_START_LISTENER;
    }

    if(!udp_server_socket_ds_parser.timer_started) {
        // Initiate the timer and start timer to parse DS
        uv_timer_init(loop, &(udp_server_socket_ds_parser.timer));
        uv_timer_start(&(udp_server_socket_ds_parser.timer), udp_datagram_server_socket_timeout, \
            udp_server_socket_ds_parser.timeout, udp_server_socket_ds_parser.timeout);
        udp_server_socket_ds_parser.timer_started = true;
    }

    return UDPE_OK;
}

UDPEcode udp_server_socket_parser(unsigned long server_socket_ds_parse_timeout) {
    if(server_socket_ds_parse_timeout <= 0)
        server_socket_ds_parse_timeout = DEFAULT_SERVER_DS_PARSE_INTERVAL;

    udp_server_socket_ds_parser.timeout = server_socket_ds_parse_timeout;

    if(udp_server_socket_ds_parser.timer_started) {
        //If the timer is already running, stop and update
        uv_timer_stop(&(udp_server_socket_ds_parser.timer));
    } else {
        // Initiate the timer
        uv_timer_init(loop, &(udp_server_socket_ds_parser.timer));
        udp_server_socket_ds_parser.timer_started = true;
    }
    uv_timer_start(&(udp_server_socket_ds_parser.timer), udp_datagram_server_socket_timeout, \
        udp_server_socket_ds_parser.timeout, udp_server_socket_ds_parser.timeout);
    return UDPE_OK;
}


//************************************************************************************************//
//                                       CLIENT CALLBACKS                                         //
//************************************************************************************************//

//AK REVIST
static void udp_datagram_client_send_callback(uv_udp_send_t* sent_req, int status) {
    udp_easy_handle_t* easy_handle = (udp_easy_handle_t*)sent_req->data;
    if(likely(sent_req != NULL)) {
        if(likely(status == 0)) {
            easy_handle->dg_sent++;
            easy_handle->dg_size_sent += easy_handle->dg_size_to_send;
        } else {
            easy_handle->dg_send_fail++;
        }
        te_free(sent_req, TE_MTYPE_UDP_SEND_DATAGRAM);
        sent_req = NULL;
    } else {
        return;
    }

    //Upon completing all send of datagrams
    if(easy_handle->dg_sent + easy_handle->dg_send_fail == easy_handle->dg_to_send) {
        //Free the memory of the message got upon completion
        if(likely(easy_handle->conn_handle_back_ptr->base != NULL)) {
            te_free(easy_handle->conn_handle_back_ptr->base, TE_MTYPE_VOID);
            easy_handle->conn_handle_back_ptr->base = NULL;
        }
        if(easy_handle->multi_handle_back_ptr->user_send_callback_fptr) {
            udp_send_metrics_t send_metrics;
            send_metrics.dg_sent          = easy_handle->dg_sent;
            send_metrics.dg_size_sent     = easy_handle->dg_size_sent;
            send_metrics.dg_send_fail     = easy_handle->dg_send_fail;
            send_metrics.conn_open_fail   = easy_handle->conn_open_fail;
            send_metrics.new_conn_opened  = easy_handle->new_conn_opened;

            easy_handle->multi_handle_back_ptr->user_send_callback_fptr(send_metrics, \
                easy_handle->usr_ptr);
        }
    }
}

static void udp_datagram_client_recv_callback(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, \
    const struct sockaddr *from_addr, unsigned flags) {

    // nread specifies the size to read
    // If nread = 0 and from_addr is NULL, then there was nothing to read (Not an ERROR)
    // As of now coded to support only IPv4
    // The req has a private data pointer that points to udp_easy_handle_t

    //Size to read can't be negative
    if (unlikely(nread < 0)) {
        //AK Revisit UDP Metrics
        eprint("Read error %s\n", uv_err_name(nread));
    } else if(unlikely(flags != 0)) {
        //Partial receive
        eprint("Partial recv %d\n", flags);
    }

    //Read the message sent
    if (likely(from_addr != NULL && nread > 0)) {
        udp_easy_handle_t* easy_handle = (udp_easy_handle_t*)req->data;
        easy_handle->dg_rcvd++;
        easy_handle->dg_size_rcvd += nread - sizeof(udp_message_header_t);

        //Stop receiving upon completion
        if(easy_handle->dg_rcvd + easy_handle->dg_recv_timedout == easy_handle->dg_to_recv) {
            //Received all
            uv_udp_recv_stop(&(easy_handle->conn_handle_back_ptr->stream));
            //To make sure the timer doesn't trigger
            easy_handle->last_sent_ts = 0;
            //Make a callback to the user level upon completion
            if(easy_handle->multi_handle_back_ptr->user_recv_callback_fptr) {
                struct timespec current_time_struct;
                clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);

                udp_recv_metrics_t recv_metrics;
                recv_metrics.dg_rcvd          = easy_handle->dg_rcvd;
                recv_metrics.dg_size_rcvd     = easy_handle->dg_size_rcvd;
                recv_metrics.dg_recv_timedout = easy_handle->dg_recv_timedout;
                recv_metrics.latency = \
                    (current_time_struct.tv_sec - easy_handle->first_dg_sent_ts.tv_sec)*1000 + \
                    (double)(current_time_struct.tv_nsec  - easy_handle->first_dg_sent_ts.tv_nsec)/BILLION;

                easy_handle->multi_handle_back_ptr->user_recv_callback_fptr(recv_metrics, \
                    easy_handle->usr_ptr);
            }
        }
    }

    //Free the memory of the message got upon completion
    if(likely(buf->base != NULL)) {
        te_free(buf->base, TE_MTYPE_VOID);
    }
}

static void on_udp_socket_timeout(uv_timer_t *udp_socket_timer)
{
    // Get current time
    struct timespec current_time_struct;
    // Reference - https://www.cs.rutgers.edu/~pxk/416/notes/c-tutorials/gettime.html
    clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);
    unsigned long current_ts =  (unsigned long)((current_time_struct.tv_sec)*1000 + \
                            (double)(current_time_struct.tv_nsec)/BILLION);
    int assert_code;

    udp_multi_handle_t *multi_handle= (udp_multi_handle_t *) udp_socket_timer->data;
    unsigned long max_tolerable_wait_time;
    udp_easy_handle_t* easy_handle;

    if(unlikely(multi_handle->conn_handle == NULL)) {
        wprint("Conn handle is yet to be initialized\n");
        return;
    }
    for(int i=0; i<multi_handle->max_connects; ++i) {
        // Only if we had sent a request out and
        // when we are expecting a response we check if the socket has timed out
        easy_handle = multi_handle->conn_handle[i].easy_handle_back_ptr;
        if(easy_handle != NULL && easy_handle->last_sent_ts != 0 && \
            easy_handle->dg_to_recv != 0) {

            // Calculate the maximum tolerable delay
            max_tolerable_wait_time = easy_handle->last_sent_ts + easy_handle->timeout;

            //If we have exceeded the timeout, then stop receiving
            if(current_ts > max_tolerable_wait_time) {
                assert_code = uv_udp_recv_stop(&(multi_handle->conn_handle[i].stream));
                if(unlikely(assert_code != 0)) {
                    eprint("Unable to stop receiving %s\n", uv_err_name(assert_code));
                }

                // Make a user level receive callback to indicate that the socket has timedout
                if(multi_handle->user_recv_callback_fptr) {
                    easy_handle->dg_recv_timedout = easy_handle->dg_to_recv - easy_handle->dg_rcvd;
                    wprint("Stopping to receive on stream_id=%lu as current_ts=%lu and "\
                        "max_tolerable_wait_time=%lu\n", multi_handle->conn_handle[i].unique_id,
                        current_ts, max_tolerable_wait_time);

                    udp_recv_metrics_t recv_metrics;

                    recv_metrics.dg_rcvd          = easy_handle->dg_rcvd;
                    recv_metrics.dg_size_rcvd     = easy_handle->dg_size_rcvd;
                    recv_metrics.dg_recv_timedout = easy_handle->dg_recv_timedout;
                    recv_metrics.latency = (current_time_struct.tv_sec - easy_handle->first_dg_sent_ts.tv_sec)*1000 + \
                        (double)(current_time_struct.tv_nsec  - easy_handle->first_dg_sent_ts.tv_nsec)/BILLION;
                    multi_handle->user_recv_callback_fptr(recv_metrics, easy_handle->usr_ptr);
                }
            }
        }
    }
}

static UDPMcode send_client_udp_datagrams(udp_connection_t* conn_handle, udp_easy_handle_t* easy_handle) {

    int assert_code;
    UDPMcode return_code = UDPM_OK;

    // LIBUV understandable message to send out
    uv_buf_t buffer;
    size_t size_to_alloc = easy_handle->dg_size_to_send + sizeof(udp_message_header_t);
    udp_datagram_alloc_buffer(NULL, size_to_alloc, &buffer);
    easy_handle->conn_handle_back_ptr->base = buffer.base;

    udp_message_header_t udp_msg_header;
    udp_msg_header.total_request_dg = easy_handle->dg_to_send;
    udp_msg_header.response_num_dg  = easy_handle->dg_to_recv;
    udp_msg_header.response_size_dg = easy_handle->dg_size_to_recv;
    udp_msg_header.respond_now      = false;
    udp_msg_header.timeout          = easy_handle->timeout;
    udp_msg_header.unique_stream_id = conn_handle->unique_id;
    udp_msg_header.client_ip        = easy_handle->conn_handle_back_ptr->client_ip;
    udp_msg_header.client_port      = easy_handle->conn_handle_back_ptr->client_port;
    if (easy_handle->multi_handle_back_ptr->remote_sock_addr_v6 != NULL) {
        uint8_t *vip = easy_handle->multi_handle_back_ptr->remote_sock_addr_v6->sin6_addr.s6_addr;
        snprintf(udp_msg_header.vip , sizeof(udp_msg_header.vip), "%x%x%x%x%x%x%x%x", vip[0], vip[1], vip[2], \
            vip[3], vip[4], vip[5], vip[6], vip[7]);
        udp_msg_header.vport = easy_handle->multi_handle_back_ptr->remote_sock_addr_v6->sin6_port;
    } else {
        snprintf(udp_msg_header.vip , sizeof(udp_msg_header.vip), "%x", easy_handle->multi_handle_back_ptr->remote_sock_addr->sin_addr.s_addr);
        udp_msg_header.vport = easy_handle->multi_handle_back_ptr->remote_sock_addr->sin_port;
    }

    //copy the data from the header  to the base struct of the buffer
    memcpy(buffer.base, &udp_msg_header, sizeof(udp_message_header_t));

    // Populate the current time to calc latency
    clock_gettime(CLOCK_MONOTONIC_RAW, &(easy_handle->first_dg_sent_ts));

    //Send all except 1 (Last datagram is special -- can have respond now set)
    for(int i=0; i<easy_handle->dg_to_send-1; i++) {
        //Update the sequence number of the buffer
        ((udp_message_header_t*)buffer.base)->sequence_number = i;

        //Send the datagram
        uv_udp_send_t* send_req;
        te_malloc(send_req, sizeof(uv_udp_send_t), TE_MTYPE_UDP_SEND_DATAGRAM);
        send_req->data = easy_handle;

        assert_code = uv_udp_send(send_req, &(conn_handle->stream), &buffer, 1, NULL, \
            udp_datagram_client_send_callback);
        if(unlikely(assert_code != 0)) {
            eprint("Unable to send %s\n", uv_err_name(assert_code));
            return_code = UDPM_UNABLE_TO_SEND;
            udp_datagram_client_send_callback(send_req, assert_code);
        }
    }

    //Final datagram is special as it can have respond now set
    ((udp_message_header_t*)(buffer.base))->sequence_number = easy_handle->dg_to_send-1;

    //Set respond now to true for the last message and send if response is expected
    if(easy_handle->dg_to_recv != 0) {
        ((udp_message_header_t*)(buffer.base))->respond_now = true;
        //Last sent timestamp is only relevant if we expect a response
        struct timespec current_time_struct;
        clock_gettime(CLOCK_MONOTONIC_RAW, &current_time_struct);
        easy_handle->last_sent_ts = (current_time_struct.tv_sec)*1000 + \
                                    (double)(current_time_struct.tv_nsec)/BILLION;
    }

    //Send the datagram
    uv_udp_send_t* send_req;
    te_malloc(send_req, sizeof(uv_udp_send_t), TE_MTYPE_UDP_SEND_DATAGRAM);
    send_req->data = easy_handle;
    assert_code = uv_udp_send(send_req, &(conn_handle->stream), &buffer, 1, \
        NULL, udp_datagram_client_send_callback);
    if(unlikely(assert_code != 0)) {
        eprint("Unable to send %s\n", uv_err_name(assert_code));
        return_code = UDPM_UNABLE_TO_SEND;
        udp_datagram_client_send_callback(send_req, assert_code);
    }

    //Start to listen in the same socket for the response if response is expected
    if(easy_handle->dg_to_recv != 0) {
        conn_handle->stream.data = easy_handle;
        uv_udp_recv_start(&(conn_handle->stream), udp_datagram_alloc_buffer,
            udp_datagram_client_recv_callback);
    }
    return return_code;
}

//**********************************************//
//            CONFIGURING CONN_HANDLE           //
//**********************************************//
// Function configures the conn_handle(udp_connection_t*)'s uv_udp_t by binding locally
// and setting the conn_handle's state.
// By default conn_handle is at CONN_UNINITED state.
// It then moves on to CONN_INITED after uv_udp_init, and to CONN_CONNECTED_AND_BUSY after binding
// The conn_handle returns to CONN_CONNECTED_AND_FREE upon easy_cleanup() of the easy handle that was
// earlier attached to the conn_handle that way, the conn_handle is free to be used by other easy_handle
static bool udp_configure_conn(udp_connection_t* conn_handle, udp_easy_handle_t* easy_handle) {
    int assert_code;
    switch(conn_handle->status) {
        case CONN_UNINITED: {
            //Initing socket
            assert_code = uv_udp_init(loop, &(conn_handle->stream));
            if(likely(assert_code == 0)) {
                easy_handle->multi_handle_back_ptr->opened_udp_uv_handles++;
                conn_handle->status = CONN_INITED;
            }
            else {
                easy_handle->conn_open_fail++;
                eprint("Unable init connection to the VIP. %s\n", uv_err_name(assert_code));
                return false;
            }

            char *pos = strchr(easy_handle->multi_handle_back_ptr->str_ip, ':');
            if (pos) {
                if(easy_handle->multi_handle_back_ptr->remote_sock_addr_v6 == NULL) {
                    te_malloc(easy_handle->multi_handle_back_ptr->remote_sock_addr_v6,
                        sizeof(struct sockaddr_in6), TE_MTYPE_SOCK_ADDR);
                    uv_ip6_addr(easy_handle->multi_handle_back_ptr->str_ip, \
                        easy_handle->multi_handle_back_ptr->port, \
                        easy_handle->multi_handle_back_ptr->remote_sock_addr_v6);
                }

                assert_code = uv_udp_connect(&(conn_handle->stream),
                    (const struct sockaddr *)easy_handle->multi_handle_back_ptr->remote_sock_addr_v6);
            } else {
                // If the remore address has not been inited yet, then do so
                if(easy_handle->multi_handle_back_ptr->remote_sock_addr == NULL) {
                    te_malloc(easy_handle->multi_handle_back_ptr->remote_sock_addr,
                        sizeof(struct sockaddr_in), TE_MTYPE_SOCK_ADDR);
                    uv_ip4_addr(easy_handle->multi_handle_back_ptr->str_ip, \
                        easy_handle->multi_handle_back_ptr->port, \
                        easy_handle->multi_handle_back_ptr->remote_sock_addr);
                }

                assert_code = uv_udp_connect(&(conn_handle->stream),
                    (const struct sockaddr *)easy_handle->multi_handle_back_ptr->remote_sock_addr);
            }
            if(likely(assert_code == 0)) {
                conn_handle->status = CONN_CONNECTED_AND_BUSY;

                // Get the socket fd to get to generate unique id and to get the local ip and port
                uv_os_fd_t fd;
                uv_fileno((uv_handle_t*)&(conn_handle->stream), &fd);
                conn_handle->fd = fd;

                // The unique ID has to be unique across space and time, to avoid any collision
                // The unique ID is used by server only upon the collision of the has it uses to find
                // the socket node
                // Unique ID is generated XOR-ING a random_number ^ file_descriptor ^ PID ^ dp's mgmt ip and cpu core
                conn_handle->unique_id = rand() ^ conn_handle->fd ^ IPC_QUEUE_ID ^ \
                    tedp_mgmt_ip ^ pinned_cpu;

                struct sockaddr_in local_addr;
                unsigned int len = sizeof(local_addr);
                getsockname(fd, (struct sockaddr *)&local_addr, &len);
                conn_handle->client_ip   = ntohl(local_addr.sin_addr.s_addr);
                conn_handle->client_port = ntohs(local_addr.sin_port);
                easy_handle->new_conn_opened++;
                return true;
            }
            else {
                // Rolling back from init
                easy_handle->conn_open_fail++;
                eprint("Unable open a connection to the VIP. %s\n", uv_err_name(assert_code));
                return false;
            }
        } break;

        case CONN_INITED: {
            // One can hit the case, only if we init-ed the prev time, but was unable to connect
            // May be we hit the port range / some other erroneous case
            // Let us try to connect again
            if (easy_handle->multi_handle_back_ptr->remote_sock_addr_v6 != NULL) {
                assert_code = uv_udp_connect(&(conn_handle->stream),
                    (const struct sockaddr *)easy_handle->multi_handle_back_ptr->remote_sock_addr_v6);
            } else {
                assert_code = uv_udp_connect(&(conn_handle->stream),
                    (const struct sockaddr *)easy_handle->multi_handle_back_ptr->remote_sock_addr);
            }

            if(likely(assert_code == 0)) {
                conn_handle->status = CONN_CONNECTED_AND_BUSY;

                // Get the socket fd to get to generate unique id and to get the local ip and port
                uv_os_fd_t fd;
                uv_fileno((uv_handle_t*)&(conn_handle->stream), &fd);
                conn_handle->fd = fd;

                //Unique ID is generated XOR-ING a random_number ^ file_descriptor ^ PID
                conn_handle->unique_id = rand() ^ conn_handle->fd ^ IPC_QUEUE_ID ^ \
                    tedp_mgmt_ip ^ pinned_cpu;

                struct sockaddr_in local_addr;
                unsigned int len = sizeof(local_addr);
                getsockname(fd, (struct sockaddr *)&local_addr, &len);
                conn_handle->client_ip   = ntohl(local_addr.sin_addr.s_addr);
                conn_handle->client_port = ntohs(local_addr.sin_port);
                easy_handle->new_conn_opened++;
                return true;
            }
            else {
                easy_handle->conn_open_fail++;
                eprint("Unable open a connection to the VIP. %s\n", uv_err_name(assert_code));
                return false;
            }
        }

        case CONN_CONNECTED_AND_FREE: {
            conn_handle->status = CONN_CONNECTED_AND_BUSY;
            //Unique ID is generated XOR-ING a random_number ^ file_descriptor ^ PID
            conn_handle->unique_id = rand() ^ conn_handle->fd ^ IPC_QUEUE_ID ^ \
                tedp_mgmt_ip ^ pinned_cpu;
            return true;
        } break;

        case CONN_CONNECTED_AND_BUSY: {
            return false;
        } break;

        default: {
            abort();
            //Invalid state
        } break;
    }
    return false;
}

//**********************************************//
//     SEND UDP DATAGRAMS OR ADD TO PENDING     //
//**********************************************//
static UDPMcode udp_send_handle_or_add_to_pending(udp_multi_handle_t* multi_handle, udp_easy_handle_t* easy_handle) {
    // The function can be called as a part of
    // A) udp_multi_add_handle():
    //      if curr_used_conn is less than max_connects, then we do have a free conn_handle
    //          so use it to immediately fire the request
    //      else add to the pending handles
    // B) udp_easy_cleanup():
    //      This is called as a part of removing the UDP request from a conn_handle
    //      So it is expected that udp_easy_cleanup(), populates:
    //          New easy_handle's conn_handle to the just then completed conn_handle
    //          Set the status of then completed conn_handle to CONN_CONNECTED_AND_FREE

    bool conn_status;
    udp_pending_handle_node_t* node;
    easy_handle->multi_handle_back_ptr = multi_handle;

    if(multi_handle->curr_used_conn < multi_handle->max_connects) {

        // Case (B)
        if(easy_handle->conn_handle_back_ptr &&
            easy_handle->conn_handle_back_ptr->array_pos >=0 && \
            easy_handle->conn_handle_back_ptr->array_pos < multi_handle->max_connects) {
            conn_status = udp_configure_conn(
                &(multi_handle->conn_handle[easy_handle->conn_handle_back_ptr->array_pos]), \
                    easy_handle);

            if(conn_status) {
                //Hurray! The current position is free
                multi_handle->curr_used_conn++;
                multi_handle->conn_handle[easy_handle->conn_handle_back_ptr->array_pos].easy_handle_back_ptr = \
                    easy_handle;
            } else {
                // Since the connection was just use, it must be available for reuse
                // Let the code mature and then we can remove the abort and handle it better
                abort();
            }
        }

        // Case (A)
        else {
            //Check if current place is free to add
            conn_status = udp_configure_conn(
                &(multi_handle->conn_handle[multi_handle->curr_used_conn]), easy_handle);
            if(conn_status) {
                //Hurray! The current position is free
                //Make the association of easy_handle <---> conn_handle (bi-directional)
                easy_handle->conn_handle_back_ptr = &(multi_handle->conn_handle[multi_handle->curr_used_conn]);
                easy_handle->conn_handle_back_ptr->array_pos = multi_handle->curr_used_conn;
                multi_handle->conn_handle[easy_handle->conn_handle_back_ptr->array_pos].easy_handle_back_ptr = \
                    easy_handle;
                multi_handle->curr_used_conn++;
            }

            // If called as a part of multi_add_handle and curr_used_conn < max_connects/
            // We can hit the below case, only if we are unable to open a new conn (may be hit port range ?)
            // Or may be unable to connect to the VIP:VPORT ?
            // Let us add to the pending handle and see if we can fire the request at later point in time
            else {
                goto add_to_pending_handle;
            }
        }

        // We have a free easy_handle to fire
        return send_client_udp_datagrams(
            &multi_handle->conn_handle[easy_handle->conn_handle_back_ptr->array_pos],
            easy_handle);
    }

    // Unable to find a free easy_handle!
    // This case happen only as a part of Case(A), and it means we no longer have a free conn_handle
    // Add to pending handle and we will fire the request when
    // one of the conn_handle becomes free as a part of easy_cleanup()
    // Add to the LL and hope for others to complete
    add_to_pending_handle:
        te_malloc(node, sizeof(udp_pending_handle_node_t), TE_MTYPE_UDP_CLIENT_PENDING_REQUEST);
        node->easy_handle = easy_handle;
        node->next = NULL;

        if(!multi_handle->pending_handle_head || !multi_handle->pending_handle_tail) {
            multi_handle->pending_handle_tail = multi_handle->pending_handle_head = node;
        } else {
            multi_handle->pending_handle_tail->next = node;
            multi_handle->pending_handle_tail = node;
        }
        return UDPM_OK_PENDING_TO_SEND;
}


//**********************************************//
//            UDP MULTI HANDLE LIBRARY          //
//**********************************************//
udp_multi_handle_t* udp_multi_init(void) {
    tprint("MULTI UDP HANDLE: INIT\n");
    udp_multi_handle_t* multi_handle;
    te_malloc(multi_handle, sizeof(udp_multi_handle_t), TE_MTYPE_UDP_CLIENT_MULTI_HANDLE);
    memset(multi_handle, 0, sizeof(udp_multi_handle_t));
    if(likely(multi_handle)) {
        multi_handle->max_connects = 1;
        multi_handle->curr_used_conn = 0;
        multi_handle->conn_handle = NULL;
        multi_handle->pending_handle_head = NULL;
        multi_handle->pending_handle_tail = NULL;
        multi_handle->socket_timeout = DEFAULT_RESP_DG_TIMEOUT;
    } else {
        abort();
    }
    return multi_handle;
}

//The callback decrements the number of opened sockets until 0
//Once 0 is reached, the array of conn handle and multi handle is freed
void udp_socket_close_cb(uv_handle_t* udp_conn) {
    udp_multi_handle_t* multi_handle = (udp_multi_handle_t*)udp_conn->data;
    multi_handle->opened_udp_uv_handles--;
    if(multi_handle->opened_udp_uv_handles == 0) {
        te_free(multi_handle->conn_handle, TE_MTYPE_UDP_CLIENT_CONN_HANDLE);
        multi_handle->conn_handle = NULL;
        if (multi_handle->remote_sock_addr_v6 != NULL) {
            te_free(multi_handle->remote_sock_addr_v6, TE_MTYPE_SOCK_ADDR);
            multi_handle->remote_sock_addr_v6 = NULL;
        }
       if (multi_handle->remote_sock_addr != NULL) {
            te_free(multi_handle->remote_sock_addr, TE_MTYPE_SOCK_ADDR);
            multi_handle->remote_sock_addr = NULL;
        }
        te_free(multi_handle, TE_MTYPE_UDP_CLIENT_MULTI_HANDLE);
        multi_handle = NULL;
    }
}

UDPMcode udp_multi_cleanup(udp_multi_handle_t* multi_handle) {
    if(!multi_handle) {
        return UDPM_NULL_MULTI_HANDLE;
    }
    //When multi handle is called, we make sure there are not any pending request to send
    if(multi_handle->pending_handle_head != NULL) {
        udp_pending_handle_node_t *temp, *node = multi_handle->pending_handle_head;
        while(node) {
            temp = node;
            node = node->next;
            free(temp);
        }
    }
    multi_handle->pending_handle_head = NULL;
    multi_handle->pending_handle_tail = NULL;
    multi_handle->curr_used_conn = 0;

    // Stop the timer only if it had been started which is
    // indicated by non-zero multi_handle->socket_timeout
    if(multi_handle->socket_timeout != 0) {
        uv_timer_stop(&(multi_handle->udp_socket_timer));
        multi_handle->udp_socket_timer.data = multi_handle;
        uv_close((uv_handle_t *)&multi_handle->udp_socket_timer, udp_socket_close_cb);
    }

    // Make callback to close all the opened sockets
    // Once all opened sockets are closed, the callback frees the multi handle as well
    // NOTE: Not all sockets need to be used. So we need to have a check on the status before
    // calling uv_close
    for(int i=0; i<multi_handle->max_connects; i++) {
        if(multi_handle->conn_handle[i].status != CONN_UNINITED) {
            multi_handle->conn_handle[i].stream.data = multi_handle;
            uv_close((uv_handle_t*) &(multi_handle->conn_handle[i].stream), udp_socket_close_cb);
        }
    }

    return UDPM_OK;
}

//**********************************************//
//                UDP MULTI SETOPT              //
//**********************************************//
// Multi handle set opt
// Options set here are reflected to all the UDP streams opened as a part of this multi handle
// The below function sets opts that has the value passed to it that are of int (or) similar types
UDPMcode udp_multi_setopt_integer(udp_multi_handle_t* multi_handle, \
                        unsigned short opt, \
                        unsigned short val) {
    if(!unlikely(multi_handle)) {
        return UDPM_NULL_MULTI_HANDLE;
    }

    UDPMcode return_code = UDPM_OK;
    switch(opt) {

        //Maximum number of connection that can be opened as a part of this multi handle
        case UDP_MAX_CONNECTS: {
            if(likely(val > 0))
                multi_handle->max_connects = val;
            else
                return_code = UDPM_INVALID_OPT;
        } break;

        //UDP port to connect to
        case UDP_PORT: {
            if(likely(val > 0))
                multi_handle->port = val;
            else
                return_code = UDPM_INVALID_OPT;
        } break;

        //Minimum timout of sockets
        case UDP_SOCKET_TIMEOUT: {
            if(likely(val >= 0))
                multi_handle->socket_timeout = val;
            else
                return_code = UDPM_INVALID_OPT;
        } break;

        //Anyother option passed to this function is invalid
        default: {
            return_code = UDPM_INVALID_OPT;
        } break;
    }
    return return_code;
}

// The below function sets opts that has the value passed to it that are of pointer type
UDPMcode udp_multi_setopt_ptr(udp_multi_handle_t* multi_handle, unsigned short opt, void* val) {
    if(unlikely(!multi_handle)) {
        return UDPM_NULL_MULTI_HANDLE;
    }

    UDPMcode return_code = UDPM_OK;
    switch(opt) {
        //Remote IP to hit
        case UDP_IP: {
            if(multi_handle->str_ip) {
                te_free(multi_handle->str_ip, TE_MTYPE_CHAR);
            }
            char* url = (char*) val;
            if(likely(url)) {
                int url_len = strlen(url)+1;
                te_malloc(multi_handle->str_ip, url_len, TE_MTYPE_CHAR);
                memset(multi_handle->str_ip, 0, url_len);
                snprintf(multi_handle->str_ip, url_len, "%s", url);
            }
            else
                return_code = UDPM_INVALID_OPT;
        } break;

        //Send callback to call. The function pointer is called for every sent out request
        case UDP_SEND_CALLBACK: {
            if(likely(val))
                multi_handle->user_send_callback_fptr = val;
            else
                return_code = UDPM_INVALID_OPT;
        } break;

        //Receive callback to call. The function pointer is called for every received request
        case UDP_RECV_CALLBACK: {
            if(likely(val))
                multi_handle->user_recv_callback_fptr = val;
            else
                return_code = UDPM_INVALID_OPT;
        } break;

        //Anyother option passed to the function is invalid
        default: {
            return_code = UDPM_INVALID_OPT;
        } break;
    }
    return return_code;
}

//**********************************************//
//        ADD EASY HANDLE TO MULTI HANDLE       //
//**********************************************//
// To malloc the conn_handle of the multi_handle and set approriate params
static void udp_init_conn_handle(udp_multi_handle_t* multi_handle) {
    te_malloc(multi_handle->conn_handle, multi_handle->max_connects * sizeof(udp_connection_t),
        TE_MTYPE_UDP_CLIENT_CONN_HANDLE);
    memset(multi_handle->conn_handle, 0, multi_handle->max_connects * sizeof(udp_connection_t));
}

UDPMcode udp_multi_add_handle(udp_multi_handle_t* multi_handle, udp_easy_handle_t* easy_handle) {
    if(unlikely(!multi_handle)) {
        return UDPM_NULL_MULTI_HANDLE;
    }
    if(unlikely(!multi_handle->str_ip)) {
        return UDPM_NULL_IP;
    }
    if(unlikely(!multi_handle->port)) {
        return UDPM_INVALID_PORT;
    }
    if(unlikely(!easy_handle)) {
        return UDPM_NULL_EASY_HANDLE;
    }

    // We try to use the connection easy_handle if available immediately and send the easy_handle out
    // Else we accept the easy_handle and add it to a pending linked list of handles
    // During the callbacks (either timed out (or) upon completion) we remove from the ll
    // and add the easy_handle to the just completed connection

    if(!multi_handle->conn_handle) {
        udp_init_conn_handle(multi_handle);
        // Start the timer for this session only if we expect response coming at all
        if(multi_handle->socket_timeout != 0) {
            uv_timer_init(loop, &(multi_handle->udp_socket_timer));
            multi_handle->opened_udp_uv_handles++;
            multi_handle->udp_socket_timer.data = multi_handle;
            uv_timer_start(&(multi_handle->udp_socket_timer), on_udp_socket_timeout, \
                multi_handle->socket_timeout, multi_handle->socket_timeout);
        }
    }

    return udp_send_handle_or_add_to_pending(multi_handle, easy_handle);
}



//**********************************************//
//             UDP EASY HANDLE LIBRARY          //
//**********************************************//
udp_easy_handle_t* udp_easy_init(void) {
    udp_easy_handle_t* udp_easy_handle;
    te_malloc(udp_easy_handle, sizeof(udp_easy_handle_t), TE_MTYPE_UDP_CLIENT_EASY_HANDLE);
    memset(udp_easy_handle, 0, sizeof(udp_easy_handle_t));
    if(likely(udp_easy_handle)) {
        //Setting defaults to avoid crashes
        udp_easy_handle->dg_to_send = 1;
        udp_easy_handle->dg_size_to_send = 1;
        udp_easy_handle->dg_to_recv = 0;
        udp_easy_handle->dg_size_to_recv = 0;
        udp_easy_handle->timeout = DEFAULT_RESP_DG_TIMEOUT;
        udp_easy_handle->conn_handle_back_ptr = NULL;   //Not associated as yet
        udp_easy_handle->multi_handle_back_ptr = NULL;  //Not associated as yet
    }
    else {
        abort();
    }
    return udp_easy_handle;
}

UDPEcode udp_easy_cleanup(udp_easy_handle_t* easy_handle) {
    if(unlikely(!easy_handle)) {
        return UDPE_NULL_EASY_HANDLE;
    }
    udp_multi_handle_t* multi_handle = easy_handle->multi_handle_back_ptr;

    //Decrement the counter as the conn is now not being actively used
    multi_handle->curr_used_conn--;
    //Make the status of the conn as binded and freed
    easy_handle->conn_handle_back_ptr->status = CONN_CONNECTED_AND_FREE;
    //Since the conn has finished the easy_handle, make it point to NULL
    easy_handle->conn_handle_back_ptr->easy_handle_back_ptr = NULL;

    //If there are pending handles to be added, add then
    if(multi_handle->pending_handle_head != NULL) {

        // Since the current easy handle is completed, it's conn handle is anyways free
        // So associate the handle with the new easy_handle
        // and fire the request by calling udp_send_handle_or_add_to_pending
        multi_handle->pending_handle_head->easy_handle->conn_handle_back_ptr = \
            easy_handle->conn_handle_back_ptr;

        udp_send_handle_or_add_to_pending(multi_handle, \
            multi_handle->pending_handle_head->easy_handle);

        //Free the current head and move to the next node
        udp_pending_handle_node_t *old_head = multi_handle->pending_handle_head;
        multi_handle->pending_handle_head = multi_handle->pending_handle_head->next;
        te_free(old_head, TE_MTYPE_UDP_CLIENT_PENDING_REQUEST);
        old_head = NULL;

        // After moving if head is pointing to NULL, then it means that,
        // It was the last pending request, so set tail to NULL as well
        if(multi_handle->pending_handle_head == NULL)
            multi_handle->pending_handle_tail = NULL;
    }

    easy_handle->conn_handle_back_ptr = NULL;
    easy_handle->multi_handle_back_ptr = NULL;

    te_free(easy_handle, TE_MTYPE_UDP_CLIENT_EASY_HANDLE);
    easy_handle = NULL;

    return UDPE_OK;
}

//**********************************************//
//                 UDP EASY SETOPT              //
//**********************************************//

// Options set here are reflected to all the UDP streams opened as a part of this easy handle
// The below function sets opts that has the value passed to it that are of int (or) similar types
UDPEcode udp_easy_setopt_integer(udp_easy_handle_t* easy_handle, unsigned short opt, short unsigned int val) {
    if(unlikely(!easy_handle)) {
        return UDPE_NULL_EASY_HANDLE;
    }

    UDPEcode return_code = UDPE_OK;
    switch(opt) {
        case UDP_DG_NUM_TO_SEND: {
            if(likely(val > 0))
                easy_handle->dg_to_send = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        case UDP_DG_SIZE_TO_SEND: {
            if(likely(val > 0))
                easy_handle->dg_size_to_send = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        case UDP_DG_NUM_TO_RECV: {
            if(val > 0)
                easy_handle->dg_to_recv = val;
            else if(val == 0)
                easy_handle->dg_size_to_recv = easy_handle->dg_to_recv = 0;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        case UDP_DG_SIZE_TO_RECV: {
            if(val > 0)
                easy_handle->dg_size_to_recv = val;
            else if(val == 0)
                easy_handle->dg_size_to_recv = easy_handle->dg_to_recv = 0;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        case UDP_RECV_TIMEOUT: {
            if(likely(val >= 0))
                easy_handle->timeout = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

        default: {
            return_code = UDPE_INVALID_OPT;
        } break;
    }
    return return_code;
}

// The below function sets opts that has the value passed to it that are of pointer type
UDPEcode udp_easy_setopt_ptr(udp_easy_handle_t* easy_handle, unsigned short opt, void* val) {
    if(!easy_handle) {
        return UDPE_NULL_EASY_HANDLE;
    }

    UDPEcode return_code = UDPE_OK;
    switch(opt) {
        case UDP_PRIVATE: {
            if(likely(val))
                easy_handle->usr_ptr = val;
            else
                return_code = UDPE_INVALID_OPT;
        } break;

       default: {
            return_code = UDPE_INVALID_OPT;
        } break;
    }
    return return_code;
}
