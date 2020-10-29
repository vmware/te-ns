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

#ifndef TE_SOCK_H
#include "te_sock.h"
#endif

te_socket_hashTbl_t te_socket_hashTbl;
extern te_resource_config_t* res_cfg;
extern tedp_profile_t tedp_profile;

//*************************************************************************//
//                       COMMON FUNCTIONS TO TCP&UDP                       //
//*************************************************************************//
void te_create_socket_hashTbl(unsigned int size)
{
    te_socket_hashTbl.size = size;
    te_socket_hashTbl.num_entries = 0;
    if(!te_socket_hashTbl.buckets) {
        te_malloc(te_socket_hashTbl.buckets, size * sizeof(te_socket_hash_t), TE_MTYPE_SOCKET_HASH);
    }
    if(unlikely(!te_socket_hashTbl.buckets)) {
        eprint("Unable to create socketHashTable.\n");
        exit(0);
    }
    memset(te_socket_hashTbl.buckets, 0, sizeof(te_socket_hash_t) * size);
    return;
}


void free_socket_node(uv_handle_t *socket_poll_handle)
{
    te_socket_node_t *socket_node = socket_poll_handle->data;
    te_socket_hashTbl.num_entries--;
    te_free(socket_node, TE_MTYPE_SOCKET_NODE);
    socket_node = NULL;
    if(te_socket_hashTbl.num_entries == 0 && res_cfg->update_flag) {
        // init te_dp after flushing all the entries in socket_table.
	    te_free(te_socket_hashTbl.buckets, TE_MTYPE_SOCKET_HASH);
        te_socket_hashTbl.buckets = NULL;
        te_socket_hashTbl.size = 0;
        init_te_dp(0);
    }
    return;
}

void te_delete_socket_hashTbl()
{
    unsigned int bucket_iter = 0;
    te_socket_node_t *socket_node = NULL;
    te_socket_node_t *temp;
    if (te_socket_hashTbl.num_entries) {
        for(bucket_iter = 0; bucket_iter < te_socket_hashTbl.size;
            bucket_iter++) {
            socket_node=te_socket_hashTbl.buckets[bucket_iter].head;
            while(socket_node) {
                temp = socket_node->next;
                switch(tedp_profile) {
                    case TCP: {
                        socket_node->tcp_poll_handle.data = socket_node;
                        uv_close((uv_handle_t *)&socket_node->tcp_poll_handle, free_socket_node);
                    } break;
                    case UDP: {
                        socket_node->udp_server_easy_handle_back_ptr->uv_udp_handle.data = socket_node;
                        uv_close(
                            (uv_handle_t *)&(socket_node->udp_server_easy_handle_back_ptr->uv_udp_handle), \
                            free_socket_node);
                    } break;
                    default: {
                        eprint("Unknown tedp_profile\n");
                        abort();
                    }
                }
                te_socket_hashTbl.buckets[bucket_iter].count--;
                socket_node = temp;
            }
        }
    }
    else if(res_cfg->update_flag) {
        if (te_socket_hashTbl.buckets) {
           te_free(te_socket_hashTbl.buckets, TE_MTYPE_SOCKET_HASH);
           te_socket_hashTbl.buckets = NULL;
        }
        te_socket_hashTbl.size = 0;
    }
    return;
}

void te_insert_into_socket_hashTbl(te_socket_node_t *socket_node, int te_socket_hashIndex)
{
    /* head of list for the bucket with index "te_socket_hashIndex" */
    if(!te_socket_hashTbl.buckets[te_socket_hashIndex].head) {
       te_socket_hashTbl.buckets[te_socket_hashIndex].head = socket_node;
       te_socket_hashTbl.buckets[te_socket_hashIndex].count = 1;
       te_socket_hashTbl.num_entries++;
       return;
    }

    /* adding new te_socket_node to the list */
    socket_node->next = te_socket_hashTbl.buckets[te_socket_hashIndex].head;

    /*
     * update the head of the list and no of
     * te_socket_nodes in the current bucket
     */
    te_socket_hashTbl.buckets[te_socket_hashIndex].head = socket_node;
    te_socket_hashTbl.buckets[te_socket_hashIndex].count++;
    te_socket_hashTbl.num_entries++;
    return;
}

//*************************************************************************//
//                            TCP SOCKET HASH                              //
//*************************************************************************//

te_socket_node_t* te_search_tcp_socket_hash(unsigned int sockfd)
{
    unsigned int te_socket_hashIndex = sockfd % te_socket_hashTbl.size;
    te_socket_node_t *socket_node = NULL;

    socket_node = te_socket_hashTbl.buckets[te_socket_hashIndex].head;
    if (unlikely(!socket_node)) {
       // dprint("Search element unavailable in te_socket_hash table\n");
       return NULL;
    }
    while(socket_node) {
       if(socket_node->tcp_sockfd == sockfd) {
           return socket_node;
       }
       socket_node = socket_node->next;
    }
    return NULL;
}

te_socket_node_t* te_create_or_retrieve_tcp_socket(curl_socket_t sockfd, te_session_t* session_p)
{
    te_socket_node_t *socket_node = te_search_tcp_socket_hash(sockfd);
    if(socket_node) {
        socket_node->session_p = session_p;
        return socket_node;
    }

    te_malloc(socket_node, sizeof(te_socket_node_t), TE_MTYPE_SOCKET_NODE);
    if(likely(socket_node)) {
       memset(socket_node, 0, sizeof(te_socket_node_t));
       socket_node->tcp_sockfd = sockfd;
       socket_node->session_p = session_p;
       socket_node->next = NULL;
       if (uv_poll_init_socket(loop, &socket_node->tcp_poll_handle, sockfd)) {
            wprint("Failed allocating uv_handle on sockfd:%d\n", sockfd);
            abort();
        }
        socket_node->tcp_poll_handle.data = socket_node;
        int te_socket_hashIndex = socket_node->tcp_sockfd % te_socket_hashTbl.size;
        te_insert_into_socket_hashTbl(socket_node, te_socket_hashIndex);
	}
    return socket_node;
}

//*************************************************************************//
//                            UDP SOCKET HASH                              //
//*************************************************************************//

te_socket_node_t* te_search_udp_socket_hash(unsigned int hash, unsigned int client_ip, \
    unsigned short client_port, unsigned long unique_stream_id, \
    udp_server_easy_handle_t *udp_server_easy_handle)
{
    te_socket_node_t *socket_node = NULL;
    socket_node = te_socket_hashTbl.buckets[hash].head;
    if (unlikely(!socket_node)) {
       return NULL;
    }
    while(socket_node) {
        if(socket_node->state.unique_stream_id == unique_stream_id &&
            socket_node->client_ip == client_ip && socket_node->client_port == client_port &&
            socket_node->udp_server_easy_handle_back_ptr &&
            socket_node->udp_server_easy_handle_back_ptr->d_port == udp_server_easy_handle->d_port) {
            //Everything matches, then return
            return socket_node;
        } else {
            //Goto Next Node
            socket_node = socket_node->next;
        }
    }
    return NULL;
}

te_socket_node_t* te_create_or_retrieve_udp_server_socket(struct sockaddr_in remote_sock_addr, \
    unsigned int client_ip, unsigned short client_port, unsigned long unique_stream_id, \
    udp_server_easy_handle_t *udp_server_easy_handle) {
    // Calculating Hash taken from AVI code
    // XORing that value with the unique stream id
    unsigned int hash = ( ((((client_ip & 0x0f000000) >> 9) + fswap(client_port) + \
        fswap(udp_server_easy_handle->d_port) ) & 524287) ^ unique_stream_id) % te_socket_hashTbl.size;

    te_socket_node_t *socket_node = te_search_udp_socket_hash(hash, client_ip, client_port, \
        unique_stream_id, udp_server_easy_handle);
    if(socket_node) {
        return socket_node;
    }

    te_malloc(socket_node, sizeof(te_socket_node_t), TE_MTYPE_SOCKET_NODE);
    if(likely(socket_node)) {
        memset(socket_node, 0, sizeof(te_socket_node_t));
        socket_node->client_ip = client_ip;
        socket_node->client_port = client_port;
        socket_node->state.unique_stream_id = unique_stream_id;
        socket_node->remote_sock_addr = remote_sock_addr;
        socket_node->udp_server_easy_handle_back_ptr = udp_server_easy_handle;
        socket_node->next = NULL;
        te_insert_into_socket_hashTbl(socket_node, hash);
    }
    return socket_node;
}

void te_remove_udp_server_socket_node(te_socket_node_t *socket_node) {

    unsigned int hash = ( ((((socket_node->client_ip & 0x0f000000) >> 9) + \
        fswap(socket_node->client_port) + \
        fswap(socket_node->udp_server_easy_handle_back_ptr->d_port) ) & 524287) ^ \
        socket_node->state.unique_stream_id) % te_socket_hashTbl.size;

    te_socket_node_t *temp = te_socket_hashTbl.buckets[hash].head, *prev=NULL;

    // If head node itself holds the key to be deleted
    if(temp != NULL &&
        temp->state.unique_stream_id == socket_node->state.unique_stream_id &&
        temp->client_ip == socket_node->client_ip &&
        temp->client_port == socket_node->client_port &&
        temp->udp_server_easy_handle_back_ptr &&
        temp->udp_server_easy_handle_back_ptr->d_port == \
            socket_node->udp_server_easy_handle_back_ptr->d_port) {
        te_socket_hashTbl.buckets[hash].head = temp->next;        // Changed head
        goto free_socket_node;
    }

    // Search for the key to be deleted, keep track of the
    // previous node as we need to change 'prev->next'
    while(temp != NULL && \
        (temp->state.unique_stream_id != socket_node->state.unique_stream_id ||
            temp->client_ip != socket_node->client_ip ||
            temp->client_port != socket_node->client_port ||
            temp->udp_server_easy_handle_back_ptr->d_port != \
                socket_node->udp_server_easy_handle_back_ptr->d_port)) {
            prev = temp;
            temp = temp->next;
    }

    // If key was not present in linked list
    if (temp == NULL)
        return;

    // Unlink the node from linked list
    prev->next = temp->next;

    free_socket_node:
        if(temp->base != NULL) {
            te_free(temp->base, TE_MTYPE_VOID);
            temp->base = NULL;
        }
        temp->udp_server_easy_handle_back_ptr = NULL;
        te_free(temp, TE_MTYPE_SOCKET_NODE);  // Free memory
        temp = NULL;
}

void te_udp_sock_parse_on_timeout(double current_time) {
    te_socket_node_t *prev, *node, *temp;
    unsigned long long_current_time = (unsigned long)current_time;
    unsigned long max_tolerable_wait_time;

    for(int i=0; i< te_socket_hashTbl.size; i++) {
        prev = node = temp = NULL;
        node = te_socket_hashTbl.buckets[i].head;
        while(node) {
            // Parse and make callback to the user level logic to indicate timeouts
            // Also delete the nodes if timedout
            max_tolerable_wait_time = node->state.last_ts + node->state.timeout;
            if(node->state.timeout != 0 && node->state.status == SERVER_SOCKET_RECV_DG && \
                max_tolerable_wait_time < long_current_time) {
                if(node->udp_server_easy_handle_back_ptr->user_recv_callback_fptr) {

                    udp_recv_metrics_t recv_metrics;
                    recv_metrics.dg_rcvd          = node->metric.dg_rcvd;
                    recv_metrics.dg_size_rcvd     = node->metric.dg_size_rcvd;
                    recv_metrics.dg_recv_timedout = node->metric.dg_to_recv - node->metric.dg_rcvd;
                    recv_metrics.latency          = current_time - node->state.first_dg_rcvd_ts;

                    eprint("Timedout and so making recv callback from te_udp_sock_parse_on_timeout "\
                        "stream_id=%lu as current_ts=%lu and max_tolerable_wait_time=%lu\n",
                        node->state.unique_stream_id, long_current_time, max_tolerable_wait_time);

                    /*If there is a callback to make, make it*/
                    node->udp_server_easy_handle_back_ptr->user_recv_callback_fptr(
                        node->state.vip, node->state.vport, recv_metrics, \
                        node->udp_server_easy_handle_back_ptr->usr_ptr);
                }
                if(node == te_socket_hashTbl.buckets[i].head) {
                    // Change head if we need to remove the head node, itself
                    te_socket_hashTbl.buckets[i].head = node->next;
                } else {
                    // Make appropriate change to the previous node's next
                    prev->next = node->next;
                }
                tprint("te_udp_sock_parse_on_timeout called for socket_node=%p, "\
                    "socket_node->easy_handle=%p\n", node, \
                    node->udp_server_easy_handle_back_ptr);
                temp = node;
                node = node->next;
                temp->udp_server_easy_handle_back_ptr = NULL;
                temp->next = NULL;
                te_free(temp, TE_MTYPE_SOCKET_NODE);
                te_socket_hashTbl.buckets[i].count--;
            } else {
                prev = node;
                node = node->next;
            }
        }
    }
}
