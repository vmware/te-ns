#ifndef TE_SOCK_H
#define TE_SOCK_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct te_socket_node_s te_socket_node_t;
typedef struct te_socket_hash_s te_socket_hash_t;
typedef struct te_socket_hashTbl_s te_socket_hashTbl_t;

#ifndef TE_DP_H
#include "te_dp.h"
#endif

#ifndef TE_UDP_LIB_H
#include "te_udp_lib.h"
#endif

#define fswap(_x)  (unsigned short) ( (_x) << 8 | (_x) >> 8 )

typedef struct te_udp_server_sock_metric_s {
    unsigned short dg_to_send;
    unsigned short dg_size_to_send;
    unsigned short dg_sent;
    unsigned short dg_size_sent;
    unsigned short dg_send_fail;

    unsigned short dg_to_recv;
    unsigned short dg_rcvd;
    unsigned short dg_size_rcvd;
    unsigned short dg_recv_timedout;
} te_udp_server_sock_metric_t;

typedef enum {
    SERVER_SOCKET_INIT,
    SERVER_SOCKET_RECV_DG,
    SERVER_SOCKET_SEND_DG,
    SERVER_SOCKET_BUFFER_DG
} server_socket_status_t;

typedef struct te_udp_server_sock_state_s {
    server_socket_status_t status;
    unsigned long          unique_stream_id;
    bool                   respond_now_recd;
    time_t                 last_ts;
    unsigned long          timeout;
    // dg sent and rcvd timestamp -- to calculate latency from the server perspective
    double                 first_dg_rcvd_ts;
    unsigned long          vip, client_ip;
    unsigned short         vport, client_port;
} te_udp_server_sock_state_t;

typedef struct te_socket_node_s {
    //**************************************//
    //                TCP                   //
    //**************************************//
    uv_poll_t              tcp_poll_handle;   // uv-poll fd associated with socket.
    curl_socket_t          tcp_sockfd;        // socket fd for the poll.
    te_session_t           *session_p;    // socket pointer to which the node belongs to


    //**************************************//
    //                UDP                   //
    //**************************************//

    // Note that the remote_sock_addr's ip and port need not be same as client_ip and client_port
    // The IP and Port in remote_sock_addr can denote the AVI's src port and ip
    struct sockaddr_in            remote_sock_addr;
    unsigned int                  client_ip;
    unsigned short                client_port;

    te_udp_server_sock_metric_t   metric;
    te_udp_server_sock_state_t    state;
    void                          *base;

    udp_server_easy_handle_t      *udp_server_easy_handle_back_ptr;

    te_socket_node_t              *next;         // The hash table has ll of socket nodes
} te_socket_node_t;

typedef struct te_socket_hash_s {
    te_socket_node_t *head;  // Array of head pointers of socket_nodes.
    unsigned int     count;  // Elements in Hash table.
} te_socket_hash_t;

typedef struct te_socket_hashTbl_s {
	te_socket_hash_t *buckets;  // Array of hash buckets.
	unsigned int size;          // num of hash buckets.
    unsigned int num_entries;   // num_entries in hash table.
} te_socket_hashTbl_t;

te_socket_node_t* te_create_or_retrieve_tcp_socket(curl_socket_t, te_session_t*);
te_socket_node_t* te_create_or_retrieve_udp_server_socket(struct sockaddr_in, unsigned int, \
    unsigned short, unsigned long, udp_server_easy_handle_t *);
void te_udp_sock_parse_on_timeout(double);
void te_remove_udp_server_socket_node(te_socket_node_t*);
void te_create_socket_hashTbl(unsigned int);
void te_delete_socket_hashTbl();
#endif
