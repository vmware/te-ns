#ifndef TE_UDP_DP_H
#define TE_UDP_DP_H

#ifndef TE_DP_H
#include "te_dp.h"
#endif

#ifndef TE_UDP_LIB_H
#include "te_udp_lib.h"
#endif

#define TE_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define TE_MIN(x, y) (((x) < (y)) ? (x) : (y))

void te_udp_datagram_alloc_buffer(uv_handle_t*, size_t, uv_buf_t*);
void te_udp_on_read(uv_udp_t*, ssize_t, const uv_buf_t*, const struct sockaddr*, unsigned);
void load_udp_random_session_data(te_session_t*);
void init_udp_multi_handle(te_session_t*);
void flush_udp_multi_handle(te_session_t*);
void add_udp_request(te_session_t*);
void delete_udp_request(te_session_t*);
void update_udp_session_config_metrics(te_session_t*);
void te_start_udp_listen();
void te_create_server_metrics_hash_table(unsigned int);
#endif