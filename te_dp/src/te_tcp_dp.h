#ifndef TE_TCP_DP_H
#define TE_TCP_DP_H

#include <openssl/ssl.h>

#ifndef TE_DP_H
#include "te_dp.h"
#endif

void update_tcp_session_config_metrics(te_session_t*);
void load_tcp_random_session_data(te_session_t*);
void load_session_metrics(CURL*, CURLcode);
void init_tcp_multi_handle(te_session_t*);
void flush_tcp_multi_handle(te_session_t*);
void add_tcp_request(te_session_t*);
void delete_tcp_request(te_tcp_request_t*);

#endif
