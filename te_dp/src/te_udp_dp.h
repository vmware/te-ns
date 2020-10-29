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
