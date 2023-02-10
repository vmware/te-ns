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

#ifndef TE_AGENT_H
#define TE_AGENT_H

#include <stdio.h>
#include <curl/curl.h>
#include <uv.h>
#include <math.h>

#ifndef TE_DP_H
#include "te_dp.h"
#endif

#ifndef TE_METRICS_H
#include "te_metrics.h"
#endif

#define TRUE true
#define FALSE false
//For parsing interface, get and post profiles
typedef struct te_bst_node_s
{
    const char* key;
    int value;
    struct te_bst_node_s *left, *right;
} te_bst_node_t;

extern uv_loop_t *loop;

void init_te_dp(bool is_update);
void update_te_dp();

//CRD for global resources.
void te_create_resources();
void te_cleanup_resources();

void te_open_logger_files();
void te_print_formatters();

//CRUD for session_config.
void te_process_session_config (const char *, bool);
void te_cleanup_session_config();
void te_create_session_config(te_session_config_t *session_cfg);
void te_delete_session_config(te_session_config_t *session_cfg);
void te_signal_session_config(te_session_config_t *session_cfg);
void te_push_session_config_fsm(TE_SESSION_CONFIG_STATE state);

void session_config_uv_async(uv_async_t *req);
void te_tedp_poll_uv_cb(uv_poll_t *req, int status, int events);

#endif
