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

#ifndef TE_METRICS_H
#define TE_METRICS_H

#ifndef TE_DP_H
#include "te_dp.h"
#endif

#ifndef TE_MEMORY_H
#include "te_memory.h"
#endif

//Messages

typedef struct te_http_vip_metrics_msg_s
{
    long type;
    te_http_vip_stats_t http_stats;
    short num_buckets;
    char vip[TEDP_MAX_STR_LEN];
    char res_hash[TEDP_MAX_STR_LEN];
    char ses_hash[TEDP_MAX_STR_LEN];
} te_http_vip_metrics_msg_t;

typedef struct te_udp_client_vip_metrics_msg_s
{
    long type;
    te_udp_vip_stats_t udp_stats;
    char vip[TEDP_MAX_STR_LEN];
    char res_hash[TEDP_MAX_STR_LEN];
    char ses_hash[TEDP_MAX_STR_LEN];
} te_udp_client_vip_metrics_msg_t;

typedef struct te_udp_server_vip_metrics_msg_s
{
    long type;
    udp_server_metrics_t udp_stats;
    char vip[TEDP_MAX_STR_LEN];
} te_udp_server_vip_metrics_msg_t;

typedef struct te_session_bucket_metrics_msg_s
{
    long type;
    te_http_session_bucket_metrics_t http_stats;
} te_session_bucket_metrics_msg_t;

typedef struct te_http_url_metrics_msg_s
{
    long type;
    te_http_url_stats_t http_stats;
    short num_buckets;
    short num_error_buckets;
    char vip[TEDP_MAX_STR_LEN];
    char uri[TEDP_MAX_STR_LEN];
    char req_type[5];
    char res_hash[TEDP_MAX_STR_LEN];
    char ses_hash[TEDP_MAX_STR_LEN];
} te_http_url_metrics_msg_t;

typedef struct te_udp_url_metrics_msg_s
{
    long type;
    te_udp_url_metrics_t udp_stats;
    char vip[TEDP_MAX_STR_LEN];
    char req_type[5];
    char res_hash[TEDP_MAX_STR_LEN];
    char ses_hash[TEDP_MAX_STR_LEN];
} te_udp_url_metrics_msg_t;

typedef struct te_url_bucket_metrics_msg_s
{
    long type;    
    te_http_url_bucket_metrics_t http_stats;
} te_url_bucket_metrics_msg_t;

typedef struct te_error_metrics_msg_s
{
    long type;
    char error_name[TEDP_MAX_STR_LEN];
    te_error_metrics_t stats;
} te_error_metrics_msg_t;

typedef struct te_http_session_metrics_msg_s
{
    long type;
    te_http_session_metrics_t http_stats;
    char res_hash[TEDP_MAX_STR_LEN];
    char ses_hash[TEDP_MAX_STR_LEN];
} te_http_session_metrics_msg_t;

typedef struct te_udp_session_metrics_msg_s
{
    long type;
    te_udp_session_metrics_t udp_stats;
    char res_hash[TEDP_MAX_STR_LEN];
    char ses_hash[TEDP_MAX_STR_LEN];
} te_udp_session_metrics_msg_t;

typedef struct te_memory_metrics_msg_s
{
    long type;
    unsigned int malloc_metric[MEMORY_TYPE_SIZE];
    unsigned int free_metric[MEMORY_TYPE_SIZE];
    int pid;
    char res_hash[TEDP_MAX_STR_LEN];
    char ses_hash[TEDP_MAX_STR_LEN];
} te_memory_metrics_msg_t;

typedef struct te_proc_finished_msg_s {
    long type;
    char finished[TEDP_MAX_STR_LEN];
} te_proc_finished_msg_t;

typedef struct te_pid_s
{
    long type;
    char pid[TEDP_MAX_STR_LEN];
} te_pid_t;

//Message Sizes
#define HTTP_VIP_METRIC_MSG_SIZE         sizeof(te_http_vip_metrics_msg_t) - sizeof(long)
#define UDP_VIP_CLIENT_METRIC_MSG_SIZE   sizeof(te_udp_client_vip_metrics_msg_t) - sizeof(long)
#define UDP_VIP_SERVER_METRIC_MSG_SIZE   sizeof(te_udp_server_vip_metrics_msg_t) - sizeof(long)
#define HTTP_VIP_BUCKET_METRIC_MSG_SIZE  sizeof(te_session_bucket_metrics_msg_t) - sizeof(long)

#define HTTP_SES_CFG_METRIC_MSG_SIZE     sizeof(te_http_session_metrics_msg_t) - sizeof(long)
#define UDP_SES_CFG_METRIC_MSG_SIZE      sizeof(te_udp_session_metrics_msg_t) - sizeof(long)

#define HTTP_URL_METRIC_MSG_SIZE         sizeof(te_http_url_metrics_msg_t) - sizeof(long)
#define UDP_URL_METRIC_MSG_SIZE          sizeof(te_udp_url_metrics_msg_t) - sizeof(long)
#define URL_BUCKET_METRIC_MSG_SIZE       sizeof(te_url_bucket_metrics_msg_t) - sizeof(long)

#define ERROR_METRIC_MSG_SIZE            sizeof(te_error_metrics_msg_t) - sizeof(long)
#define MEMORY_METRIC_MSG_SIZE           sizeof(te_memory_metrics_msg_t) - sizeof(long)
#define PROC_FINISHED_MSG_SIZE           sizeof(te_proc_finished_msg_t) - sizeof(long)
#define PID_MSG_SIZE                     sizeof(te_pid_t) - sizeof(long)

//Message Types
#define TE_HTTP_VIP_METRIC_IPC_MSG        0x0001
#define TE_UDP_CLIENT_VIP_METRIC_IPC_MSG  0x0002
#define TE_UDP_SERVER_VIP_METRIC_IPC_MSG  0x0003
#define TE_VIP_BUCKET_METRIC_IPC_MSG      0x0004

#define TE_HTTP_SES_CFG_METRIC_IPC_MSG    0x0005
#define TE_UDP_SES_CFG_METRIC_IPC_MSG     0x0006

#define TE_HTTP_URL_METRIC_IPC_MSG        0x0007
#define TE_UDP_URL_METRIC_IPC_MSG         0x0008
#define TE_URL_BUCKET_METRIC_IPC_MSG      0x0009

#define TE_ERROR_METRIC_IPC_MSG           0x000A
#define TE_MEMORY_METRIC_IPC_MSG          0x000B
#define TE_PROC_FINISHED_IPC_MSG          0x000C

bool te_dump_vip_metrics(te_resource_config_t*);
bool dump_udp_server_vip_metics(te_resource_config_t*);
bool dump_udp_client_vip_metics(te_resource_config_t*);
bool dump_tcp_vip_metics(te_resource_config_t*);

bool te_dump_session_config_metrics(te_resource_config_t*, te_session_config_t*);
bool dump_http_session_config_metrics(te_session_config_t *);
bool dump_udp_session_config_metrics(te_session_config_t *);

bool te_dump_url_metrics(te_resource_config_t*);
bool te_dump_stats(te_resource_config_t*, te_session_config_t*, bool);
bool te_dump_memory_metrics();
#endif
