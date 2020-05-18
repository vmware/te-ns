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

//For parsing interface, get and post profiles
typedef struct te_bst_node_s
{
    const char* key;
    int value;
    struct te_bst_node_s *left, *right;
} te_bst_node_t;

uv_loop_t *loop;

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
