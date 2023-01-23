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

#ifndef TE_DP_H
#include "te_dp.h"
#endif


//Inputs to te_dp
char res_cfg_path[TEDP_MAX_STR_LEN];
char session_cfg_path[TEDP_MAX_STR_LEN];
char res_hash[TEDP_MAX_STR_LEN];
char ses_hash[TEDP_MAX_STR_LEN];
char tedp_mgmt_ip_str[TEDP_MAX_STR_LEN];
unsigned int tedp_mgmt_ip;
short pid;
int stats_timer;
bool metrics_enabled;
bool memory_metrics_enabled;

//Definitions regarding Metrics
uv_timer_t dump_metrics_timer;

te_update_context_t   *te_update_context;
te_resource_config_t  *res_cfg_updated;
te_session_config_t   *te_session_cfgs_updated;
te_log_files_t        *te_log_files;
te_url_random_map_t *te_url_random_map;


extern uv_loop_t *loop;
extern te_socket_hashTbl_t te_socket_hashTbl;
extern te_resource_config_t* res_cfg;
extern te_session_config_t *te_session_cfgs;
extern tedp_profile_t tedp_profile;
extern tedp_mode_t tedp_mode;
te_req_write_memory_t te_req_write_data;

//To cycle through various states of session
void (*te_session_state_switcher[])(te_session_t*) = {
    te_session_start,
    te_session_send_1_st_request,
    te_session_send_all_request,
    te_session_sleep,
    te_session_end,
};

void delete_session_cfg_uv_hndl_close_cb(uv_handle_t *session_cfg_uv_handle)
{
    te_session_config_t *session_cfg_p = session_cfg_uv_handle->data;
    session_cfg_p->pending_uv_deletes--;
    if (session_cfg_p->pending_uv_deletes == 0) {
        for(int i=0; i<session_cfg_p->num_sessions; i++) {
            switch(tedp_profile) {
                case TCP: {
                    te_free(session_cfg_p->te_sessions[i].tcp, TE_MTYPE_TCP_SESSION);
                } break;
                case UDP: {
                    te_free(session_cfg_p->te_sessions[i].udp, TE_MTYPE_UDP_SESSION);
                } break;
                default : {
                    eprint("Unknown tedp_profile : %d\n", tedp_profile);
                    abort();
                } break;
            }
        }
        te_free(session_cfg_p->te_sessions, TE_MTYPE_SESSION);
        session_cfg_p->te_sessions = NULL;
        session_cfg_p->ramped_sessions = 0;
        session_cfg_p->completed_sessions = 0;
        session_cfg_p->running_state = TE_SESSION_CONFIG_STATE_READY;
        tprint("%s flush_session_config Complete\n", __FUNCTION__);
    }
}

void delete_session_uv_hndl_close_cb(uv_handle_t *session_uv_handle)
{
    te_session_t *session = session_uv_handle->data;
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    session->pending_uv_deletes--;
    tprint("%s hdl %p \n", __FUNCTION__, session_uv_handle);
    if (session->pending_uv_deletes == 0) {
        assert (session_cfg_p != NULL);
        assert (session != NULL);
        session_cfg_p->pending_sessions--;
        if (session_cfg_p->pending_sessions == 0) {
            uv_timer_stop(&session_cfg_p->ramp_timer);
            uv_close((uv_handle_t *)&session_cfg_p->ramp_timer,
                      delete_session_cfg_uv_hndl_close_cb);
            uv_close((uv_handle_t *)&session_cfg_p->session_signal_handler,
                      delete_session_cfg_uv_hndl_close_cb);
            tprint("%s Sessions in Session Config Cleanup Complete\n",
                   __FUNCTION__);
        }
    }
}

void push_session_sm_uv_async(uv_async_t *req)
{
    te_session_t *session= (te_session_t *) req->data;
    te_process_session_state(session, session->state);
}

void session_config_uv_async(uv_async_t *req)
{
    te_session_config_t *session_cfg_p = (te_session_config_t *) req->data;
    switch(session_cfg_p->config_state) {
        case TE_SESSION_CONFIG_STATE_START:
        {
            tprint("%s Creating Sessions. Pending Sessions:%d\n", __FUNCTION__, \
                session_cfg_p->pending_sessions);
            create_te_sessions(session_cfg_p);
        }break;
        case TE_SESSION_CONFIG_STATE_RESUME:
        {
            resume_te_sessions(session_cfg_p);
            tprint("%s Resuming Te Sessions.\n", __FUNCTION__);
        }break;
        default:
           break;
    }
}

void load_random_session_data(te_session_t * session)
{
    te_session_config_t *session_cfg = session->session_cfg_p;

    // select connections and requests randomly.
    if (session_cfg->type == TE_SESSION_TYPE_BROWSER) {
        if ((session->cycle_iter == 0) || (session_cfg->cycle_type == TE_SESSION_CYCLE_RESTART))
            session->num_connections =  te_random(session_cfg->min_connections, session_cfg->max_connections);
        session->num_requests = te_random(session_cfg->min_requests, session_cfg->max_requests);
    }

    else {
        session->num_connections = session_cfg->max_connections;
        session->num_requests = session_cfg->max_requests;
    }

    if (session->cycle_iter == 0){
        // chose vip randomly from list of vips (or) round robin.
        if (res_cfg->vip_selection_rr) {
            session->vip_index = res_cfg->vip_rr_counter%res_cfg->total_vips;
            res_cfg->vip_rr_counter++;
        }
        else
            session->vip_index = te_random(0, res_cfg->total_vips);
    }

    switch(tedp_profile) {
        case TCP: {
            load_tcp_random_session_data(session);
        } break;
        case UDP: {
            load_udp_random_session_data(session);
        } break;
        default: {
            eprint("Unknown TE_DP profile %d\n", tedp_profile);
            abort();
        }
    }
    if(session_cfg->type == TE_SESSION_TYPE_BROWSER)
        clock_gettime(CLOCK_MONOTONIC_RAW, &session->start_time);

    tprint("%d,%lu, CYCLE_START:Random_Seed[Conn:%d Reqs:%d for vip:%s]\n",
        session->id, session->cycle_iter+1, session->num_connections,
        session->num_requests, res_cfg->vips[session->vip_index].vip);
}

void send_session_requests(te_session_t *session, unsigned int num_requests)
{
    unsigned int iter = 0;
    switch(tedp_profile) {
        case TCP:
            for(iter = 0 ; iter < num_requests ; ++iter)
                add_tcp_request(session);
            break;
        case UDP:
            for(iter = 0 ; iter < num_requests ; ++iter)
                add_udp_request(session);
            break;
        default:
            eprint("Unknown TE_DP profile %d\n", tedp_profile);
            abort();
    }

    tprint("%d, %lu, CYCLE_SEND_REQUESTS:%d\n", session->id, session->cycle_iter+1, num_requests);
    return;
}

void session_ramp_timer_cb(uv_timer_t *ramp_timer)
{
    te_session_t *session;
    te_session_config_t *session_cfg = (te_session_config_t *) (ramp_timer->data);
    unsigned int iter = session_cfg->ramped_sessions;
    session_cfg->ramped_sessions += session_cfg->session_ramp_step;
    unsigned short is_update = res_cfg->update_flag | session_cfg->update_flag;

    if (is_update && (session_cfg->ramped_sessions > te_update_context->to_start)) {
        session_cfg->ramped_sessions = te_update_context->to_start;
        tprint("ramp timer cb starting %d sessions func %s to_start %d\n",
            (session_cfg->ramped_sessions-iter), __FUNCTION__, te_update_context->to_start);
    }
    else if (!is_update && (session_cfg->ramped_sessions > session_cfg->num_sessions)) {
        session_cfg->ramped_sessions = session_cfg->num_sessions;
        tprint("ramp timer cb starting %d sessions func %s\n", (session_cfg->ramped_sessions-iter), \
        __FUNCTION__);
    }

    for (;iter < session_cfg->ramped_sessions; iter++) {
        session = &session_cfg->te_sessions[iter];
        session->id = iter + 1;
        session->session_cfg_p = session_cfg;
        // create session related fsm_handler here.
        // AK: Avoid the signal handler, if possible
        // On running TE, the overhead of the signal handler > 50% using strace()
        uv_async_init(loop, &session->fsm_handler, push_session_sm_uv_async);
        session->fsm_handler.data = session;
        session->pending_uv_deletes++;

        // To induce sleep b/w cycles in case of resume
        // AK: May be add a if here ?
        uv_timer_init(loop, &session->cycle_timer);
        session->cycle_timer.data = session;
        session->pending_uv_deletes++;

        // cURL Timer (Used only in case of TCP)
        if(tedp_profile == TCP) {
            uv_timer_init(loop, &session->tcp->cm_timer);
            session->tcp->cm_timer.data = session;
            session->pending_uv_deletes++;
        }

        session->state = TE_SESSION_STATE_CYCLE_START;
        uv_async_send(&session->fsm_handler);
    }
    tprint("Pending sessions in batch start = %d\n",
            session_cfg->num_sessions - session_cfg->ramped_sessions);
    session_cfg->running_state = TE_SESSION_CONFIG_STATE_RUNNING;
    session_cfg->config_state = TE_SESSION_CONFIG_STATE_START;
    if (session_cfg->ramped_sessions == session_cfg->num_sessions) {
        tprint("ramp timer stop for ses cfg %p \n", session_cfg);
        uv_timer_stop(&session_cfg->ramp_timer);
        return;
    }
}


void create_te_sessions(te_session_config_t *session_cfg)
{
    unsigned int num_sessions = session_cfg->num_sessions;
    if (!session_cfg->te_sessions) {
        te_malloc(session_cfg->te_sessions, num_sessions * sizeof(te_session_t), TE_MTYPE_SESSION);
        if (!session_cfg->te_sessions) {
            wprint("Unable to allocate memory\n");
            return;
        }
        memset(session_cfg->te_sessions, 0, num_sessions * sizeof(te_session_t));
        for(int i=0; i<num_sessions; ++i) {
            switch(tedp_profile) {
                case TCP: {
                    te_malloc(session_cfg->te_sessions[i].tcp, sizeof(te_tcp_session_t), \
                        TE_MTYPE_TCP_SESSION);
                    memset(session_cfg->te_sessions[i].tcp, 0, sizeof(te_tcp_session_t));
                    memset(&session_cfg->http_metrics, 0, sizeof(te_http_session_metrics_t));
                    session_cfg->http_metrics.num_sessions = num_sessions;
                } break;
                case UDP: {
                    te_malloc(session_cfg->te_sessions[i].udp, sizeof(te_udp_session_t), \
                        TE_MTYPE_UDP_SESSION);
                    memset(session_cfg->te_sessions[i].udp, 0, sizeof(te_udp_session_t));
                    memset(&session_cfg->udp_metrics, 0, sizeof(te_udp_session_metrics_t));
                    session_cfg->udp_metrics.num_sessions = num_sessions;
                } break;
                default: {
                    eprint("Unknown TE_DP profile %d\n", tedp_profile);
                    abort();
                } break;
            }
        }

        uv_timer_start(&session_cfg->ramp_timer, session_ramp_timer_cb, 1,
            session_cfg->session_ramp_delay * 1000);
    }
}

void on_session_cycle_timeout(uv_timer_t *cycle_timer)
{
    te_session_t *session= (te_session_t *) cycle_timer->data;
    te_process_session_state(session, TE_SESSION_STATE_CYCLE_END);
}

void te_stop_one_session (te_session_t *session)
{
    tprint("in function %s, delete session id %d  of %s cfg\n", __FUNCTION__, session->id,
        session->session_cfg_p == te_session_cfgs ? "old" : "new");

    switch(tedp_profile) {
        case TCP:
            uv_timer_stop(&session->tcp->cm_timer);
            flush_tcp_multi_handle(session);
            uv_close((uv_handle_t *)&session->tcp->cm_timer, delete_session_uv_hndl_close_cb);
            break;
        case UDP:
            //AK revisit: cm_timer's equivalent for udp :)
            flush_udp_multi_handle(session);
            break;
        default:
            eprint("Unknown tedp_profile : %d\n", tedp_profile);
            abort();
    }

    // AK: May be add a if for resume only ?
    uv_timer_stop(&session->cycle_timer);
    uv_close((uv_handle_t *)&session->cycle_timer, delete_session_uv_hndl_close_cb);

    //AK: Avoid if possible ?
    uv_close((uv_handle_t *)&session->fsm_handler, delete_session_uv_hndl_close_cb);

    session->is_completed = 1;
}

void te_equalize_configs(te_session_t *session, int diff)
{
    if (te_update_context->diff > 0) { /*old is greater than new */
        tprint("diff is %d >0 deleting olf session\n", te_update_context->diff);
        te_stop_one_session(session);
        session->session_cfg_p->ramped_sessions--;
        te_update_context->diff--;
    } else if (te_update_context->diff < 0) { /*new is greater than old */
        te_stop_one_session(session);
        te_update_context->ramp_step_ctxt++;
        te_update_context->to_start += te_update_context->ramp_step_ctxt;
        te_update_context->ramp_step_ctxt = 0;
        te_update_context->to_start += (0 - te_update_context->diff);
        te_update_context->diff = 0;
    }
}

void te_check_and_queue_updated_config (te_session_t *session, int diff)
{
    tprint("diff = %d , ramped old = %d func %s \n",
        diff,session->session_cfg_p->ramped_sessions, __FUNCTION__);
    if (diff != 0) {
        te_equalize_configs(session, diff);
        return;
    }

    if (session->session_cfg_p->ramped_sessions > 0) {
        te_stop_one_session(session);
        session->session_cfg_p->ramped_sessions--;
        te_update_context->ramp_step_ctxt++;
        tprint("te delete 1 session in func %s, ramped old %d ramp ctxt %d \n",
            __FUNCTION__,
            session->session_cfg_p->ramped_sessions,
            te_update_context->ramp_step_ctxt);
    }

    if (te_update_context->ramp_step_ctxt ==
        te_session_cfgs_updated->session_ramp_step) {
        tprint("batch starting sessions equal to ramp step func %s \n",
            __FUNCTION__);
        te_update_context->to_start += te_update_context->ramp_step_ctxt;
        te_update_context->ramp_step_ctxt = 0;
    }

    if (session->session_cfg_p->ramped_sessions == 0)
    {
        tprint("hitless update complete, starting %d sessions func %s \n",
            te_update_context->ramp_step_ctxt,
            __FUNCTION__);
        if (te_update_context->ramp_step_ctxt != 0) {
            te_update_context->to_start += te_update_context->ramp_step_ctxt;
            te_update_context->ramp_step_ctxt = 0;
        }
        return;
    }
}

void te_session_start(te_session_t* session) {
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    load_random_session_data(session);
    switch(tedp_profile) {
        case TCP:
            init_tcp_multi_handle(session);
            break;
        case UDP:
            init_udp_multi_handle(session);
            break;
        default:
            eprint("Unknown tedp_profile : %d\n", tedp_profile);
            abort();
    }
    if (session_cfg_p->type == TE_SESSION_TYPE_BROWSER) {
        // send 1 req if session is browser
        // Evaluate if the response is good
        // Get persistense data, if any, and if enabled
        // Continue further
        if (!session->good_1st_response) {
            te_process_session_state(session, TE_SESSION_STATE_SEND_1ST_REQ);
        }
        // Except for the very first request of the 1st cycle_iter of
        // every target_cycle_iter, everything is sent together
        else {
            te_process_session_state(session, TE_SESSION_STATE_SEND_ALL_REQ);
        }
    }
    else {
        //In MaxPerf mode, we just bombard traffic
        te_process_session_state(session, TE_SESSION_STATE_SEND_ALL_REQ);
    }
}

void te_session_send_1_st_request(te_session_t* session) {
    send_session_requests(session, 1);
}

void te_session_send_all_request(te_session_t* session) {
    switch(tedp_profile) {
        case TCP: {
            if(session->num_requests > session->tcp->reqs_sent) {
                send_session_requests(session, session->num_requests - session->tcp->reqs_sent);
            }
        } break;
        case UDP: {
            if(session->num_requests > session->udp->reqs_sent) {
                send_session_requests(session, session->num_requests - session->udp->reqs_sent);
            }
        }
    }
}

void te_session_end(te_session_t* session) {
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    session->cycle_iter++;
    session_cfg_p->cycles_complete++;
    switch(tedp_profile) {
        case TCP:
            update_tcp_session_config_metrics(session);
            break;
        case UDP:
            update_udp_session_config_metrics(session);
            break;
        default:
            abort();
    }

    //If the current cycle_iter is over
    if (session_cfg_p->num_cycles &&
        (session->cycle_iter == session_cfg_p->num_cycles)) {

        tprint("ses_cfg %p(%s) num_cycles cmplted, for session id %d\n",
            session_cfg_p, (session_cfg_p == te_session_cfgs ) ? "old":"new",
            session->id);

        // There is no update which is graceful present as of now
        if (unlikely(session_cfg_p->update_flag)) {
            //batch start a new session from resource and sesson cfg
            tprint("Calling check and queue updated config \n");
            te_check_and_queue_updated_config(session, te_update_context->diff);
            return;
        }

        tprint("SESSION_ALL_CYCLE_COMPLETE! Session_Cfg:%d\n", session_cfg_p->id);
        switch(tedp_profile) {
            case TCP:
                flush_tcp_multi_handle(session);
                res_cfg->http_vip_metrics[session->vip_index].vip_stats.sessions++;
                break;
            case UDP:
                flush_udp_multi_handle(session);
                res_cfg->udp_vip_metrics[session->vip_index].udp_vip_stats.sessions++;
                break;
            default:
                eprint("Unknown tedp_profile : %d\n", tedp_profile);
                abort();
        }
        session->cycle_iter = 0;
        session->total_cycle_iter++;

        //If target cycle is also done
        //Clean and exit
        if (session_cfg_p->target_cycles &&
            (session->total_cycle_iter == session_cfg_p->target_cycles)) {

            session->total_cycle_iter = 0;
            tprint("%s\n","Target-cycles completed");

            session_cfg_p->completed_sessions++;
            session->is_completed = 1;
            int total_cycles = session_cfg_p->num_sessions *
                session_cfg_p->target_cycles * session_cfg_p->num_cycles;

            //cycles_complete increments for every single cycle across session
            if (session_cfg_p->cycles_complete == total_cycles) {
                // Dumping the metrics if metrics is enabled
                session_cfg_p->pending_sessions = 0;
                if (metrics_enabled || memory_metrics_enabled) {
                    uv_timer_stop(&dump_metrics_timer);
                    if(!te_dump_stats(res_cfg, session_cfg_p, true)) {
                        eprint("Unable to Dump Stats!\n");
                    }
                }
                te_push_session_config_fsm(TE_SESSION_CONFIG_STATE_STOP);
            }
            return;
        }
    }
    //Multi handle is cleaned if cycle state is RESTART, (or) no 1st good response is got in RESUME
    else if (session_cfg_p->cycle_type == TE_SESSION_CYCLE_RESTART || \
            (!session->good_1st_response && session_cfg_p->cycle_type == TE_SESSION_CYCLE_RESUME)) {
        switch(tedp_profile) {
            case TCP:
                flush_tcp_multi_handle(session);
                break;
            case UDP:
                flush_udp_multi_handle(session);
                break;
            default:
                eprint("Unknown tedp_profile : %d\n", tedp_profile);
                abort();
        }
    }
    te_process_session_state(session, TE_SESSION_STATE_CYCLE_START);
}

void te_session_sleep(te_session_t* session) {
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    clock_gettime(CLOCK_MONOTONIC_RAW, &session->end_time);
    unsigned short cycle_delay = 0;
    if (session->is_completed == 0) {
        cycle_delay = te_random(session_cfg_p->min_cycle_delay,
                        session_cfg_p->max_cycle_delay);
        if (cycle_delay == 0) {
            cycle_delay = 1;
            //incase if 0 delay, it depends on libuv to force it again.
            //so enforce to fire-it in 1 ms.
        }
        uv_timer_start(&session->cycle_timer, on_session_cycle_timeout, cycle_delay, 0);
    }
}

void te_process_session_state(te_session_t * session, TE_SESSION_STATE state)
{
    session->state = state;

    test_print("Sesssion States: id=%d, state=%d, cycle_iter=%lu, total_cycle_iter=%d\n",
        session->id, state, session->cycle_iter, session->total_cycle_iter);

    if(likely(state >= TE_SESSION_STATE_CYCLE_START && \
        state <= TE_SESSION_STATE_CYCLE_END)) {
        (*te_session_state_switcher[state])(session);
    } else {
        //As of today, following states are not supporeted by TE_DP:
        // * TE_SESSION_STATE_PAUSE,
        // * TE_SESSION_STATE_CYCLE_REMOVED
        eprint("Unknown state! \n");
        abort();
    }
}

void resume_te_sessions(te_session_config_t *session_cfg)
{
    te_session_t *session;
    unsigned int iter = 0;
    for (iter = 0; iter < session_cfg->ramped_sessions; iter++) {
        session = &session_cfg->te_sessions[iter];
        /* just push the state-machine as
           session->state points to its running state.*/
        if (!session->is_completed) {
            uv_async_send(&session->fsm_handler);
            session_cfg->pending_sessions--;
            assert(session_cfg->pending_sessions >= 0);
        }
    }
    if (session_cfg->pending_sessions == 0) {
        uv_timer_start(&session_cfg->ramp_timer, session_ramp_timer_cb,
                       1, session_cfg->session_ramp_delay * 1000);
        session_cfg->running_state = TE_SESSION_CONFIG_STATE_RUNNING;
   }
}

void delete_te_sessions(te_session_config_t *session_cfg)
{
    te_session_t *session;
    unsigned int iter = 0;

    for (iter=0; iter<session_cfg->ramped_sessions; iter++) {
        session = &session_cfg->te_sessions[iter];
        te_stop_one_session(session);
    }
}
