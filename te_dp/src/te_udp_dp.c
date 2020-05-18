#ifndef TE_UDP_DP_H
#include "te_udp_dp.h"
#endif

extern tedp_mode_t tedp_mode;
te_server_metrics_hash_table_t te_server_metrics_hash_table;

//**********************************************//
//            UDP SERVER CALLBACKS              //
//**********************************************//
void te_create_server_metrics_hash_table(unsigned int size) {
	te_server_metrics_hash_table.size = size;
	te_server_metrics_hash_table.num_entries = 0;
	if(!te_server_metrics_hash_table.buckets) {
        te_malloc(te_server_metrics_hash_table.buckets, size * sizeof(te_udp_server_metrics_hash_t), \
            TE_MTYPE_UDP_SERVER_METRICS_HASH);
	}

    if(unlikely(!te_server_metrics_hash_table.buckets)) {
        eprint("Unable to create udp server metrics HashTable.\n");
        exit(0);
    }
    memset(te_server_metrics_hash_table.buckets, 0, sizeof(te_udp_server_metrics_hash_t) * size);
    return;
}

void te_insert_into_server_metrics_hash_hash_table(te_vip_end_metrics_node_t *server_metrics_node, int hash)
{
    if(!te_server_metrics_hash_table.buckets[hash].head) {
        te_server_metrics_hash_table.buckets[hash].head = server_metrics_node;
        te_server_metrics_hash_table.buckets[hash].count = 1;
        te_server_metrics_hash_table.num_entries++;
        return;
    }

    /* adding new server_metrics_node to the list */
    server_metrics_node->next = te_server_metrics_hash_table.buckets[hash].head;

    /*
     * update the head of the list and no of
     * server_metrics_node in the current bucket
     */
    te_server_metrics_hash_table.buckets[hash].head = server_metrics_node;
    te_server_metrics_hash_table.buckets[hash].count++;
    te_server_metrics_hash_table.num_entries++;
    return;
}

te_vip_end_metrics_node_t* te_search_or_create_udp_server_metrics_node(unsigned long vip, \
    unsigned short vport) {
    te_vip_end_metrics_node_t *server_metrics_node = NULL;
    unsigned int hash   = vip % te_server_metrics_hash_table.size;
    server_metrics_node = te_server_metrics_hash_table.buckets[hash].head;

    if(server_metrics_node == NULL) {
        // Create node if unavailable
        te_malloc(server_metrics_node, sizeof(te_vip_end_metrics_node_t), \
            TE_MTYPE_UDP_SERVER_VIP_METRICS_NODE);
        if(likely(server_metrics_node)) {
            memset(server_metrics_node, 0, sizeof(te_vip_end_metrics_node_t));
            server_metrics_node->vip   = vip;
            server_metrics_node->vport = vport;
            server_metrics_node->vip_end_metrics.min_latency = DBL_MAX;
            server_metrics_node->vip_end_metrics.max_latency = 0;
            te_insert_into_server_metrics_hash_hash_table(server_metrics_node, hash);
            return server_metrics_node;
        } else {
            eprint("Malloc to create new metric node failed\n");
            return NULL;
        }
    }

    while(server_metrics_node) {
       if(server_metrics_node->vip == vip && server_metrics_node->vport == vport) {
           return server_metrics_node;
       }
       server_metrics_node = server_metrics_node->next;
    }

    return NULL;
}


void te_udp_server_send_callback(unsigned long vip, unsigned short vport, \
    udp_send_metrics_t send_metrics, void* user_ptr) {

    #if(UDP_SERVER_VIP_END_METRICS)
        te_vip_end_metrics_node_t *server_metrics_node = \
            te_search_or_create_udp_server_metrics_node(vip, vport);

        if(unlikely(server_metrics_node == NULL)) {
            eprint("Unable to find / allocate server_metrics_node for vip=%lu and vport=%hu", \
                vip, vport);
            return;
        }
        server_metrics_node->stats_present                       = true;
        server_metrics_node->vip_end_metrics.dg_sent            += send_metrics.dg_sent;
        server_metrics_node->vip_end_metrics.dg_size_sent       += send_metrics.dg_size_sent;
        server_metrics_node->vip_end_metrics.dg_send_fail       += send_metrics.dg_send_fail;
        server_metrics_node->vip_end_metrics.sum_latency        += send_metrics.latency;
        server_metrics_node->vip_end_metrics.sum_square_latency += send_metrics.latency * \
                                                                    send_metrics.latency;
        if(send_metrics.latency != 0) {
            server_metrics_node->vip_end_metrics.min_latency = TE_MIN(send_metrics.latency,
                server_metrics_node->vip_end_metrics.min_latency);
            server_metrics_node->vip_end_metrics.max_latency = TE_MAX(send_metrics.latency,
                server_metrics_node->vip_end_metrics.max_latency);
        }

        if(send_metrics.dg_send_fail == 0 && send_metrics.dg_sent != 0) {
            // If there were atleast resp sent, and if there were no fails
            server_metrics_node->vip_end_metrics.response_sent++;
        } else {
            server_metrics_node->vip_end_metrics.response_send_fail++;
        }

        tprint("DG_SENT=%d, DG_FAILED=%d, DG_SIZE_SENT=%d, RESP_SENT=%d \n", \
            server_metrics_node->vip_end_metrics.dg_sent, \
            server_metrics_node->vip_end_metrics.dg_send_fail, \
            server_metrics_node->vip_end_metrics.dg_size_sent, \
            server_metrics_node->vip_end_metrics.response_sent);

    #else
        te_udp_listen_handle_t* listen_handle = (te_udp_listen_handle_t*)user_ptr;

        if(unlikely(listen_handle == NULL)) {
            eprint("Unable to get the listen_handle for vip=%lu and vport=%hu", vip, vport);
            return;
        }
        listen_handle->stats_present                          = true;
        listen_handle->server_end_metrics.dg_sent            += send_metrics.dg_sent;
        listen_handle->server_end_metrics.dg_size_sent       += send_metrics.dg_size_sent;
        listen_handle->server_end_metrics.dg_send_fail       += send_metrics.dg_send_fail;
        listen_handle->server_end_metrics.sum_latency        += latency;
        listen_handle->server_end_metrics.sum_square_latency += latency * latency;

        if(send_metrics.latency != 0) {
            listen_handle->server_end_metrics.min_latency = TE_MIN(send_metrics.latency,
                listen_handle->server_end_metrics.min_latency);
            listen_handle->server_end_metrics.max_latency = TE_MAX(send_metrics.latency,
                listen_handle->server_end_metrics.max_latency);
        }

        if(send_metrics.dg_send_fail == 0) {
            listen_handle->server_end_metrics.response_sent++;
        } else {
            listen_handle->server_end_metrics.response_send_fail++;
        }
        tprint("DG_SENT=%d, DG_FAILED=%d, DG_SIZE_SENT=%d, RESP_SENT=%d \n", \
            server_metrics_node->server_end_metrics.dg_sent, \
            server_metrics_node->server_end_metrics.dg_send_fail, \
            server_metrics_node->server_end_metrics.dg_size_sent, \
            server_metrics_node->server_end_metrics.response_sent);
    #endif
}

void te_udp_server_recv_callback(unsigned long vip, unsigned short vport, \
    udp_recv_metrics_t recv_metrics, void* user_ptr) {

    #if(UDP_SERVER_VIP_END_METRICS)
        te_vip_end_metrics_node_t *server_metrics_node = te_search_or_create_udp_server_metrics_node(vip, vport);

        if(unlikely(server_metrics_node == NULL)) {
            eprint("Unable to find / allocate server_metrics_node for vip=%lu and vport=%hu", vip, vport);
            return;
        }
        server_metrics_node->stats_present                     = true;
        server_metrics_node->vip_end_metrics.dg_rcvd          += recv_metrics.dg_rcvd;
        server_metrics_node->vip_end_metrics.dg_size_rcvd     += recv_metrics.dg_size_rcvd;
        server_metrics_node->vip_end_metrics.dg_recv_timedout += recv_metrics.dg_recv_timedout;
        if(recv_metrics.dg_recv_timedout == 0) {
            server_metrics_node->vip_end_metrics.request_rcvd++;
        } else {
            server_metrics_node->vip_end_metrics.request_recv_timedout++;
        }
        tprint("DG_RCVD=%d, DG_RECV_TIMEOUT=%d DG_SIZE_RCVD=%d, REQS_RCVD=%d \n", \
            server_metrics_node->vip_end_metrics.dg_sent, \
            server_metrics_node->vip_end_metrics.dg_recv_timedout, \
            server_metrics_node->vip_end_metrics.dg_size_sent, \
            server_metrics_node->vip_end_metrics.request_rcvd);

    #else
        te_udp_listen_handle_t *listen_handle = (te_udp_listen_handle_t*)user_ptr;

        if(unlikely(listen_handle == NULL)) {
            eprint("Unable to get the listen_handle for vip=%lu and vport=%hu", vip, vport);
            return;
        }
        listen_handle->stats_present                        = true;
        listen_handle->server_end_metrics.dg_rcvd          += recv_metrics.dg_rcvd;
        listen_handle->server_end_metrics.dg_size_rcvd     += recv_metrics.dg_size_rcvd;
        listen_handle->server_end_metrics.dg_recv_timedout += recv_metrics.dg_recv_timedout;
        if(recv_metrics.dg_recv_timedout == 0) {
            listen_handle->server_end_metrics.request_rcvd++;
        } else {
            listen_handle->server_end_metrics.request_recv_timedout++;
        }
        tprint("DG_RCVD=%d, DG_RECV_TIMEOUT=%d DG_SIZE_RCVD=%d, REQS_RCVD=%d \n", \
            listen_handle->server_end_metrics.dg_sent, \
            listen_handle->server_end_metrics.dg_recv_timedout, \
            listen_handle->server_end_metrics.dg_size_sent, \
            listen_handle->server_end_metrics.request_rcvd);
    #endif
}

void te_start_udp_listen() {
    //Starts the listener for various UDP handles
    UDPEcode ecode;

    ecode = udp_server_socket_parser(res_cfg->server_socket_ds_parse_timeout);
    if(unlikely(ecode != UDPE_OK))
        eprint("UDP_LISTEN_PORT, %d\n", ecode);

    for(int i=0; i<res_cfg->num_udp_listen_handle; ++i) {

        res_cfg->udp_listen_handle[i].server_easy_handle = udp_server_easy_init();
        res_cfg->udp_listen_handle[i].server_end_metrics.max_latency = 0;
        res_cfg->udp_listen_handle[i].server_end_metrics.min_latency = DBL_MAX;

        //Setting options on the listening opts
        ecode = udp_server_easy_setopt(res_cfg->udp_listen_handle[i].server_easy_handle, \
            UDP_LISTEN_PORT, res_cfg->udp_listen_handle[i].port);
        if(unlikely(ecode != UDPE_OK))
            eprint("UDP_LISTEN_PORT, %d\n", ecode);

        ecode = udp_server_easy_setopt(res_cfg->udp_listen_handle[i].server_easy_handle, \
            UDP_LISTEN_PRIVATE, &(res_cfg->udp_listen_handle[i]));
        if(unlikely(ecode != UDPE_OK))
            eprint("UDP_LISTEN_PRIVATE, %d\n", ecode);

        ecode = udp_server_easy_setopt(res_cfg->udp_listen_handle[i].server_easy_handle, \
            UDP_LISTEN_SEND_CALLBACK, te_udp_server_send_callback);
        if(unlikely(ecode != UDPE_OK))
            eprint("UDP_LISTEN_SEND_CALLBACK, %d\n", ecode);

        ecode = udp_server_easy_setopt(res_cfg->udp_listen_handle[i].server_easy_handle, UDP_LISTEN_RECV_CALLBACK, \
            te_udp_server_recv_callback);
        if(unlikely(ecode != UDPE_OK))
            eprint("UDP_LISTEN_RECV_CALLBACK, %d\n", ecode);

        ecode = udp_server_easy_start_listen(res_cfg->udp_listen_handle[i].server_easy_handle);
        if(unlikely(ecode != UDPE_OK))
            eprint("UDP_LISTEN_START, %d\n", ecode);
    }
}

//**********************************************//
//            UDP CLIENT CALLBACKS              //
//**********************************************//

void te_process_udp_session(te_session_t *session) {

    // One will land in the function, only if a request is complete
    // Completion is defined either by getting all the datagrams within timeout
    // or not getting everything within timeout

    if(session->session_cfg_p->type == TE_SESSION_TYPE_BROWSER && !session->good_1st_response) {
        if(session->udp->resp_timedout == 0) {
            // A UDP request is said to be successful, if there are no timeouts
            // And so we increment the good_1st_response counter
            assert(session->udp->reqs_sent != 0);
            tprint("Rcvd 1st Response session:%d, status:GOOD\n", session->id);
            session->good_1st_response++;
            // After getting 1st good response, we go to
            // * sleep state if there is only 1 request to send in the cycle
            // * send_all_request state if there are other requests to send in the cycle
            if(session->num_requests == 1) {
                session->state = TE_SESSION_STATE_CYCLE_SLEEP;
            } else {
                session->state = TE_SESSION_STATE_SEND_ALL_REQ;
            }
        } else {
            // HardLuck!! Bad 1st response, End the session cycle.
            wprint("Rcvd 1st Response  session:%d, status:BAD\n", session->id);
            session->state = TE_SESSION_STATE_CYCLE_SLEEP;
        }
        goto udp_session_send_signal;
    }

    // If all requests were responded or timedout or no response was required, then move state
    if (session->udp->resp_recd + session->udp->resp_timedout + session->udp->resp_not_needed == \
            session->num_requests) {
        if (session->session_cfg_p->type == TE_SESSION_TYPE_BROWSER)  {
            session->state = TE_SESSION_STATE_CYCLE_SLEEP;
        } else {
            session->state = TE_SESSION_STATE_CYCLE_END;
        }
        goto udp_session_send_signal;
    }

    return;

    udp_session_send_signal:
        uv_async_send(&session->fsm_handler);
}


/* The receive and send callback need not be received in order
 * Please refer to Pending Callbacks in http://docs.libuv.org/en/v1.x/design.html
 * It is stated that:
 *   All I/O callbacks are called right after polling for I/O, for the most part.
 *   There are cases, however, in which calling such a callback is deferred for the next loop iteration.
 *   If the previous iteration deferred any I/O callback it will be run at this point.
 *   So we could end up in a state as descrived below:
 *     0 0 0 0 ------> send datagrams (but cbs can be deffered to next iteration)
 *         0 0 <------ server responding with reply datagrams
 *     Getting callbacks for the received datagrams
 * ..
 * ..
 * .. (Next uv loop iteration starts)
 * Getting callbacks for the sent datagrams
 * So in order the avoid the above scenario, the data must be cleaned only after getting both sent
 * and received callbacks
*/
void te_udp_send_callback(udp_send_metrics_t send_metrics, void* user_ptr) {
    te_udp_request_t* request                 = (te_udp_request_t*)user_ptr;
    te_session_t* session                     = request->session;
    te_session_config_t* session_cfg          = session->session_cfg_p;
    te_udp_session_metrics_t* session_metrics = &session_cfg->udp_metrics;
    te_resource_config_t* res_cfg             = session_cfg->res_cfg;
    unsigned int vip_hash                     = session->vip_index;
    te_udp_vip_metrics_t* vip_metric          = &res_cfg->udp_vip_metrics[vip_hash];
    te_udp_url_metrics_t* udp_url_metrics;

    switch(request->req_type) {
        case TE_SESSION_REQ_UPLOAD: {
            udp_url_metrics = vip_metric->udp_upload_metrics;
            vip_metric->upload_stats_present = true;
        } break;
        case TE_SESSION_REQ_DOWNLOAD: {
            udp_url_metrics = vip_metric->udp_download_metrics;
            vip_metric->download_stats_present = true;
        } break;
        default: {
            eprint("Unknown request type\n");
            abort();
        }
    }

    // To facilitate lesser dumping of stats
    vip_metric->stats_present = true;
    request->dg_sent = send_metrics.dg_sent + send_metrics.dg_send_fail;

    // To indicate successful / failed conns
    vip_metric->udp_vip_stats.failed_connections += send_metrics.conn_open_fail;
    session_metrics->failed_connections          += send_metrics.conn_open_fail;

    vip_metric->udp_vip_stats.good_connections   += send_metrics.new_conn_opened;
    session_metrics->good_connections            += send_metrics.new_conn_opened;

    if(send_metrics.dg_sent == request->dg_to_send) {
        session->udp->reqs_sent++;
        session_metrics->reqs_sent++;
        udp_url_metrics->reqs_sent++;
    } else {
        session->udp->reqs_failed++;
        session_metrics->reqs_failed++;
        udp_url_metrics->reqs_failed++;
    }

    if(request->dg_to_recv == 0) {
        // If responses are not needed, then increment the counter
        session->udp->resp_not_needed++;
    }

    // Session metrics
    session_metrics->dg_sent      += send_metrics.dg_sent;
    session_metrics->dg_size_sent += send_metrics.dg_size_sent;
    session_metrics->dg_send_fail += send_metrics.dg_send_fail;

    // URL metrics
    udp_url_metrics->dg_sent      += send_metrics.dg_sent;
    udp_url_metrics->dg_size_sent += send_metrics.dg_size_sent;
    udp_url_metrics->dg_send_fail += send_metrics.dg_send_fail;

    tprint("DG_SENT=%d, DG_SIZE_SENT=%d, DF_FAILED=%d REQS_SENT=%u RESP_NOT_NEEDED=%u\n", \
        send_metrics.dg_sent, send_metrics.dg_size_sent, send_metrics.dg_send_fail, \
        session->udp->reqs_sent, session->udp->resp_not_needed);

    //Sent all and received all, clean it up
    if(request->dg_rcvd == request->dg_to_recv && request->dg_sent == request->dg_to_send) {
        te_process_udp_session(session);
        udp_easy_cleanup(request->easy_handle);
        te_free(request, TE_MTYPE_UDP_REQUEST);
    }
}

void te_udp_recv_callback(udp_recv_metrics_t recv_metrics, void* user_ptr) {
    te_udp_request_t* request                 = (te_udp_request_t*)user_ptr;
    te_session_t* session                     = request->session;
    te_session_config_t* session_cfg          = session->session_cfg_p;
    te_udp_session_metrics_t* session_metrics = &session_cfg->udp_metrics;
    te_resource_config_t* res_cfg             = session_cfg->res_cfg;
    unsigned int vip_hash                     = session->vip_index;
    te_udp_vip_metrics_t* vip_metric          = &res_cfg->udp_vip_metrics[vip_hash];
    te_udp_url_metrics_t* udp_url_metrics;

    switch(request->req_type) {
        case TE_SESSION_REQ_UPLOAD: {
            vip_metric->upload_stats_present = true;
            udp_url_metrics = vip_metric->udp_upload_metrics;
        } break;
        case TE_SESSION_REQ_DOWNLOAD: {
            vip_metric->download_stats_present = true;
            udp_url_metrics = vip_metric->udp_download_metrics;
        } break;
        default: {
            eprint("Unknown request type\n");
            abort();
        }
    }

    // To facilitate lesser stats dump
    vip_metric->stats_present = true;
    request->dg_rcvd = recv_metrics.dg_rcvd + recv_metrics.dg_recv_timedout;

    if(request->dg_to_recv != 0) {
        if(recv_metrics.dg_rcvd == request->dg_to_recv) {
            // Ideal scnario, where we got all the expected datagrams back
            session->udp->resp_recd++;
            session_metrics->resp_recd++;
            udp_url_metrics->resp_recd++;
            udp_url_metrics->sum_latency        += recv_metrics.latency;
            udp_url_metrics->sum_square_latency += recv_metrics.latency * recv_metrics.latency;

            if(recv_metrics.latency != 0) {
                udp_url_metrics->min_latency = TE_MIN(recv_metrics.latency, udp_url_metrics->min_latency);
                udp_url_metrics->max_latency = TE_MAX(recv_metrics.latency, udp_url_metrics->max_latency);
            }
        } else if(request->dg_rcvd == request->dg_to_recv) {
            // Scenario, where we got timedouts
            session->udp->resp_timedout++;
            session_metrics->resp_timedout++;
            udp_url_metrics->resp_timedout++;
        } else {
            // We expected response but library neither reported it in timedout, nor in success
            abort();
        }
    }

    // Session metrics
    session_metrics->dg_recd          += recv_metrics.dg_rcvd;
    session_metrics->dg_size_recd     += recv_metrics.dg_size_rcvd;
    session_metrics->dg_recv_timedout += recv_metrics.dg_recv_timedout;

    // URL metrics
    udp_url_metrics->dg_recd         += recv_metrics.dg_rcvd;
    udp_url_metrics->dg_size_recd    += recv_metrics.dg_size_rcvd;
    udp_url_metrics->dg_recv_timedout+= recv_metrics.dg_recv_timedout;

    tprint("DG_RECD=%d, DG_TIMEDOUT=%d REQS_SENT=%d REQS_RECD=%u REQS_TIMEDOUT=%u\n", \
        recv_metrics.dg_rcvd, recv_metrics.dg_recv_timedout, session->udp->reqs_sent, \
        session->udp->resp_recd, session->udp->resp_timedout);

    // Sent all and received all, clean it up
    if(request->dg_rcvd == request->dg_to_recv && request->dg_sent == request->dg_to_send) {
        te_process_udp_session(session);
        udp_easy_cleanup(request->easy_handle);
        te_free(request, TE_MTYPE_UDP_REQUEST);
    }
}

void load_udp_random_session_data(te_session_t* session) {
    int sum_of_download_upload_ratio = res_cfg->download_upload_ratio[session->vip_index].download_ratio + \
        res_cfg->download_upload_ratio[session->vip_index].upload_ratio;

    if(likely(sum_of_download_upload_ratio)) {
        // If num_requests was 0, we must still be able to go ahead without crashing
        if(session->num_requests == 0) {
            session->num_requests = sum_of_download_upload_ratio;
        }
        session->udp->num_downloads = (res_cfg->download_upload_ratio[session->vip_index].download_ratio *  \
                            session->num_requests)/(sum_of_download_upload_ratio);
    }
    else {
        eprint("DOWNLOAD-TO-UPLOAD Ratio is 0:0 for vip=%s\n", res_cfg->vips[session->vip_index].vip);
        abort();
    }
    session->udp->num_uploads = session->num_requests - session->udp->num_downloads;
    session->udp->is_download = true;

    //We must have something to upload or download
    assert(session->udp->num_uploads + session->udp->num_downloads != 0);

    //Check if the download-profile already exists, else switch to complete uploads
    unsigned short profile_index = res_cfg->vips[session->vip_index].udp_profile_index;
    if(session->udp->num_downloads) {
        //There is something to download but the vip has no download profile, switch to upload
        if(res_cfg->udp_reqs[profile_index].download_req == NULL) {
            session->udp->num_uploads += session->udp->num_downloads;
            session->udp->num_downloads = 0;
            session->udp->is_download = false;
            wprint("No download_prof for vip=%s & mandating to all uploads, num_downloads=%d, " \
                "num_uploads=%d\n", res_cfg->vips[session->vip_index].vip, \
                session->udp->num_downloads, session->udp->num_uploads);
        }
    } else {
        //If there is nothing to download
        session->udp->is_download = false;
    }

    //Check if the upload-profile already exists, else switch to complete uploads
    if(session->udp->num_uploads) {
        //There is something to upload but the vip has no upload profile, switch to download
        if(res_cfg->udp_reqs[profile_index].upload_req == NULL) {
            session->udp->num_downloads += session->udp->num_uploads;
            session->udp->num_uploads = 0;
            wprint("No upload_prof for vip=%s & mandating to all downloadss, num_downloads=%d, "\
                "num_uploads=%d\n", res_cfg->vips[session->vip_index].vip, \
                session->udp->num_downloads, session->udp->num_uploads);
        }
    }

    session->udp->pending_downloads = session->udp->num_downloads;
    session->udp->pending_uploads = session->udp->num_uploads;

    // Reset the reqs_sent, resp_rcvd while loading session_data.
    session->udp->reqs_sent = 0;
    session->udp->reqs_failed = 0;
    session->udp->resp_recd = 0;
    session->udp->resp_not_needed = 0;
    session->udp->resp_timedout = 0;
}

void flush_udp_multi_handle(te_session_t *session) {
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    udp_multi_handle_t* um_handle = session->udp->um_handle;
    session->udp->um_handle = NULL;
    UDPMcode mcode = udp_multi_cleanup(um_handle);
    if(unlikely(mcode != UDPM_OK)) {
        eprint("udp_multi_cleanup, %d\n",(int)mcode);
    }
    if ((!session->good_1st_response) ||
        (session->cycle_iter == session_cfg_p->num_cycles) ||
        (session_cfg_p->config_state == TE_SESSION_CONFIG_STATE_STOP)) {
        session->good_1st_response = 0;
    }
}

void init_udp_multi_handle(te_session_t * session) {
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    UDPMcode mcode;

    //If Session's details are already there, do a flush_multi_handle (where ever required)
    if (session->udp->um_handle) {
       if (session_cfg_p->cycle_type == TE_SESSION_CYCLE_RESTART) {
            // Flush the multi-easy_handle if CYCLE is restart, irrespective of session type.
            tprint("%d,%lu, CYCLE_START_TYPE: Restarting.\n", session->id, session->cycle_iter + 1);
            flush_udp_multi_handle(session);
            session->udp->um_handle = udp_multi_init();
        }
        else {
            // Session Cycle is Resume type and no good 1st response.
            if (!session->good_1st_response && session->session_cfg_p->type == TE_SESSION_TYPE_BROWSER) {
                // Flush the multi-easy_handle if no good 1st response.
                wprint("%d,%lu, CYCLE_START_TYPE: Restarting due to PREV_BAD_CYCLE.\n",
                    session->id, session->cycle_iter + 1);
                flush_udp_multi_handle(session);
                session->udp->um_handle = udp_multi_init();
            }
            else {
                tprint("%d,%lu, CYCLE_START_TYPE: RESUMING.\n", session->id, session->cycle_iter + 1);
            }
        }
    }
    else {
        session->udp->um_handle = udp_multi_init();
    }
    //Maximum connections to open from the multi-handle
    mcode = udp_multi_setopt(session->udp->um_handle, UDP_MAX_CONNECTS, session->num_connections);
    if(unlikely(mcode != UDPM_OK))
        eprint("UDP_MAX_CONNECTS, %d\n",(int)mcode);

    //Callback for every sentout UDP datagram
    mcode = udp_multi_setopt(session->udp->um_handle, UDP_SEND_CALLBACK, te_udp_send_callback);
    if(unlikely(mcode != UDPM_OK))
        eprint("UDP_SEND_CALLBACK, %d\n",(int)mcode);

    //Callback for every received UDP datagram
    mcode = udp_multi_setopt(session->udp->um_handle, UDP_RECV_CALLBACK, te_udp_recv_callback);
    if(unlikely(mcode != UDPM_OK))
        eprint("UDP_RECV_CALLBACK, %d\n",(int)mcode);

    //IP to hit by the multi handle
    mcode = udp_multi_setopt(session->udp->um_handle, UDP_IP, res_cfg->vips[session->vip_index].vip);
    if(unlikely(mcode != UDPM_OK))
        eprint("UDP_IP, %d\n",(int)mcode);

    //Port to hit by the multi handle
    mcode = udp_multi_setopt(session->udp->um_handle, UDP_PORT, res_cfg->vips[session->vip_index].vport);
    if(unlikely(mcode != UDPM_OK))
        eprint("UDP_PORT, %d\n",(int)mcode);

    //Timeout for the multi handle
    int udp_profile_index = res_cfg->vips[session->vip_index].udp_profile_index;
    te_udp_request_object_t udp_profile = res_cfg->udp_reqs[udp_profile_index];
    mcode = udp_multi_setopt(session->udp->um_handle, UDP_SOCKET_TIMEOUT, udp_profile.min_timeout);
    if(unlikely(mcode != UDPM_OK))
        eprint("UDP_TIMEOUT, %d\n",(int)mcode);

}


te_udp_request_t* create_udp_request() {
    te_udp_request_t *request;
    te_malloc(request, sizeof(te_udp_request_t), TE_MTYPE_UDP_REQUEST);
    if(likely(request)) {
        memset(request, 0, sizeof(te_udp_request_t));
        return request;
    }
    return NULL;
}

void add_udp_request(te_session_t* session) {
    udp_easy_handle_t* easy_handle = udp_easy_init();
    int vip_hash = session->vip_index;
    int udp_profile_index = res_cfg->vips[vip_hash].udp_profile_index;
    te_udp_datagram_t *req, *resp;
    TE_SESSION_REQ req_type;

    if(session->udp->is_download && session->udp->pending_downloads != 0) {
        --session->udp->pending_downloads;
        if(session->udp->pending_uploads != 0)
            session->udp->is_download = false;
        req = res_cfg->udp_reqs[udp_profile_index].download_req;
        resp = res_cfg->udp_reqs[udp_profile_index].download_resp;
        req_type = TE_SESSION_REQ_DOWNLOAD;
    }
    else if(!session->udp->is_download && session->udp->pending_uploads != 0) {
        --session->udp->pending_uploads;
        if(session->udp->pending_downloads != 0)
            session->udp->is_download = true;
        req = res_cfg->udp_reqs[udp_profile_index].upload_req;
        resp = res_cfg->udp_reqs[udp_profile_index].upload_resp;
        req_type = TE_SESSION_REQ_UPLOAD;
    }
     else {
        eprint("No Upload or Download Request to add! is_download=%d pending_downloads=%d pending_uploads=%d vip=%s\n",
        (int)session->udp->is_download, session->udp->pending_downloads, session->udp->pending_uploads, \
        res_cfg->vips[vip_hash].vip);
        abort();
    }

    unsigned short dg_num_send = te_random(req->min_datagram, req->max_datagram);
    unsigned short dg_size_send = te_random(req->min_datagram_size, req->max_datagram_size);
    unsigned short dg_num_recv = te_random(resp->min_datagram, resp->max_datagram);
    unsigned short dg_size_recv = te_random(resp->min_datagram_size,  resp->max_datagram_size);

    //If size expected is 0 then there is no point expecting a response and vice-versa
    if(dg_num_recv == 0 || dg_size_recv == 0) {
        dg_num_recv = dg_size_recv = 0;
    }

    UDPEcode ecode;

    // We can't have 0 sent out dgs
    assert(dg_num_send != 0 && dg_size_send != 0);

    ecode = udp_easy_setopt(easy_handle, UDP_DG_NUM_TO_SEND, dg_num_send);
    if(unlikely(ecode != UDPE_OK))
        eprint("UDP_DG_NUM_TO_SEND, %d\n",(int)ecode);
    ecode = udp_easy_setopt(easy_handle, UDP_DG_SIZE_TO_SEND, dg_size_send);
    if(unlikely(ecode != UDPE_OK))
        eprint("UDP_DG_SIZE_TO_SEND, %d\n",(int)ecode);

    // If there is nothing to recv, don't set the knobs of receiving
    // as the default is 0 dgs to recv
    if(dg_num_recv != 0) {
        ecode = udp_easy_setopt(easy_handle, UDP_DG_NUM_TO_RECV, dg_num_recv);
        if(unlikely(ecode != UDPE_OK))
            eprint("UDP_DG_NUM_TO_RECV, %d\n",(int)ecode);

        ecode = udp_easy_setopt(easy_handle, UDP_DG_SIZE_TO_RECV, dg_size_recv);
        if(unlikely(ecode != UDPE_OK))
            eprint("UDP_DG_SIZE_TO_RECV, %d\n",(int)ecode);
    }

    // But the default knob for timeout is 10s,
    // So no matter what, we got to set the timeout
    ecode = udp_easy_setopt(easy_handle, UDP_RECV_TIMEOUT, resp->timeout);
    if(unlikely(ecode != UDPE_OK))
        eprint("UDP_RECV_TIMEOUT, %d\n",(int)ecode);

    te_udp_request_t* request = create_udp_request();
    if (unlikely(!request)) {
        wprint("Unable to allocate memory for request.\n");
        abort();
    }
    request->req_type = req_type;
    request->session = session;
    request->dg_to_send = dg_num_send;
    request->dg_to_recv = dg_num_recv;
    request->dg_size_to_send = dg_size_send;
    request->dg_size_to_recv = dg_size_recv;
    request->easy_handle = easy_handle;
    ecode = udp_easy_setopt(easy_handle, UDP_PRIVATE, request);
    if(unlikely(ecode != UDPE_OK))
        eprint("UDP_PRIVATE, %d\n",(int)ecode);


    UDPMcode mcode = udp_multi_add_handle(session->udp->um_handle, easy_handle);
    if (mcode != UDPM_OK && mcode != UDPM_OK_PENDING_TO_SEND) {
        eprint("failed to add to multi easy_handle , rc = %d\n", mcode);
    } else if(mcode == UDPM_OK_PENDING_TO_SEND) {
        tprint("Pending to be sent out\n");
    }
    return;
}

void update_udp_session_config_metrics(te_session_t* session) {
    te_udp_vip_metrics_t *vip_metric = NULL;
    te_resource_config_t *res_cfg = NULL;
    te_session_config_t *session_cfg=session->session_cfg_p;
    te_udp_session_metrics_t* ses_metric = &session_cfg->udp_metrics;

    res_cfg = session_cfg->res_cfg;
    vip_metric = &res_cfg->udp_vip_metrics[session->vip_index];

    ses_metric->cycles_complete++;
    vip_metric->stats_present = true;
}
