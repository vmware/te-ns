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

#ifndef TE_TCP_DP_H
#include "te_tcp_dp.h"
#endif

void load_tcp_random_session_data(te_session_t* session) {
    te_session_config_t *session_cfg = session->session_cfg_p;

    int sum_of_get_post_ratio = res_cfg->get_post_ratio[session->vip_index].get_ratio + \
        res_cfg->get_post_ratio[session->vip_index].post_ratio;

    if(likely(sum_of_get_post_ratio)) {
        // If num_requests was 0, we must still be able to go ahead without crashing
        if(session->num_requests == 0) {
            session->num_requests = sum_of_get_post_ratio;
        }
        session->tcp->num_gets = (res_cfg->get_post_ratio[session->vip_index].get_ratio *  \
                            session->num_requests)/(sum_of_get_post_ratio);
    }

    else {
        eprint("GET-TO-POST Ratio is 0:0 for vip=%s\n", res_cfg->vips[session->vip_index].vip);
        abort();
    }
    session->tcp->num_posts = session->num_requests - session->tcp->num_gets;
    session->tcp->is_get = true;

    //We must have something to either post or get
    assert(session->tcp->num_gets + session->tcp->num_posts != 0);

    //Check if the get-profile already exists, else switch to complete posts
    if(session->tcp->num_gets) {
        //There is something to get but the vip has no get profile, switch to posts
        if(res_cfg->vips[session->vip_index].get_profile_index == -1) {
            session->tcp->num_posts += session->tcp->num_gets;
            session->tcp->num_gets = 0;
            session->tcp->is_get = false;
            wprint("No get_prof for vip=%s & mandating to all posts, num_gets=%d, num_posts=%d\n", \
                res_cfg->vips[session->vip_index].vip, session->tcp->num_gets, session->tcp->num_posts);
        }
    } else {
        //If there is nothing to get
        session->tcp->is_get = false;
    }

    //Check if the post-profile already exists, else switch to complete gets
    if(session->tcp->num_posts) {
        //There is something to post but the vip has no post profile, switch to gets
        if(res_cfg->vips[session->vip_index].post_profile_index == -1) {
            session->tcp->num_gets += session->tcp->num_posts;
            session->tcp->num_posts = 0;
            wprint("No post_prof for vip=%s & mandating to all gets, num_gets=%d, num_posts=%d\n", \
                res_cfg->vips[session->vip_index].vip, session->tcp->num_gets, session->tcp->num_posts);
        }
    }

    session->tcp->pending_gets = session->tcp->num_gets;
    session->tcp->pending_posts = session->tcp->num_posts;

    session_cfg->http_metrics.open_connections += session->num_connections;
    session_cfg->http_metrics.total_connections += session->num_connections;

    // Reset the reqs_sent, resp_rcvd while loading session_data.
    session->tcp->reqs_sent = 0;
    session->tcp->resp_recd = 0;

    int interface_profile_index = res_cfg->vips[session->vip_index].interface_profile_index;
    if(session->session_cfg_p->cycle_type == TE_SESSION_CYCLE_RESTART || session->cycle_iter == 0) {
        // Chose the interface, everytime if the type is restart,
        // Or only for the 1st time (as choosing a new interface, will close the prev opened conns)
        if(interface_profile_index != -1) {
            // If the VIP has an attached interface details
            int interface_index = res_cfg->vips[session->vip_index].rr_interface_counter % \
                                            res_cfg->num_interfaces_in_profiles[interface_profile_index];
            res_cfg->vips[session->vip_index].rr_interface_counter++;
            session->tcp->interface_obj = \
                &res_cfg->interface_obj[interface_profile_index][interface_index];
        } else {
            session->tcp->interface_obj = NULL;
        }
    }
}

//**********************************************//
//                ERROR DUMPERS                 //
//**********************************************//
/* Die if we get a bad CURLMcode somewhere */
#define te_dump_mcode_or_die(where, code) \
    do { \
        if (unlikely(CURLM_OK != code)) { \
            const char *s; \
            switch(code) { \
                case     CURLM_BAD_HANDLE:         s="CURLM_BAD_HANDLE";         break; \
                case     CURLM_BAD_EASY_HANDLE:    s="CURLM_BAD_EASY_HANDLE";    break; \
                case     CURLM_OUT_OF_MEMORY:      s="CURLM_OUT_OF_MEMORY";      break; \
                case     CURLM_INTERNAL_ERROR:     s="CURLM_INTERNAL_ERROR";     break; \
                case     CURLM_BAD_SOCKET:         s="CURLM_BAD_SOCKET";         break; \
                case     CURLM_UNKNOWN_OPTION:     s="CURLM_UNKNOWN_OPTION";     break; \
                case     CURLM_LAST:               s="CURLM_LAST";               break; \
                default: s="CURLM_unknown"; \
            } \
            wprint("CURL_MERROR: %s returns %s\n", where, s); \
            abort(); \
        } \
    } while(0);

void dump_error_request(te_tcp_request_t *req, int fail_reason, char* header, char* post_file_name)
{
    char *url;
    te_request_object_t* rlist;
    char *local_ip, *remote_ip;
    unsigned long local_port, remote_port;
    CURL *ce_handle;
    double content_length;
    double start_time = 0;
    double complete_time = 0;
    te_session_t *session = req->sessionp;
    ce_handle = req->ce_handle;
    curl_easy_getinfo(ce_handle, CURLINFO_PRIMARY_IP, &remote_ip);
    curl_easy_getinfo(ce_handle, CURLINFO_PRIMARY_PORT, &remote_port);
    curl_easy_getinfo(ce_handle, CURLINFO_LOCAL_IP, &local_ip);
    curl_easy_getinfo(ce_handle, CURLINFO_LOCAL_PORT, &local_port);
    curl_easy_getinfo(ce_handle, CURLINFO_EFFECTIVE_URL, &url);

    switch(fail_reason) {
        case POST_FILE_NOT_FOUND: {
            eprint("%d, %lu, POST_ERROR, %d, %s, %ld, %s, %ld, %s, ,%s: %s\n",
                 session->id, session->cycle_iter+1, req->id + 1,
                 local_ip, local_port, remote_ip, remote_port, url, "FILE_NOT_FOUND", post_file_name);
        } break;

        case PERSIST_CHECK_FAIL: {
            eprint("%d, %lu, PERSIST_CHECK_FAIL, %d, %s, %ld, %s, %ld, %s, %.*s, %s\n",
                session->id, session->cycle_iter+1, req->id + 1,
                local_ip, local_port, remote_ip, remote_port, url,
                (int)strlen(session->tcp->persist_str)-2,
                &session->tcp->persist_str[0], header);
        } break;

        case LENGTH_CHECK_FAIL: {
            curl_easy_getinfo(ce_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
                &content_length);
            int usize;
            if (req->req_type == TE_SESSION_REQ_GET) {
                rlist = &(res_cfg->greqs[req->prof_index][req->url_index]);
            }
            else if (req->req_type == TE_SESSION_REQ_POST) {
                rlist = &(res_cfg->preqs[req->prof_index][req->url_index]);
            }
            usize = rlist->request_uri.size;
            eprint("%d, %lu, LENGTH_CHECK_FAIL, %d, %s, %ld, %s, %ld, %s, %d, %d\n",
                session->id, session->cycle_iter+1, req->id + 1,
                local_ip, local_port, remote_ip, remote_port, url,
                usize, (int)content_length);
        } break;

        case URL_TIME_EXCEEDED: {
            curl_easy_getinfo(ce_handle, CURLINFO_PRETRANSFER_TIME, &start_time);
            curl_easy_getinfo(ce_handle, CURLINFO_TOTAL_TIME, &complete_time);
            double thres_time;
            if (req->req_type == TE_SESSION_REQ_GET) {
                rlist = &(res_cfg->greqs[req->prof_index][req->url_index]);
            }
            else if (req->req_type == TE_SESSION_REQ_POST) {
                rlist = &(res_cfg->preqs[req->prof_index][req->url_index]);
            }
            thres_time = (double)rlist->request_uri.threshold_time;
            eprint("%d, %lu, URL_TIME_EXCEEDED, %d, %s, %ld, %s, %ld, %s, %.03lf, %.03lf\n",
                session->id, session->cycle_iter+1, req->id + 1,
                local_ip, local_port, remote_ip, remote_port, url,
                thres_time,(complete_time - start_time));
        } break;
    }
}


//**********************************************//
//             PROCESSING SESSION               //
//**********************************************//
void te_process_session(te_session_t *session)
{
    CURLMsg *message;
    int pending = 0;
    CURL *ce_handle = NULL;
    CURLM *cm_handle;
    cm_handle = session->tcp->cm_handle;
    long response_code;
    te_tcp_request_t *msg_request = NULL;
    CURLcode CEcode, Ecode;

    if (unlikely(is_session_config_state_stopped(session->session_cfg_p))) {
       return;
    }

    while((message = curl_multi_info_read(cm_handle, &pending))) {
        switch(message->msg) {
            case CURLMSG_DONE:
                ce_handle = message->easy_handle;
                CEcode = curl_easy_getinfo(ce_handle, CURLINFO_PRIVATE, &msg_request);
                if(unlikely(CEcode != CURLE_OK))
                    eprint("CURLINFO_PRIVATE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

                CEcode = curl_easy_getinfo(ce_handle, CURLINFO_RESPONSE_CODE, &response_code);
                if(unlikely(CEcode != CURLE_OK))
                    eprint("CURLINFO_RESPONSE_CODE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

                session->tcp->resp_recd++;
                Ecode = message->data.result;
                if (metrics_enabled) {
                    load_session_metrics(ce_handle, Ecode);
                }

                CEcode = curl_easy_setopt(ce_handle, CURLOPT_PRIVATE, NULL);
                if(unlikely(CEcode != CURLE_OK))
                    eprint("CURLOPT_PRIVATE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

                delete_tcp_request(msg_request);
                if (session->session_cfg_p->type == TE_SESSION_TYPE_BROWSER) {
                    if (session->tcp->resp_recd == 1) {
                        /* Received 1st response in browser session cycle.
                        Check if we have good 1st response
                        for session across all cycles.*/
                        if (!session->good_1st_response) {
                            // No good 1st response so far.
                            tprint("response code %lu \n", response_code);
                            if (response_code >= 200 && response_code < 300) {

                                /* Got good 1st response for a browser session. Wohooo!!!
                                Now the session is GREEN for all pending requests.*/
                                session->good_1st_response++;

                                // If there is only one req to send, go to sleep in case of browser
                                // Else go to send all request state
                                if(session->num_requests == 1) {
                                    session->state = TE_SESSION_STATE_CYCLE_SLEEP;
                                } else {
                                    session->state = TE_SESSION_STATE_SEND_ALL_REQ;
                                }
                                tprint("Rcvd 1st Response session:%d, status:GOOD\n", session->id);
                                goto end_review;
                            } else {
                                // HardLuck!! Bad 1st response, End the session cycle.
                                wprint("Rcvd 1st Response  session:%d, status:BAD\n", session->id);
                                session->state = TE_SESSION_STATE_CYCLE_SLEEP;
                                goto end_review;
                            }
                        }
                    }
                }
                if (session->tcp->resp_recd == session->num_requests) {
                    // All responses rcvd, so end the cycle.
                    tprint("id=%d c_iter=%lu, t_iter=%d,num_req=%d, sent_req=%d, recd_req=%d\n", \
                        session->id, session->cycle_iter, session->total_cycle_iter, \
                        session->num_requests, session->tcp->reqs_sent, session->tcp->resp_recd);
                    if (session->session_cfg_p->type == TE_SESSION_TYPE_BROWSER)  {
                        session->state = TE_SESSION_STATE_CYCLE_SLEEP;
                    } else {
                        session->state = TE_SESSION_STATE_CYCLE_END;
                    }
                    goto end_review;
                }
                break;

            default:
                break;
        }
    }
    return;

    end_review:
        uv_async_send(&session->fsm_handler);
        return;
}


//**********************************************//
//                 UV CALLBACKS                 //
//**********************************************//
void te_poll_req_uv_cb(uv_poll_t *user_p, int status, int events)
{
    te_socket_node_t* conn_poll_handle = (te_socket_node_t *)user_p->data;
    int flags = 0, running_handles;
    CURLMcode rc;

    if(events & UV_READABLE)
        flags |= CURL_CSELECT_IN;
    if(events & UV_WRITABLE)
        flags |= CURL_CSELECT_OUT;

    assert(conn_poll_handle->session_p != NULL);

    rc = curl_multi_socket_action(conn_poll_handle->session_p->tcp->cm_handle, \
        conn_poll_handle->tcp_sockfd, flags, &running_handles);
    te_dump_mcode_or_die("poll_cb: te_poll_req_uv_cb", rc);
    te_process_session(conn_poll_handle->session_p);
}

void on_session_uv_timeout(uv_timer_t *user_p)
{
    int running_handles;
    CURLMcode rc;
    te_session_t *session= (te_session_t *) user_p->data;
    if (unlikely(is_session_config_state_stopped(session->session_cfg_p))) {
        return;
    }
    if (likely(session->tcp->cm_handle)) {
        rc = curl_multi_socket_action(session->tcp->cm_handle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
        te_dump_mcode_or_die("session_uv_timeout", rc);
        te_process_session(session);
    } else {
        abort();
    }
}


//**********************************************//
//         HELPERS TO ACCUMULATE METRICS        //
//**********************************************//
short te_search_ses_bucket_index(te_http_vip_metrics_t *vip_metrics,
                                short num_buckets,
                                double cycle_cmplt_time)
{
    short low,  high,  mid;
    if (vip_metrics == NULL || vip_metrics->session_buckets == NULL) {
        return -1;
    }
    /*convert to ms, should we make it configurable ? */
    cycle_cmplt_time = cycle_cmplt_time*1000;
    low = 0;
    high = num_buckets-1;
    mid = (high+low)/2;
    while (low < high) {
        if (vip_metrics->session_buckets[mid].bucket_start_time <= cycle_cmplt_time) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
        if (vip_metrics->session_buckets[mid].bucket_start_time <= cycle_cmplt_time &&
                    vip_metrics->session_buckets[mid].bucket_end_time > cycle_cmplt_time) {
            break;
        }
        mid = (high+low)/2;
    }
    if (vip_metrics->session_buckets[mid].bucket_end_time > cycle_cmplt_time) {
        return mid;
    }
    return -1;
}

short te_search_url_bucket_index (te_http_url_metrics_t *url_metrics,
                                  short num_buckets,
                                  double cycle_cmplt_time)
{
    short low,  high,  mid;
    cycle_cmplt_time = cycle_cmplt_time*1000; /*convert to ms*/
    low = 0;
    high = num_buckets-1;
    mid = (high+low)/2;
    if ((url_metrics == NULL) || (url_metrics->url_buckets) == NULL) {
        return -1;
    }
    while (low < high) {
        if (url_metrics->url_buckets[mid].bucket_start_time <= cycle_cmplt_time) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
        if (url_metrics->url_buckets[mid].bucket_start_time <= cycle_cmplt_time &&
                    url_metrics->url_buckets[mid].bucket_end_time > cycle_cmplt_time) {
            break;
        }
        mid = (high+low)/2;
    }
    if (url_metrics->url_buckets[mid].bucket_end_time > cycle_cmplt_time) {
        return mid;
    }
    return -1;
}


//**********************************************//
//     PROCESSING AND ACCUMULATING METRICS      //
//**********************************************//
void load_session_metrics(CURL *ce_handle, CURLcode Ecode) {
    te_request_object_t* rlist = NULL;
    te_tcp_request_t* request = NULL;
    te_session_t* session = NULL;
    te_session_config_t* session_cfg = NULL;
    double start_time = 0;
    double complete_time = 0;
    double diff_time = 0;
    unsigned int response_code = 0;
    double content_length = 0;
    double bytes_download = 0;
    unsigned int vip_hash = 0;
    unsigned int is_failed_req = false;
    unsigned int resp_value = 0;
    te_resource_config_t *res_cfg;
    char response_code_str[14];

    curl_easy_getinfo(ce_handle, CURLINFO_PRIVATE, &request);
    session = request->sessionp;
    session_cfg = session->session_cfg_p;
    res_cfg = session_cfg->res_cfg;

    //Ses Metrics
    te_http_session_metrics_t* ses_metric = &session_cfg->http_metrics;

    //VIP Metrics
    vip_hash = session->vip_index;
    te_http_vip_metrics_t* vip_metric = &res_cfg->http_vip_metrics[vip_hash];
    te_http_url_metrics_t* url_metric = NULL;
    te_error_metrics_t** error_metric = NULL;

    //Get Url Metric's pointer
    if (request->req_type == TE_SESSION_REQ_GET) {
        rlist = &(res_cfg->greqs[request->prof_index][request->url_index]);
        url_metric = &(vip_metric->url_get_metrics[request->url_index]);
    }
    else if (request->req_type == TE_SESSION_REQ_POST) {
        rlist = &(res_cfg->preqs[request->prof_index][request->url_index]);
        url_metric = &(vip_metric->url_post_metrics[request->url_index]);
    }
    else {
        abort();
    }

    //Get Error Metric's pointer
    error_metric = url_metric->error_metrics;
    //Setting stats_present to true, that way the stats gets dumped
    url_metric->stats_present = true;
    vip_metric->stats_present = true;

    //Bytes Download
    curl_easy_getinfo(ce_handle, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(ce_handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_length);
    curl_easy_getinfo(ce_handle, CURLINFO_SIZE_DOWNLOAD, &bytes_download);
    ses_metric->bytes_download += bytes_download;
    url_metric->url_stats.bytes_download += bytes_download;

    //Compute Time Taken
    curl_easy_getinfo(ce_handle, CURLINFO_PRETRANSFER_TIME, &start_time);
    curl_easy_getinfo(ce_handle, CURLINFO_TOTAL_TIME, &complete_time);
    diff_time = (complete_time - start_time);
    url_metric->url_stats.sum_latency += diff_time;
    url_metric->url_stats.sum_square_latency += diff_time * diff_time;
    ses_metric->complete_time += complete_time;

    //Count responses Received
    ses_metric->resp_rcvd++;
    url_metric->url_stats.resp_rcvd++;
    if (request->req_type == TE_SESSION_REQ_GET) {
        ses_metric->http_gets_rcvd++;
        url_metric->url_stats.http_gets_rcvd++;
    }
    else {
        ses_metric->http_posts_rcvd++;
        url_metric->url_stats.http_posts_rcvd++;
    }

    int code = (int)Ecode;
    switch(code) {
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_SSL_ENGINE_NOTFOUND:
        case CURLE_SSL_ENGINE_SETFAILED:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case CURLE_PEER_FAILED_VERIFICATION:
        case CURLE_USE_SSL_FAILED:
        case CURLE_SSL_ENGINE_INITFAILED:
        case CURLE_SSL_CACERT_BADFILE:
        case CURLE_SSL_SHUTDOWN_FAILED:
        case CURLE_SSL_CRL_BADFILE:
        case CURLE_SSL_ISSUER_ERROR:
        case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
        case CURLE_SSL_INVALIDCERTSTATUS:
            is_failed_req = true;
            error_metric[SSL_ERROR] = insert_or_update_error(error_metric[SSL_ERROR], code, \
                curl_easy_strerror(code), url_metric);
            break;

        case CURLE_URL_MALFORMAT:
        case CURLE_HTTP2:
        case CURLE_HTTP_RETURNED_ERROR:
        case CURLE_HTTP_POST_ERROR:
        case CURLE_HTTP2_STREAM:
        case CURLE_PARTIAL_FILE:
        case CURLE_RANGE_ERROR:
        case CURLE_BAD_DOWNLOAD_RESUME:
        case CURLE_TOO_MANY_REDIRECTS:
        case CURLE_GOT_NOTHING:
        case CURLE_BAD_CONTENT_ENCODING:
            is_failed_req = true;
            error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], code, \
                curl_easy_strerror(code), url_metric);
            break;

        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_CONNECT:
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_INTERFACE_FAILED:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
        case CURLE_AGAIN:
            is_failed_req = true;
            error_metric[TCP_ERROR] = insert_or_update_error(error_metric[TCP_ERROR], code, \
                curl_easy_strerror(code), url_metric);
            break;

        case CURLE_OK:
            break;

        default:
            eprint("UNKNOWN ERROR: %d %s\n", code, curl_easy_strerror(code));
    }

    //Count response codes received
    resp_value = response_code/100;
    switch(resp_value)
    {
        case CLIENT_ERR:
            url_metric->url_stats.responses_4xx++;
            is_failed_req = true;
            if(response_code==404) {
                url_metric->url_stats.responses_404++;
                error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                    RES_NOT_FOUND, "RES_NOT_FOUND", url_metric);
            }
            else {
                snprintf(response_code_str, 14, "http_code_%d", response_code);
                error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                    response_code, response_code_str, url_metric);
            }
            break;
        case SERVER_ERR:
            url_metric->url_stats.responses_5xx++;
            is_failed_req = true;
            snprintf(response_code_str, 14, "http_code_%d", response_code);
            error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                response_code, response_code_str, url_metric);
            break;
        case TCP_ERR:
            url_metric->url_stats.tcp_failures++;
            is_failed_req = true;
            //Already Taken Care of (No need to call insert_or_update_error)!
            break;
        case REDIRECTION:
            url_metric->url_stats.responses_3xx++;
            snprintf(response_code_str, 14, "http_code_%d", response_code);
            error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                response_code, response_code_str, url_metric);
            break;
        case SUCCESS:
            url_metric->url_stats.responses_2xx++;
            if(response_code==200)
               url_metric->url_stats.responses_200++;
            break;
        case INFO_RESP:
            url_metric->url_stats.responses_1xx++;
            snprintf(response_code_str, 14, "http_code_%d", response_code);
            error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                response_code, response_code_str, url_metric);
            break;
        default:
            error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                RESP_UNKNOWN, "RESP_UNKNOWN", url_metric);
    }

    //Dump errors and update error
    if ((rlist->request_uri.size) && (content_length != rlist->request_uri.size)) {
        ses_metric->len_fail++;
        url_metric->url_stats.len_fail++;
        dump_error_request(request, LENGTH_CHECK_FAIL, NULL, NULL);
        error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
            LENGTH_CHECK_FAIL, "LENGTH_CHECK_FAIL", url_metric);
    }

    short bucket_index = 0;
    if (url_metric->num_url_buckets) {
        bucket_index = te_search_url_bucket_index(url_metric,
                        url_metric->num_url_buckets, diff_time);
        assert(bucket_index < url_metric->num_url_buckets);
        if (bucket_index != -1) {
            url_metric->url_buckets[bucket_index].bucket++;
            url_metric->url_buckets[bucket_index].total_time += diff_time;
        }

        else {
            tprint("no url bucket found url index %d cmplt_time %0.3lf\n", \
                request->url_index, diff_time*1000);
        }
    }
    if (url_metric->url_stats.resp_rcvd == 1) {
        url_metric->url_stats.min_time = diff_time;
        url_metric->url_stats.max_time = diff_time;
    }
    else {
        if (diff_time < url_metric->url_stats.min_time) {
           url_metric->url_stats.min_time = diff_time;
        }
        if (url_metric->url_stats.max_time < diff_time) {
            url_metric->url_stats.max_time = diff_time;
            if (rlist->request_uri.threshold_time &&
                (url_metric->url_stats.max_time > rlist->request_uri.threshold_time)) {
                is_failed_req = true;
                dump_error_request(request, URL_TIME_EXCEEDED, NULL, NULL);
                error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                    URL_TIME_EXCEEDED, "URL_TIME_EXCEEDED", url_metric);
            }
        }
    }
    if (is_failed_req) {
        url_metric->url_stats.failed_reqs++;
        ses_metric->failed_reqs++;
    }
    return;
}

void update_tcp_session_config_metrics(te_session_t *session)
{
    short  bucket_index = 0;
    te_http_vip_metrics_t *vip_metric = NULL;
    te_resource_config_t *res_cfg = NULL;
    te_session_config_t *session_cfg=session->session_cfg_p;

    res_cfg = session_cfg->res_cfg;
    vip_metric = &res_cfg->http_vip_metrics[session->vip_index];

    // Setting stats_present to true, that way stats gets dumped
    // Not setting url' stats_present to true, as touching vip's stats doesn't affect url's stat
    // Not the other way around though
    vip_metric->stats_present = true;
    // This is painful bug to have!! If you could find it,
    // Congrats!! you are expert of TE_DP!
    // Now if you could not fix it. Increment hours_wasted = 1 + 1

    //AK: As of yet, it is not possible to detemine the exact number of conn failure
    //as TE_DP operates at Request Level. If it's possible to fix the issue, please
    //uncomment the lines maked as *** below and remove lines marked as **

    //vip_metric->vip_stats.failed_connections += session->failed_conns; //***
    vip_metric->vip_stats.failed_connections = 0; //**
    vip_metric->vip_stats.connections += session->num_connections;
    session->failed_conns = 0; //**
    if (session->num_connections >= session->failed_conns) {
        //vip_metric->vip_stats.good_connections += (session->num_connections - session->failed_conns); //***
        vip_metric->vip_stats.good_connections = 0; //**
    }

    te_http_session_metrics_t* ses_metric = &session_cfg->http_metrics;
    double cycle_complete_time = te_difftime(session->end_time, session->start_time);
    ses_metric->complete_time += cycle_complete_time;
    ses_metric->open_connections -= session->num_connections;
    ses_metric->cycles_complete++;

    if (vip_metric->num_session_buckets) {
        bucket_index = te_search_ses_bucket_index(vip_metric, vip_metric->num_session_buckets,
                        cycle_complete_time);
        assert(bucket_index < vip_metric->num_session_buckets);
        if (bucket_index != -1) {
            vip_metric->session_buckets[bucket_index].bucket++;
            vip_metric->session_buckets[bucket_index].total_time += cycle_complete_time;
        }
        else {
            tprint("no ses bucket found for vip index %d complt_time %0.3lf\n",
                session->vip_index, cycle_complete_time*1000);
        }
    }
}


//**********************************************//
//            MULTI SETOPT CALLBACKS            //
//**********************************************//
int curl_socket_timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
    /*
    * The callback is made at timeout
    * Since UV is event based, it is necessary to have a timer callback as well,
    * in order to perform timeout related activites.
    * It calls on_session_uv_timeout()
    */
    te_session_t *session = (te_session_t *)userp;
    if (unlikely(is_session_config_state_stopped(session->session_cfg_p))) {
       return 0;
    }
    if (timeout_ms < 0) {
       uv_timer_stop(&session->tcp->cm_timer);
    }
    else {
        if(timeout_ms == 0)
            timeout_ms = 1;
        uv_timer_start(&session->tcp->cm_timer, on_session_uv_timeout, timeout_ms, 0);
    }
    return 0;
}

int curl_socket_cb(CURL *easy, curl_socket_t s, int action, void *user_p, void *socket_p)
{
    /*
    * Please don't touch the below piece of code. IT WORKS. LEAVE IT.
    * If it doesn't work, still leave it. A bug takes about a week to solve
    * :""((
    */
    te_socket_node_t* socket_ptr_cb = (te_socket_node_t*)socket_p;
    te_socket_node_t* socket_ptr;
    te_tcp_request_t* request;
    te_session_t* session_ptr = (te_session_t *)user_p;
    int events = 0;
    CURLMcode CEcode;

    assert(session_ptr != NULL);
    if (unlikely(is_session_config_state_stopped(session_ptr->session_cfg_p))) {
        return 0;
    }

    CEcode = curl_easy_getinfo(easy, CURLINFO_PRIVATE, &request);
    if(unlikely(CEcode != CURLM_OK))
        eprint("CURLINFO_PRIVATE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    assert(request != NULL);

    /*
    * If the number of connection in the multi_handle is 1, then the call_back is called
        * Either on timeout
        * And while
            * PUTTING the Request to the wire
            * GETTING the Response from the wire
            * REMOVING the easy handle once completed
    * Else if there are more than 1 connection in the multi handle,
        * For each connection, the callback is called for CURL_POLL_OUT once
        * Followed by it, the calls are made only for CURL_POLL_IN/CURL_POLL_REMOVE
    */
    switch(action){
        case CURL_POLL_IN:
        case CURL_POLL_OUT:
        case CURL_POLL_INOUT:
        {
            if(!socket_ptr_cb)
                socket_ptr = te_create_or_retrieve_tcp_socket(s, session_ptr);
            else {
                assert(session_ptr == socket_ptr_cb->session_p);
                socket_ptr = socket_ptr_cb;
            }
            assert(socket_ptr->tcp_sockfd == s);

            //CURL_MULTI_ASSOC creates an assoc b/w sockfd and the sock_ptr
            CEcode = curl_multi_assign(session_ptr->tcp->cm_handle, s, socket_ptr);
            if(CEcode != CURLM_OK)
                eprint("curl_multi_assign, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

            if(action != CURL_POLL_IN)
                events |= UV_WRITABLE;
            if(action != CURL_POLL_OUT)
                events |= UV_READABLE;

            uv_poll_start(&socket_ptr->tcp_poll_handle, events, te_poll_req_uv_cb);
        } break;

        case CURL_POLL_REMOVE:
        {
            /*
            * From CURL DOCS:
                * CURL_POLL_REMOVE: The specified socket/file descriptor is no longer used by libcurl.
                * Which means we can confidantly remove the socket once the call is made
            */

            //Make sure while removing the socket if it is for the particular sockfd and sesssion
            assert(socket_ptr_cb->tcp_sockfd == s);
            assert(socket_ptr_cb->session_p == session_ptr);
            if(socket_ptr_cb) {
                uv_poll_stop(&socket_ptr_cb->tcp_poll_handle);
            }
        } break;
        default:
            abort();
    }
    return 0;
}


//**********************************************//
//          CONNECTION INIT AND FLUSH           //
//**********************************************//
void init_tcp_multi_handle(te_session_t * session)
{
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    CURLMcode mcode;
    CURLSHcode shcode;

    //If Session's details are already there, do a flush_tcp_multi_handle (where ever required)
    if (session->tcp->cm_handle) {
       if (session_cfg_p->cycle_type == TE_SESSION_CYCLE_RESTART) {
            // Flush the multi-handle if CYCLE is restart, irrespective of session type.
            flush_tcp_multi_handle(session);
            tprint("%d,%lu, CYCLE_START_TYPE: Restarting.\n", session->id, session->cycle_iter + 1);
        }
        else {
            // Session Cycle is Resume type and no good 1st response.
            if (!session->good_1st_response && session->session_cfg_p->type == TE_SESSION_TYPE_BROWSER) {
                // Flush the multi-handle if no good 1st response.
                flush_tcp_multi_handle(session);
                wprint("%d,%lu, CYCLE_START_TYPE: Restarting due to PREV_BAD_CYCLE.\n",
                    session->id, session->cycle_iter + 1);
            }
            else {
                tprint("%d,%lu, CYCLE_START_TYPE: RESUMING.\n", session->id, session->cycle_iter + 1);
            }
        }
    }
    else {
        //SOCKET FUNCTION
        session->tcp->cm_handle = curl_multi_init();
        mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_SOCKETFUNCTION, curl_socket_cb);
        if(unlikely(mcode != CURLM_OK))
            eprint("CURLMOPT_SOCKETFUNCTION, %d, %s\n",(int)mcode, curl_multi_strerror(mcode));

        //SOCKET DATA
        mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_SOCKETDATA, session);
        if(unlikely(mcode != CURLM_OK))
            eprint("CURLMOPT_SOCKETDATA, %d, %s\n",(int)mcode, curl_multi_strerror(mcode));

        //TIMER FUNCTION
        mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_TIMERFUNCTION, curl_socket_timer_cb);
        if(unlikely(mcode != CURLM_OK))
            eprint("CURLMOPT_TIMERFUNCTION, %d, %s\n",(int)mcode, curl_multi_strerror(mcode));

        //TIMER DATA
        mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_TIMERDATA, session);
        if(unlikely(mcode != CURLM_OK))
            eprint("CURLMOPT_TIMERDATA, %d, %s\n",(int)mcode, curl_multi_strerror(mcode));

        //HTTP PIPELINING
        switch(res_cfg->http_pipeline)
        {
            case HTTP_NOTHING:
                mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_PIPELINING, CURLPIPE_NOTHING);
                break;
            case HTTP1_PIPELINE:
                mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_PIPELINING, CURLPIPE_HTTP1);
                break;
            case HTTP2_MULTIPLEX:
                mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
                break;
            default:
                mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_PIPELINING, CURLPIPE_HTTP1);
        }
        if(unlikely(mcode != CURLM_OK))
            eprint("CURLMOPT_PIPELINING, %d, %s\n",(int)mcode, curl_multi_strerror(mcode));
    }

    //SHARE HANDLE OF MULTI-UV
    if(!session->tcp->share_handle) {
        session->tcp->share_handle = curl_share_init();
        if (likely(session->tcp->share_handle)) {
            if(res_cfg->ssl_details.session_reuse) {
                // We got cache ssl session id in the share handle in order to be available to reuse
                shcode = curl_share_setopt(session->tcp->share_handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
                if(unlikely(shcode != CURLSHE_OK))
                    eprint("CURLSHOPT_SHARE, %d, %s\n",(int)shcode, curl_share_strerror(shcode));
            }
            if(session_cfg_p->persist_flag) {
                // We evaluate the  cache ssl session id in the share handle in order to be available to reuse
                shcode = curl_share_setopt(session->tcp->share_handle, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
                if(unlikely(shcode != CURLSHE_OK))
                    eprint("CURLSHOPT_SHARE, %d, %s\n",(int)shcode, curl_share_strerror(shcode));
            }
        }
    }

    //CONNECTION RELATED KNOBS
    mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_MAX_TOTAL_CONNECTIONS, \
        session->num_connections);
    if(unlikely(mcode != CURLM_OK))
        eprint("CURLMOPT_MAX_TOTAL_CONNECTIONS, %d, %s\n",(int)mcode, curl_multi_strerror(mcode));

    mcode = curl_multi_setopt(session->tcp->cm_handle, CURLMOPT_MAX_HOST_CONNECTIONS, \
        session->num_connections);
    if(unlikely(mcode != CURLM_OK))
        eprint("CURLMOPT_MAX_HOST_CONNECTIONS, %d, %s\n",(int)mcode, curl_multi_strerror(mcode));
}

void flush_tcp_multi_handle(te_session_t *session)
{
    te_session_config_t *session_cfg_p = session->session_cfg_p;
    CURLSH *share_handle = session->tcp->share_handle;
    CURLM *cm_handle = session->tcp->cm_handle;
    session->tcp->cm_handle = NULL;
    curl_multi_cleanup(cm_handle);
    if ((!session->good_1st_response) ||
        (session->cycle_iter == session_cfg_p->num_cycles) ||
        (session_cfg_p->config_state == TE_SESSION_CONFIG_STATE_STOP)) {
        session->tcp->share_handle = NULL;
        curl_share_cleanup(share_handle);
        session->good_1st_response = 0;
        session->tcp->pdata_exists = 0;
        if (session->tcp->persist_str[0] != '\0') {
           memset(session->tcp->persist_str, '\0', sizeof(session->tcp->persist_str));
        }
    }
}


//**********************************************//
//             EASY SETOPT CALLBACKS           //
//**********************************************//
// To send TCP reset instead of FIN
int send_tcp_resets(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose) {
    struct linger sl;
    sl.l_onoff = 1;   /* non-zero value enables linger option in kernel */
    sl.l_linger = 0;  /* timeout interval in seconds */
    setsockopt(curlfd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
    return CURL_SOCKOPT_OK;
}

size_t te_request_write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
   /* we are not interested in the downloaded bytes itself,
      so we only return the size we would have saved ... */
    (void)ptr;  /* unused */
    (void)data; /* unused */
    return (size_t)(size * nmemb);
}

int te_socket_close(void *clientp, curl_socket_t sockfd) {
    close(sockfd);
    return 0;
}

CURLcode ssl_ctx_callback(CURL *curl, void *ssl_ctx, void *user_p) {
    //https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set1_groups.html
    te_ssl_t* ssl_details = (te_ssl_t*) user_p;
    if(ssl_details->groups != NULL) {
        int return_val = SSL_CTX_set1_groups_list(ssl_ctx, ssl_details->groups);
        if(return_val != 1)
            eprint("SSL_CTX_set1_groups_list, %d, %s\n", return_val, "Expected 1 but got 0");
    }
    return CURLE_OK;
}

size_t te_header_function_cb(void *buffer, size_t size, size_t nitems, void *request_p)
{
    te_tcp_request_t *req= (te_tcp_request_t *) request_p;
    te_session_t *session = req->sessionp;
    te_session_config_t *session_cfg = session->session_cfg_p;
    te_http_session_metrics_t* ses_metric = &session_cfg->http_metrics;
    te_http_vip_metrics_t *vip_metric = &res_cfg->http_vip_metrics[session->vip_index];
    te_http_url_metrics_t *http_url_metric;
    te_error_metrics_t** error_metric;
    if(req->req_type == TE_SESSION_REQ_GET) {
        http_url_metric = &(vip_metric->url_get_metrics[req->url_index]);
    }
    else if(req->req_type == TE_SESSION_REQ_POST) {
        http_url_metric = &(vip_metric->url_get_metrics[req->url_index]);
    }
    else {
        eprint("Got Unexpected Request type in te_header_function_cb: %d", req->req_type);
        abort();
    }
    error_metric = http_url_metric->error_metrics;
    char *header = NULL;
    if (session->session_cfg_p->persist_flag) {
        header = strstr( buffer, "tens_srv_ip:" );
        if (!header) {
            return (nitems*size);
        }
        if (!session->tcp->pdata_exists) {
            strncpy(session->tcp->persist_str, header, strlen(header));
            session->tcp->pdata_exists = 1;
            tprint("%d,%lu, CYCLE_1ST_RESPONSE: persist_str_update len:%d, str:%s",
                session->id, session->cycle_iter+1,
                (int)strlen(session->tcp->persist_str), session->tcp->persist_str);
        } else {
            if (memcmp(session->tcp->persist_str, header, strlen(header)) != 0) {
                if (metrics_enabled) {
                    ses_metric->persist_fail++;
                    //Setting stats present to true, that way stats gets dumped
                    http_url_metric->stats_present = true;
                    vip_metric->stats_present = true;
                    http_url_metric->url_stats.persist_fail++;
                    error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                        PERSIST_CHECK_FAIL, "PERSIST_CHECK_FAIL", http_url_metric);
                }
                dump_error_request(req, PERSIST_CHECK_FAIL, header, NULL);
            }
        }
    }
    return (nitems*size);
}

static curl_socket_t te_open_socket_in_ns(void *user_p, curlsocktype purpose, \
    struct curl_sockaddr *address) {

    te_interface_t* interface_obj = (te_interface_t*) user_p;

    // To switch to the desired namespace, open a fd to describe the ns
    int fd = open(interface_obj->ns_descriptor, O_RDONLY);
    if (fd < 0 ) {
        // If unable to open, return curl error code: CURL_SOCKET_BAD
        // This would further signal, an unrecoverable error to libcurl
        // which would in turn raise CURLE_COULDNT_CONNECT
        // refer to: https://curl.haxx.se/libcurl/c/CURLOPT_OPENSOCKETFUNCTION.html
        eprint("Error Getting Net_NS FD for NS: %s\n", interface_obj->nw_namespace);
        return CURL_SOCKET_BAD;
    }

    // Set the namespace to the desired
    if(setns(fd, 0) < 0) {
        // If unable to switch, return curl error code: CURL_SOCKET_BAD
        // This would further signal, an unrecoverable error to libcurl
        // which would in turn raise CURLE_COULDNT_CONNECT
        // refer to: https://curl.haxx.se/libcurl/c/CURLOPT_OPENSOCKETFUNCTION.html
        eprint("Unable to switch to NS: %s\n", interface_obj->nw_namespace);
        return CURL_SOCKET_BAD;
    }

    // Open a socket in that namespace
    curl_socket_t sockfd = socket(address->family, address->socktype, address->protocol);
    // Close the dummy fd, used for switching ns
    close(fd);

    // Put te_dp back to namespace of proc 1 (root namespace)
    fd = open("/proc/1/ns/net", O_RDONLY);
    if (fd < 0 ) {
        // The proc 1's namespace is always root and must exist. We got to examine the code otherwise
		eprint("Error Getting Net_NS FD for root NS and errno=%d\n", errno);
        abort();
    }
    if (setns(fd, 0) < 0) {
        eprint("Error Re-setting Root_NS after NS change to: %s and errno=%d\n", \
            interface_obj->nw_namespace, errno);
        // This situation of reverting back to namespace must not be a problem
        // If it happens we got to investigate further, so, abort as of now
        abort();
    }

    // Close the dummy fd, used for switching ns
    close(fd);
    return sockfd;
}

//**********************************************//
//          REQUEST LEVEL PARAM SETTERS         //
//**********************************************//
void te_set_curl_opts(CURL *handle, te_session_config_t *session_cfg_p, te_session_t *session,
    te_tcp_request_t * request, char* url) {

    CURLcode CEcode;

    //TCP Timeout
    //Setting this value to be lesser that the default timeout value of the server is important
    //If unused then the polling sockfd is stopped as soon as the request is complete
    //But if curl chose to not close the conn, then the FIN from the server is left unread
    //Resulting in CLOSE_WAIT sockets
    if(res_cfg->tcp_keepalive_timeout) {
        CEcode = curl_easy_setopt(handle, CURLOPT_TCP_KEEPALIVE, 1L);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_TCP_KEEPALIVE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

        CEcode = curl_easy_setopt(handle, CURLOPT_TCP_KEEPINTVL, res_cfg->tcp_keepalive_timeout);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_TCP_KEEPINTVL, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

        CEcode = curl_easy_setopt(handle, CURLOPT_TCP_KEEPIDLE, res_cfg->tcp_keepalive_timeout);
        if(unlikely(CEcode != CURLE_OK))
           eprint("CURLOPT_TCP_KEEPIDLE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }
    // TCP CONNECT TIMEOUT
    if (res_cfg->tcp_connect_timeout) {
        CEcode = curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, res_cfg->tcp_connect_timeout);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_CONNECTTIMEOUT_MS, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    //SET URL
    CEcode = curl_easy_setopt(handle, CURLOPT_URL, url);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_URL, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    //Points to cipher list
    CEcode = curl_easy_setopt(handle, CURLOPT_SSL_CIPHER_LIST, res_cfg->ssl_details.cipher_list);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_SSL_CIPHER_LIST, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    //write_callback - Just returns the size of response
    CEcode = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, te_request_write_cb);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_WRITEFUNCTION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    //Set SSL Version
    switch(res_cfg->ssl_details.version)
    {
        case SSL_V1:
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
            break;
        case TLS_V1_0:
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
            break;
        case TLS_V1_1:
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_1);
            break;
        case TLS_V1_2:
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
            break;
        case TLS_V1_3:
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
            break;
        default:
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);
    }
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_SSLVERSION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    //Set HTTP Version
    switch(res_cfg->http_version)
    {
        case HTTP_1_0:
            CEcode = curl_easy_setopt(handle, CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_1_0);
            break;
        case HTTP_1_1:
            CEcode = curl_easy_setopt(handle, CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_1_1);
            break;
        case HTTP_2_0:
            CEcode = curl_easy_setopt(handle, CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_2_0);
            break;
        case HTTP_2_0_TLS:
            CEcode = curl_easy_setopt(handle, CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_2TLS);
            break;
        case HTTP_2_0_PK:
            CEcode = curl_easy_setopt(handle, CURLOPT_HTTP_VERSION , \
                CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        break;
        default:
            CEcode = curl_easy_setopt(handle, CURLOPT_HTTP_VERSION , CURL_HTTP_VERSION_1_1);
    }
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_HTTP_VERSION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    //To send TCP Resets (Promotes faster closing of connections - Not recommended for HTTP 1.1)
    if (res_cfg->send_tcp_resets) {
        CEcode = curl_easy_setopt(handle, CURLOPT_SOCKOPTFUNCTION, send_tcp_resets);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_SOCKOPTFUNCTION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    //Call Back to Close the socket connection
    CEcode = curl_easy_setopt(handle, CURLOPT_CLOSESOCKETFUNCTION, te_socket_close);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_CLOSESOCKETFUNCTION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    // Set opt to send the outgoing connection
    // When a session comes up, it choses an interface in a round robin fashion and uses it,
    // till the end of the session
    if(session->tcp->interface_obj != NULL) {
        if(session->tcp->interface_obj->nw_interface != NULL)  {
            CEcode = curl_easy_setopt(handle, CURLOPT_INTERFACE, \
                session->tcp->interface_obj->nw_interface);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_INTERFACE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }
        if(session->tcp->interface_obj->nw_namespace != NULL)  {
            CEcode = curl_easy_setopt(handle, CURLOPT_OPENSOCKETDATA, session->tcp->interface_obj);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_OPENSOCKETDATA, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

            CEcode = curl_easy_setopt(handle, CURLOPT_OPENSOCKETFUNCTION, te_open_socket_in_ns);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_OPENSOCKETFUNCTION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }
    }

    //Setting CA Cert path to /dev/null to solve issues
    CEcode = curl_easy_setopt(handle, CURLOPT_CAPATH, "/dev/null");
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_CAPATH, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    CEcode = curl_easy_setopt(handle, CURLOPT_CAINFO, "/dev/null");
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_CAINFO, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    CEcode = curl_easy_setopt(handle, CURLOPT_PIPEWAIT, 1L);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_PIPEWAIT, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    CEcode = curl_easy_setopt(handle, CURLOPT_PRIVATE, request);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_PRIVATE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    CEcode = curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, te_header_function_cb);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_HEADERFUNCTION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    CEcode = curl_easy_setopt(handle, CURLOPT_HEADERDATA, request);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_HEADERDATA, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    //SSL Opts
    //* Using SSL Version 1.1.1
    //* A lot has changed from the previous openSSL Version
    //* Please refer https://curl.haxx.se/mail/lib-2019-03/0099.html
    //* Make sure all the addition w.r.t to ssl callback is related to OPENSSLv1.1.1
    CEcode = curl_easy_setopt(handle, CURLOPT_SSL_CTX_DATA, &(res_cfg->ssl_details));
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_SSL_CTX_DATA, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    CEcode = curl_easy_setopt(handle, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_SSL_CTX_FUNCTION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    if (res_cfg->vips[session->vip_index].num_certs) {

        // Select a random cert from the available list
        int cert_idx = te_random(0, res_cfg->vips[session->vip_index].num_certs);
        if (res_cfg->vips[session->vip_index].certs[cert_idx].cert_type) {
            //Default Cert Type is PEM
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLCERTTYPE, \
                res_cfg->vips[session->vip_index].certs[cert_idx].cert_type);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_SSLCERTTYPE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }
        else {
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLCERTTYPE, "PEM");
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_SSLCERTTYPE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }

        //Set the client's SSL cert file
        if (res_cfg->vips[session->vip_index].certs[cert_idx].client_cert_path) {
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLCERT, \
                res_cfg->vips[session->vip_index].certs[cert_idx].client_cert_path);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_SSLCERT, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }
        //set the private key for client auth
        if (res_cfg->vips[session->vip_index].certs[cert_idx].client_pvt_key) {
            CEcode = curl_easy_setopt(handle, CURLOPT_SSLKEY, \
                res_cfg->vips[session->vip_index].certs[cert_idx].client_pvt_key);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_SSLKEY, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }
        //set the passphrase for client pvt key
        if (res_cfg->vips[session->vip_index].certs[cert_idx].client_pass) {
            CEcode = curl_easy_setopt(handle, CURLOPT_KEYPASSWD, \
                res_cfg->vips[session->vip_index].certs[cert_idx].client_pass);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_KEYPASSWD, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }

        //Set the ca's SSL cert file and if present,
        //a check for server cert's authenticity is to be done
        if (res_cfg->vips[session->vip_index].certs[cert_idx].ca_cert_path) {
            CEcode = curl_easy_setopt(handle, CURLOPT_CAINFO, \
                res_cfg->vips[session->vip_index].certs[cert_idx].ca_cert_path);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_CAINFO, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

            CEcode = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_SSL_VERIFYPEER, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

            //Must client verify server's CN (Common Name) in the cert ?
            //2L and 1L are supposed to do the same (till version 7.28.0 1L was throwing error)
            if (res_cfg->vips[session->vip_index].certs[cert_idx].cname_verify) {
                CEcode = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
                if(unlikely(CEcode != CURLE_OK))
                    eprint("CURLOPT_SSL_VERIFYHOST, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
            }
            else {
                CEcode = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
                if(unlikely(CEcode != CURLE_OK))
                    eprint("CURLOPT_SSL_VERIFYHOST, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
            }
        }
        else {
            CEcode = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_SSL_VERIFYHOST, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
            CEcode = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_SSL_VERIFYPEER, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }
    }
    else {
        CEcode = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_SSL_VERIFYPEER, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        CEcode = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_SSL_VERIFYHOST, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    CEcode = curl_easy_setopt(handle, CURLOPT_SHARE, session->tcp->share_handle);
    if(unlikely(CEcode != CURLE_OK))
        eprint("CURLOPT_SHARE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    //SSL Session reuse, by caching SSL session ID
    if(res_cfg->ssl_details.session_reuse) {
        CEcode = curl_easy_setopt(handle, CURLOPT_SSL_SESSIONID_CACHE, 1);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_SSL_SESSIONID_CACHE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }
    else {
        CEcode = curl_easy_setopt(handle, CURLOPT_SSL_SESSIONID_CACHE, 0);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_SSL_SESSIONID_CACHE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    if(res_cfg->set_cookies) {
        CEcode = curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_COOKIEFILE, %d, %s\n", (int)CEcode, curl_easy_strerror(CEcode));
    }

    if (res_cfg->is_verbose) {
        CEcode = curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_VERBOSE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }
}


char* te_add_custom_url_qparams(te_tcp_request_t* request, te_request_object_t req_obj,\
    te_session_t* session, CURL* handle)
{
    int buffer_offset=0; //Length of the query_params added
    int i=0;
    int url_size = strlen(res_cfg->vips[session->vip_index].vip)+1;
    char* url = NULL;
    CURLcode CEcode;

    //MALLOC FOR URL
    if(req_obj.request_uri.has_uri)
        url_size += strlen(req_obj.request_uri.uri)+1;
    if (req_obj.has_query_params)
        url_size += req_obj.len_qparams;
    ++url_size; //To account for the null character
    url_size = url_size + 2;
    te_malloc(url, url_size, TE_MTYPE_CHAR);
    if(unlikely(!url)) {
        wprint("Out of memory whiel allocating url\n");
        return NULL;
    }
    memset(url,0,url_size);

    //BUILD URL
    if (req_obj.request_uri.has_uri) {
        buffer_offset += snprintf(url+buffer_offset, \
                        (strlen(res_cfg->vips[session->vip_index].vip) + 1 +
                        strlen(req_obj.request_uri.uri) + 1 ), "%s/%s",
                        res_cfg->vips[session->vip_index].vip,
                        req_obj.request_uri.uri);
    }
    else {
        buffer_offset += snprintf(url+buffer_offset, \
                        strlen(res_cfg->vips[session->vip_index].vip) +1 , "%s",
                        res_cfg->vips[session->vip_index].vip);
    }

    //BUILD QUERY PARAMS
    if (req_obj.has_query_params) {
        if(req_obj.num_qparams > 0)
            buffer_offset += snprintf(url+buffer_offset, 2, "?");
        for (i=0; i<req_obj.num_qparams; i++) {
            buffer_offset  += snprintf(url+buffer_offset, req_obj.len_qparams + 1,
                "&%s",req_obj.query_params[i]);
        }
    }

    if (req_obj.has_headers)
    {
        for(i=0; i<req_obj.num_headers; i++) {
            request->headerlist = curl_slist_append(request->headerlist,req_obj.headers[i]);
        }
        CEcode = curl_easy_setopt(handle, CURLOPT_HTTPHEADER, request->headerlist);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_HTTPHEADER, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

    }

    if (req_obj.has_cookies) {
        CEcode = curl_easy_setopt(handle, CURLOPT_COOKIE, req_obj.cookies);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_COOKIE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    //Redirect Options
    if (req_obj.max_redirects) {
        CEcode = curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_FOLLOWLOCATION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

        CEcode = curl_easy_setopt(handle, CURLOPT_MAXREDIRS, req_obj.max_redirects);
        if(CEcode != CURLE_OK)
            eprint("CURLOPT_MAXREDIRS, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }
    else {
        CEcode = curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_FOLLOWLOCATION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    return url;
}

char* add_get_request(te_tcp_request_t* request, te_session_t* session, CURL* handle,\
    te_request_object_t req_obj)
{
    CURLcode CEcode;
    request->req_type = TE_SESSION_REQ_GET;
    char* url = te_add_custom_url_qparams(request, req_obj, session, handle);

    if(req_obj.rate) {
        CEcode = curl_easy_setopt(handle, CURLOPT_MAX_RECV_SPEED_LARGE, (curl_off_t)req_obj.rate);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_MAX_RECV_SPEED_LARGE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    //Redirect Options
    if (req_obj.max_redirects) {
        CEcode = curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);
        if(CEcode != CURLE_OK)
            eprint("CURLOPT_FOLLOWLOCATION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));

        CEcode = curl_easy_setopt(handle, CURLOPT_MAXREDIRS, req_obj.max_redirects);
        if(CEcode != CURLE_OK)
            eprint("CURLOPT_MAXREDIRS, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }
    else {
        CEcode = curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0);
        if(CEcode != CURLE_OK)
            eprint("CURLOPT_FOLLOWLOCATION, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    return url;
}

char* add_post_request(te_tcp_request_t* request, te_session_t* session, CURL* handle,
    te_request_object_t req_obj, te_http_url_metrics_t* http_url_metric)
{
    request->req_type = TE_SESSION_REQ_POST;
    request->formpost=NULL;
    request->lastptr=NULL;
    CURLcode CEcode;
    te_error_metrics_t** error_metric = http_url_metric->error_metrics;

    char* url = te_add_custom_url_qparams(request, req_obj, session, handle);

    if (req_obj.has_postfile) {
        if( access(req_obj.postfile, F_OK) == -1) {
            if (metrics_enabled) {
                session->session_cfg_p->http_metrics.post_fnf++;
                error_metric[HTTP_ERROR] = insert_or_update_error(error_metric[HTTP_ERROR], \
                    POST_FILE_NOT_FOUND, "POST_FILE_NOT_FOUND", http_url_metric);
            }
            dump_error_request(request, POST_FILE_NOT_FOUND, NULL, req_obj.postfile);
        }
        else{
            // Fill in the file upload field
            curl_formadd(&request->formpost,
                &request->lastptr,
                CURLFORM_COPYNAME, "sendfile",
                CURLFORM_FILE, req_obj.postfile,
                CURLFORM_END);

            // Fill in the filename field
            curl_formadd(&request->formpost,
                &request->lastptr,
                CURLFORM_COPYNAME, "filename",
                CURLFORM_COPYCONTENTS, req_obj.postfile,
                CURLFORM_END);

            // Fill in the submit field too, even if this is rarely needed
            curl_formadd(&request->formpost,
                &request->lastptr,
                CURLFORM_COPYNAME, "submit",
                CURLFORM_COPYCONTENTS, "send",
                CURLFORM_END);

            // initialize custom header list (stating that Expect: 100-continue is not wanted
            CEcode = curl_easy_setopt(handle, CURLOPT_HTTPPOST, request->formpost);
            if(unlikely(CEcode != CURLE_OK))
                eprint("CURLOPT_HTTPPOST, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
        }
    }
    else if (req_obj.has_postdata)
    {
        tprint("HAS POST DATA and data:%s\n", req_obj.postdata);
        CEcode = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req_obj.postdata);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_HTTPPOST, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    if(req_obj.rate) {
        CEcode = curl_easy_setopt(handle, CURLOPT_MAX_SEND_SPEED_LARGE, (curl_off_t)req_obj.rate);
        if(unlikely(CEcode != CURLE_OK))
            eprint("CURLOPT_MAX_SEND_SPEED_LARGE, %d, %s\n",(int)CEcode, curl_easy_strerror(CEcode));
    }

    return url;
}

//**********************************************//
//         REQUEST ADDITION AND DELETION        //
//**********************************************//
te_tcp_request_t* create_tcp_request()
{
    te_tcp_request_t *request;
    te_malloc(request, sizeof(te_tcp_request_t), TE_MTYPE_TCP_REQUEST);
    memset(request, 0, sizeof(te_tcp_request_t));
    return request;
}

void add_tcp_request(te_session_t* session)
{
    CURL *handle;
    CURLMcode rc;
    int code;

    int req_idx = 0;
    char* url;

    te_session_config_t* session_cfg = session->session_cfg_p;
    int vip_hash = session->vip_index;
    te_http_vip_metrics_t* vip_metric = &res_cfg->http_vip_metrics[vip_hash];
    te_http_url_metrics_t* http_url_metric = NULL;
    int get_profile_index = res_cfg->vips[vip_hash].get_profile_index;
    int post_profile_index = res_cfg->vips[vip_hash].post_profile_index;

    //INIT HANDLE FOR CURL
    handle = curl_easy_init();
    if (unlikely(!handle)) {
        wprint("Handle Alloc Failed!\n");
        abort();
    }

    //INIT REQUEST TO ADD TO THE HANDLE AND MAKE IT A GET/POST, BY
    //SETTING APPROPRIATE VALUES IN `te_tcp_request_t* request`
    te_tcp_request_t* request = create_tcp_request();
    if (unlikely(!request)) {
        wprint("Unable to allocate memory for request.\n");
        abort();
    }

    request->id = session->tcp->reqs_sent;
    session->tcp->reqs_sent++;
    request->sessionp = session;
    request->ce_handle = handle;
    request->headerlist=NULL;

    if(get_profile_index==-1 || res_cfg->num_get_reqs_in_profile[get_profile_index] == 0)
        session->tcp->is_get = false;

    if(session->tcp->is_get && session->tcp->pending_gets != 0)
    {
        --session->tcp->pending_gets;
        req_idx = (session->tcp->pending_gets)%res_cfg->num_get_reqs_in_profile[get_profile_index];

        //ADD REQUEST
        url = add_get_request(request, session, handle, res_cfg->greqs[get_profile_index][req_idx]);
        request->prof_index = get_profile_index;

        if(session->tcp->pending_posts != 0)
            session->tcp->is_get = false;

        if(metrics_enabled) {
            //COUNT THE REQS SENT
            session->session_cfg_p->http_metrics.http_gets_sent++;

            //URL Metrics
            http_url_metric = &(vip_metric->url_get_metrics[req_idx]);
            http_url_metric->url_stats.reqs_sent++;
            http_url_metric->url_stats.http_gets_sent++;
            //Setting stats_present to true, that way stats gets dumped
            http_url_metric->stats_present = true;
            vip_metric->stats_present = true;
        }
    }
    else if(post_profile_index != -1 && res_cfg->num_post_reqs_in_profile[post_profile_index]!= 0 \
        && session->tcp->pending_posts != 0)
    {
        if(metrics_enabled) {
            http_url_metric = &(vip_metric->url_post_metrics[req_idx]);
        }

        --session->tcp->pending_posts;
        req_idx = (session->tcp->pending_posts)%res_cfg->num_post_reqs_in_profile[post_profile_index];

        //ADD REQUEST
        url = add_post_request(request, session, handle, \
            (res_cfg->preqs)[post_profile_index][req_idx], http_url_metric);
        request->prof_index = post_profile_index;

        if(session->tcp->pending_gets != 0)
            session->tcp->is_get = true;

        if(metrics_enabled) {
            //COUNT THE REQS SENT
            session->session_cfg_p->http_metrics.http_posts_sent++;

            //URL Metrics
            http_url_metric->url_stats.reqs_sent++;
            http_url_metric->url_stats.http_posts_sent++;
            //Setting stats_present to true, that way stats gets dumped
            http_url_metric->stats_present = true;
            vip_metric->stats_present = true;
        }
    }
    else {
        eprint("No Get or Post Request to add! is_get=%d pending_get=%d pending_post=%d vip=%s\n",
        (int)session->tcp->is_get, session->tcp->pending_gets, session->tcp->pending_posts, \
        res_cfg->vips[vip_hash].vip);
        abort();
    }

    request->url_index = req_idx;

    //Set Curl Opts
    te_set_curl_opts(handle, session_cfg, session, request, url);

    // Attach easy handle to multi handle
    rc = curl_multi_add_handle(session->tcp->cm_handle, handle);
    code = (int)rc;
    if (code != 0 && code <= 8 && code >= -1)
        code += 95;
    if (rc != CURLM_OK) {
        wprint("failed to add to multi handle , rc = %d and %s\n", rc, curl_easy_strerror(rc));
    }

    if(metrics_enabled) {
        session->session_cfg_p->http_metrics.reqs_sent++;
    }
    te_free(url, TE_MTYPE_CHAR);
    url = NULL;
    return;
}

void delete_tcp_request(te_tcp_request_t* request)
{
    if (request) {
        CURL *ce_handle = request->ce_handle;
        CURLM *cm_handle = request->sessionp->tcp->cm_handle;
        curl_multi_remove_handle(cm_handle, ce_handle);
        curl_easy_cleanup(ce_handle);
        request->ce_handle = NULL;
        //request->sessionp->requests[request->id] = NULL;

        if (request->req_type == TE_SESSION_REQ_POST) {
           /* then cleanup the formpost chain */
           curl_formfree(request->formpost);
        }
        if (request->headerlist) {
           curl_slist_free_all(request->headerlist);
           request->headerlist = NULL;
        }
        te_free(request, TE_MTYPE_TCP_REQUEST);
        request = NULL;
    }
}
