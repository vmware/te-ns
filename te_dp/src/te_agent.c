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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <uv.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <netinet/in.h>
#include <json-c/json.h>
#include <sys/msg.h>

#ifndef TE_AGENT_H
#include "te_agent.h"
#endif

struct timeval tv;
struct tm * timeinfo;
uv_loop_t *loop;

// The IPC_QUEUE is used to dump the metrics
// It is named with the TE_DP process's pid as its fd
int IPC_QUEUE_ID;

TE_DEBUG_FLAG te_log_level = TE_LOG_DEFAULT_MODE;

void te_process_session_stat_buckets (json_object *jvalue, int vip_index,
                                      te_resource_config_t *res_cfg);
void te_process_url_stat_buckets (json_object* jvalue, te_http_url_metrics_t* url_metrics);

// Global Objects.
te_resource_config_t* res_cfg=NULL;
te_session_config_t *te_session_cfgs = NULL;
tedp_profile_t tedp_profile=TE_UNDEFINED;
tedp_mode_t tedp_mode=TE_UNDEFINED;
unsigned short pinned_cpu;

// To cycle through various states of session config
bool (*te_session_config_state_switcher[])(te_session_config_t*, TE_SESSION_CONFIG_STATE) = {
    te_session_config_start,
    te_session_config_stop_or_update,
    te_session_config_resume,
    te_session_config_pause,
    te_session_config_stop_or_update,
    te_session_config_stop_or_update
};

te_bst_node_t* new_node(const char* key, int value) {
    te_bst_node_t* node;
    te_malloc(node, sizeof(te_bst_node_t), TE_MTYPE_BST_NODE);
    node->key = key;
    node->value = value;
    node->left = NULL;
    node->right = NULL;
    return node;
}

te_bst_node_t* insert(te_bst_node_t* node, const char* key, int value) {
    if(node == NULL)
        return new_node(key, value);
    else if(strcmp(key, node->key) < 0)
        node->left = insert(node->left, key, value);
    else if(strcmp(key, node->key) > 0)
        node->right = insert(node->right, key, value);
    return node;
}

int find(te_bst_node_t* node, const char* key) {
    if(node == NULL)
        return -1;
    int str_cmp_val = strcmp(key, node->key);
    if(str_cmp_val < 0)
        return find(node->left, key);
    else if(str_cmp_val > 0)
        return find(node->right, key);
    else
        return node->value;
}

void te_update_ses_buckets ()
{
    int i, arraylen = 0;
    json_object *jobj, *jvalue, *jarray, *temp = NULL;
    json_object* root =  json_object_from_file(res_cfg_path);
    if (root == NULL) {
        wprint("error while updating session buckets: check res cfg file/syntax \n");
        return;
    }
    if (res_cfg) {
        if (json_object_object_get_ex(root, "resource-config",&jobj)) {
            json_object_object_foreach(jobj, key, val) {
                jvalue = val;
                if (strstr(key,"vip-list")) {
                    jarray = jvalue;
                    arraylen = json_object_array_length(jarray);
                    for (i=0; i< arraylen; i++) {
                        jvalue = json_object_array_get_idx(jarray, i);
                        if (json_object_object_get_ex(jvalue, "stat-buckets",&temp)) {
                            te_process_session_stat_buckets(temp, i, res_cfg);
                        }
                    }
                }
            }
        }
    }
}


//AK REVISIT
void te_update_url_buckets() {
    /*
    int i, vip_index, arraylen = 0;
    json_object *jobj, *jvalue, *jarray, *temp = NULL;
    json_object* root =  json_object_from_file(res_cfg_path);
    if (root == NULL) {
        wprint("error while updating url buckets: check res cfg file/syntax \n");
        return;
    }
    if (res_cfg) {
        if (json_object_object_get_ex(root, "resource-config",&jobj)) {
            json_object_object_foreach(jobj, key, val) {
                jvalue = val;
                if (strstr(key,"get-list")) {
                    jarray = jvalue;
                    arraylen = json_object_array_length(jarray);
                    for (i = 0 ; i < arraylen; ++i) {
                        jvalue = json_object_array_get_idx(jarray, i);                        
                        if(json_object_object_get_ex(jvalue, "stat-buckets", &temp)) {
                            for (vip_index = 0 ; vip_index < res_cfg->num_get_reqs; ++vip_index) {
                                te_process_url_stat_buckets(temp, \
                                    vip_index * res_cfg->num_get_reqs + i, res_cfg->url_get_metrics);
                            }
                        }
                    }
                }

                if (strstr(key,"post-list")) {
                    jarray = jvalue;
                    arraylen = json_object_array_length(jarray);
                    for (i = 0 ; i < arraylen; ++i) {
                        jvalue = json_object_array_get_idx(jarray, i);
                        if(json_object_object_get_ex(jvalue, "stat-buckets", &temp)) {
                            for (vip_index = 0 ; vip_index < res_cfg->num_post_reqs; ++vip_index) {
                                te_process_url_stat_buckets(temp, \
                                    vip_index * res_cfg->num_post_reqs + i, res_cfg->url_post_metrics);
                            }
                        }
                    }
                }
            }
        }
    }*/
}

void te_create_resources()
{
    if (res_cfg) {
        te_open_logger_files();
        if (tedp_profile == TCP) {
            if(curl_global_init(CURL_GLOBAL_ALL)) {
                wprint("Could not init curl.Exiting\n");
                goto cleanup_res;
            }
            te_create_socket_hashTbl(TE_SOCKET_HASH_TABLE_SIZE);
        } else if(tedp_profile == UDP) {
            if(tedp_mode == SERVER) {
                //Socket DS init for server of UDP
                te_create_server_metrics_hash_table(TE_UDP_SERVER_METRICS_HASH_TABLE_SIZE);
                te_create_socket_hashTbl(TE_SOCKET_HASH_TABLE_SIZE);
            }
        } else {
            eprint("Unknown tedp profile (neither TCP nor UDP). aborting \n");
            abort();
        }
    }
    return;

    cleanup_res:
        te_free(res_cfg, TE_MTYPE_RESOURCE_CONFIG);
        res_cfg = NULL;
        return;
}

void te_cleanup_resources()
{
    if (res_cfg) {
        curl_global_cleanup();
        //Incase if res_cfg is getting updated. init calls after complete flush.
        te_delete_socket_hashTbl();
    }
}

void te_create_session_config(te_session_config_t *session_cfg)
{
    tprint("%s pending_sessions:%d\n",__FUNCTION__, session_cfg->pending_sessions);
    tprint("%s ses_cfg %p \n", __FUNCTION__, session_cfg);

    //When we get a command to process at a config level (say pause / resume) UNUSED ?
    uv_async_init(loop, &session_cfg->session_signal_handler, session_config_uv_async);

    //To ramp up the sessions
    uv_timer_init(loop, &session_cfg->ramp_timer);

    session_cfg->ramp_timer.data = session_cfg;
    session_cfg->pending_uv_deletes++;

    session_cfg->session_signal_handler.data = session_cfg;
    uv_async_send(&session_cfg->session_signal_handler);
    session_cfg->pending_uv_deletes++;
}

te_http_vip_metrics_t *te_allocate_vip_metrics (int num_vip_metrics)
{
    int metric_size;
    te_http_vip_metrics_t *vip_metrics;
    metric_size = sizeof(te_http_vip_metrics_t) * num_vip_metrics;
    if (metric_size == 0) {
        printf("vip metric size zero, config failure");
        abort();
    }
    te_malloc(vip_metrics, metric_size, TE_MTYPE_VIP_METRICS);
    memset(vip_metrics, 0, metric_size);
    return(vip_metrics);
}

te_udp_vip_metrics_t *te_allocate_udp_vip_metrics (int num_vip_metrics)
{
    int metric_size;
    te_udp_vip_metrics_t *vip_metrics;
    metric_size = sizeof(te_udp_vip_metrics_t) * num_vip_metrics;
    if (metric_size == 0) {
        printf("vip metric size zero, config failure");
        abort();
    }
    te_malloc(vip_metrics, metric_size, TE_MTYPE_UDP_VIP_METRICS);
    memset(vip_metrics, 0, metric_size);

    for (int i=0; i<num_vip_metrics; ++i) {
        te_malloc(vip_metrics[i].udp_download_metrics, sizeof(te_udp_url_metrics_t), \
            TE_MTYPE_UDP_URL_METRICS);
        memset(vip_metrics[i].udp_download_metrics, 0, sizeof(te_udp_url_metrics_t));
        vip_metrics[i].udp_download_metrics->min_latency = DBL_MAX;
        vip_metrics[i].udp_download_metrics->max_latency = 0;

        te_malloc(vip_metrics[i].udp_upload_metrics, sizeof(te_udp_url_metrics_t), \
            TE_MTYPE_UDP_URL_METRICS);
        memset(vip_metrics[i].udp_upload_metrics, 0, sizeof(te_udp_url_metrics_t));
        vip_metrics[i].udp_upload_metrics->min_latency = DBL_MAX;
        vip_metrics[i].udp_upload_metrics->max_latency = 0;
    }
    return(vip_metrics);
}

void te_process_url_stat_buckets(json_object* temp, te_http_url_metrics_t *url_metrics)
{
    unsigned int length,i,  metric_size;
    json_object* temp2;

    /* delete get url bucket */
    if (url_metrics->url_buckets) {
       te_free(url_metrics->url_buckets, TE_MTYPE_URL_BUCKET_METRICS);
       url_metrics->url_buckets = NULL;
       url_metrics->num_url_buckets = 0;
    }

    if (temp == NULL) {
        return;
    }

    length = json_object_array_length(temp);
    url_metrics->num_url_buckets = length;
    if (length == 0) {
        return;
    }
    metric_size = sizeof(te_http_url_bucket_metrics_t) * \
                    url_metrics->num_url_buckets;
    te_malloc(url_metrics->url_buckets, metric_size, TE_MTYPE_URL_BUCKET_METRICS);
    memset(url_metrics->url_buckets, 0, metric_size);
    for (i = 0; i < length; i++) {
        temp2 = json_object_array_get_idx(temp,i);
        json_object_object_foreach(temp2, key, val) {
            if (strstr(key, "start_time")) {
                url_metrics->url_buckets[i].bucket_start_time = json_object_get_int(val);
            }
            if (strstr(key, "end_time")) {
                url_metrics->url_buckets[i].bucket_end_time = json_object_get_int(val);
            }
        }
    }
}

void te_add_requests(te_request_object_t** request_list, te_http_url_metrics_t** url_metrics_profile, \
    int profile_idx, int num_requests, json_object* jrequests) {

    const char *jstr;
    te_request_object_t* request;
    json_object *jvalue = NULL, *cookie_json=NULL, *jtmp = NULL, *jr;
    te_malloc(request_list[profile_idx], num_requests * sizeof(te_request_object_t), \
        TE_MTYPE_REQUEST_OBJECT);
    memset(request_list[profile_idx], 0, num_requests * sizeof(te_request_object_t));

    te_malloc(url_metrics_profile[profile_idx], num_requests * sizeof(te_http_url_metrics_t), \
        TE_MTYPE_URL_METRICS);
    memset(url_metrics_profile[profile_idx], 0, num_requests * sizeof(te_http_url_metrics_t));

    for (int i = 0; i < num_requests; ++i) {
        jr = json_object_array_get_idx(jrequests, i);
        bool is_cookie_present = false;
        request = &(request_list[profile_idx][i]);

        request->num_headers = 0;
        if (json_object_object_get_ex(jr, "headers", &jtmp)) {
            json_object_object_foreach(jtmp, key, val) {
                if (!strcmp(key, "Cookie"))
                    is_cookie_present = true;
                else
                    ++request->num_headers;
            }
        }

        request->len_qparams = 0;
        request->num_qparams = 0;
        if (json_object_object_get_ex(jr, "query-params", &jtmp)) {
            json_object_object_foreach(jtmp, key, val) {
                jstr = key; //UNUSED
                ++request->num_qparams;
            }
        }

        json_object_object_foreach(jr, key, val) {
            jvalue = val;
            if (strstr(key, "uri")) {
                jstr = json_object_get_string(jvalue);
                int size = strlen(jstr) + 1;
                request->request_uri.has_uri = true;
                te_malloc(request->request_uri.uri, sizeof(char) * size, TE_MTYPE_AGENT_CHAR);
                memset(request->request_uri.uri, 0, size);
                strcpy(request->request_uri.uri, jstr);
            }

            if(strstr(key, "rate")) {
                request->rate = json_object_get_int(jvalue);
            }

            if(strstr(key, "max-redirects")) {
                request->max_redirects = json_object_get_int(jvalue);
            }

            if (strstr(key, "size"))
                request->request_uri.size = json_object_get_int(jvalue);

            if (strstr(key, "weight"))
                 request->request_uri.weight = json_object_get_int(jvalue);

            if (strstr(key,"stat-buckets")) {
                jtmp = jvalue;
                te_process_url_stat_buckets(jtmp, url_metrics_profile[profile_idx]);
            }

            //POST FILE / DATA
            if (strstr(key,"file")) {
                jstr = json_object_get_string(jvalue);
                if (jstr) {
                    request->has_postfile = true;
                    int size = strlen(jstr) + 1;
                    te_malloc(request->postfile, size, TE_MTYPE_AGENT_CHAR);
                    memset(request->postfile,0,size);
                    strcpy(request->postfile, jstr);
                }
            }
            if (strstr(key,"data")) {
                jstr = json_object_get_string(jvalue);
                if (jstr) {
                    request->has_postdata = true;
                    int size = strlen(jstr) + 1;
                    te_malloc(request->postdata, size, TE_MTYPE_AGENT_CHAR);
                    memset(request->postdata,0,size);
                    strcpy(request->postdata, jstr);
                }
            }

            if (!strcmp(key,"query-params")) {
                const char * pstr;
                int i = 0 ;
                request->has_query_params = true;
                request->len_qparams = 1; //for the starting ? symbol
                te_malloc(request->query_params, sizeof(char *) * request->num_qparams, \
                    TE_MTYPE_AGENT_DOUBLE_POINTER);
                memset(request->query_params,0,sizeof(char *) * request->num_qparams);
                json_object_object_foreach(jvalue,jkey,jval) {
                    pstr = json_object_get_string(jval);
                    int size = strlen(pstr) + strlen(jkey) + 2;
                    request->len_qparams += (strlen(pstr) + strlen(jkey) + 2);
                                        // to account for the '=' and '&' characters
                    te_malloc(request->query_params[i], size+2, TE_MTYPE_AGENT_CHAR);
                    memset(request->query_params[i],0,size+2);
                    strcat(request->query_params[i],jkey);
                    strcat(request->query_params[i],"=");
                    strcat(request->query_params[i],pstr);
                    ++i;
                }
            }

            if (!strcmp(key,"headers")) {
                const char * hstr;
                int i = 0 ;
                request->has_headers = true;
                te_malloc(request->headers, sizeof(char *) *request->num_headers, \
                    TE_MTYPE_AGENT_DOUBLE_POINTER);
                memset(request->headers,0,sizeof(char *) * request->num_headers);
                json_object_object_foreach(jvalue,jkey,jval) {

                    if(!strcmp(jkey, "Cookie"))
                        cookie_json = jval;

                    else {
                        hstr = json_object_get_string(jval);
                        int size = strlen(hstr) + strlen(jkey) + 2;
                        te_malloc(request->headers[i], size+2, TE_MTYPE_AGENT_CHAR);
                        memset(request->headers[i],0,size+2);
                        strcat(request->headers[i],jkey);
                        strcat(request->headers[i],":");
                        strcat(request->headers[i],hstr);
                        ++i;
                    }
                }
            }

            if (is_cookie_present) {
                const char * cstr;
                request->has_cookies = true;
                int clen = 0; //total len of the cookie in cookie notation
                int type = json_object_get_type(cookie_json);

                switch(type)
                {
                    case json_type_string:
                    {
                        cstr = json_object_get_string(cookie_json);
                        clen = strlen(cstr);
                        te_malloc(request->cookies, clen+1, TE_MTYPE_AGENT_CHAR);
                        memset(request->cookies, 0, clen+1);
                        strcat(request->cookies, cstr);
                    } break;

                    case json_type_object:
                    {
                        json_object_object_foreach(cookie_json,jkey1,jval1) {
                            cstr = json_object_get_string(jval1);
                            clen += (strlen(cstr) + strlen(jkey1) + 2);
                        }
                        clen ++; //To account for the terminal null character
                        te_malloc(request->cookies, clen+2, TE_MTYPE_AGENT_CHAR);
                        memset(request->cookies, 0, clen+2);
                        json_object_object_foreach(cookie_json,jkey2,jval2) {
                            cstr = json_object_get_string(jval2);
                            strcat(request->cookies,jkey2);
                            strcat(request->cookies,"=");
                            strcat(request->cookies,cstr);
                            strcat(request->cookies,";");
                        }
                    } break;
                }
            }
        }
    }
}

void te_add_request_to_udp_profile(json_object** l1, te_udp_datagram_t* obj, bool is_response,
        int default_timeout) {

    json_object *l2=NULL, *l3=NULL, *l4=NULL;
    if(is_response)
        json_object_object_get_ex(*l1, "response", &l2);
    else
        json_object_object_get_ex(*l1, "request", &l2);

    if(!l2 && is_response) {
        //Client need not await for response
        obj->min_datagram = obj->max_datagram = 0;
        obj->min_datagram_size = obj->max_datagram_size = 0;
    } else if(!l2) {
        //But client will have to send request
        eprint("INVALID INPUT: No request parameter is mentioned in the profile!\n");
        abort();
    }

    //num datagrams range to send / recv
    json_object_object_get_ex(l2, "num-datagram-range", &l3);
    if(!l3 && is_response) {
        //Client need not await for response
        obj->min_datagram = obj->max_datagram = 0;
        obj->min_datagram_size = obj->max_datagram_size = 0;
        //If no response is expected return - there is no point scanning for response size and timeout
        return;
    } else if(!l3) {
        //But client will have to send request
        eprint("INVALID INPUT: No num-datagram-range parameter is mentioned in the profile!\n");
        abort();
    } else {
        l4 = json_object_array_get_idx(l3, 0);
        obj->min_datagram = json_object_get_int(l4);
        l4 = json_object_array_get_idx(l3, 1);
        obj->max_datagram = json_object_get_int(l4);
        if(obj->max_datagram == 0) {
            obj->min_datagram = obj->max_datagram = 0;
            obj->min_datagram_size = obj->max_datagram_size = 0;
        }
    }

    //num datagram size range to send /receive
    json_object_object_get_ex(l2, "datagram-size-range", &l3);
    if(!l3 && is_response) {
        //Client need not await for response
        obj->min_datagram = obj->max_datagram = 0;
        obj->min_datagram_size = obj->max_datagram_size = 0;
    } else if(!l3) {
        //But client will have to send request
        eprint("INVALID INPUT: No datagram-size-range parameter is mentioned in the profile!\n");
        abort();
    } else {
        l4 = json_object_array_get_idx(l3, 0);
        obj->min_datagram_size = json_object_get_int(l4);
        l4 = json_object_array_get_idx(l3, 1);
        obj->max_datagram_size = json_object_get_int(l4);
        //When max expected size is 0, then it is as good as expecting nothing
        if(obj->max_datagram_size == 0) {
            obj->min_datagram = obj->max_datagram = 0;
            obj->min_datagram_size = obj->max_datagram_size = 0;
        }
    }

    if(is_response) {
        //10s default timeout (Part of response only)
        obj->timeout = default_timeout;
        json_object_object_get_ex(l2, "timeout", &l3);
        if(l3) {
            obj->timeout = json_object_get_int(l3);
        }
    }
}

void te_add_udp_requests(te_udp_request_object_t* request_list, int profile_idx, \
    json_object* jrequests, int default_timeout) {

    //Temp init
    te_udp_request_object_t* request;
    json_object *l1=NULL;

    request = &(request_list[profile_idx]);
    request->min_timeout = ULONG_MAX;

    json_object_object_get_ex(jrequests, "download", &l1);
    request = &(request_list[profile_idx]);
    if(l1) {
        te_malloc(request->download_req, sizeof(te_udp_datagram_t), TE_MTYPE_UDP_DATAGRAM_OBJECT);
        memset(request->download_req, 0, sizeof(te_udp_datagram_t));
        te_add_request_to_udp_profile(&l1, request->download_req, false, default_timeout);
        te_malloc(request->download_resp, sizeof(te_udp_datagram_t), TE_MTYPE_UDP_DATAGRAM_OBJECT);
        memset(request->download_resp, 0, sizeof(te_udp_datagram_t));
        te_add_request_to_udp_profile(&l1, request->download_resp, true, default_timeout);
        request->min_timeout = (request->download_resp->timeout < request->min_timeout) ?
            request->download_resp->timeout : request->min_timeout;
    } else {
        request->download_req = NULL;
        request->download_resp = NULL;
    }

    l1 = NULL;
    json_object_object_get_ex(jrequests, "upload", &l1);
    if(l1) {
        te_malloc(request->upload_req, sizeof(te_udp_datagram_t), TE_MTYPE_UDP_DATAGRAM_OBJECT);
        memset(request->upload_req, 0, sizeof(te_udp_datagram_t));
        te_add_request_to_udp_profile(&l1, request->upload_req, false, default_timeout);
        te_malloc(request->upload_resp, sizeof(te_udp_datagram_t), TE_MTYPE_UDP_DATAGRAM_OBJECT);
        memset(request->upload_resp, 0, sizeof(te_udp_datagram_t));
        te_add_request_to_udp_profile(&l1, request->upload_resp, true, default_timeout);
        request->min_timeout = (request->upload_resp->timeout < request->min_timeout) ?
            request->upload_resp->timeout : request->min_timeout;
    } else {
        request->upload_req = NULL;
        request->upload_resp = NULL;
    }

    // If there is no response that is expected of this profile, then there is no need to run a timer
    // So set it to 0
    if((request->download_resp && request->download_resp->max_datagram == 0) || \
        (request->upload_resp && request->upload_resp->max_datagram) == 0) {
            request->min_timeout = 0;
    }
    // If min_timeout is still max, then it means there was no explicit timeout specified by user
    // Default to 10s
    else if(request->min_timeout == ULONG_MAX) {
        request->min_timeout = res_cfg->udp_resp_default_timeout;
    }
}

void te_add_custom_certs(te_resource_config_t* res_cfg_temp, json_object* jcerts, int idx) {

    res_cfg_temp->vips[idx].num_certs = json_object_array_length(jcerts);
    te_malloc(res_cfg_temp->vips[idx].certs, sizeof(te_cert_t) * res_cfg_temp->vips[idx].num_certs, \
        TE_MTYPE_CERT);
    json_object *jvalue = NULL, *temp = NULL;
    int j;
    for (j = 0 ; j < res_cfg_temp->vips[idx].num_certs ; ++j) {
        jvalue = json_object_array_get_idx(jcerts,j);

        //Get the SSL Cert path for CA
        if (json_object_object_get_ex(jvalue, "ca-cert-path", &temp)){
            te_malloc(res_cfg_temp->vips[idx].certs[j].ca_cert_path, strlen(json_object_get_string(temp))+1,    TE_MTYPE_AGENT_CHAR);
            memset(res_cfg_temp->vips[idx].certs[j].ca_cert_path, 0, \
                strlen(json_object_get_string(temp))+1);
            strcpy(res_cfg_temp->vips[idx].certs[j].ca_cert_path, json_object_get_string(temp));
        }
        else
            res_cfg_temp->vips[idx].certs[j].ca_cert_path = NULL;

        //To verify host name or Common Name in Server Cert - Default : False
        if (json_object_object_get_ex(jvalue, "enable-cname-verification", &temp)) {
            res_cfg_temp->vips[idx].certs[j].cname_verify = json_object_get_boolean(temp);
        }
        else
            res_cfg_temp->vips[idx].certs[j].cname_verify = false;

        //Get the SSL Cert path for client
        if (json_object_object_get_ex(jvalue, "cert-path", &temp)) {
            te_malloc(res_cfg_temp->vips[idx].certs[j].client_cert_path, 
                strlen(json_object_get_string(temp))+1, TE_MTYPE_AGENT_CHAR);
            memset(res_cfg_temp->vips[idx].certs[j].client_cert_path, 0, \
                strlen(json_object_get_string(temp))+1);
            strcpy(res_cfg_temp->vips[idx].certs[j].client_cert_path, json_object_get_string(temp));
        }
        else
            res_cfg_temp->vips[idx].certs[j].client_cert_path = NULL;

        //Get the private key of client cert
        if (json_object_object_get_ex(jvalue, "key-path", &temp)){
            te_malloc(res_cfg_temp->vips[idx].certs[j].client_pvt_key, 
                strlen(json_object_get_string(temp))+1, TE_MTYPE_AGENT_CHAR);
            memset(res_cfg_temp->vips[idx].certs[j].client_pvt_key, 0, \
                strlen(json_object_get_string(temp))+1);
            strcpy(res_cfg_temp->vips[idx].certs[j].client_pvt_key, json_object_get_string(temp));
        }
        else
            res_cfg_temp->vips[idx].certs[j].client_pvt_key = NULL;


        //Get the passphrase of client pvt key
        if (json_object_object_get_ex(jvalue, "passphrase", &temp)){
            te_malloc(res_cfg_temp->vips[idx].certs[j].client_pass, 
                strlen(json_object_get_string(temp))+1, TE_MTYPE_AGENT_CHAR);
            memset(res_cfg_temp->vips[idx].certs[j].client_pass, 0, \
                strlen(json_object_get_string(temp))+1);
            strcpy(res_cfg_temp->vips[idx].certs[j].client_pass, json_object_get_string(temp));
        }
        else
            res_cfg_temp->vips[idx].certs[j].client_pass = NULL;

        //Get the cert type here - default is PEM
        if (json_object_object_get_ex(jvalue, "type", &temp)){
            te_malloc(res_cfg_temp->vips[idx].certs[j].cert_type, 
                strlen(json_object_get_string(temp))+1, TE_MTYPE_AGENT_CHAR);
            memset(res_cfg_temp->vips[idx].certs[j].cert_type, 0, \
                strlen(json_object_get_string(temp))+1);
            strcpy(res_cfg_temp->vips[idx].certs[j].cert_type, json_object_get_string(temp));
        }
        else
            res_cfg_temp->vips[idx].certs[j].cert_type = "PEM";
    }
}

te_http_url_metrics_t* deep_copy(te_http_url_metrics_t* source, int length) {
    int i, j, num_buckets;
    te_http_url_metrics_t* destn;
    te_malloc(destn, sizeof(te_http_url_metrics_t) * length, TE_MTYPE_URL_METRICS);
    for (i=0; i<length; i++) {
        memcpy(&(destn[i]), &source[i], sizeof(te_http_url_metrics_t) - sizeof(te_http_url_bucket_metrics_t*));
        num_buckets = source[i].num_url_buckets;
        if(num_buckets) {
            te_malloc(destn[i].url_buckets, \
                sizeof(te_http_url_bucket_metrics_t) * num_buckets, TE_MTYPE_URL_BUCKET_METRICS);
            for (j=0; j<num_buckets; j++) {
            memcpy(&(destn[i].url_buckets[j]), &(source[i].url_buckets[j]), \
                sizeof(te_http_url_bucket_metrics_t));
            }
        }
        else {
            destn[i].url_buckets = NULL;
        }
    }
    return destn;
}

void te_process_resource_config(const char* resource_config, bool is_update) {
    int i, arraylen;
    json_object *jobj, *jvalue, *jtmp, *jarray, *jr, *temp = NULL, *root = NULL;
    const char *jobj_str = NULL, *ratio_str=NULL, *jstr;
    int profile_index = 0, num_requests=0;
    int if_index = 0, num_ifs = 0;

    //BST Root to get and post profiles
    te_bst_node_t *get_profile_root=NULL, *post_profile_root=NULL, *udp_profile_root=NULL, *if_profile_root=NULL;

    te_resource_config_t* res_cfg_temp = NULL;
    if (res_cfg  && (is_update == 0)) {
        te_cleanup_res_cfg();
    }
    root =  json_object_from_file(resource_config);
    if (root == NULL) {
        printf("aborting : please check the config file, syntax etc \n");
        abort();
    }
    if (!res_cfg_temp) {
        te_malloc(res_cfg_temp, sizeof(te_resource_config_t), TE_MTYPE_RESOURCE_CONFIG);
    }
    if (!te_log_files) {
        te_malloc(te_log_files, sizeof(te_log_files_t), TE_MTYPE_LOG_FILES);
        memset(te_log_files, 0, sizeof(te_log_files_t));
    }

    //*************************************************************************//
    //                           COMMON PARSING                                //
    //*************************************************************************//
    if(res_cfg_temp) {
        memset(res_cfg_temp, 0, sizeof(te_resource_config_t));

        //To select VIPs in round robin by default
        res_cfg_temp->vip_selection_rr = true;
        res_cfg_temp->vip_rr_counter = 0;

        if (json_object_object_get_ex(root, "resource-config", &jobj)) {
            json_object_object_foreach(jobj, key, val) {
                jvalue = val;

                if (strstr(key,"log-path")) {
                    te_malloc(te_log_files->log_file_path, sizeof(char) * TEDP_MAX_STR_LEN, \
                        TE_MTYPE_AGENT_CHAR);
                    strcpy(te_log_files->log_file_path, json_object_get_string(jvalue));
                }

                if (strstr(key,"log-level")) {
                    jobj_str = json_object_get_string(jvalue);
                    if (jobj_str) {
                        if (strstr(jobj_str, "all")) {
                            te_log_level = TE_LOG_SCREWED_MODE;
                        }
                        else if (strstr(jobj_str, "debug")) {
                            te_log_level = TE_LOG_DEBUG_MODE;
                        }
                        else if (strstr(jobj_str, "screen")) {
                            te_log_level = TE_LOG_TRACE_MODE;
                        }
                        else if (strstr(jobj_str, "test")) {
                            te_log_level = TE_LOG_TEST_MODE;
                        }
                        else {
                            te_log_level = TE_LOG_DEFAULT_MODE;
                        }
                    }
                }

                if (strstr(key, "vip-selection-rr")) {
                    if (json_object_get_boolean(jvalue)) {
                        res_cfg_temp->vip_selection_rr = true;
                    } else {
                        res_cfg_temp->vip_selection_rr = false;
                    }
                }
            }
        }
    }

    //*************************************************************************//
    //                              UDP PARSING                                //
    //*************************************************************************//
    if(res_cfg_temp && tedp_profile == UDP) {
        if (json_object_object_get_ex(root, "resource-config", &jobj)) {

            //************************************************************//
            //                      SERVER PARSING                        //
            //************************************************************//
            if(tedp_mode == SERVER) {
                if(json_object_object_get_ex(jobj, "port-list", &temp)) {
                    int port_len = json_object_array_length(temp);
                    te_malloc(res_cfg_temp->udp_listen_handle, port_len * \
                        sizeof(te_udp_listen_handle_t), TE_MTYPE_UDP_LISTEN_HANDLE);
                    memset(res_cfg_temp->udp_listen_handle, 0 , port_len * \
                        sizeof(te_udp_listen_handle_t));

                    res_cfg_temp->num_udp_listen_handle = port_len;
                    for (int counter=0; counter<port_len; ++counter) {
                        jtmp = json_object_array_get_idx(temp, counter);
                        res_cfg_temp->udp_listen_handle[counter].port = \
                            (short)json_object_get_int(jtmp);
                    }
                }
                else if(json_object_object_get_ex(jobj, "port-range", &temp)) {
                    jtmp = json_object_array_get_idx(temp, 0);
                    int min = json_object_get_int(jtmp);
                    jtmp = json_object_array_get_idx(temp, 1);
                    int max = json_object_get_int(jtmp);
                    te_malloc(res_cfg_temp->udp_listen_handle, (max-min+1) * \
                        sizeof(te_udp_listen_handle_t), TE_MTYPE_UDP_LISTEN_HANDLE);
                    memset(res_cfg_temp->udp_listen_handle, 0 , (max-min+1) * \
                        sizeof(te_udp_listen_handle_t));

                    res_cfg_temp->num_udp_listen_handle = max-min+1;
                    for (int counter=0; counter<max-min+1; counter++) {
                        res_cfg_temp->udp_listen_handle[counter].port = min + counter;
                    }
                }
                else {
                    eprint("Neither port-list not port-range was mentioned\n");
                    abort();
                }

                if(json_object_object_get_ex(jobj, "socket-ds-parse-interval", &temp)) {
                    res_cfg_temp->server_socket_ds_parse_timeout = json_object_get_int(temp);
                } else {
                    //By default parse every 15s
                    res_cfg_temp->server_socket_ds_parse_timeout = 15*1000;
                }

                json_object_put(root);
                goto end_resource_config_processing;
            }

            //********************************************************//
            //                   CLIENT PARSING                       //
            //********************************************************//
            else if (tedp_mode == CLIENT) {
                unsigned short default_download_ratio=1, default_upload_ratio=1;
                unsigned short upload_ratio, download_ratio;

                //Default timeout for UDP datagram's response
                res_cfg_temp->udp_resp_default_timeout = 10000;

                json_object_object_foreach(jobj, key, val) {
                    profile_index = 0;
                    num_requests=0;
                    jvalue = val;

                    if(strstr(key, "default-download-upload-ratio")) {
                        ratio_str = json_object_get_string(jvalue);
                        sscanf(ratio_str,"%hu:%hu", &default_download_ratio, &default_upload_ratio);
                    }

                    if(strstr(key, "default-response-timeout")) {
                        res_cfg_temp->udp_resp_default_timeout = json_object_get_int(jvalue);
                    }

                    if (strstr(key,"udp-profiles")) {
                        res_cfg_temp->num_udp_list_profile = json_object_object_length(jvalue);

                        te_malloc(res_cfg_temp->udp_reqs, \
                            res_cfg_temp->num_udp_list_profile * sizeof(te_udp_request_object_t), \
                            TE_MTYPE_UDP_REQUEST_OBJECT);
                        memset(res_cfg_temp->udp_reqs, 0, res_cfg_temp->num_udp_list_profile * \
                            sizeof(te_udp_request_object_t));

                        json_object_object_foreach(jvalue, key_udp, val_udp) {
                            te_add_udp_requests(res_cfg_temp->udp_reqs, profile_index, val_udp, \
                                res_cfg_temp->udp_resp_default_timeout);
                            udp_profile_root = insert(udp_profile_root, key_udp, profile_index);
                            profile_index++;
                        }
                    }

                    //Parsing vip list
                    if(strstr(key, "vip-list")) {
                        jarray = jvalue;
                        arraylen = json_object_array_length(jarray);
                        res_cfg_temp->total_vips = arraylen;

                        te_malloc(res_cfg_temp->vips, sizeof(te_vip_t) * arraylen, TE_MTYPE_VIP);
                        memset(res_cfg_temp->vips, 0, sizeof(te_vip_t) * arraylen);

                        te_malloc(res_cfg_temp->download_upload_ratio, sizeof(download_upload_t) * \
                            arraylen, TE_MTYPE_GET_POST_RATIO);
                        memset(res_cfg_temp->download_upload_ratio, 0 , sizeof(download_upload_t) * \
                            arraylen);

                        res_cfg_temp->udp_vip_metrics = \
                            te_allocate_udp_vip_metrics(res_cfg_temp->total_vips);

                        for (i=0; i< arraylen; i++) {
                            te_malloc(res_cfg_temp->vips[i].vip, sizeof(char) * TEDP_MAX_STR_LEN, \
                                TE_MTYPE_AGENT_CHAR);
                            memset(res_cfg_temp->vips[i].vip, 0, sizeof(char) * TEDP_MAX_STR_LEN);

                            //Scanning vIP:port
                            jvalue = json_object_array_get_idx(jarray,i);
                            if (json_object_object_get_ex(jvalue, "vip",&temp)) {
                                res_cfg_temp->vips[i].vport = 162;
                                char delim[] = ":";
                                char* ptr = strtok((char*)json_object_get_string(temp), delim);
                                int cnt = 0;
                                bool got_vip = false;
                                while(ptr != NULL) {
                                    if(cnt == 0) {
                                        got_vip = true;
                                        strcpy(res_cfg_temp->vips[i].vip, ptr);
                                    }
                                    else if(cnt == 1)
                                        res_cfg_temp->vips[i].vport = atoi(ptr);
                                    else {
                                        eprint("Unexpected vip format. Expected - vip:port\n");
                                        abort();
                                    }
                                    cnt++;
                                    ptr = strtok(NULL, delim);
                                }
                                if(!got_vip) {
                                    eprint("Unexpected vip format. Expected - vip:port\n");
                                    abort();
                                }
                            }

                            if (json_object_object_get_ex(jvalue, "stat-buckets", &temp)) {
                                te_process_session_stat_buckets(temp, i, res_cfg_temp);
                            }

                            if (json_object_object_get_ex(jvalue, "udp-profile", &temp)) {
                                int prof_index = find(udp_profile_root, json_object_get_string(temp));
                                res_cfg_temp->vips[i].udp_profile_index = prof_index;
                            }
                            else {
                                res_cfg_temp->vips[i].get_profile_index = -1;
                            }

                            //download-upload-ratio
                            if (json_object_object_get_ex(jvalue, "download-upload-ratio", &temp)) {
                                ratio_str = json_object_get_string(temp);
                                download_ratio = upload_ratio = 0;
                                sscanf(ratio_str,"%hu:%hu", &download_ratio, &upload_ratio);
                                res_cfg_temp->download_upload_ratio[i].download_ratio = download_ratio;
                                res_cfg_temp->download_upload_ratio[i].upload_ratio = upload_ratio;
                            } else {
                                res_cfg_temp->download_upload_ratio[i].download_ratio = \
                                    default_download_ratio;
                                res_cfg_temp->download_upload_ratio[i].upload_ratio = \
                                    default_upload_ratio;
                            }
                        }
                    }
                }
                json_object_put(root);
                goto end_resource_config_processing;
            }

            else {
                eprint("Unknown TEDP_MODE=%d", tedp_mode);
                abort();
            }
        }
    }

    //*************************************************************************//
    //                              TCP PARSING                                //
    //*************************************************************************//
    else if (res_cfg_temp && tedp_profile == TCP) {
        //HTTP Defaults
        res_cfg_temp->http_version=HTTP_1_1;
        res_cfg_temp->http_pipeline = HTTP_NOTHING;
        res_cfg_temp->is_pipelined = false;

        //SSL DEfaults
        res_cfg_temp->ssl_details.version=SSL_DEFAULT;
        te_malloc(res_cfg_temp->ssl_details.cipher_list, sizeof("DEFAULT"), TE_MTYPE_AGENT_CHAR);
        strcpy(res_cfg_temp->ssl_details.cipher_list,"DEFAULT");
        res_cfg_temp->ssl_details.session_reuse = false;
        res_cfg_temp->ssl_details.groups=NULL;

        //TCP Defaults
        res_cfg_temp->send_tcp_resets = false;
        res_cfg_temp->tcp_keepalive_timeout = 20;
        res_cfg_temp->tcp_connect_only = false;

        //Basic INIT
        te_http_url_metrics_t** url_get_metrics_profile = NULL;
        te_http_url_metrics_t** url_post_metrics_profile = NULL;
        unsigned short default_get_ratio=0, default_post_ratio=0;

        if (json_object_object_get_ex(root, "resource-config", &jobj)) {
            json_object_object_foreach(jobj, key, val) {
                jvalue = val;
                profile_index = num_requests = if_index = num_ifs = 0;

                if (strstr(key,"global-ns")) {
                    // If global ns is present, then the tedp process is supposed to run in that namespace
                    // TE_WORK.py would:
                    // * set this, iff the resource-config is in such a manner
                    //   that all the VIPs has to be hit from the same namespace
                    // * pop all the entries of 'ns' from 'interface-profiles' object
                    // * assure that global-ns != root

                    char* ns_descriptor;
                    jstr = json_object_get_string(jvalue);
                    // len("/var/run/netns/") = 16 (prepended before ns)
                    int ns_len = json_object_get_string_len(jvalue) + 16;
                    te_malloc(ns_descriptor, ns_len, TE_MTYPE_CHAR);
                    memset(ns_descriptor, 0, ns_len);
                    snprintf(ns_descriptor, ns_len, "/var/run/netns/%s", jstr);

                    // To switch to the desired namespace, open a fd to describe the ns
                    int fd = open(ns_descriptor, O_RDONLY);
                    if (fd < 0 ) {
                        // Aborting, since we will now not able to open any sockets across sessions
                        eprint("Error Getting Net_NS FD for NS: %s\n", jstr);
                        abort();
                    }

                    // Set the namespace to the desired
                    if(setns(fd, 0) < 0) {
                        // Aborting, since we will now not able to open any sockets across sessions
                        eprint("Unable to switch to NS: %s\n", jstr);
                        abort();
                    } else {
                        tprint("Process Moved to NS: %s\n", jstr);
                    }
                }

                if (strstr(key,"interface-profiles")) {
                    int num_if_profiles = json_object_object_length(jvalue);

                    te_malloc(res_cfg_temp->interface_obj, num_if_profiles * sizeof(te_interface_t*), \
                        TE_MTYPE_AGENT_DOUBLE_POINTER);
                    memset(res_cfg_temp->interface_obj, 0, num_if_profiles * sizeof(te_interface_t*));

                    te_malloc(res_cfg_temp->num_interfaces_in_profiles, \
                        num_if_profiles * sizeof(int), TE_MTYPE_AGENT_INT);
                    memset(res_cfg_temp->num_interfaces_in_profiles, 0, \
                        num_if_profiles * sizeof(int));

                    json_object_object_foreach(jvalue, key_get, val_get) {
                        num_ifs = json_object_array_length(val_get);
                        res_cfg_temp->num_interfaces_in_profiles[if_index] = num_ifs;

                        te_malloc(res_cfg_temp->interface_obj[if_index], num_ifs * sizeof(te_interface_t), \
                            TE_MTYPE_INTERFACE);
                        memset(res_cfg_temp->interface_obj[if_index], 0, num_ifs * sizeof(te_interface_t));

                        for (int cnt = 0; cnt < num_ifs; ++cnt) {
                            jr = json_object_array_get_idx(val_get, cnt);
                            json_object_object_foreach(jr, if_key, if_val) {
                                if(strstr(if_key, "if")) {
                                    jstr = json_object_get_string(if_val);
                                    unsigned int size = strlen(jstr) + 1;
                                    te_malloc(res_cfg_temp->interface_obj[if_index][cnt].nw_interface, \
                                        sizeof(char) * size, TE_MTYPE_AGENT_CHAR);
                                    memset(res_cfg_temp->interface_obj[if_index][cnt].nw_interface, 0, size);
                                    strcpy(res_cfg_temp->interface_obj[if_index][cnt].nw_interface, jstr);
                                } if(strstr(if_key, "ns")) {
                                    jstr = json_object_get_string(if_val);
                                    unsigned int size = strlen(jstr) + 1;
                                    te_malloc(res_cfg_temp->interface_obj[if_index][cnt].nw_namespace, \
                                        sizeof(char) * size, TE_MTYPE_AGENT_CHAR);
                                    memset(res_cfg_temp->interface_obj[if_index][cnt].nw_namespace, 0, size);
                                    strcpy(res_cfg_temp->interface_obj[if_index][cnt].nw_namespace, jstr);

                                    size_t ns_len = 16 + size; // len("/var/run/netns/") = 16 (prepended before ns)
                                    te_malloc(res_cfg_temp->interface_obj[if_index][cnt].ns_descriptor, \
                                        ns_len, TE_MTYPE_CHAR);
                                    memset(res_cfg_temp->interface_obj[if_index][cnt].ns_descriptor, \
                                        0, ns_len);
                                    snprintf(res_cfg_temp->interface_obj[if_index][cnt].ns_descriptor, \
                                        ns_len, "/var/run/netns/%s", \
                                        res_cfg_temp->interface_obj[if_index][cnt].nw_namespace);
                                }
                            }
                        }

                        if_profile_root = insert(if_profile_root, key_get, if_index);
                        if_index++;
                    }
                }

                if (strstr(key,"get-profiles")) {
                    res_cfg_temp->num_get_list_profile = json_object_object_length(jvalue);

                    te_malloc(res_cfg_temp->greqs, \
                        res_cfg_temp->num_get_list_profile * sizeof(te_request_object_t*), \
                        TE_MTYPE_AGENT_DOUBLE_POINTER);
                    memset(res_cfg_temp->greqs, 0, res_cfg_temp->num_get_list_profile * \
                        sizeof(te_request_object_t*));

                    te_malloc(res_cfg_temp->num_get_reqs_in_profile, \
                        sizeof(int) * res_cfg_temp->num_get_list_profile,
                        TE_MTYPE_AGENT_INT);
                    memset(res_cfg_temp->num_get_reqs_in_profile, 0, \
                            res_cfg_temp->num_get_list_profile * sizeof(int));

                    te_malloc(url_get_metrics_profile, \
                        res_cfg_temp->num_get_list_profile * sizeof(te_http_url_metrics_t*),
                        TE_MTYPE_AGENT_DOUBLE_POINTER);
                    memset(url_get_metrics_profile, 0, res_cfg_temp->num_get_list_profile * \
                        sizeof(te_http_url_metrics_t*));

                    json_object_object_foreach(jvalue, key_get, val_get) {
                        num_requests = json_object_array_length(val_get);
                        te_add_requests(res_cfg_temp->greqs, url_get_metrics_profile,
                            profile_index, num_requests, val_get);
                        get_profile_root = insert(get_profile_root, key_get, profile_index);
                        res_cfg_temp->num_get_reqs_in_profile[profile_index]=num_requests;
                        profile_index++;
                    }
                }

                if (strstr(key,"post-profiles")) {
                    res_cfg_temp->num_post_list_profile = json_object_object_length(jvalue);

                    te_malloc(res_cfg_temp->preqs, \
                        res_cfg_temp->num_post_list_profile * sizeof(te_request_object_t*),
                        TE_MTYPE_AGENT_DOUBLE_POINTER);
                    memset(res_cfg_temp->preqs, 0, res_cfg_temp->num_post_list_profile * \
                        sizeof(te_request_object_t*));

                    te_malloc(res_cfg_temp->num_post_reqs_in_profile, \
                        sizeof(int) * res_cfg_temp->num_post_list_profile,
                        TE_MTYPE_AGENT_INT);
                    memset(res_cfg_temp->num_post_reqs_in_profile, 0, \
                            res_cfg_temp->num_post_list_profile * sizeof(int));

                    te_malloc(url_post_metrics_profile, \
                        res_cfg_temp->num_post_list_profile * sizeof(te_http_url_metrics_t*),
                        TE_MTYPE_AGENT_DOUBLE_POINTER);
                    memset(url_post_metrics_profile, 0, res_cfg_temp->num_post_list_profile * \
                        sizeof(te_http_url_metrics_t*));

                    json_object_object_foreach(jvalue, key_post, val_post) {
                        num_requests = json_object_array_length(val_post);
                        te_add_requests(res_cfg_temp->preqs, url_post_metrics_profile,
                            profile_index, num_requests, val_post);
                        post_profile_root = insert(post_profile_root, key_post, profile_index);
                        res_cfg_temp->num_post_reqs_in_profile[profile_index]=num_requests;
                        profile_index++;
                    }
                }

                if (strstr(key,"default-get-post-ratio")) {
                    ratio_str = json_object_get_string(jvalue);
                    sscanf(ratio_str,"%hu:%hu", &default_get_ratio, &default_post_ratio);
                }

                if (strstr(key,"vip-list")) {
                    jarray = jvalue;
                    arraylen = json_object_array_length(jarray);
                    res_cfg_temp->total_vips = arraylen;
                    te_malloc(res_cfg_temp->vips, sizeof(te_vip_t) * arraylen, TE_MTYPE_VIP);
                    te_malloc(res_cfg_temp->get_post_ratio, sizeof(get_post_t) * arraylen,
                        TE_MTYPE_GET_POST_RATIO);
                    res_cfg_temp->http_vip_metrics = te_allocate_vip_metrics(res_cfg_temp->total_vips);
                    memset(res_cfg_temp->vips, 0, sizeof(te_vip_t) * arraylen);
                    for (i=0; i< arraylen; i++) {

                        te_malloc(res_cfg_temp->vips[i].vip, sizeof(char) * TEDP_MAX_STR_LEN, \
                            TE_MTYPE_AGENT_CHAR);
                        memset(res_cfg_temp->vips[i].vip, 0, sizeof(char) * TEDP_MAX_STR_LEN);

                        jvalue = json_object_array_get_idx(jarray,i);
                        if (json_object_object_get_ex(jvalue, "vip",&temp)) {
                            strcpy(res_cfg_temp->vips[i].vip, json_object_get_string(temp));
                        }

                        if (json_object_object_get_ex(jvalue, "stat-buckets", &temp)) {
                            te_process_session_stat_buckets(temp, i, res_cfg_temp);
                        }

                        if (json_object_object_get_ex(jvalue, "certs", &temp)) {
                            te_add_custom_certs(res_cfg_temp, temp, i);
                        }

                        if (json_object_object_get_ex(jvalue, "interface-profile", &temp)) {
                            res_cfg_temp->vips[i].interface_profile_index = \
                                find(if_profile_root, json_object_get_string(temp));
                        } else {
                            res_cfg_temp->vips[i].interface_profile_index = -1;
                        }

                        if (json_object_object_get_ex(jvalue, "get-profile", &temp)) {
                            int prof_index = find(get_profile_root, json_object_get_string(temp));
                            int num_reqs = res_cfg_temp->num_get_reqs_in_profile[prof_index];
                            res_cfg_temp->vips[i].get_profile_index = prof_index;

                            res_cfg_temp->http_vip_metrics[i].url_get_metrics = 
                                deep_copy(url_get_metrics_profile[prof_index], num_reqs);

                            res_cfg_temp->http_vip_metrics[i].num_url_get_metrics = \
                                res_cfg_temp->num_get_reqs_in_profile[prof_index];
                        }
                        else {
                            res_cfg_temp->vips[i].get_profile_index = -1;
                            res_cfg_temp->http_vip_metrics[i].url_get_metrics = NULL;
                        }

                        if (json_object_object_get_ex(jvalue, "post-profile", &temp)) {
                            int prof_index = find(post_profile_root, json_object_get_string(temp));
                            int num_reqs = res_cfg_temp->num_post_reqs_in_profile[prof_index];
                            res_cfg_temp->vips[i].post_profile_index = prof_index;

                            res_cfg_temp->http_vip_metrics[i].url_post_metrics = 
                                deep_copy(url_post_metrics_profile[prof_index], num_reqs);

                            res_cfg_temp->http_vip_metrics[i].num_url_post_metrics = \
                                res_cfg_temp->num_post_reqs_in_profile[prof_index];
                        }
                        else {
                            res_cfg_temp->vips[i].post_profile_index = -1;
                            res_cfg_temp->http_vip_metrics[i].url_post_metrics = NULL;
                        }

                        if (json_object_object_get_ex(jvalue, "get-post-ratio", &temp)) {
                            ratio_str = json_object_get_string(temp);
                            sscanf(ratio_str,"%hu:%hu", &(res_cfg_temp->get_post_ratio[i].get_ratio),
                                &(res_cfg_temp->get_post_ratio[i].post_ratio));
                        }
                        else {
                            res_cfg_temp->get_post_ratio[i].get_ratio = default_get_ratio;
                            res_cfg_temp->get_post_ratio[i].post_ratio = default_post_ratio;
                        }
                    }
                }

                //TCP Params
                if (strstr(key,"send-tcp-resets")) {
                    if (json_object_get_boolean(jvalue)) {
                        res_cfg_temp->send_tcp_resets = true;
                    }
                    else {
                        res_cfg_temp->send_tcp_resets = false;
                    }
                }
                if(strstr(key, "tcp-keepalive-timeout")) {
                    res_cfg_temp->tcp_keepalive_timeout = json_object_get_int(jvalue);
                }
                if(strstr(key, "tcp-connect-timeout")) {
                    res_cfg_temp->tcp_connect_timeout = json_object_get_int(jvalue);
                }
                if (strstr(key,"tcp-connect-only")) {
                    if (json_object_get_boolean(jvalue)) {
                        res_cfg_temp->tcp_connect_only = true;
                    }
                    else {
                        res_cfg_temp->tcp_connect_only = false;
                    }
                }

                //HTTP VERSION AND PIPELINE
                if (strstr(key,"http-version")) {
                    jobj_str = json_object_get_string(jvalue);
                    if (!strcmp(jobj_str,"2.0")) {
                        res_cfg_temp->http_version = HTTP_2_0;
                    }
                    else if(!strcmp(jobj_str,"2.0pk")) {
                        res_cfg_temp->http_version = HTTP_2_0_PK;
                    }
                    else if(!strcmp(jobj_str,"2.0tls")) {
                        res_cfg_temp->http_version = HTTP_2_0_TLS;
                    }
                    else if(!strcmp(jobj_str,"1.0")) {
                        res_cfg_temp->http_version = HTTP_1_0;
                    }
                    else {
                        res_cfg_temp->http_version = HTTP_1_1;
                    }
                }
                if (strstr(key,"http-pipeline")) {
                    jobj_str = json_object_get_string(jvalue);
                    if (!strcmp(jobj_str,"HTTP_NOTHING"))
                    {
                        res_cfg_temp->http_pipeline = HTTP_NOTHING;
                        res_cfg_temp->is_pipelined = false;
                    }
                    else if (!strcmp(jobj_str,"HTTP1_PIPELINE"))
                    {
                        res_cfg_temp->http_pipeline = HTTP1_PIPELINE;
                        res_cfg_temp->is_pipelined = true;
                    }
                    else if (!strcmp(jobj_str,"HTTP2_MULTIPLEX"))
                    {
                        res_cfg_temp->http_pipeline = HTTP2_MULTIPLEX;
                        res_cfg_temp->is_pipelined = true;
                    }
                }

                if (!strcmp(key, "be-verbose")) {
                    if (json_object_get_boolean(jvalue)) {
                        res_cfg_temp->is_verbose = true;
                    }
                    else {
                        res_cfg_temp->is_verbose = false;
                    }
                }

                //SSL & CIPHERS
                if (strstr(key,"ssl-version")) {
                    jobj_str = json_object_get_string(jvalue);
                    if (!strcmp(jobj_str,"ssl"))
                        res_cfg_temp->ssl_details.version = SSL_V1;
                    else if(!strcmp(jobj_str,"tlsv1.0"))
                        res_cfg_temp->ssl_details.version = TLS_V1_0;
                    else if(!strcmp(jobj_str,"tlsv1.1"))
                        res_cfg_temp->ssl_details.version = TLS_V1_1;
                    else if(!strcmp(jobj_str,"tlsv1.2"))
                        res_cfg_temp->ssl_details.version = TLS_V1_2;
                    else if(!strcmp(jobj_str,"tlsv1.3"))
                        res_cfg_temp->ssl_details.version = TLS_V1_3;
                    else
                        res_cfg_temp->ssl_details.version = SSL_DEFAULT;
                }
                if (strstr(key,"cipher")) {
                    te_free(res_cfg_temp->ssl_details.cipher_list, TE_MTYPE_AGENT_CHAR);
                    res_cfg_temp->ssl_details.cipher_list = NULL;
                    jobj_str=json_object_get_string(jvalue);
                    int len_of_cipher_list = json_object_get_string_len(jvalue) + 1;
                    te_malloc(res_cfg_temp->ssl_details.cipher_list, len_of_cipher_list * \
                        sizeof(jobj_str), TE_MTYPE_AGENT_CHAR);
                    strncpy(res_cfg_temp->ssl_details.cipher_list, jobj_str, len_of_cipher_list);
                }
                if (strstr(key,"ssl-groups")) {
                    te_free(res_cfg_temp->ssl_details.groups, TE_MTYPE_AGENT_CHAR);
                    res_cfg_temp->ssl_details.groups = NULL;
                    jobj_str=json_object_get_string(jvalue);
                    te_malloc(res_cfg_temp->ssl_details.groups, sizeof(jobj_str), TE_MTYPE_AGENT_CHAR);
                    strcpy(res_cfg_temp->ssl_details.groups, jobj_str);
                }
                if (strstr(key, "ssl-session-reuse")) {
                    if (json_object_get_boolean(jvalue)) {
                        res_cfg_temp->ssl_details.session_reuse = true;
                    } else {
                        res_cfg_temp->ssl_details.session_reuse = false;
                    }
                }

                //To enable Set-Cookies
                if(strstr(key, "set-cookies-resend")) {
                    if(json_object_get_boolean(jvalue)) {
                        res_cfg_temp->set_cookies = true;
                    } else {
                        res_cfg_temp->set_cookies = false;
                    }
                }
            }
        }
        json_object_put(root);
        goto end_resource_config_processing;
    } else {
        // Something is off
        // Either TCP/UDP is not defined as the profile
        // or resourcce-config key is not found
        abort();
    }

    end_resource_config_processing:
        if (is_update) {
            res_cfg_updated = res_cfg_temp;
        }
        else {
            res_cfg = res_cfg_temp;
            te_create_resources();
        }
        assert(tedp_mode != TE_UNDEFINED);
}

void init_te_dp (bool is_hitless_update)
{
    //TEDP can run as server (UDP only) and client(TCP/UDP)
    //The Call populates the global DS for tedp_mode
    te_process_resource_config(res_cfg_path, is_hitless_update);

    //UDP SERVER HAS NO SESSION CONFIG
    if(tedp_mode == CLIENT)
        te_process_session_config(session_cfg_path, is_hitless_update);

    else
        te_start_udp_listen();
    te_print_formatters();
}

void update_te_dp()
{
   tprint("res_cfg->update flag %d \n", res_cfg->update_flag);
   if (res_cfg->update_flag) {
      te_cleanup_resources();
   } else {
      te_process_session_config(session_cfg_path, 0);
   }
}
void te_parse_updated_config (bool res_update, bool ses_update)
{
   tprint("%s %s %s ses update %d, res update %d \n", __FUNCTION__,
           res_cfg_path, session_cfg_path, ses_update, res_update);
   if (res_update) {
       te_process_resource_config(res_cfg_path, true);
   }
   if (ses_update) {
       te_process_session_config(session_cfg_path, true);
   }
}
void te_init_update_context ()
{
    unsigned short size;
    size = sizeof(te_update_context_t);
    te_malloc(te_update_context, size, TE_MTYPE_UPDATE_CONTEXT);
    memset(te_update_context, 0, size);
    te_update_context->diff = te_session_cfgs->ramped_sessions
                              - te_session_cfgs_updated->num_sessions;
    if (te_session_cfgs->ramped_sessions == 0) {
        te_update_context->to_start =+ (0 - te_update_context->diff);
    }
}
void te_allocate_sessions(te_session_config_t *session_cfg)
{
    unsigned int num_sessions = session_cfg->num_sessions;
    session_cfg->http_metrics.num_sessions = num_sessions;
    tprint("%s \n", __FUNCTION__);
    if (!session_cfg->te_sessions) {
        te_malloc(session_cfg->te_sessions, num_sessions * sizeof(te_session_t), TE_MTYPE_AGENT_SESSION);
        if (!session_cfg->te_sessions) {
            wprint("Unable to allocate memory\n");
            return;
        }
        memset(session_cfg->te_sessions, 0,
               num_sessions * sizeof(te_session_t));
        memset(&session_cfg->http_metrics, 0, sizeof(te_http_session_metrics_t));
    }
}

void te_cleanup_res_cfg()
{
    int iter, profile_iter;
    if (res_cfg->greqs) {
        for(profile_iter = 0; profile_iter!=res_cfg->num_get_list_profile; profile_iter++) {
            for  (iter = 0; iter < res_cfg->num_get_reqs_in_profile[profile_iter] ; ++iter) {
                //Free URI
                if(res_cfg->greqs[profile_iter][iter].request_uri.has_uri)
                {
                    te_free(res_cfg->greqs[profile_iter][iter].request_uri.uri, TE_MTYPE_AGENT_CHAR);
                    res_cfg->greqs[profile_iter][iter].request_uri.uri = NULL;
                }

                //Free Query Params
                if (res_cfg->greqs[profile_iter][iter].has_query_params) {
                    int iiter;
                    for (iiter = 0 ; iiter < res_cfg->greqs[profile_iter][iter].num_qparams ; ++iiter) {
                        te_free(res_cfg->greqs[profile_iter][iter].query_params[iiter], \
                            TE_MTYPE_AGENT_CHAR);
                        res_cfg->greqs[profile_iter][iter].query_params[iiter] = NULL;
                    }
                    te_free(res_cfg->greqs[profile_iter][iter].query_params, \
                        TE_MTYPE_AGENT_DOUBLE_POINTER);
                    res_cfg->greqs[profile_iter][iter].query_params = NULL;
                }

                //Free Headers
                if (res_cfg->greqs[profile_iter][iter].has_headers) {
                    int iiter;
                    for (iiter = 0 ; iiter < res_cfg->greqs[profile_iter][iter].num_headers ; ++iiter) {
                        te_free(res_cfg->greqs[profile_iter][iter].headers[iiter], TE_MTYPE_AGENT_CHAR);
                        res_cfg->greqs[profile_iter][iter].headers[iiter] = NULL;
                    }
                    te_free(res_cfg->greqs[profile_iter][iter].headers, TE_MTYPE_AGENT_DOUBLE_POINTER);
                    res_cfg->greqs[profile_iter][iter].headers = NULL;
                }

                //Free Cookies
                if (res_cfg->greqs[profile_iter][iter].has_cookies) {
                    te_free(res_cfg->greqs[profile_iter][iter].cookies, TE_MTYPE_AGENT_CHAR);
                    res_cfg->greqs[profile_iter][iter].cookies = NULL;
                }
            }
            te_free(res_cfg->greqs[profile_iter], TE_MTYPE_REQUEST_OBJECT);
            res_cfg->greqs[profile_iter] = NULL;
        }

        //Free Greqs
        te_free(res_cfg->greqs, TE_MTYPE_AGENT_DOUBLE_POINTER);
        res_cfg->greqs = NULL;
    }

    if (res_cfg->preqs) {
        for(profile_iter = 0; profile_iter!=res_cfg->num_post_list_profile; profile_iter++) {
            for  (iter = 0; iter < res_cfg->num_post_reqs_in_profile[profile_iter] ; ++iter) {
                //Free URI
                if(res_cfg->preqs[profile_iter][iter].request_uri.has_uri)
                {
                    te_free(res_cfg->preqs[profile_iter][iter].request_uri.uri, TE_MTYPE_AGENT_CHAR);
                    res_cfg->preqs[profile_iter][iter].request_uri.uri = NULL;
                }

                //Free Post Data
                if (res_cfg->preqs[profile_iter][iter].has_postdata) {
                    te_free(res_cfg->preqs[profile_iter][iter].postdata, TE_MTYPE_AGENT_CHAR);
                    res_cfg->preqs[profile_iter][iter].postdata = NULL;
                }

                //Free Post File
                if (res_cfg->preqs[profile_iter][iter].has_postfile) {
                    te_free(res_cfg->preqs[profile_iter][iter].postfile, TE_MTYPE_AGENT_CHAR);
                    res_cfg->preqs[profile_iter][iter].postfile = NULL;
                }

                //Free Query Params
                if (res_cfg->preqs[profile_iter][iter].has_query_params) {
                    int iiter;
                    for (iiter = 0 ; iiter < res_cfg->preqs[profile_iter][iter].num_qparams ; ++iiter) {
                        te_free(res_cfg->preqs[profile_iter][iter].query_params[iiter], \
                            TE_MTYPE_AGENT_CHAR);
                        res_cfg->preqs[profile_iter][iter].query_params[iiter] = NULL;
                    }
                    te_free(res_cfg->preqs[profile_iter][iter].query_params, \
                        TE_MTYPE_AGENT_DOUBLE_POINTER);
                    res_cfg->preqs[profile_iter][iter].query_params = NULL;
                }

                //Free Headers
                if (res_cfg->preqs[profile_iter][iter].has_headers) {
                    int iiter;
                    for (iiter = 0 ; iiter < res_cfg->preqs[profile_iter][iter].num_headers ; ++iiter) {
                        te_free(res_cfg->preqs[profile_iter][iter].headers[iiter], \
                            TE_MTYPE_AGENT_CHAR);
                        res_cfg->preqs[profile_iter][iter].headers[iiter] = NULL;
                    }
                    te_free(res_cfg->preqs[profile_iter][iter].headers, TE_MTYPE_AGENT_DOUBLE_POINTER);
                    res_cfg->preqs[profile_iter][iter].headers = NULL;
                }

                //Free Cookies
                if (res_cfg->preqs[profile_iter][iter].has_cookies) {
                    te_free(res_cfg->preqs[profile_iter][iter].cookies, TE_MTYPE_AGENT_CHAR);
                    res_cfg->preqs[profile_iter][iter].cookies = NULL;
                }
            }
            te_free(res_cfg->preqs[profile_iter], TE_MTYPE_REQUEST_OBJECT);
            res_cfg->preqs[profile_iter] =  NULL;
        }

        //Free Preqs
        te_free(res_cfg->preqs, TE_MTYPE_AGENT_DOUBLE_POINTER);
        res_cfg->preqs = NULL;
    }

    if (res_cfg->vips) {
        int iter = 0;
        for (iter = 0 ; iter < res_cfg->total_vips ; ++iter) {
            if (res_cfg->vips[iter].vip) {
                te_free(res_cfg->vips[iter].vip, TE_MTYPE_AGENT_CHAR);
                res_cfg->vips[iter].vip = NULL;
            }

            if (res_cfg->http_vip_metrics && res_cfg->http_vip_metrics->url_get_metrics) {
                int i;
                if(res_cfg->http_vip_metrics->url_get_metrics) {
                    for(i=0; i<res_cfg->http_vip_metrics->num_url_get_metrics; i++) {
                        if(res_cfg->http_vip_metrics->url_get_metrics[i].url_buckets) {
                            res_cfg->http_vip_metrics->url_get_metrics[i].num_url_buckets = 0;
                            te_free(res_cfg->http_vip_metrics->url_get_metrics[i].url_buckets,
                                TE_MTYPE_URL_BUCKET_METRICS);
                            res_cfg->http_vip_metrics->url_get_metrics[i].url_buckets = NULL;
                        }
                    }
                }
                te_free(res_cfg->http_vip_metrics->url_get_metrics, TE_MTYPE_URL_METRICS);
                res_cfg->http_vip_metrics->url_get_metrics = NULL;
            }

            if (res_cfg->http_vip_metrics && res_cfg->http_vip_metrics->url_post_metrics) {
                int i;
                if(res_cfg->http_vip_metrics->url_post_metrics) {
                    for(i=0; i<res_cfg->http_vip_metrics->num_url_post_metrics; i++) {
                        if(res_cfg->http_vip_metrics->url_post_metrics[i].url_buckets) {
                            res_cfg->http_vip_metrics->url_post_metrics[i].num_url_buckets = 0;
                            te_free(res_cfg->http_vip_metrics->url_post_metrics[i].url_buckets, \
                                TE_MTYPE_URL_BUCKET_METRICS);
                            res_cfg->http_vip_metrics->url_post_metrics[i].url_buckets = NULL;
                        }
                    }
                }
                te_free(res_cfg->http_vip_metrics->url_post_metrics, TE_MTYPE_URL_METRICS);
                res_cfg->http_vip_metrics->url_post_metrics = NULL;
            }


            if (res_cfg->http_vip_metrics && res_cfg->http_vip_metrics[iter].session_buckets) {
                res_cfg->http_vip_metrics[iter].num_session_buckets = 0;
                te_free(res_cfg->http_vip_metrics[iter].session_buckets, TE_MTYPE_SESSION_BUCKET_METRICS);
                res_cfg->http_vip_metrics[iter].session_buckets = NULL;
            }
            if (res_cfg->http_vip_metrics) {
                te_free(res_cfg->http_vip_metrics, TE_MTYPE_VIP_METRICS);
                res_cfg->http_vip_metrics = NULL;
            }
        }
        te_free(res_cfg->vips, TE_MTYPE_VIP);
        res_cfg->vips = NULL;
    }
    if (res_cfg->ssl_details.cipher_list) {
        te_free(res_cfg->ssl_details.cipher_list, TE_MTYPE_CHAR);
        res_cfg->ssl_details.cipher_list = NULL;
    }
    if (res_cfg->ssl_details.groups) {
        te_free(res_cfg->ssl_details.groups, TE_MTYPE_CHAR);
        res_cfg->ssl_details.groups = NULL;
    }
    if (te_log_files->log_file_path) {
        te_free(te_log_files->log_file_path, TE_MTYPE_CHAR);
        te_log_files->log_file_path = NULL;
    }
    te_free(res_cfg, TE_MTYPE_RESOURCE_CONFIG);
    res_cfg = NULL;
}

void te_free_ses_cfgs()
{
    te_free(te_session_cfgs, TE_MTYPE_SESSION_CONFIG);
    te_session_cfgs = NULL;
}

void te_cleanup_on_update ()
{
   // delete_te_sessions(te_session_cfgs);
    if (res_cfg_updated) {
        te_cleanup_res_cfg();
    }
    if (te_session_cfgs_updated) {
        te_free_ses_cfgs();
    }
}

void te_hitless_update_complete ()
{
    // HITLESS UPDATE IS NOT USED. FIX THE BELOW, UPON NECESSITY
    tprint("%s \n", __FUNCTION__);
    /*dump old data */
    if (metrics_enabled) {
        //dump_session_config_metrics(te_session_cfgs);
        te_dump_vip_metrics(res_cfg);
    }
    /* clenup old data structures */
    te_cleanup_on_update();
     /*tie up updated to fresh start datas */
    res_cfg = res_cfg_updated ? res_cfg_updated : res_cfg;
    te_session_cfgs = te_session_cfgs_updated ? te_session_cfgs_updated :
                      te_session_cfgs;
    te_session_cfgs_updated = NULL;
    res_cfg_updated = NULL;
    /*set update flags to zero and memset update context to zero */
    memset(te_update_context, 0, sizeof(te_update_context_t));

}

void te_batch_start_timer_cb(uv_timer_t *ramp_timer)
{
    //Removed the redundant piece of code from here
    session_ramp_timer_cb(ramp_timer);
    te_session_config_t *session_cfg = (te_session_config_t *) (ramp_timer->data);
    if (session_cfg->ramped_sessions == session_cfg->num_sessions) {
        te_hitless_update_complete();
        return;
    }
}
void te_start_ramp_timer (te_session_config_t *session_cfg)
{
    session_cfg->running_state = TE_SESSION_CONFIG_STATE_PENDING;
    // As we only start after stop.
    session_cfg->config_state = TE_SESSION_CONFIG_STATE_STOP;
    session_cfg->pending_sessions = 0;
    session_cfg->completed_sessions = 0;
    uv_async_init(loop, &session_cfg->session_signal_handler, session_config_uv_async);
    uv_timer_init(loop, &session_cfg->ramp_timer);
    session_cfg->ramp_timer.data = session_cfg;
    session_cfg->pending_uv_deletes++;
    session_cfg->session_signal_handler.data = session_cfg;
    session_cfg->pending_uv_deletes++;

    uv_timer_start(&session_cfg->ramp_timer, te_batch_start_timer_cb, 1,
                   session_cfg->session_ramp_delay * 1000);
    tprint("started ramp timer %s \n", __FUNCTION__);
}

bool te_session_config_start(te_session_config_t* session_cfg,
                            TE_SESSION_CONFIG_STATE prev_state) {
    if (prev_state == TE_SESSION_CONFIG_STATE_STOP) {
        session_cfg->pending_sessions = session_cfg->ramped_sessions;
        tprint("%s pending ssns %d\n", __FUNCTION__, session_cfg->pending_sessions);
        te_create_session_config(session_cfg);
        return true;
    } else {
        return false;
    }
}

bool te_session_config_stop_or_update(te_session_config_t* session_cfg, \
                            TE_SESSION_CONFIG_STATE prev_state) {

    // stop is acceptable from any state
    session_cfg->pending_sessions = session_cfg->ramped_sessions;
    if (session_cfg->config_state == TE_SESSION_CONFIG_STATE_UPDATE) {
        eprint("%s update te_dp got! UNIMPLEMENTED.\n", __FUNCTION__);
        session_cfg->update_flag = 1;
        res_cfg->update_flag = 1;
    }
    if (session_cfg->config_state == TE_SESSION_CONFIG_STATE_UPDATE_SESS) {
        eprint("%s Update te_dp ses config got! UNIMPLEMENTED\n", __FUNCTION__);
        session_cfg->update_flag = 1;
    }

    //Ideally the only `IF` construct that must hit!
    if ((session_cfg->config_state == TE_SESSION_CONFIG_STATE_STOP) &&
        !((session_cfg->update_flag) || (res_cfg->update_flag))) {
        session_cfg->config_state = TE_SESSION_CONFIG_STATE_STOP;
        te_delete_session_config(session_cfg);
        return true;
    }

    //Non Tested and mostly non functional
    if ((session_cfg->config_state == TE_SESSION_CONFIG_STATE_STOP) &&
        ((session_cfg->update_flag) || (res_cfg->update_flag))) {
        eprint("Calling update_te_dp with prev_state as STOP. "\
                "Untested update call! %s \n",__FUNCTION__);
        update_te_dp();
        init_te_dp(0);
        return true;
    }
    //Non Tested and mostly non functional
    if (res_cfg->update_flag || session_cfg->update_flag) {
        eprint("Calling update_te_dp. Untested update call! %s \n",__FUNCTION__);
        te_parse_updated_config(res_cfg->update_flag, session_cfg->update_flag);
        te_init_update_context();
        te_allocate_sessions(te_session_cfgs_updated);
        te_start_ramp_timer(te_session_cfgs_updated);
    }
    return true;
}

bool te_session_config_pause(te_session_config_t* session_cfg, \
                            TE_SESSION_CONFIG_STATE prev_state) {
    if (prev_state == TE_SESSION_CONFIG_STATE_STOP) {
        // A pause after stop needs no pending sessions, is same as stop.
        return false;
    }
    session_cfg->pending_sessions = (session_cfg->ramped_sessions -
        session_cfg->completed_sessions);
    if (session_cfg->ramped_sessions < session_cfg->num_sessions) {
        uv_timer_stop(&session_cfg->ramp_timer);
    }
    return true;
}

bool te_session_config_resume(te_session_config_t* session_cfg, \
                            TE_SESSION_CONFIG_STATE prev_state) {
    // config_state got updated, just signal session_config.
    if (prev_state == TE_SESSION_CONFIG_STATE_PAUSE) {
        // A resume after pause just needs poke
        session_cfg->pending_sessions = (session_cfg->ramped_sessions -
            session_cfg->completed_sessions);
        te_signal_session_config(session_cfg);
        return true;
    } else {
        return false;
    }
}

void te_process_session_config_state(te_session_config_t *session_cfg,
                                     TE_SESSION_CONFIG_STATE state)
{
    assert (session_cfg != NULL);
    TE_SESSION_CONFIG_STATE prev_state = session_cfg->config_state;

    // If previous state is same as the new state (OR)
    // If there are no pending sessions (OR)
    // If the already started update is yet to complete
    // Ignore
    if ((prev_state == state) ||
        (session_cfg->pending_sessions != 0) ||
        (res_cfg->update_flag) || (session_cfg->update_flag)) {
        tprint("%s:TE COMMAND is ignored! session_config_state:%d"
            " pending_sessions:%d new_state:%d update flag %d \n\n",
            __FUNCTION__, session_cfg->config_state,
            session_cfg->pending_sessions, state, session_cfg->update_flag);
      return;
    }

    session_cfg->config_state = state;
    bool is_session_config_state_moved = (*te_session_config_state_switcher[state])(session_cfg, prev_state);

    if(!is_session_config_state_moved) {
        session_cfg->config_state = prev_state;
        session_cfg->pending_sessions = 0;
        wprint("%s:TE COMMAND is ignored after parse! session_config_state:%d"
                " pending_sessions:%d new_state:%d\n\n", __FUNCTION__,
                session_cfg->config_state, session_cfg->pending_sessions, state);
    }

    return;
}

void te_push_session_config_fsm(TE_SESSION_CONFIG_STATE state)
{
   unsigned int iter = 0;
   te_session_config_t *session_cfg = NULL;
   tprint("te_push_session_config_fsm state %d \n", state);
   for (iter = 0; iter < res_cfg->num_session_cfgs; iter++) {
      session_cfg = &te_session_cfgs[iter];
      assert (session_cfg != NULL);
      te_process_session_config_state(session_cfg, state);
   }
}

void te_process_session_stat_buckets (json_object *jvalue, int vip_index,
                                      te_resource_config_t *res_cfg)
{
    int length, i,  metric_size;
    json_object *temp = NULL;
    if (res_cfg->http_vip_metrics && res_cfg->http_vip_metrics[vip_index].num_session_buckets) {
        /* this is an update context , free the memory before proceeding
        TODO Check other places for possible leaks in such scenarios */
        if (res_cfg->http_vip_metrics[vip_index].session_buckets) {
            res_cfg->http_vip_metrics[vip_index].num_session_buckets = 0;
            te_free(res_cfg->http_vip_metrics[vip_index].session_buckets, \
                TE_MTYPE_SESSION_BUCKET_METRICS);
            res_cfg->http_vip_metrics[vip_index].session_buckets = NULL;
        }
    }
    if (jvalue == NULL) {
        return;
    }
    length = json_object_array_length(jvalue);
    res_cfg->http_vip_metrics[vip_index].num_session_buckets = length;
    if (length == 0) {
        return;
    }
    metric_size = sizeof(te_http_session_bucket_metrics_t) * \
                    res_cfg->http_vip_metrics[vip_index].num_session_buckets;
    te_malloc(res_cfg->http_vip_metrics[vip_index].session_buckets, metric_size,\
        TE_MTYPE_SESSION_BUCKET_METRICS);
    memset(res_cfg->http_vip_metrics[vip_index].session_buckets, 0, metric_size);
    for (i = 0; i < length; i++) {
        temp = json_object_array_get_idx(jvalue,i);
        json_object_object_foreach(temp, key, val) {
            if (strstr(key, "start_time")) {
                res_cfg->http_vip_metrics[vip_index].session_buckets[i].bucket_start_time \
                    = json_object_get_int(val);
            }
            if (strstr(key, "end_time")) {
                res_cfg->http_vip_metrics[vip_index].session_buckets[i].bucket_end_time \
                    = json_object_get_int(val);
            }
        }
    }
}

void te_process_session_config (const char* session_config, bool is_update)
{
    int i, arraylen;
    json_object* root=  json_object_from_file(session_config);
    json_object *jobj, *jvalue, *jarray, *temp = NULL;
    unsigned int num_cfgs = 0;
    unsigned int num_conns = 0;
    unsigned int num_sessions = 0;
    int iter = 0;
    te_session_config_t *session_cfg, *te_session_cfgs_temp = NULL;
    tprint("func %s is_update %d \n", __FUNCTION__, is_update);
    if (te_session_cfgs && (is_update == 0)) {
        te_free_ses_cfgs();
    }
    if (root == NULL) {
        printf("error parsing session config, please check the file, syntax etc \n");
        abort();
    }
    if (json_object_object_get_ex(root, "session-config",&jarray)) {
        arraylen = json_object_array_length(jarray);
        if (is_update && res_cfg_updated) {
            res_cfg_updated->num_session_cfgs = num_cfgs = arraylen;
        } else {
            res_cfg->num_session_cfgs = num_cfgs = arraylen;
        }
        if (!te_session_cfgs_temp) {
            te_malloc(te_session_cfgs_temp, sizeof(te_session_config_t) * num_cfgs, \
                TE_MTYPE_SESSION_CONFIG);
        }
        memset(te_session_cfgs_temp, 0, sizeof(te_session_config_t) * num_cfgs);

        // Default knob setting
        // Note that, as of now, we use only one session config / te_dp
        te_session_cfgs_temp[0].persist_flag = false;

        for (i=0; i< arraylen; i++) {
            jobj = json_object_array_get_idx(jarray, i);
            json_object_object_foreach(jobj, key, val) {
                // printf("key: %s\n", key);
                jvalue = val;
                if (strstr(key, "session-type")) {
                    if (strstr(json_object_get_string(jvalue), "MaxPerf")) {
                        te_session_cfgs_temp[i].type = TE_SESSION_TYPE_MAX_CONN_REQS;
                    } else {
                        te_session_cfgs_temp[i].type = TE_SESSION_TYPE_BROWSER;
                    }
                }
                if (strstr(key, "num-sessions")) {
                    te_session_cfgs_temp[i].num_sessions = json_object_get_int(jvalue);
                    tprint("num-sessions:%d\n", te_session_cfgs_temp[i].num_sessions);
                    num_sessions += te_session_cfgs_temp[i].num_sessions;
                }
                if (strstr(key,"target-cycles")) {
                    te_session_cfgs_temp[i].target_cycles = json_object_get_int(jvalue);
                    tprint("target-cycles:%d\n", te_session_cfgs_temp[i].target_cycles);
                }
                if (strstr(key, "connection-range")) {
                    temp = json_object_array_get_idx(jvalue, 0);
                    te_session_cfgs_temp[i].min_connections = json_object_get_int(temp);
                    tprint("%s min_connections:%d\n", __FUNCTION__, \
                        te_session_cfgs_temp[i].min_connections);
                    temp = json_object_array_get_idx(jvalue, 1);
                    te_session_cfgs_temp[i].max_connections = json_object_get_int(temp);
                    num_conns += te_session_cfgs_temp[i].max_connections;
                    tprint("%s max_connections:%d\n", __FUNCTION__, \
                        te_session_cfgs_temp[i].max_connections);
                }
                if (strstr(key, "requests-range")) {
                    temp = json_object_array_get_idx(jvalue, 0);
                    te_session_cfgs_temp[i].min_requests = json_object_get_int(temp);
                    tprint("%s min_reqs:%d\n", __FUNCTION__, te_session_cfgs_temp[i].min_requests);
                    temp = json_object_array_get_idx(jvalue, 1);
                    te_session_cfgs_temp[i].max_requests = json_object_get_int(temp);
                    tprint("%s max_reqs:%d\n", __FUNCTION__, te_session_cfgs_temp[i].max_requests);
                }
                if (strstr(key, "persist")) {
                    if (json_object_get_boolean(jvalue)) {
                        te_session_cfgs_temp[i].persist_flag = true;
                    } else {
                        te_session_cfgs_temp[i].persist_flag = false;
                    }
                }
                if (strstr(key, "num-cycles")) {
                    te_session_cfgs_temp[i].num_cycles = json_object_get_int(jvalue);
                    tprint("num-cycles:%d\n", te_session_cfgs_temp[i].num_cycles);
                }
                if (strstr(key, "cycle-delay")) {
                    temp = json_object_array_get_idx(jvalue, 0);
                    te_session_cfgs_temp[i].min_cycle_delay = json_object_get_int(temp);
                    tprint("%s min_cycle_delay:%d\n", __FUNCTION__, te_session_cfgs_temp[i].min_cycle_delay);

                    temp = json_object_array_get_idx(jvalue, 1);
                    te_session_cfgs_temp[i].max_cycle_delay= json_object_get_int(temp);
                    tprint("%s max_cycle_delay:%d\n", __FUNCTION__, te_session_cfgs_temp[i].max_cycle_delay);
                }
                if (strstr(key, "cycle-type")) {
                    if (strstr(json_object_get_string(jvalue), "restart")) {
                        te_session_cfgs_temp[i].cycle_type = TE_SESSION_CYCLE_RESTART;
                        tprint("%s session_type:%s\n", __FUNCTION__, "restart");
                    } else {
                        te_session_cfgs_temp[i].cycle_type = TE_SESSION_CYCLE_RESUME;
                        tprint("%s session_type:%s\n", __FUNCTION__, "resume");
                    }
                }
                if (strstr(key, "session-ramp-step")) {
                    te_session_cfgs_temp[i].session_ramp_step =
                    json_object_get_int(jvalue);
                }
                if (strstr(key, "session-ramp-delay")) {
                    te_session_cfgs_temp[i].session_ramp_delay =
                    json_object_get_int(jvalue);
                }
                te_session_cfgs_temp[i].res_cfg = res_cfg_updated ? res_cfg_updated : res_cfg;
            }
        }
        json_object_put(root);
    }
    if (is_update) {
        te_session_cfgs_updated = te_session_cfgs_temp;
    } else {
        te_session_cfgs = te_session_cfgs_temp;
    }
    tprint("updated ses_cfg %p prev ses_cfg %p \n", te_session_cfgs_updated, te_session_cfgs);
    if (is_update == false) {
        for (iter = 0; iter < num_cfgs; iter++) {
            session_cfg = &te_session_cfgs[iter];
            session_cfg->id = iter + 1;
            session_cfg->running_state = TE_SESSION_CONFIG_STATE_PENDING;
            // As we only start after stop.
            session_cfg->config_state = TE_SESSION_CONFIG_STATE_STOP;
            session_cfg->pending_sessions = 0;
            session_cfg->completed_sessions = 0;
            
            if(session_cfg->session_ramp_step == 0) {
                session_cfg->session_ramp_step = session_cfg->num_sessions;
            }
            if(session_cfg->session_ramp_delay == 0) {
                session_cfg->session_ramp_delay = 1;
            }
            te_process_session_config_state(session_cfg, TE_SESSION_CONFIG_STATE_START);
        }
    }
    return;
}

void te_cleanup_session_config()
{
    unsigned int iter, num_cfgs = res_cfg->num_session_cfgs;
    for (iter = 0; iter < num_cfgs; iter++) {
        te_delete_session_config(&te_session_cfgs[iter]);
    }
}

void te_delete_session_config( te_session_config_t *session_cfg)
{
    dprint("%s\n",__FUNCTION__);
    if (session_cfg->num_sessions) {
        //uv_async_send(&session_cfg->session_signal_handler);
        delete_te_sessions(session_cfg);
    }
}

void te_signal_session_config( te_session_config_t *session_cfg)
{
    dprint("%s\n",__FUNCTION__);
    uv_async_send(&session_cfg->session_signal_handler);
}

void te_open_logger_files()
{
    char filename[128];
    unsigned int pid = getpid();
    
    /* if log files are already open , do not re open again*/
    if (te_log_files->logs_open == true) {
        return;
    }
    snprintf(filename , 128,"%s/te_debug.%d.csv", te_log_files->log_file_path, pid);
    te_log_files->debug_logger = fopen(filename, "wb");
    if (!te_log_files->debug_logger) {
        return;
    }
    setbuf(te_log_files->debug_logger, NULL);

    snprintf(filename , 128,"%s/te_error.%d.csv", te_log_files->log_file_path, pid);
    te_log_files->error_logger = fopen(filename, "wb");
    if (!te_log_files->error_logger) {
        return;
    }
    setbuf(te_log_files->error_logger, NULL);

    snprintf(filename , 128,"%s/te_test.%d.csv", te_log_files->log_file_path, pid);
    te_log_files->test_logger = fopen(filename, "wb");
    if (!te_log_files->test_logger) {
        return;
    }
    setbuf(te_log_files->test_logger, NULL);

    te_log_files->logs_open = true;
}

void te_print_formatters()
{
    if (te_log_files->headers_printed == true) {
        return;
    }
    iprint(TE_TRACE, "LOG_TYPE_INFO, TIME, Session, Cycle, Message\n");
    /*iprint(TE_ERROR, "LOG_TYPE_ERROR, TIME,  Session, Cycle,  ERROR_CODE, Req Id,"
           "Local IP, Local Port, Remote IP, Remote Port, URL, Expected, Received\n");*/
    te_log_files->headers_printed = true;
}

void te_set_sys_limits()
{
    int status;
    struct rlimit rl;
    getrlimit (RLIMIT_NOFILE, &rl);
    rl.rlim_cur = USHRT_MAX;
    rl.rlim_max = USHRT_MAX;
    // Setting Max open files per process as 65535
    status = setrlimit (RLIMIT_NOFILE, &rl);
    if (status) {
        printf("Unable to set open files:%d error:%d. Run as sudo\n",
               USHRT_MAX, status);
        exit(1);
    }
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    status = setrlimit (RLIMIT_FSIZE, &rl);
    if (status) {
        printf("Unable to set max file size. error:%d. Run as sudo\n",
               status);
        exit(1);
    }
    /**AK: Keeps failing in Docker -- Need to fix it ASAP
    status = setrlimit (RLIMIT_CORE, &rl);
    if (status) {
        printf("Unable to set core file. error:%d. Run as sudo\n", status);
        exit(1);
    }*/
    status = setrlimit (RLIMIT_DATA, &rl);
    if (status) {
        printf("Unable to set data size. error:%d. Run as sudo\n", status);
        exit(1);
    }
    status = setrlimit (RLIMIT_STACK, &rl);
    if (status) {
        printf("Unable to set stack size. error:%d. Run as sudo\n", status);
        exit(1);
    }
    srand(time(NULL));
}

int te_make_sys_vq(int id)
{
    key_t q_key = ftok("/tmp", id);
    int q_id = msgget(q_key, 0666 | IPC_CREAT);
    if(q_id == -1)
    {
        perror("ftok");
        return -1;
    }
    return q_id;
}

void te_dump_metrics_timer_cb (uv_timer_t* timer) {
    if(!te_dump_stats(res_cfg, te_session_cfgs, false)) {
        eprint("Unable to Dump Stats!\n");
    }
}

void handle_signal(int sig)
{
    tprint("Got a signal %d\n", sig);
    uv_timer_stop(&dump_metrics_timer);
    if(!te_dump_stats(res_cfg, te_session_cfgs, true)) {
        eprint("Unable to Dump Stats!\n");
    }
    else {
        tprint("Stopping and dumping stats\n");
    }
    exit(0);
}

int main(int argc, char **argv)
{
    int opt;
    pid = getpid();
    te_set_sys_limits();
    loop = uv_default_loop();
    srand(time(NULL));

    metrics_enabled = false;
    memory_metrics_enabled = false;
    stats_timer = -1;
    tedp_profile = TCP;
    tedp_mode = CLIENT;
    bool got_opts = false, got_ip=false, got_cpu = false;

    while((opt = getopt(argc, argv, ":r:j:s:k:c:p:a:d:i:tmh")) != -1)
    {
        got_opts = true;
        switch(opt)
        {
            case 'i':
                // Mgmt IP
                strcpy(tedp_mgmt_ip_str, optarg);
                tedp_mgmt_ip = inet_addr(tedp_mgmt_ip_str);
                printf("tedp_mgmt_ip:%s, %d\n", tedp_mgmt_ip_str, tedp_mgmt_ip);
                got_ip = true;
                break;
            case 'c':
                // CPU in which the process is running
                // Compulsary in case of UDP to get the unique stream id
                pinned_cpu = atoi(optarg);
                printf("cpu:%d\n", pinned_cpu);
                got_cpu = true;
                break;
            case 'r':
                //Path to resource config
                strcpy(res_cfg_path, optarg);
                printf("res_cfg_path:%s\n", res_cfg_path);
                break;
            case 'j':
                //Hash of resource config
                strcpy(res_hash, optarg);
                printf("res_hash:%s\n", res_hash);
                break;
            case 's':
                //Path to session config
                strcpy(session_cfg_path, optarg);
                printf("session_cfg_path:%s\n", session_cfg_path);
                break;
            case 'k':
                //Hash of session config
                strcpy(ses_hash, optarg);
                printf("ses_hash:%s\n", ses_hash);
                break;
            case 'p':
                //Type of TEDP profile (TCP/UDP)
                if(strstr(optarg, "TCP"))
                    tedp_profile = TCP;
                else if(strstr(optarg, "UDP"))
                    tedp_profile = UDP;
                break;
            case 'a':
                //Type of TEDP mode (CLIENT/SERVER)
                if(strstr(optarg, "CLIENT"))
                    tedp_mode = CLIENT;
                else if(strstr(optarg, "SERVER"))
                    tedp_mode = SERVER;
                break;
            case 'd':
                //Interval to dump metrics
                stats_timer = atoi(optarg) * 1000;
                break;
            case 'm':
                //Is metrics enabled ?
                metrics_enabled = true;
                printf("metrics_enabled\n");
                break;
            case 't':
                //Is memory metrics enabled?
                memory_metrics_enabled = true;
                printf("memory_metrics_enabled\n");
                break;
            case 'h':
                goto print_helper;
        }
    }

    if(!got_opts) {
        printf("WRONG INPUT FORMAT:\n");
        print_helper:
            printf("Usage: %s [options] \n"
                "        -r resource_config         -- path to the resource configuration describing what traffic to send\n" \
                "        -j resource_config's-hash  -- hash/unique-identifier of the resource configuration\n" \
                "\n"\
                "        [-s session_config]        -- path to the session configuration describing how to send the traffic\n" \
                "                                   -- To be used only in case of CLIENT\n"
                "        [-k session_config's-hash] -- hash/unique-identifier of the session configuration\n" \
                "                                   -- To be used only in case of CLIENT\n"
                "\n"\
                "        [-p TCP/UDP]               -- profile of process\n"
                "                                   -- UDP / TCP\n" \
                "                                   -- defaults to `TCP`\n" \
                "\n"\
                "        [-a CLIENT/SERVER]         -- mode of the process\n" \
                "                                   -- CLIENT / SERVER\n" \
                "                                   -- defaults to `CLIENT`\n" \
                "\n"\
                "        [-c pinned-cpu]            -- cpu to which the process is pinnned to\n" \
                "                                   -- compulsary argument only in case of UDP CLIENT profile\n" \
                "\n"\
                "        [-i mgmt-ip]               -- management ip of the host\n"
                "                                   -- compulsary argument only in case of UDP profile, both CLIENT AND SERVER\n" \
                "\n"\
                "        [-d stats_dump_interval]   -- interval at which the collected metrics has to be dumped in seconds\n" \
                "                                   -- has to be used in conjuncture of options like [-m] and/or [-t]\n" \
                "                                   -- defaults to `NO` metrics dumping\n" \
                "\n"\
                "        [-m]                       -- to enable collection of metrics\n" \
                "                                   -- enabling this option doesn't collect metrics regarding memory utilization\n" \
                "                                   -- defaults to `NO` metrics collection\n" \
                "\n"\
                "        [-t]                       -- to enable collection of memory utilization metrics\n" \
                "                                   -- defaults to `NO` memory metrics collection\n",
                argv[0]);
            exit(-1);
    }

    if(tedp_profile == UDP) {
        // For UDP we need the IP of the local machine
        // It is used to generate unique stream ids which are unique for client
        // and is used by server in case if compiled to collect metrics from server end
        // Also we need the pinned cpu in case of UDP Client to generate stream ids
        if(tedp_mode == CLIENT) {
            if(!got_ip) {
                printf("Mgmt IP is compulsary if TEDP Client has to run in UDP mode\n");
                exit(-1);
            } if(!got_cpu) {
                printf("Pinned CPU is compulsary if TEDP Client has to run in UDP mode\n");
                exit(-1);
            }
        }

        if(metrics_enabled && tedp_mode == SERVER && !UDP_SERVER_VIP_END_METRICS && !got_ip) {
            printf("Mgmt IP is compulsary if TEDP UDP Server has to collect metrics from server " \
                "perspective\n");
            exit(-1);
        }
    }

    if(tedp_profile == TCP && tedp_mode == SERVER) {
        printf("te_dp works only as client for TCP. SERVER mode is not supported\n");
        exit(-1);
    }

    if(stats_timer <= 0 && (metrics_enabled || memory_metrics_enabled)) {
        printf("Metrics Dump option is compulsary if metrics/memory_metrics is enabled\n");
        exit(-1);
    }

    if(memory_metrics_enabled || metrics_enabled) {
        IPC_QUEUE_ID = te_make_sys_vq(pid);
        if(IPC_QUEUE_ID < 0)
        {
            printf("Unable to create SysVQ for pid=%d\n", pid);
            exit(1);
        }

        //Start Timer to collect stats
        uv_timer_init(loop, &dump_metrics_timer);
        uv_timer_start(&dump_metrics_timer, (uv_timer_cb)te_dump_metrics_timer_cb, stats_timer, stats_timer);
        signal(SIGINT, handle_signal);
    }

    init_te_dp(0);

    iprint(TE_TRACE, "%s: Going to loop\n",__FUNCTION__);
    uv_run(loop, UV_RUN_DEFAULT);
    tprint("loop over \n");
    te_cleanup_session_config();
    te_cleanup_resources();
    uv_loop_close(loop);
    return 0;
}
