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

#ifndef TE_STATS_COLLECTOR_H
#include "te_stats_collector.h"
#endif

/*
 * Helper Function to print and debug
 */
void print(string tag, vector<int> v)
{
    cout << tag << ": ";
    for(auto i=v.begin(); i!=v.end(); i++)
        cout << *i << " ";
    cout << endl;
}
void print(string tag, set<int> v)
{
    cout << tag << ": ";
    for(auto i=v.begin(); i!=v.end(); i++)
        cout << *i << " ";
    cout << endl;
}

void add_vip_or_memory_metric_at_level(json_object* vip_or_memory_metrics, json_object* metrics, \
    array<string, 3> map_key)
{
    const char* res_hash_c = (map_key[0]).c_str();
    const char* ses_hash_c = (map_key[1]).c_str();
    const char* vip_c = (map_key[2]).c_str();

        json_object *res_level, *ses_level;

    if(json_object_object_get_ex(vip_or_memory_metrics, res_hash_c, &res_level)) {
        if(json_object_object_get_ex(res_level, ses_hash_c, &ses_level)) {
            json_object_object_add(ses_level, vip_c, metrics);
        }
        else {
            ses_level = json_object_new_object();
            json_object_object_add(ses_level, vip_c, metrics);
            json_object_object_add(res_level, ses_hash_c, ses_level);
        }
    }
    else {
        ses_level = json_object_new_object();
        json_object_object_add(ses_level, vip_c, metrics);
        res_level = json_object_new_object();
        json_object_object_add(res_level, ses_hash_c, ses_level);
        json_object_object_add(vip_or_memory_metrics, res_hash_c, res_level);
    }
}

pair<json_object*, json_object*> te_get_vip_metrics(vector<int> q_id_vector)
{
    int ses_bucket_counter = 0, num_ses_buckets = 0;
    string res_hash, ses_hash, vip;
    bool got_metrics = false, got_bucket_metrics = false;

    json_object *vip_metric = json_object_new_object();
    json_object *ses_bucket_metric = json_object_new_object();
    json_object *metric, *metrics;
    const char* key_c;

    pair<double, double> stat_bucket_key;
    array<string, 3> vip_metric_key;
    map<array<string, 3>, map<string, double > > vip_stats;
    map<array<string, 3>, map<pair<double, double>, pair<int, double> > > bucket_stats;
    
    
    for(auto q_id = q_id_vector.begin(); q_id != q_id_vector.end(); ++q_id) {

        te_http_vip_metrics_msg_t vip_metric_msg;
        //Get the all the VIP metrics from q_id
        while(msgrcv(*q_id, &vip_metric_msg, HTTP_VIP_METRIC_MSG_SIZE, TE_HTTP_VIP_METRIC_IPC_MSG, \
            IPC_NOWAIT) != -1) {

            vip = vip_metric_msg.vip;
            res_hash = vip_metric_msg.res_hash;
            ses_hash = vip_metric_msg.ses_hash;
            vip_metric_key = {res_hash, ses_hash, vip};

            vip_stats[vip_metric_key]["sessions"]         += vip_metric_msg.http_stats.sessions;
            vip_stats[vip_metric_key]["connections"]      += vip_metric_msg.http_stats.connections;
            vip_stats[vip_metric_key]["good_connections"] += vip_metric_msg.http_stats.good_connections;
            vip_stats[vip_metric_key]["failed_connections"] += \
                                        vip_metric_msg.http_stats.failed_connections;
            vip_stats[vip_metric_key]["profile_type"]        = HTTP_PROFILE;

            //Get all bucket metrics from 
            num_ses_buckets = vip_metric_msg.num_buckets;
            for(ses_bucket_counter=0; ses_bucket_counter<num_ses_buckets; ses_bucket_counter++) {
                te_session_bucket_metrics_msg_t ses_bucket_metric_msg;
                if(msgrcv(*q_id, &ses_bucket_metric_msg, HTTP_VIP_BUCKET_METRIC_MSG_SIZE, \
                    TE_VIP_BUCKET_METRIC_IPC_MSG, IPC_NOWAIT) == -1) {
                    return {NULL, NULL};
                }
                else {
                    stat_bucket_key = {ses_bucket_metric_msg.http_stats.bucket_start_time,\
                                        ses_bucket_metric_msg.http_stats.bucket_end_time};
                    bucket_stats[vip_metric_key][stat_bucket_key].first += \
                                            ses_bucket_metric_msg.http_stats.bucket;
                    bucket_stats[vip_metric_key][stat_bucket_key].second += \
                                            ses_bucket_metric_msg.http_stats.total_time;
                }
            }
            got_metrics = true;
        }

        te_udp_client_vip_metrics_msg_t udp_vip_metric_msg;
        while(msgrcv(*q_id, &udp_vip_metric_msg, UDP_VIP_CLIENT_METRIC_MSG_SIZE, TE_UDP_CLIENT_VIP_METRIC_IPC_MSG, \
            IPC_NOWAIT) != -1) {

            vip      = udp_vip_metric_msg.vip;
            res_hash = udp_vip_metric_msg.res_hash;
            ses_hash = udp_vip_metric_msg.ses_hash;
            vip_metric_key = {res_hash, ses_hash, vip};

            vip_stats[vip_metric_key]["sessions"]           += udp_vip_metric_msg.udp_stats.sessions;
            vip_stats[vip_metric_key]["good_connections"]   += \
                        udp_vip_metric_msg.udp_stats.good_connections;
            vip_stats[vip_metric_key]["failed_connections"] += \
                        udp_vip_metric_msg.udp_stats.failed_connections;
            vip_stats[vip_metric_key]["profile_type"]        = UDP_CLIENT_PROFILE;
            got_metrics = true;
        }
    }

    for(auto i=vip_stats.begin(); i!=vip_stats.end(); i++) {
        metrics = json_object_new_object();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            key_c = (j->first).c_str();
            json_object_object_add(metrics, key_c, json_object_new_double(j->second));   
        }
        add_vip_or_memory_metric_at_level(vip_metric, metrics, i->first);
    }

    for(auto i=bucket_stats.begin(); i!=bucket_stats.end(); i++) {
        metrics = json_object_new_array();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            metric = json_object_new_object();
            json_object_object_add(metric, "start_time", \
                json_object_new_double(j->first.first));
            json_object_object_add(metric, "end_time", 
                json_object_new_double(j->first.second));
            json_object_object_add(metric, "bucket", \
                json_object_new_int(j->second.first));
            json_object_object_add(metric, "total_time", \
                json_object_new_double(j->second.second));
            json_object_array_add(metrics, metric);
        }
        add_vip_or_memory_metric_at_level(ses_bucket_metric, metrics, i->first);
        got_bucket_metrics = true;
    }

    if(got_metrics && got_bucket_metrics)
        return {vip_metric, ses_bucket_metric};
    else if(got_metrics)
        return {vip_metric, NULL};
    else
        return {NULL, NULL};
}

json_object* te_get_server_vip_metrics(vector<int> q_id_vector) {
    string vip;
    bool got_metrics = false;

    json_object *vip_metric = json_object_new_object();
    json_object *metrics;
    const char* key_c;
    map< string, map<string, double > > vip_stats;
    map< string, vector<te_mean_variance_t> > latency_stats;
    double mean, var;

    for(auto q_id = q_id_vector.begin(); q_id != q_id_vector.end(); ++q_id) {

        te_udp_server_vip_metrics_msg_t udp_vip_metric_msg;
        while(msgrcv(*q_id, &udp_vip_metric_msg, UDP_VIP_SERVER_METRIC_MSG_SIZE, TE_UDP_SERVER_VIP_METRIC_IPC_MSG, \
            IPC_NOWAIT) != -1) {

            vip = udp_vip_metric_msg.vip;

            if (vip_stats.find(vip) == vip_stats.end()) {
                vip_stats[vip]["min_latency"] = numeric_limits<double>::max();
                vip_stats[vip]["max_latency"] = 0;
            }

            vip_stats[vip]["dg_rcvd"]               += udp_vip_metric_msg.udp_stats.dg_rcvd;
            vip_stats[vip]["dg_recv_timedout"]      += udp_vip_metric_msg.udp_stats.dg_recv_timedout;
            vip_stats[vip]["dg_size_rcvd"]          += udp_vip_metric_msg.udp_stats.dg_size_rcvd;
            vip_stats[vip]["dg_sent"]               += udp_vip_metric_msg.udp_stats.dg_sent;
            vip_stats[vip]["dg_send_fail"]          += udp_vip_metric_msg.udp_stats.dg_send_fail;
            vip_stats[vip]["dg_size_sent"]          += udp_vip_metric_msg.udp_stats.dg_size_sent;
            vip_stats[vip]["request_rcvd"]          += udp_vip_metric_msg.udp_stats.request_rcvd;
            vip_stats[vip]["request_recv_timedout"] += udp_vip_metric_msg.udp_stats.request_recv_timedout;
            vip_stats[vip]["response_sent"]         += udp_vip_metric_msg.udp_stats.response_sent;
            vip_stats[vip]["response_send_fail"]    += udp_vip_metric_msg.udp_stats.response_send_fail;
            vip_stats[vip]["profile_type"]           = UDP_SERVER_PROFILE;
            got_metrics = true;

            if(udp_vip_metric_msg.udp_stats.request_rcvd != 0) {
                vip_stats[vip]["min_latency"] = min(vip_stats[vip]["min_latency"],
                                                    udp_vip_metric_msg.udp_stats.min_latency);
                vip_stats[vip]["max_latency"] = max(vip_stats[vip]["max_latency"],
                                                    udp_vip_metric_msg.udp_stats.max_latency);

                mean = udp_vip_metric_msg.udp_stats.sum_latency / udp_vip_metric_msg.udp_stats.request_rcvd;
                var = (udp_vip_metric_msg.udp_stats.sum_square_latency / udp_vip_metric_msg.udp_stats.request_rcvd) - \
                      (mean * mean);
                latency_stats[vip].push_back({udp_vip_metric_msg.udp_stats.request_rcvd, mean, var});
            } else if(vip_stats[vip]["max_latency"] == 0) {
                // No request is received for this VIP from this process
                // and the vip has not got any stats regarding latency so far,
                // so pop the dummp entry
                vip_stats[vip].erase("min_latency");
                vip_stats[vip].erase("max_latency");
            }
        }
    }

    //Latency Stats -- Dumping the mean and variance of latency
    double net_mean=0, denom=0, net_var=0;
    for(auto i=vip_stats.begin(); i!=vip_stats.end(); i++) {
        metrics = json_object_new_object();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            key_c = (j->first).c_str();
            json_object_object_add(metrics, key_c, json_object_new_double(j->second));
        }

        auto lat_stat_of_vip = latency_stats.find(vip);
        if(lat_stat_of_vip != latency_stats.end()){
            net_mean=0, denom=0, net_var=0;
            for(auto j=lat_stat_of_vip->second.begin(); j!=lat_stat_of_vip->second.end(); j++) {
                net_mean += j->mean * j->n;
                denom += j->n;
            }
            if(denom != 0) {
                net_mean /= denom;
                for(auto j=lat_stat_of_vip->second.begin(); j!=lat_stat_of_vip->second.end(); j++) {
                    net_var += j->n * ( ((j->mean - net_mean)*(j->mean - net_mean)) + j->var);
                }
                net_var /= denom;
                json_object_object_add(metrics, "mean_latency", json_object_new_double(net_mean));
                json_object_object_add(metrics, "var_latency", json_object_new_double(net_var));
            }
        }

        key_c = (i->first).c_str();
        json_object_object_add(vip_metric, key_c, metrics);
    }

    if(got_metrics)
        return vip_metric;
    else
        return NULL;
}

void add_uri_metric_at_level(json_object* url_metric, json_object* metric, array<string, 5> map_keys)
{
    const char* res_hash_c = ((map_keys)[0]).c_str();
    const char* ses_hash_c = ((map_keys)[1]).c_str();
    const char* vip_c = ((map_keys)[2]).c_str();
    const char* method_c = ((map_keys)[3]).c_str();
    const char* uri_c = ((map_keys)[4]).c_str();
    
    json_object *uri_level, *method_level, *vip_level, *ses_level, *res_level;

    if(json_object_object_get_ex(url_metric, res_hash_c, &res_level)) {
        if(json_object_object_get_ex(res_level, ses_hash_c, &ses_level)) {
            if(json_object_object_get_ex(ses_level, vip_c, &vip_level)) {
                if(json_object_object_get_ex(vip_level, method_c, &method_level)) {
                    if(json_object_object_get_ex(method_level, uri_c, &uri_level)) {
                        json_object_object_foreach(metric, key, val) {
                            json_object_object_add(uri_level, key, val);
                        }
                    }
                    else {
                        json_object_object_add(method_level, uri_c, metric);
                    }
                }
                else {
                    uri_level = json_object_new_object();
                    json_object_object_add(uri_level, uri_c, metric);
                    json_object_object_add(vip_level, method_c, uri_level);
                }
            }
            else {
                uri_level = json_object_new_object();
                json_object_object_add(uri_level, uri_c, metric);
                method_level = json_object_new_object();
                json_object_object_add(method_level, method_c, uri_level);
                json_object_object_add(ses_level, vip_c, method_level);
            }
        }
        else {
            uri_level = json_object_new_object();
            json_object_object_add(uri_level, uri_c, metric);
            method_level = json_object_new_object();
            json_object_object_add(method_level, method_c, uri_level);
            vip_level = json_object_new_object();
            json_object_object_add(vip_level, vip_c, method_level);
            json_object_object_add(res_level, ses_hash_c, vip_level);
        }
    }
    else {
        uri_level = json_object_new_object();
        json_object_object_add(uri_level, uri_c, metric);
        method_level = json_object_new_object();
        json_object_object_add(method_level, method_c, uri_level);
        vip_level = json_object_new_object();
        json_object_object_add(vip_level, vip_c, method_level);
        ses_level = json_object_new_object();
        json_object_object_add(ses_level, ses_hash_c, vip_level);
        json_object_object_add(url_metric, res_hash_c, ses_level);
        
    }
}

array<json_object*, 3> te_get_url_metrics(vector<int> q_id_vector)
{
    te_http_url_metrics_msg_t http_url_metric_msg;
    te_udp_url_metrics_msg_t  udp_url_metric_msg;

    te_url_bucket_metrics_msg_t url_bucket_metric_msg;
    te_error_metrics_msg_t error_metric_msg;
    int url_bucket_counter, num_url_buckets;
    int error_counter, num_error_buckets;
    bool got_metrics=false, got_bucket_metrics=false, got_error_metrics=false;
    string res_hash, ses_hash, vip, uri, method;
    const char* key_c;
    double mean=0, var=0;

    //RES_TAG => SES_TAG => VIP => METHOD => URI => (k,v)
    map<array<string, 5>, map<string, double> > url_stats;
    map<array<string, 5>, vector<te_mean_variance_t> > latency_stats;
    map<array<string, 5>, map<pair<double, double>, pair<int, double> > > bucket_stats;
    map<array<string, 5>, map<string, pair<pair<time_t, time_t>, int> > > error_stats;
    
    pair<double, double> url_bucket_key;
    array<string, 5> url_key;
    string error_key;
    
    json_object *url_metric = json_object_new_object();
    json_object *url_bucket_metric = json_object_new_object();
    json_object *error_metrics = json_object_new_object();
    json_object *metrics, *metric;

    //Iterate through all SysVQ to get URL metrics
    for(auto q_id = q_id_vector.begin(); q_id != q_id_vector.end(); ++q_id) {

        //Get the all the URL metrics from q_id
        while(msgrcv(*q_id, &http_url_metric_msg, HTTP_URL_METRIC_MSG_SIZE, TE_HTTP_URL_METRIC_IPC_MSG, \
            IPC_NOWAIT) != -1) {

            res_hash = http_url_metric_msg.res_hash;
            ses_hash = http_url_metric_msg.ses_hash;
            vip      = http_url_metric_msg.vip;
            method   = http_url_metric_msg.req_type;
            uri      = http_url_metric_msg.uri;
            url_key = {res_hash, ses_hash, vip, method, uri};

            if (url_stats.find(url_key) == url_stats.end()) {
                //Not Found
                url_stats[url_key]["min_time"] = numeric_limits<double>::max();
                url_stats[url_key]["max_time"] = numeric_limits<double>::min();
            }

            url_stats[url_key]["http_gets_sent"]  += http_url_metric_msg.http_stats.http_gets_sent;
            url_stats[url_key]["http_gets_rcvd"]  += http_url_metric_msg.http_stats.http_gets_rcvd;
            url_stats[url_key]["http_posts_sent"] += http_url_metric_msg.http_stats.http_posts_sent;
            url_stats[url_key]["http_posts_rcvd"] += http_url_metric_msg.http_stats.http_posts_rcvd;
            url_stats[url_key]["failed_reqs"]     += http_url_metric_msg.http_stats.failed_reqs;
            url_stats[url_key]["len_fail"]        += http_url_metric_msg.http_stats.len_fail;
            url_stats[url_key]["persist_fail"]    += http_url_metric_msg.http_stats.persist_fail;
            url_stats[url_key]["tcp_failures"]    += http_url_metric_msg.http_stats.tcp_failures;
            url_stats[url_key]["responses_1xx"]   += http_url_metric_msg.http_stats.responses_1xx;
            url_stats[url_key]["responses_200"]   += http_url_metric_msg.http_stats.responses_200;
            url_stats[url_key]["responses_2xx"]   += http_url_metric_msg.http_stats.responses_2xx;
            url_stats[url_key]["responses_3xx"]   += http_url_metric_msg.http_stats.responses_3xx;
            url_stats[url_key]["responses_4xx"]   += http_url_metric_msg.http_stats.responses_4xx;
            url_stats[url_key]["responses_404"]   += http_url_metric_msg.http_stats.responses_404;
            url_stats[url_key]["responses_5xx"]   += http_url_metric_msg.http_stats.responses_5xx;
            url_stats[url_key]["bytes_download"]  += http_url_metric_msg.http_stats.bytes_download;
            url_stats[url_key]["reqs_sent"]       += http_url_metric_msg.http_stats.reqs_sent;
            url_stats[url_key]["resp_rcvd"]       += http_url_metric_msg.http_stats.resp_rcvd;
            url_stats[url_key]["min_time"]         = min(url_stats[url_key]["min_time"],
                                                        http_url_metric_msg.http_stats.min_time);
            url_stats[url_key]["max_time"]         = max(url_stats[url_key]["max_time"],
                                                        http_url_metric_msg.http_stats.max_time);
            url_stats[url_key]["profile_type"]     = HTTP_PROFILE;

            if(http_url_metric_msg.http_stats.resp_rcvd != 0) {
                mean = http_url_metric_msg.http_stats.sum_latency / http_url_metric_msg.http_stats.resp_rcvd;
                var = (http_url_metric_msg.http_stats.sum_square_latency / http_url_metric_msg.http_stats.resp_rcvd) - \
                      (mean * mean);
                latency_stats[url_key].push_back({http_url_metric_msg.http_stats.resp_rcvd, mean, var});
            }
            
            num_url_buckets = http_url_metric_msg.num_buckets;
            num_error_buckets = http_url_metric_msg.num_error_buckets;
            for(url_bucket_counter=0; url_bucket_counter<num_url_buckets; url_bucket_counter++) {
                if(msgrcv(*q_id, &url_bucket_metric_msg, URL_BUCKET_METRIC_MSG_SIZE, \
                    TE_URL_BUCKET_METRIC_IPC_MSG, IPC_NOWAIT) == -1) {
                    return {NULL, NULL, NULL};
                }
                else {
                    url_bucket_key = {url_bucket_metric_msg.http_stats.bucket_start_time,\
                                        url_bucket_metric_msg.http_stats.bucket_end_time};
                    bucket_stats[url_key][url_bucket_key].first += \
                        url_bucket_metric_msg.http_stats.bucket;
                    bucket_stats[url_key][url_bucket_key].second += \
                        url_bucket_metric_msg.http_stats.total_time;
                }
                memset(&url_bucket_metric_msg, 0, sizeof(url_bucket_metric_msg));
            }

            for(error_counter=0; error_counter<num_error_buckets; error_counter++) {
                if(msgrcv(*q_id, &error_metric_msg, ERROR_METRIC_MSG_SIZE, \
                    TE_ERROR_METRIC_IPC_MSG, IPC_NOWAIT) == -1) {
                    return {NULL, NULL, NULL};
                }
                else {
                    error_key = error_metric_msg.error_name;
                    if(error_stats[url_key][error_key].first.first == 0) {
                        error_stats[url_key][error_key].first.first = \
                            numeric_limits<time_t>::max();
                    }
                    error_stats[url_key][error_key].first.first = \
                        min(error_stats[url_key][error_key].first.first, \
                        error_metric_msg.stats.start_time);
                    error_stats[url_key][error_key].first.second = \
                        max(error_stats[url_key][error_key].first.second, \
                        error_metric_msg.stats.end_time);
                    error_stats[url_key][error_key].second += error_metric_msg.stats.err_counter;
                }
                memset(&error_metric_msg, 0, sizeof(error_metric_msg));
            }
            memset(&http_url_metric_msg, 0, sizeof(http_url_metric_msg));
            got_metrics = true;
        }

        while(msgrcv(*q_id, &udp_url_metric_msg, UDP_URL_METRIC_MSG_SIZE, TE_UDP_URL_METRIC_IPC_MSG, \
            IPC_NOWAIT) != -1) {

            res_hash = udp_url_metric_msg.res_hash;
            ses_hash = udp_url_metric_msg.ses_hash;
            vip      = udp_url_metric_msg.vip;
            method   = udp_url_metric_msg.req_type;
            uri      = "";
            url_key = {res_hash, ses_hash, vip, method, uri};

            if (url_stats.find(url_key) == url_stats.end()) {
                //Not Found
                url_stats[url_key]["min_latency"] = numeric_limits<double>::max();
                url_stats[url_key]["max_latency"] = 0;
            }

            url_stats[url_key]["reqs_sent"]        += udp_url_metric_msg.udp_stats.reqs_sent;
            url_stats[url_key]["reqs_failed"]      += udp_url_metric_msg.udp_stats.reqs_failed;
            url_stats[url_key]["dg_sent"]          += udp_url_metric_msg.udp_stats.dg_sent;
            url_stats[url_key]["dg_size_sent"]     += udp_url_metric_msg.udp_stats.dg_size_sent;
            url_stats[url_key]["dg_send_fail"]     += udp_url_metric_msg.udp_stats.dg_send_fail;
            url_stats[url_key]["resp_recd"]        += udp_url_metric_msg.udp_stats.resp_recd;
            url_stats[url_key]["resp_timedout"]    += udp_url_metric_msg.udp_stats.resp_timedout;
            url_stats[url_key]["dg_recd"]          += udp_url_metric_msg.udp_stats.dg_recd;
            url_stats[url_key]["dg_size_recd"]     += udp_url_metric_msg.udp_stats.dg_size_recd;
            url_stats[url_key]["dg_recv_timedout"] += udp_url_metric_msg.udp_stats.dg_recv_timedout;
            url_stats[url_key]["profile_type"]      = UDP_CLIENT_PROFILE;

            if(udp_url_metric_msg.udp_stats.resp_recd != 0) {
                url_stats[url_key]["min_latency"]       = min(url_stats[url_key]["min_latency"],
                                                        udp_url_metric_msg.udp_stats.min_latency);
                url_stats[url_key]["max_latency"]       = max(url_stats[url_key]["max_latency"],
                                                        udp_url_metric_msg.udp_stats.max_latency);

                mean = udp_url_metric_msg.udp_stats.sum_latency / udp_url_metric_msg.udp_stats.resp_recd;
                var = (udp_url_metric_msg.udp_stats.sum_square_latency / udp_url_metric_msg.udp_stats.resp_recd) - \
                      (mean * mean);
                latency_stats[url_key].push_back({udp_url_metric_msg.udp_stats.resp_recd, mean, var});
            } else if(url_stats[url_key]["max_latency"] == 0) {
                // No response is received for this url_key from this process
                // and the url_key has not got any stats regarding latency so far,
                // so pop the dummp entry
                url_stats[url_key].erase("min_latency");
                url_stats[url_key].erase("max_latency");
            }

            got_metrics = true;
        }
    }

    for(auto i=url_stats.begin(); i!=url_stats.end(); i++) {
        metrics = json_object_new_object();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            key_c = (j->first).c_str();
            json_object_object_add(metrics, key_c, json_object_new_double(j->second));
        }
        add_uri_metric_at_level(url_metric, metrics, i->first);
    }

    //Latency Stats -- Dumping the mean and variance of latency
    double net_mean, net_var, denom;
    for(auto i=latency_stats.begin(); i!=latency_stats.end(); i++) {
        net_mean=0, denom=0, net_var=0;
        metrics = json_object_new_object();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            net_mean += j->mean * j->n;
            denom += j->n;
        }
        if(denom != 0) {
            net_mean /= denom;
            for(auto j=i->second.begin(); j!=i->second.end(); j++) {
                net_var += j->n * ( ((j->mean - net_mean)*(j->mean - net_mean)) + j->var);
            }
            net_var /= denom;
            json_object_object_add(metrics, "mean_latency", json_object_new_double(net_mean));
            json_object_object_add(metrics, "var_latency", json_object_new_double(net_var));
            add_uri_metric_at_level(url_metric, metrics, i->first);
        }
    }

    for(auto i=bucket_stats.begin(); i!=bucket_stats.end(); i++) {
        metrics = json_object_new_array();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            metric = json_object_new_object();
            json_object_object_add(metric, "start_time", json_object_new_double(j->first.first));
            json_object_object_add(metric, "end_time", json_object_new_double(j->first.second));
            json_object_object_add(metric, "bucket", json_object_new_int(j->second.first));
            json_object_object_add(metric, "total_time", json_object_new_double(j->second.second));
            json_object_array_add(metrics, metric);
        }
        add_uri_metric_at_level(url_bucket_metric, metrics, i->first);
        got_bucket_metrics = true;
    }

    for(auto i=error_stats.begin(); i!=error_stats.end(); i++) {
        metrics = json_object_new_object();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            metric = json_object_new_object();
            json_object_object_add(metric, "start_time", \
                json_object_new_string(ctime(&(j->second.first.first))));
            json_object_object_add(metric, "end_time", \
                json_object_new_string(ctime(&(j->second.first.second))));
            json_object_object_add(metric, "counter", \
                json_object_new_int(j->second.second));
            key_c = (j->first).c_str();
            json_object_object_add(metrics, key_c, metric);
        }
        add_uri_metric_at_level(error_metrics, metrics, i->first);
        got_error_metrics = true;
    }

    array<json_object*, 3> result_array;
    if(got_metrics) {
        result_array[0] = url_metric;
    } else {
        result_array[0] = NULL;
    }

    if(got_bucket_metrics) {
        result_array[1] = url_bucket_metric;
    } else {
        result_array[1] = NULL;
    }

    if(got_error_metrics) {
        result_array[2] = error_metrics;
    } else {
        result_array[2] = NULL;
    }

    return result_array;
}

json_object* te_get_memory_metrics(vector<int> q_id_vector)
{
    te_memory_metrics_msg_t memory_metric_msg;
    bool got_metrics = false;
    string res_hash, ses_hash, pid;
    json_object *metrics, *memory_metric = json_object_new_object();
    json_object *malloc_metric, *free_metric;
    array<string, 3> key;
    const char* key_c;
    vector<unsigned int> metric_array;

    //RES_TAG => SES_TAG => PID => (k,v)
    map<array<string, 3>, map<string, json_object*> > memory_stats;

    for(auto q_id = q_id_vector.begin(); q_id != q_id_vector.end(); ++q_id) {
        while(msgrcv(*q_id, &memory_metric_msg, MEMORY_METRIC_MSG_SIZE, \
            TE_MEMORY_METRIC_IPC_MSG, IPC_NOWAIT) != -1) {
            res_hash = memory_metric_msg.res_hash;
            ses_hash = memory_metric_msg.ses_hash;
            pid = to_string(memory_metric_msg.pid);
            key = {res_hash, ses_hash, pid};

            malloc_metric = json_object_new_array();
            free_metric = json_object_new_array();

            for (int counter=0; counter<MEMORY_TYPE_SIZE; counter++) {
                json_object_array_add(malloc_metric, \
                    json_object_new_int(memory_metric_msg.malloc_metric[counter]));
                json_object_array_add(free_metric, \
                    json_object_new_int(memory_metric_msg.free_metric[counter]));
            }

            memory_stats[key]["malloc_metric"] = malloc_metric;
            memory_stats[key]["free_metric"] = free_metric;

            got_metrics = true;
        }
    }

    for(auto i=memory_stats.begin(); i!=memory_stats.end(); i++) {
        metrics = json_object_new_object();
        for(auto j=i->second.begin(); j!= i->second.end(); j++) {
            key_c = (j->first).c_str();
            json_object_object_add(metrics, key_c, j->second);
        }
        add_vip_or_memory_metric_at_level(memory_metric, metrics, i->first);
    }

    if (got_metrics)
        return memory_metric;
    else
        return NULL;
}

json_object* te_get_ses_metrics(vector<int> q_id_vector)
{
    te_http_session_metrics_msg_t http_ses_metric_msg;
    te_udp_session_metrics_msg_t  udp_ses_metric_msg;
    map< pair<string, string>, map<string, double> > ses_stats;
    pair<string, string> key;
    json_object *ses_metric = json_object_new_object();
    json_object *metrics, *res_level;
    const char* key_c;
    bool got_metrics = false;
    string res_hash, ses_hash;
    const char *res_hash_c, *ses_hash_c;

    //Iterate through all SysVQ to get VIP metrics
    for(auto q_id = q_id_vector.begin(); q_id != q_id_vector.end(); ++q_id) {

        //Get all the HTTP SES metrics from q_id
        while(msgrcv(*q_id, &http_ses_metric_msg, HTTP_SES_CFG_METRIC_MSG_SIZE, \
            TE_HTTP_SES_CFG_METRIC_IPC_MSG, IPC_NOWAIT) != -1) {
            res_hash = http_ses_metric_msg.res_hash;
            ses_hash = http_ses_metric_msg.ses_hash;
            key = {res_hash, ses_hash};
            ses_stats[key]["sessions"]          += http_ses_metric_msg.http_stats.num_sessions;
            ses_stats[key]["open_connections"]  += http_ses_metric_msg.http_stats.open_connections;
            ses_stats[key]["total_connections"] += http_ses_metric_msg.http_stats.total_connections;
            ses_stats[key]["cycles_complete"]   += http_ses_metric_msg.http_stats.cycles_complete;
            ses_stats[key]["reqs_sent"]         += http_ses_metric_msg.http_stats.reqs_sent;
            ses_stats[key]["resp_rcvd"]         += http_ses_metric_msg.http_stats.resp_rcvd;
            ses_stats[key]["http_gets_sent"]    += http_ses_metric_msg.http_stats.http_gets_sent;
            ses_stats[key]["http_gets_rcvd"]    += http_ses_metric_msg.http_stats.http_gets_rcvd;
            ses_stats[key]["http_posts_sent"]   += http_ses_metric_msg.http_stats.http_posts_sent;
            ses_stats[key]["http_posts_rcvd"]   += http_ses_metric_msg.http_stats.http_posts_rcvd;
            ses_stats[key]["failed_reqs"]       += http_ses_metric_msg.http_stats.failed_reqs;
            ses_stats[key]["len_fail"]          += http_ses_metric_msg.http_stats.len_fail;
            ses_stats[key]["persist_fail"]      += http_ses_metric_msg.http_stats.persist_fail;
            ses_stats[key]["post_fnf"]          += http_ses_metric_msg.http_stats.post_fnf;
            ses_stats[key]["bytes_download"]    += http_ses_metric_msg.http_stats.bytes_download;
            ses_stats[key]["complete_time"]     += http_ses_metric_msg.http_stats.complete_time;
            ses_stats[key]["profile_type"]       = HTTP_PROFILE;

            got_metrics = true;
        }

        //Get all the UDP SES metrics from q_id
        while(msgrcv(*q_id, &udp_ses_metric_msg, UDP_SES_CFG_METRIC_MSG_SIZE, \
            TE_UDP_SES_CFG_METRIC_IPC_MSG, IPC_NOWAIT) != -1) {
            res_hash = udp_ses_metric_msg.res_hash;
            ses_hash = udp_ses_metric_msg.ses_hash;
            key = {res_hash, ses_hash};

            ses_stats[key]["sessions"]           += udp_ses_metric_msg.udp_stats.num_sessions;
            ses_stats[key]["cycles_complete"]    += udp_ses_metric_msg.udp_stats.cycles_complete;
            ses_stats[key]["good_connections"]   += udp_ses_metric_msg.udp_stats.good_connections;
            ses_stats[key]["failed_connections"] += udp_ses_metric_msg.udp_stats.failed_connections;

            ses_stats[key]["reqs_sent"]          += udp_ses_metric_msg.udp_stats.reqs_sent;
            ses_stats[key]["reqs_failed"]        += udp_ses_metric_msg.udp_stats.reqs_failed;
            ses_stats[key]["dg_sent"]            += udp_ses_metric_msg.udp_stats.dg_sent;
            ses_stats[key]["dg_size_sent"]       += udp_ses_metric_msg.udp_stats.dg_size_sent;
            ses_stats[key]["dg_send_fail"]       += udp_ses_metric_msg.udp_stats.dg_send_fail;

            ses_stats[key]["resp_recd"]          += udp_ses_metric_msg.udp_stats.resp_recd;
            ses_stats[key]["resp_timedout"]      += udp_ses_metric_msg.udp_stats.resp_timedout;
            ses_stats[key]["dg_recd"]            += udp_ses_metric_msg.udp_stats.dg_recd;
            ses_stats[key]["dg_size_recd"]       += udp_ses_metric_msg.udp_stats.dg_size_recd;
            ses_stats[key]["dg_recv_timedout"]   += udp_ses_metric_msg.udp_stats.dg_recv_timedout;
            ses_stats[key]["profile_type"]        = UDP_CLIENT_PROFILE;

            got_metrics = true;
        }
        
    }

    for(auto i=ses_stats.begin(); i!=ses_stats.end(); i++) {
        metrics = json_object_new_object();
        for(auto j=i->second.begin(); j!=i->second.end(); j++) {
            key_c = (j->first).c_str();
            json_object_object_add(metrics, key_c, json_object_new_double(j->second));
        }
        res_hash_c = (i->first.first).c_str();
        ses_hash_c = (i->first.second).c_str();
        if(json_object_object_get_ex(ses_metric, res_hash_c, &res_level)) {
            json_object_object_add(res_level, ses_hash_c, metrics);
        }
        else {
            res_level = json_object_new_object();
            json_object_object_add(res_level, ses_hash_c, metrics);
            json_object_object_add(ses_metric, res_hash_c, res_level);
        }
    }

    if(got_metrics)
        return ses_metric;
    else
        return NULL;
}

vector<int> te_get_process_finished(vector<int> q_id_vector) {
    vector<int> finished_processes;
    te_proc_finished_msg_t proc_finished_msg;
    for(auto q_id = q_id_vector.begin(); q_id != q_id_vector.end(); ++q_id) {
        if(msgrcv(*q_id, &proc_finished_msg, PROC_FINISHED_MSG_SIZE, \
            TE_PROC_FINISHED_IPC_MSG, IPC_NOWAIT) != -1) {
            finished_processes.push_back(*q_id);
        }
    }
    return finished_processes;
}

/* For Future Enhancements of making the stat collector stateless
 * Use share memory to keep the pid of processes
 * Pgrep for active processes
 * Use SHM queues to get the active processes
 */
int create_or_bind_to_shmid(int token_id, size_t size_of_shm)
{
    //Please Refer: https://stackoverflow.com/a/22262955

    key_t tKey = ftok("/dev/null", token_id);
    if (tKey == -1)  {
        cerr << "ERROR: ftok(id: " << token_id << ") failed, " << strerror(errno) << endl;
        exit(1);
    }

    int id = shmget(tKey, size_of_shm, 0);
    if (id == -1)  {
        cout << "Unable to find an existing shm, will try to create one" << endl;
        id = shmget(tKey, size_of_shm, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH | IPC_CREAT);
        if (id == -1)  {
            cerr << "ERROR: shmget() failed, " << strerror(errno) << endl;
            exit(1);
        }
    }
    cout << "Attached to SHM ID=" << id << endl;
    return id;
}

vector<int> get_active_tedp() {

    string cmd = "pgrep te_dp 2>&1";
    string data;
    vector<int> pid_vector;

    FILE * stream;
    char buffer[TEDP_MAX_STR_LEN];
    char *token;

    //Get the string of PID
    stream = popen(cmd.c_str(), "r");
    if (stream) {
        while (!feof(stream))
        {
            if (fgets(buffer, TEDP_MAX_STR_LEN, stream) != NULL) {
                data.append(buffer);
            }
        }
        pclose(stream);
    }
    token = strtok((char*)data.c_str(), "\n");

    //Convert the PID string to PID vector
    while (token != NULL) {
        pid_vector.push_back(strtol(token, NULL, 10));
        token = strtok(NULL, "\n");
    }
    return pid_vector;
}

vector<int> get_newly_spawned_tedp_from_sysvq(int q_id) {
    te_pid_t pid_msg;
    vector<int> pid_vector;
    while(msgrcv(q_id, &pid_msg, PID_MSG_SIZE, 0, IPC_NOWAIT) != -1) {
        pid_vector.push_back(atoi(pid_msg.pid));
    }   
    return pid_vector;
}

vector<int> get_queue_from_pid(set<int> pid_set)
{
    vector<int> qid_set;
    int q_id;
    key_t q_key;
    for(auto it=pid_set.begin(); it!=pid_set.end(); it++) {
        q_key = ftok("/tmp", *it);
        q_id = msgget(q_key, 0666 | IPC_CREAT | IPC_EXCL);
        if(q_id == -1) {
            q_id = msgget(q_key, 0666 | IPC_CREAT);
            if(q_id == -1) {
                perror("ftok"); 
            }
            else {
                qid_set.push_back(q_id);
            }
        }
    }
    return qid_set;
}

int create_or_bind_to_sysvq(int id)
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

void stat_collector_thread(zmq::socket_t *socket, vector<int> &active_tedp_in_last_run, \
    int te_work_q_id, int nproc, const char* host_ip) {

    //Metics Basics
    int serialized_metrics_len;
    const char* serialized_metrics;

    //Get information regarding currently active, dead and crashed te_dps
    vector<int> newly_spawned_tedp = get_newly_spawned_tedp_from_sysvq(te_work_q_id);
    vector<int> active_pid_vector = get_active_tedp();
    vector<int> dead_tedp(nproc*3);
    set<int> tedp_to_collect_stats_from;
    vector<int>::iterator it;

    //Dead te_dp by diff
    it = set_difference(newly_spawned_tedp.begin(), newly_spawned_tedp.end(),\
        active_pid_vector.begin(), active_pid_vector.end(), \
        dead_tedp.begin());
    dead_tedp.resize(it - dead_tedp.begin());

    //List of tedps to collect the http_stats from
    tedp_to_collect_stats_from.insert(active_pid_vector.begin(), active_pid_vector.end());
    tedp_to_collect_stats_from.insert(newly_spawned_tedp.begin(), newly_spawned_tedp.end());
    tedp_to_collect_stats_from.insert(active_tedp_in_last_run.begin(), \
        active_tedp_in_last_run.end());

    //Get the corresponding q_id of the p_id to collect http_stats from
    vector<int> q_id_vector = get_queue_from_pid(tedp_to_collect_stats_from);
    active_tedp_in_last_run = active_pid_vector;

    json_object* metrics = json_object_new_object();
    bool got_stats = false;

    //VIP METRICS
    pair<json_object*, json_object*> vip_metrics = te_get_vip_metrics(q_id_vector);
    if(vip_metrics.first) {
        json_object_object_add(metrics, "vip_metrics", vip_metrics.first);
        got_stats = true;
    }
    if(vip_metrics.second) {
        json_object_object_add(metrics, "ses_bucket_metrics", vip_metrics.second);
        got_stats = true;
    }

    //SERVER VIP METRICS
    json_object* server_vip_metrics = te_get_server_vip_metrics(q_id_vector);
    if(server_vip_metrics) {
        json_object_object_add(metrics, "server_vip_metrics", server_vip_metrics);
        got_stats = true;
    }

    //URL METRICS
    array<json_object*, 3> url_metrics = te_get_url_metrics(q_id_vector);
    if(url_metrics[0]) {
        json_object_object_add(metrics, "url_metrics", url_metrics[0]);
        got_stats = true;
    }
    if(url_metrics[1]) {
        json_object_object_add(metrics, "url_bucket_metrics", url_metrics[1]);
        got_stats = true;
    }
    if(url_metrics[2]) {
        json_object_object_add(metrics, "error_metrics", url_metrics[2]);
        got_stats = true;
    }

    //SESSION METRICS
    json_object* ses_metrics = te_get_ses_metrics(q_id_vector);
    if(ses_metrics) {
        json_object_object_add(metrics, "ses_metrics", ses_metrics);
        got_stats = true;
    }

    //MEMORY METRICS
    json_object* memory_metrics = te_get_memory_metrics(q_id_vector);
    if(memory_metrics) {
        json_object_object_add(metrics, "memory_metrics", memory_metrics);
        got_stats = true;
    }

    vector<int> finished_processes = te_get_process_finished(q_id_vector);

    if(got_stats) {
        auto timenow = chrono::system_clock::to_time_t(chrono::system_clock::now());
        json_object_object_add(metrics, "ts", json_object_new_string(ctime(&timenow)));
        json_object_object_add(metrics, "host_ip", json_object_new_string(host_ip));
        serialized_metrics = json_object_to_json_string(metrics);
        cout <<  serialized_metrics << endl;
        serialized_metrics_len = strlen(serialized_metrics);
        zmq::message_t request(serialized_metrics_len);
        memcpy(request.data(), serialized_metrics, serialized_metrics_len);
        socket->send(request);
    }

    if(!newly_spawned_tedp.empty())
        print("newly_spawned_tedp", newly_spawned_tedp);
    if(!active_pid_vector.empty())
        print("active_pid_vector", active_pid_vector);
    if(!dead_tedp.empty())
        print("dead_tedp", dead_tedp);
    if(!tedp_to_collect_stats_from.empty())
        print("tedp_to_collect_stats_from", tedp_to_collect_stats_from);
    if(!active_tedp_in_last_run.empty())
        print("Current Active TE_DP", active_tedp_in_last_run);
    if(!finished_processes.empty())
        print("finished_process", finished_processes);
    cout << endl << endl;
}

void stats_collector_caller(int stats_every, string te_ip, string te_zmq_port, const char* host_ip)
{
    zmq::context_t context(1);
    zmq::socket_t socket(context, ZMQ_PUSH);
    string tcp_socket_to_connect = "tcp://" + te_ip + ":" + te_zmq_port;
    socket.connect(tcp_socket_to_connect);
    int te_work_q_id = create_or_bind_to_sysvq(1);
    int nproc = get_nprocs();
    vector<int> active_tedp_in_last_run;
    while(1) {
        stat_collector_thread(&socket, active_tedp_in_last_run, te_work_q_id, nproc, host_ip);
        this_thread::sleep_for(chrono::seconds(stats_every));
    }
}

int main(int argc, char** argv)
{
    //TE_WORK process will send the spawned te_dp's PID in SysVQ 1
    if(argc != 2) {
        cout << "Improper argument! Run as `" << argv[0] << " <path_to_stat_collector_config>`" << \
            endl;
        exit(1);
    }

    freopen("/tmp/te_stats_collector_output.log","w",stdout);
    freopen("/tmp/te_stats_collector_error.log","w",stderr);

    ifstream f(argv[1]);
    if (!f.good()) {
        cerr << "No I/P files" << endl;
        exit(-1);
    }

    json_object *jobj;
    json_object *root = json_object_from_file(argv[1]);
    int stats_every = 15, zmq_port;
    string te_ip, te_zmq_port, host_ip, stats_every_s;

    if (json_object_object_get_ex(root, "te_ip", &jobj)) {
        te_ip = json_object_get_string(jobj);
        cout << te_ip << endl;
    } else {
        cerr << "Missing te_ip in the config";
        exit(-1);
    }

    if (json_object_object_get_ex(root, "my_ip", &jobj)) {
        host_ip = json_object_get_string(jobj);
        cout << host_ip << endl;
    } else {
        cerr << "Missing my_ip in the config";
        exit(-1);
    }

    if (json_object_object_get_ex(root, "te_zmq_port", &jobj)) {
        int val_type = json_object_get_type(jobj);
        switch (val_type) {
            case json_type_int:
                zmq_port = json_object_get_int(jobj);
                te_zmq_port = to_string(zmq_port);
                break;
            case json_type_string:
                te_zmq_port = json_object_get_string(jobj);
                break;
        }
        cout << te_zmq_port << endl;
    } else {
        cerr << "Missing te_zmq_port in the config";
        exit(-1);
    }

    if (json_object_object_get_ex(root, "collect_every", &jobj)) {
        int val_type = json_object_get_type(jobj);
        switch (val_type) {
            case json_type_int:
                stats_every = json_object_get_int(jobj);
                break;
            case json_type_string:
                stats_every_s = json_object_get_string(jobj);
                stats_every = stoi(stats_every_s);
                break;
        }
        cout << stats_every << endl;
    }

    thread thr(stats_collector_caller, stats_every, te_ip, te_zmq_port, host_ip.c_str());
    thr.join();
}
