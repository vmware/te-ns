#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <stdbool.h>

#ifndef TE_METRICS_H
#include "te_metrics.h"
#endif

extern int IPC_QUEUE_ID;
extern tedp_profile_t tedp_profile;
extern tedp_mode_t tedp_mode;
extern char tedp_mgmt_ip_str[TEDP_MAX_STR_LEN];
extern te_server_metrics_hash_table_t te_server_metrics_hash_table;

bool post_order_dump_and_free(te_error_metrics_t* node) {

    //If nothing to dump return true
    if(node == NULL)
        return true;

    //Traverse left and right of the tree
    bool left_bool=true, right_bool=true, return_value=true;

    left_bool = post_order_dump_and_free(node->left);
    node->left = NULL;
    right_bool = post_order_dump_and_free(node->right);
    node->right = NULL;

    //Dump metrics in the current node and collect dump success status
    te_error_metrics_msg_t error_metric_msg;
    error_metric_msg.stats = *node;
    error_metric_msg.type = TE_ERROR_METRIC_IPC_MSG;
    snprintf(error_metric_msg.error_name, strlen(node->error_name)+1, "%s", node->error_name);
    if(msgsnd(IPC_QUEUE_ID, &error_metric_msg, ERROR_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
        eprint("Metrics Dump failed at post_order_dump_and_free\n");
        return_value = false;
    }
    else {
        return_value = left_bool && right_bool;
    }

    //Free the node
    te_free(node->error_name, TE_MTYPE_CHAR);
    node->error_name = NULL;
    te_free(node, TE_MTYPE_ERROR_METRICS);
    node = NULL;
    return return_value;
}

bool __dump_error_metrics(te_error_metrics_t** error_metrics) {
    int i;
    bool return_value = true;
    for(i=0; i<NUM_TYPES_OF_ERR; i++) {
        if(!post_order_dump_and_free(error_metrics[i])) {
            eprint("Metrics Dump failed at error_metrics\n");
            return_value = false;
        }
        error_metrics[i] = NULL;
    }
    return return_value;
}

bool __dump_http_url_metrics(te_http_url_metrics_t* url_metrics, te_request_object_t* request_list, \
int num_requests, char* vip, char* req_type)
{
    unsigned int i, bucket_iter;
    char *uri;
    te_http_url_metrics_msg_t url_metric_msg;
    te_url_bucket_metrics_msg_t bucket_metric_msg;

    for (i = 0; i < num_requests; i++) {
        uri = request_list[i].request_uri.uri;
        if(uri && url_metrics[i].stats_present) {
            url_metric_msg.type = TE_HTTP_URL_METRIC_IPC_MSG;
            url_metric_msg.http_stats = url_metrics[i].url_stats;
            url_metric_msg.num_buckets = url_metrics[i].num_url_buckets;
            url_metric_msg.num_error_buckets = url_metrics[i].num_error_buckets;
            snprintf(url_metric_msg.vip, (int)strlen(vip)+1, "%s", vip);
            snprintf(url_metric_msg.uri, (int)strlen(uri)+1, "%s", uri);
            snprintf(url_metric_msg.req_type, (int)strlen(req_type)+1, "%s", req_type);
            snprintf(url_metric_msg.res_hash, (int)strlen(res_hash)+1, "%s", res_hash);
            snprintf(url_metric_msg.ses_hash, (int)strlen(ses_hash)+1, "%s", ses_hash);

            if(msgsnd(IPC_QUEUE_ID, &url_metric_msg, HTTP_URL_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
                eprint("Metrics Dump failed at http_url_metric_msg\n");
                return false;
            }

            for (bucket_iter = 0; bucket_iter < url_metrics[i].num_url_buckets; bucket_iter++) {
                bucket_metric_msg.http_stats = url_metrics[i].url_buckets[bucket_iter];
                bucket_metric_msg.type = TE_URL_BUCKET_METRIC_IPC_MSG;

                if(msgsnd(IPC_QUEUE_ID, &bucket_metric_msg, URL_BUCKET_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
                    eprint("Metrics Dump failed at http_url_bucket_metric_msg\n");
                    return false;
                }

                url_metrics[i].url_buckets[bucket_iter].total_time = 0;
                url_metrics[i].url_buckets[bucket_iter].bucket = 0;
            }


            if(!__dump_error_metrics(url_metrics[i].error_metrics))
                return false;

            memset(&(url_metrics[i].url_stats), 0, sizeof(te_http_url_stats_t));
            url_metrics[i].stats_present = false;
            url_metrics[i].num_error_buckets = 0;
        }
    }
    return true;
}

bool te_dump_vip_metrics(te_resource_config_t* res_cfg) {

    bool (*dump_vip_metrics)(te_resource_config_t* res_cfg);

    switch(tedp_profile) {
        case TCP: {
            dump_vip_metrics = dump_tcp_vip_metics;
        } break;

        case UDP: {
            switch(tedp_mode) {
                case CLIENT: {
                    dump_vip_metrics = dump_udp_client_vip_metics;
                } break;

                case SERVER: {
                    dump_vip_metrics = dump_udp_server_vip_metics;
                } break;

                default: {
                    eprint("Unknown TEDP_MODE=%d\n", tedp_mode);
                    abort();
                } break;
            }
        } break;

        default: {
            eprint("Unknown TEDP_PROFILE=%d\n", tedp_profile);
            abort();
        }
    }

    return dump_vip_metrics(res_cfg);
}

bool dump_tcp_vip_metics(te_resource_config_t* res_cfg) {

    te_http_vip_metrics_msg_t vip_metric_msg;
    te_session_bucket_metrics_msg_t bucket_metric_msg;
    unsigned int vip_iter = 0, bucket_iter = 0;
    int num_get_requests, num_post_requests;
    int get_prof_index, post_prof_index;
    short number_of_bucket_stats;
    char* vip;

    for (vip_iter = 0; vip_iter < res_cfg->total_vips; vip_iter++) {
        if(!res_cfg->http_vip_metrics[vip_iter].stats_present) {
            // Nothing to dump, continue
            continue;
        }
        number_of_bucket_stats = res_cfg->http_vip_metrics[vip_iter].num_session_buckets;
        vip = res_cfg->vips[vip_iter].vip;
        get_prof_index = res_cfg->vips[vip_iter].get_profile_index;
        post_prof_index = res_cfg->vips[vip_iter].post_profile_index;
        vip_metric_msg.type = TE_HTTP_VIP_METRIC_IPC_MSG;
        vip_metric_msg.http_stats = res_cfg->http_vip_metrics[vip_iter].vip_stats;
        vip_metric_msg.num_buckets = number_of_bucket_stats;
        snprintf(vip_metric_msg.vip, (int)strlen(vip)+1, "%s", vip);
        snprintf(vip_metric_msg.res_hash, (int)strlen(res_hash)+1, "%s", res_hash);
        snprintf(vip_metric_msg.ses_hash, (int)strlen(ses_hash)+1, "%s", ses_hash);

        if(msgsnd(IPC_QUEUE_ID, &vip_metric_msg, HTTP_VIP_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
            eprint("Metrics Dump failed at http_vip_metric_msg\n");
            return false;
        }


        for (bucket_iter = 0; bucket_iter < number_of_bucket_stats; bucket_iter++) {

            bucket_metric_msg.http_stats = res_cfg->http_vip_metrics[vip_iter].session_buckets[bucket_iter];
            bucket_metric_msg.type = TE_VIP_BUCKET_METRIC_IPC_MSG;

            if(msgsnd(IPC_QUEUE_ID, &bucket_metric_msg, HTTP_VIP_BUCKET_METRIC_MSG_SIZE, \
                IPC_NOWAIT) == -1) {
                eprint("Metrics Dump failed at http_vip_bucket_metric_msg\n");
                return false;
            }

            //Clean after send
            res_cfg->http_vip_metrics[vip_iter].session_buckets[bucket_iter].total_time = 0;
            res_cfg->http_vip_metrics[vip_iter].session_buckets[bucket_iter].bucket = 0;
        }

        num_get_requests = res_cfg->http_vip_metrics[vip_iter].num_url_get_metrics;
        if(num_get_requests) {
            if(!__dump_http_url_metrics(res_cfg->http_vip_metrics[vip_iter].url_get_metrics, \
                res_cfg->greqs[get_prof_index], num_get_requests, vip, "GET")) {
                eprint("Metrics Dump failed at http_url_get_metrics\n");
                return false;
            }
        }

        num_post_requests = res_cfg->http_vip_metrics[vip_iter].num_url_post_metrics;
        if(num_post_requests) {
            if(!__dump_http_url_metrics(res_cfg->http_vip_metrics[vip_iter].url_post_metrics, \
                res_cfg->preqs[post_prof_index], num_post_requests, vip, "POST")) {
                eprint("Metrics Dump failed at http_url_post_metrics\n");
                return false;
            }
        }

        memset(&(res_cfg->http_vip_metrics[vip_iter].vip_stats), 0, sizeof(te_http_vip_stats_t));
        res_cfg->http_vip_metrics[vip_iter].stats_present = false; //Resetting the stats_present
    }
    return true;
}

bool dump_udp_server_vip_metics(te_resource_config_t* res_cfg) {
    #if(UDP_SERVER_VIP_END_METRICS)
        unsigned int size = te_server_metrics_hash_table.size;
        te_vip_end_metrics_node_t *server_metrics_node = NULL;

        // ( (3<one part of ip> + 1 <dot>) * 4<parts of ip> -  1<last part doesn't have dot>)
        //  + 5<max port size>
        unsigned int len_of_vip = 20;

        for(int i=0; i<size; ++i) {
            // Walk through each of the hash of the table
            server_metrics_node = te_server_metrics_hash_table.buckets[i].head;

            while(server_metrics_node != NULL) {
                if(server_metrics_node->stats_present) {
                    // Walk through each of the node in that hash if stats is present

                    te_udp_server_vip_metrics_msg_t vip_metric_msg;
                    vip_metric_msg.type = TE_UDP_SERVER_VIP_METRIC_IPC_MSG;
                    vip_metric_msg.udp_stats = server_metrics_node->vip_end_metrics;
                    snprintf(vip_metric_msg.vip, len_of_vip, "%i.%i.%i.%i:%hu", \
                        server_metrics_node->vip & 0xFF, (server_metrics_node->vip >> 8) & 0xFF,
                        (server_metrics_node->vip >> 16) & 0xFF, (server_metrics_node->vip >> 24) & 0xFF, \
                        ntohs(server_metrics_node->vport));

                    if(msgsnd(IPC_QUEUE_ID, &vip_metric_msg, UDP_VIP_SERVER_METRIC_MSG_SIZE, \
                        IPC_NOWAIT) == -1) {
                        eprint("Metrics Dump failed at dump_udp_server_vip_metics\n");
                        return false;
                    }

                    // Flush the metrics
                    memset(&server_metrics_node->vip_end_metrics, 0, sizeof(udp_server_metrics_t));
                    server_metrics_node->stats_present = false;
                    server_metrics_node->vip_end_metrics.min_latency = DBL_MAX;
                    server_metrics_node->vip_end_metrics.max_latency = 0;
                }
                // Move to next node
                server_metrics_node = server_metrics_node->next;
            }
        }
    #else
        te_udp_listen_handle_t udp_listen_handle;
        for (int i=0; i<res_cfg->num_udp_listen_handle; ++i) {
            udp_listen_handle = res_cfg->udp_listen_handle[i];
            if(udp_listen_handle.stats.present) {

                te_udp_server_vip_metrics_msg_t vip_metric_msg;
                vip_metric_msg.type = TE_UDP_SERVER_VIP_METRIC_IPC_MSG;
                vip_metric_msg.stats = udp_listen_handle.server_end_metrics;
                snprintf(vip_metric_msg.vip, len_of_vip, "%s:%d", tedp_mgmt_ip_str, \
                    udp_listen_handle.port);

                if(msgsnd(IPC_QUEUE_ID, &vip_metric_msg, UDP_VIP_SERVER_METRIC_MSG_SIZE, \
                    IPC_NOWAIT) == -1) {
                    eprint("Metrics Dump failed at dump_udp_server_vip_metics\n");
                    return false;
                }

                // Flush the metrics
                memset(&udp_listen_handle.server_end_metrics, 0, sizeof(udp_server_metrics_t));
                udp_listen_handle.stats_present = false;
                udp_listen_handle.server_end_metrics.max_latency = 0;
                udp_listen_handle.server_end_metrics.min_latency = DBL_MAX;
            }
        }
    #endif

    return true;
}

bool __dump_udp_url_metrics(te_udp_url_metrics_t *url_stats, char* vip, char* req_type)
{
    te_udp_url_metrics_msg_t url_metric_msg;
    url_metric_msg.type = TE_UDP_URL_METRIC_IPC_MSG;
    url_metric_msg.udp_stats = *url_stats;
    snprintf(url_metric_msg.vip, (int)strlen(vip)+1, "%s", vip);
    snprintf(url_metric_msg.req_type, (int)strlen(req_type)+1, "%s", req_type);
    snprintf(url_metric_msg.res_hash, (int)strlen(res_hash)+1, "%s", res_hash);
    snprintf(url_metric_msg.ses_hash, (int)strlen(ses_hash)+1, "%s", ses_hash);

    if(msgsnd(IPC_QUEUE_ID, &url_metric_msg, UDP_URL_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
        eprint("Metrics Dump failed at __dump_udp_url_metrics\n");
        return false;
    }
    return true;
}

bool dump_udp_client_vip_metics(te_resource_config_t* res_cfg) {
    unsigned int vip_iter = 0;
    char* vip;
    unsigned short vport;

    for (vip_iter = 0; vip_iter < res_cfg->total_vips; vip_iter++) {
        te_udp_client_vip_metrics_msg_t vip_metric_msg;
        if(!res_cfg->udp_vip_metrics[vip_iter].stats_present) {
            // Nothing to dump, continue
            continue;
        }
        vip = res_cfg->vips[vip_iter].vip;
        vport = res_cfg->vips[vip_iter].vport;
        vip_metric_msg.type = TE_UDP_CLIENT_VIP_METRIC_IPC_MSG;
        vip_metric_msg.udp_stats = res_cfg->udp_vip_metrics[vip_iter].udp_vip_stats;

        snprintf(vip_metric_msg.vip, (int)strlen(vip)+5+1, "%s:%hu", vip, vport);
        snprintf(vip_metric_msg.res_hash, (int)strlen(res_hash)+1, "%s", res_hash);
        snprintf(vip_metric_msg.ses_hash, (int)strlen(ses_hash)+1, "%s", ses_hash);

        if(msgsnd(IPC_QUEUE_ID, &vip_metric_msg, UDP_VIP_CLIENT_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
            eprint("Metrics Dump failed at dump_udp_client_vip_metics\n");
            return false;
        }

        if(res_cfg->udp_vip_metrics[vip_iter].download_stats_present) {
            __dump_udp_url_metrics(res_cfg->udp_vip_metrics[vip_iter].udp_download_metrics,
                vip_metric_msg.vip, "DOWN");
            memset(res_cfg->udp_vip_metrics[vip_iter].udp_download_metrics, 0, \
                sizeof(te_udp_url_metrics_t));
            res_cfg->udp_vip_metrics[vip_iter].download_stats_present = false;
            res_cfg->udp_vip_metrics[vip_iter].udp_download_metrics->min_latency = DBL_MAX;
            res_cfg->udp_vip_metrics[vip_iter].udp_download_metrics->max_latency = 0;
        }

        if(res_cfg->udp_vip_metrics[vip_iter].upload_stats_present) {
            __dump_udp_url_metrics(res_cfg->udp_vip_metrics[vip_iter].udp_upload_metrics,
                vip_metric_msg.vip, "UP");
            memset(res_cfg->udp_vip_metrics[vip_iter].udp_upload_metrics, 0, \
                sizeof(te_udp_url_metrics_t));
            res_cfg->udp_vip_metrics[vip_iter].upload_stats_present = false;
            res_cfg->udp_vip_metrics[vip_iter].udp_upload_metrics->min_latency = DBL_MAX;
            res_cfg->udp_vip_metrics[vip_iter].udp_upload_metrics->max_latency = 0;
        }

        memset(&(res_cfg->udp_vip_metrics[vip_iter].udp_vip_stats), 0, sizeof(te_udp_vip_stats_t));
        res_cfg->udp_vip_metrics[vip_iter].stats_present = false;
    }
    return true;
}

bool te_dump_session_config_metrics(te_resource_config_t* res_cfg, \
    te_session_config_t* te_session_cfgs) {
    unsigned int iter = 0;
    te_session_config_t *session_cfg = NULL;

    bool (*session_cfg_dump_caller)(te_session_config_t*);

    if(tedp_mode == SERVER) {
        // There is no sense of session explicitly maintained by the server
        return true;
    }

    // Assigning the appropriate function pointer for UDP / HTTP to dump metrics
    switch(tedp_profile) {
        case TCP: {
            session_cfg_dump_caller = dump_http_session_config_metrics;
        } break;

        case UDP: {
            session_cfg_dump_caller = dump_udp_session_config_metrics;
        } break;

        default: {
            eprint("Unknown tedp_profile=%d\n", tedp_profile);
            abort();
        }
    }

    for (iter = 0; iter < res_cfg->num_session_cfgs; iter++) {
        session_cfg = &te_session_cfgs[iter];
        if(!session_cfg_dump_caller(session_cfg)) {
            return false;
        }
    }
    return true;
}

bool dump_http_session_config_metrics(te_session_config_t *session_cfg) {
    te_http_session_metrics_msg_t ses_cfg_metric_msg;
    ses_cfg_metric_msg.http_stats = session_cfg->http_metrics;
    ses_cfg_metric_msg.type = TE_HTTP_SES_CFG_METRIC_IPC_MSG;
    snprintf(ses_cfg_metric_msg.res_hash, (int)strlen(res_hash)+1, "%s", res_hash);
    snprintf(ses_cfg_metric_msg.ses_hash, (int)strlen(ses_hash)+1, "%s", ses_hash);

    if(msgsnd(IPC_QUEUE_ID, &ses_cfg_metric_msg, HTTP_SES_CFG_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
        eprint("Metrics Dump failed at dump_http_session_config_metrics\n");
        return false;
    }
    memset(&session_cfg->http_metrics, 0, sizeof(te_http_session_metrics_t));
    return true;
}

bool dump_udp_session_config_metrics(te_session_config_t *session_cfg) {
    te_udp_session_metrics_msg_t ses_cfg_metric_msg;
    ses_cfg_metric_msg.udp_stats = session_cfg->udp_metrics;
    ses_cfg_metric_msg.type = TE_UDP_SES_CFG_METRIC_IPC_MSG;
    snprintf(ses_cfg_metric_msg.res_hash, (int)strlen(res_hash)+1, "%s", res_hash);
    snprintf(ses_cfg_metric_msg.ses_hash, (int)strlen(ses_hash)+1, "%s", ses_hash);

    if(msgsnd(IPC_QUEUE_ID, &ses_cfg_metric_msg, UDP_SES_CFG_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
        eprint("Metrics Dump failed at dump_udp_session_config_metrics\n");
        return false;
    }
    memset(&session_cfg->udp_metrics, 0, sizeof(te_udp_session_metrics_t));
    return true;
}

bool te_dump_memory_metrics() {
    te_memory_metrics_msg_t memory_metric_msg;
    memory_metric_msg.type = TE_MEMORY_METRIC_IPC_MSG;
    snprintf(memory_metric_msg.res_hash, (int)strlen(res_hash)+1, "%s", res_hash);
    snprintf(memory_metric_msg.ses_hash, (int)strlen(ses_hash)+1, "%s", ses_hash);
    memory_metric_msg.pid = pid;
    memcpy(memory_metric_msg.malloc_metric, malloc_metric, sizeof(malloc_metric));
    memcpy(memory_metric_msg.free_metric, free_metric, sizeof(free_metric));


    if(msgsnd(IPC_QUEUE_ID, &memory_metric_msg, MEMORY_METRIC_MSG_SIZE, IPC_NOWAIT) == -1) {
        eprint("Metrics Dump failed at te_dump_memory_metrics\n");
        return false;
    }

    memset(malloc_metric, 0, sizeof(malloc_metric));
    memset(free_metric, 0, sizeof(free_metric));
    return true;
}

bool te_dump_stats(te_resource_config_t* res_cfg, te_session_config_t* session_cfg, \
    bool process_finish) {

    if(memory_metrics_enabled && !te_dump_memory_metrics()) {
        return false;
    }

    if(metrics_enabled) {
        if(!te_dump_session_config_metrics(res_cfg, session_cfg)) {
            return false;
        }

        if(!te_dump_vip_metrics(res_cfg)) {
            return false;
        }

        if(process_finish) {
            te_proc_finished_msg_t proc_finished_msg;
            snprintf(proc_finished_msg.finished, 5, "True");
            proc_finished_msg.type = TE_PROC_FINISHED_IPC_MSG;
            if(msgsnd(IPC_QUEUE_ID, &proc_finished_msg, PROC_FINISHED_MSG_SIZE, IPC_NOWAIT) == -1) {
                eprint("Metrics Dump failed at proc_finished_msg\n");
                return false;
            }
        }
    }
    return true;
}
