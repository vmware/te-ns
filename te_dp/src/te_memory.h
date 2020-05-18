
#ifndef TE_MEMORY_H
#define TE_MEMORY_H

#include <malloc.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef TE_DEBUG_H
#include "te_debug.h"
#endif

enum MEMORY_TYPE {

    // To avoid crashing if type passed < 0    
    TE_MTYPE_MIN,

    // TE_DP ALLOCS
    // These allocs are the ones that happens often
    TE_MTYPE_CHAR,
    TE_MTYPE_DOUBLE_POINTER,
    TE_MTYPE_ERROR_METRICS,
    TE_MTYPE_TCP_REQUEST,
    TE_MTYPE_UDP_REQUEST,
    TE_MTYPE_SESSION,
    TE_MTYPE_TCP_SESSION,
    TE_MTYPE_UDP_SESSION,
    TE_MTYPE_VOID,

    //UDP Library level allocs
    TE_MTYPE_UDP_CLIENT_CONN_HANDLE,
    TE_MTYPE_UDP_CLIENT_EASY_HANDLE,
    TE_MTYPE_UDP_CLIENT_MULTI_HANDLE,
    TE_MTYPE_UDP_CLIENT_PENDING_REQUEST,
    TE_MTYPE_UDP_SERVER_EASY_HANDLE,
    TE_MTYPE_UDP_SEND_DATAGRAM,
    TE_MTYPE_SOCK_ADDR,

    // METRIC ALLOCS
    TE_MTYPE_URL_STATS,
    TE_MTYPE_URL_BUCKET_METRICS,
    TE_MTYPE_URL_METRICS,
    TE_MTYPE_UDP_URL_METRICS,
    TE_MTYPE_SESSION_BUCKET_METRICS, 
    TE_MTYPE_VIP_METRICS, 
    TE_MTYPE_UDP_VIP_METRICS,
    TE_MTYPE_SESSION_METRICS,
    TE_MTYPE_UDP_SERVER_VIP_METRICS_NODE,
    TE_MTYPE_UDP_SERVER_METRICS_HASH,


    // SOCKET ALLOCS
    TE_MTYPE_SOCKET_NODE,
    TE_MTYPE_SOCKET_HASH,

    // TE_AGENT 1 TIME ALLOCS
    // These allocs are spl cases as they occur only once. So memory metrics might be misleading
    // as they may end up never getting freed
    // Any memory type, having an alloc in 
    //    > te_agent.c is marked with TE_MTYPE_AGENT_* and
    //    > rest all as TE_MTYPE_*
    TE_MTYPE_AGENT_CHAR,
    TE_MTYPE_AGENT_INT,
    TE_MTYPE_AGENT_SHORT,
    TE_MTYPE_AGENT_DOUBLE_POINTER,
    TE_MTYPE_AGENT_SESSION,
    TE_MTYPE_BST_NODE,
    TE_MTYPE_VIP,
    TE_MTYPE_GET_POST_RATIO,
    TE_MTYPE_UPDATE_CONTEXT,
    TE_MTYPE_PARAMETER_RANDOM_MAP,
    TE_MTYPE_RESOURCE_CONFIG,
    TE_MTYPE_WRITE_CONTEXT,
    TE_MTYPE_SESSION_CONFIG,
    TE_MTYPE_URL_RANDOM_MAP,
    TE_MTYPE_URI,
    TE_MTYPE_REQUEST_OBJECT,
    TE_MTYPE_INTERFACE,
    TE_MTYPE_UDP_REQUEST_OBJECT,
    TE_MTYPE_UDP_DATAGRAM_OBJECT,
    TE_MTYPE_UDP_LISTEN_HANDLE,
    TE_MTYPE_UDP_SOCKET_METRIC,
    TE_MTYPE_UDP_SOCKET_STATE,
    TE_MTYPE_PARAMETER,
    TE_MTYPE_CERT,
    TE_MTYPE_HEADER,
    TE_MTYPE_LOG_FILES,

    // To avoid crashing if type passed > MAX SIZE OF ARRAY
    TE_MTYPE_MAX,

    // Types < 0 and > MAX falls into this bucket (Ideally should always be 0)
    TE_MTYPE_GENERIC
};

#define MEMORY_TYPE_SIZE (TE_MTYPE_GENERIC - TE_MTYPE_MIN + 1)

// Will be memset to 0, after every dump
// Posses the number of times an alloc / free is made
unsigned int malloc_metric[MEMORY_TYPE_SIZE];
unsigned int free_metric[MEMORY_TYPE_SIZE];

// Defaults to false, will run, only during the run of test-suites
extern bool memory_metrics_enabled;

#define te_malloc(void_pointer, size_to_alloc, type) \
do \
{ \
    if ( !((void_pointer) = malloc(size_to_alloc)) ) \
    { \
        eprint("INSUFFICIENT MEMORY TO ALLOCATE MEMORY OF SIZE %lu and TYPE %d\n", \
            (long unsigned int)size_to_alloc, type); \
        exit(EXIT_FAILURE); \
    } \
    if (memory_metrics_enabled) { \
        if(type <= TE_MTYPE_MIN || type >= TE_MTYPE_MAX) { \
            malloc_metric[TE_MTYPE_GENERIC]++; \
        } \
        else { \
            malloc_metric[type]++; \
        } \
    } \
} \
while(0)

#define te_free(void_pointer, type) \
do \
{ \
    free(void_pointer); \
    if (memory_metrics_enabled) { \
        if(type <= TE_MTYPE_MIN || type >= TE_MTYPE_MAX) { \
            free_metric[TE_MTYPE_GENERIC]++; \
        } \
        else { \
            free_metric[type]++; \
        } \
    } \
} \
while(0)

#endif
