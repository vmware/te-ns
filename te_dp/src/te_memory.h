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
    TE_MTYPE_MIN,                                        // 0

    // TE_DP ALLOCS
    // These allocs are the ones that happens often
    TE_MTYPE_CHAR,                                       // 1
    TE_MTYPE_DOUBLE_POINTER,                             // 2
    TE_MTYPE_ERROR_METRICS,                              // 3
    TE_MTYPE_TCP_REQUEST,                                // 4
    TE_MTYPE_UDP_REQUEST,                                // 5
    TE_MTYPE_SESSION,                                    // 6
    TE_MTYPE_TCP_SESSION,                                // 7
    TE_MTYPE_UDP_SESSION,                                // 8
    TE_MTYPE_VOID,                                       // 9

    //UDP Library level allocs
    TE_MTYPE_UDP_CLIENT_CONN_HANDLE,                     // 10
    TE_MTYPE_UDP_CLIENT_EASY_HANDLE,                     // 11
    TE_MTYPE_UDP_CLIENT_MULTI_HANDLE,                    // 12
    TE_MTYPE_UDP_CLIENT_PENDING_REQUEST,                 // 13
    TE_MTYPE_UDP_SERVER_EASY_HANDLE,                     // 14
    TE_MTYPE_UDP_SEND_DATAGRAM,                          // 15
    TE_MTYPE_SOCK_ADDR,

    // METRIC ALLOCS
    TE_MTYPE_URL_STATS,                                  // 16
    TE_MTYPE_URL_BUCKET_METRICS,                         // 17
    TE_MTYPE_URL_METRICS,                                // 18
    TE_MTYPE_UDP_URL_METRICS,                            // 19
    TE_MTYPE_SESSION_BUCKET_METRICS,                     // 20
    TE_MTYPE_VIP_METRICS,                                // 21
    TE_MTYPE_UDP_VIP_METRICS,                            // 22
    TE_MTYPE_SESSION_METRICS,                            // 23
    TE_MTYPE_UDP_SERVER_VIP_METRICS_NODE,                // 24
    TE_MTYPE_UDP_SERVER_METRICS_HASH,                    // 25


    // SOCKET ALLOCS
    TE_MTYPE_SOCKET_NODE,                                // 26
    TE_MTYPE_SOCKET_HASH,                                // 27

    // TE_AGENT 1 TIME ALLOCS
    // These allocs are spl cases as they occur only once. So memory metrics might be misleading
    // as they may end up never getting freed
    // Any memory type, having an alloc in
    //    > te_agent.c is marked with TE_MTYPE_AGENT_* and
    //    > rest all as TE_MTYPE_*
    TE_MTYPE_AGENT_CHAR,                                 // 28
    TE_MTYPE_AGENT_INT,                                  // 29
    TE_MTYPE_AGENT_SHORT,                                // 30
    TE_MTYPE_AGENT_DOUBLE_POINTER,                       // 31
    TE_MTYPE_AGENT_SESSION,                              // 32
    TE_MTYPE_BST_NODE,                                   // 33
    TE_MTYPE_VIP,                                        // 34
    TE_MTYPE_GET_POST_RATIO,                             // 35
    TE_MTYPE_UPDATE_CONTEXT,                             // 36
    TE_MTYPE_PARAMETER_RANDOM_MAP,                       // 37
    TE_MTYPE_RESOURCE_CONFIG,                            // 38
    TE_MTYPE_WRITE_CONTEXT,                              // 39
    TE_MTYPE_SESSION_CONFIG,                             // 40
    TE_MTYPE_URL_RANDOM_MAP,                             // 41
    TE_MTYPE_URI,                                        // 42
    TE_MTYPE_REQUEST_OBJECT,                             // 43
    TE_MTYPE_INTERFACE,                                  // 44
    TE_MTYPE_UDP_REQUEST_OBJECT,                         // 45
    TE_MTYPE_UDP_DATAGRAM_OBJECT,                        // 46
    TE_MTYPE_UDP_LISTEN_HANDLE,                          // 47
    TE_MTYPE_UDP_SOCKET_METRIC,                          // 48
    TE_MTYPE_UDP_SOCKET_STATE,                           // 49
    TE_MTYPE_PARAMETER,                                  // 50
    TE_MTYPE_CERT,                                       // 51
    TE_MTYPE_HEADER,                                     // 52
    TE_MTYPE_LOG_FILES,                                  // 53

    // To avoid crashing if type passed > MAX SIZE OF ARRAY
    TE_MTYPE_MAX,                                        // 54

    // Types < 0 and > MAX falls into this bucket (Ideally should always be 0)
    TE_MTYPE_GENERIC                                     // 55
};

#define MEMORY_TYPE_SIZE (TE_MTYPE_GENERIC - TE_MTYPE_MIN + 1)

// Will be memset to 0, after every dump
// Posses the number of times an alloc / free is made
extern unsigned int malloc_metric[MEMORY_TYPE_SIZE];
extern unsigned int free_metric[MEMORY_TYPE_SIZE];

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
