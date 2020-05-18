#ifndef TE_STATS_COLLECTOR_H
#define TE_STATS_COLLECTOR_H

#include <iostream>
#include <array>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <limits>

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <json/json.h>
#include <sys/sysinfo.h>

#include <zmq.hpp>

#include <time.h>
#include <thread>
#include <chrono>
#include <ctime>
#include <boost/date_time.hpp>

#ifndef TE_METRICS_H
#include "te_metrics.h"
#endif

// Metrics Profile message
// NOTE: Metrics Profile message is shared with TE_METRICS.py and TE_WRAP.py
// Changes must be reflected at both the places
#define HTTP_PROFILE        1
#define UDP_CLIENT_PROFILE  2
#define UDP_SERVER_PROFILE  3

using namespace std;

typedef struct te_mean_variance_s {
    unsigned int n;
    double mean;
    double var;
} te_mean_variance_t;

#endif
