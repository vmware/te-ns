#ifndef TE_UTILS_H
#define TE_UTILS_H

#ifndef TE_DP_H
#include "te_dp.h"
#endif

#include<time.h>

#define te_abs (a) (a < 0 ? -a : a);

#define te_difftime(end, start) \
    (double)((end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000) / 1000000.0;


te_error_metrics_t* new_error_node(int, const char*, te_http_url_metrics_t*);
te_error_metrics_t* insert_or_update_error(te_error_metrics_t*, int, const char*, te_http_url_metrics_t*);
unsigned int te_random(unsigned int, unsigned int);
void te_swap(short*, short*);
#endif
