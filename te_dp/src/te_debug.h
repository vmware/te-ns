#ifndef TE_DEBUG_H
#define TE_DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#define TE_NO_DEBUG         0x0000
#define TE_SCREEN           0x0001
#define TE_TRACE            0x0002
#define TE_DEBUG            0x0004
#define TE_WARNING          0x0008
#define TE_ERROR            0x0010
#define TE_TEST             0x0020
#define TE_ENABLE_ALL       0x003f

#define TE_LOG_DEFAULT_MODE (TE_ERROR | TE_WARNING)
#define TE_LOG_TRACE_MODE   (TE_TRACE | TE_ERROR | TE_SCREEN)
#define TE_LOG_DEBUG_MODE   (TE_TRACE | TE_ERROR | TE_WARNING | TE_DEBUG)
#define TE_LOG_TEST_MODE    (TE_TRACE | TE_ERROR | TE_WARNING | TE_DEBUG | TE_TEST)
#define TE_LOG_SCREWED_MODE (TE_ENABLE_ALL)

typedef unsigned int TE_DEBUG_FLAG;
extern TE_DEBUG_FLAG te_log_level;
extern struct timeval tv;
extern struct tm * timeinfo;
extern te_resource_config_t* res_cfg;

#define te_print(format, level, args...) \
    do { \
        char fmt[64]; \
        char buf[64]; \
        FILE *te_logger; \
        gettimeofday(&tv, NULL);\
        timeinfo = localtime(&tv.tv_sec); \
        strftime(fmt, sizeof(fmt), "%H:%M:%S.%%06u", timeinfo); \
        snprintf(buf, sizeof(buf), fmt, tv.tv_usec); \
        if(level & TE_TRACE) { \
            if(level & TE_SCREEN) { \
                fprintf(stderr, GREEN "INFO, " RESET); \
            } \
            te_logger = te_log_files->debug_logger; \
            fprintf(te_logger, "INFO,"); \
        } \
        else if(level & TE_DEBUG) { \
            if(level & TE_SCREEN) { \
                fprintf(stderr, GREEN "DEBUG, " RESET); \
            } \
            te_logger = te_log_files->debug_logger; \
            fprintf(te_logger, "DEBUG,"); \
        } \
        else if(level & TE_WARNING) { \
            if(level & TE_SCREEN) { \
                fprintf(stderr, RED "WARNING, " RESET); \
            } \
            te_logger = te_log_files->debug_logger; \
            fprintf(te_logger, "WARNING,"); \
        } \
        else if(level & TE_ERROR) { \
            if(level & TE_SCREEN) { \
                fprintf(stderr, RED "ERROR, " RESET); \
            } \
            te_logger = te_log_files->error_logger; \
            fprintf(te_logger, "ERROR,"); \
        } \
        else if(level & TE_TEST) { \
            if(level & TE_SCREEN) { \
                fprintf(stderr, GREEN "TEST, " RESET); \
            } \
            te_logger = te_log_files->test_logger; \
            fprintf(te_logger, "TEST,"); \
        } \
        if(level & TE_SCREEN) { \
            fprintf(stderr, "%s, ", buf); \
            fprintf(stderr, format, ##args); \
        } \
        fprintf(te_logger, "%s, ", buf); \
        fprintf(te_logger, format, ##args); \
    } while (0)

#define tprint(fmt, args...) \
    do { \
        if (te_log_level & TE_TRACE) { \
            if(te_log_level & TE_SCREEN) { \
                te_print(fmt, (TE_SCREEN | TE_TRACE), ##args); \
            } else { \
                te_print(fmt, TE_TRACE, ##args); \
            }\
        } \
    } while (0)

#define test_print(fmt, args...) \
    do { \
        if (te_log_level & TE_TEST) { \
            if(te_log_level & TE_SCREEN) { \
                te_print(fmt, (TE_SCREEN | TE_TEST), ##args); \
            } else { \
                te_print(fmt, TE_TEST, ##args); \
            }\
        } \
    } while (0)

#define dprint(fmt, args...) \
    do { \
        if (te_log_level & TE_DEBUG) { \
            if(te_log_level & TE_SCREEN) { \
                te_print(fmt, (TE_SCREEN | TE_DEBUG), ##args); \
            } else { \
                te_print(fmt, TE_DEBUG, ##args); \
            }\
        } \
    } while (0)

#define wprint(fmt, args...) \
    do { \
        if (te_log_level & TE_WARNING) { \
            if(te_log_level & TE_SCREEN) { \
                te_print(fmt, (TE_SCREEN | TE_WARNING), ##args); \
            } else { \
                te_print(fmt, TE_WARNING, ##args); \
            }\
        } \
    } while (0)

#define eprint(fmt, args...) \
    do { \
        if (te_log_level & TE_ERROR) { \
            if(te_log_level & TE_SCREEN) { \
                te_print(fmt, (TE_SCREEN | TE_ERROR), ##args); \
            } else { \
                te_print(fmt, TE_ERROR, ##args); \
            }\
        } \
    } while (0)

#define iprint(level, args...) \
    do { \
        if(te_log_level & TE_SCREEN) { \
            fprintf(stderr, ##args); \
        } \
        logprint(level, args); \
    } while (0)

#define logprint(level, args...) \
    do { \
        FILE *te_logger; \
        if((level == TE_DEBUG) || (level == TE_WARNING) || (level == TE_TRACE)) { \
            te_logger = te_log_files->debug_logger; \
        } else if(level == TE_ERROR) { \
            te_logger = te_log_files->error_logger; \
        } \
        fprintf(te_logger, ##args); \
    } while (0)
#endif
