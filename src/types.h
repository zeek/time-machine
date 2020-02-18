#ifndef TM_TYPES_H
#define TM_TYPES_H

// Expose C99 functionality from inttypes.h, which would otherwise not be
// available in C++.
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>

#include "config.h"

typedef u_char* pkt_ptr;

typedef double tm_time_t;

inline tm_time_t to_tm_time(const struct timeval* tv) {
	return (double)tv->tv_sec+(double)tv->tv_usec/1e6;
}
/*
inline tm_time_t spec_to_tm(const struct timespec* tv) {
    return (double)tv->tv_sec + (double)tv->tv_nsec/1e9;
}
*/
/*
#ifdef __APPLE__
inline tm_time_t valspec_to_tm(const struct tvalspec* tv) {
    return (double)tv->tv_sec + (double)tv->tv_nsec/1e9;
}
#endif
*/

//typedef enum {tcp, udp, icmp} proto_t;
typedef uint8_t proto_t;

//typedef double hash_t;

#endif
