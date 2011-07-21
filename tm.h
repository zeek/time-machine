/*
Timemachine
Copyright (c) 2006 Technische Universitaet Muenchen,
                   Technische Universitaet Berlin,
                   The Regents of the University of California
All rights reserved.


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the names of the copyright owners nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// $Id: tm.h 270 2011-07-20 18:56:46Z gregor $

#ifndef TM_H
#define TM_H

#include <string>

#include "types.h"

// #define QUERY_RACE_PROTECT


/* If TM_HEAVY_DEBUG is defined, quite some expensive code with asserts,
 * sanity-checks etc. is run. Only define it, if you need it, since it
 * may slow down the TM considerable. 
 * That's why we don't allow it to be set via configure */
//#define TM_HEAVY_DEBUG

class Storage;
extern Storage *storage;

// FIXME: Maybe move to Storage
extern uint64_t tot_bytes;
extern uint64_t tot_pkt_cnt;
extern uint64_t uncut_bytes;
extern uint64_t uncut_pkt_cnt;
extern uint64_t querySentPkts;
extern uint64_t querySentBytes;

#define TM_LOG_DEBUG	10
#define TM_LOG_NOTE		20
#define TM_LOG_WARN		30
#define TM_LOG_ERROR	40
void tmlog(int severity, const char *ident, const char *fmt, ...);
void tmlog(const char *ident, const char *fmt, ...);


// from cmd_parser.cc
struct broccoli_worker_thread_data;
int parse_cmd(const char* cmd, FILE *outfp, Storage* s, broccoli_worker_thread_data* thread);
void cmd_parser_init(void);
void cmd_parser_finish(void);

#define TM_TWEAK_CAPTURE_THREAD_NONE 0
#define TM_TWEAK_CAPTURE_THREAD_PRIO 1
#define TM_TWEAK_CAPTURE_THREAD_SCOPE 2

/* Dynamic Classes: Direction of connection,either origin, response
    or both */
#define TM_DYNCLASS_BOTH 0 
#define TM_DYNCLASS_ORIG 1 
#define TM_DYNCLASS_RESP 2 


/* Security margin for index system. The intervals stored in 
 * the IndexEntry classes begins IDX_PKT_SECUIRTY_MARGIN packets
 * (meassured thru avg. iat) before the timestamp of the first
 * packet. Why? Since we used have to convert between doubles and
 * timevals precision errors might occur which might lead to 
 * missed packets during a query. Furthermore I'm not entirely
 * sure how well the binary search works. I.E. this offset also 
 * helps the bin_search() during query */
#define IDX_PKT_SECURITY_MARGIN 8


#define IDX_AGGREGATE_COUNT 10

/* How long to wait after an index has been written to disk before another index
 * can be written 
 */
#define IDX_MIN_TIME_BETWEEN_WRITES 1.5

#define IDX_MIN_TIME_BETWEEN_AGGREGATE 10


#endif
