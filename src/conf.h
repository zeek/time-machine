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

// $Id: conf.h 251 2009-02-04 08:14:24Z gregor $
//
#ifndef CONF_H
#define CONF_H

#include <pcap.h>

#include "Storage.hh"

/***************************************************************************
 * configuration parameters
 */

extern int conf_main_log_interval;
extern const char* conf_main_workdir;
extern const char* conf_main_indexdir;
extern const char* conf_main_logfile_name;
extern const char* conf_main_bro_connect_str;
extern int conf_main_console;
extern int conf_main_daemon;
extern int conf_main_tweak_capture_thread;
extern tm_time_t conf_main_conn_timeout;
extern int conf_main_max_subscriptions;
extern const char* conf_main_queryfiledir;

extern unsigned short conf_main_rmtconsole_port;
extern struct in_addr conf_main_rmtconsole_listen_addr; 
extern int conf_main_rmtconsole;

extern int conf_main_bro_listen;
extern int conf_main_bro_listen_port;
extern struct in_addr conf_main_bro_listen_addr;

extern int parse_config(const char* filename, StorageConfig* storageConf);




#endif
