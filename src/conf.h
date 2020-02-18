#ifndef CONF_H
#define CONF_H

#include <pcap.h>

#include "Storage.hh"

/***************************************************************************
 * configuration parameters
 */

extern int conf_main_log_interval;
extern int conf_main_log_level;
extern const char* conf_main_workdir;
extern const char* conf_main_indexdir;
extern const char* conf_main_profilepath;
//extern const char* conf_classdir;
extern const char* conf_main_logfile_name;
extern const char* conf_main_bro_connect_str;
extern int conf_main_console;
extern int conf_main_daemon;
extern int conf_main_tweak_capture_thread;
extern tm_time_t conf_main_conn_timeout;
extern int conf_main_max_subscriptions;
extern const char* conf_main_queryfiledir;
extern const char* conf_main_classdir_format;
extern const char* conf_main_filename_format;

extern unsigned short conf_main_rmtconsole_port;
extern struct in_addr conf_main_rmtconsole_listen_addr; 
extern int conf_main_rmtconsole;

extern int conf_main_bro_listen;
extern int conf_main_bro_listen_port;
extern struct in_addr conf_main_bro_listen_addr;

extern int parse_config(const char* filename, StorageConfig* storageConf);




#endif
