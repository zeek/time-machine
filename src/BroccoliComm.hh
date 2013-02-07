#include "conf.h"

#ifndef BROCCOLICOMM_HH
#define BROCCOLICOMM_HH

#ifdef USE_BROCCOLI

struct pcap_pkthdr;

extern void broccoli_init();
extern void broccoli_exit();
extern void broccoli_start_worker_thread(int fd);
extern void broccoli_send_packet(broccoli_worker_thread_data* bc_thread, 
		const struct pcap_pkthdr *header, const unsigned char *packet, const std::string& tag);

extern int broccoli_recv_q_peak;

#endif

#endif
