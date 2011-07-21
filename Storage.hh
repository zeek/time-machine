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

// $Id: Storage.hh 268 2011-07-20 17:19:13Z gregor $

#ifndef STORAGE_HH
#define STORAGE_HH

#include <pcap.h>
#include <pthread.h>
#include <list>
#include <string>

#include "Fifo.hh"
#include "Connections.hh"
#include "Query.hh"
#include "DynClass.hh"

// number of indexes instantiated in Storage class
// used in Index.hh at PktLinkList next/previous members
// #define NUM_INDEXES 6

// TODO: We should really make the Storage class a true global singleton instead 
// of having to have a pointer to storage in a bunch of classes!

//#include "Index.hh"
class Indexes;

void *capture_thread(void *arg);
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Abstracts the configuration for a Storage instance
class StorageConfig {
	public:
		StorageConfig(); 

		std::string filter;
		std::string device;
		std::string readtracefile;
		std::list<Fifo *> fifos;
		tm_time_t conn_timeout;
		int max_subscriptions;
		Indexes *indexes;
};

class Storage {
public:
	Storage(StorageConfig& conf);
	~Storage();

	void cancelThread();
	void addPkt(const struct pcap_pkthdr* header, const unsigned char* packet);
	void aggregateIndexFiles();
	void debugPrint();
	void debugPrint(FILE *fp);

	void addFifo(Fifo*);
	void setConnTimeout(tm_time_t t) {
		conn_timeout=t;
	}
	int getPcapStats(struct pcap_stat *ps) {
		return pcap_stats(ph, ps);
	}
	int getPcapDatalink() {
		return pcap_datalink(ph);
	}
	int getPcapSnaplen() {
		return snaplen;
	}

	tm_time_t getOldestTimestampMem();
	tm_time_t getOldestTimestampMemHacked();
	tm_time_t getOldestTimestampDisk();

	void logStatsClasses();
	std::string getStatsIndexesStr();
	//FIXME: This is ugly. Use encapsulation
	Indexes* getIndexes() {
		return indexes;
	}
	//FIXME: This is ugly. Use encapsulation
	Connections& getConns() {
		return conns;
	}
	//FIXME: This is ugly. Use encapsulation
	std::list<Fifo*>& getFifos() {
		return fifos;
	}
	//FIXME: This is ugly. Use encapsulation
	Fifo* getFifoByName(std::string search_name);
	void query(QueryRequest*, QueryResult*);
	bool suspendCutoff(ConnectionID4, bool);
	bool suspendTimeout(ConnectionID4, bool);
	bool setDynClass(IPAddress *ip, int dir, const char *classname);
	bool unsetDynClass(IPAddress *ip);

	uint64_t getTotNumQueries() {
		return tot_num_queries;
	}
	uint64_t getTotQueriesDuration() {
		return tot_queries_duration;
	}
	int getNumDynClasses() {
		return dynclasses.getNumEntries();
	}
	
	friend void *capture_thread(void *arg);
private:
	pcap_t *ph;
	int snaplen;
	pthread_t capture_thread_tid;
	pthread_attr_t capture_thread_attr;

	std::list<Fifo*> fifos;

	Indexes* indexes;

	bool started;

	Connections conns;

	DynClassTable dynclasses;

	tm_time_t conn_timeout;
	uint64_t tot_num_queries;
	uint64_t tot_queries_duration;

};

#endif
