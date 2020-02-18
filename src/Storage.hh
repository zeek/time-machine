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

//extern int get_link_header_size(int dl);

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

/*
protected:
    void Close();
    void SetHdrSize();
    int datalink;
    char errbuf[PCAP_ERRBUF_SIZE];
    int hdr_size;
    //const u_char* data;
*/

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
