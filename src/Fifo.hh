#ifndef FIFO_HH
#define FIFO_HH

//#include <pthread.h>
//#define _REENTRANT
#include <string>

/* resolve circular header file dependency by forward declarations
 */

//class Fifo;
class FifoDisk;

#include "FifoMem.hh"
//#include "Index.hh"
#include "Connection.hh"
#include "tm.h"

/*
class Fifo::Conf {
  Fifo::Conf() {
    classname="default";
    fifo_mem_sz=5000000;
    fifo_disk_sz=50000000;
    cutoff=10000;
  }
protected:
  std::string classname;
  uint64_t fifo_mem_sz;
  uint64_t fifo_disk_sz;
  uint64_t cutoff;
  pcap_t* ph;
}
*/

class Fifo: FifoMemEvictionHandler {
public:
	Fifo();
	Fifo(const std::string& classname, uint64_t fifo_mem_sz,
		 uint64_t fifo_disk_sz, pcap_t*, const char* classdir);
	void start();
	virtual ~Fifo();
	uint64_t pktEviction();
	bool addPkt(const struct pcap_pkthdr* header, const unsigned char* packet,
				Connection*);
	const FifoMem* getFm();
	const FifoDisk* getFd();
	void setCutoff(uint64_t n) {
		cutoff=n;
	}
	bool doCutoff() {
		return do_cutoff;
	}
	void enableCutoff() {
		do_cutoff=true;
	}
	void disableCutoff() {
		do_cutoff=false;
	}
	uint64_t getCutoff() {
		return cutoff;
	}
	void setClassname(std::string s) {
		classname=s;
	}
	std::string getClassname() {
		return classname;
	}
	void setClassnameId(std::string s) {
		classnameId=s;
	}
    void setClassdir(const char* s) {
        classdir=s;
    }
    const char* getClassdir() {
        return classdir;
    }
	void setFilenameFormat(const char *s) {
		filename_format=s;
	}
	const char* getFilenameFormat() {
		return filename_format;
	}
	void setClassdirFormat(const char *s) {
		classdir_format=s;
	}
	const char* getClassdirFormat() {
		return classdir_format;
	}
	void setFifoMemSz(uint64_t s) {
		fifo_mem_sz=s;
	}
	void setFifoDiskSz(uint64_t s) {
		fifo_disk_sz=s;
	}
	void setFifoDiskSzUnlimited() {
		fifo_disk_unlimited=true;
	}
	void setFifoDiskFileSz(uint64_t s) {
		fifo_disk_filesz=s;
	}
	void setPcapHandle(pcap_t* ph) {
		this->ph=ph;
	}
	void setFilter(std::string f) {
		filter=f;
	}
	void setPrecedence(int i) {
		precedence=i;
	}
	void setPktsToDisk(int i) {
		pkts_to_disk=i;
	}
	void setDynTimeout(tm_time_t t) {
		dynTimeout = t;
	}
	int getPrecedence() {
		return precedence;
	}
	tm_time_t getDynTimeout() {
		return dynTimeout;
	}
	bool matchPkt(const struct pcap_pkthdr*, const unsigned char*);
	uint64_t getStoredBytes() {
		return stored_bytes;
	}
	uint64_t getCutofBbytes() {
		return cutoff_bytes;
	}
	uint64_t getStoredPkts()   {
		return stored_pkts;
	}
	uint64_t getCutoffPkts()   {
		return cutoff_pkts;
	}
	std::string getStatsStr();
	static std::string getStatsStrHeader();
	uint64_t query(QueryRequest*, QueryResult*, IntervalSet*);
protected:
	bool do_cutoff;
	uint64_t cutoff;
	std::string classname;
	std::string classnameId;
	std::string filter;
    const char* classdir; 
        const char* filename_format;
	const char* classdir_format;
	uint64_t fifo_mem_sz;
	uint64_t fifo_disk_sz;
	bool fifo_disk_unlimited;
	uint64_t fifo_disk_filesz;
	int precedence;
	tm_time_t dynTimeout;
	pcap_t* ph;
	bool started;
	struct bpf_program fp;

	uint64_t pkts_to_disk;

	// statistics
	uint64_t stored_bytes;
	uint64_t cutoff_bytes;
	uint64_t stored_pkts;
	uint64_t cutoff_pkts;

	FifoMem* fm;
	FifoDisk* fd;
	//   pthread_t m2d_thread_id;
	//   volatile int m2d_thread_stop;
	//  int i;

	void init();
	//  static void* m2d_thread(void* arg);

};

#endif /* FIFO_HH */
