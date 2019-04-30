#ifndef FIFODISK_HH
#define FIFODISK_HH

#include <pcap.h>
#include <list>
#include <string>

#include "types.h"
#include "tm.h"
#include "Index.hh"

/* resolve circular header file dependency by forward declarations
 */
class QueryRequest;
class QueryResult;
class IntervalSet;

class FifoDiskFile;

class FifoDisk {
public:
	FifoDisk(const std::string& classname, uint64_t size,
			 uint64_t file_size, pcap_t*, const char* classdir,
			 const char* filename_format, const char* classdir_format,
			 const std::string &classnameId,
			 bool size_unlimited
			 );
	~FifoDisk();
	//  void addPkt(const struct pcap_pkthdr *header, const unsigned char *packet);
	void addPkt(const pkt_ptr p);
	tm_time_t getStartTimestamp();
	tm_time_t getOldestTimestamp() const;
	tm_time_t getNewestTimestamp() const;
	uint64_t getHeldBytes() {
		return held_bytes;
	}
	uint64_t getHeldPkts() {
		return held_pkts;
	};
	std::list <FifoDiskFile*>::iterator filesBeginIt() {
		return files.begin();
	}
	std::list <FifoDiskFile*>::iterator filesEndIt() {
		return files.end();
	}
#ifdef QUERY_RACE_PROTECT
	void lockQueryInProgress() { 
		pthread_mutex_lock(&query_in_progress_mutex);
	}
	void unlockQueryInProgress() { 
		pthread_mutex_unlock(&query_in_progress_mutex);
	}
#else
	void lockQueryInProgress() {};
	void unlockQueryInProgress() {};
#endif

#ifdef QUERY_RACE_PROTECT
	void incQueryInProgress() {
		lockQueryInProgress();
		queries++;
		unlockQueryInProgress();
	}
	void decQueryInProgress() {
		lockQueryInProgress();
		queries++;
		unlockQueryInProgress();
	}
#else
	void incQueryInProgress() { };
	void decQueryInProgress() { };
#endif

protected:
	std::string classname;
	std::string classnameId;
        const char* classdir;
	const char* filename_format;
	const char* classdir_format;
	std::list <FifoDiskFile*> files;
	uint64_t size;
	bool size_unlimited;
	uint64_t file_size;
	uint64_t tot_bytes;
	uint64_t tot_pkts;
	uint32_t file_number;
	pcap_t* pcap_handle;
	uint64_t held_bytes;
	uint64_t held_pkts;
	tm_time_t oldestTimestamp;
	tm_time_t newestTimestamp;
	pthread_mutex_t query_in_progress_mutex;
	int queries;
};


class FifoDiskFile {
public:
	FifoDiskFile(const std::string& filename, pcap_t*);
	~FifoDiskFile();
	void open();
	void close();
	void remove();
	void removeNoUnlink();
	void addPkt(const struct pcap_pkthdr *header, const unsigned char *packet);
	void addPkt(pkt_ptr p);
	int64_t getCurFileSize() {
		return cur_file_size;
	}
	uint64_t getHeldBytes() {
		return held_bytes;
	}
	uint64_t getHeldPkts() {
		return held_pkts;
	}
	tm_time_t getOldestTimestamp() {
		return oldest_timestamp;
	}
	tm_time_t getNewestTimestamp() {
		return newest_timestamp;
	}
	std::string getFilename() {
		return filename;
	}
	bool flush() {
		return pcap_dump_flush(pcap_dumper_handle)==0;
	}
	/* iterator will be increased up to the first interval completeley
	   not in file */
	uint64_t query( QueryRequest*, QueryResult*, IntervalSet*, const char* classdirectory);
protected:
	std::string filename;
        const char* classdir;
	bool is_open;
	pcap_dumper_t *pcap_dumper_handle;
	int64_t cur_file_size;
	uint64_t held_bytes;
	uint64_t held_pkts;
	pcap_t *pcap_handle;
	tm_time_t oldest_timestamp;
	tm_time_t newest_timestamp;
};


#endif /* FIFODISK_HH */
