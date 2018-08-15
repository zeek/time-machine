#ifndef INDEXFILE_HH
#define INDEXFILE_HH

#include <netinet/in.h>  // ntohl()
#include <fstream>
#include <list>
#include <set>
#include <pcap.h>
#include <sstream>
#include <pthread.h>

#include "types.h"
#include "IndexField.hh"
#include "IndexEntry.hh"
#include "IndexHash.hh"


/* forward declaration */
class Storage;

/*
 * Organisation on Disk: 
 * The index maintainer threads writes in regular intervals (on every rotate)
 * the index entries to file. This file is sorted, to enable fast disk lookups
 * using bianary search. I.e. a lookup on disk requires to search every file. 
 *
 * Since we have to search every file and since the files are rather small, we
 * want to aggregate / merge several of these smaller files into larger
 * files. It's possible to repeat this multiple times to get an aggregation
 * hierachy with several aggregation levels. When a file is written to disk, it
 * is of aggregation level 0. Several of these level 0 files (say 10) are then
 * aggregated into one file of level 1, agein several level 1 files can be aggregated
 * into one level 2 file. 
 *
 * The aggregation thread is responsible to for this aggregation of files. The 
 * file_number[level] and file_number_oldest[level] arrays are used to keep track of the
 * current files of a given level on disk. file_number_oldest is the oldest file (the
 * one with the lowest number) on disk. file_number is the next file number that is 
 * not yet written. 
 *
 * 
 ***************************************************************************
 * Note on threading. 
 *
 * The index maintaining thread calls writeIndex() to create a new index file
 * The aggregation thread call aggregate() to aggregate/merge files together.
 * Query threads call lookup to search for entries on disk. 
 *
 *   file_number[] and file_number_oldest[] are accessed from multiple threads as follows:
 *   writeIndex() reads and updates file_number[0]. The lock is aquired, file_number[0] is read, 
 *       the lock is released, the file is written (with the just read file_number), the lock
 *       is aquired, file_number[0] is incremented, the lock is released. Since only  writeIndex
 *       updates file_number[0] it is save to release the lock between reading and incrementing. 
 *       While writeIndex is in progress, other threads just won't see the file that is just 
 *       written.
 *       Since the IndexEntrys are kept in memory, until file_number[0] is updated, no race 
 *       condition occurs in which we might temporaliy "loose" some entries. 
 *       AS LONG AS THE MEMORY IS QURIED BEFORE THE DISK INDEX IS QUERIED.
 *   aggregate_internal(), reads all file_numbers and file_number_oldest entries, it updates all
 *       entries except file_number[0].  The same mechanism's as for writeIndex also apply here: 
 *       first reading the file_number, file_number_oldest  vars, then aggregating and creating 
 *       new files (without holding the lock), then updating the file_number, file_number_oldest
 *       entries. _After_ the file_number_oldest vars have been updated, the files that have just
 *       been aggregated can be unlink()ed savely without holding the lock.
 *   lookup() reads file_number and file_number_oldest. It will hold the lock during the whole
 *       lookup procedure. This ensures that no file is unlink()ed that is currently read
 *       (or that is going to be read) by an ongoing lookup.
 *       FIXME: this is inefficient and should be changed.
 *
 *
 */

/***************************************************************************
 * class IndexFilesReader
 *
 * Transparent access to index files stored on disk. Entries can read in 
 * ascending  order and searches/lookups in the file can be done. 
 *
 * The filename pointer passed to the constructor will be owned by
 * IndexFileReader and free()'d upon object destruction
 *
 * FIXME: IndexFileReader is not templated and parts of the implementation
 * are rather large, so it might be a good idea to move it to a seperate
 * file, which gets compiled to a distinct object file. 
 */
class IndexFileReader {
	public:
		IndexFileReader(char *fn);
		~IndexFileReader();
		tm_time_t getFirst() {
			return first;
		}
		tm_time_t getLast() {
			return last;
		}
		uint64_t getKeySize() {
			return keysize;
		}
		uint64_t getEntrySize() {
			return entrysize;
		}
		const void *getCurEntry();
		void readNextEntry();
		void lookupEntry(IntervalSet *set, IndexField *key);
	protected:
		FILE *fp;
		char *fname;
		tm_time_t first, last;
		uint64_t keysize;
		size_t entrysize;
		void *buffer;
		bool eof;
};

/***************************************************************************
 * class DiskIndex
 */

class DiskIndex {
public:
	DiskIndex() {};
	virtual void lookup(IntervalSet *iset, IndexField *key, tm_time_t t0, tm_time_t t1) = 0;
	virtual void writeIndex( IndexHash *ih) = 0;
	virtual void aggregate(tm_time_t oldestTimestampDisk) = 0;
	virtual ~DiskIndex() {}
};

template <class T> class IndexFiles: DiskIndex {
public:
	IndexFiles(const std::string& pathname, const std::string& indexname);
	 ~IndexFiles();
	void lookup(IntervalSet *iset, IndexField *key, tm_time_t t0, tm_time_t t1);
	void writeIndex(IndexHash *ih);
	void aggregate(tm_time_t oldestTimestampDisk);
protected:
	void lock_file_numbers() {
		pthread_mutex_lock(&file_number_mutex);
	}
	void unlock_file_numbers() {
		pthread_mutex_unlock(&file_number_mutex);
	}
	void aggregate_internal(int level);
	// Returns a malloc'ed buffer containing the filename for this index.
	// You must free() the filename after use
	char *getFilename(int aggregation_level, uint64_t file_number); 
	std::string indexname;
	std::string pathname;
	int num_aggregate_levels;
	uint64_t *file_number;
	uint64_t *file_number_oldest;
	pthread_mutex_t file_number_mutex;
};

#include "DiskIndex.cc"


#endif
