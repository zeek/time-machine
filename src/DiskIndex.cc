#ifndef INDEXFILE_CC
#define INDEXFILE_CC

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>  // htonl()
#include <errno.h>
#include <unistd.h>

#include <fstream>
#include <vector>

#include "tm.h"
#include "types.h"
#include "packet_headers.h"
#include "Storage.hh"
#include "Query.hh"
#include "IndexHash.hh"
#include "conf.h"

#include <time.h>

/* new glibc's (and/or) gcc's complain about not using the 
 * return value of certain functions. 
 * FIXME: Yes, we should check the retval here, but for that we would need
 * a way better error handling framework...
 */
static void 
my_fread (void* buf, size_t size, size_t nmemb, FILE* stream)
{
	// silence gcc
	size_t rv = fread(buf, size, nmemb, stream);
	if (rv)
		; // do nothing
}

static void
my_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	// silence gcc
	size_t rv = fwrite(ptr, size, nmemb, stream);
	if (rv)
		; // do nothing
}

/***************************************************************************
 * class IndexFilesReader
 */
inline IndexFileReader::IndexFileReader(char *fn) : fp(NULL), fname(fn), eof(false) {

        char filepath[100];

        strcpy(filepath, conf_main_workdir);
        strcat(filepath, "/");
        strcat(filepath, fname);
        //printf("The index file name is %s\n", filepath);

        if (chdir(conf_main_workdir)) {
            fprintf(stderr, "cannot chdir to %s\n", conf_main_workdir);
            //return(1);
        }

	fp = fopen(fn, "rb"); // read as binary 
	if (fp == NULL) {
		//TODO: Decent error handling
		tmlog(TM_LOG_ERROR, "IFR", "Could not open index file \"%s\" for reading.\n", fname);
                //char path[70];

                //char errbufnav[PCAP_ERRBUF_SIZE];

                //printf("The directory for Fifo that we are in is %s\n", getcwd(path, 70));

	}
	my_fread(&first, sizeof(tm_time_t), 1, fp);
	my_fread(&last, sizeof(tm_time_t), 1, fp);
	my_fread(&keysize, sizeof(keysize), 1, fp);
	keysize = ntohl(keysize);
	entrysize = keysize + 2*sizeof(tm_time_t);
	buffer = malloc(entrysize);
	readNextEntry();
}

inline IndexFileReader::~IndexFileReader() {
	free(fname);
	free(buffer);
	fclose(fp);
}

inline const void *IndexFileReader::getCurEntry() {
	if (eof)
		return NULL;
	else 
		return buffer;
}

inline void IndexFileReader::readNextEntry() {
	if (fread(buffer, entrysize, 1, fp) != 1)
		eof = true;
}

inline void IndexFileReader::lookupEntry(IntervalSet *set, IndexField *key) {
	long first_entry_off;
	long num_entries;
	bool found = false;
	const void *keyptr;
	long left, right, mid;  // Left, right and middle entry for binary search
	int cmp;

	if (!fp)
		return;

	keyptr = key->getConstKeyPtr();

	first_entry_off = (2*sizeof(tm_time_t) + sizeof(keysize));
	fseek(fp, 0, SEEK_END);
	num_entries = ftell(fp);
	num_entries -= first_entry_off;
	// num_entries now contains the number of bytes occupied by
	// entries in the file
	
	num_entries /= entrysize;
	left = 0;
	mid = 0;
	cmp = -1;
	right = num_entries-1; 
	found = false;

	//TODO:
	// Check if key is less or greater than any key in the current file
	/*fseek(fp, first_entry_off, SEEK_SET);
	fread(buffer, keysize, 1, fp);
	if (memcmp(buffer, keyptr, keysize) < 0)
		return; 
	fseek(fp, entrysize, SEEK_END);
	fread(buffer, keysize, 1, fp);
	if (memcmp(buffer, keyptr, keysize) > 0)
		return; 
*/
	while(left<=right && !found) {
		mid = left + (right-left)/2;
		fseek(fp, first_entry_off+mid*entrysize, SEEK_SET);
		my_fread(buffer, keysize, 1, fp);
		cmp = memcmp(buffer, keyptr, keysize);
		if (cmp < 0)   // mid < key
			right = mid - 1;
		else if (cmp > 0)
			left = mid + 1;
		else 
			found = true;
	}
	if (!found) {
		//fprintf(stderr, "Not found\n");
		return; 
	}

	/* Go left until we find the first entry with the current key */
	while (cmp==0 && mid>0 ) {
		mid--;
		fseek(fp, first_entry_off+mid*entrysize, SEEK_SET);
		my_fread(buffer, keysize, 1, fp);
		cmp = memcmp(buffer, keyptr, keysize);
	}
	if (cmp==0 && mid == 0) 
		; // First entry contains the key
	else 
		mid++; // else: we left the loop because cmp!=0.
		// increment mid. mid now points to the first entry with key
	cmp = 0; 
	fseek(fp, first_entry_off+mid*entrysize, SEEK_SET);
	while(fread(buffer, entrysize, 1, fp)==1) {
		Interval iv = Interval(0,0);
		cmp = memcmp(buffer, keyptr, keysize);
		if (cmp != 0) 
			break;
		iv.getStart() = *((tm_time_t*)((char *)buffer+keysize));
		iv.getLast() = *((tm_time_t*)((char *)buffer+keysize+sizeof(tm_time_t)));
		tmlog(TM_LOG_DEBUG, "query", "IFR::lookupEntry: adding interval [%lf,%lf]",
				iv.getStart(), iv.getLast());
		set->add(iv);
	}
	
}
/***************************************************************************
 * class IndexFiles<T>
 */

template <class T>
IndexFiles<T>::IndexFiles(const std::string& pathname, const std::string& indexname):
		indexname(indexname),
		pathname(pathname),
		num_aggregate_levels(3)
		{
			file_number = new uint64_t[num_aggregate_levels];
			file_number_oldest = new uint64_t[num_aggregate_levels];
			for (int i=0; i<num_aggregate_levels; i++) {
				file_number[i] = file_number_oldest[i] = 0;
			}
			pthread_mutex_init(&file_number_mutex, NULL);
}

template <class T>
IndexFiles<T>::~IndexFiles() {
	delete[] file_number;
	delete[] file_number_oldest;
	pthread_mutex_destroy(&file_number_mutex);
}

template <class T>
char *IndexFiles<T>::getFilename(int aggregation_level, uint64_t file_number) {
	int fn_size;
	char *fn;

	// length of filename: 
	//    pathname + 
	//    '/' +                 (1)
	//    indexname + 
	//    '_' +                 (1)
	//    aggregation_level +   (2)
	//    '_'                   (1)
	//    filenumber +          (8)
	//    '\0'                  (1)
	//                     Sum: 14
	fn_size = pathname.length() + indexname.length() + 14;
	fn = (char *)malloc(fn_size);
	snprintf(fn, fn_size, "%s/%s_%02x_%08lu", pathname.c_str(), indexname.c_str(), aggregation_level, file_number);
	return fn;
}

template <class T>
void IndexFiles<T>::lookup(IntervalSet *iset, IndexField *key, tm_time_t t0, tm_time_t t1) {
	int level;
	uint64_t curfile;
    // class IndexFileReader from DiskIndex.hh
	IndexFileReader *ifr;
	char *fname;

	lock_file_numbers();
	for(level=num_aggregate_levels-1; level>=0; level--) {
		for(curfile = file_number_oldest[level]; curfile < file_number[level]; curfile++) {
			fname = getFilename(level, curfile);
			// fname is now owned by IndexFileReader
			ifr = new IndexFileReader(fname);
			if ((t1+1e3 > ifr->getFirst()) && (t0-1e3 < ifr->getLast())) {
				tmlog(TM_LOG_DEBUG, "query", "IndexFiles::lookupmem: [t0,t1]=[%lf,%lf], curIdxFile=[%lf,%lf]",
						t0, t1, ifr->getFirst(), ifr->getLast());
				// the intervals [t0,t1] and [first,last] intersect 
				// ==> look for matches
				ifr->lookupEntry(iset, key);

			}
			delete ifr;
		}
	}
	unlock_file_numbers();
}

#define EPS 1e-3
template <class T>

// This function writes the key, the time interval of the IndexEntry, the overall time interval of the index,
// and the keysize in network byte order
void IndexFiles<T>::writeIndex( IndexHash *ih) {
	//tmlog(TM_LOG_DEBUG, "writeIndex", "beginning to write index");
    // Object type that identifies a stream and contains the information needed to control 
    // it, including a pointer to its buffer, its position indicator and all its state indicators.
    // It will be used to write index files

    /*
    if (chdir(conf_main_workdir)) {
        fprintf(stderr, "cannot chdir to %s\n", conf_main_workdir);
        //return(1);
    }
    */

	FILE *fp;
	char *new_file_name;
	IndexEntry *ie; // Hash table is made up of IndexEntry's, an IndexEntry is the data object containing 
                    // the intervals for a single entry in an index.
	const Interval *ci; // Interval type has 2 tm_time_t variables representing start and end of an interval for
                        // a single IndexEntry entry
	tm_time_t interval[2];  // the current interval
	tm_time_t range[2] = {0, 0};  // First TS in index and last TS in index
	int keysize = 0; // size of key (can be taken from IndexEntry->getKey()->getKeySize() )

	lock_file_numbers();
    // gets the file name from aggregation level and file number, puts it in a char array
    // definition of getFilename is a few lines above in DiskIndex.cc
	new_file_name = getFilename(0, file_number[0]);
	unlock_file_numbers();
    // open the file as a binary file containing that file name with writing privileges
    // w = writing, b = open as binary file
    if (chdir(conf_main_workdir)) {
        fprintf(stderr, "cannot chdir to %s\n", conf_main_workdir);
        //return(1);
    }


	fp = fopen(new_file_name, "wb");
    // if the file could not be opened, log error and return
	if (fp == NULL) {
		tmlog(TM_LOG_ERROR, T::getIndexNameStatic().c_str(), "Could not open file %s for writing.", new_file_name);
        // clear the hash table, though don't delete it O.o
		ih->clear();
		return;
	}

    // seeks this position of 2*sizeof(tm_time_t)+sizeof(keysize) from the start of the file (SEEK_SET means
    // from start of the file) this function seems to be part of standard library
    // 2*sizeof(tm_time_t) because of the time interval (has 2 tm_time_t variables) and sizeof(keysize) because
    // of key
	fseek(fp, 2*sizeof(tm_time_t)+sizeof(keysize), SEEK_SET);

    // initial walk/path for avl tree transversal in the hash table
	ih->initWalk();

    // Do an in-order tree walk. Delete Elements from the hash if
    // their node and their subtrees have been vistied. NOTE that the
    // order in which the elements are delete does NOT correspond with
    // the order in which the are returned!
    // This deleted element is of IndexEntry type. We will write this to disk.
    // getNextDelete is from IndexHash.cc
	ie=ih->getNextDelete();

    // If it is not NULL, get the keysize of the key of this IndexEntry
	if (ie) {
		keysize = ie->getKey()->getKeySize();
	}

	int count = 0;
    // While not NULL (NULL happens if there's only the root of the AVL tree left)
	while(ie)  {
		count++;

        // intlist is the list head of a linked list of Interval types of the IndexEntry
        // Interval type has 2 tm_time_t types
    	// Since most index entries contain only one interval we use
    	// the listheadd to store the first interval. (from IndexEntry.hh, both
        // getIntList and Interval)
		ci = ie->getIntList();
		//keysize = ie->getKey()->getKeySize();
		//fprintf(stderr, "%08X:%d - %08X:%d\n", tmp->ip1, tmp->port1, tmp->ip2, tmp->port2);
		// using do ... while is safe, since getIntList will always return a valid
		// pointer
		do {
            // write the key to the disk file
			my_fwrite(ie->getKey()->getConstKeyPtr(), 1, keysize, fp);
            // get the start and last time stamps of the list head of the linked
            // list of Interval types
			interval[0] = (*ci).getStart();
			interval[1] = (*ci).getLast();
            
            // if the start of this interval is less than the overall start or
            // less than the EPS, 1 milisecond,
            // set the overall start time stamp of the entry to be that
			if (interval[0] < range[0] || (range[0] < EPS)) 
				range[0] = interval[0];
            // on the other end, if the end of this interval is greater than
            // the overall end, then set the overall end time stamp of the entry to be that
			if (interval[1] > range[1])
				range[1] = interval[1];

            // write this particular interval of the IndexEntry to the file
			my_fwrite(interval, sizeof(tm_time_t), 2, fp);

            // move on to the next interval in the linked list of Interval types of the IndexEntry
			ci = ci->getNextPtr();
		} while(ci); // continue to do this while there are still interval in the linked list (not NULL)
    
        // set the indexentry to be written to be disk to be the next visited and deleted entry from the hash table
		ie=ih->getNextDelete();
        //tmlog(TM_LOG_NOTE, "DiskIndex:wrting", "Deleting the IndexEntry type from the hash table");
	}
	tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), 
			"Heigth of tree was: %d. level=%d. we wrote %d entries.", ih->height, ih->level, count);

    // resets the position indicator to beginning of file (recall that we used fseek to alter the position indicator)
	rewind(fp);
    
    // write the first and last overall timestamps in index to the file
	my_fwrite(range, sizeof(tm_time_t), 2, fp);

    // convert from host byte order (low-order byte is stored on next address (A+1) and high-order byte is
    // stored on starting address (A), little endian) to network byte order ((low-order byte is stored on 
    // the starting address (A) and high-order byte is stored 
    // on the next address (A + 1), big endian).
	keysize = htonl(keysize);

    // write thie network byte order keysize to the file
	my_fwrite(&keysize, sizeof(keysize), 1, fp);

    // close the file
	fclose(fp);
	free(new_file_name);
	lock_file_numbers();

    // increment file_number
	file_number[0]++;
	unlock_file_numbers();
}

/** Check if there are any files to aggregate. If so: aggregate them. */
template <class T>
void IndexFiles<T>::aggregate(tm_time_t oldestTimestampDisk) {
	char *oldest_fname;
	IndexFileReader *ifr;
	// Aggregate each level
	for (int level=0; level<num_aggregate_levels-1; level++) {
		aggregate_internal(level);
	}
	// On the highest aggregation level: check if the oldest file can be removed. It
	// can be removed if all of its entries have been evicted from disk. 
	// 
	// Note: We only check for the oldest file. It might be that the second oldest file
	// could also be removed but we just rely on the fact, that the aggregation thread
	// will call aggregate() often enough so we don't need to loop here. 
	lock_file_numbers(); 
	// check if there's at least one file at the hightes aggregation level
	if (file_number[num_aggregate_levels-1] != file_number_oldest[num_aggregate_levels-1]) {
		oldest_fname = getFilename(num_aggregate_levels-1, file_number_oldest[num_aggregate_levels-1]);
		ifr = new IndexFileReader(oldest_fname);
		if (ifr->getLast() < oldestTimestampDisk) {
			unlink(oldest_fname);
			file_number_oldest[num_aggregate_levels-1]++;
		}
        //free(oldest_fname);
		delete ifr;
	}
	unlock_file_numbers();
	
}

/** Aggregate IDX_AGGREGATE_COUNT files starting with file number fn_min  
 *  of level level
 *  into one index file of level+1. Aggregated files are unlinked. The
 *  file_number settings are adjusted accordingly
 *
 * @param level aggregation level to start with. writeIndex will write files
 * with aggregation level 0.
 */
template <class T>
void IndexFiles<T>::aggregate_internal(int level) {
    if (chdir(conf_main_workdir)) {
            fprintf(stderr, "cannot chdir to %s\n", conf_main_workdir);
            //return(1);
    }    

    // vector of IndexFileReader pointers
	std::vector<IndexFileReader *> ifr_vec;
	std::vector<IndexFileReader *>::iterator it;
	//struct timeval tv1, tvtmp; //tv2, tvtmp;
	IndexFileReader *greatest;
	FILE *ofp;

	char *of_name;
	char *if_name;
	int keysize, entrysize;
	tm_time_t range[2];
	int fn_min;
	int count;

	lock_file_numbers();
    // if the number of files at a particular level to aggregate is less than 
    // IDX_AGGREGATE_COUNT (10), return
	if (file_number[level] - file_number_oldest[level]  < IDX_AGGREGATE_COUNT) {
		unlock_file_numbers();
		return;
	}
    // minimum file number since it is the oldest file number of that
    // particular level
	fn_min = file_number_oldest[level];

    // we will aggregate IDX_AGGREGATE_COUNT (10) files
	count = IDX_AGGREGATE_COUNT;

    // getting a new file name for a file with a level + 1
	of_name = getFilename(level+1, file_number[level+1]);
	unlock_file_numbers();

    // open this new file with +1 level
	ofp = fopen(of_name, "wb");

	//XXX MAybe change to DEUBG level
	//tmlog(TM_LOG_NOTE, "aggregate", "New file is %s\n", of_name);

    // go through the ten files to aggregate
	for (int i=fn_min; i<fn_min+count; i++) {
		if_name = getFilename(level, i);
		// if_name is now owned by the IndexFileReader
        // push back this new instance of IndexFileReader in ifr_vec,
        // a vector of IndexFileReader pointers
		ifr_vec.push_back(new IndexFileReader(if_name));
	}

    // get the key size and entry size of the first element in the vector
	keysize = (ifr_vec.front())->getKeySize();
	entrysize = (ifr_vec.front())->getEntrySize();

    // initialize the range time's
	range[0] = ifr_vec.front()->getFirst();
	range[1] = ifr_vec.front()->getLast();

    // go through the for loop and get the absolute first time
    // of the entire vector and the absolute last time of the entire
    // vector
	for (it = ifr_vec.begin(); it!=ifr_vec.end(); it++) {
        // since we can do better in start time, set range[0] equal to it
		if ((*it)->getFirst() < range[0])
			range[0] = (*it)->getFirst();
        // since we can do better in end time, set range[1] equal to it
		if ((*it)->getLast() > range[1])
			range[1] = (*it)->getLast();
	}

    // write this range to the new file ofp
	my_fwrite(range, sizeof(tm_time_t), 2, ofp);

    // convert from host byte order (low-order byte is stored on next address (A+1) and high-order byte is
    // stored on starting address (A), little endian) to network byte order ((low-order byte is stored on 
    // the starting address (A) and high-order byte is stored 
    // on the next address (A + 1), big endian).
	keysize = htonl( (ifr_vec.front())->getKeySize());

    // write the network byte order keysize to the file
	my_fwrite(&keysize, sizeof(keysize), 1, ofp);

    // flush the output buffer to the file
	fflush(ofp);
	keysize = (ifr_vec.front())->getKeySize();

	int i=0;
	//unsigned int usec = 500*1000; // 500 ms
	//gettimeofday(&tv1, NULL);
    /*
    #ifdef __APPLE__
    struct tvalspec tv1, tvtmp;
    clock_get_time(CLOCK_MONOTONIC_COARSE, &tv1);
    tvtmp = tv1;
    #endif
    #ifdef linux
    struct timespec tv1, tvtmp;;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &tv1);
    tvtmp = tv1;
    #endif
    #ifdef __FreeBSD__
    struct timespec tv1, tvtmp;
    clock_gettime(CLOCK_MONOTONIC_FAST, &tv1);
    tvtmp = tv1;
    #endif
    */
	//tvtmp = tv1;
	while (!ifr_vec.empty()) {
		greatest = NULL;
		for (it = ifr_vec.begin(); it!=ifr_vec.end(); it++) {
			// If the current file is already exhausted, delete it from the
			// vector. Since erasing an element from a vector invalidates all
			// iterators, we mus break the for loop
			if ((*it)->getCurEntry() == NULL) { 
				delete (*it);
				ifr_vec.erase(it); 
				greatest=NULL;
				//fprintf(stderr, "IFR deleted. %d\n", i);
				break;
			}
			if (greatest == NULL)
				greatest = (*it);
			if (memcmp(greatest->getCurEntry(), (*it)->getCurEntry(), keysize) < 0)
				greatest = *it;
		}
		if (greatest != NULL) {
			my_fwrite(greatest->getCurEntry(), entrysize, 1, ofp);
			greatest->readNextEntry();
			i++;
		}
		/* Give the rest of the tm time to breath */
		/*
		if (i%50000 == 0) {
			//gettimeofday(&tv2, NULL);
			if (to_tm_time(&tv2)-to_tm_time(&tv1)<2.5) {
				log_file->log("aggregate", "Sleeping for file  %s \n", of_name);
				usleep(usec);
				//gettimeofday(&tv1, NULL);
			}
		}
		*/
	}
	//gettimeofday(&tv2, NULL);
	fclose(ofp);
	//tmlog(TM_LOG_DEBUG, "aggregate", "File %s done. It took %lf sec", of_name, to_tm_time(&tv2)-to_tm_time(&tvtmp));
	free(of_name);
	lock_file_numbers();
	file_number[level+1]++;
	file_number_oldest[level] = fn_min+count;
	unlock_file_numbers();
	// The file_numbers are now updated. We can now remove the files that we
	// just aggregated.
	for (int i=fn_min; i<fn_min+count; i++) {
		if_name = getFilename(level, i);
		unlink(if_name);
		free(if_name);
	}
	// Decouple aggregate runs
	sleep(IDX_MIN_TIME_BETWEEN_AGGREGATE );
}



#endif
