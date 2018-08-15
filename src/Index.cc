/* CAUTION: Only "templated" code goes here.  Index.cc is included by
 * Index.hh, so object code goes to the objects including Index.hh.
 * It mustn't go to Index.o, too.
 */

#ifndef INDEX_CC
#define INDEX_CC

#include <sys/stat.h>
#include <errno.h>

#include <fstream>
#include <queue>
#include <string>
//#include <gperftools/profiler.h> 

#include "tm.h"
#include "types.h"
#include "packet_headers.h"
#include "Storage.hh"
#include "LogFile.hh"
#include "Query.hh"
#include "IndexHash.hh"
#include "conf.h"


/***************************************************************************
 * class Index<T>
 */

template <class T>
Index<T>::Index(tm_time_t d_t, int hash_size_index, bool do_disk_index, Storage *storage):
		input_q(MyQueue(1000000)),
		cap_thread_iat(0), idx_thread_iat(0),
		d_t(d_t),
		last_rotated(0),
		last_updated(0),
		num_entries_disk(0),
		storage(storage),
		rotate_count(0) 
        {
        /*
            primes[0] = 1;
            primes[1] = 2;
            primes[2] = 3;
            primes[4] = 7;
            primes[5] = 13;
            primes[6] = 29;
            primes[7] = 53;
            primes[8] = 97;
            primes[9] = 193;
            primes[10] = 389;
            primes[11] = 769;
            primes[12] = 1543;
            primes[13] = 3079;
            primes[14] = 6151;
            primes[15] = 12289;
            primes[16] = 24593;
            primes[17] = 49157;
            primes[18] = 98317;
            primes[19] = 196613;
            primes[20] = 393241;
            primes[21] = 786433;
            primes[22] = 1572869;
            primes[23] = 3145739;
            primes[24] = 6291469;
            primes[25] = 12582917;
            primes[26] = 25165843;
            primes[27] = 50331653;
            primes[28] = 100663319;
            primes[29] = 201326611;
            primes[30] = 402653189;
            primes[31] = 805306457;
            primes[32] = 1610612741;
            primes[33] = 3221225479;
            primes[34] = 6442450967;
            primes[35] = 12884901947;
        */
        /*        
        primes = {1, 2, 3, 7, 13, 29, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157, \
                             98317, 196613, 393241, 786433, 1572869, 3145739, 6291469, \
                             12582917, 25165843, 50331653, 100663319, 201326611, 402653189, \
                             805306457, 1610612741, 3221225479, 6442450967, 12884901947};
        */
	    cur = new IndexHash(hash_size_index);
	    old = new IndexHash(hash_size_index);
        
        if (chdir(conf_main_workdir)) {
            fprintf(stderr, "cannot chdir to %s\n", conf_main_workdir);
            //return(1);
        }

        struct stat st;

        if (stat(conf_main_indexdir, &st) != 0)
        {
            printf("The index directory %s did not exist. Creating the directory ...\n", conf_main_indexdir);
            mkdir(conf_main_indexdir, 0755);
        } 
        
	    if (do_disk_index)
		    disk_index = new IndexFiles<T>((std::string)conf_main_indexdir, "index_"+T::getIndexNameStatic());
	    else
		    disk_index = NULL;
	    pthread_mutex_init(&hash_lock_mutex, NULL);
	    pthread_mutex_init(&queue_lock_mutex, NULL);
	    pthread_cond_init(&queue_cond, NULL);
//--- Now done by Storage	pthread_create(&maintainer_thread, NULL, start_index_thread, this);
}

template <class T>
Index<T>::~Index() {
	//tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "Index<T>::~Index");

	pthread_mutex_destroy(&hash_lock_mutex);
	pthread_mutex_destroy(&queue_lock_mutex);
	pthread_cond_destroy(&queue_cond);
	//pthread_mutex_trylock(&queue_lock_mutex);
	std::deque<IndexField *>::iterator it;
	while (!input_q.empty()) {
		delete input_q.back();
		input_q.pop_back();
	}

	// Free IndexEntries from hashes
	cur->clear();
	old->clear();
	// Destroy the hashes
	delete cur;
	delete old;
	if (disk_index)
		delete disk_index;
}

template <class T>
void Index<T>::cancelThread() {
	//tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "Canceling Index Thread.");
	pthread_cancel(maintainer_thread);
	//tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "   Canceled. Now Joining.");
	pthread_join(maintainer_thread, NULL);
	//tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "   Joined.");
}

/* Called by the capture thread */
template <class T>
void Index<T>::addPkt(const pcap_pkthdr* header, const u_char* packet) {

    // set the last and now to the timestamp of the pcap packet header
	static tm_time_t last = to_tm_time(&header->ts);
	tm_time_t now = last; //to_tm_time(&header->ts);

    // IndexField pointer
	T* curentry;

	lock_queue();
    // keysPerPacket is the number of keys per packet
    // so, for example, a connectionIF2 has 1 key, connectionIF3 has 2 keys, and a connectionIF4 has 1 key
    //tmlog(TM_LOG_NOTE, "addPkt for indexfields", "there are %d keys for this packet %d", T::keysPerPacket(), header->ts.tv_usec);
	for (int i=0; i<T::keysPerPacket(); i++) {
        // set curentry to the key, depends on i for which key
        // for example, i = 0 could mean source ip address for some connection type
		curentry = T::genKey(packet, i);
#ifdef TM_HEAVY_DEBUG
		assert(curentry);
#endif
        // set the timestamp of the current entry to be 
		curentry->ts = now;
        // push this IndexField pointer entry to the front of the input queue, which is of type MyQueue
        // (Index.hh)
		input_q.push_front(curentry);
        /*
        //tmlog(TM_LOG_NOTE, "addPkt for indexfields", "we are pushing in the front an indexfield to the input queue with timestamp %f and form %s and type %s", \
        curentry->ts, curentry->getStrPkt(packet).c_str(), curentry->getIndexName().c_str());
        //tmlog(TM_LOG_NOTE, "addPkt: size of input q", "The size of the input queue in the for loop is %d", input_q.size());
        */
	}

    //tmlog(TM_LOG_NOTE, "addPkt: size of input q", "The size of the input queue is %d", input_q.size());

    // set the capture thread's oldest time stamp in memory, disk, and interarrival time to be
    // equal to that of storage's oldest time stamp in memory and disk, and interarrival time, 
    // respectively
    // definitions are in Storage.cc
    // gets the oldest time stamp in the memory ring buffer
	cap_thread_oldestTimestampMem = storage->getOldestTimestampMemHacked();
	cap_thread_oldestTimestampDisk = storage->getOldestTimestampDisk();
    // InterArrival time is the time between packets
    // For example, if we have 200 packets in 10 seconds, the iat would be 10/200, which is 0.05 seconds
	cap_thread_iat = (cap_thread_iat  + (now - last))/2.0; /* Weighted avg of IAT */
	last = now;
	//TODO: Dont' hardcode the qlen 
    // if the input queue gets too full
	if (input_q.size() > 10) 
    {
        //tmlog(TM_LOG_NOTE, "addPkt for Index.cc", "we shoudl reach here when the input_q.size is > 10. The input queue size is %d", input_q.size());
        // alert index thread, which is implemented in the run() method
		cond_broadcast_queue();
    }
	unlock_queue();
}

/* addEntry(): add the the queue entry to the hash index. Write index to disk if 
 * necessary. Called by run()
 * You must hold the hash lock (lock_hash(), unlock_hash() before calling addEntry() 
 *
 * @param iqe Pointer to the IndexQueueEntry to add
 */
template <class T>
void Index<T>::addEntry(IndexField *iqe) {
	uint64_t hash_size; 
    int hash_size_index;
	IndexHash *tmp;
    // if last_rotated is less than a milisecond
	if (last_rotated<1e-3)
        // set it equal to the (from run() ) popped IndexField pointer last element's time stamp
		last_rotated = iqe->ts;
	/* We rotate, when the last roatation is older than the oldest Packet
	 * in the Memory Ringbuffer. And we only rotate if the input_q is not too
	 * long.
	 * When the input_q gets too full and when the memory ringbuffer is rather
	 * small, it may (and WILL) happen, that the index thread will reach a point,
	 * were the packets in the input queue are older than the oldest packet in
	 * the memory ringbuffer. When this happens, the index is rotated after every
	 * packet, since the last_rotated timestamp is set from the packet header's 
	 * timestamp and in the above scenario, this means that even just after rotation,
	 *  last_rotated < oldestTimestampMem
	 *
	 * Therefor we check if the qlen is short enough. Comparing the qlen against the
	 * number of packets currently held in the cur hash seems a good solution, since
	 * we don't have to use a hardcoded value for the 'maximum qlen for roatation'
	 *
	 * When we write an index to disk, we use a lot of CPU time and
	 * disk IO (well we are writing the entries). Since the excat moment of
	 * the rotation isn't important for us, we ensure that only ONE index can
	 * be in the process of writing to disk. We ensure
	 * this thru the trylockDiskWriter
	 *
	 * TODO: Check what happens if the TM is CPU-bound. Will the capture thread drop
	 * packets or will the input_q fill up and eat all the system's mem? 
	 * TODO: There is a possible problem now: A sparsely populated index. Like an index
	 * for the Layer 4 protocol. It will only have, say, 3 different values, so the
	 * queue will always be longer than the # of entries. As long as the # of intervals
	 * in each of these entries doesn't grow we should still be fine, but if the
	 * # of intervals does grow, we might have a problem.
	 */

    // if last rotation, represented by the time stamp of the popped last element, is older than 
    // the oldest packet in the memory ring buffer, represented by idx_thread_oldestTimestampMem via
    // cap_thread_oldestTimestampMem (in run() )
    // Second condition is that the length of the input queue is less than the number of entries in
    // the hash table
    // write/send the entries in bunches (batch job), Note that qlen, cur->getNumEntries() are dynamic
	if ((last_rotated < idx_thread_oldestTimestampMem) &&
			qlen < cur->getNumEntries()) {
            //tmlog(TM_LOG_NOTE, "Index.cc", "getting the number of entries in the current hash table");
        // returns 0 if lock for disk writing was successfully achieved (trylockDiskWrite function definition from Index.hh)
		if (storage->getIndexes()->trylockDiskWrite() == 0) {

			tmlog(TM_LOG_NOTE, T::getIndexNameStatic().c_str(), "Rotate. Old=%d. Cur=%d. Buckets=%d. qlen=%d.",  
						old->getNumEntries(), cur->getNumEntries(), cur->getNumBuckets(), qlen);

            //tmlog(TM_LOG_NOTE, "Index.cc", "prior to deleting, the number of buckets in the old hash table is: %d", old->getNumBuckets());
            //tmlog(TM_LOG_NOTE, "Index.cc", "prior to deleting, the number of entries in the old hash table is: %d", old->getNumEntries());


			// Write the old hash to disk.
            // while the number of entries in the old hash table is nonzero
			if (old->getNumEntries() != 0)
			{ 
                // if the index files do exist (these are the index files in the index directory)
				if (disk_index) {
					tmlog(TM_LOG_NOTE, T::getIndexNameStatic().c_str(), 
							"Writing %d entries to disk.",  old->getNumEntries());
					// writeIndex will delete the entries from the hash and write them to disk (DiskIndex.cc)
					disk_index->writeIndex(old);
				} else {
					// not disk writer, clear the old hash table, though not deleted
                    //tmlog(TM_LOG_NOTE, "Index.cc", "we are clearing the old hash table");
					old->clear();
				}
#ifdef TM_HEAVY_DEBUG
				//tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "Qlen now is %d", input_q.size());
				assert(old->getNumEntries() == 0);
#endif
			}
            //tmlog(TM_LOG_NOTE, "Index.cc", "the number of buckets in the old hash table is: %d", old->getNumBuckets());
            //tmlog(TM_LOG_NOTE, "Index.cc", "the number of entries in the old hash table is: %d", old->getNumEntries());
            //tmlog(TM_LOG_NOTE, "Index.cc", "the number of entries in the cur has table is: %d", cur->getNumEntries());
            // at this point, old hash table is cleared and/or deleted
            // set the temporary IndexHash pointer to current hash table
			tmp = cur;

            // set the current hash table to the old hash table
			cur = old;

            // set the old hash tabe to be the temporary Hash, which is the newer hash table at this point
			old = tmp;

            // get the number of buckets in the current hash table (formerly old hash table)
            // Note that while the number of entries will be 0, the number of buckets will remain unchanged
            // the number of entries are like the actual number of entries, including the entries in the collisions lists
            // However, the number of buckets, I guess like the infrastructure of the Hash table without collision lists
            // still remains.
			hash_size_index = cur->getNumBucketsIndex();
            hash_size = cur->getNumBuckets();
            // cur currently has 0 entries
            //tmlog(TM_LOG_NOTE, "Index.cc", "the number of buckets in the current (formerly old) hash table is: %d", hash_size);
            //tmlog(TM_LOG_NOTE, "Index.cc", "the number of entries in the current (formerly old) hash table is: %d", cur->getNumEntries());
            //tmlog(TM_LOG_NOTE, "Index.cc", "the number of entries in the old (formerly cur) has table is: %d", old->getNumEntries());
			/* Balance number of hash buckets */
			/* Hash has twice as many buckets as entries. shrink.
			 * yes, we want to compare the size of cur with the # entries of old (formerly new hash table) */
            /* Why 2.24? The biggest ratio between consecutive numbers in the hash table size list was 29/13, which is 2.23. So, if the hash table
             * size is more than 2.24 times bigger than the number of entries, we can safely shrink the hash table size, to the element before in the
             * hash table size array. 
             */
		    if (hash_size > 2.24*old->getNumEntries()) {
              //if (hash_size < old->getNumEntries()) { 
                // Note that we delete cur - this means we delete the formerly old hash table, which has been written to disk
                //tmlog(TM_LOG_NOTE, "Index.cc", "we are about to delete the current (formerly old) hash table");
				delete cur;
                if (hash_size_index > 1)
                {
                    //tmlog(TM_LOG_ERROR, "Index.cc:addEntry", "we are decreasing hash table size to %d and the number of entries in old hash is %d with %d buckets", hash_size_index - 1, old->getNumEntries(), old->getNumBuckets()); 
				    cur = new IndexHash(hash_size_index - 1);
                }
                else
                    cur = new IndexHash(0);
			}
            
			/* Hash has half as many buckets than entries. enlarge */
            /* UPDATED COMMENT: If 1.82 * hash_size is less than the number of entries, then enlarge the hash table (1.82 was chosen instead of 3/2 = 1.5 because 
             * 1.82 is for the 53/29, which is the smallest and more likely to happen than 3/2. We enlarge it by two (approx factor of 4) via hash table
             * size array. We do this because sometimes, the number of entries were observed to increase by a factor of 4 (tested via the numerous tmlogs you see
             * littering this area of the code). Also, 1.82 worked better than simply 1 or 1.95 in terms of packet drops, it appears. More testing may be needed
             * to determine the optimal number.
             */
            else if (1.82 * hash_size < old->getNumEntries()) {
	    	//else if (1.9*hash_size < old->getNumEntries()) {
            //else if (hash_size > old->getNumEntries()) {
                // Note that we delete cur - this means we delete the formerly old hash table, which has been written to disk
                // for notes about the formerly current, now old hash table, look at the the end of this function defintion for the comments
				delete cur;
                if (hash_size_index < 41)
                {
                    //tmlog(TM_LOG_ERROR, "Index.cc:addEntry", "we are increasing hash table size to %d and the number of entries is %d with %d buckets ", hash_size_index + 2, old->getNumEntries(), old->getNumBuckets());
				    cur = new IndexHash(hash_size_index + 2);
                }
                // Based on experimentation, it should never go here. Hash table sizes range at around 10,000->100,000 only.
                else
                    cur = new IndexHash(old->getNumEntries() + (old->getNumEntries() % 2 + 1));
                /*
                else
                {
                    cur = new IndexHash(
                }
                */
			}
            
            // set last_rotated to be equal to the (from run() ) popped IndexField pointer last element's time stamp
            // the IndexField that was to be added to the hash table
			last_rotated = iqe->ts;
            // increment rotate count
			rotate_count++;

            // unlock disk writing
			storage->getIndexes()->unlockDiskWrite();
		} // end if trylock
	} // end time to rotate

	/* Add the entry */

    // determine if the entry to add is already in the hash table
	IndexEntry* ie=cur->lookup(iqe);
    //tmlog(TM_LOG_NOTE, "addEntry", "check in the lookup for entry with timestamp %f is done and form %s", iqe->ts, iqe->getStr().c_str());

    // if it is not in the Hash table (== NULL)
	if (ie==NULL) {

        //ProfilerStart("/home/lakers/timemachine_results/profile/blah.prof");

        //tmlog(TM_LOG_DEBUG, "addEntry", "beginning to add entry with timestamp %f and form %s", iqe->ts, iqe->getStr().c_str());

		/* the key (ieq->indexField) is now owned by the IndexEntry, resp.
		 * the hash. they will take care about deallocation */
        // convert from IndexField pointer to IndexEntry pointer
        // inputs are IndexField pointer, start interval time, end interval time
        // add this to the hash table
		IndexEntry* ie_n=new IndexEntry(iqe, 
				iqe->ts-IDX_PKT_SECURITY_MARGIN*idx_thread_iat, iqe->ts);
		cur->add(iqe, ie_n);

        // update last_updated time
        last_updated = iqe->ts;

    	//last_updated = iqe->ts;

        //ProfilerStop();
	} else {
        //tmlog(TM_LOG_NOTE, "addEntry", "updating the entry with timestamp %f and form %s", iqe->ts, iqe->getStr().c_str());
        // the entry is already in the hash table
        // update time to include iqe's interval...d_t is difference between end times of intervals? O.o
		// FIXME: this looks ugly. handle the iat in some other way
		ie->update_time(iqe->ts, d_t, idx_thread_iat);
		/* Update an entry. key is no longer needed, so we free it's memory */
		delete iqe;
	}
    // update last_updated time
	//last_updated = iqe->ts;

    // Note that old hash table is now the formerly current hash table. So, it is in the memory, and we can do look up on it
    // This must be the table that Aashish says that indexes do not persist, part of of index persistence (other part is
    // the querying cannot query the stuff in disk, which will be looked into later
}

template <class T>
void Index<T>::debugPrint() const {
	debugPrint(stderr);
}

template <class T>
void Index<T>::debugPrint(FILE *fp) const {
	/*
	hq_t::const_iterator_t i;
	int c;
	printf("-- top 5:\n");
	for (i=hq.nodes.begin(), c=0;
	     i!=hq.nodes.end() && c<5; i++, c++)
	  printf("* %s\n%s\n", i->getConstK()->getStr().c_str(),
	  i->v->getStr().c_str());
	printf("-- bottom 5\n");
	for (i=hq.nodes.end(), i--, c=0;
	     i!=hq.nodes.begin() && c<5; i--, c++)
	  printf("* %s\n%s\n", i->getConstK()->getStr().c_str(),
	  i->v->getStr().c_str());
	*/
	//disk_index.DBStatPrint();
}

template <class T>
void Index<T>::lookupMem(IntervalSet *set, IndexField* key) {
	IndexEntry *ie;
	lock_hash();
	ie = cur->lookup(key);
	if (ie!=NULL) {
		set->add(ie);
		//tmlog(TM_LOG_DEBUG, "query", "Index::lookupMem adding index entry to intset");
	}
	ie = old->lookup(key);
	if (ie!=NULL) {
		set->add(ie);
		//tmlog(TM_LOG_DEBUG, "query", "Index::lookupMem adding index entry to intset using old table");
	}
	/* Add a dummy interval, ranging from "now" FAR into the
	 * future.
	 * Why: When a query is issued, packets may have arrived
	 * and stored to the MemFifo but they may not yet be in 
	 * the index hashes. This dummy interval will ensure, that
	 * these packets are found. 
	 * Maybe it is enough to only add the interval when a 
	 * subscription is requested 
	 */
	set->add(Interval(last_updated-IDX_PKT_SECURITY_MARGIN*idx_thread_iat, 1e13));
		//tmlog(TM_LOG_DEBUG, "query", "Index::lookupMem adding DUMMY interval to intset");
	unlock_hash();
}

// disk_index is of types IndexFiles, from DiskIndex.cc
template <class T>
void Index<T>::lookupDisk(IntervalSet* set, IndexField* key, tm_time_t t0, tm_time_t t1) {
	if (disk_index)
		disk_index->lookup(set, key, t0, t1);
}

template <class T>
void Index<T>::aggregate() {
	if (!disk_index)
		return;
	tm_time_t oldestTimestampDisk; 
	//FIXME: do we really have to lock the queue here??
	lock_queue(); 
	oldestTimestampDisk = this->idx_thread_oldestTimestampDisk;
	unlock_queue();
    // aggregate the oldest files
	disk_index->aggregate(oldestTimestampDisk);
}

/* Main method of the index maintainer thread
 */
template <class T>
void Index<T>::run() {
    // queue length variable
	int myqlen; 
    // IndexField pointer to last element in the queue
	IndexField *iqe;
    //tmlog(TM_LOG_NOTE, "addEntry, run", "the size of the input_q is %d before the lock_queue", input_q.size());
	lock_queue(); // Must have the lock when calling cond_wait
    // run forever
	while(1) {
        // wait for queue to have something?
        // Wait for signal, that data is availabe in the queue 
        // from Index.hh

        //tmlog(TM_LOG_NOTE, "addEntry, run", "the size of the input_q is %d before the cond_wait_queue", input_q.size());

        // called from the cond_broadcast_queue
		cond_wait_queue();

        //tmlog(TM_LOG_NOTE, "addEntry, run", "the size of the input_q is after the cond_wait_queue %d", input_q.size());

		// XXX: Maybe we should read from the queue in burst of, say 10, 
		// entries, so that we don't have that many lock(), unlock() calls
		while (!input_q.empty()) {
            // set iqe pointer to the last element in the queue
			iqe = input_q.back();
            //tmlog(TM_LOG_NOTE, "addEntry, run", "the entry we pop out from back timestamp %f and form %s and index name %s", iqe->ts, iqe->getStr().c_str(), iqe->getIndexName().c_str());
            // pop the last element of the queue from the queue
			input_q.pop_back();
            // set myqlen to the new input queue size after popping the last element
			myqlen = input_q.size();
			// Read oldestTimestampMem while holding the queue lock
            // set the index thread oldest time stamps to the capture thread oldest
            // time stamps
			idx_thread_oldestTimestampMem = cap_thread_oldestTimestampMem;
			idx_thread_oldestTimestampDisk = cap_thread_oldestTimestampDisk;
			idx_thread_iat = cap_thread_iat;
			unlock_queue();

            // not sure how well this lock works, still get some perhaps evidence of race conditions
            // for addEntry
			lock_hash();
            // set qlen to myqlen, the new input queue length
			qlen = myqlen;
            // do the infamous addEntry of the popped IndexField pointer last element
            //tmlog(TM_LOG_NOTE, "addEntry, run", "The entry we are adding has timestamp %f and form %s", iqe->ts, iqe->getStr().c_str());
			addEntry(iqe);
			unlock_hash();
			lock_queue();
		}
	}
	// pro forma
	unlock_queue();
};
#endif
