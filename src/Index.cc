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
Index<T>::Index(tm_time_t d_t, uint32_t hash_size, bool do_disk_index, Storage *storage):
		input_q(MyQueue(500000)),
		cap_thread_iat(0), idx_thread_iat(0),
		d_t(d_t),
		last_rotated(0),
		last_updated(0),
		num_entries_disk(0),
		storage(storage),
		rotate_count(0){
	cur = new IndexHash(hash_size);
	old = new IndexHash(hash_size);
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
	tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "Index<T>::~Index");

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
	tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "Canceling Index Thread.");
	pthread_cancel(maintainer_thread);
	tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "   Canceled. Now Joining.");
	pthread_join(maintainer_thread, NULL);
	tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "   Joined.");
}

/* Called by the capture thread */
template <class T>
void Index<T>::addPkt(const pcap_pkthdr* header, const u_char* packet) {
	static tm_time_t last = to_tm_time(&header->ts);
	tm_time_t now=to_tm_time(&header->ts);
	T* curentry;

	lock_queue();
	for (int i=0; i<T::keysPerPacket(); i++) {
		curentry = T::genKey(packet, i);
#ifdef TM_HEAVY_DEBUG
		assert(curentry);
#endif
		curentry->ts = now;
		input_q.push_front(curentry);
	}
	cap_thread_oldestTimestampMem = storage->getOldestTimestampMemHacked();
	cap_thread_oldestTimestampDisk = storage->getOldestTimestampDisk();
	cap_thread_iat = (cap_thread_iat  + (now - last))/2.0; /* Weighted avg of IAT */
	last = now;
	//TODO: Dont' hardcode the qlen 
	if (input_q.size() > 10) 
		cond_broadcast_queue();
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
	int hash_size;
	IndexHash *tmp;
	if (last_rotated<1e-3)
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
	if ((last_rotated < idx_thread_oldestTimestampMem) &&
			qlen < cur->getNumEntries()) {
		if (storage->getIndexes()->trylockDiskWrite() == 0) {

			tmlog(TM_LOG_NOTE, T::getIndexNameStatic().c_str(), "Rotate. Old=%d. Cur=%d. Buckets=%d. qlen=%d.",  
						old->getNumEntries(), cur->getNumEntries(), cur->getNumBuckets(), qlen);
			// Write the old hash to disk.
			if (old->getNumEntries() != 0)
			{ 
				if (disk_index) {
					tmlog(TM_LOG_NOTE, T::getIndexNameStatic().c_str(), 
							"Writing %d entries to disk.",  old->getNumEntries());
					// writeIndex will delete the entries from the hash
					disk_index->writeIndex(old);
				} else {
					// not disk writer
					old->clear();
				}
#ifdef TM_HEAVY_DEBUG
				tmlog(TM_LOG_DEBUG, T::getIndexNameStatic().c_str(), "Qlen now is %d", input_q.size());
				assert(old->getNumEntries() == 0);
#endif
			}
			tmp = cur;
			cur = old;
			old = tmp;
			hash_size = cur->getNumBuckets();
			/* Balance number of hash buckets */
			/* Hash has twice as many buckets as entries. shrink.
			 * yes, we want to compare the size of cur with the # entries of old */
			if (hash_size > 2*old->getNumEntries()) { 
				delete cur;
				cur = new IndexHash(hash_size/2);
			}
			/* Hash has half as many buckets than entries. large */
			else if (2*hash_size < old->getNumEntries()) {
				delete cur;
				cur = new IndexHash(2*hash_size);
			}
			last_rotated = iqe->ts;
			rotate_count++;
			storage->getIndexes()->unlockDiskWrite();
		} // end if trylock
	} // end time to rotate

	/* Add the entry */
	IndexEntry* ie=cur->lookup(iqe);
	if (ie==NULL) {
		/* the key (ieq->indexField) is now owned by the IndexEntry, resp.
		 * the hash. they will take care about deallocation */
		IndexEntry* ie_n=new IndexEntry(iqe, 
				iqe->ts-IDX_PKT_SECURITY_MARGIN*idx_thread_iat, iqe->ts);
		cur->add(iqe, ie_n);
	} else {
		// FIXME: this looks ugly. handle the iat in some other way
		ie->update_time(iqe->ts, d_t, idx_thread_iat);
		/* Update an entry. key is no longer needed, so we free it's memory */
		delete iqe;
	}
	last_updated = iqe->ts;
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
		tmlog(TM_LOG_DEBUG, "query", "Index::lookupMem adding index entry to intset");
	}
	ie = old->lookup(key);
	if (ie!=NULL) {
		set->add(ie);
		tmlog(TM_LOG_DEBUG, "query", "Index::lookupMem adding index entry to intset");
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
		tmlog(TM_LOG_DEBUG, "query", "Index::lookupMem adding DUMMY interval to intset");
	unlock_hash();
}

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
	disk_index->aggregate(oldestTimestampDisk);
}

/* Main method of the index maintainer thread
 */
template <class T>
void Index<T>::run() {
	int myqlen; 
	IndexField *iqe;
	lock_queue(); // Must have the lock when calling cond_wait
	while(1) {
		cond_wait_queue();
		// XXX: Maybe we should read from the queue in burst of, say 10, 
		// entries, so that we don't have that many lock(), unlock() calls
		while (!input_q.empty()) {
			iqe = input_q.back();
			input_q.pop_back();
			myqlen = input_q.size();
			// Read oldestTimestampMem while holding the queue lock
			idx_thread_oldestTimestampMem = cap_thread_oldestTimestampMem;
			idx_thread_oldestTimestampDisk = cap_thread_oldestTimestampDisk;
			idx_thread_iat = cap_thread_iat;
			unlock_queue();
			lock_hash();
			qlen = myqlen;
			addEntry(iqe);
			unlock_hash();
			lock_queue();
		}
	}
	// pro forma
	unlock_queue();
};
#endif
