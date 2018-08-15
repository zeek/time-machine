#ifndef DYNCLASS_HH
#define DYNCLASS_HH

#include "tm.h"
#include "Fifo.hh"
#include "IndexField.hh"

#include <assert.h>
#include <pthread.h>


/* One setting for a dynamic class. 
   Also directly used to store entries in the hashtable, so
   DynClass also contains the key and pointers fo the collision list
   And DynClass also contains pointers for a sorted list/queue that 
   determine the order of the timeouts
   XXX: Not very reuseable, but I don't care at the moment
*/
class DynClass {
public:
	DynClass() : key(NULL), target(NULL), timeout(0), colNext(NULL), colPrev(NULL), qNext(NULL), qPrev(NULL)
	{ };
	DynClass(IPAddress *key, int dir, Fifo *target, tm_time_t timeout) : 
		key(key), target(target), timeout(timeout), colNext(NULL), colPrev(NULL), qNext(NULL), qPrev(NULL)
	{ };

	IPAddress *key;
	Fifo *target;
    // direction, probably means direction of the packet (source, destination, maybe both (see Storage.cc))
	int dir;
	tm_time_t timeout;

    // pointers for the collision list? O.o
	DynClass *colNext;
	DynClass *colPrev;

	// List, kept in sorted order of timestamps
	DynClass *qNext;
	DynClass *qPrev;
};

/*
struct DynClassTimeCmp : public std::binary_function<DynClass*, DynClass*, bool> {
	bool operator()(DynClass *a, DynClass *b) { return a->timeout > b->timeout; }
};
*/


class DynClassTable {
public:
	DynClassTable(int size);
	~DynClassTable();

	void clear();

	int getNumEntries() {
		return numEntries;
	}
	int getNumBuckets() {
		return numBuckets;
	}
	void lock() {
		pthread_mutex_lock(&dc_mutex);
	}
	void unlock() {
		pthread_mutex_unlock(&dc_mutex);
	}

	DynClass *get(const IPAddress *key);
	//void insert(DynClass *dc);
	void insert_or_update(IPAddress *key, int dir, Fifo *target, tm_time_t timeout);
	// Remove from table. nothing is deallocated. That's up to the caller. 
	// Returns the element just removed. 
	// dc must point to a valid entry (i.e. colPrev, colNext of dc must be valid)
	DynClass *remove(IPAddress *key);
	DynClass *remove(DynClass *dc);

	// Remove all entries that have timed out 
	void removeOld();

protected:
	pthread_mutex_t dc_mutex;
	DynClass *getNoLock(const IPAddress *key);
	DynClass *removeNoLock(DynClass *dc);
	void remove_from_table(DynClass *dc);
	void remove_from_q(DynClass *dc);
#ifdef TM_HEAVY_DEBUG
	void dbg_verify() {
		DynClass *cur, *next;
		int i=0;
		next = qhead;
		cur = NULL;
		while(next) {
			cur=next;
			i++;
			next=cur->qNext;

			if (cur->qNext)
				assert(cur->qNext->qPrev == cur);
			if (cur->qPrev)
				assert(cur->qPrev->qNext == cur);
			/*if (next)
				assert(cur->timeout <= next->timeout);*/
			//----fprintf(stderr, "%4i: %s %s %lf\n", i, cur->key->getStr().c_str(), cur->target->getClassname().c_str(), cur->timeout);
		}
		assert(qtail == cur);
		//assert(i==numEntries);
		//----fprintf(stderr, "i=%d, numEntries=%d\n", i, numEntries);
	}
#endif
	int numEntries;
	int numBuckets;

	// the hash table
	// table[i].colNext  points to the first element in the list
	// table[i].colPrev  is always NULL.
	// the head and tail elements of the coll list have their 
	// colPrev resp. colNext pointers NULL
	DynClass *table;

	// A double-linked list kept in sorted timeout order
	// qhead points to the entry with the lowest timeout
	// qtail to the entry with the highest timeout. 
	// Both pointers point to DynClass instances actually carring data, so they
	// are unlike table[i]
	DynClass *qhead;
	DynClass *qtail;
	//std::priority_queue<DynClass*, std::vector<DynClass*>, DynClassTimeCmp> pq;

};

#endif
