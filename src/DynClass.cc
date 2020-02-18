#include <assert.h>

#include "tm.h"
#include "IndexField.hh"
#include "DynClass.hh"

DynClassTable::DynClassTable(int size) : 
	numEntries(0),
	numBuckets(size),
	qhead(NULL),
	qtail(NULL)
{
	pthread_mutex_init(&dc_mutex, NULL);
	table = new DynClass[numBuckets];
}
	
DynClassTable::~DynClassTable() {	
	clear();
	pthread_mutex_destroy(&dc_mutex);
	delete[] table;
}

/* Clear all entries.  Deallocate keys, leave Fifos alone */
void DynClassTable::clear() {
	lock();
	DynClass *next, *cur;
	for (int i=0; i<numBuckets; i++) {
		next = table[i].colNext; 
		while(next!=NULL)  {
			cur = next;
			next=cur->colNext;
			delete(cur->key);
			delete(cur);
			numEntries--;
		}
	}
	qhead=NULL;
	qtail=NULL;
	assert(numEntries==0);
	unlock();
}

DynClass* DynClassTable::remove(IPAddress *k) { 
	DynClass *dc;
	lock();
	dc = getNoLock(k);
	removeNoLock(dc);
	unlock();
	return dc;
}

DynClass* DynClassTable::remove(DynClass *dc) { 
	lock();
	removeNoLock(dc);
	unlock();
	return dc;
}
DynClass* DynClassTable::removeNoLock(DynClass *dc) { 
	if (!dc)
		return NULL;
	remove_from_table(dc);
	remove_from_q(dc);
	numEntries--;
#ifdef TM_HEAVY_DEBUG
	dbg_verify();
#endif
	return dc;
}

// Remove from hashtable only
void DynClassTable::remove_from_table(DynClass *dc) { 
	DynClass *cell;


	cell = &(table[dc->key->hash()%numBuckets]);

	// Check if have to update the col list head
	if (cell->colNext == dc) 
		cell->colNext = dc->colNext;
	// remove dc from col list	
	if (dc->colNext) {
#ifdef TM_HEAVY_DEBUG
		assert(dc->colNext->colPrev == dc);
#endif
		dc->colNext->colPrev = dc->colPrev;
	}
	if (dc->colPrev) {
#ifdef TM_HEAVY_DEBUG
		assert(dc->colPrev->colNext == dc);
#endif
		dc->colPrev->colNext = dc->colNext;
	}
	dc->colNext = dc->colPrev = NULL;
}


// REmoved dc from the queue only 
void DynClassTable::remove_from_q(DynClass *dc) { 
	/* Queue */
	// check q list head 
	if (qhead == dc)
		qhead = dc->qNext;
	if (qtail == dc)
		qtail = dc->qPrev;
	// remove dc from q list	
	if (dc->qNext) {
#ifdef TM_HEAVY_DEBUG
		assert(dc->qNext->qPrev == dc);
#endif
		dc->qNext->qPrev = dc->qPrev;
	}
	if (dc->qPrev) {
#ifdef TM_HEAVY_DEBUG
		assert(dc->qPrev->qNext == dc);
#endif
		dc->qPrev->qNext = dc->qNext;
	}

	dc->qNext = dc->qPrev = NULL;
}


void DynClassTable::removeOld() {
	//struct timeval tv;
	tm_time_t now;
	DynClass *next, *cur;

	lock();
	//gettimeofday(&tv, NULL);

    /*
    #ifdef __APPLE__
    struct tvalspec tmptv;
    clock_get_time(CLOCK_MONOTONIC_COARSE, &tmptv)i;
    now = valspec_to_tm(&tmptv);
    #endif
    */
    /*
    #ifdef linux
    struct timespec tmptv;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &tmptv);
    now = spec_to_tm(&tmptv);
    #endif
    #ifdef __FreeBSD__
    struct timespec tmptv;
    clock_gettime(CLOCK_MONOTONIC_FAST, &tmptv);
    now = spec_to_tm(&tmptv);
    #endif
    */
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    now = to_tm_time(&tv);
    
	//now = to_tm_time(&tv);

    // set next to pointer to the entry with the lowest timeout (timeouts are sorted)
	next = qhead;
    // as long as it is not null?
	while (next) {
		cur = next;
        // next to the next entry
		next = cur->qNext;
        // if the timeout parameter of the dynamic class pointer is less than the current time,
        // it is and old connection and should be removed from Hash table and sorted list/queue that 
        // determine the order of the timeouts
		if (cur->timeout < now) {
			//fprintf(stderr, "GMDEBUG: Removing dynClass: %s\n", cur->key->getStr().c_str());
			removeNoLock(cur);
            // delete the key and entry that seem to be by themselves now (the removeNoLock doesn't seem to actually delete, just re-arrange the pointers)
			delete(cur->key);
			delete(cur);
		}
		else
			break;
	}

	/* DEBUG */
#ifdef TM_HEAVY_DEBUG
	dbg_verify();
#endif
	/***/
	unlock();
}


/* Return the DC identified by K */
DynClass* DynClassTable::get(const IPAddress* k) { 
	DynClass *dc;
	lock();
	dc = getNoLock(k);
	unlock();
	return dc;
}

DynClass* DynClassTable::getNoLock(const IPAddress* k) { 
	DynClass *next;
    
    // get the collision list of the entry in hash table, it looks like
    // this particular command colNext sets it to the first element of the
    // collision list
	next = table[k->hash()%numBuckets].colNext;

    //tmlog(TM_LOG_NOTE, "DynClassTable::getNoLock", "the k->hash() is %u", k->hash());
    //tmlog(TM_LOG_NOTE, "DynClassTable::getNoLock", "the k->hash()_numBuckets is %u and the numBuckets is %d", k->hash()%numBuckets, numBuckets);
    // as long as the element we are on is not NULL
	while(next!=NULL) {
        // check if the key matches the ip address key
		if (*k == *(next->key)) {
			return next;
		}
        // if not, move on to the next element in the collision list
		next = next->colNext;
	}
	return NULL;
}


void DynClassTable::insert_or_update(IPAddress *key, int dir, Fifo *target, tm_time_t endtime) {
	DynClass *head=NULL, *cell=NULL, *dc=NULL, *prev=NULL, *cur=NULL;

	lock();
	dc = getNoLock(key);
	// Handle insert / update in hashtable
	if (dc) {
		delete key;
		dc->target  = target;
		dc->dir = dir;
		dc->timeout = endtime;
		remove_from_q(dc);
	}
	else {
		dc = new DynClass(key, dir, target, endtime);
		/* Insert into HashTable */
		cell = &(table[key->hash()%numBuckets]);
		head = cell->colNext;

		dc->colNext = head;
		if (head)
			head->colPrev = dc;
		cell->colNext = dc;  // set new head pointer
		numEntries++;
	}

	// Now insert into q, q is sorted by timeout
	if (qhead==NULL) {
		qhead=qtail=dc;
	}
	else {
		prev = qtail;
		// find position to insert
		while(prev) {
			cur = prev;
			prev = cur->qPrev;
			if (cur->timeout <= dc->timeout) {
				break;
			}
		}
		if (cur->timeout <= dc->timeout) {
			dc->qNext = cur->qNext;
			dc->qPrev = cur;
			if (cur->qNext)
				cur->qNext->qPrev = dc;
			cur->qNext = dc;
			if (qtail==cur)
				qtail = dc;
		}
		else {
			dc->qPrev = cur->qPrev;
			dc->qNext = cur;
			if (cur->qPrev) 
				cur->qPrev->qNext = dc;
			cur->qPrev = dc;
			if (qhead==cur)
				qhead = dc;
		}
	} // end else

#ifdef TM_HEAVY_DEBUG
	dbg_verify();
#endif
	unlock();
}
			
			
