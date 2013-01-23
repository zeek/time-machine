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

// $Id: DynClass.cc 208 2007-09-05 18:33:13Z gregor $

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
	struct timeval tv;
	tm_time_t now;
	DynClass *next, *cur;

	lock();
	gettimeofday(&tv, NULL);
	now = to_tm_time(&tv);

	next = qhead;
	while (next) {
		cur = next;
		next = cur->qNext;
		if (cur->timeout < now) {
			//fprintf(stderr, "GMDEBUG: Removing dynClass: %s\n", cur->key->getStr().c_str());
			removeNoLock(cur);
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

	next = table[k->hash()%numBuckets].colNext;
	while(next!=NULL) {
		if (*k == *(next->key)) {
			return next;
		}
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
			
			
