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

// $Id$


#include "IndexHash.hh"
IndexHash::IndexHash(size_t size) {
	htable = new hash_t[size];
	numEntries = 0;
	numBuckets = size;
	for (unsigned i=0; i<size; i++)
		htable[i] = NULL;
	troot = tnext = tprev = tcur = NULL;
}

IndexHash::~IndexHash() {
	clear();
	delete []htable;
}

int IndexHash::clear() {
	IndexEntry *col_cur, *col_next;
	unsigned count = 0;
	
	troot = tnext = tprev = tcur = NULL;
	for (unsigned i=0; i<numBuckets; i++) {
		col_next = htable[i];
		while (col_next) {
			col_cur = col_next;
			col_next = col_cur->col_next;
			delete col_cur;
			count++;
		}
		htable[i]=NULL;
	}
	assert(count == numEntries);
	numEntries = 0;
	return count;
}


IndexEntry* IndexHash::lookup( IndexField* key) {
	IndexEntry *cur;

	cur = htable[key->hash()%numBuckets];
	while (cur != NULL) {
		if (*key == *cur->getKey()) {
			break;
		}
		cur = cur->col_next;
	}
	return cur;
}

void IndexHash::add(IndexField *key, IndexEntry *ie) {
	IndexEntry *cur, *prev;
	int cmp;
	cur = troot;
	prev = NULL;
	cmp = 0;
#ifdef TM_HEAVY_DEBUG
	assert(!lookup(key));
	if (troot)
		assert(troot->parent == NULL);
	assert(ie->parent == NULL);
	assert(ie->left == NULL);
	assert(ie->right == NULL);
	assert(ie->avlbal == 0);
#endif
	
	while (cur) {
#ifdef TM_HEAVY_DEBUG
		assert(cur->avlbal>=-1 && cur->avlbal<=1);
#endif
		prev = cur;
		cmp = memcmp(key->getConstKeyPtr(), cur->getKey()->getConstKeyPtr(), key->getKeySize());
		if (cmp > 0)
			cur = cur->left;
		else if (cmp < 0)
			cur = cur->right;
		else {
			tmlog(TM_LOG_ERROR, "idx_hash",  "tried to insert an already existing entry into the tree. numEntries=%d\n",
					getNumEntries());
			//h->add_or_update(key, ie);
			abort();
			return ; // entry exists, shouldn't happen	
		}
	}

	if (!troot) {
		troot = ie;
#ifdef TM_HEAVY_DEBUG
		assert(troot->parent == NULL);
		assert(troot->left == NULL);
		assert(troot->right == NULL);
		assert(troot->avlbal == 0);
#endif
	}
	else {
#ifdef TM_HEAVY_DEBUG
		assert(prev);
		assert(!cur);
		assert(cmp!=0);
#endif
		// We are now at a terminal node. Insert the entry
		ie->parent = prev;
		if (cmp>0) {
			prev->left = ie;
			prev->avlbal--;
		}
		else {
			prev->right = ie;
			prev->avlbal++;
		}
		rebalance(prev);
	}

	unsigned hval;

	hval = key->hash()%numBuckets;

	ie->col_next = htable[hval];
	ie->col_prev = NULL;
	htable[hval] = ie;
	
	if (ie->col_next != NULL) 
		ie->col_next->col_prev = ie;

	numEntries++;
	return;
}


// rebalance an avl tree. 
// cur is the parent of the just inserted node
// Haven' bothered if this code could also be used to rebal after delete
void IndexHash::rebalance(IndexEntry *cur) {
	while (cur) {
		/* Case 1: new node was added on the shorter subtree. we are donw */
		if (cur->avlbal == 0) 
			return;
		/* Case 2: the new node was added to a balanced node. Propagade
		 * upwards
		 */
		else if (cur->avlbal == -1 || cur->avlbal == 1) {
			if (cur->parent) { //not the root
				if (cur == cur->parent->left)  //cur is a left child
					cur->parent->avlbal--;
				else // right child
					cur->parent->avlbal++;
			} // end: not the root
			else 
				return;
			cur = cur->parent;
		}
		/* Case 3a: AVL condition is violated in left subtree
		 * We must roate */
		else if (cur->avlbal == -2) {
			if (cur->left->avlbal == -1) {  // Singe rotation 
				rot_right(cur);
			}
			else {
				rot_left_right(cur);
			}
			return;
		}
		/* Case 3b: AVL condition is violated in right subtree.
		 * We must roate */
		else if (cur->avlbal == +2) {
			if (cur->right->avlbal == +1) {  // Singe rotation 
				rot_left(cur);
			}
			else {
				rot_right_left(cur);
			}
			return;
		}
		else
			abort();
	}
	
	
}

void IndexHash::initWalk (void) {
	tnext = troot;
	tcur = tprev = NULL;
	height = 0;
	level = 0;
}

// Do an in-order tree walk. Delete Elements from the hash if
// their node and their subtrees have been vistied. NOTE that the
// order in which the elements are delete does NOT correspond with
// the order in which the are returned! 
IndexEntry * IndexHash::getNextDelete (void) {
	while (tnext) {
#ifdef TM_HEAVY_DEBUG
		assert(tnext->avlbal>=-1 && tnext->avlbal<=1);
#endif
		if (level>height)
			height = level;
		tprev = tcur;
		tcur = tnext;
		if (tprev) {
			if (tprev->parent == tcur) {
				// we cam from below. tprev has been completly
				// viisted. can erase it.
				eraseEntry(tprev);
			}
		}
		if (tprev == tcur->parent) { // came from above, or we are the troot
			tnext = tcur->left;
			level++;
			if (!tnext) { // no left child. 
				level--;
				if (tcur->right) {
					tnext = tcur->right;
					level++;
				}
				else {
					tnext = tcur->parent;
					level--;
				}
				return tcur; // visit the node;
			}
		} 
		else if (tprev == tcur->left) { // came from the left
			if (tcur->right) {
				level++;
				tnext = tcur->right;
			}
			else {
				level--;
				tnext = tcur->parent;
			}
			return tcur;
		}
		else { // came from right. we are done with all subtrees
			tnext = tcur->parent;
			level--;
		}
	}
	/* when we get when there's only the root left */
#ifdef TM_HEAVY_DEBUG
	assert(tcur == troot);
	assert(getNumEntries() == 1);
#endif
	if (troot) 
		eraseEntry(troot);
	troot = tnext = tprev = tcur = NULL;
	return NULL;
}


void IndexHash::eraseEntry(IndexEntry *ie) {
	/* remove from collision list */
	if (ie->col_next)
		ie->col_next->col_prev = ie->col_prev;

	if (ie->col_prev) 
		ie->col_prev->col_next = ie->col_next;
	else { 
		/* first in list. update pointer in hashtable.
		 * XXX: Ugly: find a nicer way
		 */
		htable[ie->key->hash()%numBuckets] = ie->col_next;
	}
	delete ie;
	numEntries--;
}




