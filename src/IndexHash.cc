#include "IndexHash.hh"
#include <iostream>

/*
 * Pseudo-proof about use of prime number hash table sizes. Please let me
 * know if you find something wrong in the proof via email.
 *
 * The indexes in the hash table are calculated by doing key mod (hash table
 *  size).
 * The statement to prove is: number of buckets used = hash_table_size / GCF(hash_table_size, factor).
 *
 * We can note that there exists y / GCF(y, n) distinct instances of m * n (mod y) for all m.
 * To see why this is true, we can let a = GCF(y, n).
 * Let n be a particular key, and y = a * x and n = a * b
 * Let's say we have n mod y, which can be written as (a * b) (mod a * x)
 * So, note that (a * b) (mod a * x) = a * (b + x) (mod a * x), since a * b + a * x (mod a * x) = a * b (mod a * x)
 * So, we only have x instances of unique remainders for all numbers with a
 * factor of a.
 * Note that y = a * x, which can be written as x = y / a
 * So, x = y / GCF(y, n)
 * We want x to be equal to y, since we want to utilize all the buckets in the
 * hash table.
 * So, GCF(y, n) = 1, which leads to only y being prime would suffice.
 * So, we need a prime number hash size to avoid clustering.
 */

static const uint64_t IndexHash_primes[] = {1, 2, 3, 7, 13, 29, 53, 97, 193, 389, 769, 1543, 3079, 6151, \
                                            12289, 24593, 49517, 98317, 196613, 393241, 786433, 1572869, \
                                            3145739, 6291469, 12582917, 25165843, 50331653, 100663319, \
                                            201326611, 402653189, 805306457, 1610612741, 3221225479, \
                                            6442450967, 12884901947, 25769803897, 51539607793, 103079215583, \
                                            206158431161, 412316862319, 824633724619, 1649267449241};

const uint64_t* IndexHash::Primes = IndexHash_primes; 

IndexHash::IndexHash(int size_index) {
    /*
    primes[0] = 1;
    primes[1] = 2;
    primes[2] = 3;
    primes[3] = 7;
    primes[4] = 13;
    primes[5] = 29;
    primes[6] = 53;
    primes[7] = 97;
    primes[8]] = 193;
    primes[9] = 389;
    primes[10] = 769;
    primes[11] = 1543;
    primes[12] = 3079;
    primes[13] = 6151;
    primes[14] = 12289;
    primes[15] = 24593;
    primes[16] = 49157;
    primes[17] = 98317;
    primes[18] = 196613;
    primes[19] = 393241;
    primes[20] = 786433;
    primes[21] = 1572869;
    primes[22] = 3145739;
    primes[23] = 6291469;
    primes[24] = 12582917;
    primes[25] = 25165843;
    primes[26] = 50331653;
    primes[27] = 100663319;
    primes[28] = 201326611;
    //primes[29] = 402653189;
    //primes[30] = 805306457;
    //primes[31] = 1610612741;
    //primes[32] = 3221225479;
    //primes[33] = 6442450967;
    //primes[34] = 12884901947;
    */
	numEntries = 0;
	numBucketsIndex = size_index;
    if (size_index < 43)
        numBuckets = Primes[size_index];
    else
        numBuckets = size_index;

    htable = new hash_t[numBuckets];

	for (unsigned i=0; i<numBuckets; i++)
		htable[i] = NULL;
	troot = tnext = tprev = tcur = NULL;
}

IndexHash::~IndexHash() {
	clear(); // removing this clear feels dangerous, not sure why it is failing
	delete []htable;
}

int IndexHash::clear() {
	IndexEntry *col_cur, *col_nextt;
	unsigned count = 0;
	
	troot = tnext = tprev = tcur = NULL;
	for (unsigned i=0; i<numBuckets; i++) {
		col_nextt = htable[i];
		while (col_nextt) {
            //tmlog(TM_LOG_NOTE, "idxhash: clear()", "entering the while loop for deletion for bucket number %d", i);
			col_cur = col_nextt;
            //IndexField *key_curr;
            //key_curr = col_nextt->getKey();
            //if (key_curr != NULL)
                //tmlog(TM_LOG_NOTE, "idxhash: clear()", "the entry to delete has key with form %s", key_curr->getIndexName().c_str());
			col_nextt = col_cur->col_next;
            //tmlog(TM_LOG_NOTE, "idxhash: clear()", "about to delete a collision list entry");
			delete col_cur;
			count++;
		}
		htable[i]=NULL;
        //tmlog(TM_LOG_NOTE, "idxhash: clear()", "we make the bucket number %d NULL", i);
	}
	assert(count == numEntries);
	numEntries = 0;
	return count;
}

IndexEntry* IndexHash::lookup( IndexField* key) {
/*
    //IndexEntry *cur;

    //tmlog(TM_LOG_NOTE, "idxhash", "checking that there is not a similar key for this timestamp: %f and info: %s", key->ts, key->getStr().c_str());
    //printf("This key has the following form: " + key->getStr() + "\n");

    //std::cout << "This key has the following form: " << key->getStr() << std::endl;

    //cur = htable[key->hash()%numBuckets];

    //cur = htable[key->getInt()%numBuckets];

    //tmlog(TM_LOG_NOTE, "idxhash", "the hash is: %u for this timestamp %f and form %s", key->hash(), key->ts, key->getStr().c_str());
    //tmlog(TM_LOG_NOTE, "idxhash", "the index is: %u for this timestamp %f and form %s", key->hash()%numBuckets, key->ts, key->getStr().c_str());
    //tmlog(TM_LOG_NOTE, "idxhash", "the number of buckets is %d for this timestampe %f and form %s", numBuckets, key->ts, key->getStr().c_str());

    // testing out the other method in add method to determine if this would help
    IndexEntry *curalt;
    int cmp;
    curalt = troot;
    cmp = 0;
#ifdef TM_HEAVY_DEBUG
    if (troot)
        assert(troot->parent == NULL);
#endif

    //tmlog(TM_LOG_NOTE, "idx_hash: lookup", "the entry to add 'lookup' has key: %d", *(key->getConstKeyPtr()));

    //tmlog(TM_LOG_NOTE, "idx_hash: lookup", "the entry to add 'lookup' has timestamp: %f", key->ts);

    while (curalt) {
#ifdef TM_HEAVY_DEBUG
        assert(curalt->avlbal>=-1 && curalt->avlbal<=1);
#endif
        cmp = memcmp(key->getConstKeyPtr(), curalt->getKey()->getConstKeyPtr(), key->getKeySize());
        if (cmp > 0)
            curalt = curalt->left;
        else if (cmp < 0)
            curalt = curalt->right;
        else {
            //tmlog(TM_LOG_NOTE, "idx_hash: lookup", "this is in lookup using the add method checker. the already existing entry is: %d\n", *(curalt->getKey()->getConstKeyPtr()));
            //tmlog(TM_LOG_NOTE, "idx_hash: lookup",  "this is in lookup using the add method checker. tried to insert an already existing entry into the tree. numEntries=%d\n",
                    getNumEntries());
            break;
            //h->add_or_update(key, ie);
        }
    }
   
    if (curalt == NULL)
        //tmlog(TM_LOG_NOTE, "idxhash", "cur is NULL, which means that this entry is allegedly unique");
    
    return curalt;
*/

    IndexEntry *cur;

    cur = htable[key->hash()%numBuckets];

    /*
    //tmlog(TM_LOG_NOTE, "IndexHash:Lookup", "huh, number of buckets is shit %d and the key is %d", numBuckets, key->hash());

    if (numBuckets > 0)
    {

        //tmlog(TM_LOG_NOTE, "IndexHash:Lookup", "huh, can we do modular shit, %d", key->hash()%numBuckets);

        cur = htable[key->hash()%numBuckets];

        while (cur != NULL) {
            //tmlog(TM_LOG_NOTE, "idxhash", "going through the keys: %d", *cur->getKey()->getConstKeyPtr());
            if (*key == *cur->getKey()) {
            //if (*(key->getConstKeyPtr()) == *(cur->getKey()->getConstKeyPtr())) {
                //tmlog(TM_LOG_NOTE, "idxhash", "the same key was found. the key is %d", *(key->getConstKeyPtr()));
                break;
            }
            cur = cur->col_next;
        }
        //tmlog(TM_LOG_NOTE, "idx_hash", "this entry has key: %d", *(key->getConstKeyPtr()));
        //if (cur == NULL)
        //    tmlog(TM_LOG_NOTE, "idxhash", "cur is NULL, which means that this entry is allegedly unique");
        return cur;

    }
    else
    {
        tmlog(TM_LOG_ERROR, "IndexHash:Lookup", "numBuckets <= 0 and is %d", numBuckets);
        return NULL;
    }
    */
   
    while (cur != NULL) {
        //tmlog(TM_LOG_NOTE, "idxhash", "going through the keys: %d", *cur->getKey()->getConstKeyPtr());
        if (*key == *cur->getKey()) {
        //if (*(key->getConstKeyPtr()) == *(cur->getKey()->getConstKeyPtr())) {
            //tmlog(TM_LOG_NOTE, "idxhash", "the same key was found. the key is %d", *(key->getConstKeyPtr()));
            break;
        }
        cur = cur->col_next;
    }
    //tmlog(TM_LOG_NOTE, "idx_hash", "this entry has key: %d", *(key->getConstKeyPtr()));
    //if (cur == NULL)
    //    tmlog(TM_LOG_NOTE, "idxhash", "cur is NULL, which means that this entry is allegedly unique");
    return cur;
    
}

void IndexHash::add(IndexField *key, IndexEntry *ie) {

    //tmlog(TM_LOG_NOTE, "idx_hash", "entering the add method");

    /*
	const void* old_val = Insert(ie, key);

    // A same entry was already in the table
    if (old_val)
    {
        tmlog(TM_LOG_NOTE, "idx_has", "we already have the same entry!");
        delete ie;
        return;
    }

    else
    {
    */
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
	
        //tmlog(TM_LOG_NOTE, "idx_hash", "the entry to add has key: %d", *(key->getConstKeyPtr()));

        //tmlog(TM_LOG_NOTE, "idx_hash", "the entry to add has timestampe: %f", key->ts);

	    while (cur) {
    #ifdef TM_HEAVY_DEBUG
		    assert(cur->avlbal>=-1 && cur->avlbal<=1);
    #endif

		    prev = cur;
            // determine where to put the entry?
            // determines where current pointer to Index Entry should be (transversing through tree)
            // this compares the 16 bytes/128-bit char arrays
		    cmp = memcmp(key->getConstKeyPtr(), cur->getKey()->getConstKeyPtr(), key->getKeySize());
            /*
	        if ( key->hash() == cur->getKey()->hash() &&
	             cmp )
		        {
	                unsigned hvalconflict;

	                hvalconflict = key->hash()%numBuckets;

	                ie->col_next = htable[hvalconflict];
	                ie->col_prev = NULL;
	                htable[hvalconflict] = ie;
                    return;
		        }
            */
			/*
            if ( key->hash() == cur->getKey()->hash() &&
                 !cmp )
                {
					cur->intlist = ie->intlist;
                    delete ie;
                    return;
                }
			*/

		    if (cmp > 0)
			    cur = cur->left;
		    else if (cmp < 0)
			    cur = cur->right;
		    else 
            {
                delete ie; 
                //tmlog(TM_LOG_NOTE, "idx_hash", "the already existing entry is: %d\n", *(cur->getKey()->getConstKeyPtr()));
			    //tmlog(TM_LOG_ERROR, "idx_hash",  "tried to insert an already existing entry into the tree. numEntries=%d\n",
					    //getNumEntries());
			    //h->add_or_update(key, ie);
                //delete ie;
                 // delete key;
			    //abort();
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

        //if (numBuckets > 0)
        //{

	    hval = key->hash()%numBuckets;

	    ie->col_next = htable[hval];
	    ie->col_prev = NULL;
	    htable[hval] = ie;
        //}
        //ie->key->hash_key = hval;

        //tmlog(TM_LOG_NOTE, "idxhash", "this entry for which we have foudn the bucket value %d for has this timestamp %f and form %s", hval, key->ts, key->getStr().c_str());

        //tmlog(TM_LOG_NOTE, "idx_hash", "setting an entry in the hash table at %d", hval);
	
	    if (ie->col_next != NULL) 
		    ie->col_next->col_prev = ie;

	    numEntries++;
	    return;
    //}
}

/*
// private
const void* IndexHash::Insert(IndexEntry* new_entry, IndexField *key)
{
	//int* num_entries_ptr;
	//int* max_num_entries_ptr;
	unsigned h;
    h = key->hash() % numBuckets;

	IndexEntry* chain = htable[h];

	int n = key->getKeySize();

    // if a collisions list/element exists in that particular spot in the hash table
	if ( chain )
	{
        IndexEntry *cur = chain;
        
        // go through all the elements in the collisions list
	    while (cur != NULL)
	    {
	        IndexEntry entry = *chain;

            // the hashes, length, and the keys are all the same
            // then that means the entry with the same exact parameters
            // already exists. So, we just return the old entry value.
	        if ( entry.getKey()->hash() == key->hash() &&
	             entry.getKey()->getKeySize() == n &&
	             ! memcmp(entry.getKey()->getConstKeyPtr(), key->getConstKeyPtr(), n) )
		        {
                    const void* old_value;
                    if (key->getConstKeyPtr() != 0)
                        old_value = key->getConstKeyPtr();
		            return old_value;
		        }
            // next element in collisions list
            cur = cur->col_next;
	    }
	}

	else
		// Create new chain.
		chain = ttbl[h] = new PList(DictEntry);

	// If we got this far, then we couldn't use an existing copy
	// of the key, so make a new one if necessary.
	if ( copy_key )
		{
		void* old_key = new_entry->key;
		new_entry->key = (void*) new char[n];
		memcpy(new_entry->key, old_key, n);
		delete (char*) old_key;
		}

	// We happen to know (:-() that appending is more efficient
	// on lists than prepending.
	chain->append(new_entry);

	if ( *max_num_entries_ptr < ++*num_entries_ptr )
		*max_num_entries_ptr = *num_entries_ptr;

	// For ongoing iterations: If we already passed the bucket where this
	// entry was put, add it to the cookie's list of inserted entries.
	loop_over_list(cookies, i)
		{
		IterCookie* c = cookies[i];
		if ( h < (unsigned int) c->bucket )
			c->inserted.append(new_entry);
		}

	return 0;
}
*/

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

// initial walk/path for avl tree transversal
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
    //tmlog(TM_LOG_NOTE, "IndexHash: eraseEntry", "we are trying to delete the entry at bucket number %d", ie->key->hash_key);
    //htable[ie->key->hash_key] = NULL;
	delete ie;
	numEntries--;
}





