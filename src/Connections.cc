#include <stdio.h>

#include "Connections.hh"

#include "tm.h"


Connections::Connections(uint32_t hash_size):
		num_entries(0),
		size(hash_size),
		q_newest(NULL),
		q_oldest(NULL),
		subscriptions(0),
		max_subscriptions(0) {
	pthread_mutex_init(&lock_mutex, NULL);
	htable = new hash_t[size];
	for (unsigned i=0; i<size; i++)
		htable[i] = NULL;
}

Connections::~Connections() {
	delete[] htable;
    //addedconn = NULL;
    //delete addedconn;
    //delete addedpacket;
	pthread_mutex_destroy(&lock_mutex);
}

/*
void Connections::addConnHelper(ConnectionID4 *c_id)
{
    //Connection *c;
    unsigned hval;

    addedconn = new Connection(c_id); // c_id now owned by c
    hval = c_id->hash()%size;
    num_entries++;

    //LOCK-XXX: we cannot guarantee that the compiler doesn't reorder, so 
    //we must use a lock()
    
    lock();
    addedconn->col_next = htable[hval];
    addedconn->col_prev = NULL;
    htable[hval] = addedconn;

    if (addedconn->col_next != NULL) 
	    addedconn->col_next->col_prev = addedconn;
    unlock();

    //addedconn = c;

    Connection *c;
    unsigned hval;

    c = new Connection(c_id); // c_id now owned by c
    hval = c_id->hash()%size;
    num_entries++;
    //LOCK-XXX: we cannot guarantee that the compiler doesn't reorder, so 
    //we must use a lock()
    
    lock();
    c->col_next = htable[hval];
    c->col_prev = NULL;
    htable[hval] = c;

    if (c->col_next != NULL) 
	    c->col_next->col_prev = c;
    unlock();

    addedconn = c;
}
*/

/* add a new connection to the table */
Connection* Connections::addConn(ConnectionID4 *c_id) {
 
    unsigned hval;

    Connection* c = new Connection(c_id); // c_id now owned by c
    hval = c_id->hash()%size;
    num_entries++;

    /* LOCK-XXX: we cannot guarantee that the compiler doesn't reorder, so
     * we must use a lock()
     */
    lock();
    c->col_next = htable[hval];
    c->col_prev = NULL;
    htable[hval] = c;

    if (c->col_next != NULL)
        c->col_next->col_prev = c;
    unlock();
   
    return c;
}


Connection* Connections::getCopy(ConnectionID4 *c_id) {
	Connection *c;
	Connection *cnew;

	lock();
	c=lookup(c_id);
	if (c != NULL)
		cnew = new Connection(c);
	else
		cnew = NULL;
	unlock();
	return cnew;
}


/* will lock the connections table */
void Connections::subscribe(ConnectionID4 *c_id, QueryResult *qres) {
	//fprintf(stderr, "DEBUG: subscribe called\n");
	if (max_subscriptions
			&& subscriptions >= max_subscriptions) {
		/* maximum number of subscriptions active */
		tmlog(TM_LOG_ERROR, "query", "maximum number of subscriptions is active, "
			   "dropping request");
	} else {
		lock();
		Connection *c = lookup(c_id);
		if (c) {
			if (c->getSubscription()) { /* a subscriptions has already been set for this connection */
				/* check if the old subscription is the same as the current query result. 
				   if so: do nothing. Otherwise: return an error code. 
				*/
				if(c->getSubscription()->getQueryID() != qres->getQueryID()) {  
					tmlog(TM_LOG_ERROR, "query", "This connection already has a subscription set. Dropping request");
				}
			}
			else { /* no subscription yet */
				//fprintf(stderr, "subscription set\n");
				c->setSubscription(qres);
				subscriptions++;
				qres->incUsage();
			}
		} else {
			/* connection is NOT in connection table */
			//	  fprintf(stderr, "cannot subscribe to connection: not in connection table: %s\n", query_req->getField()->getStr().c_str());
		}
		unlock();
	} /* if (max_subscriptions) ... */
}


#if 0
/* XXX: do we really need these ??  */

void Connections::printStats() const {
	printStats(stdout);
}
	
void Connections::printStats(FILE *fp) const {
	fprintf(fp, "Connections Object Statistics\n"
		   "%"PRIu64" total connections stored\n",
		   getNumEntries()
		  );
}

void Connections::debugPrint() const {
	debugPrint(stderr);
}
#endif 

void Connections::printConnSample(FILE *outfp) const {
	Connection *c;
	int cnt;
	fprintf(outfp, "-- top (newest) 5:\n");

	for (c = q_newest, cnt = 0;
			c != NULL && cnt<5; c=c->q_older, cnt++) {
		fprintf(outfp, "* %s\n", c->getStr().c_str()); 
	}
	
	fprintf(outfp, "-- bottom (oldest) 5\n");
	for (c = q_oldest, cnt = 0;
			c != NULL && cnt<5; c=c->q_newer, cnt++) {
		fprintf(outfp, "* %s\n", c->getStr().c_str()); 
	}
	/*
	fprintf(fp, "-- bottom 5\n");
	for (i=hq.nodes.end(), i--, c=0;
			i!=hq.nodes.begin() && c<5; i--, c++)
		fprintf(fp, "* %s\n%s\n", i->getConstK()->getStr().c_str(),
			   i->v->getStr().c_str());
	*/
}



void Connections::removeOld(tm_time_t threshold) {
	Connection* c;
	unsigned loop_iters = 0;

	lock();

	while(num_entries && q_oldest!=NULL && q_oldest->getLastTs() < threshold) {
		c = q_oldest;
		if (c->getSuspendTimeout()) {
			/* connection should not be timed out */
			/* move to front of queue */
			q_remove(c);
			q_add_newest(c);
#ifdef TM_HEAVY_DEBUG
			assert(q_newest == c);
#endif
			/* We must ensure, that we can leave the loop when all entries in the
			 * hash queue have a suspended timeout */
			loop_iters++;
			if (loop_iters > num_entries) {
				// We have checked every entry in the hq. Obviously all of them
				// have a suspended timeout. Break the loop
				break;
			}
		} else {
			/* remove timed out connection */
			q_remove(c);
			/* remove from collision list */
			if (c->col_next)
				c->col_next->col_prev = c->col_prev;

			if (c->col_prev) 
				c->col_prev->col_next = c->col_next;
			else { 
				/* first in list. update pointer in hashtable.
				 * XXX: Ugly: find a nicer way
				 */
				htable[c->c_id->hash()%size] = c->col_next;
			}

			delete c;
			num_entries--;
		}
	}
	unlock();
}


void Connections::lock() {
	pthread_mutex_lock(&lock_mutex);
}

void Connections::unlock() {
	pthread_mutex_unlock(&lock_mutex);
}

