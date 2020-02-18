#ifndef CONNECTIONS_HH
#define CONNECTIONS_HH

#include <pthread.h>

#include "tm.h"

//#include "Queue.hh"
#include "Query.hh"
#include "Connection.hh"

/**  
 * The central connection table. Mainly used by Storage.cc and the capture
 * thread. 
 *
 * NOTE: THIS CLASS MAKES ASSUMPTIONS ABOUT WHICH METHODS CAN BE CALLED
 * FROM WHICH THREADS. IT IS NOT COMPLETELY THREAD SAFE. READ THE COMMENTS\
 * BEFORE MODIFYING.
 *
 * This class is optimized for performance and we try to avoid locks as far
 * as possible. These implies that some methods are not thread-safe and must
 * not be used across threads. These methods are only used by the capture
 * thread. That's also the reason, why these functions are 'protected:'
 *
 * Updating the connection table is done by the capture thread
 * without locking. The methods for capturing / updating ensure that
 * the connection table is always consistent while they  update. 
 * An Update is something that modifies fields in the ConnEntry, an Update
 * does NOT modify collision lists or such
 *
 * LOCK-XXX:
 * Adding an entry is done while holding a lock. We wanted to do this without
 * locking, but that doesn't work, since the compile may reorder. 
 * Solving this would be nice though, since adding entries during a 
 * flood must be as efficient as possible. 
 *
 * Removing entries from the connection table is also done by the capture
 * thread, but it requires locking!  
 * There are public methods, can be used from other threads safely. These
 * methods acquire a lock to protect them from race conditions when the
 * capture thread REMOVES data.
 *
 * There are still race conditions, but they are not critical and acceptable.
 * The capture thread might have just updated an entry in the table, but a
 * query thread does not yet see the updated entry. This is not a problem,
 * because the capture thread acts when it receives packets from libpacp,
 * and we cannot control the delay between a packet arriving at the NIC and 
 * it beeing delivered to the Timemachine, so the delay that might get added
 * due to the race conditions is negligible.
 * 
 */
class Connections {
/* NOTE: THIS CLASS MAKES ASSUMPTIONS ABOUT WHICH METHODS CAN BE CALLED
 * FROM WHICH THREADS. IT IS NOT COMPLETELY THREAD SAFE. READ THE COMMENTS\
 * BEFORE MODIFYING.
 */
public:
	typedef Connection* hash_t;
	Connections(unsigned hash_size);
	~Connections();


	/* These methods can be called from any thread 
	 * They use locking
	 */
	uint64_t getNumEntries() const {
		return num_entries;
	}
	Connection* getCopy(ConnectionID4 *c_id);
	void subscribe(ConnectionID4 *c_id, QueryResult *qres);
	void setMaxSubscriptions(int i) {
		max_subscriptions=i;
	}

	/* Print a sample of connections onto the given outfp. 
	 * Currently this will print the 5 most recently modified
	 * connections
	 */
	void printConnSample(FILE *outfp) const;

	/* informative. rename and code !! */
	void printStats(FILE *outfp) {
		;
	}
#ifdef TM_HEAVY_DEBUG
	void checkme(tm_time_t now) { 
		static tm_time_t t = 0;
		Connection *cur, *next;
		unsigned i;

		if (now - t < 10) 
			return;
		//printf("************************** checking conn table ********************************\n");
		//printf("should have %u entries\n", num_entries);
		//printf("checking q ....\n");
		if (q_newest) {
			assert(q_newest->q_newer == NULL);
		}
		if (q_oldest) {
			assert(q_oldest->q_older == NULL);
		}
		i=0;
		next = q_newest;
		cur = NULL;
		while (next) {
			assert(next->q_newer == cur);
			cur = next;
			if (cur->q_older) {
				assert(cur->q_older->q_newer == cur);
			}
			next = cur->q_older;
			i++;
		}
		assert(q_oldest == cur);
		assert(i == num_entries);
		/* the other way */
		i=0;
		next = q_oldest;
		cur = NULL;
		while (next) {
			assert(next->q_older == cur);
			cur = next;
			if (cur->q_newer) {
				assert(cur->q_newer->q_older == cur);
			}
			next = cur->q_newer;
			i++;
		}
		assert(q_newest == cur);
		assert(i == num_entries);

		//printf("checking collision lists\n");
		i=0;
		for(unsigned k=0; k<size; k++) {
			cur = NULL;
			next = htable[k];
			while (next) {
				assert(next->col_prev == cur);
				cur = next;
				if (cur->col_next)
					assert(cur->col_next->col_prev == cur);
				next = cur->col_next;
				i++;
			}
		}
		assert(i == num_entries);

		t = now;

	}
#endif


	// Allow Storage acces to potentially dangerous 
	// methods.
	friend class Storage;

protected:
	/* These methods must not be used from differtent threads. NOT THREAD SAFE
	 * Only call them from the capture thread! */
	void removeOld(tm_time_t threshold);
	// these are 
	inline Connection* lookup(ConnectionID4 *c_id);
	inline Connection* addPkt (const struct pcap_pkthdr*, const u_char*);

	//void addConnHelper(ConnectionID4 *c_id);

	Connection* addConn(ConnectionID4 *c_id); 

private:
	void lock();
	void unlock();

	inline void q_remove(Connection *c);
	inline void q_add_newest(Connection *c);


	unsigned num_entries;
	unsigned size;
	// the hashtable containing the connections
	hash_t* htable;

	//Connection* addedconn;

	//Connection* addedpacket;

	/* every connection is in the hashtable and in a de-queue, where newest is
	 * the connection that has been accessed last. I.e. oldest it the connection
	 * that has been inactive for the longest time. 
	 */ 
	Connection *q_newest;
	Connection *q_oldest;

	pthread_mutex_t lock_mutex;
	int subscriptions;
	int max_subscriptions;
};

	

inline Connection* Connections::lookup(ConnectionID4 *c_id) {
	Connection* cur;

	cur = htable[c_id->hash()%size];
	while (cur != NULL) {
		/* found it */
		if (*c_id == *cur->c_id) {
			break;
		}
		cur = cur->col_next;
	}
	return cur;
}

/* add a packet. lookup the connection and increment byte and pkt counters if it exists,
 * otherwise create the entry 
 */
inline Connection* Connections::addPkt(const struct pcap_pkthdr* header, const u_char* packet) {
	ConnectionID4* c_id=new ConnectionID4(packet);
	Connection* addedpacket;

#ifdef TM_HEAVY_DEBUG
	checkme(to_tm_time(&header->ts));
#endif
	addedpacket = lookup(c_id);
	if (addedpacket == NULL) {
		addedpacket = addConn(c_id);
		// c_id now belongs to c
	}
	else {
		delete c_id;
		q_remove(addedpacket);
	}

	addedpacket->addPkt(header, packet);
	q_add_newest(addedpacket);
	return addedpacket;
}


inline void Connections::q_remove(Connection *c) {
	Connection *newer;
	Connection *older;

	newer = c->q_newer;
	older = c->q_older;

	/* yes, we DO compare pointers here 
	 */
	if (newer) 
		newer->q_older = older;
	else {
#ifdef TM_HEAVY_DEBUG
		assert(q_newest == c);
#endif
		q_newest = older;
	}
	
	if (older)
		older->q_newer = newer;
	else {
#ifdef TM_HEAVY_DEBUG
		assert(q_oldest == c);
#endif
		q_oldest = newer;
	}
}

inline void Connections::q_add_newest(Connection *c) {
	c->q_newer = NULL;
	c->q_older = q_newest;
	if (q_newest) 
		q_newest->q_newer = c;
	q_newest = c;
	if (!q_oldest)  // first element to add
		q_oldest = c;
}
#endif
