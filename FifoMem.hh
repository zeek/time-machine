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

// $Id: FifoMem.hh 269 2011-07-20 17:46:47Z gregor $

#ifndef FIFOMEM_HH
#define FIFOMEM_HH

#include <pcap.h>
#include <pthread.h>
#include "tm.h"

#include "types.h"
//#include "IndexField.hh"
///#include "Index.hh"
//#include "Query.hh"

#define MAXCAPLEN (8192+sizeof(struct pcap_pkthdr))


class QueryRequest;
class QueryResult;
class IntervalSet;

class FifoMemEvictionHandler;

class FifoMem {
public:
	FifoMem(uint64_t);
	~FifoMem();
	void setEvictionHandler(FifoMemEvictionHandler *h);
	void addPkt(const struct pcap_pkthdr *header, const unsigned char *packet);
	uint64_t popPkt();
	pkt_ptr getWp() const;
	pkt_ptr getS() const;
	uint64_t getClearance() const;
	uint64_t getTotPkts() const;
	uint64_t getTotPktbytes() const;
	uint64_t getTotLostPkts() const;
	uint64_t getTotLostPktbytes() const;
	uint64_t getHeldPkts() const {
		return held_pkts;
	}
	uint64_t getHeldBytes() const {
		return held_bytes;
	}
	tm_time_t getOldestTimestamp() const;
	tm_time_t getNewestTimestamp() const;
	void debugPrint() const;
	void debugPrint(FILE *fp) const;
	uint64_t query(QueryRequest*, QueryResult*, IntervalSet*);
	void lock();
	void unlock();

protected:
	pkt_ptr start,      // start of buffer block
	end,              // position after last byte of block (start+size)
	buffer_end,              // last byte of the buffer (start+size+max_pkt_size)
	lp,               // position of most recently added packet
	wp,               // current writing position
	//    e,                // e
	s;                // beginning of first valid packet in block
	pkt_ptr *align;     // list of positions where packets are aligned
	uint64_t align_num;  //
	uint64_t align_gran;  //

	uint64_t a_s, a_lp, a_max;
	pkt_ptr a_next;
	uint64_t size;  // size of block in bytes
	uint64_t
	tot_pkts,     // packets entered into this Fifo
	tot_lost_pkts,
	held_pkts;    // packets currently held in block
	uint64_t
	tot_pktbytes, // bytes entered into this Fifo (excluding pcap hdrs)
	tot_lost_pktbytes,
	held_bytes;
	FifoMemEvictionHandler *eviction_handler;
	//  int add_semaphore;
	tm_time_t oldestTimestamp;
	tm_time_t newestTimestamp;

	pthread_mutex_t lock_mutex;

	inline pkt_ptr block (pkt_ptr p);
	int bin_search (pkt_ptr *p, tm_time_t t, bool floor);

	uint64_t pktEviction();

};


class FifoMemEvictionHandler {
public:
	virtual ~FifoMemEvictionHandler() { }
	// stuff to do before a packet will get evicted from memory
	// returns true if it removed a packet
	virtual uint64_t pktEviction() = 0;
};


#endif /* FIFOMEM_HH */

