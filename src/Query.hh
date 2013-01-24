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

// $Id: Query.hh 230 2008-02-27 16:47:15Z gregor $

#ifndef QUERY_HH
#define QUERY_HH

#include <pcap.h>
#include <pthread.h>
#include <assert.h>

#include "tm.h"
#include "config.h"

#ifdef HAVE_BROCCOLI
#include <broccoli.h>
#endif

/* resolve circular header file dependency by forward declarations
 */

class QueryRequest;
class QueryResult;
class FifoDiskFile;
//#include "FifoDisk.hh"

//#include "Storage.hh"
///#include "Index.hh"
#include "IndexField.hh"


class QueryRequest {
public:
	QueryRequest(IndexField* field, double t0, double t1, bool mem_only, bool subscribe, int linktype, int snaplen);
	virtual ~QueryRequest();
	virtual bool matchPkt(const pkt_ptr p);
	virtual bool matchPkt(struct pcap_pkthdr *hdr, const u_char *pkt);
	virtual void compileBPF();
	IndexField* getField() {
		return field;
	}
	bool isMemOnly() {
		return mem_only;
	}
	bool isSubscribe() {
		return subscribe;
	}
	double getT0() {
		return t0;
	}
	double getT1() {
		return t1;
	}
protected:
	IndexField *field;
	double t0, t1;
	bool mem_only; 
	bool subscribe;
	pcap_t *ph;
	struct bpf_program fp;
	bool have_bpf;
};


class QueryResult {
public:
	QueryResult(int queryID) : queryID(queryID), usage(0) { };
	virtual ~QueryResult() {}
	virtual bool sendPkt(const struct pcap_pkthdr*, const unsigned char*) = 0;
	virtual bool sendPkt(pkt_ptr) = 0;
	virtual std::string getStr() = 0;

	virtual int getQueryID() {
		return queryID;
	}
	virtual int getUsage() {
		return usage;
	}
	virtual void incUsage() {
		usage++;
	}
	virtual void decUsage() {
		usage--;
#ifdef TM_HEAVY_DEBUG
		assert(usage >= 0);
#endif
	}
private:
	int queryID;
	int usage;
};


class QueryResultFile: public QueryResult {
public:
	QueryResultFile(int queryID, const std::string& filename, int linktype, int snaplen);
	~QueryResultFile();
	bool sendPkt(const struct pcap_pkthdr*, const unsigned char*);
	bool sendPkt(pkt_ptr p);
	std::string getStr();
private:
	pcap_t *ph;
	//  std::string filename;
	FifoDiskFile *f;
};


#ifdef HAVE_BROCCOLI

struct broccoli_worker_thread_data;

class QueryResultBroConn: public QueryResult {
public:
	QueryResultBroConn(int queryID, broccoli_worker_thread_data* thread, std::string tag) :
		QueryResult(queryID), bc_thread(thread), tag(tag) {}
	~QueryResultBroConn();
	bool sendPkt(const struct pcap_pkthdr*, const unsigned char*);
	bool sendPkt(pkt_ptr p);
	std::string getStr();
private:
	broccoli_worker_thread_data* bc_thread;
	pthread_mutex_t *bc_mutex;
	string tag;
};

#endif




#endif
