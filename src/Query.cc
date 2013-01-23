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

// $Id: Query.cc 230 2008-02-27 16:47:15Z gregor $
#include <pcap.h>
#include <sstream>

#include "Fifo.hh"
#include "Query.hh"

#include "FifoDisk.hh"

#ifdef HAVE_LIBBROCCOLI
#include <broccoli.h>
#endif

#include "conf.h"

QueryRequest::QueryRequest(IndexField* field, double t0, double t1, bool mem_only, bool subscribe, int linktype, int snaplen) :
	field(field), t0(t0), t1(t1), mem_only(mem_only), subscribe(subscribe), have_bpf(false) {
		ph = pcap_open_dead(linktype, snaplen);
}

QueryRequest::~QueryRequest() {
	if (have_bpf) {
		have_bpf = false;
		pcap_freecode(&fp);
	}
	if (field != NULL)
		delete field;
	pcap_close(ph);
}

bool QueryRequest::matchPkt(const pkt_ptr p) {
	/*
	if (!have_bpf) compileBPF();
	return bpf_filter(fp.bf_insns, p+sizeof(struct pcap_pkthdr),
	    ((struct pcap_pkthdr *)p)->len,
	    ((struct pcap_pkthdr *)p)->caplen);
	*/
	return matchPkt((struct pcap_pkthdr *)p, p+sizeof(struct pcap_pkthdr));
}

bool QueryRequest::matchPkt(struct pcap_pkthdr *hdr, const u_char *pkt) {
	if (!have_bpf) compileBPF();
	return bpf_filter(fp.bf_insns, (u_char *)pkt,
					  hdr->len,
					  hdr->caplen);
}

void QueryRequest::compileBPF() {
#define MAX_BPF_STR_LEN 2048 
	/*
	how long?
	 
	host 123.123.123.123 and port 12345 and host 123.123.123.123 and port 12345
	                                                                          ^
	                                                                          74
	*/
	char bpf_str[MAX_BPF_STR_LEN];
	/* this is in main.cc */
	field->getBPFStr(bpf_str, MAX_BPF_STR_LEN);
	/* FIXME: not sure, if pcap_geterr() is thread safe. Probaly not. */
	if (pcap_compile(ph, &fp, bpf_str, 0, 0) == -1) {
		tmlog(TM_LOG_ERROR, "query", "QueryRequest::compileBPF(): pcap_compile():  %s", pcap_geterr(ph));
		tmlog(TM_LOG_DEBUG, "query", "QueryRequest::compileBPF(): pcap_compile(): Problem expression was: ", bpf_str);
		return;
	}
	have_bpf=true;
}


QueryResultFile::QueryResultFile(int queryID, const std::string& filename, int linktype, int snaplen) 
	: QueryResult(queryID)
{
	ph = pcap_open_dead(linktype, snaplen);
	f = new FifoDiskFile(conf_main_queryfiledir+std::string("/")+filename, ph);
}

QueryResultFile::~QueryResultFile() {
	delete f;
	pcap_close(ph);
}

bool QueryResultFile::sendPkt(const struct pcap_pkthdr *header,
							  const unsigned char *packet) {
	// TODO: these values are not thread-safe. Altough since approx. figures areq 
	// enough at the moment, we don't lock!!
	querySentPkts++;
	querySentBytes += header->caplen;
	f->addPkt(header, packet);
	return true;
	//  f->flush();
}

bool QueryResultFile::sendPkt(pkt_ptr p) {
	// TODO: these values are not thread-safe. Altough since approx. figures areq 
	// enough at the moment, we don't lock!!
	querySentPkts++;
	querySentBytes += ((struct pcap_pkthdr *)p)->caplen;
	f->addPkt(p);
	return true;
	//  f.flush();
}

std::string QueryResultFile::getStr() {
	return "to_file "+f->getFilename();
}


#ifdef HAVE_LIBBROCCOLI

#include "BroccoliComm.hh"

QueryResultBroConn::~QueryResultBroConn() {}

bool QueryResultBroConn::sendPkt(const struct pcap_pkthdr *header,
								 const unsigned char *packet) {
	// TODO: these values are not thread-safe. Altough since approx. figures areq 
	// enough at the moment, we don't lock!!
	querySentPkts++;
	querySentBytes += header->caplen;

	broccoli_send_packet(bc_thread, header, packet, tag);	   
	return true;
}

bool QueryResultBroConn::sendPkt(pkt_ptr p) {
	return sendPkt((struct pcap_pkthdr*)p,          // pcap header
			p+sizeof(struct pcap_pkthdr));  // packet
}

std::string QueryResultBroConn::getStr() {
	char c_str[50];
	snprintf(c_str, 50, "to_broConn %p", this);
	std::string r=c_str;
	return r;
}

#endif // HAVE_LIBBROCCOLI


