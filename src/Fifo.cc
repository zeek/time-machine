#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sstream>
#include <pcap.h>

#include "types.h"
#include "Fifo.hh"
#include "Connection.hh"
#include "FifoDisk.hh"
#include "tm.h"
//#include "bro_inet_ntop.h"

Fifo::Fifo() {
	init();
}


Fifo::~Fifo() {
	//tmlog(TM_LOG_DEBUG, "storage",  "Fifo::~Fifo");
	if (started) {
		pcap_freecode(&fp);
	}
	started=false;
	if (fm) 
		delete fm;
	if (fd) 
		delete fd;
}


Fifo::Fifo(const std::string& classname, uint64_t fifo_mem_sz, uint64_t fifo_disk_sz, pcap_t* pcap_handle, const char* classdir) {
	init();
	this->classname=classname;
	this->classnameId = classname;
	this->fifo_mem_sz=fifo_mem_sz;
	this->fifo_disk_sz=fifo_disk_sz;
	this->fifo_disk_unlimited = false;
	this->ph=pcap_handle;
    this->classdir = classdir;
	this->started=false;
}


void Fifo::init() {
	classname="default";
	classnameId = classname;
        classdir=conf_main_workdir;
	classdir_format = conf_main_classdir_format;
	filename_format = conf_main_filename_format;
	filter="";
	fifo_mem_sz=5000000;
	fifo_disk_sz=50000000;
	fifo_disk_unlimited=false;
	fifo_disk_filesz=50000000;
	do_cutoff=true;
	cutoff=10000;
	ph=NULL;
	dynTimeout  = 3600 * 4; /* 4 hrs */
	precedence=0;
	pkts_to_disk=1;

	stored_bytes=cutoff_bytes=0;
	stored_pkts=cutoff_pkts=0;

	fm=NULL;
	fd=NULL;
}


void Fifo::start() {
    // make sure the handle to read packets is valid
	assert(ph);
    // create a new FifoMem object in memory (with the default time interval being 0 to 0)
    // fifo_mem_sz is size of block in bytes
	fm=new FifoMem(fifo_mem_sz);
    // create a new FifoDisk object for the disk
    // classname is the name of the class (string instance)
    // fifo_disk_sz is the size of buffer block in bytes
    // fifo_disk_filesz is the size of the file
    // ph is the handler
	fd=new FifoDisk(classname, fifo_disk_sz, fifo_disk_filesz, ph, classdir, 
		filename_format, classdir_format, classnameId,
		fifo_disk_unlimited);
    
    // setting eviction handler for FifoMem object
	fm->setEvictionHandler(this);

    //tmlog(TM_LOG_DEBUG, "Fifo: Fifo.cc, ~line 69", "Fifo started");

	// compile BPF filter
	char* cp=strdup(filter.c_str());
    // pcap_compile returns 0 for success, returns -1 for failure
	if(pcap_compile(ph, &fp, cp, 0, 0) == -1) {
		tmlog(TM_LOG_ERROR, "storage", "pcap_compile() error filter string \"%s\"", cp);
		//// error handling!!!!!!!!!!!!!!!!!!!
		exit(1);
	}
    // free our duplicated char array
	free(cp);

    // woo hoo we started the Fifo's
	started=true;
}


bool Fifo::matchPkt(const struct pcap_pkthdr* header,
					const unsigned char* packet) {
    //tmlog(TM_LOG_DEBUG, "Fifo: matchPkt", "The value of this bpffilter for packet %lu and %lu is %lu", header->ts.tv_sec, header->ts.tv_usec, bpf_filter(fp.bf_insns, (unsigned char*)packet, header->len, header->caplen));

	return bpf_filter(fp.bf_insns, (unsigned char*)packet,
					  header->len,
					  header->caplen);
}


uint64_t Fifo::pktEviction() {
	uint64_t n=0;
	uint64_t i;
    // for all the packets to disk with the condition that
    // the number of held packets in the memory ring buffer is
    // greater than 0
	for (i=0; i<pkts_to_disk && fm->getHeldPkts()>0; i++) {
        // adding packet to Fifo disk, addPkt method is from FifoDisk.cc
        // getS() method is from FifoMem.c - it gets the beginning of first valid packet in the memory ring buffer block


        //char str1[INET6_ADDRSTRLEN];

        //bro_inet_ntop(AF_INET6, &(IP6(fm->getS() + 4 + sizeof(struct pcap_pkthdr))->ip6_src.s6_addr), str1, INET6_ADDRSTRLEN);

        //char s1[INET6_ADDRSTRLEN];

        //inet_pton(AF_INET6, s1, str1);

        //char str2[INET6_ADDRSTRLEN];

        //bro_inet_ntop(AF_INET6, &(IP6(fm->getS() + 4 + sizeof(struct pcap_pkthdr))->ip6_dst.s6_addr), str2, INET6_ADDRSTRLEN);

        //tmlog(TM_LOG_NOTE, "Fifo::pktEviction", "we ard adding the packet to the FifoDisk with src ip %s and dst ip %s", str1, str2);
		fd->addPkt(fm->getS());
        // pop the packet from the memory ring buffer (I'm still not sure about the align stuff, with a_s, a_lp)
        // note that popPkt returns the size of the popped packet in bytes
        // increment n by the size of the popped packet
		n+=fm->popPkt();
	}
    // this shouldn't happen often
	if (i<pkts_to_disk) {
		tmlog(TM_LOG_WARN, "storage", "Strange, only evicted %" PRIu64 " packets", i);
	}
    // return the total number of bytes evicted from the memory ring buffer and added to the disk ring buffer
	return n;
}

// When the connection is subscribed or when a tcp control flag
// is set, then addPkt is called with a connection NULL pointer
// This function returns true if we are able to add the packet and returns
// false otherwise
bool Fifo::addPkt(const struct pcap_pkthdr* header,
				  const unsigned char* packet, Connection* c) {
    // started is true when we call Fifo::start() (above member function definition)
	if (started) {
		if (c && doCutoff() && c->getTotPktbytes()>getCutoff()) {
			// cut-off
            //tmlog(TM_LOG_DEBUG, "addPkt: Fifo.cc, ~line 114", "Connection cut-off is occuring for packet %lu (cannot add to connection) ", header->ts.tv_usec);
            // increment the cutoff_pkts and cutoff_bytes
			cutoff_pkts++;
			cutoff_bytes+=header->len;
			return false;
		} else {

            //char str1[INET6_ADDRSTRLEN];

            //bro_inet_ntop(AF_INET6, &(IP6(packet + 4)->ip6_src.s6_addr), str1, INET6_ADDRSTRLEN);

            //char s1[INET6_ADDRSTRLEN];

            //inet_pton(AF_INET6, s1, str1);

            //char str2[INET6_ADDRSTRLEN];

            //bro_inet_ntop(AF_INET6, &(IP6(packet + 4)->ip6_dst.s6_addr), str2, INET6_ADDRSTRLEN);

            //tmlog(TM_LOG_NOTE, "Fifo::addPkt", "the packet we are adding to FifoMem has source ip %s and destination ip %s", str1, str2);

			// normal addition to Memory Fifo since this packet is not cutoff
			fm->addPkt(header, packet);
            //tmlog(TM_LOG_DEBUG, "addPkt: Fifo.cc, ~line 121", "Connection cut-off did not occur for packet %lu", header->ts.tv_usec);
            // increment the stored_pkts and stored_bytes
			stored_pkts++;
			stored_bytes+=header->len;
			return true;
		}
	} // if (started)
	else return false;
}


std::string Fifo::getStatsStr() {
	// TODO: This is very ugle: c_str -> string -> c_str. 
	// Should fix this soon!
#define STR_SIZE 1000
	char s[STR_SIZE];
	if (started) {
		snprintf(s, STR_SIZE, 
				"%" PRIu64 " "
				"%" PRIu64 " "
				"%" PRIu64 " "
				"%" PRIu64 " "
				"%" PRIu64 " "
				"%" PRIu64 " "
				"%.2lf "
				"%" PRIu64 " "
				"%" PRIu64 " "
				"%.2lf ",
			 stored_bytes,
			 stored_pkts,
			 cutoff_bytes,
			 cutoff_pkts,
			 fm->getHeldBytes(),
			 fm->getHeldPkts(),
			 fm->getNewestTimestamp()-fm->getOldestTimestamp(),
			 fd->getHeldBytes(),
			 fd->getHeldPkts(),
			 fd->getNewestTimestamp()-fd->getOldestTimestamp()
			 );
		return std::string(s);
	} else return "(Fifo "+getClassname()+" not running)";
}

std::string Fifo::getStatsStrHeader() {
	return std::string(
			"stored_bytes "
			"stored_pkts "
			"cut_bytes "
			"cut_pkts "
			"mem_bytes "
			"mem_pkts "
			"mem_dt "
			"disk_bytes "
			"disk_pkts "
			"disk_dt "
		);
}




const FifoMem* Fifo::getFm() {
	return fm;
}


const FifoDisk* Fifo::getFd() {
	return fd;
}


uint64_t Fifo::query(QueryRequest *qreq, QueryResult *qres,
				 IntervalSet *interval_set) {
	uint64_t matches = 0;
    /*
        if (chdir(classdir)) {
            fprintf(stderr, "cannot class(Fifo:query) chdir to %s\n", classdir);
            //return;
        }
    */ 

    //printf("The class name is: %s\n", classname.c_str());
    //printf("The directory the classes are in is: %s\n", classdir); 
	FifoDiskFile *cur_file;

	if (!qreq->isMemOnly()) {
		fd->incQueryInProgress();
		IntervalSet::iterator i_i = interval_set->begin();
		std::list <FifoDiskFile*>::iterator f_i=fd->filesBeginIt();
		while ( f_i!=fd->filesEndIt() && i_i != interval_set->end() ) {
			cur_file = *f_i;
			f_i++;
#ifdef QUERY_RACE_PROTECT
			if (f_i == fd->filesEndIt())
				fm->lock();
#endif
			/* Check time interval */ 
			tmlog(TM_LOG_WARN, "query", "%d Fifo::query: start-end=[%lf,%lf] * curfile=[%lf,%lf] * fn=%s",
					qres->getQueryID(), qreq->getT0(), qreq->getT1(), 
					cur_file->getOldestTimestamp(), cur_file->getNewestTimestamp(),
					cur_file->getFilename().c_str());
			if ( (qreq->getT1()+1e-3 >= cur_file->getOldestTimestamp()) &&
					(qreq->getT0()-1e-3 <= cur_file->getNewestTimestamp()) ) {
 
                if (chdir(classdir)) {
                    fprintf(stderr, "cannot class(Fifo:query) chdir to %s\n", classdir);
                    //return;
                }

                //char path[70];

                //char errbufnav[PCAP_ERRBUF_SIZE];

                //printf("The directory for Fifo that we are in is %s\n", getcwd(path, 70));


				matches+= cur_file->query(qreq, qres, interval_set, classdir);
			}
		}
		fd->decQueryInProgress();
	}
#ifdef QUERY_RACE_PROTECT
	else
		fm->lock();
#endif

#ifndef QUERY_RACE_PROTECT
	/* If QUERY_RACE_PROTECT is set, then fm will be locked at this
	 * point. So we only lock it here if QUERY_RACE_PROTECT is undef
	 */
	fm->lock();
#endif
	matches+= fm->query(qreq, qres, interval_set);
	fm->unlock();
	return matches;
}


