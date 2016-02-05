#include <pcap.h>
#include <pthread.h>
#include <limits.h>

#include <sstream>
#include <iostream>

#include "DynClass.hh"
#include "types.h"
#include "Storage.hh"
#include "Index.hh"
#include "IndexField.hh"
#include "FifoDisk.hh"
#include "packet_headers.h"
#include "conf.h"
#include "tm.h"

#define SNAPLEN 8192


/***************************************************************************
 * callback handler for pcap_loop
 */

void callback(u_char *args, const struct pcap_pkthdr *header,
			  const u_char *packet) {
	Storage *storage = (Storage *)args;

	//FIXME: put these counters somewhere else
	tot_pkt_cnt++;
	tot_bytes+=header->len;

	/* FIXME: make this useful again 
	if (timercmp(&header->ts, &network_time, <)) {
		struct timeval dt;
		timersub(&header->ts, &network_time, &dt);
		log_file->log("main", "network time jumped backward %fs",-to_tm_time(&dt));
	}
	network_time=header->ts;
	*/ 

	storage->addPkt(header, packet);

} // callback()

/***************************************************************************
 * capture thread
 */

void *capture_thread(void *arg) {
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	Storage *storage = (Storage *)arg;
	//  sleep(15);
	pcap_loop(storage->ph, -1, (pcap_handler)callback, (u_char*)storage);
	tmlog(TM_LOG_NOTE, "storage", "pcap input exhausted");
	return NULL;
}


StorageConfig::StorageConfig() : 
			filter(),
			device(),
			readtracefile(),
			conn_timeout(1800),
			max_subscriptions(10000),
			indexes(new Indexes) 
{
	;
}

Storage::Storage(StorageConfig& conf):
		snaplen(SNAPLEN),
		conns(1000000),
		dynclasses(25000),
tot_num_queries(0) {
	//FIXME: Deallocate fifos when throwing an exception !!!
	//FIXME: Same for indexes
	char errbuf[PCAP_ERRBUF_SIZE]; 
	struct bpf_program fp;

	conn_timeout = conf.conn_timeout;
	conns.setMaxSubscriptions(conf.max_subscriptions);

	indexes = conf.indexes;
	indexes->setStorage(this);
	indexes->startThread();

	// Get pcap handle 
	errbuf[0] = '\0';
	if (!conf.readtracefile.empty()) {
		ph = pcap_open_offline(conf.readtracefile.c_str(), errbuf);
	}
	else if (!conf.device.empty()) {
		ph = pcap_open_live(conf.device.c_str(), snaplen, 1, 20, errbuf);
	}
	else {
		tmlog(TM_LOG_ERROR, "storage", "You must specify a capture device or a tracefile");
		exit(1);
	}

	if (!ph) {
		tmlog(TM_LOG_ERROR, "storage", "pcap_open failed: %s", errbuf);
		exit(1);
	}

	//TODO: If strlen(errbuf)>0, then errbuf contains a WARNING!
	//
	
	if (!conf.filter.empty()) {
		char *filterstr = strdup(conf.filter.c_str());
		if(pcap_compile(ph, &fp, filterstr, 0, 0)  < 0) {
			tmlog(TM_LOG_ERROR, "storage", "Could not compile  capture filter: %s", pcap_geterr(ph));
			pcap_close(ph);
			exit(1);
		}
		free(filterstr);

		if(pcap_setfilter(ph, &fp) < 0) {
			tmlog(TM_LOG_ERROR, "storage", "Could not set capture filter: %s", pcap_geterr(ph));
			pcap_close(ph);
			exit(1);
		}
		pcap_freecode(&fp);
	}
	for (std::list<Fifo*>::iterator it=conf.fifos.begin(); it!=conf.fifos.end(); it++) {
		(*it)->setPcapHandle(ph);
		fifos.push_back(*it);
	}
	conf.fifos.clear();


	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
		(*i)->start();

	// Start Capture thread
	pthread_attr_init(&capture_thread_attr);
#ifdef __FreeBSD__
	{
		int scope = -1;
		struct sched_param param;
		int err = 0;
		int policy = SCHED_RR;
		//TODO: error handling
		if (conf_main_tweak_capture_thread != TM_TWEAK_CAPTURE_THREAD_NONE) {
			pthread_attr_getscope(&capture_thread_attr, &scope);
			pthread_attr_getschedpolicy(&capture_thread_attr, &policy);
			pthread_attr_getschedparam(&capture_thread_attr, &param);
			if (scope != PTHREAD_SCOPE_PROCESS) {
				tmlog(TM_LOG_WARN, "storage", "Tried to tweak capture thread scheduling, but current scope is strange (%d)", scope);
				err = 1;
			}
			/* FIXME: those to tests could be omitted. should probabl do so in the future*/
			if (param.sched_priority != 15) {
				tmlog(TM_LOG_WARN, "storage", "Tried to tweak capture thread scheduling, but current priority is strange (%d)", param.sched_priority);
				err = 1;
			}
			if (policy != SCHED_RR) {
				tmlog(TM_LOG_WARN, "storage", "Tried to tweak capture thread scheduling, but current policy is strange (%d)", policy);
				err = 1;
			}
			/* end of fixme */
			if (err)
				tmlog(TM_LOG_WARN, "storage", "Not changing capture thread parameters\n");
		}
		if (conf_main_tweak_capture_thread == TM_TWEAK_CAPTURE_THREAD_PRIO && !err) {
			policy = SCHED_RR;
			param.sched_priority = 30;
			if (pthread_attr_setschedpolicy(&capture_thread_attr, policy) !=0) {
				tmlog(TM_LOG_WARN, "storage", "pthread_attr_policy() failed");
				err = 1;
			}
			if (!err && (pthread_attr_setschedparam(&capture_thread_attr, &param) !=0)) {
				tmlog(TM_LOG_WARN, "storage", "pthread_attr_setschedparam() failed");
				err = 1;
			}
			if (!err) 
				tmlog(TM_LOG_NOTE, "storage", "Set Capture thread to realtime priority");
		}
		else if (conf_main_tweak_capture_thread == TM_TWEAK_CAPTURE_THREAD_SCOPE && !err) {
			if (pthread_attr_setscope(&capture_thread_attr, PTHREAD_SCOPE_SYSTEM) != 0) {
				tmlog(TM_LOG_WARN, "storage", "pthread_attr_setscope() failed");
			}
			else
				tmlog(TM_LOG_NOTE, "storage", "Set Capture thread to system contention scope");
		}
	}
#endif
	int i=pthread_create(&capture_thread_tid, &capture_thread_attr, capture_thread, (void *)this);
	if (i!=0) {
		pcap_close(ph);
		tmlog(TM_LOG_ERROR, "storage", "Could not create capture thread.");
		exit(1);
	}
}

Storage::~Storage() {
	tmlog(TM_LOG_DEBUG, "storage", "Storage::~Storage");
	/*fprintf(stderr, "Breaking pcap_loop()\n");
	pcap_breakloop(ph);
	fprintf(stderr, "pcap_loop() is destroyed\n"); */
	for (std::list<Fifo*>::iterator it=fifos.begin(); it!=fifos.end(); it++)
		delete (*it);
	tmlog(TM_LOG_DEBUG, "storage", "Fifos deleted.");
	delete indexes;
	tmlog(TM_LOG_DEBUG, "storage", "pcap handle closed.");
	pcap_close(ph);
}

void Storage::cancelThread() {
	tmlog(TM_LOG_DEBUG, "storage", "Canceling capture thread");
	pthread_cancel(capture_thread_tid);
	tmlog(TM_LOG_DEBUG, "storage", "Joining capture thread.");
	pthread_join(capture_thread_tid, NULL);
	tmlog(TM_LOG_DEBUG, "storage", "Capture thread is gone.");
	indexes->cancelThread();
}


/*void Storage::addFifo(Fifo* f) {
	fifos.push_back(f);
}*/


void Storage::addPkt(const struct pcap_pkthdr *header,
					 const unsigned char *packet) {
	uint16_t ether_type=ntohs(ETHERNET(packet)->ether_type);
	if ( ! (ether_type==ETHERTYPE_IP || ether_type==0x8100) ) {
		//    fprintf(stderr,"unknown ether_type 0x%.4X\n", ether_type);
		return;
	}
	const unsigned char* idxpacket=packet;
	// skip VLAN header for indexing
	if (ether_type==0x8100) idxpacket+=4;

	tm_time_t now = to_tm_time(&header->ts);

	/* update connections state, classify, elephant cutoff */
	Connection* c=conns.addPkt(header, idxpacket);
	Fifo *f=c->getFifo();
	QueryResult *qr=c->getSubscription();
	if (!f) {
		/* No class has been assigned so far. */

		/* Expire old connections. We can call removeOld anytime. It 
		 * doesn't really matter. But we want to find a place, where it's
		 * called often enough but not too often. On every incoming 
		 * packet is too often. Every couple of seconds is NOT often
		 * enough*/
		conns.removeOld(now-conn_timeout);
		
		/* Check, if we have a dynamic rule for the IPs of this
		   connection, if so: use the clas specified by the dynamic rules table.
		*/
		IPAddress *ip;
		DynClass *dc;
		int curdir;
		dynclasses.removeOld(); // Housekeeping
		for (int i=0; i<2; i++) {
			if (i==0) {
				ip = SrcIPAddress::genKey(idxpacket, 0);
				curdir = TM_DYNCLASS_ORIG;
			}
			else {
				ip = DstIPAddress::genKey(idxpacket, 0);
				curdir = TM_DYNCLASS_RESP;
			}

#ifdef TM_HEAVY_DEBUG
			assert(ip);
#endif
			dc = dynclasses.get(ip);
			if (dc) {
				if (dc->dir==TM_DYNCLASS_BOTH || dc->dir==curdir)
					f = dc->target;
				delete(ip);
				break;
			}
			delete(ip);
		}
		if (f)
			c->setFifo(f);
	}
	if (!f) {
		/* Still no class assigned. 
		 * Now evaluate BPF expressions defined for all classes and pick
		 * the appropriate class
		*/
		int max_precedence=INT_MAX;
		for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++) {
			if (// packet matches this class' filter and
				(*i)->matchPkt(header, idxpacket) &&
				// first match or higher precedence match
				(f==NULL || (*i)->getPrecedence()>max_precedence) ) {
				f=*i;
				max_precedence=f->getPrecedence();
			}
		}
		if (f)
			c->setFifo(f);
	} // if (!f)
	if (f) {
		bool tcp_ctrl_flag=false;
		if (IP(idxpacket)->ip_p==IPPROTO_TCP)
			if (TCP(idxpacket)->th_flags & ( TH_FIN | TH_SYN | TH_RST ))
				tcp_ctrl_flag=true;
		if ( (( c->getSuspendCutoff() | tcp_ctrl_flag )
				&& f->addPkt(header, idxpacket, NULL)) ||
				f->addPkt(header, idxpacket, c)) {
			/* packet was stored in Fifo *f */
			uncut_bytes += header->len;
			uncut_pkt_cnt++;

			/* update indexes */
			for (std::list<IndexType*>::iterator i=indexes->begin();
					i!=indexes->end();
					i++) {
				(*i)->addPkt(header, idxpacket);
			}
		} // if (f->addPkt) ... else it was "cut off"
	
	    c->setFifo(f);
	} // if (f)
	if (qr) {
		// there is a subscription for this connection
		if (!(qr->sendPkt(header, idxpacket)))
			c->deleteSubscription();
		/* Note: delteSubscription() decrements the use counter of the subscr. and
		 * if it reaches 0, the subscription is really deleted. 
		 * But since other conns using the same subscription will also detect that
		 * the subscriptions target is gone, the subscription will be removed in the
		 * end 
		 */
	}
}


void Storage::aggregateIndexFiles() {
	for (std::list<IndexType*>::iterator i=indexes->begin(); i!=indexes->end(); i++) {
		(*i)->aggregate();
	}
}

void Storage::debugPrint() {
	debugPrint(stderr);
}

void Storage::debugPrint(FILE *fp) {
	//  Fifo* f[]={&f_udp, &f_tcp, &f_other};
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
		fprintf(fp, "%s totBytes: %"PRIu64"\n", (*i)->getClassname().c_str(),
			   (*i)->getFm()->getTotPktbytes());
	for (std::list<IndexType*>::iterator i=indexes->begin();
			i!=indexes->end();
			i++) {
		//(*i)->lock();
		fprintf(fp, "# %s index nodes RAM/Disk %"PRIu64" %"PRIu64"\n",
			   (*i)->getIndexName().c_str(),
			   (*i)->getNumEntriesRAM(),
			   (*i)->getNumEntriesDisk());
		(*i)->debugPrint(fp);
		//(*i)->unlock();
	}
}


void Storage::logStatsClasses() {
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
		tmlog(TM_LOG_NOTE, (*i)->getClassname().c_str(), (*i)->getStatsStr().c_str());
}

std::string Storage::getStatsIndexesStr() {
	std::stringstream ss;
	for (std::list<IndexType*>::iterator i=indexes->begin();
			i!=indexes->end();
			i++) {
		//(*i)->lock();
		ss << (*i)->getIndexName() << " " //(*i)->getNumEntriesRAM() << " RAM / "
		//<< (*i)->getNumEntriesDisk() << " Disk "
		<< (*i)->getQlen() << " queue entries *** ";
		//    (*i)->DBStatPrint();
		//(*i)->unlock();
	}
	return ss.str();
}


tm_time_t Storage::getOldestTimestampMem() {
	tm_time_t r=0;
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
		if (r==0 || (*i)->getFm()->getOldestTimestamp() < r)
			r=(*i)->getFm()->getOldestTimestamp();
	return r;
}

tm_time_t Storage::getOldestTimestampMemHacked() {
	tm_time_t r=0;
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
		if ((*i)->getFm()->getOldestTimestamp() > r)
			r=(*i)->getFm()->getOldestTimestamp();
	return r;
}


tm_time_t Storage::getOldestTimestampDisk() {
	tm_time_t r=0;
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
		if (r==0 || (*i)->getFd()->getOldestTimestamp() < r)
			r=(*i)->getFd()->getOldestTimestamp();
	return r;
}


void Storage::query(QueryRequest *query_req, QueryResult *query_res) {
	struct timeval t_start, t_end;
	gettimeofday(&t_start, NULL);
	//fprintf(stderr, "Query ID: %d\n",  query_res->getQueryID());

	IndexType* idx=indexes->getIndexByName(query_req->getField()->getIndexName());
	if (!idx) {
		tmlog(TM_LOG_ERROR, "query", "Tried to query index \"%s\" but it does not exist\n",
			   query_req->getField()->getIndexName().c_str());
	} else {
		unsigned matches=0;
		IntervalSet interval_set;
		/* NOTE: it may happen, that the index is rotated between the
		 * lookupMem and lookupDisk call. This isn't a problem. In the worst case
		 * an entry will be found twice: in the memory index before the rotation
		 * and in the disk index  after the rotation. Since the IntervalSet class
		 * ensures sort order and overlap free intervals, we are fine. No need
		 * for locks or something. 
		 */
		
		//    printf("getting ie for %s\n", query_req->getField()->getStr().c_str());
		idx->lookupMem(&interval_set, query_req->getField());

		if (!query_req->isMemOnly()) {
			idx->lookupDisk(&interval_set, query_req->getField(),
							query_req->getT0(), query_req->getT1());
		}
		//XXX:
		tmlog(TM_LOG_DEBUG, "query", "%d interval_set now has %u entries", 
				query_res->getQueryID(), interval_set.getNumIntervals());

		//    printf("disk_set: %s'n", disk_set->getStr().c_str());

		for (std::list<Fifo*>::iterator fifo_i=fifos.begin();
				fifo_i != fifos.end(); fifo_i++)
			matches+=(*fifo_i)->query(query_req, query_res, &interval_set);
		tmlog(TM_LOG_DEBUG, "query", "%d Query is done. Had %u matches", query_res->getQueryID(),
				matches);

	} // if (!idx)
	/*  printf("idx query fin\n"); */

//TODO:
	/* handle potential subscription request */
	if (query_req->isSubscribe()) {
		/* subscription requested */
		if (query_req->getField()->getIndexName() == "connection4") {
				conns.subscribe(  ((ConnectionIF4*)(query_req->getField()))->getCID(), query_res  );
		}
	} /* if (subscription requested) */


	gettimeofday(&t_end, NULL);
	tmlog(TM_LOG_NOTE, "query", "%d Done. It took %.2lf seconds", query_res->getQueryID(), 
		to_tm_time(&t_end)-to_tm_time(&t_start));
	if (query_res->getUsage() == 0) {
		/* haven't passed it on to a subscription, delete it */
		delete query_res;
	}
	delete query_req;

	tot_queries_duration+=(uint64_t) ( (t_end.tv_sec-t_start.tv_sec)*1e6
										+(t_end.tv_usec-t_start.tv_usec) );
	tot_num_queries++;
}

bool Storage::suspendCutoff(ConnectionID4 cid, bool b) {
	bool rv=false;
	conns.lock();
	Connection *c=conns.lookup(&cid);
	if (c) {
		c->setSuspendCutoff(b);
		rv=true;
	} else {
		//    fprintf(stderr, "Storage::suspend_cutoff(%d): CONNECTION NOT IN CONNECTION TABLE\n", b);
		rv=false;
	}
	conns.unlock();
	return rv;
}

bool Storage::suspendTimeout(ConnectionID4 cid, bool b) {
	bool rv=false;
	conns.lock();
	Connection *c=conns.lookup(&cid);
	if (c) {
		c->setSuspendTimeout(b);
		rv=true;
	} else {
		//    fprintf(stderr, "Storage::suspend_timeout(%d): CONNECTION NOT IN CONNECTION TABLE\n", b);
		//XXX: c=conns.newConn_get(new ConnectionID4(cid));
		//c->setSuspendTimeout(b);
		rv=false;
	}
	conns.unlock();
	return rv;
}

bool Storage::setDynClass(IPAddress *ip, int dir, const char *classname) {
	struct timeval tv;
	tm_time_t now;
	Fifo *f;
	bool retval = true;

	gettimeofday(&tv, NULL);
	now = to_tm_time(&tv);

	tmlog(TM_LOG_DEBUG, "dyn_class", "Setting IP %s to class %s, direction %d",
			ip->getStr().c_str(), classname, dir);
	f = getFifoByName(std::string("class_") + classname);
	if (f) {
		if (dynclasses.get(ip) != NULL) {
			tmlog(TM_LOG_NOTE, "dyn_class", "Overwrite dynamic assignment for IP %s",
					ip->getStr().c_str());
		}
		dynclasses.insert_or_update(ip, dir, f, now+f->getDynTimeout());
	}
	else {
		tmlog(TM_LOG_ERROR, "dyn_class", "Class %s not found", classname);
		//fprintf(stderr, "class %s not found %p\n", classname, f);
		retval = false;
		delete(ip);
	}
	return retval;
}
bool Storage::unsetDynClass(IPAddress *ip) {
	tmlog(TM_LOG_DEBUG, "dyn_class", "Remvoing setting for IP %s (if it exists)", ip->getStr().c_str());
	dynclasses.remove(ip);
	delete(ip);
	return true;
}

Fifo* Storage::getFifoByName(std::string search_name) {
	Fifo *r=NULL;
	for (std::list<Fifo*>::iterator i=fifos.begin();
			!r && i!=fifos.end();
			i++) {
		if ((*i)->getClassname() == search_name)
			r=*i;
	}
	return r;
}

