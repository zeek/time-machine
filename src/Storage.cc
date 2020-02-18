#include <pcap.h>
#include <pthread.h>
#include <limits.h>

#include <sstream>
#include <iostream>
//#include <gperftools/profiler.h>

#include "DynClass.hh"
#include "types.h"
#include "Storage.hh"
#include "Index.hh"
#include "IndexField.hh"
#include "FifoDisk.hh"
#include "packet_headers.h"
#include "conf.h"
#include "tm.h"
//#include "bro_inet_ntop.h"

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

    //char str1[INET6_ADDRSTRLEN];

    //inet_ntop(AF_INET6, &(IP6(packet)->ip6_src.s6_addr), str1, INET6_ADDRSTRLEN);

    //char s1[INET6_ADDRSTRLEN];

    //inet_pton(AF_INET6, s1, str1);

    //char str2[INET6_ADDRSTRLEN];

    //inet_ntop(AF_INET6, &(IP6(packet)->ip6_dst.s6_addr), str2, INET6_ADDRSTRLEN);

    //tmlog(TM_LOG_NOTE, "Storage::callback", "we are going to call addpacket of storage on packet that has source ip %s and destination ip %s", str1, str2);

    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_DEBUG, "storage callback: Storage.cc, ~line 29", "Callback function for pcap_loop%lu", header->ts.tv_usec);

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
	//tmlog(TM_LOG_NOTE, "storage: Storage.cc, ~line 59", "pcap input exhausted");
	return NULL;
}

bool compare_precedence(Fifo* first, Fifo* second)
{
    return (first->getPrecedence() > second->getPrecedence());
}

// Abstracts the configuration for a Storage instance,
// initializing some of member variables
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

// initializing some of the private member variables
Storage::Storage(StorageConfig& conf):
		snaplen(SNAPLEN),
		conns(1000000),
		dynclasses(25000),
		tot_num_queries(0) 

{
	//FIXME: Deallocate fifos when throwing an exception !!!
	//FIXME: Same for indexes
	// error buffer for displaying error messages, if I remember correctly
	char errbuf[PCAP_ERRBUF_SIZE]; 

	/* The compiled filter expression */
	struct bpf_program fp;

	// set the connection timeout and maximum number of subscriptions
	conn_timeout = conf.conn_timeout;
	conns.setMaxSubscriptions(conf.max_subscriptions);

	/*
	 * An Index Object that is added to Indexes is owned by Indexes 
	 * I.e. Indexes will take care of deallocation the storage for
	 * Index.
	 * set the indexes to the storage config conf indexes
     * set the storage to this storage we are defining
     * start the mainainer index thread (arghhh they call it Index thread, maintainer thread and index maintainer thread)
	 */
	indexes = conf.indexes;
	indexes->setStorage(this);
	indexes->startThread();

	// Get pcap handle
    // initialize error buffer to have that ending character
	errbuf[0] = '\0';
    // if the trace file to read is not empty, open it
	if (!conf.readtracefile.empty()) {
		ph = pcap_open_offline(conf.readtracefile.c_str(), errbuf);
	}
    // if the device list is not empty, open the device
	else if (!conf.device.empty()) {
        // parameters are device, maximum amount of data to capture, 
        // promiscuous mode on, and a timeout of 20 miliseconds
        // returns a device handler in the form of a struct pcap_t
		ph = pcap_open_live(conf.device.c_str(), snaplen, 1, 20, errbuf);
	}
    // error, neither capture device or trace file was specified
	else {
		tmlog(TM_LOG_ERROR, "storage", "You must specify a capture device or a tracefile");
		exit(1);
	}

    // if ph is NULL, pcap_open failed (part of definitions of pcap_open_*)
	if (!ph) {
		tmlog(TM_LOG_ERROR, "storage", "pcap_open failed: %s", errbuf);
		exit(1);
	}

	//TODO: If strlen(errbuf)>0, then errbuf contains a WARNING!
	// if the filter list is not empty
	
	if (!conf.filter.empty()) {
        // duplicates the filter string
		char *filterstr = strdup(conf.filter.c_str());
        tmlog(TM_LOG_NOTE, "storage", "the filter is: %s", conf.filter.c_str());
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
    /*
    // I added this in to help understand the code
    else
    {
        //tmlog(TM_LOG_NOTE, "storage", "hmmm, filter is empty!");
    }
    */
	for (std::list<Fifo*>::iterator it=conf.fifos.begin(); it!=conf.fifos.end(); it++) {
        // A pcap_t is a handle used to read packets from a network interface, or from a pcap
        // here we are setting the handle (from Fifo.hh)
		(*it)->setPcapHandle(ph);
        // push back this handle onto the list of Fifo* for Storage (not Storage config)
		fifos.push_back(*it);
	}
    // clear the list of Fifo* from the Storage configuration
	conf.fifos.clear();

    fifos.sort(compare_precedence);

    // go through the list of Fifo* for Storage
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
        // from Fifo.cc, create instances of FifoMem and FifoDisk and do some compilation of the filter
		(*i)->start();

	// Start Capture thread
	pthread_attr_init(&capture_thread_attr);
    //tmlog(TM_LOG_DEBUG, "capture thread: Storage.cc, ~line 141", "initializing capture thread attribute");
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

    //tmlog(TM_LOG_DEBUG, "capture thread: Storage.cc, ~line 195", "attempting to create capture thread");
	if (i!=0) {
		pcap_close(ph);
		tmlog(TM_LOG_ERROR, "storage", "Could not create capture thread.");
		exit(1);
	}
}

Storage::~Storage() {
	//tmlog(TM_LOG_DEBUG, "storage: Storage.cc, ~line 204", "Storage::~Storage");
	/*fprintf(stderr, "Breaking pcap_loop()\n");
	pcap_breakloop(ph);
	fprintf(stderr, "pcap_loop() is destroyed\n"); */
	for (std::list<Fifo*>::iterator it=fifos.begin(); it!=fifos.end(); it++)
		delete (*it);
	//tmlog(TM_LOG_DEBUG, "storage: Storage.cc, ~line 210", "Fifos deleted.");
	delete indexes;
	//tmlog(TM_LOG_DEBUG, "storage: Storage.cc, ~line 212", "pcap handle closed.");
        //printf("Pcap handle closed\n");
	pcap_close(ph);
}

void Storage::cancelThread() {
	//tmlog(TM_LOG_DEBUG, "storage: Storage.cc, ~line 217", "Canceling capture thread");
	pthread_cancel(capture_thread_tid);
	//tmlog(TM_LOG_DEBUG, "storage: Storage.cc, ~line 219", "Joining capture thread.");
	pthread_join(capture_thread_tid, NULL);
	//tmlog(TM_LOG_DEBUG, "storage: Storage.cc, ~line 221", "Capture thread is gone.");
	indexes->cancelThread();
}


/*void Storage::addFifo(Fifo* f) {
	fifos.push_back(f);
}*/

/*
int get_link_header_size(int dl)
	{
	switch ( dl ) {
	case DLT_NULL:
		return 4;

	case DLT_EN10MB:
		return 14;

	case DLT_FDDI:
		return 13 + 8;	// fddi_header + LLC

#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		return 16;
#endif

	case DLT_PPP_SERIAL:	// PPP_SERIAL
		return 4;

	case DLT_RAW:
		return 0;
	}

	return -1;
	}

void Storage::Close()
	{
	if ( ph )
		{
		pcap_close(ph);
		ph = 0;
		//closed = true;
		}
	}


void Storage::SetHdrSize()
	{
	int dl = pcap_datalink(ph);
	hdr_size = get_link_header_size(dl);

	if ( hdr_size < 0 )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			 "unknown data link type 0x%x", dl);
		Close();
		}

	datalink = dl;
	}
*/


// note that the pcap packet header has the timestamp of the packet
void Storage::addPkt(const struct pcap_pkthdr *header,
					 const unsigned char *packet) {

	//ProfilerStart("/home/lakers/timemachine_results/profile/blah.prof");
	uint16_t ether_type=ntohs(ETHERNET(packet)->ether_type);
    // ETHERTYPE_IP is EtherType 0x800, for IPv4 addresses
    // EtherType 0x8100 is for VLAN header
    // EtherType 0x86DD is for IPv6 addresses
    // EtherType is a field in the ethernet header frame
	if ( ! (ether_type==ETHERTYPE_IP || ether_type==0x8100 || ether_type==0x86DD) ) {

        //tmlog(TM_LOG_DEBUG, "addPkt: Storage.cc, ~line 240", "unknown ether_type 0x%.4X", ether_type);

		//    fprintf(stderr,"unknown ether_type 0x%.4X\n", ether_type);
		return;
	}

    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_NOTE, "addPkt: Storage.cc, ~line 240", "adding packet %lu !", header->ts.tv_usec);

    //SetHdrSize();

	// Unfortunately some packets on the link might have MPLS labels
	// while others don't. That means we need to ask the link-layer if
	// labels are in place. TODO: Cannot handle MPLS labels just yet
	bool have_mpls = false;

	const unsigned char* idxpacket=packet;
	// skip VLAN header (related to ethernet frame header) for indexing TODO: look at VLAN header more closely
    // Virtual Bridged Local Area Network for logically group network devices together, which share the same 
    // physical network. VLAN tag is 4 bytes and so a VLAN header is 4 bytes longer than a regular ethernet header
	//if (ether_type==0x8100) idxpacket+=4;
    
    if (ether_type == 0x8100)
    {
		// Check for MPLS in VLAN.
        
        // TODO: Cannot handle MPLS labels just yet
        
		if ( ((idxpacket[2] << 8) + idxpacket[3]) == 0x8847 )
			have_mpls = true;
        

		idxpacket += 4; // Skip the vlan header
		packet += 4; // Skip the vlan header
		
		//pkt_hdr_size = 0;

		// Check for 802.1ah (Q-in-Q) containing IP.
		// Only do a second layer of vlan tag
		// stripping because there is no
		// specification that allows for deeper
		// nesting.

		if ( ((idxpacket[2] << 8) + idxpacket[3]) == 0x0800 )
		{
			idxpacket += 4;
			packet += 4;
		}
    }

    // TODO: Cannot handle MPLS labels just yet
    
	if ( have_mpls )
		{
		// Skip the MPLS label stack.
		bool end_of_stack = false;

		while ( ! end_of_stack )
			{
			end_of_stack = *(idxpacket + 2) & 0x01;
			idxpacket += 4;
			}
		}
    
    // DEBUG DEBUG DEBUG
    //tmlog(TM_LOG_NOTE, "addPkt: Storage.cc, ~line 246", "ethernet phase/physical layer complete for packet %lu", header->ts.tv_usec);

    // set now to be the time stamp field of the pcap packet header
	tm_time_t now = to_tm_time(&header->ts);

    //init_hash_function();

	/* update connections state, classify, elephant cutoff */
    // conns is of type Connections
    /* add a packet. lookup the connection and increment byte and pkt counters if it exists,
     * otherwise create the entry (from Connections.hh)
     */
	Connection* c=conns.addPkt(header, idxpacket);

    //ProfilerStop();

    // a flow of packets characterized by the 5-tuple of (layer 4 protocol, source ip, source port, destination ip, destination port)
    // note that for protocols other than tcp/udp, may not include source/dest ports
    //tmlog(TM_LOG_NOTE, "addPkt: Storage.cc, ~line 255", "updating connection state to have the packet %lu", header->ts.tv_usec);
    // get class for connection
	Fifo *f=c->getFifo();
	QueryResult *qr=c->getSubscription();
	if (!f) {
        // f is the ring buffer
		/* No class has been assigned so far. */

		/* Expire old connections (that have presumably timed out). We can call removeOld anytime. It 
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
        // dynclasses is of type DynClassTable (from Storage.hh)
		dynclasses.removeOld(); // Housekeeping, basically removes the timed out connections (from DynClass.cc)
        // go through the source and destination addresses
		for (int i=0; i<2; i++) {
			if (i==0) {
                //tmlog(TM_LOG_NOTE, "Storage:addPkt", "source ip address get key");
                // get the ip address of source - in the definition in IndexField.hh, the 0 is an option in a 
                // case statement that is for the ip address of the source
				ip = SrcIPAddress::genKey(packet, 0);
				curdir = TM_DYNCLASS_ORIG;
			}
			else {
                //tmlog(TM_LOG_NOTE, "Storage:addPkt", "destination ip address get key");
                // get the ip address of destination - in the definition, the 0 is an option in a case statement
                // that is for the ip address of destination
				ip = DstIPAddress::genKey(packet, 0);
				curdir = TM_DYNCLASS_RESP;
			}

#ifdef TM_HEAVY_DEBUG
			assert(ip);
#endif
            // get the DynClass that corresponds to the ip key
			dc = dynclasses.get(ip);
            // if it is not NULL (meaning that the ip key was found in the hash table)
			if (dc) {
                // if the direction of the connection matches either of these options
				if (dc->dir==TM_DYNCLASS_BOTH || dc->dir==curdir)
                    // target class, class assigned
					f = dc->target;
                // delete the ip that we created
				delete(ip);
                // break out of for loop if we got the ip, but it did not match with those options
                // note that due to the for loop, the curdir is to correspond correctly with the ip
				break;
			}
			delete(ip);
		}
        // if class was assigned (not null) (basically, that the ip address corresponded to an entry in the
        // hash table already)
		if (f)
        {
            // set cache to which class this connection belongs
            // remember, c is of type Connection pointer
			c->setFifo(f);
        }
	}
	if (!f) {
		/* Still no class assigned. 
		 * Now evaluate BPF expressions defined for all classes and pick
		 * the appropriate class
		*/
        /*
		int max_precedence=INT_MAX;
        // go through all the possible classes
		for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++) {
    
            //tmlog(TM_LOG_DEBUG, "addPkt: Storage.cc, ~line 310", "value of matchPkt of packet %lu is %lu", header->ts.tv_usec, (*i)->matchPkt(header, idxpacket));

			if (// packet matches this class' filter (from Fifo.cc) and
				(*i)->matchPkt(header, packet) &&
				// first match or higher precedence match
				(f==NULL || (*i)->getPrecedence()>max_precedence) ) {
                //tmlog(TM_LOG_DEBUG, "addPkt: Storage.cc, ~line 316", "Packet match for packet %lu", header->ts.tv_usec);

                // class assigned
				f=*i;
                // set max_precedence to be the class filter's precedence, this is to check in the for loop to see if there is another class filter with higher precedence
				max_precedence=f->getPrecedence();
			}
		}
        */

        std::list<Fifo*>::iterator i = fifos.begin();
        while (i != fifos.end())
        {
            if ((*i)->matchPkt(header, packet))
            {
                f = *i;
                break;
            }
            i++;
        }
        // if class is assigned
		if (f)
            // set cache to which class this connection belongs
            // remember, c is of type Connection pointer
			c->setFifo(f);
	} // if (!f)
    //tmlog(TM_LOG_DEBUG, "addPkt: Storage.cc, ~line 324", "class assigned for packet %lu", header->ts.tv_usec);

    // if class is assigned
	if (f) {

		bool tcp_ctrl_flag=false;
        // making sure that the transport protocol is of TCP - packet_header
		if (IP(packet)->ip_p==IPPROTO_TCP || IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
            // tcp control flags, if true, set the tcp control flag to true
            // 
			if (TCP(packet)->th_flags & ( TH_FIN | TH_SYN | TH_RST ))
				tcp_ctrl_flag=true;

            //char str1[INET6_ADDRSTRLEN];

            //bro_inet_ntop(AF_INET6, &(IP6(idxpacket)->ip6_src.s6_addr), str1, INET6_ADDRSTRLEN);

            //char s1[INET6_ADDRSTRLEN];

            //inet_pton(AF_INET6, s1, str1);

            //char str2[INET6_ADDRSTRLEN];

            //bro_inet_ntop(AF_INET6, &(IP6(idxpacket)->ip6_dst.s6_addr), str2, INET6_ADDRSTRLEN);

            //tmlog(TM_LOG_NOTE, "Storage::addPkt", "we will be calling Fifo::Addpkt on packet that has source ip %s and destination ip %s", str1, str2);
        /* true if cutoff should not be done for this connection */
        // When the connection is subscribed or when a tcp control flag
        // is set, then addPkt is called with a connection NULL pointer
        // (From Fifo.cc, addPkt definition)
        // this also does the cut-off, partially based on the addPkt definition
        // from Fifo.cc
        // Finally, note that the addPkt definition of Fifo calls the addPkt
        // definition of FifoMem, which calls a packet eviction in memory to
        // delete older packets that are currently held in block until
        // there remains the newest recently added packet
        // The path seems to be: Storage::addPkt->Fifo::addPkt->FifoMem::addPkt -> FifoMem::pktEviction-> virtual FifoMemEvictionHandler: pktEviction -> Fifo::pktEviction -> FifoDisk::addPkt
        // So, it eventually leads to the writing of the class files (woo)
        // Also, note that f->addPkt returns true if we can add the packet, false otherwise
		if ( (( c->getSuspendCutoff() | tcp_ctrl_flag )
				&& f->addPkt(header, packet, NULL)) ||
				f->addPkt(header, packet, c)) {
			/* packet was stored in Fifo *f */
            // woo-hoo! bytes from the packet were not cut
			uncut_bytes += header->len;
			uncut_pkt_cnt++;

			/* update indexes, creates an input queue of IndexFields TODO: think about this for loop more - does it do this for all the packets? */
            /* It seems like it does it for all the packets that fulfill the if statement, goes through all the applicable indexes (ip, connection2, connection3,
               connection4). look at conf_parser.yy, at the conf_add_index method which seems to addIndex (method of Indexes) if applicable
               note that indexes is of type Indexes, which is in index.hh. An Index Object that is added to Indexes is owned by Indexes 
               I.e. Indexes will take care of deallocation the storage for
               Index.
            */
			for (std::list<IndexType*>::iterator i=indexes->begin();
					i!=indexes->end();
					i++) {

                // converts packet to IndexField type
				(*i)->addPkt(header, idxpacket);

                //tmlog(TM_LOG_DEBUG, "addPkt: Storage.cc, ~line 348", "testing to see whether connection 4 is called after this");

                //tmlog(TM_LOG_NOTE, "addPkt: Storage.cc, ~line 350", "adding packet %lu to indices for this index type %s", header->ts.tv_usec, (*i)->getIndexName().c_str());
			}
		} // if (f->addPkt) ... else it was "cut off"

        // set cache to which class this connection belongs
        // remember, c is of type Connection pointer
	    c->setFifo(f);
	} // if (f)
	if (qr) {
		// there is a subscription for this connection
		if (!(qr->sendPkt(header, packet)))
			c->deleteSubscription();
		/* Note: delteSubscription() decrements the use counter of the subscr. and
		 * if it reaches 0, the subscription is really deleted. 
		 * But since other conns using the same subscription will also detect that
		 * the subscriptions target is gone, the subscription will be removed in the
		 * end 
		 */
	}

    //delete c;
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
		fprintf(fp, "%s totBytes: %" PRIu64 "\n", (*i)->getClassname().c_str(),
			   (*i)->getFm()->getTotPktbytes());
	for (std::list<IndexType*>::iterator i=indexes->begin();
			i!=indexes->end();
			i++) {
		//(*i)->lock();
		fprintf(fp, "# %s index nodes RAM/Disk %" PRIu64 " %" PRIu64 "\n",
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
    // go through all the Fifo classes
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
        // if a time stamp for a fifo class is older than the previously oldest
        // time stamp, set the oldest timestamp to it
        // Note this is for in memory ring buffer
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
    // go through all the Fifo classes
	for (std::list<Fifo*>::iterator i=fifos.begin(); i!=fifos.end(); i++)
        // if a time stamp for a fifo class is older than the previously oldest
        // time stamp, set the oldest timestamp to it
        // Note this is for in disk
		if (r==0 || (*i)->getFd()->getOldestTimestamp() < r)
			r=(*i)->getFd()->getOldestTimestamp();
	return r;
}


void Storage::query(QueryRequest *query_req, QueryResult *query_res) {
	struct timeval t_start, t_end;
	gettimeofday(&t_start, NULL);
    /*
    #ifdef __APPLE__
    struct tvalspec t_start, t_end;
    clock_get_time(CLOCK_MONOTONIC_COARSE, &t_start);
    #endif
    #ifdef linux
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &t_start);
    #endif
    #ifdef __FreeBSD__
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC_FAST, &t_start);
    #endif
    */
	//fprintf(stderr, "Query ID: %d\n",  query_res->getQueryID());

    // getIndexByName is from Index.hh from class Indexes
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

    /*
    #ifdef __APPLE__
    clock_get_time(CLOCK_MONOTONIC_COARSE, &t_end);
    tmlog(TM_LOG_NOTE, "query", "%d Done. It took %.2lf seconds", query_res->getQueryID(), 
        valspec_to_tm(&t_end)-valspec_to_tm(&t_start));
    #endif
    */
    //#ifdef linux
    /*
    #if defined(linux) || defined(__APPLE__)
    clock_gettime(CLOCK_MONOTONIC_COARSE, &t_end);
    tmlog(TM_LOG_NOTE, "query", "%d Done. It took %.2lf seconds", query_res->getQueryID(),  
        spec_to_tm(&t_end)-spec_to_tm(&t_start));
    #endif
    #ifdef __FreeBSD__
    clock_gettime(CLOCK_MONOTONIC_FAST, &t_end);
    tmlog(TM_LOG_NOTE, "query", "%d Done. It took %.2lf seconds", query_res->getQueryID(),  
        spec_to_tm(&t_end)-spec_to_tm(&t_start));
    #endif
    */

	gettimeofday(&t_end, NULL);
	tmlog(TM_LOG_NOTE, "query", "%d Done. It took %.2lf seconds", query_res->getQueryID(), 
		to_tm_time(&t_end)-to_tm_time(&t_start));
	if (query_res->getUsage() == 0) {
		/* haven't passed it on to a subscription, delete it */
		delete query_res;
	}
	delete query_req;

	tot_queries_duration+=(uint64_t) ( (t_end.tv_sec-t_start.tv_sec)*1e6
										+(t_end.tv_usec-t_start.tv_usec)/1000 );
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

        /*
        #ifdef __APPLE__
        struct tvalspec tmptv;
        clock_get_time(CLOCK_MONOTONIC_COARSE, &tmptv)i;
        now = valspec_to_tm(&tmptv);
        #endif
        #ifdef linux
        */
        /*
        #if defined(linux) || defined(__APPLE__)
        struct timespec tmptv;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &tmptv);
        now = spec_to_tm(&tmptv);
        #endif
        #ifdef __FreeBSD__
        struct timespec tmptv;
        clock_gettime(CLOCK_MONOTONIC_FAST, &tmptv);
        now = spec_to_tm(&tmptv);
        #endif
        */
	//tmlog(TM_LOG_DEBUG, "dyn_class", "Setting IP %s to class %s, direction %d",
			//ip->getStr().c_str(), classname, dir);
	f = getFifoByName(std::string("class_") + classname);
	if (f) {
		if (dynclasses.get(ip) != NULL) {
			//tmlog(TM_LOG_NOTE, "dyn_class", "Overwrite dynamic assignment for IP %s",
			//		ip->getStr().c_str());
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
	//tmlog(TM_LOG_DEBUG, "dyn_class", "Remvoing setting for IP %s (if it exists)", ip->getStr().c_str());
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

