#include <pcap.h>
#include <sstream>

#include "Fifo.hh"
#include "Query.hh"

#include "FifoDisk.hh"

#ifdef USE_BROCCOLI
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

// note that typedef of pkt_ptr is u char*
bool QueryRequest::matchPkt(const pkt_ptr p) {
	/*
	if (!have_bpf) compileBPF();
	return bpf_filter(fp.bf_insns, p+sizeof(struct pcap_pkthdr),
	    ((struct pcap_pkthdr *)p)->len,
	    ((struct pcap_pkthdr *)p)->caplen);
	*/
	tmlog(TM_LOG_NOTE, "QueryRequest: matchPkt(const pkt_ptr)", "determine if a packet matches");
	// matchPkt method from Fifo
	return matchPkt((struct pcap_pkthdr *)p, p+sizeof(struct pcap_pkthdr));
}

bool QueryRequest::matchPkt(struct pcap_pkthdr *hdr, const u_char *pkt) {
	//tmlog(TM_LOG_ERROR, "QueryRequest: matchPkt(struct pcap_pkthdr, u_char pkt)", "determine if a packet matches");
        //printf("QueryRequest:matchPkt, determine if a packet matches");
	if (!have_bpf) compileBPF();


        //printf("QueryRequest:matchPkt, determine if a packet matchesi after compileBPF()\n");

    uint16_t ether_type=ntohs(ETHERNET(pkt)->ether_type);
    // ETHERTYPE_IP is EtherType 0x800, for IPv4 addresses
    // EtherType 0x8100 is for VLAN header
    // EtherType 0x86DD is for IPv6 addresses
    // EtherType is a field in the ethernet header frame
	if ( ! (ether_type==ETHERTYPE_IP || ether_type==0x8100 || ether_type==0x86DD) ) {

        tmlog(TM_LOG_DEBUG, "QueryRequest::matchPkt, ~line 240", "unknown ether_type 0x%.4X", ether_type);

		//    fprintf(stderr,"unknown ether_type 0x%.4X\n", ether_type);
		return false;
	}

    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_NOTE, "addPkt: Storage.cc, ~line 240", "adding packet %lu !", header->ts.tv_usec);

    //SetHdrSize();

	// Unfortunately some packets on the link might have MPLS labels
	// while others don't. That means we need to ask the link-layer if
	// labels are in place. TODO: Cannot handle MPLS labels just yet
	//bool have_mpls = false;

	// skip VLAN header (related to ethernet frame header) for indexing TODO: look at VLAN header more closely
    // Virtual Bridged Local Area Network for logically group network devices together, which share the same 
    // physical network. VLAN tag is 4 bytes and so a VLAN header is 4 bytes longer than a regular ethernet header
	//if (ether_type==0x8100) idxpacket+=4;
    
    if (ether_type == 0x8100)
    {
        tmlog(TM_LOG_NOTE, "QueryRequest::matchPkt", "we have a vlan tag");
		// Check for MPLS in VLAN.
        
        // TODO: Cannot handle MPLS labels just yet
        /*
		if ( ((idxpacket[2] << 8) + idxpacket[3]) == 0x8847 )
			have_mpls = true;
        */

		pkt += 4; // Skip the vlan header
		//pkt_hdr_size = 0;

		// Check for 802.1ah (Q-in-Q) containing IP.
		// Only do a second layer of vlan tag
		// stripping because there is no
		// specification that allows for deeper
		// nesting.
		if ( ((pkt[2] << 8) + pkt[3]) == 0x0800 )
			pkt += 4;
    }

    // TODO: Cannot handle MPLS labels just yet
    /*
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
    */

    //printf("QueryRequest: matchPkt, the value of the bpf_filter in query request for packet %lu and %lu is%lu", hdr->ts.tv_sec, hdr->ts.tv_usec, bpf_filter(fp.bf_insns, (unsigned char*)(pkt), hdr->len, hdr->caplen));
    //tmlog(TM_LOG_ERROR, "QueryRequest: matchPkt(2 args)", "The value of the bpf_filter in query request  for packet %lu and %lu is %lu", hdr->ts.tv_sec, hdr->ts.tv_usec, bpf_filter(fp.bf_insns, (unsigned char*)(pkt), hdr->len, hdr->caplen));
    
	return bpf_filter(fp.bf_insns, (u_char *)(pkt),
					  hdr->len,
					  hdr->caplen);
}

void QueryRequest::compileBPF() {
#define MAX_BPF_STR_LEN 2048 //8192 
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
       if (chdir(conf_main_workdir)) {
           fprintf(stderr, "cannot chdir to %s\n", conf_main_workdir);
           //return(1);
        }

        struct stat st;

        if (stat(conf_main_queryfiledir, &st) != 0)
        {
            printf("The index directory %s did not exist. Creating the directory ...\n", conf_main_queryfiledir);
            mkdir(conf_main_queryfiledir, 0755);
        }


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


#ifdef USE_BROCCOLI

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

#endif // USE_BROCCOLI


