#include "types.h"

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include "re2/re2.h"

#include "Connection.hh"
#include "packet_headers.h"
#include "Fifo.hh"
#include "Query.hh"
#include "tm.h"

static std::string pattern_ip4 ("(?:\\d+\\.\\d+\\.\\d+\\.\\d+)");
static std::string pattern_ip6_expanded ("(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})");
static std::string pattern_ip6_compressed_hex ("(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)");
static std::string pattern_ip6_6hex4dec ("(?:(?:[0-9A-Fa-f]{1,4}:){6,6})(?:[0-9]+)\\.(?:[0-9]+)\\.(?:[0-9]+)\\.(?:[0-9]+)");
static std::string pattern_ip6_compressed_6hex4dec ("(?:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::(?:(?:[0-9A-Fa-f]{1,4}:)*)(?:[0-9]+)\\.(?:[0-9]+)\\.(?:[0-9]+)\\.(?:[0-9]+)");
static std::string pattern_ip6 = pattern_ip6_expanded + "|" + pattern_ip6_compressed_hex + "|" + pattern_ip6_6hex4dec + "|" + pattern_ip6_compressed_6hex4dec;
static std::string pattern_ip = "(" + pattern_ip4 + "|" + pattern_ip6 + ")";

static std::string pattern_ipport = pattern_ip + ":(\\d+)";

inline uint32_t revert_uint32(uint32_t i) {
	uint32_t r;
	((uint8_t*)&r)[0]=((uint8_t*)&i)[3];
	((uint8_t*)&r)[1]=((uint8_t*)&i)[2];
	((uint8_t*)&r)[2]=((uint8_t*)&i)[1];
	((uint8_t*)&r)[3]=((uint8_t*)&i)[0];

	return r;
}

inline uint16_t revert_uint16(uint16_t i) {
	uint16_t r;
	((uint8_t*)&r)[0]=((uint8_t*)&i)[1];
	((uint8_t*)&r)[1]=((uint8_t*)&i)[0];

	return r;
}

inline bool addr_port_canon_lt(uint32_t s_ip, uint32_t d_ip,
							   uint16_t s_port, uint16_t d_port) {
	if (s_ip == d_ip)
		return (s_port < d_port);
	else
		return (s_ip < d_ip);
}

void ConnectionID4::init(proto_t proto,
						 uint32_t s_ip, uint32_t d_ip,
						 uint16_t s_port, uint16_t d_port) {
	v.proto=proto;
	if (addr_port_canon_lt(s_ip,d_ip,s_port,d_port)) {
		//    v.is_canonified=true;
		v.ip1=IPAddr(IPv4, &d_ip, IPAddr::Network);
		v.ip2=IPAddr(IPv4, &s_ip, IPAddr::Network);

		v.port1=d_port;
		v.port2=s_port;
	} else {
		//    v.is_canonified=false;
		v.ip1=IPAddr(IPv4, &s_ip, IPAddr::Network);
		v.ip2=IPAddr(IPv4, &d_ip, IPAddr::Network);
		v.port1=s_port;
		v.port2=d_port;
	}
}

void ConnectionID3::init(proto_t proto,
						 uint32_t ip1, uint32_t ip2,
						 uint16_t port2) {
	v.proto=proto;
	v.ip1=IPAddr(IPv4, &ip1, IPAddr::Network);
	v.ip2=IPAddr(IPv4, &ip2, IPAddr::Network);
	v.port2=port2;
}

void ConnectionID2::init( uint32_t s_ip, uint32_t d_ip) {
	if (addr_port_canon_lt(s_ip,d_ip,0,0)) {
		//    v.is_canonified=true;
		v.ip1=IPAddr(IPv4, &d_ip, IPAddr::Network);
		v.ip2=IPAddr(IPv4, &s_ip, IPAddr::Network);
	} else {
		//    v.is_canonified=false;
		v.ip1=IPAddr(IPv4, &s_ip, IPAddr::Network);
		v.ip2=IPAddr(IPv4, &d_ip, IPAddr::Network);
	}
}

ConnectionID4::ConnectionID4(const u_char* packet) {
	switch (IP(packet)->ip_p) {
	case IPPROTO_UDP:
		init(IP(packet)->ip_p,
			 IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr,
			 UDP(packet)->uh_sport, UDP(packet)->uh_dport);
		break;
	case IPPROTO_TCP:
		init(IP(packet)->ip_p,
			 IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr,
			 TCP(packet)->th_sport, TCP(packet)->th_dport);
		break;
	default:
		init(IP(packet)->ip_p,
			 IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr,
			 0, 0);
		break;
	}
}


ConnectionID3::ConnectionID3(const u_char* packet,
							 int wildcard_port) {
	switch (IP(packet)->ip_p) {
	case IPPROTO_UDP:
		if (wildcard_port) 
			init(IP(packet)->ip_p,
				 IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr,
				 UDP(packet)->uh_dport);
		else
			init(IP(packet)->ip_p,
				 IP(packet)->ip_dst.s_addr, IP(packet)->ip_src.s_addr,
				 UDP(packet)->uh_sport);
		break;
	case IPPROTO_TCP:
		if (wildcard_port) 
			init(IP(packet)->ip_p,
				 IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr,
				 TCP(packet)->th_dport);
		else
			init(IP(packet)->ip_p,
				 IP(packet)->ip_dst.s_addr, IP(packet)->ip_src.s_addr,
				 TCP(packet)->th_sport);
		break;
	default:
		if (wildcard_port) 
			init(IP(packet)->ip_p,
				 IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr,
				 0);
		else
			init(IP(packet)->ip_p,
				 IP(packet)->ip_dst.s_addr, IP(packet)->ip_src.s_addr,
				 0);
		break;
	}
}


ConnectionID2::ConnectionID2(const u_char* packet) {
	init(IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr);
}


//TODO: MAke this inline (i.e. move to Connection.hh so that it is
//consistent with ConnectionID4
bool ConnectionID3::operator==(const ConnectionID& other) const {
	return (v.proto == ((ConnectionID3*)&other)->v.proto)
		   && (v.ip1 == ((ConnectionID3*)&other)->v.ip1)
		   && (v.ip2 == ((ConnectionID3*)&other)->v.ip2)
		   && (v.port2 == ((ConnectionID3*)&other)->v.port2);
}

//TODO: MAke this inline (i.e. move to Connection.hh so that it is
//consistent with ConnectionID4
bool ConnectionID2::operator==(const ConnectionID& other) const {
	return (v.ip1 == ((ConnectionID2*)&other)->v.ip1)
		   && (v.ip2 == ((ConnectionID2*)&other)->v.ip2);
}

void ConnectionID4::getStr(char* s, int maxsize) const {
	getStr().copy(s, maxsize);

}

void ConnectionID3::getStr(char* s, int maxsize) const {
	getStr().copy(s, maxsize);
}

void ConnectionID2::getStr(char* s, int maxsize) const {
	getStr().copy(s, maxsize);
}

std::string ConnectionID4::getStr() const {
	std::stringstream ss;

	ss << " ConnectionID4 "
	<< get_proto() << " "
	// << " canonified " << get_is_canonified() << " "
	<< get_ip1()->AsString()
	<< ":"
	<< ntohs(get_port1())
	<< " - "
	<< get_ip2()->AsString()
	<< ":"
	<< ntohs(get_port2());
	return ss.str();
}


std::string ConnectionID3::getStr() const {
	std::stringstream ss;

	ss << " ConnectionID3 "
	<< get_ip1()->AsString()
	<< " - "
	<< get_ip2()->AsString()
	<< ":"
	<< get_port();
	return ss.str();
}

std::string ConnectionID2::getStr() const {
	std::stringstream ss;

	ss << " ConnectionID2 "
	<< get_ip1()->AsString()
	<< " - "
	<< get_ip2()->AsString();
	return ss.str();
}



// Static Member initialization
std::string ConnectionID4::pattern_connection4 = "\\s*(\\w+)\\s+"
	+ pattern_ipport + "\\s+-?\\s*" + pattern_ipport + "\\s*";
RE2 ConnectionID4::re(ConnectionID4::pattern_connection4);

ConnectionID4* ConnectionID4::parse(const char *str) {
	std::string protostr, src_ip, dst_ip;
	unsigned src_port, dst_port;
	proto_t proto;

	if (!RE2::FullMatch(str, re, &protostr, &src_ip, &src_port, &dst_ip, &dst_port)) {
		return NULL;
	}
	if (protostr == std::string("tcp"))
		proto = IPPROTO_TCP;
	else 
		proto = IPPROTO_UDP;
		
	return new ConnectionID4(proto, inet_addr(src_ip.c_str()), inet_addr(dst_ip.c_str()),
			htons(src_port), htons(dst_port));
}

void Connection::addPkt(const struct pcap_pkthdr* header, const u_char* packet) {
	last_ts=to_tm_time(&header->ts);
	tot_pkts++;
	tot_pktbytes+=header->caplen;
}

int Connection::deleteSubscription() {
	//fprintf(stderr, "DEBUG deleteSubscription called\n");
	if (subscription) {
		subscription->decUsage();
		if (subscription->getUsage() == 0)  {
			delete(subscription);
			//fprintf(stderr, "DEBUG subscription deleted\n");
		}
		return 1;
	}
	return 0;
}


void Connection::init(ConnectionID4 *id) {
	last_ts=tot_pktbytes=tot_pkts=0;
	subscription=NULL;
	fifo=NULL;
	suspend_cutoff=suspend_timeout=false;

	col_next = col_prev = NULL;
	q_older = q_newer = NULL;
	c_id = id;
}

Connection::Connection(Connection *c) {
	last_ts = c->last_ts;
	tot_pktbytes = c->tot_pktbytes;
	tot_pkts = c->tot_pkts;
	fifo = c->fifo;
	//FIXME: TODO: should we make a deep copy here??
	subscription = c->subscription;
	suspend_cutoff = c->suspend_cutoff;
	suspend_timeout = c->suspend_timeout;

	col_next = col_prev = NULL;
	q_older = q_newer = NULL;

	c_id = new ConnectionID4(c->c_id);
}


std::string Connection::getStr() const {
	std::stringstream ss;
	ss.setf(std::ios::fixed);
	ss << tot_pkts << " pkts, " << tot_pktbytes << " bytes"
	<< ", last packet at " << last_ts
	<< std::endl
	<< (fifo ? "class "+fifo->getClassname() :
		"no class associated")
	<< (suspend_cutoff ? ", cutoff suspended" : "")
	<< (suspend_timeout ? ", timeout suspended" : "")
	<< (subscription ? ", subscription to "+subscription->getStr() : "")
	;
	return c_id->getStr() + " " + ss.str();
}

