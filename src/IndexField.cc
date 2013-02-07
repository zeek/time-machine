#ifndef INDEXFIELD_CC
#define INDEXFIELD_CC

#include <limits.h>
#include <list>

#include "types.h"
#include "packet_headers.h"
#include <sstream>

#include "IndexField.hh"
#include "tm.h"

static std::string pattern_ip ("(\\d+\\.\\d+\\.\\d+\\.\\d+)");
static std::string pattern_ipport ("(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)");


/* size of an ip addr in dottet decimal as string: 4x3digits, 
  3 dots, terminating nul byte */
#define TM_IP_STR_SIZE 16
static void ip_to_str(uint32_t ip, char *str, int len) {
#define UCP(x) ((unsigned char *)&(x))
	str[0] = '\0';
	snprintf(str, len, "%d.%d.%d.%d",
			 UCP(ip)[0] & 0xff,
			 UCP(ip)[1] & 0xff,
			 UCP(ip)[2] & 0xff,
			 UCP(ip)[3] & 0xff);
}
/*
IndexField::IndexField(void *p) {
  memcpy(getConstKeyPtr(), p, getKeySize());
}
*/

/******************************************************************************
 * IPAddress
 ******************************************************************************/
// Static Member initialization
std::string IPAddress::pattern = "\\s*" + pattern_ip + "\\s*";
RE2 IPAddress::re(IPAddress::pattern);

IndexField* IPAddress::parseQuery(const char *query) {
	std::string ip;

	if (!RE2::FullMatch(query, re, &ip))
		return NULL;

	return new IPAddress(ip.c_str());
}

std::list<IPAddress*> IPAddress::genKeys(const u_char* packet) {
	std::list<IPAddress*> li;
	li.push_back(new SrcIPAddress(packet));
	li.push_back(new DstIPAddress(packet));
	return li;
}

void IPAddress::getStr(char* s, int maxsize) const {
	unsigned char *ucp = (unsigned char *)&ip_address;

	snprintf(s, maxsize, "%d.%d.%d.%d",
			 ucp[0] & 0xff,
			 ucp[1] & 0xff,
			 ucp[2] & 0xff,
			 ucp[3] & 0xff);
}

std::string IPAddress::getStr() const {
	unsigned char *ucp = (unsigned char *)&ip_address;
	std::stringstream ss;
	ss << (ucp[0] & 0xff) << "."
	<< (ucp[1] & 0xff) << "."
	<< (ucp[2] & 0xff) << "."
	<< (ucp[3] & 0xff);

	return ss.str();
}

void IPAddress::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "host %s", getStr().c_str());
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "IPAddress::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}


SrcIPAddress::SrcIPAddress(const u_char* packet):
IPAddress(IP(packet)->ip_src.s_addr) {}

std::list<SrcIPAddress*> SrcIPAddress::genKeys(const u_char* packet) {
	std::list<SrcIPAddress*> li;
	li.push_back(new SrcIPAddress(packet));
	return li;
}

void SrcIPAddress::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "src host %s", getStr().c_str());
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "SrcIPAddress::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}


DstIPAddress::DstIPAddress(const u_char* packet):
IPAddress(IP(packet)->ip_dst.s_addr) {}

std::list<DstIPAddress*> DstIPAddress::genKeys(const u_char* packet) {
	std::list<DstIPAddress*> li;
	li.push_back(new DstIPAddress(packet));
	return li;
}

void DstIPAddress::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "dst host %s", getStr().c_str());
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "DstIPAddress::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}


/******************************************************************************
 * Port
 ******************************************************************************/
// Static Member initialization
std::string Port::pattern = "\\s*(\\d+)\\s*";
RE2 Port::re(Port::pattern);

std::list<Port*> Port::genKeys(const u_char* packet) {
	std::list<Port*> li;
	li.push_back(new SrcPort(packet));
	li.push_back(new DstPort(packet));
	return li;
}

IndexField* Port::parseQuery(const char *query) {
	unsigned port;

	if (!RE2::FullMatch(query, re, &port))
		return NULL;

	/*
	fprintf(stderr, "%s\nPort::parseQuery:  %s ===> <%u> \n", 
				pattern.c_str(), query, port);
	
	*/
	return new Port( htons(port));
}


void Port::getStr(char* s, int maxsize) const {
	snprintf(s, maxsize, "%d", port);
}

std::string Port::getStr() const {
	std::stringstream ss;
	ss << ntohs(port);
	return ss.str();
}

void Port::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "port %u", ntohs(port));
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "Port::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}


SrcPort::SrcPort(const u_char* packet) {
	switch (IP(packet)->ip_p) {
	case IPPROTO_UDP:
		port=(UDP(packet)->uh_sport);
		break;
	case IPPROTO_TCP:
		port=(TCP(packet)->th_sport);
		break;
	default:
		port=0;
		break;
	}
};

std::list<SrcPort*> SrcPort::genKeys(const u_char* packet) {
	std::list<SrcPort*> li;
	li.push_back(new SrcPort(packet));
	return li;
}

void SrcPort::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "src port %s", getStr().c_str());
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "SrcPort::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}


DstPort::DstPort(const u_char* packet) {
	switch (IP(packet)->ip_p) {
	case IPPROTO_UDP:
		port=(UDP(packet)->uh_dport);
		break;
	case IPPROTO_TCP:
		port=(TCP(packet)->th_dport);
		break;
	default:
		port=0;
		break;
	}
};

std::list<DstPort*> DstPort::genKeys(const u_char* packet) {
	std::list<DstPort*> li;
	li.push_back(new DstPort(packet));
	return li;
}

void DstPort::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "dst port %s", getStr().c_str());
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "DstPort::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}


/***********************************************************************
 * ConnectionIF4
 **********************************************************************/
// Static Member initialization
std::string ConnectionIF4::pattern_connection4 = "\\s*(\\w+)\\s+"
	+ pattern_ipport + "\\s+" + pattern_ipport + "\\s*";
RE2 ConnectionIF4::re(ConnectionIF4::pattern_connection4);

std::list<ConnectionIF4*> ConnectionIF4::genKeys(const u_char* packet) {
	std::list<ConnectionIF4*> li;
	li.push_back(new ConnectionIF4(packet));
	return li;
}

//FIXME: merge this somehow with ConnectionID4::parse() !!!!
IndexField* ConnectionIF4::parseQuery(const char *query) {
	std::string protostr, src_ip, dst_ip;
	unsigned src_port, dst_port;
	proto_t proto;


	if (!RE2::FullMatch(query, re, &protostr, &src_ip, &src_port, &dst_ip, &dst_port))
		return NULL;

	/*
	fprintf(stderr, "%s\nConnectionIF4::parseQuery:  %s ===> <%s> <%s>:<%u> <%s>:<%u>\n", 
				pattern_connection4.c_str(), query, protostr.c_str(), 
				src_ip.c_str(), src_port, dst_ip.c_str(), dst_port);
	*/
	if (protostr == std::string("tcp"))
		proto = IPPROTO_TCP;
	else 
		proto = IPPROTO_UDP;
		
	return new ConnectionIF4(proto, inet_addr(src_ip.c_str()), htons(src_port),
			inet_addr(dst_ip.c_str()), htons(dst_port));
}

void ConnectionIF4::getBPFStr(char *str, int max_str_len) const {

	char s_ip_str[TM_IP_STR_SIZE];
	char d_ip_str[TM_IP_STR_SIZE];
	uint32_t s_port;
	uint32_t d_port;
	/*
	if (c_id.get_is_canonified()) {
	  s_ip=c_id.get_ip2();
	  d_ip=c_id.get_ip1();
	  s_port=c_id.get_port2();
	  d_port=c_id.get_port1();
	} else {
	*/
	ip_to_str(c_id.get_ip1(), s_ip_str, sizeof(s_ip_str));
	ip_to_str(c_id.get_ip2(), d_ip_str, sizeof(d_ip_str));
	s_port=c_id.get_port1();
	d_port=c_id.get_port2();
	/*  }  */

	snprintf(str, max_str_len,
			 "host %s and port %d and host %s and port %d",
			 s_ip_str, 
			 ntohs(s_port),
			 d_ip_str,
			 ntohs(d_port));
}


/***********************************************************************
 * ConnectionIF3
 **********************************************************************/
// Static Member initialization
std::string ConnectionIF3::pattern_connection3 = "\\s*(\\w+)\\s+"
		+ pattern_ip + "\\s+" + pattern_ip + ":"
		+ "(\\d+)\\s*";
RE2 ConnectionIF3::re(ConnectionIF3::pattern_connection3);

std::list<ConnectionIF3*>
ConnectionIF3::genKeys(const u_char* packet) {
	std::list<ConnectionIF3*> li;
	li.push_back(new ConnectionIF3(packet, 0));
	li.push_back(new ConnectionIF3(packet, 1));
	return li;
}

IndexField* ConnectionIF3::parseQuery(const char *query) {
	std::string protostr, src_ip, dst_ip;
	unsigned port;
	proto_t proto;
	
	if (!RE2::FullMatch(query, re, &protostr, &src_ip, &dst_ip, &port))
		return NULL;

	/*
	fprintf(stderr, "%s\nConnectionIF3::parseQuery:  %s ===> <%s> <%s> <%s> <%u>\n", 
				pattern_connection3.c_str(), query, protostr.c_str(), 
				src_ip.c_str(), dst_ip.c_str(), port);
	*/
	if (protostr == std::string("tcp"))
		proto = IPPROTO_TCP;
	else 
		proto = IPPROTO_UDP;
		
	return new ConnectionIF3(proto, inet_addr(src_ip.c_str()), 
			inet_addr(dst_ip.c_str()), htons(port));
}

void ConnectionIF3::getBPFStr(char *str, int max_str_len) const {

	char ip1_str[TM_IP_STR_SIZE];
	char ip2_str[TM_IP_STR_SIZE];

	ip_to_str(c_id.get_ip1(), ip1_str, sizeof(ip1_str));
	ip_to_str(c_id.get_ip2(), ip2_str, sizeof(ip2_str));

	snprintf(str, max_str_len,
			 "(src host %s and dst host %s and dst port %d) or "
			 "(dst host %s and src host %s and src port %d)",
			 ip1_str, ip2_str, ntohs(c_id.get_port()),
			 ip1_str, ip2_str, ntohs(c_id.get_port()));
}


/***********************************************************************
 * ConnectionIF2
 **********************************************************************/
// Static Member initialization
std::string ConnectionIF2::pattern_connection2 = 
		"\\s*" + pattern_ip + "\\s+" + pattern_ip + "\\s*";
RE2 ConnectionIF2::re(ConnectionIF2::pattern_connection2);

std::list<ConnectionIF2*>
ConnectionIF2::genKeys(const u_char* packet) {
	std::list<ConnectionIF2*> li;
	li.push_back(new ConnectionIF2(packet));
	return li;
}


IndexField* ConnectionIF2::parseQuery(const char *query) {
	std::string src_ip, dst_ip;
	
	if (!RE2::FullMatch(query, re, &src_ip, &dst_ip))
		return NULL;

	/*
	fprintf(stderr, "%s\nConnectionIF22:parseQuery:  %s ===> <%s> <%s>\n", 
				pattern_connection2.c_str(), query, src_ip.c_str(), dst_ip.c_str());
	*/
	return new ConnectionIF2(inet_addr(src_ip.c_str()), inet_addr(dst_ip.c_str()));
}

void ConnectionIF2::getBPFStr(char *str, int max_str_len) const {

	char s_ip_str[TM_IP_STR_SIZE];
	char d_ip_str[TM_IP_STR_SIZE];

	ip_to_str(c_id.get_ip1(), s_ip_str, sizeof(s_ip_str));
	ip_to_str(c_id.get_ip2(), d_ip_str, sizeof(d_ip_str));


	snprintf(str, max_str_len,
			 "host %s and host %s",
			 s_ip_str, d_ip_str);
}



#endif
