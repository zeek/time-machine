#ifndef INDEXFIELD_CC
#define INDEXFIELD_CC

#include <limits.h>
#include <list>

#include "types.h"
#include "packet_headers.h"
#include <sstream>

#include "IndexField.hh"
#include "bro_inet_ntop.h"
#include "tm.h"

const uint8_t IPAddress::v4_mapped_prefix[12] = { 0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0xff, 0xff };


static std::string pattern_ip ("(\\d+\\.\\d+\\.\\d+\\.\\d+)"); // TODO: figure out the structure
                                                               // I think I understand: look at the re2 directory
                                                               // parsing, with d representing integer and plus sign meaning
                                                               // preceding character once or more


//static std::string pattern_ip6 ("(\\w+:\\w+:\\w+:\\w+:\\w+:\\w+:\\w+:\\w+)"); // I am using word from re2, perl regular expression for the alphanumeric part

static std::string pattern_ip6 ("\\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\]");
// stolen from stackoverflow http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses

static std::string pattern_ipport ("(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)");

// brackets are necessary when specifying a port number of IPv6
//static std::string pattern_ip6port ("([\\w+:\\w+:\\w+:\\w+:\\w+:\\w+:\\w+:\\w+]):(\\d+)"); // IPv6 addresses that have a port are of the form []:#

static std::string pattern_ip6port ("\\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\]:(\\d+)");
// stolen from stackoverflow http://stackoverflow.com/questions/53497/regular-expression-that-


/* size of an ip addr in dottet decimal as string: 4x3digits, 
  3 dots, terminating nul byte */
#define TM_IP_STR_SIZE 16
/*
static void ip_to_str(const unsigned char* ip, char *str, int len) {
//#define UCP(x) ((unsigned char *)&(x))
	str[0] = '\0';
*/
    /*
	snprintf(str, len, "%d.%d.%d.%d",
			 UCP(ip)[0] & 0xff,
			 UCP(ip)[1] & 0xff,
			 UCP(ip)[2] & 0xff,
			 UCP(ip)[3] & 0xff);
    */
/*
    snprintf(str, len, "%s", ip);
}
*/
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
std::string IPAddress::pattern6 = "\\s*" + pattern_ip6 + "\\s*";
RE2 IPAddress::re(IPAddress::pattern);
RE2 IPAddress::re6(IPAddress::pattern6);
//int IPAddress::AFtypelength;

IndexField* IPAddress::parseQuery(const char *query) {
	std::string ip;

	if (!RE2::FullMatch(query, re, &ip) && !RE2::FullMatch(query, re6, &ip))
    {
        tmlog(TM_LOG_ERROR,"parseQuery", "Cannot do full match!");
        //tmlog(TM_LOG_ERROR, "parseQuery", ip);
		return NULL;
    }
    /*
    if (AFtypelength == INET_ADDRSTRLEN)
        char strIP[INET_ADDRSTRLEN];
    else
        char strIP[INET6_ADDRSTRLEN];
    */
    //char strIP[AFtypelength];


    // WHAT and so it begins i guess
    // INET6_ADDRSTRLEN is 46 and INET_ADDRSTRLEN is 16
    //char strIP46[INET6_ADDRSTRLEN];

    tmlog(TM_LOG_NOTE, "parseQuery", "the argument we pass to IPAddress is %s", ip.c_str());

	return new IPAddress(ip.c_str());//, strIP46);
}

std::list<IPAddress*> IPAddress::genKeys(const u_char* packet) {
	std::list<IPAddress*> li;
    if (IP(packet)->ip_v == 4)
    {
    	li.push_back(new SrcIPAddress(IP(packet)->ip_src.s_addr));
    	li.push_back(new DstIPAddress(IP(packet)->ip_dst.s_addr));
    }
    else
    {
    	li.push_back(new SrcIPAddress(IP6(packet)->ip6_src.s6_addr));
    	li.push_back(new DstIPAddress(IP6(packet)->ip6_dst.s6_addr));
    }
	return li;
}

void IPAddress::getStr(char* s, int maxsize) const {
	//unsigned char *ucp = (unsigned char *)&ip6_address;

	if ( GetFamily() == IPv4 )
		{
        tmlog(TM_LOG_NOTE, "IPAddress", "IPAddress, IPv4");
		char ucp[INET_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET, &ipv6_address.s6_addr[12], ucp, INET_ADDRSTRLEN) )
			tmlog(TM_LOG_ERROR, "IPAddress", "<bad IPv4 address conversion");
		else
			snprintf(s, maxsize, "%s", ucp);
		}
	else
		{
        tmlog(TM_LOG_NOTE, "IPAddress", "IPAddress, IPv6");
		char ucp[INET6_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET6, ipv6_address.s6_addr, ucp, INET6_ADDRSTRLEN) )
			tmlog(TM_LOG_ERROR, "IPAddress", "<bad IPv6 address conversion");
		else
			snprintf(s, maxsize, "%s", ucp);
		}


// Why do they do this?
/*
	snprintf(s, maxsize, "%d.%d.%d.%d",
			 ucp[0] & 0xff,
			 ucp[1] & 0xff,
			 ucp[2] & 0xff,
			 ucp[3] & 0xff);
*/
}

/*
std::string IPAddress::getStr() const {
	unsigned char *ucp = (unsigned char *)&ip_address;
	std::stringstream ss;
	ss << (ucp[0] & 0xff) << "."
	<< (ucp[1] & 0xff) << "."
	<< (ucp[2] & 0xff) << "."
	<< (ucp[3] & 0xff);

	return ss.str();
}
*/

void IPAddress::Init(const std::string& s)
	{
    // if it could not find :, then it is equal to npos and so IPv4
	if ( s.find(':') == std::string::npos ) // IPv4.
		{
        tmlog(TM_LOG_NOTE, "IPAddress:Init", "initializing IPAddress, IPv4");
		memcpy(ipv6_address.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));

		// Parse the address directly instead of using inet_pton since
		// some platforms have more sensitive implementations than others
		// that can't e.g. handle leading zeroes.
		int a[4];
		int n = sscanf(s.c_str(), "%d.%d.%d.%d", a+0, a+1, a+2, a+3);

		if ( n != 4 || a[0] < 0 || a[1] < 0 || a[2] < 0 || a[3] < 0 ||
		     a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 )
			{
            tmlog(TM_LOG_ERROR, "Bad IP address: %s", s.c_str());
			//reporter->Error("Bad IP address: %s", s.c_str());
			memset(ipv6_address.s6_addr, 0, sizeof(ipv6_address.s6_addr));
			return;
			}

		uint32_t addr = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
		addr = htonl(addr);
		memcpy(&ipv6_address.s6_addr[12], &addr, sizeof(uint32_t));
		}

	else
		{
        tmlog(TM_LOG_NOTE, "IPAddress:Init", "initializing IPAddress, IPv6");
		if ( inet_pton(AF_INET6, s.c_str(), ipv6_address.s6_addr) <=0 )
			{
            tmlog(TM_LOG_ERROR, "Bad IP address: %s", s.c_str());
			//reporter->Error("Bad IP address: %s", s.c_str());
			memset(ipv6_address.s6_addr, 0, sizeof(ipv6_address.s6_addr));
			}
		}
        tmlog(TM_LOG_NOTE, "IPAddress::Init", "good IP Address %s", s.c_str());
	}

std::string IPAddress::getStr() const
{
    
	if ( GetFamily() == IPv4 )
		{
        tmlog(TM_LOG_NOTE, "IPAddress: getStr()", "IPAddress, IPv4");
		char s[INET_ADDRSTRLEN];

		if ( ! bro_inet_ntop(AF_INET, &ipv6_address.s6_addr[12], s, INET_ADDRSTRLEN) )
			return "<bad IPv4 address conversion";
		else
			return s;
		}
	else
		{
        
        tmlog(TM_LOG_NOTE, "IPAddress: getStr()", "IPAddress, IPv6");
		char s[INET6_ADDRSTRLEN];

		if ( ! bro_inet_ntop(AF_INET6, ipv6_address.s6_addr, s, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
			return s;
		}
}

std::string IPAddress::getStrPkt(const u_char* packet) const
{
    #define UCP(x) ((unsigned char *)&x)

	std::stringstream ss;
    
	if (IP(packet)->ip_v == 4)
		{

        unsigned char ip4[16];      

        memcpy(ip4, ipv6_address.s6_addr, sizeof(ipv6_address.s6_addr));

	    ss << " ip "
	    << (UCP(ip4)[0] & 0xff) << "."
	    << (UCP(ip4)[1] & 0xff) << "."
	    << (UCP(ip4)[2] & 0xff) << "."
	    << (UCP(ip4)[3] & 0xff);
	    return ss.str();
		}
	else
		{   

        tmlog(TM_LOG_NOTE, "IPAddress: getStr(u_char*)", "IPAddress, IPv6");
		char str[INET6_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET6, ipv6_address.s6_addr, str, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
        {
            ss << " ip for IPv6"

            << "[" << str << "]";
			return ss.str();
        }
	}
}


void IPAddress::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "host %s", getStr().c_str());
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "IPAddress::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}

/*
SrcIPAddress::SrcIPAddress(const u_char* packet)
{
    if (IP(packet)->ip_v == 4)
    {
        tmlog(TM_LOG_NOTE, "IndexField.cc: SrcIPAddress", "IPv4 initialization");
	    new IPAddress(IP(packet)->ip_src.s_addr);

    }

    else
    {
        tmlog(TM_LOG_NOTE, "IndexField.cc: SrcIPAddress", "IPv6 initialization");
        new IPAddress(IP6(packet)->ip6_src.s6_addr);  
    } 
}
*/
// it might be ok to leave it as it is since Init takes care of the IPv6 part
//SrcIPAddress::SrcIPAddress(const char* s): IPAddress(s) {}

//SrcIPAddress::SrcIPAddress(const u_char* packet): IPAddress(IP6(packet)->ip6_src.s6_addr) {}

std::list<SrcIPAddress*> SrcIPAddress::genKeys(const u_char* packet) {
	std::list<SrcIPAddress*> li;
    if (IP(packet)->ip_v == 4)
    	li.push_back(new SrcIPAddress(IP(packet)->ip_src.s_addr));
    else
    	li.push_back(new SrcIPAddress(IP6(packet)->ip6_src.s6_addr));
	return li;
}

std::string SrcIPAddress::getStrPkt(const u_char* packet) const
{
	std::stringstream ss;
    
	if (IP(packet)->ip_v == 4)
		{

        unsigned char *ip4 = (unsigned char *)&(IP(packet)->ip_src.s_addr);      

	    ss << " ip "
	    << (ip4[0] & 0xff) << "."
	    << (ip4[1] & 0xff) << "."
	    << (ip4[2] & 0xff) << "."
	    << (ip4[3] & 0xff);
	    return ss.str();
		}
	else
		{   

        tmlog(TM_LOG_NOTE, "SrcIPAddress: getStr(u_char*)", "IPAddress, IPv6");
		char str[INET6_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET6, IP6(packet)->ip6_src.s6_addr, str, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
        {
            ss << "source stuff ip for IPv6"

            << "[" << str << "]";
			return ss.str();
        }
	}
}

void SrcIPAddress::getBPFStr(char *str, int max_str_len) const {
	int rc = snprintf(str, max_str_len, "src host %s", getStr().c_str());
	if ( rc >= max_str_len )
		tmlog(TM_LOG_ERROR, "query",  "SrcIPAddress::getBPFStr: %s truncated by %d characters",
				str, rc-max_str_len);
}


//DstIPAddress::DstIPAddress(const u_char* packet):
//IPAddress(IP(packet)->ip_dst.s_addr) {}

std::list<DstIPAddress*> DstIPAddress::genKeys(const u_char* packet) {
	std::list<DstIPAddress*> li;
    if (IP(packet)->ip_v == 4)
	    li.push_back(new DstIPAddress(IP(packet)->ip_dst.s_addr));
    else
	    li.push_back(new DstIPAddress(IP6(packet)->ip6_dst.s6_addr));
    return li;
}

std::string DstIPAddress::getStrPkt(const u_char* packet) const
{
	std::stringstream ss;
    
	if (IP(packet)->ip_v == 4)
		{
        unsigned char *ip4 = (unsigned char *)&(IP(packet)->ip_dst.s_addr);      

	    ss << " ip "
	    << (ip4[0] & 0xff) << "."
	    << (ip4[1] & 0xff) << "."
	    << (ip4[2] & 0xff) << "."
	    << (ip4[3] & 0xff);
	    return ss.str();
		}
	else
		{   

        tmlog(TM_LOG_NOTE, "DstIPAddress: getStr(u_char*)", "IPAddress, IPv6");
		char str[INET6_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET6, IP6(packet)->ip6_dst.s6_addr, str, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
        {
            ss << "dst stuff ip for IPv6"

            << "[" << str << "]";
			return ss.str();
        }
	}
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

std::string Port::getStrPkt(const u_char* packet) const
{
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

std::string SrcPort::getStrPkt(const u_char* packet) const
{
	std::stringstream ss;
	ss << ntohs(port);
	return ss.str();
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

std::string DstPort::getStrPkt(const u_char* packet) const
{
	std::stringstream ss;
	ss << ntohs(port);
	return ss.str();
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

std::string ConnectionIF4::pattern6_connection4 = "\\s*(\\w+)\\s+"
	+ pattern_ip6port + "\\s+" + pattern_ip6port + "\\s*";

RE2 ConnectionIF4::re(ConnectionIF4::pattern_connection4);

RE2 ConnectionIF4::re6(ConnectionIF4::pattern6_connection4);

std::list<ConnectionIF4*> ConnectionIF4::genKeys(const u_char* packet) {
    // DEBUG DEBUG DEBUG
    //tmlog(TM_LOG_DEBUG, "ConnectionIF4", "getting key for packet. The pattern_connection4 is: %s", pattern_connection4.c_str());
	std::list<ConnectionIF4*> li;
	li.push_back(new ConnectionIF4(packet));
	return li;
}

//FIXME: merge this somehow with ConnectionID4::parse() !!!!
IndexField* ConnectionIF4::parseQuery(const char *query) {
	std::string protostr, src_ip, dst_ip;
	unsigned src_port, dst_port;
	proto_t proto;


	if (!RE2::FullMatch(query, re, &protostr, &src_ip, &src_port, &dst_ip, &dst_port) && !RE2::FullMatch(query, re6, &protostr, &src_ip, &src_port, &dst_ip, &dst_port))
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
		
    if (RE2::FullMatch(query, re, &protostr, &src_ip, &src_port, &dst_ip, &dst_port))
    {
	    return new ConnectionIF4(proto, inet_addr(src_ip.c_str()), htons(src_port),
			    inet_addr(dst_ip.c_str()), htons(dst_port));
    }
    
    else
    {
        unsigned char src_ip6[16];
        unsigned char dst_ip6[16];

        //const char* src_ip6;
        //char* dst_ip6;

        if (inet_pton(AF_INET6, src_ip.c_str(), src_ip6) == 1 && inet_pton(AF_INET6, dst_ip.c_str(), dst_ip6) == 1)
        {
	        return new ConnectionIF4(proto, src_ip6, htons(src_port),
	                dst_ip6, htons(dst_port));
        }
        return NULL;
    }
}

void ConnectionIF4:: ip_to_str(const unsigned char* ip, char *str, int len) const {
//#define UCP(x) ((unsigned char *)&(x))
	str[0] = '\0';
    /*
	snprintf(str, len, "%d.%d.%d.%d",
			 UCP(ip)[0] & 0xff,
			 UCP(ip)[1] & 0xff,
			 UCP(ip)[2] & 0xff,
			 UCP(ip)[3] & 0xff);
    */

    snprintf(str, len, "%s", ip);
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

std::string ConnectionIF3::pattern6_connection3 = "\\s*(\\w+)\\s+"
		+ pattern_ip6 + "\\s+" + pattern_ip6 + ":"
		+ "(\\d+)\\s*";

RE2 ConnectionIF3::re(ConnectionIF3::pattern_connection3);

RE2 ConnectionIF3::re6(ConnectionIF3::pattern_connection3);

std::list<ConnectionIF3*>
ConnectionIF3::genKeys(const u_char* packet) {
	std::list<ConnectionIF3*> li;
    // DEBUG DEBUG DEBUG
    //tmlog(TM_LOG_DEBUG, "ConnectionIF3", "getting key for packet. The pattern_connection3 is: %s", pattern_connection3.c_str());
	li.push_back(new ConnectionIF3(packet, 0));
	li.push_back(new ConnectionIF3(packet, 1));
	return li;
}

IndexField* ConnectionIF3::parseQuery(const char *query) {
	std::string protostr, src_ip, dst_ip;
	unsigned port;
	proto_t proto;
	
	if (!RE2::FullMatch(query, re, &protostr, &src_ip, &dst_ip, &port) && !RE2::FullMatch(query, re6, &protostr, &src_ip, &dst_ip, &port))
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

    if (RE2::FullMatch(query, re, &protostr, &src_ip, &dst_ip, &port))
    {
		return new ConnectionIF3(proto, inet_addr(src_ip.c_str()), 
			    inet_addr(dst_ip.c_str()), htons(port));
    }
    else
    {
        unsigned char src_ip6[16];
        unsigned char dst_ip6[16];

        if (inet_pton(AF_INET6, src_ip.c_str(), src_ip6) == 1 && inet_pton(AF_INET6, dst_ip.c_str(), dst_ip6) == 1)
        {
            return new ConnectionIF3(proto, src_ip6, dst_ip6, htons(port));
        }
        return NULL;
    }
}

void ConnectionIF3:: ip_to_str(const unsigned char* ip, char *str, int len) const {
//#define UCP(x) ((unsigned char *)&(x))
	str[0] = '\0';
    /*
	snprintf(str, len, "%d.%d.%d.%d",
			 UCP(ip)[0] & 0xff,
			 UCP(ip)[1] & 0xff,
			 UCP(ip)[2] & 0xff,
			 UCP(ip)[3] & 0xff);
    */

    snprintf(str, len, "%s", ip);
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

std::string ConnectionIF2::pattern6_connection2 = 
		"\\s*" + pattern_ip6 + "\\s+" + pattern_ip6 + "\\s*";

RE2 ConnectionIF2::re(ConnectionIF2::pattern_connection2);

RE2 ConnectionIF2::re6(ConnectionIF2::pattern6_connection2);

std::list<ConnectionIF2*>
ConnectionIF2::genKeys(const u_char* packet) {
	std::list<ConnectionIF2*> li;
    // DEBUG DEBUG DEBUG
    //tmlog(TM_LOG_DEBUG, "ConnectionIF2", "getting key for packet. The pattern_connection2 is: %s", pattern_connection2.c_str());
	li.push_back(new ConnectionIF2(packet));
	return li;
}


IndexField* ConnectionIF2::parseQuery(const char *query) {
	std::string src_ip, dst_ip;
	
	if (!RE2::FullMatch(query, re, &src_ip, &dst_ip) && !RE2::FullMatch(query, re6, &src_ip, &dst_ip))
		return NULL;

	/*
	fprintf(stderr, "%s\nConnectionIF22:parseQuery:  %s ===> <%s> <%s>\n", 
				pattern_connection2.c_str(), query, src_ip.c_str(), dst_ip.c_str());
	*/

    if (RE2::FullMatch(query, re, &src_ip, &dst_ip))
    {
    	return new ConnectionIF2(inet_addr(src_ip.c_str()), inet_addr(dst_ip.c_str()));
    }
    else
    {
        unsigned char src_ip6[16];
        unsigned char dst_ip6[16];

        if (inet_pton(AF_INET6, src_ip.c_str(), src_ip6) == 1 && inet_pton(AF_INET6, dst_ip.c_str(), dst_ip6) == 1)
        {
            return new ConnectionIF2(src_ip6, dst_ip6);
        }
        return NULL;
    }
}

void ConnectionIF2:: ip_to_str(const unsigned char* ip, char *str, int len) const {
//#define UCP(x) ((unsigned char *)&(x))
	str[0] = '\0';
    /*
	snprintf(str, len, "%d.%d.%d.%d",
			 UCP(ip)[0] & 0xff,
			 UCP(ip)[1] & 0xff,
			 UCP(ip)[2] & 0xff,
			 UCP(ip)[3] & 0xff);
    */

    snprintf(str, len, "%s", ip);
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
