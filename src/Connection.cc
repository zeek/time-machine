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

#include "bro_inet_ntop.h"

#ifdef __FreeBSD__
#include <sys/socket.h>
#endif


static std::string pattern_ip ("(\\d+\\.\\d+\\.\\d+\\.\\d+)");
static std::string pattern_ipport ("(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)");

static std::string pattern_ip6 ("\\[((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\]");
// stolen from stackoverflow http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses

//static std::string pattern_ip6 ("\\[([0-9a-fA-F]{1,4}:{7,7}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:{1,7}:|[0-9a-fA-F]{1,4}:{1,6}:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:{1,5}:[0-9a-fA-F]{1,4}{1,2}|[0-9a-fA-F]{1,4}:{1,4}:[0-9a-fA-F]{1,4}{1,3}|[0-9a-fA-F]{1,4}:{1,3}:[0-9a-fA-F]{1,4}{1,4}|[0-9a-fA-F]{1,4}:{1,2}:[0-9a-fA-F]{1,4}{1,5}|[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}{1,6}|::[0-9a-fA-F]{1,4}{1,7}|:|fe80::[0-9a-fA-F]{0,4}{0,4}%[0-9a-zA-Z]{1,}|::ffff:0{1,4}{0,1}:{0,1}25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9].{3,3}25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9]|[0-9a-fA-F]{1,4}:{1,4}:25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9].{3,3}25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9])\\]");

static std::string pattern_ip6port ("\\[((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\]:(\\d+)");
//static std::string pattern_ip6port ("\\[([0-9a-fA-F]{1,4}:{7,7}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:{1,7}:|[0-9a-fA-F]{1,4}:{1,6}:[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}:{1,5}:[0-9a-fA-F]{1,4}{1,2}|[0-9a-fA-F]{1,4}:{1,4}:[0-9a-fA-F]{1,4}{1,3}|[0-9a-fA-F]{1,4}:{1,3}:[0-9a-fA-F]{1,4}{1,4}|[0-9a-fA-F]{1,4}:{1,2}:[0-9a-fA-F]{1,4}{1,5}|[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}{1,6}|::[0-9a-fA-F]{1,4}{1,7}|:|fe80::[0-9a-fA-F]{0,4}{0,4}%[0-9a-zA-Z]{1,}|::ffff:0{1,4}{0,1}:{0,1}25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9].{3,3}25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9]|[0-9a-fA-F]{1,4}:{1,4}:25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9].{3,3}25[0-5]|2[0-4]|1{0,1}[0-9]{0,1}[0-9])\\]:(\\d+)");
// stolen from stackoverflow http://stackoverflow.com/questions/53497/regular-expression-that-

/*
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
*/

inline bool addr_port_canon_lt(uint32_t s_ip, uint32_t d_ip,
							   uint16_t s_port, uint16_t d_port) {
	if (s_ip == d_ip)
		return (s_port < d_port);
	else
		return (s_ip < d_ip);
}

inline bool addr6_port_canon_lt(const unsigned char s6_ip[], const unsigned char d6_ip[],
                                uint16_t s_port, uint16_t d_port) {
	if (!(memcmp(s6_ip, d6_ip, 16)))
		return (s_port < d_port);
	else
		return (memcmp(s6_ip, d6_ip, 16) < 0);
}



void ConnectionID4::init(proto_t proto4,
						 uint32_t s_ip, uint32_t d_ip,
						 uint16_t s_port, uint16_t d_port) {
    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_NOTE, "connection 4: Connection.cc, ~line 48", "connection 4 for ipv4 initialized");

    //in4_addr ipv4_d_address;
    //in4_addr ipv4_s_address;

    v6.version = 4;
	v6.proto=proto4;

    static uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr


    //ipv4_d_address.s_addr = d_ip;
    //ipv4_s_address.s_addr = s_ip;

	if (addr_port_canon_lt(s_ip,d_ip,s_port,d_port)) {
		//    v.is_canonified=true;

        // setting v6.ip1 to be  destination address and v6.ip2 to be source address
        //key.ip1.s6_tm_addr = &v4_mapped_prefix[0];
        //char *

        memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip1.s6_addr[12], &d_ip, sizeof(d_ip));

        memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip2.s6_addr[12], &s_ip, sizeof(s_ip));

        v6.ip1 = d_ip;
        v6.ip2 = s_ip;

        /*
        IPAddr(ipv4_d_address);

        //memcpy(in6.s6_addr, v6.ip1, 16);

		//v6.ip1=in6.s6_addr;

        IPAddr(ipv4_s_address);

        //memcpy(in6.s6_addr, v6.ip2, 16);

		//v6.ip2=in6.s6_addr;
        */

		//v6.port1=d_port;
		//v6.port2=s_port;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
 
        // setting s6_ip to be source address and d6_ip to be dest address       
        //memcpy(s6_ip.s6_addr, v6.ip2, 16);
        //memcpy(d6_ip.s6_addr, v6.ip1, 16);

        //key.ip1 = s6_ip;
        //key.ip2 = d6_ip;
        key.port1 = s_port;
        key.port2 = d_port;

	} 
    else {
		//    v.is_canonified=false;

        // setting v6.ip1 to be source address and v6.ip2 to be destination address

        memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip1.s6_addr[12], &s_ip, sizeof(s_ip));

        memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip2.s6_addr[12], &d_ip, sizeof(d_ip));

        v6.ip1 = s_ip;
        v6.ip2 = d_ip;

        /*
        IPAddr(ipv4_s_address);

        //memcpy(in6.s6_addr, v6.ip1, 16);

		//v6.ip1=in6.s6_addr;

        IPAddr(ipv4_d_address);

        //memcpy(in6.s6_addr, v6.ip2, 16);

		//v6.ip2=in6.s6_addr;
        */        
        
		//v6.port1=s_port;
		//v6.port2=d_port;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
        
        //memcpy(s6_ip.s6_addr, v6.ip1, 16);
        //memcpy(d6_ip.s6_addr, v6.ip2, 16);

	    //key.ip1 = d6_ip;
	    //key.ip2 = s6_ip;
	    key.port1 = d_port;
	    key.port2 = s_port;
	}

    //tmlog(TM_LOG_NOTE, "connection4: Connection.cc", "connection 4 with form %s", getStr().c_str());

    //init_hash_function();

    //HashKey* newHashKey = new HashKey(&key, sizeof(key));

    //tmlog(TM_LOG_NOTE, "ConnectionID4::hash()", "the hash of newhashkey is %u", newHashKey->Hash());

    //HashKey* newHashKeyDos = new HashKey(&key, sizeof(key));

    //tmlog(TM_LOG_NOTE, "ConnectionID4::hash()", "the second hash of newhashkeydos is %u", newHashKeyDos->Hash());

    //memcpy(&hash_key, newHashKey->Hash(), 8);

    hash_key = HashKey::HashBytes(&key, sizeof(key)); //newHashKey->Hash();

    //delete newHashKey;

    //free_hash_function();
}

void ConnectionID4::init6(proto_t proto6,
                  unsigned char s_ip[], unsigned char d_ip[],
                  uint16_t s_port, uint16_t d_port) {
    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_NOTE, "connection 4: Connection.cc, ~line 48", "connection 4 for ipv6 initialized");

    v6.version = 6;
	v6.proto=proto6;

	// Lookup up connection based on canonical ordering, which is
	// the smaller of <src addr, src port> and <dst addr, dst port>
	// followed by the other.
	if (addr6_port_canon_lt(s_ip,d_ip,s_port,d_port)) {
		//    v6.is_canonified=true;
        // memcpy(destination, source, size)
        memcpy(key.ip1.s6_addr, d_ip, 16);
        memcpy(key.ip2.s6_addr, s_ip, 16);
		//v6.ip1=d_ip;
		//v6.ip2=s_ip;
		//v6.port1=d_port;
		//v6.port2=s_port;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
        
        //memcpy(s6_ip.s6_addr, s_ip, 16);
        //memcpy(d6_ip.s6_addr, d_ip, 16);

        //key.ip1 = s6_ip;
        //key.ip2 = d6_ip;
        key.port1 = s_port;
        key.port2 = d_port;

	} else {
		//    v6.is_canonified=false;
        memcpy(key.ip1.s6_addr, s_ip, 16);
        memcpy(key.ip2.s6_addr, d_ip, 16);
		//v6.ip1=s_ip;
		//v6.ip2=d_ip;
		//v6.port1=s_port;
		//v6.port2=d_port;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
        
        //memcpy(s6_ip.s6_addr, s_ip, 16);
        //memcpy(d6_ip.s6_addr, d_ip, 16);

	    //key.ip1 = d6_ip;
	    //key.ip2 = s6_ip;
	    key.port1 = d_port;
	    key.port2 = s_port;
	}
    //tmlog(TM_LOG_NOTE, "connection4: Connection.cc", "connection 4 with form %s", getStr().c_str());

    //init_hash_function();

    //HashKey* newHashKey = new HashKey(&key, sizeof(key));

    //tmlog(TM_LOG_NOTE, "ConnectionID4::hash()", "the hash of newhashkey is %u", newHashKey->Hash());

    //HashKey* newHashKeyDos = new HashKey(&key, sizeof(key));

    //tmlog(TM_LOG_NOTE, "ConnectionID4::hash()", "the second hash of newhashkeydos is %u", newHashKeyDos->Hash());

    //memcpy(&hash_key, newHashKey->Hash(), 8);

    hash_key = HashKey::HashBytes(&key, sizeof(key));

    //delete newHashKey;

    //free_hash_function();
}

void ConnectionID3::init(proto_t proto4,
						 uint32_t ip1, uint32_t ip2,
						 uint16_t port2) {

    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_DEBUG, "connection 3: Connection.cc, ~line 71", "connection 3 initialized");

    //in4_addr ipv4_d_address;
    //in4_addr ipv4_s_address;

    v6.version = 4;

	v6.proto=proto4;

    static uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
    
    //ipv4_s_address.s_addr = ip1;
    //ipv4_d_address.s_addr = ip2;

    /*
    IPAddr(ipv4_s_address);

    //memcpy(in6.s6_addr, v6.ip1, 16);

    IPAddr(ipv4_d_address);

    //memcpy(in6.s6_addr, v6.ip2, 16);

    */

    memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
    memcpy(&key.ip1.s6_addr[12], &ip1, sizeof(ip1));

    memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
    memcpy(&key.ip2.s6_addr[12], &ip2, sizeof(ip2));

    v6.ip1 = ip1;
    v6.ip2 = ip2;

	//key.port2=port2;

    /*	
	// Lookup up connection based on canonical ordering, which is
	// the smaller of <src addr, src port> and <dst addr, dst port>
	// followed by the other.
	if (addr6_port_canon_lt(v6.ip1, v6.ip2, 0, v6.port2))
		{
            in6_addr s6_ip;
            in6_addr d6_ip;
            
            //memcpy(s6_ip.s6_addr, v6.ip1, 16);
            //memcpy(d6_ip.s6_addr, v6.ip2, 16);

		    key.ip1 = s6_ip;
		    key.ip2 = d6_ip;
		    key.port1 = 0;
		    key.port2 = v6.port2;
		}
	else
		{
            in6_addr s6_ip;
            in6_addr d6_ip;
            
            //memcpy(s6_ip.s6_addr, v6.ip1, 16);
            //memcpy(d6_ip.s6_addr, v6.ip2, 16);

		    key.ip1 = d6_ip;
		    key.ip2 = s6_ip;
		    key.port1 = v6.port2;
		    key.port2 = 0;
		}
	*/

        //in6_addr s6_ip;
        //in6_addr d6_ip;

        //memcpy(s6_ip.s6_addr, v6.ip1, 16);
        //memcpy(d6_ip.s6_addr, v6.ip2, 16);

        //key.ip1 = d6_ip;
        //key.ip2 = s6_ip;
        key.port1 = 0;
        key.port2 = port2;

    //init_hash_function();

    //HashKey* newHashKey = new HashKey(&key, sizeof(key));

    //hash_key = newHashKey->Hash();

	hash_key = HashKey::HashBytes(&key, sizeof(key));//newHashKey->Hash();

    //delete newHashKey;

    //free_hash_function();
}

void ConnectionID3::init6(proto_t proto6,
						 unsigned char ip1[], unsigned char ip2[],
						 uint16_t port2) {

    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_DEBUG, "connection 3: Connection.cc, ~line 71", "connection 3 initialized");

	v6.proto=proto6;

    v6.version = 6;

    // memcpy(destination, source, size)
    // setting v6.ip1 to be source address and v6.ip2 to be destination address 
    memcpy(key.ip1.s6_addr, ip1, 16);
    memcpy(key.ip2.s6_addr, ip2, 16);

	//v.ip1=ip1;
	//v.ip2=ip2;
	//key.port2=port2;

	/*
	// Lookup up connection based on canonical ordering, which is
	// the smaller of <src addr, src port> and <dst addr, dst port>
	// followed by the other.
	if (addr6_port_canon_lt(v6.ip1, v6.ip2, 0, v6.port2))
		{
            in6_addr s6_ip;
            in6_addr d6_ip;
    
            // setting s6_ip to have source address and d6_ip to have dest address        
            //memcpy(s6_ip.s6_addr, ip1, 16);
            //memcpy(d6_ip.s6_addr, ip2, 16);

            // setting key.ip1 to be source address and key.ip2 to be dest address 
		    key.ip1 = s6_ip;
		    key.ip2 = d6_ip;
		    key.port1 = 0;
		    key.port2 = v6.port2;
		}
	else
		{
            in6_addr s6_ip;
            in6_addr d6_ip;
        
            // setting s6_ip to have source address and d6_ip to have dest address    
            //memcpy(s6_ip.s6_addr, ip1, 16);
            //memcpy(d6_ip.s6_addr, ip2, 16);

            // setting key.ip1 to be dest address and key.ip2 to be source address
		    key.ip1 = d6_ip;
		    key.ip2 = s6_ip;
		    key.port1 = v6.port2;
		    key.port2 = 0;
		}
	*/
		
        //in6_addr s6_ip;
        //in6_addr d6_ip;
    
        // setting s6_ip to have source address and d6_ip to have dest address
        //memcpy(s6_ip.s6_addr, ip1, 16);
        //memcpy(d6_ip.s6_addr, ip2, 16);

        // setting key.ip1 to be dest address and key.ip2 to be source address
        //key.ip1 = d6_ip;
        //key.ip2 = s6_ip;
        key.port1 = 0;
        key.port2 = port2;
	

    //init_hash_function();

    //HashKey* newHashKey = new HashKey(&key, sizeof(key));

    //hash_key = newHashKey->Hash();

	hash_key = HashKey::HashBytes(&key, sizeof(key)); //newHashKey->Hash();

    //delete newHashKey;

    //free_hash_function();
}

void ConnectionID2::init( uint32_t s_ip, uint32_t d_ip) {

    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_DEBUG, "connection 2: Connection.cc, ~line 82", "connection 2 initialized");

    v6.version = 4;

    static uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr

    //in4_addr ipv4_d_address;
    //in4_addr ipv4_s_address;

    //ipv4_s_address.s_addr = s_ip;
    //ipv4_d_address.s_addr = d_ip;

	if (addr_port_canon_lt(s_ip,d_ip,0,0)) {
		//    v.is_canonified=true;
        /*
        ConnectionID4 ipv4_addr = ConnectionID4(ipv4_d_address);
        //memcpy(v6.ip1, in6.s6_addr, 16);

        IPAddr(ipv4_s_address);
        //memcpy(in6.s6_addr, v6.ip2, 16);
        */

        // setting v6.ip1 to dest address and v6.ip2 to source address

        memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip1.s6_addr[12], &d_ip, sizeof(d_ip));

        memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip2.s6_addr[12], &s_ip, sizeof(s_ip));

        v6.ip1 = d_ip;
        v6.ip2 = s_ip;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
 
        // setting s6_ip to be source address and d6_ip to be dest address       
        //memcpy(s6_ip.s6_addr, v6.ip2, 16);
        //memcpy(d6_ip.s6_addr, v6.ip1, 16);

        // setting key.ip1 to be source address and key.ip2 to be dest address
	    //key.ip1 = s6_ip;
	    //key.ip2 = d6_ip;
	    key.port1 = 0;
	    key.port2 = 0;

	} else {
		//    v.is_canonified=false;
        /*
        IPAddr(ipv4_s_address);
        //memcpy(in6.s6_addr, v6.ip1, 16);

        IPAddr(ipv4_d_address);
        //memcpy(in6.s6_addr, v6.ip2, 16);
        */

        // setting v6.ip1 to be source address and v6.ip2 to be dest address

        memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip1.s6_addr[12], &s_ip, sizeof(s_ip));

        memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        memcpy(&key.ip2.s6_addr[12], &d_ip, sizeof(d_ip));

        v6.ip1 = s_ip;
        v6.ip2 = d_ip;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
 
        // ssetting s6_ip to be source address and d6_ip to be dest address    
        //memcpy(s6_ip.s6_addr, v6.ip1, 16); 
        //memcpy(d6_ip.s6_addr, v6.ip2, 16);

        // setting key.ip1 to be dest address and key.ip2 to be source address
	    //key.ip1 = d6_ip;
	    //key.ip2 = s6_ip;
	    key.port1 = 0;
	    key.port2 = 0;
	}

    //init_hash_function();

    //HashKey* newHashKey = new HashKey(&key, sizeof(key));

    //hash_key = newHashKey->Hash();

	hash_key = HashKey::HashBytes(&key, sizeof(key)); //newHashKey->Hash();

    //delete newHashKey;

    //free_hash_function();
}

void ConnectionID2::init6( unsigned char s_ip[], unsigned char d_ip[]) {

    // DEBUG DEBUG DEBUG
	//tmlog(TM_LOG_DEBUG, "connection 2: Connection.cc, ~line 82", "connection 2 initialized");

    v6.version = 6;

	if (addr6_port_canon_lt(s_ip,d_ip,0,0)) {
		//    v.is_canonified=true;
        // memcpy(destination, source, size)
        memcpy(key.ip1.s6_addr, d_ip, 16);
        memcpy(key.ip2.s6_addr, s_ip, 16);

		//v6.ip1=d_ip;
		//v6.ip2=s_ip;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
        
        //memcpy(s6_ip.s6_addr, s_ip, 16);
        //memcpy(d6_ip.s6_addr, d_ip, 16);

	    //key.ip1 = d6_ip;
	    //key.ip2 = s6_ip;
	    key.port1 = 0;
	    key.port2 = 0;

	} else {
		//    v.is_canonified=false;
        memcpy(key.ip1.s6_addr, s_ip, 16);
        memcpy(key.ip2.s6_addr, d_ip, 16);
		//v.ip1=s_ip;
		//v.ip2=d_ip;

        // this is for the hash key
        //in6_addr s6_ip;
        //in6_addr d6_ip;
        
        //memcpy(s6_ip.s6_addr, s_ip, 16);
        //memcpy(d6_ip.s6_addr, d_ip, 16);

	    //key.ip1 = s6_ip;
	    //key.ip2 = d6_ip;
	    key.port1 = 0;
	    key.port2 = 0;
	}

    //char str_test1[INET6_ADDRSTRLEN];
    //char str_test2[INET6_ADDRSTRLEN];

    // now get it back and print it
    //inet_ntop(AF_INET6, &(key.ip1), str_test1, INET6_ADDRSTRLEN);

    //inet_ntop(AF_INET6, &(key.ip2), str_test2, INET6_ADDRSTRLEN);

    //printf("testing 1 ... %s\n", str_test1); // prints "2001:db8:8714:3a90::12"
    //printf("testing 2 ... %s\n", str_test2);

    //init_hash_function();

    //HashKey* newHashKey = new HashKey(&key, sizeof(key));

    //hash_key = newHashKey->Hash();

	hash_key = HashKey::HashBytes(&key, sizeof(key)); //newHashKey->Hash();

    //delete newHashKey;

    //free_hash_function();
}


ConnectionID4::ConnectionID4(const u_char* packet) {

    //tmlog(TM_LOG_NOTE, "Connection.cc", "Some Packet with some ip addresses");


    if (IP(packet)->ip_v != 4 && IP6(packet)->ip6_ctlun.ip6_un2_vfc >> 4 != 6)
    {
        // This should never happen
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "Neither IPv4 nor IPv6");
        return;
    }

    else if (IP(packet)->ip_v == 4)
    {
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "IPv4");
        // check the protocol
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

    else
    {
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "IPv6");

        //unsigned char src_ip6[16];
        //unsigned char dst_ip6[16];

        //memcpy(src_ip6, IP6(packet)->ip6_src.s6_addr, 16);
        //memcpy(dst_ip6, IP6(packet)->ip6_dst.s6_addr, 16);

        // check the protocol
	    switch (IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
	    case IPPROTO_UDP:
            //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "UDP IPv6");
		    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
			     IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr,
			     UDP6(packet)->uh_sport, UDP6(packet)->uh_dport);
		    break;
	    case IPPROTO_TCP:
            //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "TCP IPv6");
		    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
			     IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr,
			     TCP6(packet)->th_sport, TCP6(packet)->th_dport);
		    break;
	    default:
            //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "default IPv6");
		    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
			     IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr,
			     0, 0);
		    break;
	    }
    }
}


ConnectionID3::ConnectionID3(const u_char* packet,
							 int wildcard_port) {

    if (IP(packet)->ip_v != 4 && IP6(packet)->ip6_ctlun.ip6_un2_vfc >> 4 != 6)
    {
        // This should never happen
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID3", "Neither IPv4 nor IPv6");
        return;
    }

    else if (IP(packet)->ip_v == 4)
    {
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID3", "IPv4");

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

    else
    {
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID3", "IPv6 with version %d", IP6(packet)->ip6_ctlun.ip6_un2_vfc >> 4);
	    switch (IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
	    case IPPROTO_UDP:
            //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "UDP IPv6");
		    if (wildcard_port) 
			    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
				     IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr,
				     UDP6(packet)->uh_dport);
		    else
			    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
				     IP6(packet)->ip6_dst.s6_addr, IP6(packet)->ip6_src.s6_addr,
				     UDP6(packet)->uh_sport);
		    break;
	    case IPPROTO_TCP:
            //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "TCP IPv6");
		    if (wildcard_port) 
			    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
				     IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr,
				     TCP6(packet)->th_dport);
		    else
			    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
				     IP6(packet)->ip6_dst.s6_addr, IP6(packet)->ip6_src.s6_addr,
				     TCP6(packet)->th_sport);
		    break;
	    default:
            //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID4", "default IPv6");
		    if (wildcard_port) 
			    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
				     IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr,
				     0);
		    else
			    init6(IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_nxt,
				     IP6(packet)->ip6_dst.s6_addr, IP6(packet)->ip6_src.s6_addr,
				     0);
		    break;
        }
    }
}


ConnectionID2::ConnectionID2(const u_char* packet) {

    if (IP(packet)->ip_v != 4 && IP6(packet)->ip6_ctlun.ip6_un2_vfc >> 4 != 6)
    {
        // This should never happen
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID2", "Neither IPv4 nor IPv6");
        return;
    }

    else if (IP(packet)->ip_v == 4)
    {
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID2", "IPv4");
    	init(IP(packet)->ip_src.s_addr, IP(packet)->ip_dst.s_addr);
    }

    else
    {
        //tmlog(TM_LOG_NOTE, "Connection.cc: ConnectionID3", "IPv6");
        //printf("the source address is %s, and the dest address is %s\n", IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr);
    	init6(IP6(packet)->ip6_src.s6_addr, IP6(packet)->ip6_dst.s6_addr);
    }
}


//TODO: MAke this inline (i.e. move to Connection.hh so that it is
//consistent with ConnectionID4
bool ConnectionID3::operator==(const ConnectionID& other) const {
/*
        return equal(key.ip1.s6_addr, ((ConnectionID3*)&other)->key.ip2.s6_addr)
               && equal(key.ip2.s6_addr, ((ConnectionID3*)&other)->key.ip2.s6_addr)
               && (key.port2 == ((ConnectionID3*)&other)->key.port2)
               && (v6.proto == ((ConnectionID3*)&other)->v6.proto);
*/
    if (v6.version == 4 && ((ConnectionID3*)&other)->v6.version == 4)
    {
        return (v6.ip1 == ((ConnectionID3*)&other)->v6.ip1)
               && (v6.ip2 == ((ConnectionID3*)&other)->v6.ip2)
               && (key.port2 == ((ConnectionID3*)&other)->key.port2)
               && (v6.proto == ((ConnectionID3*)&other)->v6.proto);
    }
    else if (v6.version == 6 && ((ConnectionID3*)&other)->v6.version == 6)
    {
        return (!memcmp(&key.ip1, &((ConnectionID3*)&other)->key.ip1, 16))
               && (!memcmp(&key.ip2, &((ConnectionID3*)&other)->key.ip2, 16))
               && (key.port2 == ((ConnectionID3*)&other)->key.port2)
               && (v6.proto == ((ConnectionID3*)&other)->v6.proto);
    }
    else
        return false;
}

//TODO: MAke this inline (i.e. move to Connection.hh so that it is
//consistent with ConnectionID4
bool ConnectionID2::operator==(const ConnectionID& other) const {
/*
        //return equal(key.ip1.s6_addr, ((ConnectionID2*)&other)->key.ip2.s6_addr)
               //&& equal(key.ip2.s6_addr, ((ConnectionID2*)&other)->key.ip2.s6_addr);
*/
    if (v6.version == 4 && ((ConnectionID3*)&other)->v6.version == 4)
    {
        return (v6.ip1 == ((ConnectionID3*)&other)->v6.ip1)
               && (v6.ip2 == ((ConnectionID3*)&other)->v6.ip2);   
    }
    else if (v6.version == 6 && ((ConnectionID3*)&other)->v6.version == 6)
    {
        return (!memcmp(&key.ip1, &((ConnectionID2*)&other)->key.ip1, sizeof(in6_addr)))
               && (!memcmp(&key.ip2, &((ConnectionID2*)&other)->key.ip2, sizeof(in6_addr)));
    }
    else
        return false;
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
#define UCP(x) ((unsigned char *)&x)

	std::stringstream ss;
/*
    uint32_t s_ip=v.ip1; //get_s_ip();
    uint32_t d_ip=v.ip2; //get_d_ip();

    ss << " ConnectionID4 "
    
     //<< " Proto " << 0+get_proto()
     //<< " canonified " << get_is_canonified() << " "
    
    << (UCP(s_ip)[0] & 0xff) << "."
    << (UCP(s_ip)[1] & 0xff) << "."
    << (UCP(s_ip)[2] & 0xff) << "."
    << (UCP(s_ip)[3] & 0xff)
    << ":"
    << ntohs(get_port1())
    << " - "
    << (UCP(d_ip)[0] & 0xff) << "."
    << (UCP(d_ip)[1] & 0xff) << "."
    << (UCP(d_ip)[2] & 0xff) << "."
    << (UCP(d_ip)[3] & 0xff)
    << ":"
    << ntohs(get_port2());
    return ss.str();
*/

    if (v6.version == 4)
    {
	    //uint32_t s_ip=v.ip1; //get_s_ip();
	    //uint32_t d_ip=v.ip2; //get_d_ip();

        //unsigned char s_ip[16];
        //unsigned char d_ip[16];

        //memcpy(s_ip, key.ip1.s6_addr, 16);
        //memcpy(d_ip, key.ip2.s6_addr, 16);

	    ss << " ConnectionID4 "
	    
	     //<< " Proto " << 0+get_proto()
	     //<< " canonified " << get_is_canonified() << " "
	   
/* 
	    << (UCP(s_ip)[0] & 0xff) << "."
	    << (UCP(s_ip)[1] & 0xff) << "."
	    << (UCP(s_ip)[2] & 0xff) << "."
	    << (UCP(s_ip)[3] & 0xff)
	    << ":"
	    << ntohs(get_port1())
	    << " - "
	    << (UCP(d_ip)[0] & 0xff) << "."
	    << (UCP(d_ip)[1] & 0xff) << "."
	    << (UCP(d_ip)[2] & 0xff) << "."
	    << (UCP(d_ip)[3] & 0xff)
	    << ":"
*/
        << (UCP(key.ip1.s6_addr)[12] & 0xff) << "."
        << (UCP(key.ip1.s6_addr)[13] & 0xff) << "."
        << (UCP(key.ip1.s6_addr)[14] & 0xff) << "."
        << (UCP(key.ip1.s6_addr)[15] & 0xff)
        << ":"
        << ntohs(get_port1())
        << " - "
        << (UCP(key.ip2.s6_addr)[12] & 0xff) << "."
        << (UCP(key.ip2.s6_addr)[13] & 0xff) << "."
        << (UCP(key.ip2.s6_addr)[14] & 0xff) << "."
        << (UCP(key.ip2.s6_addr)[15] & 0xff)
        << ":"


	    << ntohs(get_port2());
	    return ss.str();
        }
    else if (v6.version == 6)
    {
        // use v6.ip1 and v6.ip2
        //unsigned char s6_ip[16]; = v6.ip1;
        //unsigned char d6_ip[16]; = v6.ip2;

        //unsigned char s_ip[16];
        //unsigned char d_ip[16];

        //memcpy(v6.ip1, s_ip, 16);
        //memcpy(v6.ip2, d6_ip, 16);

        // I already put v6.ip1 and v6.ip2 in there

        char str1[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &key.ip1, str1, INET6_ADDRSTRLEN);

        char str2[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &key.ip2, str2, INET6_ADDRSTRLEN);


        ss << " ConnectionID4 for IPv6"

        << "[" << str1 << "]"
        << ":"
        << ntohs(get_port1())
        << "-"
        << "[" << str2 << "]"
        << ":"
        << ntohs(get_port2());
        return ss.str();
    }
    else
    {
        ss << "";
        return ss.str();
    }

}


std::string ConnectionID3::getStr() const {
#define UCP(x) ((unsigned char *)&x)

	std::stringstream ss;

	//uint32_t s_ip=get_ip1();//get_s_ip();
	//uint32_t d_ip=get_ip2();//get_d_ip();

    if (v6.version == 4)
    {

        //unsigned char s_ip[16];
        //unsigned char d_ip[16];

        //memcpy(s_ip, key.ip1.s6_addr, 16);
        //memcpy(d_ip, key.ip2.s6_addr, 16);

	    ss << " ConnectionID3 "
	    << (UCP(key.ip1.s6_addr)[12] & 0xff) << "."
	    << (UCP(key.ip1.s6_addr)[13] & 0xff) << "."
	    << (UCP(key.ip1.s6_addr)[14] & 0xff) << "."
	    << (UCP(key.ip1.s6_addr)[15] & 0xff)
	    << " - "
	    << (UCP(key.ip2.s6_addr)[12] & 0xff) << "."
	    << (UCP(key.ip2.s6_addr)[13] & 0xff) << "."
	    << (UCP(key.ip2.s6_addr)[14] & 0xff) << "."
	    << (UCP(key.ip2.s6_addr)[15] & 0xff)
	    << ":"
	    << get_port();
	    return ss.str();
    }

    else if (v6.version == 6)
    {
        // use v6.ip1 and v6.ip2
        //unsigned char s6_ip[16]; = v6.ip1;
        //unsigned char d6_ip[16]; = v6.ip2;

        //unsigned char s_ip[16];
        //unsigned char d_ip[16];

        //memcpy(v6.ip1, s_ip, 16);
        //memcpy(v6.ip2, d6_ip, 16);

        // I already put v6.ip1 and v6.ip2 in there

        char str1[INET6_ADDRSTRLEN];

        bro_inet_ntop(AF_INET6, &(key.ip1), str1, INET6_ADDRSTRLEN);

        char str2[INET6_ADDRSTRLEN];

        bro_inet_ntop(AF_INET6, &(key.ip2), str2, INET6_ADDRSTRLEN);

        ss << " ConnectionID3 for IPv6"

        << "[" << str1 << "]"
        << "-"
        << "[" << str2 << "]"
        << ":"
        << ntohs(get_port());

/*
        << "[" << (UCP(v6.ip1)[0] & 0xffff) << ":"
        << (UCP(v6.ip1)[1] & 0xffff) << ":"
        << (UCP(v6.ip1)[2] & 0xffff) << ":"
        << (UCP(v6.ip1)[3] & 0xffff) << ":" 
        << (UCP(v6.ip1)[4] & 0xffff) << ":" 
        << (UCP(v6.ip1)[5] & 0xffff) << ":" 
        << (UCP(v6.ip1)[6] & 0xffff) << ":" 
        << (UCP(v6.ip1)[7] & 0xffff) << "]"
        << " - "
        << "[" << (UCP(v6.ip2)[0] & 0xffff) << ":"
        << (UCP(v6.ip2)[1] & 0xffff) << ":"
        << (UCP(v6.ip2)[2] & 0xffff) << ":"
        << (UCP(v6.ip2)[3] & 0xffff) << ":" 
        << (UCP(v6.ip2)[4] & 0xffff) << ":" 
        << (UCP(v6.ip2)[5] & 0xffff) << ":" 
        << (UCP(v6.ip2)[6] & 0xffff) << ":" 
        << (UCP(v6.ip2)[7] & 0xffff) << "]"
        << ":"
        << ntohs(get_port());
*/

        return ss.str();
    }

    else
    {
        ss << "";
        return ss.str();
    }
}

std::string ConnectionID2::getStr() const {
#define UCP(x) ((unsigned char *)&x)

	std::stringstream ss;

	//uint32_t s_ip=get_ip1();//get_s_ip();
	//uint32_t d_ip=get_ip2();//get_d_ip();

    if (v6.version == 4)
    {

        //unsigned char s_ip[16];
        //unsigned char d_ip[16];

        //memcpy(s_ip, key.ip1.s6_addr, 16);
        //memcpy(d_ip, key.ip2.s6_addr, 16);

	    ss << " ConnectionID2 "
	    << (UCP(key.ip1.s6_addr)[12] & 0xff) << "."
	    << (UCP(key.ip1.s6_addr)[13] & 0xff) << "."
	    << (UCP(key.ip1.s6_addr)[14] & 0xff) << "."
	    << (UCP(key.ip1.s6_addr)[15] & 0xff)
	    << " - "
	    << (UCP(key.ip2.s6_addr)[12] & 0xff) << "."
	    << (UCP(key.ip2.s6_addr)[13] & 0xff) << "."
	    << (UCP(key.ip2.s6_addr)[14] & 0xff) << "."
	    << (UCP(key.ip2.s6_addr)[15] & 0xff);
	    return ss.str();
    }

    else if (v6.version == 6)
    {
        // use v6.ip1 and v6.ip2
        //unsigned char s6_ip[16]; = v6.ip1;
        //unsigned char d6_ip[16]; = v6.ip2;

        //unsigned char s_ip[16];
        //unsigned char d_ip[16];

        //memcpy(v6.ip1, s_ip, 16);
        //memcpy(v6.ip2, d6_ip, 16);

        // I already put v6.ip1 and v6.ip2 in there

        //struct sockaddr_in6 sa;
        //char str_test[INET6_ADDRSTRLEN];

        // store this IP address in sa:
        //inet_pton(AF_INET6, "fe80::213:faff:fe03:c11e", &(sa.sin6_addr));

        // now get it back and print it
        //inet_ntop(AF_INET6, &(sa.sin6_addr), str_test, INET6_ADDRSTRLEN);

        //printf("testing ... %s\n", str_test); // prints "2001:db8:8714:3a90::12"


        char str1[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(key.ip1), str1, INET6_ADDRSTRLEN);

        char str2[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(key.ip2), str2, INET6_ADDRSTRLEN);

        ss << " ConnectionID2 for IPv6"

        << "[" << str1 << "]"
        << "-"
        << "[" << str2 << "]";

/*
        << "[" << (UCP(v6.ip1)[0] & 0xffff) << ":"
        << (UCP(v6.ip1)[1] & 0xffff) << ":"
        << (UCP(v6.ip1)[2] & 0xffff) << ":"
        << (UCP(v6.ip1)[3] & 0xffff) << ":" 
        << (UCP(v6.ip1)[4] & 0xffff) << ":" 
        << (UCP(v6.ip1)[5] & 0xffff) << ":" 
        << (UCP(v6.ip1)[6] & 0xffff) << ":" 
        << (UCP(v6.ip1)[7] & 0xffff) << "]"
        << " - "
        << "[" << (UCP(v6.ip2)[0] & 0xffff) << ":"
        << (UCP(v6.ip2)[1] & 0xffff) << ":"
        << (UCP(v6.ip2)[2] & 0xffff) << ":"
        << (UCP(v6.ip2)[3] & 0xffff) << ":" 
        << (UCP(v6.ip2)[4] & 0xffff) << ":" 
        << (UCP(v6.ip2)[5] & 0xffff) << ":" 
        << (UCP(v6.ip2)[6] & 0xffff) << ":" 
        << (UCP(v6.ip2)[7] & 0xffff) << "]";
*/

        return ss.str();
    }

    else
    {
        ss << "";
        return ss.str();
    }
}

hash_t ConnectionID4::hash() const
	{
	    return hash_key;
	}

hash_t ConnectionID3::hash() const
	{
        return hash_key;
	}

hash_t ConnectionID2::hash() const
	{
        return hash_key;
	}

// Static Member initialization
std::string ConnectionID4::pattern_connection4 = "\\s*(\\w+)\\s+"
	+ pattern_ipport + "\\s+" + pattern_ipport + "\\s*";
RE2 ConnectionID4::re(ConnectionID4::pattern_connection4);

std::string ConnectionID4::pattern6_connection4 = "\\s*(\\w+)\\s+"
	+ pattern_ip6port + "\\s+" + pattern_ip6port + "\\s*";
RE2 ConnectionID4::re6(ConnectionID4::pattern6_connection4);

ConnectionID4* ConnectionID4::parse(const char *str) {
	std::string protostr, src_ip, dst_ip;
	unsigned src_port, dst_port;
	proto_t proto;

	if (!RE2::FullMatch(str, re, &protostr, &src_ip, &src_port, &dst_ip, &dst_port) && !RE2::FullMatch(str, re6, &protostr, &src_ip, &src_port, &dst_ip, &dst_port)) {
        //tmlog(TM_LOG_ERROR, "ConnectionID4", "No match found");
		return NULL;
	}
	if (protostr == std::string("tcp"))
		proto = IPPROTO_TCP;
	else 
		proto = IPPROTO_UDP;

    if (RE2::FullMatch(str, re, &protostr, &src_ip, &src_port, &dst_ip, &dst_port))
    {
	    return new ConnectionID4(proto, inet_addr(src_ip.c_str()), inet_addr(dst_ip.c_str()),
			    htons(src_port), htons(dst_port));
    }
    else
    {
        //unsigned char src_ip6[16];
        //unsigned char dst_ip6[16];

        //const char* src_ip6;
        //char* dst_ip6;

        in6_addr src_addr6;
        in6_addr dst_addr6;

        if (inet_pton(AF_INET6, src_ip.c_str(), &(src_addr6)) == 1 && inet_pton(AF_INET6, dst_ip.c_str(), &(dst_addr6)) == 1)
        {
	        return new ConnectionID4(proto, src_addr6.s6_addr, dst_addr6.s6_addr, htons(src_port), htons(dst_port));
        }
        return NULL;
    }
}

void Connection::addPkt(const struct pcap_pkthdr* header, const u_char* packet) {
	last_ts=to_tm_time(&header->ts);
	tot_pkts++;
	tot_pktbytes+=header->caplen; //len
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

