#ifndef INDEXFIELD_HH
#define INDEXFIELD_HH

#include <pcap.h>
#include <list>
#include <string>
#include <arpa/inet.h>

#include "re2/re2.h"

#include "types.h"
#include "packet_headers.h"

class IndexField;

#include "Hash.h"
#include "Connection.hh"
//#include "IPAddr.h"
#include "util.h"
#include "tm.h"

/** IndexField: Base class for all index "keys".
 *
 * The derived classes from IndexField are used as templated class
 * for Index<T>. E.g. Index<ConnectionIF4>
 */
class IndexField {
public:
	virtual ~IndexField() {};
	virtual const std::string getIndexName() const = 0;
	static const std::string getIndexNameStatic();
	virtual const unsigned char* getConstKeyPtr() const=0;
	//  virtual char* getKeyPtr() { return NULL; }
	virtual const int getKeySize() const=0;
	virtual void getStr(char* s, int maxsize) const=0;
	virtual std::string getStr() const=0;
    //virtual std::string getStrPkt(const u_char* packet) const = 0;
	virtual bool operator==(const IndexField& other) const {
		//  printf("IndexField::operator==(const IndexField& other)\n");
		return !memcmp(getConstKeyPtr(),other.getConstKeyPtr(),getKeySize());
	}
	virtual bool operator!=(const IndexField& o) const {
		return !(*this==o);
	}
	//  virtual bool compare_to(IndexField* other) const;
	virtual bool operator==(const char* other_key) const {
		//fprintf(stderr, "IndexField::operator==(const char* other_key)\n");
		return !memcmp(getConstKeyPtr(),other_key,getKeySize());
	}

	//virtual uint32_t hash() const=0;

    virtual hash_t hash() const = 0;

	virtual const unsigned char* getInt() const= 0;
	// The Timestamp field is only used, when the IndexField is put into
	// the input_q of an index? Why? We need a timestamp for every entry
	// in the input_q. If we take the TS out and use a seperate IndexQueueEntry
	// class, then we need _two_ mallocs() and _two_ frees for every queue 
	// entry. Since every packet will normaly to lead to one IndexField object
	// per configured index, saving one of those malloc() / free() pairs saves
	// a lot of CPU time.
	tm_time_t ts;
	
	virtual void getBPFStr(char *, int) const = 0;

    hash_t hash_key;

	//  IndexField(void *);
	
};

class SrcIPAddress;
class DstIPAddress;
class IPAddress: public IndexField {
public:

    typedef IPFamily Family;

/*
	IPAddress(uint32_t ip): ip_address(ip), AFtype(AF_INET), AFtypelength(INET_ADDRSTRLEN), strIP(new char[INET_ADDRSTRLEN]) {
    }
*/

    IPAddress(uint32_t ip)
    {
        in_addr in4;
        in4.s_addr = ip;

		memcpy(ipv6_address.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		memcpy(&ipv6_address.s6_addr[12], &in4.s_addr, sizeof(in4.s_addr));

        //init_hash_function();
        //HashKey* newHashKey = new HashKey((void*)ipv6_address.s6_addr, sizeof(ipv6_address.s6_addr));

        key_u.u32 = ip;
       
        key = (void*) &key_u;

        //hash_key = newHashKey->Hash();

        hash_key = HashKey::HashBytes(key, sizeof(ip));
 
        //delete newHashKey;

        //free_hash_function();
    }
/*
    IPAddress(unsigned char ip6[])
    {
        std::copy(ip6, ip6 + 16, ip6_address);
        AFtype = AF_INET6;
        AFtypelength = INET6_ADDRSTRLEN;
        strIP = new char[INET6_ADDRSTRLEN];
    }
*/

    IPAddress(unsigned char ip6[])
    {
        memcpy(ipv6_address.s6_addr, ip6, 16);

        //init_hash_function();
        HashKey* newHashKey = new HashKey((void*)ipv6_address.s6_addr, sizeof(ipv6_address.s6_addr));

        //key_u.u32 = ipv6_address.s6_addr;

        hash_key = newHashKey->Hash();

        //key = HashKey::CopyKey((void*)ipv6_address.s6_addr, sizeof(ipv6_address.s6_addr));

        //hash_key = HashKey::HashBytes(key, sizeof(ipv6_address.s6_addr));

        //key = (void*) &key_u

        //hash_key = HashKey::HashBytes(key, sizeof(key));

        delete newHashKey;

        //free_hash_function();
    }
/*
    // The inet_addr() function converts the Internet host address cp from IPv4 
    // numbers-and-dots notation into binary data in network byte order.
    // inet_pton() function does it for either IPv4 or IPv6 addresses
	IPAddress(const char* s, char strIP[]) 
    {
        if (AFtype == AF_INET)
            ip_address = inet_pton(AFtype, s, strIP);
        else
            //memcpy(ip6_address, (char)((unsigned int) inet_pton(AFtype, s, strIP)), 16);
            sprintf(ip6_address, "%d", inet_pton(AFtype, s, strIP));
            //ip6_address = inet_pton(AFtype, s, strIP);
    }
*/

    
    IPAddress(const char* str_arg)
    {
        Init(str_arg);
    }
    
	IPAddress(void *p) {
		memcpy((void*)getConstKeyPtr(), p, getKeySize());

        //init_hash_function();
        HashKey* newHashKey = new HashKey((void*)ipv6_address.s6_addr, sizeof(ipv6_address.s6_addr));

        hash_key = newHashKey->Hash();

        delete newHashKey;

        //free_hash_function();
	}
	virtual ~IPAddress() {
        //tmlog(TM_LOG_NOTE, "IPAddress", "deleting an ipaddress type");
        //delete [] ip6_address;
        //delete [] strIP;
    };


	/**
	 * Returns the address' family.
	 */
    
	Family GetFamily() const
		{
        
		if (!memcmp(ipv6_address.s6_addr, v4_mapped_prefix, 12))
			return IPv4;
		else
			return IPv6;
        
		}

	/**
	 * Returns a key that can be used to lookup the IP Address in a hash
	 * table. Passes ownership to caller.
	 */
    /*
	HashKey* GetHashKey() const
		{
		return new HashKey((void*)in6.s6_addr, sizeof(in6.s6_addr));
		}
    */
    /*
	virtual uint32_t hash() const {
		// TODO: initval
		return hash1words(ip_address, 0);
	}
    */    


	virtual hash_t hash() const {
		// TODO: initval
        return hash_key;
	}
	virtual const unsigned char* getInt() const {
		return ipv6_address.s6_addr;
	}
	virtual const unsigned char* getConstKeyPtr() const {
		return ipv6_address.s6_addr;
	}
	//  char* getKeyPtr() { return (char*)&ip_address; }
	virtual const int getKeySize() const {
		return sizeof(ipv6_address.s6_addr);
	}
	virtual void getStr(char* s, int maxsize) const;
	virtual std::string getStr() const;

    //virtual std::string getStrPkt(const u_char* packet) const;

	virtual const std::string getIndexName() const {
		return "ip";
	}
	static const std::string getIndexNameStatic() {
		return "ip";
	}
	static std::list<IPAddress*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 2;
	}
	// getKey need to go to the bottom, since it needs the
	// definition of SrcIPAddress, and DstIPAddress
	static IPAddress* genKey (const u_char* packet, int keynum);

	static IndexField* parseQuery(const char *query);
	virtual void getBPFStr(char *, int) const;

protected:
    union {
            bro_int_t i;
            uint32 u32;
            double d;
            const void* p;
        } key_u;

    void* key;

    hash_t hash_key;

private:

	/**
	 * Initializes an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IPv6 address.
	 */
	void Init(const std::string& s);

	//in6_addr in6; // IPv6 or v4-to-v6-mapped address

	static const uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr

	//uint32_t ip_address;
    //unsigned char ip6_address[16]; // unsigned char ip6_address[16]
 	static std::string pattern;
    static std::string pattern6;
	static RE2 re;
    static RE2 re6;
    //int AFtype;
    //int AFtypelength;
    //unsigned char *strIP;
    in6_addr ipv6_address;
};

class SrcIPAddress: public IPAddress {
public:
	SrcIPAddress(uint32_t ip): IPAddress(ip) {}
    SrcIPAddress(unsigned char ip6[]): IPAddress(ip6) {}
	//SrcIPAddress(const char* ip, char strIP[]): IPAddress(ip, strIP) {}

    //SrcIPAddress(const char* ip): IPAddress(ip) {}

	//SrcIPAddress(const u_char* packet);
	static std::list<SrcIPAddress*> genKeys(const u_char* packet);

    //std::string getStrPkt(const u_char* packet) const;

	static int keysPerPacket() {
		return 1;
	}
	static SrcIPAddress* genKey (const u_char* packet, int keynum) {
        /*
        switch (keynum) {
            case 0: return new SrcIPAddress(packet);
            default: return NULL;
        }
        */

        if (keynum == 0)
        {
            if(IP(packet)->ip_v == 4)
            {
                
                //tmlog(TM_LOG_NOTE, "SrcIPAddress: genKey", "get key for IPv4 address");
                return new SrcIPAddress(IP(packet)->ip_src.s_addr);
            }

            else
            {
                //tmlog(TM_LOG_NOTE, "SrcIPAddress:genkey tester", "the version for Ipv6 is: %d", IP6(packet)->ip6_ctlun.ip6_un1.ip6_un1_flow);
                //tmlog(TM_LOG_NOTE, "SrcIPAddress: genKey", "get key for IPv6 address");
                return new SrcIPAddress(IP6(packet)->ip6_src.s6_addr);
            }
        }
        else
        {
            return NULL;
        }

	}
	virtual const std::string getIndexName() const {
		return "srcip";
	}
	static const std::string getIndexNameStatic() {
		return "srcip";
	}
	void getBPFStr(char *, int) const;
};

class DstIPAddress: public IPAddress {
public:
	DstIPAddress(uint32_t ip): IPAddress(ip) {}
    DstIPAddress(unsigned char ip6[]): IPAddress(ip6) {}
	//DstIPAddress(const char* ip, char strIP[]): IPAddress(ip, strIP) {}

    //DstIPAddress(const char* ip): IPAddress(ip) {}

	//DstIPAddress(const u_char* packet);
	static std::list<DstIPAddress*> genKeys(const u_char* packet);

    //std::string getStrPkt(const u_char* packet) const;

	static int keysPerPacket() {
		return 1;
	}
	static DstIPAddress* genKey (const u_char* packet, int keynum) {
        /*
		switch (keynum) {
			case 0: return new DstIPAddress(packet);
			default: return NULL;
		}
        */

        if (keynum == 0)
        {
            if (IP(packet)->ip_v == 4)
            {
                return new DstIPAddress(IP(packet)->ip_dst.s_addr);
            }
            else
            {
                return new DstIPAddress(IP6(packet)->ip6_dst.s6_addr);
            }
        }
        else
        {
            return NULL;
        }
	}
	virtual const std::string getIndexName() const {
		return "dstip";
	}
	static const std::string getIndexNameStatic() {
		return "dstip";
	}
	void getBPFStr(char *, int) const;
};

class Port: public IndexField {
public:
	Port(): port(0) {
        //init_hash_function();
        /*
        HashKey* newHashKey = new HashKey((void*)ipv6_address.s6_addr, sizeof(ipv6_address.s6_addr));

	    hash_key =  newHashKey->Hash();

        delete newHashKey;
        */
        //free_hash_function();
    }
	Port(uint16_t port): port(port) {  /* printf("Port(%u)\n", port); */
        //init_hash_function();
        /*
        HashKey* newHashKey = new HashKey((void*)ipv6_address.s6_addr, sizeof(ipv6_address.s6_addr));

	    hash_key =  newHashKey->Hash();

        delete newHashKey;
        */
        //free_hash_function();
	}
	virtual ~Port() {}

    // I don't think this is ever used, so returning 0 should be ok
	virtual const unsigned char* getInt() const {
        //unsigned char portInt[16];

        //memcpy(portInt, (unsigned char*) &port, sizeof(uint16_t));

		return 0;
	}
	virtual const unsigned char* getConstKeyPtr() const {
		return (const unsigned char*)&port;
	};
	//  char* getKeyPtr() { return (char*)&port; };
	virtual const int getKeySize() const {
		return sizeof(port);
	};
	static std::list<Port*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 2;
	}
	// getKey need to go to the bottom, since it needs the
	// definition of SrcPort, and DstPort
	static Port* genKey (const u_char* packet, int keynum);
	static IndexField* parseQuery(const char *query);
/*
	virtual uint32_t hash() const {
		// TODO: initval
		return hash1words(port, 0);
	}
*/

	/**
	 * Returns a key that can be used to lookup the IP Address in a hash
	 * table. Passes ownership to caller.
	 */
    /*
	HashKey* GetHashKey() const
		{
		return new HashKey((void*)in6.s6_addr, sizeof(in6.s6_addr));
		}
    */
	virtual hash_t hash() const {
		// TODO: initval
        HashKey* newHashKey = new HashKey(uint32_t(port));

        hash_t hash_key =  newHashKey->Hash();

        delete newHashKey;

        return hash_key;
	}

	virtual const std::string getIndexName() const {
		return "port";
	}
	static const std::string getIndexNameStatic() {
		return "port";
	}
	virtual void getStr(char* s, int maxsize) const;
	virtual std::string getStr() const;
    //virtual std::string getStrPkt(const u_char* packet) const;
	virtual void getBPFStr(char *, int) const;
protected:
    //hash_t hash_key;
	uint16_t port;
	static std::string pattern;
	static RE2 re;

private:
	in6_addr ipv6_address; // IPv6 or v4-to-v6-mapped address

    //const unsigned char portInt[16];

	static const uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
};

class SrcPort: public Port {
public:
	SrcPort(uint16_t nport): Port(nport) {}
	SrcPort(const u_char* packet);
	static std::list<SrcPort*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 1;
	}
	static SrcPort* genKey (const u_char* packet, int keynum) {
		switch (keynum) {
			case 0: return new SrcPort(packet);
			default: return NULL;
		}
	}
	virtual const std::string getIndexName() const {
		return "srcport";
	}
	static const std::string getIndexNameStatic() {
		return "srcport";
	}

    //std::string getStrPkt(const u_char* packet) const;

	void getBPFStr(char *, int) const;
};

class DstPort: public Port {
public:
	DstPort(uint16_t nport): Port(nport) {}
	DstPort(const u_char* packet);
	static std::list<DstPort*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 1;
	}
	static DstPort* genKey (const u_char* packet, int keynum) {
		switch (keynum) {
			case 0: return new DstPort(packet);
			default: return NULL;
		}
	}
	virtual const std::string getIndexName() const {
		return "dstport";
	}
	static const std::string getIndexNameStatic() {
		return "dstport";
	}

    //std::string getStrPkt(const u_char* packet) const;

	void getBPFStr(char *, int) const;
};

//class ConnectionID;

class ConnectionIF4: public IndexField {
public:
	ConnectionIF4(proto_t proto, uint32_t ip1, uint16_t port1,
				  uint32_t ip2, uint16_t port2):
	c_id(proto, ip1, ip2, port1, port2) {} 

    ConnectionIF4(proto_t proto, unsigned char ip6_1[], uint16_t port1,
                  unsigned char ip6_2[], uint16_t port2):
    c_id(proto, ip6_1, ip6_2, port1, port2) {}

	ConnectionIF4(const u_char* packet):
	c_id(packet) {} 
	ConnectionIF4(ConnectionID4 c):
	c_id(c) {} 
	ConnectionIF4(void *p) {
		
		memcpy((void*)getConstKeyPtr(), p, getKeySize());
	}
	virtual ~ConnectionIF4() {} 
	virtual hash_t hash() const {
		return c_id.hash();
	}

	const unsigned char* getInt() const {
		return 0;
	}
	virtual const unsigned char* getConstKeyPtr() const {
		return (const unsigned char*)c_id.getConstV();
	}
	//  char* getKeyPtr() { return (char*)c_id.getV(); }
	virtual const int getKeySize() const {
		return sizeof(*c_id.getConstV());
	}
	virtual const std::string getIndexName() const {
		return "connection4";
	}
	static const std::string getIndexNameStatic() {
		return "connection4";
	}
	static std::list<ConnectionIF4*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 1;
	}
	static ConnectionIF4* genKey (const u_char* packet, int keynum) {
		switch (keynum) {
			case 0: return new ConnectionIF4(packet);
			default: return NULL;
		}
	}
	static IndexField* parseQuery(const char *query);
	std::string getStr() const {
		return c_id.getStr();
	}
    
	void getStr(char *c, int l) const  {
		getStr().copy(c, l);
	}
    /* 
    std::string getStrPkt(const u_char* packet) const
    {
        return getStr();
    }
    */
	void getBPFStr(char *, int) const;

    void ip_to_str(const unsigned char* ip, char *str, int len) const;

	ConnectionID4 *getCID() {
		return &c_id;
	}
	bool operator==(const IndexField& other) const {
		return c_id==((ConnectionIF4*)&other)->c_id;
	}
	bool operator==(const char* other_key) const {
		return c_id==*(ConnectionID4 *)other_key;
	}

    hash_t hash_key;
private:
	ConnectionID4 c_id;
	static std::string pattern_connection4;
    static std::string pattern6_connection4;
	static RE2 re;
    static RE2 re6;
};


class ConnectionIF3: public IndexField {
public:
	ConnectionIF3(proto_t proto, uint32_t ip1, 
				  uint32_t ip2, uint16_t port2):
	c_id(proto, ip1, ip2, port2) {}

	ConnectionIF3(proto_t proto, unsigned char ip6_1[], 
				  unsigned char ip6_2[], uint16_t port2):
	c_id(proto, ip6_1, ip6_2, port2) {}

	ConnectionIF3(const u_char* packet, int wildcard_port):
	c_id(packet, wildcard_port) {}
	ConnectionIF3(ConnectionID3 c_id):
	c_id(c_id) {}
	ConnectionIF3(void *p) {
		memcpy((void*)getConstKeyPtr(), p, getKeySize());
	}
	virtual ~ConnectionIF3() {};
	virtual hash_t hash() const {
		return c_id.hash();
	}
	const unsigned char* getInt() const {
		return 0;
	}
	virtual const unsigned char* getConstKeyPtr() const {
		return (const unsigned char*)c_id.getConstV();
	}
	virtual const int getKeySize() const {
		return sizeof(*c_id.getConstV());
	}
	virtual const std::string getIndexName() const {
		return "connection3";
	}
	static const std::string getIndexNameStatic() {
		return "connection3";
	}
	static std::list<ConnectionIF3*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 2;
	}
	static ConnectionIF3* genKey (const u_char* packet, int keynum) {
		// do the switch to be able to find invalid keynums
		switch (keynum) {
			case 0: return new ConnectionIF3(packet,0);
			case 1: return new ConnectionIF3(packet,1);
			default: return NULL;
		}
	}
    
	std::string getStr() const {
		return c_id.getStr();
	}
    
	static IndexField* parseQuery(const char *query);
	void getStr(char *c, int l) const  {
		getStr().copy(c, l);
	}
    /*
    std::string getStrPkt(const u_char* packet) const
    {
        return getStr();
    }
    */
	void getBPFStr(char *, int) const;
	ConnectionID3 *getCID() {
		return &c_id;
	}

    void ip4_to_str(const unsigned char* ip, char *str, int len) const;

	bool operator==(const IndexField& other) const {
		return c_id==((ConnectionIF3*)&other)->c_id;
	}
	bool operator==(const char* other_key) const {
		//printf("ConnectionIF::operator==(const char* other_key)\n");
		return c_id==*(ConnectionID3 *)other_key;
	}

    hash_t hash_key;
private:
	ConnectionID3 c_id;
	static std::string pattern_connection3;
    static std::string pattern6_connection3;
	static RE2 re;
    static RE2 re6;
};


class ConnectionIF2: public IndexField {
public:
	ConnectionIF2(uint32_t ip1, uint32_t ip2):
	c_id(ip1, ip2) {}

	ConnectionIF2(unsigned char ip6_1[], unsigned char ip6_2[]):
	c_id(ip6_1, ip6_2) {}

	ConnectionIF2(const u_char* packet):
	c_id(packet) {}
	ConnectionIF2(ConnectionID2 c_id):
	c_id(c_id) {}
	ConnectionIF2(void *p) {
		memcpy((void*)getConstKeyPtr(), p, getKeySize());
	}
	virtual ~ConnectionIF2() {};
	virtual hash_t hash() const {
		return c_id.hash();
	}
	const unsigned char* getInt() const {
		return 0;
	}
	static IndexField* parseQuery(const char *query);

	virtual const unsigned char* getConstKeyPtr() const {
		return (const unsigned char*)c_id.getConstV();
	}
	virtual const int getKeySize() const {
		return sizeof(*c_id.getConstV());
	}
	virtual const std::string getIndexName() const {
		return "connection2";
	}
	static const std::string getIndexNameStatic() {
		return "connection2";
	}
	static std::list<ConnectionIF2*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 1;
	}
	static ConnectionIF2* genKey (const u_char* packet, int keynum) {
		switch (keynum) {
			case 0: return new ConnectionIF2(packet);
			default: return NULL;
		}
	}
    
	std::string getStr() const {
		return c_id.getStr();
	}
	void getStr(char *c, int l) const  {
		getStr().copy(c, l);
	}
    /*
    std::string getStrPkt(const u_char* packet) const
    {
        return getStr();
    }
    */
	void getBPFStr(char *, int) const;

    void ip4_to_str(const unsigned char* ip, char *str, int len) const;

	ConnectionID2 *getCID() {
		return &c_id;
	}
	bool operator==(const IndexField& other) const {
		return c_id==((ConnectionIF2*)&other)->c_id;
	}
	bool operator==(const char* other_key) const {
		return c_id==*(ConnectionID2 *)other_key;
	}

    hash_t hash_key;
private:
	ConnectionID2 c_id;
	static std::string pattern_connection2;
    static std::string pattern6_connection2;
	static RE2 re;
    static RE2 re6;
};

inline IPAddress* IPAddress::genKey (const u_char* packet, int keynum)
{
    /*
	switch (keynum) {
		case 0: return new SrcIPAddress(packet);
		case 1: return new DstIPAddress(packet);
		default: return NULL;
	}
    */

    if (keynum == 0)
    {
        if (IP(packet)->ip_v == 4)
        {
            return new SrcIPAddress(IP(packet)->ip_src.s_addr);
        }
        else
        {
            return new SrcIPAddress(IP6(packet)->ip6_src.s6_addr);
        }
    }

    else if (keynum == 1)
    {
        if (IP(packet)->ip_v == 4)
        {
            return new DstIPAddress(IP(packet)->ip_dst.s_addr);
        }
        else
        {
            return new DstIPAddress(IP6(packet)->ip6_dst.s6_addr);
        }
    }   

    else
    {
        return NULL;
    }
}
inline Port* Port::genKey (const u_char* packet, int keynum) {
	switch (keynum) {
		case 0: return new SrcPort(packet);
		case 1: return new DstPort(packet);
		default: return NULL;
	}
}
#endif

