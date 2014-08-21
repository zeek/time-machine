#ifndef CONNECTION_HH
#define CONNECTION_HH

#include <string>

#include "types.h"
#include "packet_headers.h"

#include "Hash.h"
//#include "IPAddr.h"
#include "re2/re2.h"

class QueryResult;
class Fifo;

typedef in_addr in4_addr;

class ConnectionID {
public:
	virtual ~ConnectionID() { }
	//  virtual hash_t hash() const = 0;
	virtual bool operator==(const ConnectionID& other) const = 0;
	//  virtual void* getVPtr() = 0;
	//  virtual const void* getConstVPtr() const = 0;
	virtual void getStr(char* s, int maxsize) const = 0;
	virtual std::string getStr() const = 0;
/*
        int equal(const unsigned char* a, const unsigned char* b) const
        {
            for (int i = 0; i < 16; i++)
            {
                if (a[i] != b[i])
                    return 0;
            }
            return 1;
        }
*/
    //virtual HashKey* hash() const = 0;

 /**
  * Returns a hash key for a given ConnID. Passes ownership to caller.
  */
    //virtual HashKey* BuildConnHashKey(const ConnectionID& curr) const = 0;
};

class ConnectionID4: public ConnectionID {
public:
	ConnectionID4(proto_t proto,
				  uint32_t s_ip, uint32_t d_ip,
				  uint16_t s_port, uint16_t d_port) {
		init(proto, s_ip, d_ip, s_port, d_port);
	}
	ConnectionID4(proto_t proto,
                  unsigned char s_ip[], unsigned char d_ip[],
                  uint16_t s_port, uint16_t d_port) {
        init6(proto, s_ip, d_ip, s_port, d_port);
    }
	ConnectionID4(ConnectionID4 *c_id) {
        memcpy(key.ip1.s6_addr, c_id->key.ip1.s6_addr, 16);
        memcpy(key.ip2.s6_addr, c_id->key.ip2.s6_addr, 16);
		key.port1 = c_id->key.port1;
		key.port2 = c_id->key.port2;
		v6.proto = c_id->v6.proto;
        v6.version = c_id->v6.version;
        v6.ip1 = c_id->v6.ip1;
        v6.ip2 = c_id->v6.ip2;
	}
	ConnectionID4(const u_char* packet);
	ConnectionID4() {};

	virtual ~ConnectionID4() {};
    /*
	uint32_t hash() const { 
		//TODO: initval
		return hash3words(v.ip1, v.ip2^v.proto, v.port1 | ((v.port2)<<16), 0);
	}
    */

    /*
    HashKey* hash() const
    {
        return BuildConnHashKey(v6.ip1, v6.ip2, v6.port1, v6.port2);
    }
    */

    /**
     * Constructs an address instance from an IPv4 address.
     *
     * @param in6 The IPv6 address.
     */
    /*
    void Convert4To6(const uint32_t s_ip, const uint32_t d_ip)
        {
        static uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
        //memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        //memcpy(&key.ip1.s6_addr[12], &s_ip, sizeof(s_ip));

        //memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        //memcpy(&key.ip2.s6_addr[12], &d_ip, sizeof(d_ip));
        }
    */

	bool operator==(const ConnectionID& other) const {
              /*
               return (!memcmp(key, ((ConnectionID4*)&other)->key, sizeof(key_t)))
                        && (v6.proto == ((ConnectionID4*)&other)->v6.proto);
               */
                if (v6.version == 4 && ((ConnectionID4*)&other)->v6.version == 4)
                {
                //return (!memcmp(&key.ip1.s6_addr + 12, &((ConnectionID4*)&other)->key.ip1.s6_addr + 12, 4))
                //           && (!memcmp(&key.ip2.s6_addr + 12, &((ConnectionID4*)&other)->key.ip2.s6_addr + 12, 4))
                    return (v6.ip1 == ((ConnectionID4*)&other)->v6.ip1)
                           && (v6.ip2 == ((ConnectionID4*)&other)->v6.ip2)
                           && (key.port1 == ((ConnectionID4*)&other)->key.port1)
                           && (key.port2 == ((ConnectionID4*)&other)->key.port2)
                           && (v6.proto == ((ConnectionID4*)&other)->v6.proto);

                }                 
                else if (v6.version == 6 && ((ConnectionID4*)&other)->v6.version == 6)
                {
                	return (!memcmp(&key.ip1.s6_addr, &((ConnectionID4*)&other)->key.ip1.s6_addr, 16))
			            && (!memcmp(&key.ip2.s6_addr, &((ConnectionID4*)&other)->key.ip2.s6_addr, 16))
			            && (key.port1 == ((ConnectionID4*)&other)->key.port1)
			            && (key.port2 == ((ConnectionID4*)&other)->key.port2)
			            && (v6.proto == ((ConnectionID4*)&other)->v6.proto);
                }
                else
                    return false;
                /*
                return equal(key.ip1.s6_addr, ((ConnectionID4*)&other)->key.ip2.s6_addr)
                           && equal(key.ip2.s6_addr, ((ConnectionID4*)&other)->key.ip2.s6_addr)
                           && (key.port1 == ((ConnectionID4*)&other)->key.port1)
                           && (key.port2 == ((ConnectionID4*)&other)->key.port2)
                           && (v6.proto == ((ConnectionID4*)&other)->v6.proto);
                 */

	}


	static ConnectionID4 *parse(const char *str);
/*
	proto_t get_proto() const {
		return v.proto;
	}
	uint32_t get_ip1() const {
		return v.ip1;
	}
	uint32_t get_ip2() const {
		return v.ip2;
	}
	uint16_t get_port1() const {
		return v.port1;
	}
	uint16_t get_port2() const {
		return v.port2;
	}
*/
	proto_t get_proto() const {
		return v6.proto;
	}
	const unsigned char* get_ip1() const {
		return key.ip1.s6_addr;
	}
    const in6_addr* get_ip1_addr() const {
        return &(key.ip1);
    }
	const unsigned char* get_ip2() const {
		return key.ip2.s6_addr;
	}
    const in6_addr* get_ip2_addr() const {
        return &(key.ip2);
    }
	uint16_t get_port1() const {
		return key.port1;
	}
	uint16_t get_port2() const {
		return key.port2;
	}
    int get_version() const {
        return v6.version;
    }

	//  bool get_is_canonified() const { return v.is_canonified; }
	/*
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	uint16_t get_s_port() const {
	  return v.is_canonified ? v.port2 : v.port1 ; }
	uint16_t get_d_port() const {
	  return v.is_canonified ? v.port1 : v.port2 ; }
	
	typedef struct {
		//  time locality
		//    uint32_t ts;
		uint32_t ip1;
		uint32_t ip2;
		uint16_t port1;
		uint16_t port2;
		proto_t proto;
        // made up my own parameter to distinguish between IPv4 and IPv6
        int version;
		//    bool is_canonified;
	}
    // have the structure fields align on one-byte boundaries
	__attribute__((packed)) v_t;
    */

/*
    struct in6_tm_addr
    {
        unsigned char *s6_tm_addr;
    };
*/
    
	typedef struct {
		//  time locality
		//    uint32_t ts;
		//unsigned char ip1[12];
		//unsigned char ip2[12];
		//uint16_t port1;
		//uint16_t port2;
        int version;
		proto_t proto;
                int ip1;
                int ip2;
		//    bool is_canonified;
	}
    // have the structure fields align on one-byte boundaries
	__attribute__((packed)) v6_t;
    
    //proto_t proto;

    typedef struct {
        in6_addr ip1;
        in6_addr ip2;
        //unsigned char ip1[16];
        //unsigned char ip2[16];
        uint16 port1;
        uint16 port2;
        //int version;
    } 
    __attribute__((packed)) key_t;

    /*
	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}
*/
	key_t* getV() {
		return &key;
	}
	const key_t* getConstV() const {
		return &key;
	}

	void getStr(char* s, int maxsize) const;
	std::string getStr() const;

    hash_t hash() const;

protected:
	void init(proto_t proto, uint32_t s_ip, uint32_t d_ip,
			  uint16_t s_port, uint16_t d_port);
    void init6(proto_t proto, unsigned char s_ip[], unsigned char d_ip[], 
               uint16_t s_port, uint16_t d_port);
	//v_t v;
    v6_t v6;
    key_t key;
    hash_t hash_key;

private:
	static std::string pattern_connection4;
    static std::string pattern6_connection4;
	static RE2 re;
    static RE2 re6;

	//in6_addr in6; // IPv6 or v4-to-v6-mapped address
};

class ConnectionID3: public ConnectionID {
public:
	ConnectionID3(proto_t proto,
				  uint32_t ip1, uint32_t ip2,
				  uint16_t port2) {
		init(proto, ip1, ip2, port2);
	}

    ConnectionID3(proto_t proto,
                  unsigned char ip1[], unsigned char ip2[], 
                  uint16_t port2) {
            init6(proto, ip1, ip2, port2);
    }

	ConnectionID3(const u_char* packet, int wildcard_port);
	ConnectionID3() {};


	virtual ~ConnectionID3() {
    };
    /*
	uint32_t hash() const {
		//TODO: initval
		return hash3words(v.ip1, v.ip2, v.port2 | ((v.proto)<<16), 0);
	}
    

    HashKey* hash() const
    {
        return BuildConnHashKey(v6.ip1, v6.ip2, v6.port2, 0);
    }
    
	bool operator==(const ConnectionID& other) const;
	proto_t get_proto() const {
		return v.proto;
	}
	uint32_t get_ip1() const {
		return v.ip1;
	}
	uint32_t get_ip2() const {
		return v.ip2;
	}
	uint16_t get_port() const {
		return v.port2;
	}
*/

    /**
     * Constructs an address instance from an IPv4 address.
     *
     * @param in6 The IPv6 address.
     */
    /*
    void Convert4To6(const uint32_t s_ip, const uint32_t d_ip)
        {
        static uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
        //memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        //memcpy(&key.ip1.s6_addr[12], &s_ip, sizeof(s_ip));

        //memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        //memcpy(&key.ip2.s6_addr[12], &d_ip, sizeof(d_ip));
        }
    */

	bool operator==(const ConnectionID& other) const;
	proto_t get_proto() const {
		return v6.proto;
	}
	const unsigned char* get_ip1() const {
		return key.ip1.s6_addr;
	}
    const in6_addr* get_ip1_addr() const {
        return &(key.ip1);
    }
	const unsigned char* get_ip2() const {
		return key.ip2.s6_addr;
	}
    const in6_addr* get_ip2_addr() const {
        return &(key.ip2);
    }
	uint16_t get_port() const {
		return key.port2;
	}

    int get_version() const {
        return v6.version;
    }

	/*
	bool get_is_canonified() const { return v.is_canonified; }
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	
	typedef struct {
		//  time locality
		//    uint32_t ts;
		uint32_t ip1;
		uint32_t ip2;
		uint16_t port2;
		proto_t proto;
        int version;
		//    bool is_canonified;
	}
	__attribute__((packed)) v_t;
    */

    
	typedef struct {
		//  time locality
		//    uint32_t ts;
		//unsigned char ip1[16];
		//unsigned char ip2[16];
		//uint16_t port2;
        int ip1;
        int ip2;
		proto_t proto;
        int version;
		//    bool is_canonified;
	}
	__attribute__((packed)) v6_t;
    

    //proto_t proto;

    typedef struct {
        in6_addr ip1;
        in6_addr ip2;
        uint16 port1;
        uint16 port2;
        //int version;
    }
    __attribute__((packed)) key_t;

/*
	v_t* getV() {
		return &v;
	}

	const v_t* getConstV() const {
		return &v;
	}
*/

	key_t* getV() {
		return &key;
	}

	const key_t* getConstV() const {
		return &key;
	}


	void getStr(char* s, int maxsize) const;
	std::string getStr() const;

/*
    HashKey* BuildConnHashKey(unsigned char s_ip[], unsigned char d_ip[],
                  uint16_t s_port, uint16_t d_port) const;
*/

    hash_t hash() const;

    hash_t hash_key; 
    v6_t v6; 
protected:
	void init(proto_t proto, uint32_t s_ip, uint32_t d_ip, uint16_t port);
    void init6(proto_t proto, unsigned char s_ip[], unsigned char d_ip[], 
               uint16_t port);
	//v_t v;
    //v6_t v6;
    key_t key;


//private:
	//in6_addr in6; // IPv6 or v4-to-v6-mapped address

	//static const uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
};


class ConnectionID2: public ConnectionID {
public:
	ConnectionID2( uint32_t s_ip, uint32_t d_ip) {
		init(s_ip, d_ip);
	}

    ConnectionID2(unsigned char s_ip[], unsigned char d_ip[]) {
        init6(s_ip, d_ip);
    }

	ConnectionID2(const u_char* packet);
	ConnectionID2() {};

	/**
	 * Constructs an address instance from an IPv4 address.
	 *
	 * @param in6 The IPv6 address.
	 */
    /*
	explicit ConnectionID2(const uint32_t s_ip, const uint32_t d_ip)
		{
    	static uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
		//memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		//memcpy(&key.ip1.s6_addr[12], &s_ip, sizeof(s_ip));

		//memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		//memcpy(&key.ip2.s6_addr[12], &d_ip, sizeof(d_ip));
		}
    */
	virtual ~ConnectionID2() {};
    /*
	uint32_t hash() const {
		//TODO: initval
		return hash2words(v.ip1, v.ip2, 0);
	}
    */

/*
    HashKey* hash() const
    {
        return BuildConnHashKey(v6.ip1, v6.ip2, 0, 0);
    }
*/

    /**
     * Constructs an address instance from an IPv4 address.
     *
     * @param in6 The IPv6 address.
     */
    /*
    void Convert4To6(const uint32_t s_ip, const uint32_t d_ip)
        {
        static uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
        //memcpy(key.ip1.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        //memcpy(&key.ip1.s6_addr[12], &s_ip, sizeof(s_ip));

        //memcpy(key.ip2.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
        //memcpy(&key.ip2.s6_addr[12], &d_ip, sizeof(d_ip));
        }
    */

	bool operator==(const ConnectionID& other) const;
/*
	uint32_t get_ip1() const {
		return v.ip1;
	}
	uint32_t get_ip2() const {
		return v.ip2;
	}
*/

	const unsigned char* get_ip1() const {
		return key.ip1.s6_addr;
	}
    const in6_addr* get_ip1_addr() const {
        return &(key.ip1);
    }
	const unsigned char* get_ip2() const {
		return key.ip2.s6_addr;
	}
    const in6_addr* get_ip2_addr() const {
        return &(key.ip2);
    }
    int get_version() const {
        return v6.version;
    }


	/*
	bool get_is_canonified() const { return v.is_canonified; }
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	
	typedef struct {
		//  time locality
		//    uint32_t ts;
		uint32_t ip1;
		uint32_t ip2;
        int version;
		//    bool is_canonified;
	}
	__attribute__((packed)) v_t;
    */
    
	typedef struct {
		//  time locality
		//    uint32_t ts;
		//unsigned char ip1[16];
		//unsigned char ip2[16];
        int ip1;
        int ip2;
        int version;
		//    bool is_canonified;
	}
	__attribute__((packed)) v6_t;
    

    typedef struct {
        in6_addr ip1;
        in6_addr ip2;
        //unsigned char ip1[16];
        //unsigned char ip2[16];
        uint16 port1;
        uint16 port2;
        //int version;
    }
    __attribute__((packed)) key_t;

/*
	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}
*/
	key_t* getV() {
		return &key;
	}
	const key_t* getConstV() const {
		return &key;
	}

	void getStr(char* s, int maxsize) const;
	std::string getStr() const;

/*
    HashKey* BuildConnHashKey(unsigned char s_ip[], unsigned char d_ip[],
                  uint16_t s_port, uint16_t d_port) const;
*/

    hash_t hash() const;

    hash_t hash_key;
    v6_t v6;
protected:
	void init(uint32_t s_ip, uint32_t d_ip);
    void init6( unsigned char s_ip[], unsigned char d_ip[]);
	//v_t v;
    //v6_t v6;
    key_t key;

//private:
	//in6_addr in6; // IPv6 or v4-to-v6-mapped address

	//static const uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
};


class Connection {
public:
	/*
	Connection(proto_t proto,
	    uint32_t s_ip, uint32_t d_ip,
	    uint16_t s_port, uint16_t d_port);
	Connection(ConnectionID&);
	*/
	/* id  will be owned by Connection class and freed by it */
	Connection(ConnectionID4 *id) {
		init(id);
	}
	Connection(Connection *c);
	virtual ~Connection() {
    // we need delete [] instead of delete because we allocated an array for the ipv6 addresses?
		delete c_id;
	}
	void addPkt(const struct pcap_pkthdr* header, const u_char* packet);
	tm_time_t getLastTs() {
		return last_ts;
	}
	uint64_t getTotPktbytes() {
		return tot_pktbytes;
	}
	//  ConnectionID* getKey() { return key; }
	Fifo* getFifo() {
		return fifo;
	}
	void setFifo(Fifo *f) {
		fifo=f;
	}
	void setSuspendCutoff(bool b) {
		suspend_cutoff=b;
	}
	bool getSuspendCutoff() {
		return suspend_cutoff;
	}
	void setSuspendTimeout(bool b) {
		suspend_timeout=b;
	}
	bool getSuspendTimeout() {
		return suspend_timeout;
	}
	std::string getStr() const;
	void setSubscription(QueryResult *q) {
		subscription=q;
	}
	QueryResult* getSubscription() {
		return subscription;
	}
	int deleteSubscription();

	friend class Connections;
protected:
	ConnectionID4 *c_id;
	//  ConnectionID* key;
	//  struct ConnectionID c_id;
	tm_time_t last_ts;

	/* cache to which class this connection belongs */
	Fifo* fifo;
	/* is there a subscription for this connection? */
	QueryResult* subscription;
	/* true if cutoff should not be done for this connection */
	bool suspend_cutoff;
	/* true if inactivity timeout should not be done for this connection */
	bool suspend_timeout;

	//	bool tcp_syn;

	uint64_t tot_pkts;
	uint64_t tot_pktbytes;

	//  hash_t hash() const;
	//  bool operator==(const Connection& other) const { return c_id==other.c_id; }
	void init(ConnectionID4 *);

	/* hash collision queue */
	Connection *col_next;
	Connection *col_prev;

	/* timeout queue */
	Connection *q_newer;
	Connection *q_older;

	
};

#endif
