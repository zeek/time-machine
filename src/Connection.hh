#ifndef CONNECTION_HH
#define CONNECTION_HH

#include <string>

#include "types.h"
#include "packet_headers.h"
#include "IPAddr.hh"


#include "jhash3.h"
#include "re2/re2.h"

class QueryResult;
class Fifo;

class ConnectionID {
public:
	virtual ~ConnectionID() { }
	//  virtual hash_t hash() const = 0;
	virtual bool operator==(const ConnectionID& other) const = 0;
	//  virtual void* getVPtr() = 0;
	//  virtual const void* getConstVPtr() const = 0;
	virtual void getStr(char* s, int maxsize) const = 0;
	virtual std::string getStr() const = 0;
};

class ConnectionID4: public ConnectionID {
public:
	ConnectionID4(proto_t proto,
				  uint32_t s_ip, uint32_t d_ip,
				  uint16_t s_port, uint16_t d_port) {
		init(proto, s_ip, d_ip, s_port, d_port);
	}
	ConnectionID4(ConnectionID4 *c_id) {
		v.ip1 = c_id->v.ip1;
		v.ip2 = c_id->v.ip2;
		v.port1 = c_id->v.port1;
		v.port2 = c_id->v.port2;
		v.proto = c_id->v.proto;
	}
	ConnectionID4(const u_char* packet);
	ConnectionID4() {};
	virtual ~ConnectionID4() {};
	uint32_t hash() const { 
		//TODO: initval
		return hash3words(v.ip1.Hash(), v.ip2.Hash()^v.proto, v.port1 | ((v.port2)<<16), 0);
	}

	bool operator==(const ConnectionID& other) const { 
		return (v.ip1 == ((ConnectionID4*)&other)->v.ip1)
			   && (v.ip2 == ((ConnectionID4*)&other)->v.ip2)
			   && (v.port1 == ((ConnectionID4*)&other)->v.port1)
			   && (v.port2 == ((ConnectionID4*)&other)->v.port2)
			   && (v.proto == ((ConnectionID4*)&other)->v.proto);
	}

	static ConnectionID4 *parse(const char *str);

	proto_t get_proto() const {
		return v.proto;
	}
	const IPAddr* get_ip1() const {
		return (const IPAddr*) &v.ip1;
	}
	const IPAddr* get_ip2() const {
		return (const IPAddr*) &v.ip2;
	}
	uint16_t get_port1() const {
		return v.port1;
	}
	uint16_t get_port2() const {
		return v.port2;
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
	*/
	typedef struct {
		//  time locality
		//    uint32_t ts;
		IPAddr ip1;
		IPAddr ip2;
		uint16_t port1;
		uint16_t port2;
		proto_t proto;
		//    bool is_canonified;
	}
	__attribute__((packed)) v_t;
	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}
	void getStr(char* s, int maxsize) const;
	std::string getStr() const;
protected:
	void init(proto_t proto, uint32_t s_ip, uint32_t d_ip,
			  uint16_t s_port, uint16_t d_port);
	v_t v;
private:
	static std::string pattern_connection4;
	static RE2 re;
};

class ConnectionID3: public ConnectionID {
public:
	ConnectionID3(proto_t proto,
				  uint32_t ip1, uint32_t ip2,
				  uint16_t port2) {
		init(proto, ip1, ip2, port2);
	}
	ConnectionID3(const u_char* packet, int wildcard_port);
	ConnectionID3() {};
	virtual ~ConnectionID3() {};
	uint32_t hash() const {
		//TODO: initval
		return hash3words(v.ip1.Hash(), v.ip2.Hash(), v.port2 | ((v.proto)<<16), 0);
	}
	bool operator==(const ConnectionID& other) const;
	proto_t get_proto() const {
		return v.proto;
	}
	const IPAddr* get_ip1() const {
		return (const IPAddr*) &v.ip1;
	}
	const IPAddr* get_ip2() const {
		return (const IPAddr*) &v.ip2;
	}
	uint16_t get_port() const {
		return v.port2;
	}
	/*
	bool get_is_canonified() const { return v.is_canonified; }
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	*/
	typedef struct {
		//  time locality
		//    uint32_t ts;
		IPAddr ip1;
		IPAddr ip2;
		uint16_t port2;
		proto_t proto;
		//    bool is_canonified;
	}
	__attribute__((packed)) v_t;
	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}
	void getStr(char* s, int maxsize) const;
	std::string getStr() const;
protected:
	void init(proto_t proto, uint32_t s_ip, uint32_t d_ip, uint16_t port);
	v_t v;
};


class ConnectionID2: public ConnectionID {
public:
	ConnectionID2( uint32_t s_ip, uint32_t d_ip) {
		init(s_ip, d_ip);
	}
	ConnectionID2(const u_char* packet);
	ConnectionID2() {};
	virtual ~ConnectionID2() {};
	uint32_t hash() const {
		//TODO: initval
		return hash2words(v.ip1.Hash(), v.ip2.Hash(), 0);
	}
	bool operator==(const ConnectionID& other) const;
	const IPAddr* get_ip1() const {
		return (const IPAddr*) &v.ip1;
	}
	const IPAddr* get_ip2() const {
		return (const IPAddr*) &v.ip2;
	}
	/*
	bool get_is_canonified() const { return v.is_canonified; }
	uint32_t get_s_ip() const {
	  return v.is_canonified ? v.ip2 : v.ip1 ; }
	uint32_t get_d_ip() const {
	  return v.is_canonified ? v.ip1 : v.ip2 ; }
	*/
	typedef struct {
		//  time locality
		//    uint32_t ts;
		IPAddr ip1;
		IPAddr ip2;
		//    bool is_canonified;
	}
	__attribute__((packed)) v_t;
	v_t* getV() {
		return &v;
	}
	const v_t* getConstV() const {
		return &v;
	}
	void getStr(char* s, int maxsize) const;
	std::string getStr() const;
protected:
	void init(uint32_t s_ip, uint32_t d_ip);
	v_t v;
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
