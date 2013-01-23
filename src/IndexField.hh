/*
Timemachine
Copyright (c) 2006 Technische Universitaet Muenchen,
                   Technische Universitaet Berlin,
                   The Regents of the University of California
All rights reserved.


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the names of the copyright owners nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// $Id: IndexField.hh 251 2009-02-04 08:14:24Z gregor $

#ifndef INDEXFIELD_HH
#define INDEXFIELD_HH

#include <pcap.h>
#include <list>
#include <string>
#include <arpa/inet.h>

#include <pcrecpp.h>

#include "types.h"
#include "packet_headers.h"

class IndexField;

#include "Connection.hh"

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
	virtual const char* getConstKeyPtr() const=0;
	//  virtual char* getKeyPtr() { return NULL; }
	virtual const int getKeySize() const=0;
	virtual void getStr(char* s, int maxsize) const=0;
	virtual std::string getStr() const=0;
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

	virtual uint32_t hash() const=0;
	virtual uint32_t getInt() const=0;
	// The Timestamp field is only used, when the IndexField is put into
	// the input_q of an index? Why? We need a timestamp for every entry
	// in the input_q. If we take the TS out and use a seperate IndexQueueEntry
	// class, then we need _two_ mallocs() and _two_ frees for every queue 
	// entry. Since every packet will normaly to lead to one IndexField object
	// per configured index, saving one of those malloc() / free() pairs saves
	// a lot of CPU time.
	tm_time_t ts;
	
	virtual void getBPFStr(char *, int) const = 0;
	//  IndexField(void *);
	
};

class SrcIPAddress;
class DstIPAddress;
class IPAddress: public IndexField {
public:
	IPAddress(uint32_t ip): ip_address(ip) {}
	IPAddress(const char* s): ip_address(inet_addr(s)) {}
	IPAddress(void *p) {
		memcpy((void*)getConstKeyPtr(), p, getKeySize());
	}
	virtual ~IPAddress() {};
	virtual uint32_t hash() const {
		// TODO: initval
		return hash1words(ip_address, 0);
	}
	virtual uint32_t getInt() const {
		return ip_address;
	}
	virtual const char* getConstKeyPtr() const {
		return (const char*)&ip_address;
	}
	//  char* getKeyPtr() { return (char*)&ip_address; }
	virtual const int getKeySize() const {
		return sizeof(ip_address);
	}
	virtual void getStr(char* s, int maxsize) const;
	virtual std::string getStr() const;
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
private:
	uint32_t ip_address;
	static std::string pattern;
	static pcrecpp::RE re;
};

class SrcIPAddress: public IPAddress {
public:
	SrcIPAddress(uint32_t ip): IPAddress(ip) {}
	SrcIPAddress(const char* ip): IPAddress(ip) {}
	SrcIPAddress(const u_char* packet);
	static std::list<SrcIPAddress*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 1;
	}
	static SrcIPAddress* genKey (const u_char* packet, int keynum) {
		switch (keynum) {
			case 0: return new SrcIPAddress(packet);
			default: return NULL;
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
	DstIPAddress(const char* ip): IPAddress(ip) {}
	DstIPAddress(const u_char* packet);
	static std::list<DstIPAddress*> genKeys(const u_char* packet);
	static int keysPerPacket() {
		return 1;
	}
	static DstIPAddress* genKey (const u_char* packet, int keynum) {
		switch (keynum) {
			case 0: return new DstIPAddress(packet);
			default: return NULL;
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
	Port(): port(0) {}
	Port(uint16_t port): port(port) {  /* printf("Port(%u)\n", port); */
	}
	virtual ~Port() {}
	virtual uint32_t getInt() const {
		return port;
	}
	virtual const char* getConstKeyPtr() const {
		return (const char*)&port;
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
	virtual uint32_t hash() const {
		// TODO: initval
		return hash1words(port, 0);
	}
	virtual const std::string getIndexName() const {
		return "port";
	}
	static const std::string getIndexNameStatic() {
		return "port";
	}
	virtual void getStr(char* s, int maxsize) const;
	virtual std::string getStr() const;
	virtual void getBPFStr(char *, int) const;
protected:
	uint16_t port;
	static std::string pattern;
	static pcrecpp::RE re;
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
	void getBPFStr(char *, int) const;
};

//class ConnectionID;

class ConnectionIF4: public IndexField {
public:
	ConnectionIF4(proto_t proto, uint32_t ip1, uint16_t port1,
				  uint32_t ip2, uint16_t port2):
	c_id(proto, ip1, ip2, port1, port2) {} 
	ConnectionIF4(const u_char* packet):
	c_id(packet) {} 
	ConnectionIF4(ConnectionID4 c):
	c_id(c) {} 
	ConnectionIF4(void *p) {
		
		memcpy((void*)getConstKeyPtr(), p, getKeySize());
	}
	virtual ~ConnectionIF4() {} 
	virtual uint32_t hash() const {
		return c_id.hash();
	}
	uint32_t getInt() const {
		return 0;
	}
	virtual const char* getConstKeyPtr() const {
		return (const char*)c_id.getConstV();
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
	void getBPFStr(char *, int) const;
	ConnectionID4 *getCID() {
		return &c_id;
	}
	bool operator==(const IndexField& other) const {
		return c_id==((ConnectionIF4*)&other)->c_id;
	}
	bool operator==(const char* other_key) const {
		return c_id==*(ConnectionID4 *)other_key;
	}
private:
	ConnectionID4 c_id;
	static std::string pattern_connection4;
	static pcrecpp::RE re;
};


class ConnectionIF3: public IndexField {
public:
	ConnectionIF3(proto_t proto, uint32_t ip1, 
				  uint32_t ip2, uint16_t port2):
	c_id(proto, ip1, ip2, port2) {}
	ConnectionIF3(const u_char* packet, int wildcard_port):
	c_id(packet, wildcard_port) {}
	ConnectionIF3(ConnectionID3 c_id):
	c_id(c_id) {}
	ConnectionIF3(void *p) {
		memcpy((void*)getConstKeyPtr(), p, getKeySize());
	}
	virtual ~ConnectionIF3() {};
	virtual uint32_t hash() const {
		return c_id.hash();
	}
	uint32_t getInt() const {
		return 0;
	}
	virtual const char* getConstKeyPtr() const {
		return (const char*)c_id.getConstV();
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
	void getBPFStr(char *, int) const;
	ConnectionID3 *getCID() {
		return &c_id;
	}
	bool operator==(const IndexField& other) const {
		return c_id==((ConnectionIF3*)&other)->c_id;
	}
	bool operator==(const char* other_key) const {
		//printf("ConnectionIF::operator==(const char* other_key)\n");
		return c_id==*(ConnectionID3 *)other_key;
	}
private:
	ConnectionID3 c_id;
	static std::string pattern_connection3;
	static pcrecpp::RE re;
};


class ConnectionIF2: public IndexField {
public:
	ConnectionIF2(uint32_t ip1, uint32_t ip2):
	c_id(ip1, ip2) {}
	ConnectionIF2(const u_char* packet):
	c_id(packet) {}
	ConnectionIF2(ConnectionID2 c_id):
	c_id(c_id) {}
	ConnectionIF2(void *p) {
		memcpy((void*)getConstKeyPtr(), p, getKeySize());
	}
	virtual ~ConnectionIF2() {};
	virtual uint32_t hash() const {
		return c_id.hash();
	}
	uint32_t getInt() const {
		return 0;
	}
	static IndexField* parseQuery(const char *query);

	virtual const char* getConstKeyPtr() const {
		return (const char*)c_id.getConstV();
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
	void getBPFStr(char *, int) const;
	ConnectionID2 *getCID() {
		return &c_id;
	}
	bool operator==(const IndexField& other) const {
		return c_id==((ConnectionIF2*)&other)->c_id;
	}
	bool operator==(const char* other_key) const {
		return c_id==*(ConnectionID2 *)other_key;
	}
private:
	ConnectionID2 c_id;
	static std::string pattern_connection2;
	static pcrecpp::RE re;
};

inline IPAddress* IPAddress::genKey (const u_char* packet, int keynum)
{
	switch (keynum) {
		case 0: return new SrcIPAddress(packet);
		case 1: return new DstIPAddress(packet);
		default: return NULL;
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

