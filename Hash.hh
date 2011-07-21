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

// $Id: Hash.hh 251 2009-02-04 08:14:24Z gregor $

#ifndef HASH_HH
#define HASH_HH

#include <list>

#include "Connection.hh"
#include "Queue.hh"

template <class K, class V> class HashNode {
public:
	HashNode(K, V&);
	~HashNode();
	K k;
	V v;
	bool operator==(const K& k1) const;
	bool operator!=(const K& k1) const;
};

template <class K, class V> class Hash {
public:
	Hash(size_t size);
	~Hash();
	typedef std::list<HashNode<K, V> > table_cell_t;
	struct iterator_t {
		iterator_t(table_cell_t* c, typename table_cell_t::iterator i):
		c(c), i(i) {};
		iterator_t() {};
		//	  iterator_t(const iterator_t&) {};
		table_cell_t* c;
		typename table_cell_t::iterator i;
	};
	class iterator;
	friend class iterator;
	/** Nested iterator to loop through all Hash entries. 
	 * The iterator will only give the values (V) stored in the 
	 * Hash. There's no key iterator
	 */
	class iterator {
		public:
			iterator():
					h(NULL) {
			};
			iterator(const Hash<K,V>* h1): 
					h(h1),
					bucket(0), 
					it(h1->table[0].begin()) {
				if(it == h1->table[0].end()) // First bucket is empty. Go to the first non empy bucket 
					operator++();
			};
			iterator(const Hash<K,V>* h1, bool): 
					h(h1),
					bucket(h1->size-1),
					it(h1->table[h1->size-1].end()) {
			};
			iterator& operator=(const iterator& it2) {
				h = it2.h;
				bucket = it2.bucket;
				it = it2.it;
				return *this;
			};
			V& operator*() const {
				return it->v;
			};
			iterator& operator++() { // Prefix form
				if (it==h->table[h->size-1].end()) {
					return *this;
				}
				it++;
				while (it==h->table[bucket].end()) {
					bucket++;
					if (bucket>=h->size) {
						bucket=h->size-1; 
						it=h->table[h->size-1].end();
						break; // end of the line reached
					}
					it = h->table[bucket].begin();
				} 
				return *this;
			}
			iterator operator++(int) {  // Postfix form
				iterator tmp = *this;
				if (it==h->table[h->size-1].end()) {
					return *this;
				}
				operator++();
				return tmp;
			}
			bool operator== (const iterator &it2) {
				return (bucket==it2.bucket && it==it2.it);
			}
			bool operator!= (const iterator &it2) {
				return !(bucket==it2.bucket && it==it2.it);
			}
		private: 
			const Hash<K,V> *h;
			uint32_t bucket;
			typename table_cell_t::iterator it;
	};

	iterator begin() { return iterator(this); };
	iterator end() { return iterator(this, true); };
	table_cell_t* table;
	uint32_t size;

	int clear(); 
	iterator_t add_or_update(K, V);
	int getNumEntries() { return numEntries; };
	int getNumBuckets() { return size; };
	void erase(K);
	void erase(iterator_t&);
	V lookup(const K);
	bool isElement(const K);
	void debugPrint();
	void debugPrint(FILE *fp);

protected:
	int numEntries;
	inline table_cell_t* find_table_entry(const K k);
	inline typename table_cell_t::iterator find_iterator(table_cell_t* entry, const K k);
};

#include "Hash.cc"

#endif
