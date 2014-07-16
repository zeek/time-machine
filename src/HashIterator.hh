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
			uint64_t bucket;
			typename table_cell_t::iterator it;
	};

	iterator begin() { return iterator(this); };
	iterator end() { return iterator(this, true); };
	table_cell_t* table;
	uint64_t size;

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

//#include "Hash.cc"

#endif
