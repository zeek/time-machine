#ifndef HASH_CC
#define HASH_CC

#include <algorithm>
#include <assert.h>
#include <stdio.h>

#include "Hash.hh"

template <class K, class V>
inline Hash<K, V>::Hash(size_t size):
size(size),
numEntries(0) {
	table=new table_cell_t[size];
}

template <class K, class V>
inline Hash<K, V>::~Hash() {
	delete []table;
}

template <class K, class V>
inline HashNode<K, V>::HashNode(K k, V& v):
k(k), v(v) {}

template <class K, class V>
inline HashNode<K, V>::~HashNode() { };

template <class K, class V>
inline bool HashNode<K, V>::operator==(const K& k1) const {
	return *k1==*k;
}

template <class K, class V>
inline bool HashNode<K, V>::operator!=(const K& k1) const {
	return *k1!=*k;
}

// typedef template Hash<K, V>::iterator_t hash_k_v_iterator_t;

template <class K, class V>
inline int Hash<K, V>::clear() {
	int k=0;	
	/* very ugly hack */
	numEntries=0;
	for (unsigned i=0; i<size; i++) { 
		while(!table[i].empty()) {
			delete table[i].back().k;
			delete table[i].back().v;
			table[i].pop_back();
			k++;
		}
	}
	return k;


}

/* Add (K,V) pair, updating existing K with new V
 * Returns the iterator (pointer) to its place in hash
 */
template <class K, class V>
inline typename Hash<K, V>::iterator_t Hash<K, V>::add_or_update(K k, V v) {
	// look up the entry in hashtable
	table_cell_t* entry=find_table_entry(k);
	// search in list in hashtable entry
	typename table_cell_t::iterator	f=find_iterator(entry, k);
	if (f!=entry->end())
		f->v=v;
	else {
		numEntries++;
		entry->push_back(HashNode<K, V>(k, v));
		f=find_iterator(entry, k);
	}
	assert(f!=entry->end());
	return iterator_t(entry, f);
	//return (iterator_t){entry, f};
}

template <class K, class V>
inline void Hash<K, V>::erase(K k) {
	// look up the entry in hashtable
	table_cell_t* entry=find_table_entry(k);
	// search in list in hashtable entry
	typename table_cell_t::iterator	f=find_iterator(entry, k);
	if (f!=entry->end()) {
		//	  delete((*f).k);
		numEntries--;
		entry->erase(f);
	}
	//	delete((*f).k);
}

template <class K, class V>
inline void Hash<K, V>::erase(iterator_t& it) {
	assert(!it.c->empty());
	assert(it.i!=it.c->end());
	numEntries--;
	it.c->erase(it.i);
	//	delete((*(it.i)).k);
}

template <class K, class V>
inline V Hash<K, V>::lookup(const K k) {
	// look up the entry in hashtable
	table_cell_t* entry=find_table_entry(k);
	// search in list in hashtable entry
	typename table_cell_t::iterator	f=find_iterator(entry, k);
	if (f!=entry->end()) {
//		printf("Hash::lookup(): found\n");
		return f->v;
	} else {
//		printf("Hash::lookup(): not found\n");
//		throw 1;
		return NULL;
	}
}

template <class K, class V>
inline bool Hash<K, V>::isElement(const K k) {
	// look up the entry in hashtable
	table_cell_t* entry=find_table_entry(k);
	// search in list in hashtable entry
	typename table_cell_t::iterator	f=find_iterator(entry, k);
	return f!=entry->end();
}

template <class K, class V>
inline typename Hash<K, V>::table_cell_t* Hash<K, V>::find_table_entry(const K k) {
	return &table[(k->hash())%size];
}


template <class K, class V>
inline typename Hash<K, V>::table_cell_t::iterator Hash<K, V>::find_iterator(
	table_cell_t* entry, const K k) {
	typename Hash<K, V>::table_cell_t::iterator i=entry->begin();
	for (; i!=entry->end() && !(*((*i).k)==*k) ; i++);
	return i;

	// this only worked with no-pointer k
	//	return find(entry->begin(), entry->end(), k);
}

template <class K, class V>
void Hash<K, V>::debugPrint() {
	debugPrint(stderr);
}

template <class K, class V>
void Hash<K, V>::debugPrint(FILE *fp) {
	for (uint32_t i=0; i<size; i++)
		fprintf(fp, "%u\t%u\n", i, table[i].size());
}

#endif
