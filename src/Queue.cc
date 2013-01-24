#ifndef QUEUE_CC
#define QUEUE_CC

#include "Queue.hh"

/*
template <class T> Queue<T>::Queue(){
}
 
template <class T> Queue<T>::~Queue(){
}
*/

template <class K, class V> HashQueue<K, V>::HashQueue(uint32_t hash_size):
hash(hash_size) {}

template <class K, class V> HashQueue<K, V>::~HashQueue() {}

template <class K, class V>
bool HashQueue<K, V>::isElement(K& k) {
	return hash.isElement(k);
}


template <class K, class V>
void HashQueue<K, V>::erase(K& k) {
	iterator_t it=hash.lookup(k);
	hash.erase(k);
	nodes.erase(it);
}


template <class K, class V>
void HashQueue<K, V>::eraseInQueue(iterator_t i) {
	if (i->connected_to_hash)
		hash.erase(i->hash_iterator);
	nodes.erase(i);
}


// insert (K, V)-pair, overwriting existing with same K
template <class K, class V>
bool HashQueue<K, V>::insert_or_update(K& k, V& v) {
	bool insert=true;
	iterator_t i=hash.lookup(k);
	if (i!=NULL) {
		nodes.erase(i);
		insert=false;
		//// i->disconnectHash();
	}
	nodes.push_front(HashQueueNode<K, V>(v));
	i=nodes.begin();
	i->connectToHash(hash.add_or_update(k, i));
	return insert;
}


/* insert (K, V)-pair
 * If K already exists, overwrite Hash Entry K, insert new V.
 * This gives duplicate Queue Entries, a lookup will return
 * the most recent insertion.
 * Returns an iterator to the most recent entry prior to this
 * insertion.
 */
template <class K, class V>
typename HashQueue<K, V>::iterator_t HashQueue<K, V>::insert(K& k, V& v) {
	iterator_t i=hash.lookup(k);
	if (i!=NULL) {
		i->disconnectHash();
		nodes.erase(i);
	}
	nodes.push_front(v);
	iterator_t n=nodes.begin();
	n->connectToHash(hash.add_or_update(k, n));
	return i;
}


// get V by K, move (K,V) to begin of queue
template <class K, class V>
V HashQueue<K, V>::update_get(K& k) {
	iterator_t i=hash.lookup(k);
	if (i!=NULL) {
//		HashQueueNode<K, V> hqn=*i;
		V v=i->v;
		nodes.erase(i);
		nodes.push_front(v);
		i=nodes.begin();
		i->connectToHash(hash.add_or_update(k, i));
		return v;
	}
	return NULL; /// was V()
}


template <class K, class V>
V HashQueue<K, V>::first() {
	return nodes.front().v;
}


template <class K, class V>
V HashQueue<K, V>::last() {
	return nodes.back().v;
}


template <class K, class V>
typename HashQueue<K, V>::iterator_t HashQueue<K, V>::lastIterator() {
	return --nodes.end();
}


template <class K, class V>
V HashQueue<K, V>::lookup(K& k) {
	//  printf("HashQueue<K, V>::lookup(%s) -> ", k->getStr().c_str());
	iterator_t i=hash.lookup(k);
	if (i!=NULL) {
		//	  printf("found\n");
		return i->v;
	} else {
		//	  printf("not found\n");

		return NULL; /// was V()
	}
	//	return (i!=NULL)?(i->v):NULL;
}



#endif
