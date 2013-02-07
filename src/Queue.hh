#ifndef QUEUE_HH
#define QUEUE_HH

#include <list>

#include "Hash.hh"

/*
template <class T> class Queue {
public:
	Queue();
	~Queue();
	std::list<T> nodes;
	typedef typename list<T>::iterator iterator;
	void insert(T& t);
};
*/

template <class K, class V> class HashQueue;

template <class K, class V> class HashQueueNode {
public:
	HashQueueNode(V v): v(v), connected_to_hash(false) {};
//	HashQueueNode(V v, typename HashQueue<K,V>::hash_t::iterator_t hash_iterator):
//		v(v),	hash_iterator(hash_iterator), connected_to_hash(true) {};
	void connectToHash(typename HashQueue<K,V>::hash_t::iterator_t hash_iterator) {
		this->hash_iterator=hash_iterator;
		connected_to_hash=true;
	};
	void disconnectHash() {
		connected_to_hash=false;
	};
	V v;
	bool connected_to_hash;
	typename HashQueue<K,V>::hash_t::iterator_t hash_iterator;
	K getK() {
		return (connected_to_hash ? hash_iterator.i->k : NULL);
	}
	const K getConstK() const {
		return (connected_to_hash ?
				const_cast<K>(hash_iterator.i->k) : NULL);
	}

};


template <class K, class V> class Hash;

template <class K, class V> class HashQueue {
public:
	HashQueue(uint32_t hash_size);
	~HashQueue();

	// Queue
	std::list<HashQueueNode<K,V> > nodes;
	typedef typename std::list<HashQueueNode<K,V> >::iterator iterator_t;
	typedef typename std::list<HashQueueNode<K,V> >::const_iterator
	const_iterator_t;

	// Hash
	typedef Hash<K, iterator_t> hash_t;
	hash_t hash;

	bool isElement(K&);
	void erase(K&);
	void eraseInQueue(iterator_t);
	// returns true on insertion, false on update
	bool insert_or_update(K&, V&);
	iterator_t insert(K&, V&);
	V update_get(K&);
	V get(iterator_t i) {
		return i->v;
	}
	V first();
	V last();
	iterator_t lastIterator();
	V lookup(K&);
	bool empty() {
		return nodes.empty();
	}
};

#include "Queue.cc"

#endif
