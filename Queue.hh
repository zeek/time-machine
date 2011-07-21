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

// $Id: Queue.hh 251 2009-02-04 08:14:24Z gregor $ 

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
