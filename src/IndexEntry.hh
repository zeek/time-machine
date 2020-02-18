#ifndef INDEXENTRY_HH
#define INDEXENTRY_HH

#include <fstream>
#include <deque>
#include <vector>
#include <sstream>

#include "tm.h"
#include "types.h"
#include "IndexField.hh"

/**
 */
class IndexEntry;

class Interval {
public:
	Interval(tm_time_t s, tm_time_t l): next(NULL), start(s), last(l) {  };
	Interval(const Interval& in): next(NULL), start(in.start), last(in.last) { };
	virtual ~Interval() {  };

	inline tm_time_t& getStart() const {
		return const_cast<tm_time_t&>(start);
	}
	inline tm_time_t& getLast() const {
		return const_cast<tm_time_t&>(last);
	}
	inline const Interval* getNextPtr() const {
		return next;
	}

	friend class IndexEntry;

	// do i need these here?
	//  Interval* getNext() { return NULL; };
	//  Interval* getPrevious() { return NULL; };

	/*
	  virtual void setNext(Interval* n)=0;
	  virtual void setPrevious(Interval* p)=0;
	*/
	void update(tm_time_t t) {
		last=t;
	}
	std::string getStr() const {
		std::stringstream ss;
		ss.setf(std::ios::fixed);
		ss << "[" << getStart()
		<< " , " << getLast()
		<< "]";
		return ss.str();
	}

protected:
	Interval *next;
	tm_time_t start;
	tm_time_t last;
};


/** An IndexEntry is the data object containing the intervals
 *  for a single entry in an index. 
 *  IndexEntries are used as <V> *  for the Hashtable.
 *
 *  see IndexHash.hh for information on why we store the tree pointers
 *  in here.
 *
 *  see Index.hh for information on why we have a timestamp and 
 *  intervals here. 
 * 
 */
class IndexHash;
class IndexEntry {
public:
	IndexEntry(IndexField* key, tm_time_t t0, tm_time_t t1) :
	key(key), icount(1), intlist(Interval(t0,t1)) {
        //tmlog(TM_LOG_NOTE, "IndexEntry:IndexEntry()", "Creating an IndexEntry instance with an IndexField type that has timestamp %f", key->ts);
		curint = &intlist;
		parent = left = right = NULL;
		col_next = col_prev = NULL;
		avlbal=0;
	};
	virtual ~IndexEntry() {
        //tmlog(TM_LOG_NOTE, "IndexEntry, deleting", "starting to delete IndexEntry type");  
		Interval *ci;
		Interval *ni;
        //tmlog(TM_LOG_NOTE, "IndexEntry, deleting", "about the delete the key, which is of IndexField type");
		delete key;
        key = NULL;
		ci=intlist.next;
		while(ci) {
            //tmlog(TM_LOG_NOTE, "IndexEntry, deleting", "deleting the linked list of intervals");
			ni = ci->next;
			delete ci;
			ci = ni;
		}
	};
	inline IndexField* getKey() {
        //tmlog(TM_LOG_NOTE, "IndexEntry:getKey()", "accessing IndexEntry's getKey() method");
		return key;
	}
	virtual int update_time(tm_time_t t, tm_time_t d_t, tm_time_t iat) {
		if (t - curint->getLast() < d_t) {
			curint->getLast() = t;
		}
		else {
			Interval *ni = new Interval(t-IDX_PKT_SECURITY_MARGIN*iat,t);
			curint->next = ni;
			curint = ni;
			icount++;
		}
		return icount;
	};
	inline Interval *getIntList() {
		return &intlist;
	};
	virtual std::string getStr() const {
        //tmlog(TM_LOG_NOTE, "IndexEntry:getStr()", "accessing IndexEntry's getStr() method");
		std::stringstream ss;
		ss.setf(std::ios::fixed);
		ss << "key: " << key->getStr()
		// FIXME: << "  previous " << previous
		// FIXME: << "  next " << next
		;
		return ss.str();
	};
	struct PQcompare : public std::binary_function<IndexEntry*, IndexEntry*, bool>
	{
		inline bool operator()(IndexEntry* a, IndexEntry* b) {
			if (memcmp(a->getKey()->getConstKeyPtr(), 
						b->getKey()->getConstKeyPtr(), a->getKey()->getKeySize()) < 0) 
				return true;
			else
				return false;
		}
	};
	friend class IndexHash;
protected:
	IndexField* key;
	int icount;
	// linked list of Intervals. intlist is the list head.
	// curint points to the currently active interval 
	// Since most index entries contain only one interval we use
	// the listheadd to store the first interval. 
	Interval intlist; 
	Interval *curint;

	// These pointer build a binary search tree. The tree is traversed inorder
	// to get the sorted entries when writing to disk
	IndexEntry *parent;
	IndexEntry *left;
	IndexEntry *right;
	int avlbal; 

	// These pointers are the collision lists for the Hashtable
	IndexEntry *col_next;
	IndexEntry *col_prev;
};


/* declarations are in header because only template code can be in
 * Index.cc.  See Index.cc header.
 *
 * An IntervalSet is "returned" from the index lookup functions 
 * (lookupMem, lookupDisk). This InteervalSet is then passed to the
 * query function in Fifo.cc
 *
 * The Intervals stored in an IntervalSet are sorted in ascending order.
 * Furthermore IntervalSet ensures that intervals don't overlap (by merging
 * intervals if necessary). 
 */
class IntervalSet {
public:
	IntervalSet () : merge_limit(5e-3) {} ;
	int getNumIntervals() {
		return intervals.size();
	}
	struct interval_lt {
		bool operator()(const Interval &i1, const Interval &i2) const {
			return i1.getStart() < i2.getStart();
		}
	};
	typedef std::deque<Interval>::iterator iterator;
	iterator begin() {
		return intervals.begin();
	}
	iterator end() {
		return intervals.end();
	}
	bool empty() {
		return intervals.empty();
	}
	void add(IndexEntry *ie) {
		const Interval *ci = ie->getIntList();
		while(ci) {
			add(*ci);
			ci = ci->getNextPtr();
		}
	} 
	/* Add an interval to the IntervalSet. Ensure that the intervals stored in
	 * *this are sorted in ascending order. Also ensure that the intervals don't 
	 * overlap. Intervals are also merged, if the differnce between two intervals
	 * is less then merge_limit, 
	 * Due to limitations on the iterators for list and deque, this implementation
	 * (esp. the merging of overlapping intervals) is highly inefficient. But since I 
	 * expect IntervalsSets to be rather small, I accept this speed penalty. If this
	 * beomces a problem, we have to build our own list implementation with decent 
	 * iterators
	 */
	void add(Interval new_int) {
		iterator it;
		new_int.getLast() += 1e-5; //Protect us from float precisous problemns
		if (intervals.empty()) {
			intervals.push_back(new_int);
			return;
		}
		for (it = begin(); it!=end() && (*it).getStart() < new_int.getStart(); it++)
			;
		// insert before it
		intervals.insert(it, new_int); 
		// Merge overlapping intervals 
		it = begin();
		while(it+1!=end()) {
			if ((*it).getLast()+merge_limit > (*(it+1)).getStart()) {
				if ((*it).getLast()+merge_limit > (*(it+1)).getLast()) {
					intervals.erase(it+1);
				}
				else {
					(*it).getLast() = (*(it+1)).getLast();
					intervals.erase(it+1);
				}
				// F**king stl containers. A deque iterator is invalidated, when
				// an element is erased in the middle of the queue and an
				// ordinary list doesn't have a RandonAccessIterator, i.e. an
				// iterator for a list doesn't support '+' and 'i'. God knows
				// why.
				// So: the iterator is invalid but we may still have intervals
				// to merge (esp. if the newly added interval spans several orginial
				// intervals. To start the merging again. 
				it = begin();
				continue;
			}
			it++;
		}
	}

	std::string getStr() {
		std::stringstream ss;
		for (iterator i=begin();
				i!=end(); i++)
			ss << (i==begin()?"":", ")
			<< i->getStr();
		return ss.str();
	}
private:
	//w need a deque, since only a list doesn't have a RandomAccessItertaor
	std::deque<Interval> intervals;
	tm_time_t merge_limit;
};


#endif
