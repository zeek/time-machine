#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sched.h>

#include "tm.h"
#include "types.h"
#include "FifoMem.hh"
#include "Query.hh"
#include "Index.hh"


FifoMem::FifoMem(uint64_t size): size(size), oldestTimestamp(0), newestTimestamp(0) {
	start=(unsigned char *)malloc(size+MAXCAPLEN+sizeof(struct pcap_pkthdr)+1);
	assert(start);
	end=start+size;
	buffer_end = start + size + MAXCAPLEN+sizeof(struct pcap_pkthdr);
	/*
	  unsigned char c=0;
	  for (unsigned char *i=buf_start; i<buf_start+size; i++)
	  *i=c++;
	  */

	// determine align positions
	align_gran=200;
	align_num=(size+MAXCAPLEN+sizeof(struct pcap_pkthdr))/align_gran + 1;
	align=(pkt_ptr*)malloc(align_num*sizeof(pkt_ptr));
	// DEBUG
	for (uint64_t i=0; i<align_num; i++) 
		align[i]=start;
	s=wp=lp=start;
	a_s=a_lp=a_max=0;
	a_next=start+align_gran;
	held_pkts=tot_pkts=tot_pktbytes=tot_lost_pkts=tot_lost_pktbytes=held_bytes=0;
	eviction_handler=NULL;

	pthread_mutex_init(&lock_mutex, NULL);
}


FifoMem::~FifoMem() {
	pthread_mutex_destroy(&lock_mutex);
	free(start);
	free(align);
}


/* Invariants after returning from addPkt
 *    - lp points to the mem location where the last written packet lies
 *    - wp points to the mem location where the next packet will be written
 *    - align[a_lp] points to a mem location where a packet starts and that
 *      is close to lp
 *    - all align entries between a_s and a_lp are valid:
 *         case a: a_s < a_lp. clear.
 *         case b: a_lp<a_s   all entries between a_lp and align_num-1 and 
 *                 0 and a_s are valid
 *        TODO: WHAT HAPPENS IF a_s == a_lp ?? WHEN IS THIS THE CASE???
 *
 */
void FifoMem::addPkt(const struct pcap_pkthdr *header,
					 const unsigned char *packet) {
	if (size>0) {

		lock();

		unsigned int pktlen=sizeof(struct pcap_pkthdr)+header->caplen;

		while (held_pkts && (wp<=s && (wp+pktlen)>=s)) {
			/* only when wp is lower than s can there be a problem. if wp>s
			 * wp will hit end _before_ reaching s. when this happend, wp 
			 * wraps around and is thus <= s
			 */
			// pktEviction eventually calls popPkt() which advances s
			if (pktEviction()) continue;
			assert(false);
		}

		/* Write the packet to the FIFO */
		oldestTimestamp = to_tm_time(&((struct pcap_pkthdr*)s)->ts);
		newestTimestamp = to_tm_time(&(header->ts));
		memcpy(wp, header, sizeof(struct pcap_pkthdr));
		memcpy(wp+sizeof(struct pcap_pkthdr), packet, header->caplen);

		/* Adjust align array and a_lp 
		 * wp now points to the packet that we just wrote */
		if (lp > wp) { 
			/* previous call to addPkt wrapped wp 
			   Must make sure that remainder of align array points to a valid addr */
			assert(wp == start);
			for (uint64_t i=a_lp+1; i<align_num; i++) {
				align[i] = lp;
			}
			/* wrap a_lp */ 
			a_lp = 0;
			align[0] = start;
			a_next = start + align_gran;
		}
		else {

			while (a_next<=wp) {
				a_lp++;
				a_next+=align_gran;
				align[a_lp] = wp;
			}
		}

		/* Adjust wp and lp */
		lp=wp;
		wp+=pktlen;

		if (wp>=end) {
			/* Wrap around */
			wp=start;
		}

		tot_pkts++;
		tot_pktbytes+=header->caplen;
		held_pkts++;
		held_bytes+=header->caplen;


		unlock();

	} // if (size>0)
}


pkt_ptr FifoMem::getWp() const {
	return wp;
}


pkt_ptr FifoMem::getS() const {
	return s;
}


uint64_t FifoMem::getTotPkts() const {
	return tot_pkts;
}


uint64_t FifoMem::getTotPktbytes() const {
	return tot_pktbytes;
}


uint64_t FifoMem::getTotLostPkts() const {
	return tot_lost_pkts;
}


uint64_t FifoMem::getTotLostPktbytes() const {
	return tot_lost_pktbytes;
}


uint64_t FifoMem::popPkt() {
	uint64_t n=0;
	if (held_pkts) {
		n=((struct pcap_pkthdr *)s)->caplen;
		s+=sizeof(struct pcap_pkthdr)+((struct pcap_pkthdr *)s)->caplen;
		if (s>=end) {
			s=start;
			a_s=0;
		} 
		else {
			while (align[a_s+1]<s) {
				a_s++;
			}
		}
		held_pkts--;
		held_bytes-=n;
	}
	return n;
}

uint64_t FifoMem::pktEviction() {
	if (eviction_handler)
		return eviction_handler->pktEviction();
	else
		return 0;
}


void FifoMem::setEvictionHandler(FifoMemEvictionHandler *h) {
	eviction_handler=h;
}


tm_time_t FifoMem::getOldestTimestamp() const {
	return oldestTimestamp;
}
tm_time_t FifoMem::getNewestTimestamp() const {
	return newestTimestamp;
}


void FifoMem::debugPrint() const {
	debugPrint(stderr);
}
	
void FifoMem::debugPrint(FILE *fp) const {
	fprintf(fp, "\nstart = %ld  s = %ld  wp = %ld  lp = %ld  end = %ld  held_pkts = %lu\n",
		   (long int)(start-start), (long int)(s-start), (long int)(wp-start), (long int)(lp-start), (long int)(end-start), (long int)held_pkts);
	fprintf(fp, "a_next = %ld  a_wp = XX  a_s = %"PRIu64" a_lp = %"PRIu64" a_max = %"PRIu64"\n",
		   (long int)(a_next-start), a_s, a_lp, a_max);

	/*
	align[i] ?
	to_tm_time(&((pcap_pkthdr*)align[i])->ts) :
	0
	*/

	/*
	#define ARRLEN 4
	#define WIDTH 70
	const pkt_ptr *ptrs[] = { &start, &s, &wp, &end };
	const char *names[] = { "start", "s", "wp", "end" };
	char out[ARRLEN][WIDTH+1];
	for (int i=0; i<ARRLEN; i++) {
	  memset(out[i], ' ', WIDTH); out[i][WIDTH]='\0';
	}
	for (int i=0; i<ARRLEN; i++) {
	  int pos = (int)( (double)(*ptrs[i]-start)/(end-start)*(WIDTH-1) );
	  if (pos < 0 || pos >= WIDTH) continue;
	  out[0][pos] = '|';
	  if (pos+strlen(names[i]) > WIDTH) pos -= pos+strlen(names[i]) - WIDTH;
	  int j;
	  for (j=1;
	j<ARRLEN && strspn(out[j]+pos, " ") >= strlen(names[i]);
	j++);
	  sprintf(out[j]+pos, names[i]);
	}
	for (int i=0; i<ARRLEN; i++) printf("%s\n", out[i]);
	*/
}

inline tm_time_t pkt_t (pkt_ptr p) {
	return to_tm_time(&((struct pcap_pkthdr*)p)->ts);
}

inline pkt_ptr FifoMem::block (pkt_ptr p) {
	assert (p<end+size);
	return p<end ? p : p-size;
}

int FifoMem::bin_search (pkt_ptr *p, tm_time_t t, bool floor) {
	uint64_t a0=a_s, a1=a_lp, at;
	pkt_ptr pt;
	uint64_t my_a0, my_a1;

	my_a0 = a0<align_num ? a0 : a0-align_num;
	my_a1 = a1<align_num ? a1 : a1-align_num; 

	tmlog(TM_LOG_DEBUG, "query", "bin_search(%lf, %d) called: a0=%lf, a1=%lf", 
			t, floor, pkt_t(align[my_a0]), pkt_t(align[my_a1]));
	if (a1<a0) a1+=align_num;

	if ( t <= pkt_t(align[a0<align_num ? a0 : a0-align_num] )
			//       && t >= pkt_t(s)
	   ) {
		*p=s;
		return 1;
	} else if ( t > pkt_t(align[a1<align_num ? a1 : a1-align_num] )
				//	      && t <= pkt_t(lp)
			  ) {
		*p=align[a1<align_num ? a1 : a1-align_num];
		return 0;
	};
	
	do {
		my_a0 = a0<align_num ? a0 : a0-align_num;
		my_a1 = a1<align_num ? a1 : a1-align_num; 
		tmlog(TM_LOG_DEBUG, "query", "bin_search: a0=%lf, a1=%lf", 
			pkt_t(align[my_a0]), pkt_t(align[my_a1]));
		at=(a0+a1)/2;
		pt=align[at<align_num ? at : at-align_num];
		tm_time_t tt=pkt_t(pt);
		if ( pkt_t(align[a0<align_num ? a0 : a0-align_num]) == t ) {
			*p=align[a0<align_num ? a0 : a0-align_num];
			return 3;
		} else if ( pkt_t(align[a1<align_num ? a1 : a1-align_num]) == t ) {
			*p=align[a1<align_num ? a1 : a1-align_num];
			return 4;
		} else if ( tt > t ) a1=at;
		else /* tt < t */ a0=at;
	} while (a0<a1-1);

	if (floor) *p = align[a0<align_num ? a0 : a0-align_num];
	else *p=align[a1<align_num ? a1 : a1-align_num];

	return 5;

}
//FIXME: When the interval is larger than the timepsan of packets
//in the FifoMem, we will get problems!!!
//
//CALLER MUS HOLD THE LOCK ON FIFO MEM!!
uint64_t FifoMem::query(QueryRequest *qreq, QueryResult *qres,
					IntervalSet *interval_set) {
	pkt_ptr p, p_orig, p_old;
	uint64_t matches = 0;
	ConnectionID4 *c_id;
	int intcnt=0, iter=0;
	bool p_will_wrap;
	tm_time_t last_match_ts = 0.0;

	// lock();
	if (!held_pkts)
		return 0;


	for (IntervalSet::iterator i=interval_set->begin();
			i!=interval_set->end(); i++) {
		intcnt++;
		if ((qreq->getT1() < i->getStart()-1e-3) || (qreq->getT0() > i->getLast()+1e-3)) {
			tmlog(TM_LOG_DEBUG, "query", "%d Skipping Interval %i 0f %i: [%lf, %lf]", intcnt, interval_set->getNumIntervals(), qres->getQueryID(), i->getStart(), i->getLast());
			continue;
		}
		int found;
		tmlog(TM_LOG_DEBUG, "query", "%d New Interval %i of %i: [%lf, %lf]", intcnt, interval_set->getNumIntervals(),
					qres->getQueryID(), i->getStart(), i->getLast());
		if (! (found=bin_search(&p, i->getStart(), true)))
			tmlog(TM_LOG_WARN, "query", "%d FifoMem::query: %lf not found", 
					qres->getQueryID(), i->getStart());

		if (found) {
			p_orig = p;
			tmlog(TM_LOG_DEBUG, "query", "%d First packet after bin-search is: ts=%lf, addr=%p, offset=%zu len=%u",
					qres->getQueryID(), pkt_t(p), p, p-start, ((struct pcap_pkthdr *)p)->caplen);
			if (p<start || p>=end+MAXCAPLEN+sizeof(struct pcap_pkthdr)+1) {
				tmlog(TM_LOG_DEBUG, "query", 
					"%d GM_FifoMem::query: found=%d, t=%lf, a_s=%lf, a_lp=%lf,  Int: %d of %d  Pointer from bin_search out of bounds: p=%p, start=%p, end+=%p", 
					qres->getQueryID(), found, i->getStart(), pkt_t(align[a_s]), pkt_t(align[a_lp]),
					intcnt, interval_set->getNumIntervals(),  p, start, end+MAXCAPLEN+sizeof(struct pcap_pkthdr)+1);
				return matches;
			}

			/* Check if p will wrap around before it reaches lp. 
			 * If it will wrap, the loop can increments p until it wraps, only
			 * then does it have to check against lp. 
			 * THIS IS INCREDIBLY UGLY, BUT THE WHOLE FifoMem WIlL BE REWRITTEN 
			 * ANYWAY */
			if (p<=lp)  
				p_will_wrap = false;
			else 
				p_will_wrap = true; 

			iter=1;
#ifdef TM_HEAVY_DEBUG
			assert(p<=end); 
			assert(p>=start);
#endif
			while ( (p_will_wrap || (p<=lp)) 
					&& pkt_t(p) <= i->getLast() ) {
				if (qreq->matchPkt(p) && last_match_ts < pkt_t(p))  {
					qres->sendPkt(p);
					if (qreq->isSubscribe()) {
						c_id = new ConnectionID4(block(p)+sizeof(struct pcap_pkthdr));
						storage->getConns().subscribe(c_id, qres);
						delete c_id;
					}
#ifdef TM_HEAVY_DEBUG
					tmlog(TM_LOG_DEBUG, "query", "%d Match: ts=%lf, addr=%p, offset=%zu len=%u, matchcnt=%zu", 
							qres->getQueryID(), pkt_t(p), p, p-start, ((struct pcap_pkthdr *)p)->caplen, matches);
#endif
					last_match_ts = pkt_t(p);
					matches++;
				}
				else if (qreq->matchPkt(p)) {  /* duplicate */
					tmlog(TM_LOG_NOTE, "query", "%d Duplicate avoided: ts=%lf, addr=%p, offset=%zu len=%u, matchcnt=%zu",
							qres->getQueryID(), pkt_t(p), p, p-start, ((struct pcap_pkthdr *)p)->caplen, matches);
				}
				p_old = p;
				p+=sizeof(struct pcap_pkthdr)+
					((struct pcap_pkthdr*)block(p))->caplen;
				if (p<start || p>=end+MAXCAPLEN+sizeof(struct pcap_pkthdr)+1) {
					tmlog(TM_LOG_DEBUG, "query", 
						"%d GM_FifoMem::query: ifound=%d, t=%lf, a_s=%lf, a_lp=%lf, Int: %d of %d. Iter %d.  Pointer out of bounds: p_orig=%p, p_old=%p, p=%p, start=%p, end=%p", 
						qres->getQueryID(), found, i->getStart(), pkt_t(align[a_s]), pkt_t(align[a_lp]),
						intcnt, interval_set->getNumIntervals(), iter,  p_orig, p_old, p, start, end);
					return matches;
				}
				if (p>end) {
					assert(p_will_wrap);
					p=start; //wrap around
					p_will_wrap=false;
				}
				iter++;
			}
		}
	}
	//DEBUG:
	//fprintf(stderr, "FifoMem::query had %lu maches\n", matches);

	//unlock();
	return matches;
}


void FifoMem::lock() {
	pthread_mutex_lock(&lock_mutex);
}

void FifoMem::unlock() {
	pthread_mutex_unlock(&lock_mutex);
}

