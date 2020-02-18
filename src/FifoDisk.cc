#include <assert.h>
#include <unistd.h>
#include <pcap.h>
#include <string>
#include <pthread.h>

#include "config.h"
#include "pcapnav/pcapnav.h"

#include "tm.h"
#include "FifoDisk.hh"
#include "Query.hh"
//#include "bro_inet_ntop.h"
#include <fmt/core.h>
#include <fmt/time.h>


/***************************************************************************
 * FifoDisk
 */


/* Query and Pkt eviction interaction 
 *
 * There is a concurrency between running queries and ongoing packet
 * eviction from FifoMem to FifoDisk. 
 *
 * a) The FifoDiskFiles std::list must not be changed while a query is 
 *    in progress, because it may corrupt the list (XXX: check this).
 *    Therefore adding or deleteing files is inhibited by chcking
 *    queryInProgress()
 * b) There is a race condition between writing/flushing evicted packets
 *    to disk and querying them. It may happen that the query thread has
 *    finished searching the most recent file in FifoDisk and is
 *    therefore going to search the FifoMem. When a packet is evicted
 *    from FifoMem during this transition period that packet will not
 *    be found be the query. 
 *    To prevent this, Fifo::query will acquire the FifoMem lock
 *    before searching the last file
 *    NOTE: It may well be, that the query thread will hold
 *    the lock for too long so that the capture thread will loose
 *    packets. A better solution must be found/.
 *
 *    These protections an be enabled/disabled at compile time. 
 *    iby Default  it is DISABLED. 
 *    See tm.h 
 */

FifoDisk::FifoDisk(const std::string& classname, uint64_t size,
				   uint64_t file_size, pcap_t* pcap_handle, const char* classdir,
				   const char* filename_format, const char* classdir_format,
				   const std::string &classnameId,
				   bool size_unlimited):
		classname(classname), classdir(classdir), size(size), file_size(file_size),
		tot_bytes(0), tot_pkts(0),
		file_number(0), pcap_handle(pcap_handle),
		held_bytes(0), held_pkts(0), oldestTimestamp(0), newestTimestamp(0), queries(0),
		filename_format(filename_format), classdir_format(classdir_format),
		classnameId(classnameId),
		size_unlimited(size_unlimited) {

	pthread_mutex_init(&query_in_progress_mutex, NULL);

}


FifoDisk::~FifoDisk() {
	pthread_mutex_destroy(&query_in_progress_mutex);
	while (!files.empty()) {
		delete(files.back());
		files.pop_back();
	}
}

// from https://stackoverflow.com/a/2336245/124042
static void mkdirall(const char *dir) {
    char tmp[25600];
	char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
	}
    for (p = tmp + 1; *p; p++) {
        if(*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
            *p = '/';
        }
	}
    mkdir(tmp, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
}

// called in Fifo.c, in the pktEviction method definition
void FifoDisk::addPkt(const pkt_ptr p) {
    // if the size of the buffer block (disk size) is greater than 0
	if (size_unlimited || size>0) {
        // get the time stamp from the pcap packet header
		newestTimestamp = to_tm_time(&(((struct pcap_pkthdr*)p)->ts));
        // if the list of FifoDisk files is empty OR
        // I'm not sure why the person is who wrote that seemed so pissed - seems reasonable to me
        // if the current file size + size of the pcap_file_header struct + size of pcap packet header
        // + length of the actual packet > desired file size (impossibru to add packet!)
        // why the last file? (files.back?) this is because we push the newest file to the back 
        // pcap_file_header is the header of the pcap file. it contains some saved values for flags,
        // version of libpcap, gmt to local correction, accuracy of timestamps, snaplength, and
        // data link type - Naoki
		if (files.empty() ||
				files.back()->getCurFileSize()
				+ sizeof(struct pcap_file_header)
				+ sizeof(struct pcap_pkthdr)
				+ ((struct pcap_pkthdr*)p)->caplen > file_size) {  /* Why do we have to be THAT precise?!?!? */
			// Do not add or delete files while a query is in progress, because 
			// the file iterator of the query might get fucked up (Seth or some other developer said that, not me - Naoki). 
			// XXX: This my starve the rotation of files or generate files that
			// are way too large. Check it. 
			lockQueryInProgress();
			if (!queries) {  /* no queries in progress at the moment */
				// need new file
				if (!files.empty()) {
					// close current file which just ran full (from a previous if condition)
					files.back()->close();
                    // if the number of bytes currently held in disk ring buffer block + size of a file are greater than the disk size that was configured
                    // note that held_bytes is the number of bytes currently held in block
					// if we're not managing storage, i.e. size_unlimited, then don't remove old files.
					if ((size_unlimited && files.size() > 1) || (!size_unlimited && held_bytes+file_size > size)) {
						if (files.size() <= 1) {
							tmlog(TM_LOG_ERROR, "fifodisk", " only %lu FifoDiskFiles for %s (held_bytes=%d, file_size=%d, size=%d)", files.size(), classname.c_str(), held_bytes, file_size, size); 

						}

						// delete/drop in-memory reference to oldest file
                        // decrement the number of bytes currently in disk ring buffer block by the number of bytes in the file in the front of the list (the oldest file)
						held_bytes-=files.front()->getHeldBytes();
                        // decrement the number of packets currently in disk ring buffer block by the number of packets in the file in the front of the list (the oldest file)
						held_pkts-=files.front()->getHeldPkts();
                        // remove the oldest file, the file in the front of the list (it actually only removes the link to the file), from FifoDisk.cc
						if (size_unlimited) {
							files.front()->removeNoUnlink();
						} else {
							files.front()->remove();
						}
                        // delete the file as well (release the storage) (since we called new on it to create it)
						delete(files.front());
                        // pop the front file (I would have though unlink, pop, and then delete, but not sure)
						files.pop_front();
                        // get the new oldest time stamp
						oldestTimestamp = files.front()->getOldestTimestamp();
					}
				}
                // increment the file number
				file_number++;
                // malloc that size to create a new char array for the file name 
				char *new_file_name;
    			if (filename_format != NULL) {
					struct tm newestTimestampTM;
					time_t newestTimestampT = (time_t) newestTimestamp;
					if (localtime_r(&newestTimestampT, &newestTimestampTM) == NULL) {
	                    fprintf(stderr, "cannot get localtime for %ld\n", newestTimestampT);
					}
					std::string dirpath;
					if (classdir_format) {
						// also format/create directory path
						dirpath = fmt::format(classdir_format,
											  fmt::arg("class_name", classname), 
											  fmt::arg("class_id", classnameId), 
											  fmt::arg("newest_timestamp", newestTimestampTM)
											  );
						mkdirall(dirpath.c_str());
						dirpath += "/";
					}
					std::string fname = fmt::format(filename_format, 
													fmt::arg("class_name", classname), 
													fmt::arg("class_id", classnameId), 
													fmt::arg("newest_timestamp", newestTimestampTM)
													);
					std::string path = dirpath + fname;								
					new_file_name = strdup(path.c_str());
				} else {
					// string size of the file name
					const int strsz=classname.length()+30;
					new_file_name=(char*)malloc(strsz);
		            // do a safe sprintf to create new_file_name
					snprintf(new_file_name, strsz, "%s_%.6f",
							classname.c_str(), newestTimestamp);
				}

                if (chdir(classdir)) {
                    fprintf(stderr, "cannot class chdir to %s\n", classdir);
                    //return;
                }


                // push back the newest disk file into the list of files
				files.push_back(new FifoDiskFile(new_file_name, pcap_handle));

                //tmlog(TM_LOG_NOTE, "FifoDisk: addPkt", "the new file name is: %s", new_file_name);
                // free new_file_name since we malloced it and don't need it anymore
				free(new_file_name);
			}
			unlockQueryInProgress();
		}

        //char str1[INET6_ADDRSTRLEN];

        //bro_inet_ntop(AF_INET6, &(IP6(p + 4 + sizeof(struct pcap_pkthdr))->ip6_src.s6_addr), str1, INET6_ADDRSTRLEN);

        //char s1[INET6_ADDRSTRLEN];

        //inet_pton(AF_INET6, s1, str1);

        //char str2[INET6_ADDRSTRLEN];

        //bro_inet_ntop(AF_INET6, &(IP6(p + 4 + sizeof(struct pcap_pkthdr))->ip6_dst.s6_addr), str2, INET6_ADDRSTRLEN);

        //tmlog(TM_LOG_NOTE, "FifoDisk::addPkt", "we are going to add in next step the packet to the FifoDisk with src ip %s and dst ip %s", str1, str2);

        // in the last file, the newest file, add the packet
		files.back()->addPkt(p);
        // get the oldest time stamp (the 1 milisecond if statement appears again)
		if (oldestTimestamp < 1e-3)
			oldestTimestamp = files.front()->getOldestTimestamp();
        // increment the number of held bytes by the size of the pcap packet header struct and the length of the packet
		held_bytes+=sizeof(struct pcap_pkthdr)+((struct pcap_pkthdr*)p)->caplen;
        // increment the number of held packets
		held_pkts++;
        // increment the number of total bytes entered into this Fifo by the size of the pcap packet header struct and the length of the packet
		tot_bytes+=sizeof(struct pcap_pkthdr)+((struct pcap_pkthdr*)p)->caplen; //len;
        // increment the number of total packets entered into this Fifo
		tot_pkts++;
	}
}

tm_time_t FifoDisk::getOldestTimestamp() const {
	return oldestTimestamp;
}
tm_time_t FifoDisk::getNewestTimestamp() const {
	return newestTimestamp;
}

/*
uint64_t FifoDisk::query(QueryRequest *qreq, QueryResult *qres,
					 IntervalSet *interval_set) {
	FifoDiskFile *cur_file;
	uint64_t matches=0;
	IntervalSet::iterator i_i=interval_set->begin();
	std::list <FifoDiskFile*>::iterator f_i=files.begin();
	while ( f_i!=files.end() && i_i != interval_set->end() ) {
		cur_file = *f_i;
		f_i++;
		if (f_i == files.end()) {
			lockLastFile();
		}
		matches += cur_file->query(interval_set, qreq, qres);
	}
	return matches;
}
*/


/***************************************************************************
 * FifoDiskFile - seems to be for querying
 */

FifoDiskFile::FifoDiskFile(const std::string& filename, pcap_t* pcap_handle):
		filename(filename), is_open(false), cur_file_size(0), held_bytes(0), held_pkts(0),
		pcap_handle(pcap_handle),
		oldest_timestamp(0),
newest_timestamp(0) {
	open();
}


void FifoDiskFile::open() {
	pcap_dumper_handle=pcap_dump_open(pcap_handle, filename.c_str());
	if (!pcap_dumper_handle) {
		char *pcap_errstr = pcap_geterr(pcap_handle);
		tmlog(TM_LOG_ERROR, "storage", "could not open file %s: %s",
				filename.c_str(), pcap_errstr);
	} else {
		is_open=true;
	}
}

FifoDiskFile::~FifoDiskFile() {
	if (is_open) close();
}


void FifoDiskFile::remove() {
	if (is_open) close();
	unlink(filename.c_str());
}

void FifoDiskFile::removeNoUnlink() {
	if (is_open) close();
}


void FifoDiskFile::close() {
	pcap_dump_close(pcap_dumper_handle);
	is_open=false;
}

void FifoDiskFile::addPkt(const struct pcap_pkthdr *header,
						  const unsigned char *packet) {
	assert(is_open==true);
	pcap_dump((u_char*)pcap_dumper_handle,
			  header,                         // pcap header
			  packet);                        // packet
	if (held_pkts==0) oldest_timestamp=to_tm_time(&header->ts);
	else newest_timestamp=to_tm_time(&header->ts);
	held_pkts++;
	held_bytes+=sizeof(struct pcap_pkthdr)+header->caplen;
	//held_bytes+=header->caplen;
	cur_file_size += sizeof(struct pcap_pkthdr)+header->caplen;
}

void FifoDiskFile::addPkt(pkt_ptr p) {
	addPkt((struct pcap_pkthdr*)p,         // pcap header
		   p+sizeof(struct pcap_pkthdr));  // packet
}

uint64_t FifoDiskFile::query( QueryRequest *qreq, QueryResult *qres, IntervalSet *set, const char* classdirectory) {
	uint64_t matches = 0;
	uint64_t scanned_packets=0;
	ConnectionID4 *c_id;
	struct timeval tv1, tv2;
	struct timeval tv;
	int res;
	int intcnt=0;
	int first_pkt_for_this_int;
    //pcapnav_t *ph;


    /*
        if (chdir(conf_main_workdir)) {
                fprintf(stderr, "cannot class chdir to %s\n", conf_main_workdir);
                return(1);
        }
    */
	// FIXME: Protect the pcap_dumper_handle from capture thread!!
	if (is_open)
		flush();

	//char errbuf[PCAP_ERRBUF_SIZE];

    //printf("The file name we are querying in is %s\n", filename.c_str());

    if (chdir(classdirectory)) {
        fprintf(stderr, "cannot class(Fifo:query) chdir to %s\n", classdirectory);
        //return;
    }

    //char path[70];

    //char errbufnav[PCAP_ERRBUF_SIZE];

    //printf("The directory that we are in is %s\n", getcwd(path, 70));
/*
    if (chdir(classdirectory)) {
        fprintf(stderr, "cannot class(Fifo:query) chdir to %s\n", classdirectory);
        //return;
    }
*/

    /*

    pcap_t *ph_debug = pcap_open_offline(filename.c_str(), errbuf);

    if (ph_debug == NULL) {
        fprintf(stderr, "Couldn't open file %s: %s\n", filename.c_str(), errbuf);
        //exit(EXIT_FAILURE);
    }

    pcap_close(ph_debug);
    */

	//ph->pcap=pcap_open_offline(filename.c_str(), errbufnav);

    pcapnav_t *ph = pcapnav_open_offline_tm(filename.c_str(), classdirectory);    

	if (!ph) {
        /*
		char *pcap_errstr = pcapnav_geterr(ph);
		tmlog(TM_LOG_ERROR, "query", "%d FifoDiskFile::query: could not open file %s: %s",
				qres->getQueryID(), filename.c_str(), pcap_errstr);
        */
        
        tmlog(TM_LOG_ERROR, "query", "%d FifoDiskFile::query: could not open file %s",
                qres->getQueryID(), filename.c_str());

	} else {
    
		struct pcap_pkthdr hdr;
		const u_char *pkt;

        
		if (pcapnav_get_timespan(ph, &tv1, &tv2) != 0) {
			tmlog(TM_LOG_WARN, "query",  "%d pcapnav could not obtain timespan.",
					qres->getQueryID());
			  //Rest of error handling
		}
        
		tmlog(TM_LOG_DEBUG, "query", "%d FifoDiskFile::query: opened file %s. timespan is [%lf,%lf]",
				qres->getQueryID(), filename.c_str(), to_tm_time(&tv1), to_tm_time(&tv2));

		for (IntervalSet::iterator it=set->begin(); it!=set->end(); it++) {
			// FIXME: get rid of this assert
			assert(getNewestTimestamp() >= getOldestTimestamp());
			/* XXX: this should be handled by pcapnav_goto_timestamp.... 
			if (getOldestTimestamp() > (*it).getLast() ||
					getNewestTimestamp() < (*it).getStart() ) {
				fprintf(stderr, "Nicht im File: [%lf, %lf] <> [%lf,%lf]\n", 
						getOldestTimestamp(), getNewestTimestamp(), 
						(*it).getStart(), (*it).getLast());
				continue;
			}
			*/
			tmlog(TM_LOG_DEBUG, "query", "%d FifoDiskFile: New Int %i of %i: [%lf, %lf]", intcnt, set->getNumIntervals(),
					qres->getQueryID(), it->getStart(), it->getLast());
			
			tv.tv_sec=(int)(*it).getStart();
			tv.tv_usec=(int)(1000000*((*it).getStart()-tv.tv_sec));
			
			// Check if interval overlaps trace start
			// FIXME: Don't hardcode the security margin with 1ms!!
			if ( (*it).getLast()+1e-3 >= to_tm_time(&tv1) &&
					(*it).getStart() <= to_tm_time(&tv1)) {
				res = PCAPNAV_DEFINITELY;
				pcapnav_goto_offset(ph, 0, PCAPNAV_CMP_LEQ);
				tmlog(TM_LOG_DEBUG, "query", "%d Interval overlapped trace start. Goto 0",
						qres->getQueryID());
			}
            
			else 
				res = pcapnav_goto_timestamp(ph, &tv);
			switch(res) {
				case PCAPNAV_ERROR:
					tmlog(TM_LOG_ERROR, "query", " %d pcapnav_goto_timestamp ERROR", qres->getQueryID()); 
					break;
				case PCAPNAV_NONE:
					tmlog(TM_LOG_DEBUG, "query", "%d pcapnav_goto_timestamp NONE", qres->getQueryID()); 
					break;
				case PCAPNAV_CLASH:
					tmlog(TM_LOG_ERROR, "query", "%d pcapnav_goto_timestamp CLASH", qres->getQueryID()); 
					break;
				case PCAPNAV_PERHAPS:
					tmlog(TM_LOG_ERROR, "query", "%d pcapnav_goto_timestamp PERHAPS", qres->getQueryID()); 
					break;
				default:
					break;
			}
            
			if (res != PCAPNAV_DEFINITELY) {
				continue;
			}
            
			first_pkt_for_this_int = 1;
			do {
				pkt = pcapnav_next(ph, &hdr);// + 4;
				scanned_packets++;
				if (!pkt)
					break;
				tm_time_t t=to_tm_time(&hdr.ts);
				if (first_pkt_for_this_int) {
					tmlog(TM_LOG_DEBUG, "query", "First packet ts for this int: %lf", t);
					first_pkt_for_this_int=0;
				}
				if (t>(*it).getLast())
					break;
				if (t>qreq->getT1())
					break;
				if (t<qreq->getT0())
					continue;
                //tmlog("The result of matchPkt from QueryRequest is %d 
                //char str1[INET6_ADDRSTRLEN];

                //bro_inet_ntop(AF_INET6, &(IP6(pkt)->ip6_src.s6_addr), str1, INET6_ADDRSTRLEN);

                //inet_ntop(AF_INET6, &(IP6(pkt)->ip6_src.s6_addr), str1, INET6_ADDRSTRLEN); 

                //char s1[INET6_ADDRSTRLEN];

                //inet_pton(AF_INET6, s1, str1);

                //char str2[INET6_ADDRSTRLEN];

                //bro_inet_ntop(AF_INET6, &(IP6(pkt)->ip6_dst.s6_addr), str2, INET6_ADDRSTRLEN);

                //inet_ntop(AF_INET6, &(IP6(pkt)->ip6_dst.s6_addr), str2, INET6_ADDRSTRLEN);               

                //char s2[INET6_ADDRSTRLEN];
                /*
                if ( inet_pton(AF_INET6, s2, str2) <=0 )
			        {
                    tmlog(TM_LOG_ERROR, "Bad IP address: %s", s2);
                    }
                */

                /* 
                //tmlog(TM_LOG_ERROR, "FifoDisk.cc: query", "the query packet has source ip address: %s and dst ip address %s and header time stamp %lu and %lu", \
                str1, str2, hdr.ts.tv_sec, hdr.ts.tv_usec);
                //tmlog(TM_LOG_ERROR, "FifoDisk.cc:query", "the query parameters are that it has a time interval from %f to %f, a hash of %lu, a timestamp of %f, and a form of %s", \
                qreq->getT0(), qreq->getT1(), qreq->getField()->hash(), qreq->getField()->ts, qreq->getField()->getStr().c_str());
                */
				if (qreq->matchPkt(&hdr, pkt))  {
					matches++;
					qres->sendPkt(&hdr, pkt);
					if (qreq->isSubscribe()) {
						c_id = new ConnectionID4(pkt);
						storage->getConns().subscribe(c_id, qres);
						delete c_id;
					}
				}
			} while (pkt);
		}
	}
	//DEBUG
	tmlog(TM_LOG_DEBUG, "query", "%d FifoDiskFile::query [HAVE_LIBPCAPNAV] finished; matches %" PRIu64 "; examined %" PRId64, 
			qres->getQueryID(), (unsigned)matches, scanned_packets);

	pcapnav_close(ph);
	return matches;
}
