/*

Copyright (C) 2002 - 2007 Christian Kreibich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifndef __pcapnav_header_h
#define __pcapnav_header_h

#include "pcapnav.h"
#include "pcapnav_buf.h"


/**
 * __pcapnav_header_resonable - checks validity of a potential header.
 * @hdr: pointer to pcap packet header
 * @first_time: start time of valid time frame in which header may be
 * @last_time: end time of valid time frame in which header may be
 *
 * The function determines whether or not a pcap packet header looks
 * resonable, given a header and an acceptable first and last time stamp.
 * If a @last_time cannot be determined, pass 0. The function will then
 * use a value that represents an appropriate, very large interval.
 *
 * Returns: non-zero if the header looks reasonable and zero otherwise.
 */
int               __pcapnav_header_reasonable(struct pcap_pkthdr *hdr,					      
					      time_t first_time,
					      time_t last_time);

/**
 * __pcapnav_header_extract - extracts a pcap packet header from a buffer.
 * @pn: pcapnav handle.
 * @buf: buffer pointer.
 * @hdr: header structure to fill in.
 *
 * The function extracts a packet header from the beginning of the buffer
 * @buf, handling byte order correctly.
 */
void              __pcapnav_header_extract(pcapnav_t  *pn,
					   u_char     *buf,
					   struct pcap_pkthdr *hdr);


/**
 * __pcapnav_header_search - looks for first header in data buffer.
 * @pn: pcapnav handle.
 * @hdrpos_addr: result pointer pointing into buffer where header starts. Can be %NULL.
 * @hdr: result pointer, getting filled with header data if found. Can be %NULL.
 *
 * The function looks for the first header in the buffer @buf that falls between
 * @start_time and @end_time. Returns the header in @hdr, and the pointer into
 * the buffer at @hdrpos_addr. Both are optional.
 *
 * Return values are %PCAPNAV_NONE, %PCAPNAV_CLASH, @PCAPNAV_PERHAPS, and
 * @PCAPNAV_DEFINITELY. The first indicates that no evidence of a header
 * was found; the second that two or more possible headers were found,
 * neither more convincing than the other(s); the third that exactly one
 * "possible" header was found; and the fourth that exactly one "definite"
 * header was found.
 *
 * Headers are detected by looking for positions in the buffer which have
 * reasonable timestamps and lengths.  If there is enough room in the buffer
 * for another header to follow a candidate header, a check is made for
 * that following header.  If it is present then the header is
 * %PCAPNAV_DEFINITELY, (unless another %PCAPNAV_PERHAPS or %PCAPNAV_DEFINITELY
 * header is found); if not, then the header is discarded.  If there is
 * not enough room in the buffer for another header then the candidate
 * is %PCAPNAV_PERHAPS (unless another header is subsequently found).  A
 * "tie" between a %PCAP_DEFINITELY header and a %PCAPNAV_PERHAPS header is
 * resolved in favor of the definite header. Any other tie leads to
 * %PCAPNAV_CLASH.
 *
 * The buffer position of the header is returned in hdrpos_addr and
 * for convenience the corresponding header in return_hdr.
 */
pcapnav_result_t  __pcapnav_header_search(pcapnav_t *pn,
					  u_char **hdrpos_addr,
					  struct pcap_pkthdr *hdr);

#endif
