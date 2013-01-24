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
#ifndef __pcapnav_macros_h
#define __pcapnav_macros_h

#include <stdlib.h>
#include "pcapnav.h"

#ifndef	FALSE
#define	FALSE	(0)
#endif

#ifndef	TRUE
#define	TRUE	(!FALSE)
#endif

#undef	MAX
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#undef	MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define NEW(X)    ((X*) calloc(1, sizeof(X)))

#define FREE(X)   { if (X) { free(X); X = NULL; } }

#ifndef MAXPATHLEN
#define MAXPATHLEN 4096
#endif

#define	SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))
#define	SWAPSHORT(y) \
	( (((y)&0xff)<<8) | ((u_short)((y)&0xff00)>>8) )

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define PATCHED_TCPDUMP_MAGIC 0xa1b2cd34

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

/* Maximum number of seconds that we can conceive of a dump file spanning. */
#define MAX_REASONABLE_FILE_SPAN (3600*24*366)	/* one year */

/* Maximum packet length we ever expect to see. */
#define MAX_REASONABLE_PACKET_LENGTH 65535

/* Size of a packet header in bytes; easier than typing the sizeof() all
 * the time ...
 */
/* #define PACKET_HDR_LEN (sizeof(struct pcap_pkthdr)) */

/* The maximum size of a tracefile packet (data + struct pcapnav_pkthdr) */
#define MAX_PACKET_SIZE(pn) (pn->trace.pkthdr_size + pn->trace.filehdr.snaplen)

/* Number of contiguous bytes from a dumpfile in which there's guaranteed
 * to be enough information to find a "definite" header if one exists
 * therein.  This takes 3 full packets - the first to be just misaligned
 * (one byte short of a full packet), missing its timestamp; the second
 * to have the legitimate timestamp; and the third to provide confirmation
 * that the second is legit, making it a "definite" header.  We could
 * scrimp a bit here since not the entire third packet is required, but
 * it doesn't seem worth it
 */
#define MAX_BYTES_FOR_DEFINITE_HEADER(pn) (3 * MAX_PACKET_SIZE(pn))

/* Maximum number of seconds that might reasonably separate two headers. */
#define MAX_REASONABLE_HDR_SEPARATION (3600 * 24 * 7)	/* one week */

/* When searching a file for a packet, if we think we're within this many
 * bytes of the packet we just search linearly.  Since linear searches are
 * probably much faster than random ones (random ones require searching for
 * the beginning of the packet, which may be unaligned in memory), we make
 * this value pretty hefty.
 */
#define STRAIGHT_SCAN_THRESHOLD(pn) (100 * MAX_PACKET_SIZE(pn))

/* The maximum number of packets we check in a row in
 * __pcapnav_follow_chain().
 */
#define MAX_CHAIN_LENGTH 20

#endif
