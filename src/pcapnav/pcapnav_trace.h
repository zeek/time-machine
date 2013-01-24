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
#ifndef __pcapnav_trace_h
#define __pcapnav_trace_h

#include "pcapnav.h"

/* Our own packet header, as pcap stores them on disc.
 * We need this to work around 64-bit time_t size issues.
 */
struct pcapnav_timeval {
  u_int32_t tv_sec;
  u_int32_t tv_usec;
};

struct pcapnav_pkthdr {
  struct pcapnav_timeval ts;
  u_int32_t caplen;
  u_int32_t len;
};

struct pcapnav_patched_pkthdr {
  struct pcapnav_timeval ts;	/* time stamp */
  u_int32_t      caplen;	/* length of portion present */
  u_int32_t      len;	        /* length this packet (off wire) */
  int		 index;
  unsigned short protocol;
  unsigned char  pkt_type;
};


/**
 * __pcapnav_trace_find_packet_at_timestamp - positions stream near timestamp.
 * @pn: pcapnav handler.
 * @desired_time: timestamp to hunt for.
 *
 * The function positions the stream so that the next packet read will
 * return the first packet with a time greater than or equal to
 * desired_time.  desired_time must be greater than min_time and less
 * than max_time, which should correspond to actual packets in the
 * file.  min_pos is the file position (byte offset) corresponding to
 * the min_time packet and max_pos is the same for the max_time packet.
 *
 * NOTE: when calling this routine, the stream *must* be already
 * aligned so that the next call to pcapnav_trace_read_packet()
 * will yield a valid packet.
 *
 * Returns: pcapnav lookup result.
 */
pcapnav_result_t __pcapnav_trace_find_packet_at_timestamp(pcapnav_t *pn,
							  struct bpf_timeval *desired_time);


/**
 * __pcapnav_trace_find_packet_at_offset - positions stream near offset.
 * @pn: pcapnav handler.
 * @offset: offset around which the function looks for a packet.
 * @boundary: where around the offset to jump to.
 *
 * The function positions the stream at the packet closest to @offset.
 * Note that the first packet's offset is 0. If the offset is not
 * within the legal range, the function positions the stream at the
 * first packet (if @offset is too small) or last packet (if @offset
 * is too large) and returns %PCAPNAV_NONE.
 *
 * Returns: pcapnav lookup result.
 */
pcapnav_result_t __pcapnav_trace_find_packet_at_offset(pcapnav_t *pn,
						       off_t offset,
						       pcapnav_cmp_t boundary);

/**
 * __pcapnav_trace_read_packet - reads a single packet.
 * @pn: pcapnav handle.
 * @hdr: packet header structure that gets filled in.
 * @buffer: buffer that receives packet data. You may pass %NULL as well.
 * @buffer_size: size of @buffer, only used of @buffer is provided.
 *
 * The function reads a single packet into the provided buffers. The
 * stream must be correctly positioned when this function is called.
 *
 * Returns: 0 on success, negative value on error.
 */
int            __pcapnav_trace_read_packet(pcapnav_t *pn, struct pcap_pkthdr *hdr,
					   u_char *buffer, int buffer_size);


/**
 * __pcapnav_trace_find_start - determines start packet time + offset.
 * @pn: pcapnav handle.
 *
 * The function finds the timestamp and offset of the first packet
 * and fills in the corresponding fields in @pn.
 */
void           __pcapnav_trace_find_start(pcapnav_t *pn);

/**
 * __pcapnav_trace_find_end - determines end packet time + offset.
 * @pn: pcapnav handle.
 *
 * The function finds the timestamp and offset of the last packet
 * and fills in the corresponding fields in @pn.
 */
void           __pcapnav_trace_find_end(pcapnav_t *pn);

#endif
