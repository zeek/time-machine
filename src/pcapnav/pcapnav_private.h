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
#ifndef __pcapnav_private_h
#define __pcapnav_private_h

#include <stdlib.h>
#include <stdio.h>

#include "pcapnav.h"
#include "pcapnav_trace.h"
#include "pcapnav_buf.h"

struct pcapnav_trace {
  off_t swapped;
  off_t length;
  off_t pkthdr_size;
  struct pcap_file_header filehdr;
};


struct pcapnav {

  /* File stream for the input file we're handling */
  FILE                   *fp;

  /* Size of the input file, in total */
  off_t                   size;

  /* Original pcap handler. */
  pcap_t                 *pcap;

  /* Timestamp of first packet in trace. */
  struct bpf_timeval      start_time;

  /* Offset of the first packet in the trace.
   * This is not 0, but rather the size of the
   * pcap trace file header.
   */
  off_t                   start_offset;

  /* Timestamp, offset, and captured length of last packet in trace. */
  struct bpf_timeval      end_time;
  off_t                   end_offset;
  u_int32_t               end_caplen;

  struct pcapnav_trace    trace;

  struct pcapnav_buf     *search_buf;
  struct pcapnav_buf     *chain_buf;
};

#endif
