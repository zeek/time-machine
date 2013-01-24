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
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <errno.h>
#include "pcapnav_private.h"
#include "pcapnav_debug.h"
#include "pcapnav_private.h"
#include "pcapnav_macros.h"
#include "pcapnav_header.h"
#include "pcapnav_util.h"
#include "pcapnav_trace.h"


/**
 * trace_get_interpolated_position - estimates offset of a timestamp in trace.
 * @min_time: start of time frame.
 * @min_pos: offset in file of @min_time packet.
 * @max_time: end of time frame.
 * @max_pos: offset in file of @max_time packet.
 * @desired_time: timestamp of packet whose offset is interpolated.
 * 
 * Given a timestamp on each side of desired_time and their offsets
 * in the file, the function returns the interpolated position of the
 * @desired_time packet. Nothing is looked at on disk, the value is
 * calculated only.
 * 
 * Returns: a negative value if @desired_time is outside the [@min_time, @max_time]
 * interval.
 */
static off_t
trace_get_interpolated_position( struct bpf_timeval *min_time, off_t min_pos,
				 struct bpf_timeval *max_time, off_t max_pos,
				 struct bpf_timeval *desired_time )
{
  double full_span    = __pcapnav_util_timeval_diff(max_time, min_time);
  double desired_span = __pcapnav_util_timeval_diff(desired_time, min_time);
  off_t full_span_pos = max_pos - min_pos;
  double fractional_offset = desired_span / full_span;

  if ( fractional_offset + 0.0000005 < 0.0 || fractional_offset - 0.0000005 > 1.0 )
    return -1;
  
  return (min_pos + (off_t) (fractional_offset * (double) full_span_pos));
}


/**
 * trace_read_up_to_timestamp - reads packets until timestamp is found.
 * @pn: pcapnav handle.
 * @desired_time: timestamp that stops the read.
 *
 * The function reads packets linearly until one with a timestamp equal
 * or larger than @desired_time is found. Then, it positions the stream
 * so that the next read will start at that packet.
 *
 * Returns: PCAPNAV_DEFINITELY if timestamp found, or PCAPNAV_ERROR.
 */
static pcapnav_result_t
trace_read_up_to_timestamp(pcapnav_t *pn, struct bpf_timeval *desired_time)
{
  struct pcap_pkthdr hdr;
  const u_char *buf;
  off_t pos;
  int status = PCAPNAV_NONE;
  
  for ( ; ; )
    {
      struct bpf_timeval *timestamp;
      
      pos = ftell(pn->fp);
      buf = pcapnav_next(pn, &hdr);
      
      if (buf == NULL)
	{
	  if (feof(pn->fp))
	    {
	      status = PCAPNAV_ERROR;
	      clearerr(pn->fp);
	    }

	  break;
	}
      
      timestamp = &hdr.ts;

      if ( ! __pcapnav_util_timeval_less_than(timestamp, desired_time))
	{
	  status = PCAPNAV_DEFINITELY;
	  break;
	}
    }
  
  if (fseek(pn->fp, pos, SEEK_SET) < 0)
    status = PCAPNAV_ERROR;
  
  return status;
}


pcapnav_result_t
__pcapnav_trace_find_packet_at_timestamp(pcapnav_t *pn,
					 struct bpf_timeval *desired_time)
{
  struct bpf_timeval min_time, max_time;
  off_t desired_pos, present_pos, min_pos, max_pos;
  u_char *hdrpos;
  struct pcap_pkthdr hdr;
  pcapnav_result_t   status = PCAPNAV_NONE;

  min_time  = pn->start_time;
  min_pos   = pn->start_offset;
  max_time  = pn->end_time;
  max_pos   = pn->end_offset;

  /* Handle the special cases -- requested timestamp beyond
   * end of trace or below start of it.
   */

  if (__pcapnav_util_timeval_less_than(&max_time, desired_time))
    {
      if (fseek(pn->fp, max_pos, SEEK_SET) < 0)
	return PCAPNAV_ERROR;

      return PCAPNAV_NONE;      
    }

  if (__pcapnav_util_timeval_less_than(desired_time, &min_time))
    {
      if (fseek(pn->fp, min_pos, SEEK_SET) < 0)
	return PCAPNAV_ERROR;

      return PCAPNAV_NONE;      
    }

  /* We actually need to look for the right spot in the trace.
   * Interpolate the position in the trace based upon the 
   * timestamps, and loop until positioned correctly. During
   * each iteration, the interpolation interval shrinks and
   * thus becomes more accurate, reflecting local values.
   */
  
  for ( ; ; )	
    {
      D(("find_packet iteration ...\n"));
      desired_pos =
	trace_get_interpolated_position(&min_time, min_pos,
					&max_time, max_pos,
					desired_time);

      if (desired_pos < 0)
	{
	  status = PCAPNAV_ERROR;
	  D(("Negative desired_pos\n"));
	  break;
	}

      present_pos = ftell(pn->fp);
      
      if ((present_pos <= desired_pos) &&
	  (desired_pos - present_pos < (off_t)STRAIGHT_SCAN_THRESHOLD(pn)))
	{
	  /* we're close enough to just blindly read ahead */
	  
	  status = trace_read_up_to_timestamp(pn, desired_time);
	  D(("Blind read-ahead\n"));
	  break;
	}

      /* Undershoot the target a little bit - it's much easier to
       * then scan straight forward than to try to read backwards ...
       */
      desired_pos -= STRAIGHT_SCAN_THRESHOLD(pn) / 2;

      if (desired_pos < min_pos)
	desired_pos = min_pos;

      if (fseek(pn->fp, desired_pos, SEEK_SET) < 0)
	{
	  D(("fseek() failed: %s\n",strerror(errno)));
	  status = PCAPNAV_ERROR;
	  break;
	}

      D(("SEEK AT BUFFER START: %lu\n", (long unsigned) desired_pos));
      
      if (__pcapnav_buf_fill(pn->search_buf, pn->fp, 0, 0, pn->search_buf->size) == 0)
	{
	  /* This shouldn't ever happen because we try to
	   * undershoot, unless the dump file has only a
	   * couple packets in it ...
	   */

	  status = PCAPNAV_ERROR;
	  D(("Buffer fill failed.\n"));
	  break;
	}
      
      
      if ( (status = __pcapnav_header_search(pn, &hdrpos, &hdr)) !=
	  PCAPNAV_DEFINITELY)
	{
	  D(("can't find header at position %lu in dump file -- result is %i\n",
	     (long unsigned) desired_pos, status));
	  
	  break;
	}

      /* desired_pos is the beginning of the buffer that was
       * filled above. hdrpos is the actual beginning of a header
       * in that chunk, so adjust desired_pos to match the
       * actual beginning of the packet.
       */
      desired_pos += (hdrpos - pn->search_buf->buf);

      /* Seek to the beginning of the header. */
      if (fseek(pn->fp, desired_pos, SEEK_SET) < 0)
	{
	  D(("fseek() failed: %s\n", strerror(errno)));
	  status = PCAPNAV_ERROR;
	  break;
	}
      
      if (__pcapnav_util_timeval_less_than(&hdr.ts, desired_time))
	{
	  /* We're too early in the file. */
	  min_time = hdr.ts;
	  min_pos = desired_pos;
	}      
      else if (__pcapnav_util_timeval_less_than(desired_time, &hdr.ts))
	{
	  /* We're too late in the file. */
	  max_time = hdr.ts;
	  max_pos = desired_pos;
	}      
      else
	{
	  /* got it! */
	  D(("Success!\n"));
	  break;
	}
    }

  D(("Return from find_packet, %i\n", status));
  return status;
}


/* NOTE -- offset 0 means first packet -- offsets are relative to
 * the end of the pcap file header.
 */
pcapnav_result_t
__pcapnav_trace_find_packet_at_offset(pcapnav_t *pn,
				      off_t offset,
				      pcapnav_cmp_t boundary)
{
  off_t               current, next_off;
  pcapnav_result_t    status = PCAPNAV_NONE;
  struct pcap_pkthdr  hdr;
  u_char             *hdrpos = NULL;

  current = offset;
  D(("Trying to find packet at %lu with policy %i\n",
     (long unsigned) offset, boundary));

  /* Handle the special cases -- requested offset beyond
   * end of trace or below beginning of actual packets.
   */
  if (offset + (off_t) sizeof(struct pcap_file_header) <= pn->start_offset)
    {
      D(("Setting to offset 0 as given offset too small\n"));
      pcapnav_set_offset(pn, 0);
      return PCAPNAV_DEFINITELY;
    }

  /* If an offset is requested that is too close to the end of the
   * trace, we return the offset of the last valid packet.
   */
  if (offset + (off_t) sizeof(struct pcap_file_header) >= pn->size)
    {
      D(("Setting to last valid offset (%llu) as given offset %llu too large\n",
	 pn->end_offset, offset));

      pcapnav_set_offset(pn, pn->end_offset);
      return PCAPNAV_DEFINITELY;
    }

  for ( ; ; )
    {
      /* Undershoot the target a little bit - it's much easier to
       * then scan straight forward than to try to read backwards ...
       */
      current -= STRAIGHT_SCAN_THRESHOLD(pn);

      if (current + (off_t) sizeof(struct pcap_file_header) < pn->start_offset)
	current = 0;

      D(("Offset seek iteration: %lu\n", (long unsigned) current));

      if (fseek(pn->fp, current + sizeof(struct pcap_file_header), SEEK_SET) < 0)
	{
	  D(("fseek() failed: %s\n", strerror(errno)));
	  status = PCAPNAV_ERROR;
	  break;
	}
            
      if (__pcapnav_buf_fill(pn->search_buf, pn->fp, 0, 0, pn->search_buf->size) == 0)
	{
	  /* This shouldn't ever happen because we try to
	   * undershoot, unless the dump file has only a
	   * couple packets in it ...
	   */
	  
	  status = PCAPNAV_ERROR;
	  D(("Buffer fill failed.\n"));
	  break;
	}
      
      if ( (status = __pcapnav_header_search(pn, &hdrpos, &hdr)) !=
	   PCAPNAV_DEFINITELY)
	{
	  D(("Can't find header at position %lu in dump file -- result is %i\n",
	     (long unsigned) current, status));
	  
	  return PCAPNAV_NONE;
	}
            
      if (current + (hdrpos - pn->search_buf->buf) <= offset)
	{
	  current += (hdrpos - pn->search_buf->buf);
	  break;
	}
    }

  /* Now follow the chain up as close as 
   * possible to the desired offset.
   */
  pcapnav_set_offset(pn, current);
  D(("Starting scan from packet at %lu, aiming at %lu\n",
     (long unsigned) current, (long unsigned) offset));

  switch (boundary)
    {
    case PCAPNAV_CMP_LEQ:
      while (pcapnav_get_offset(pn) <= offset)
	{
	  current = pcapnav_get_offset(pn);
	  
	  if (!pcapnav_next(pn, &hdr))
	    break;
	  	  
	  D(("Packet at %lu, next one at %lu\n",
	     (long unsigned) current, (long unsigned) pcapnav_get_offset(pn)));
	}
      break;

    case PCAPNAV_CMP_GEQ:
      while (current < offset)
	{
	  if (!pcapnav_next(pn, &hdr))
	    break;
	  	  
	  current = pcapnav_get_offset(pn);	  
	  D(("Packet at %lu\n", (long unsigned) current));
	}
      break;

    case PCAPNAV_CMP_ANY:
    default:

      while (pcapnav_get_offset(pn) <= offset)
	{
	  current = pcapnav_get_offset(pn);
	  
	  if (!pcapnav_next(pn, &hdr))
	    break;
	  
	  /* If we scan past the goal, check if the offset we get
	   * to is closer to the goal as the one we found below
	   * the goal. Then use whichever packet is closer.
	   */     
	  if ( (next_off = pcapnav_get_offset(pn)) > offset)
	    {
	      if ((next_off - offset) < (offset - current))
		{
		  current = next_off;
		  break;
		}
	    }
	  
	  D(("Packet at %lu, next one at %lu\n",
	     (long unsigned) current, (long unsigned) pcapnav_get_offset(pn)));
	}
    }
  
  pcapnav_set_offset(pn, current);

  return status;
}


void
__pcapnav_trace_find_start(pcapnav_t *pn)
{
  struct pcap_pkthdr hdr, hdr2;
  off_t old_pos;
  
  memset(&pn->start_time, 0, sizeof(struct bpf_timeval));

  if ((old_pos = ftell(pn->fp)) < 0)
    {
      D(("ftell() failed: %s\n", strerror(errno)));
      return;
    }

  if (fseek(pn->fp, sizeof(struct pcap_file_header), SEEK_SET) < 0)
    {
      D(("fseek() failed: %s\n", strerror(errno)));
      return;
    }

  if (fread((void *) &hdr, sizeof(struct pcap_pkthdr), 1, pn->fp) != 1)
    {
      D(("fread() failed: %s\n", strerror(errno)));
      return;
    }

  if (fseek(pn->fp, old_pos, SEEK_SET) < 0)
    {
      D(("fseek() to old position failed: %s\n", strerror(errno)));
      return;
    }

  pn->start_offset = sizeof(struct pcap_file_header);

  __pcapnav_header_extract(pn, (u_char*) &hdr, &hdr2);
  pn->start_time.tv_sec = hdr2.ts.tv_sec;
  pn->start_time.tv_usec = hdr2.ts.tv_usec;
}


void
__pcapnav_trace_find_end(pcapnav_t *pn)
{
  off_t   num_bytes;
  u_char *hdrpos;
  struct  pcap_pkthdr hdr;
  off_t   offset_orig, tmp_offset;

  if ((pn->start_time.tv_sec == 0)  &&
      (pn->start_time.tv_usec == 0))
    __pcapnav_trace_find_start(pn);

  pn->end_offset = 0;
  memset(&pn->end_time, 0, sizeof(struct bpf_timeval));

  /* We go back in the trace far enough to see MAX_CHAIN_LENGTH
   * consecutive packets, but still use only the (smaller) search_buf.
   * Once we've found a valid packet, we use pcap to iterate to
   * the last valid header. This'll involve disk I/O, but is a
   * safer method than jumping near the end of the trace were we
   * cannot scan enough packets to be really sure.
   */

  /* Remember current position */
  offset_orig = pcapnav_get_offset(pn);

  if (pn->trace.length < (int) MAX_PACKET_SIZE(pn) * MAX_CHAIN_LENGTH)
    num_bytes = pn->trace.length;
  else
    num_bytes = MAX_PACKET_SIZE(pn) * MAX_CHAIN_LENGTH;
  
  __pcapnav_buf_fill(pn->search_buf, pn->fp, -num_bytes, SEEK_END, pn->search_buf->size);
  if (__pcapnav_header_search(pn, &hdrpos, &hdr) != PCAPNAV_DEFINITELY)
    {
      D(("Header search failed\n"));
      goto cleanup_return;
    }
  
  tmp_offset = pn->search_buf->offset + (hdrpos - pn->search_buf->buf);
  D(("Definite header at offset %lu\n", (long unsigned) tmp_offset));
  pcapnav_set_offset(pn, tmp_offset - sizeof(struct pcap_file_header));
  
  pn->end_time   = hdr.ts;
  pn->end_caplen = hdr.caplen;
  pn->end_offset = pcapnav_get_offset(pn);

  /* Select last packet so that the offset is pointing
   * AT the last packet, not to the offset following it!
   */

 for ( ; ; )
    {
      tmp_offset = pcapnav_get_offset(pn) + sizeof(struct pcap_file_header);
      
      if (!pcap_next(pn->pcap, &hdr))
	break;
      
      pn->end_time   = hdr.ts;
      pn->end_caplen = hdr.caplen;
      pn->end_offset = tmp_offset;
    }

  D(("Finished -- last valid packet is at %lu, at %u.%u, captured %u bytes.\n",
     (long unsigned) pn->end_offset, (unsigned) pn->end_time.tv_sec,
     (unsigned) pn->end_time.tv_usec, pn->end_caplen));
  
 cleanup_return:
  /* Rewind to old position */
  pcapnav_set_offset(pn, offset_orig);
}
