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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "pcapnav.h"
#include "pcapnav_debug.h"
#include "pcapnav_private.h"
#include "pcapnav_macros.h"
#include "pcapnav_buf.h"
#include "pcapnav_header.h"


/* These are numeric codes for the outcome of the
 * __pcapnav_follow_chain() operation. They're ordered
 * numerically in order of increasing reliability.
 */
typedef enum {
  PCAPNAV_CHAIN_UNKNOWN  = 0,
  PCAPNAV_CHAIN_ABORT    = 1,
  PCAPNAV_CHAIN_NOSPACE  = 2,
  PCAPNAV_CHAIN_OK       = 3,
} pcapnav_chain_result_t;


int
__pcapnav_header_reasonable(struct pcap_pkthdr *hdr,
			    time_t start_time,
			    time_t end_time)
{
  if (end_time == 0)
    end_time = start_time + MAX_REASONABLE_FILE_SPAN;
  
#ifdef PCAPNAV_DEBUG
  D(("Start time: %lu, end time: %lu\n",
     start_time, end_time));

  do {
    if ((unsigned) hdr->ts.tv_sec < (unsigned) start_time)
      {
	D(("timestamp before start of trace: %lu %lu %lu\n",
	   start_time, hdr->ts.tv_sec, end_time));
	break;
      }
    if ((unsigned) hdr->ts.tv_sec > (unsigned) end_time)
      {
	D(("timestamp after end of trace: %lu %lu %lu\n",
	   start_time, hdr->ts.tv_sec, end_time));
	break;
      }
    if (hdr->len > MAX_REASONABLE_PACKET_LENGTH)
      {
	D(("Header too large.\n"));
	break;
      }
    if (hdr->caplen > hdr->len)
      {
	D(("Capture length larger than entire length."));
	break;
      }
    } while(0);
#endif

  return ((unsigned) hdr->ts.tv_sec >= (unsigned) start_time &&
	  (unsigned) hdr->ts.tv_sec <= (unsigned) end_time &&
	  hdr->len <= MAX_REASONABLE_PACKET_LENGTH &&
	  hdr->caplen <= hdr->len);
}


void
__pcapnav_header_extract(pcapnav_t *pn, u_char *buf,
			 struct pcap_pkthdr *hdr)
{
  struct pcapnav_pkthdr phys_hdr;

  memcpy((char *) &phys_hdr, (char *) buf, sizeof(struct pcapnav_pkthdr));
  memset(hdr, 0, sizeof(struct pcap_pkthdr));
  
  if (pn->trace.swapped)
    {
      hdr->ts.tv_sec = SWAPLONG(phys_hdr.ts.tv_sec);
      hdr->ts.tv_usec = SWAPLONG(phys_hdr.ts.tv_usec);
      hdr->len = SWAPLONG(phys_hdr.len);
      hdr->caplen = SWAPLONG(phys_hdr.caplen);
    }
  else
    {
      hdr->ts.tv_sec = phys_hdr.ts.tv_sec;
      hdr->ts.tv_usec = phys_hdr.ts.tv_usec;
      hdr->len = phys_hdr.len;
      hdr->caplen = phys_hdr.caplen;
    }
  
  /*
   * We interchanged the caplen and len fields at version 2.3,
   * in order to match the bpf header layout.  But unfortunately
   * some files were written with version 2.3 in their headers
   * but without the interchanged fields.
   */
  if (pn->trace.filehdr.version_minor < 3 ||
      (pn->trace.filehdr.version_minor == 3 && hdr->caplen > hdr->len) )
    {
      int t = hdr->caplen;
      hdr->caplen = hdr->len;
      hdr->len = t;
    }
}


/**
 * __pcapnav_follow_chain - returns length of valid a sequence of packets.
 * @pn: pcapnav handle.
 * @chain_length: pointer to int, receiving length found.
 *
 * The function follows a given buffer pointer, assuming a valid
 * packet header at that point, and sees how many headers are reasonable
 * when following the given packet header to the next one etc, up to
 * MAX_CHAIN_LENGTH (see pcapnav_macros.h) packets. If the search buffer
 * of the pcapnav handle doesn't suffice, we read more data into the
 * chain buffer.
 *
 * Returns: a result of type pcapnav_chain_result_t and the length of the
 * chain found, if @chain_length is given.
 */
static pcapnav_chain_result_t
__pcapnav_follow_chain(pcapnav_t *pn, int *chain_length)
{
  u_char *search_ptr, *old_search_ptr, *search_endptr;
  
  time_t start_time, end_time;
  struct pcap_pkthdr hdr;
  int i;
  off_t searched_size;

  start_time     = pn->start_time.tv_sec;
  end_time       = 0;
  search_ptr     = old_search_ptr = pn->search_buf->bufptr;
  search_endptr  = pn->search_buf->bufend - pn->trace.pkthdr_size;

  /* First check the remaining buffer space in the search buffer.
   * If we bump into an invalid header (as we will most of the time),
   * we save the expensive disk read!
   *
   * Also, do not require packet timestamps to be strictly increasing.
   * We require the following packet to be in a window of one week before
   * or after the previous packet.
   */
  for (i = 0 ; i < MAX_CHAIN_LENGTH && search_ptr < search_endptr; i++)
    {
      __pcapnav_header_extract(pn, search_ptr, &hdr);

      D(("Iteration %i: offset %lu, %i, %i %i\n", i,
	 (long unsigned) __pcapnav_buf_get_offset(pn->search_buf) + i,
	 i, hdr.caplen, hdr.len));
      old_search_ptr = search_ptr;
      search_ptr += pn->trace.pkthdr_size + hdr.caplen;
      
      if (!__pcapnav_header_reasonable(&hdr, start_time, end_time))
	{
	  if (chain_length)
	    *chain_length = i;
	  
	  return PCAPNAV_CHAIN_ABORT;
	}

      start_time = MAX(hdr.ts.tv_sec - MAX_REASONABLE_HDR_SEPARATION, pn->start_time.tv_sec);
      end_time   = hdr.ts.tv_sec + MAX_REASONABLE_HDR_SEPARATION;
    }

  if (i > MAX_CHAIN_LENGTH)
    {
      /* We've exhausted our maximum number of packets read, without
       * finding an invalid header. Return the chain length and
       * success.
       */

      if (chain_length)
	*chain_length = i;

      return PCAPNAV_CHAIN_OK;
    }

  /* Otherwise, this wasn't enough and we have exhausted the search
   * buffer without a result -- fill the chain buffer with as much
   * as is still required, and continue scanning.*/

  searched_size = old_search_ptr - pn->search_buf->buf;
  D(("%i out of %i packets valid, extending chain by %li bytes\n",
     i, MAX_CHAIN_LENGTH, (long) searched_size));

  __pcapnav_buf_fill(pn->chain_buf, pn->fp,
		     pn->search_buf->offset + searched_size,
		     SEEK_SET, pn->chain_buf->size - searched_size);
  
  /* We need to be able to extract at least a packet header --
   * make sure we have enough space for that!
   */
  __pcapnav_buf_move_end(pn->chain_buf, -pn->trace.pkthdr_size);

  end_time = 0;
  
  /* Now iterate over our freshly read chain buffer, still
   * incrementing our packet counter.
   */
  for (i-- ; i < MAX_CHAIN_LENGTH && __pcapnav_buf_pointer_valid(pn->chain_buf); i++)
    {
      __pcapnav_header_extract(pn, pn->chain_buf->bufptr, &hdr);

      D(("Iteration 2: %i, %i %i\n", i, hdr.caplen, hdr.len));

      __pcapnav_buf_move_pointer(pn->chain_buf, pn->trace.pkthdr_size + hdr.caplen);
      
      if (!__pcapnav_header_reasonable(&hdr, start_time, end_time))
	{
	  if (chain_length)
	    *chain_length = i;
	  
	  return PCAPNAV_CHAIN_ABORT;
	}
      
      start_time = MAX(hdr.ts.tv_sec - MAX_REASONABLE_HDR_SEPARATION, pn->start_time.tv_sec);
      end_time   = hdr.ts.tv_sec + MAX_REASONABLE_HDR_SEPARATION;
    }

  D(("Chain length %i\n", i));

  if (chain_length)
    *chain_length = i;

  if (!__pcapnav_buf_pointer_valid(pn->chain_buf))
    return PCAPNAV_CHAIN_NOSPACE;
  
  return PCAPNAV_CHAIN_OK;
}


pcapnav_result_t
__pcapnav_header_search(pcapnav_t *pn,
			u_char **hdrpos_addr, struct pcap_pkthdr *return_hdr)
{
  u_char                  *best_bufptr = NULL, *best_suc_bufptr = NULL;
  struct pcap_pkthdr       best_hdr, tmp_hdr;
  int                      chain_len, best_chain_len = 0;
  pcapnav_chain_result_t   chain_result, best_chain_result = PCAPNAV_CHAIN_UNKNOWN;
  pcapnav_result_t         result = PCAPNAV_NONE;

  memset(&best_hdr, 0, sizeof(struct pcap_pkthdr));

  /* We need space for at least a single packet header. Make sure
   * we have that available.
   */
  __pcapnav_buf_move_end(pn->search_buf, -pn->trace.pkthdr_size);

  /* Try each buffer position to see whether it looks like
   * a valid packet header.  We may later restrict the positions we look
   * at to avoid seeing a sequence of legitimate headers as conflicting
   * with one another.
   */  
  for (__pcapnav_buf_set_pointer(pn->search_buf, 0);   /* from the buffer start,     */
       __pcapnav_buf_pointer_valid(pn->search_buf);    /* while we're within buffer, */
       __pcapnav_buf_move_pointer(pn->search_buf, 1))  /* increment bytewise.        */
    {
      /* D(("Looking at %lu\n", pn->search_buf->offset + __pcapnav_buf_get_pointer_offset(pn->search_buf))); */

      /* Check what we've got available at this offset. */
      chain_result = __pcapnav_follow_chain(pn, &chain_len);
      
      if (chain_len == 0)
	/* Not a valid chain of packets -- skip this offset. */
	continue;
      
      /* If we've found a "best" match already, the current one may
       * be its successor. Make sure we skip it.
       */
      if (pn->search_buf->bufptr == best_suc_bufptr)
	{
	  __pcapnav_header_extract(pn, pn->search_buf->bufptr, &tmp_hdr);
	  best_suc_bufptr += pn->trace.pkthdr_size + tmp_hdr.caplen;
	  D(("Skipped.\n"));
	  continue;
	}


      if ((chain_len == best_chain_len) && (best_chain_result == chain_result))
	{
	  /* We have two chains with equal lengths, so both could be the right
	   * match. Declare this to be a clash if the results are of equal
	   * reliability. Otherwise, the new packet might still be picked
	   * as the new best match below, if the match is of greater
	   * reliability as the old one.
	   *
	   * Since we have a clash, we cannot really tell which one's right,
	   * so we just wipe our memory and continue. If we cannot find any
	   * other matches, we will still return the clash result.
	   */

	  D(("Clash -- clearing memory.\n"));
	  result = PCAPNAV_CLASH;
	  
	  best_chain_len    = 0;
	  best_chain_result = PCAPNAV_CHAIN_UNKNOWN;
	  best_bufptr       = NULL;
	  best_suc_bufptr   = NULL;
	  memset(&best_hdr, 0, sizeof(struct pcap_pkthdr));
	  
	  continue;
	}

      /* Memorize new match if it's got a greater length than the old one
       * and is just as realiable, or if it's just more reliable.
       */

      if ((chain_len > best_chain_len &&
	   chain_result == best_chain_result) ||
	  (chain_result > best_chain_result))
	{
	  if (chain_len == 1)
	    result = PCAPNAV_PERHAPS;
	  else if (chain_len > 1)
	    result = PCAPNAV_DEFINITELY;

	  best_chain_len    = chain_len;
	  best_chain_result = chain_result;
	  best_bufptr       = pn->search_buf->bufptr;
	  	  
	  __pcapnav_header_extract(pn, best_bufptr, &best_hdr);

	  /* Make sure we don't demote this "definite" to a "clash" if we stumble
	   * across its successor. We remember the index that actually is its
	   * successor, so that we properly recognize it above.
	   */
	  best_suc_bufptr = best_bufptr + pn->trace.pkthdr_size + best_hdr.caplen;

	  D(("New best chain length %i, skipping %lli\n",
	     chain_len, pn->search_buf->offset +
	     (long long) (best_suc_bufptr - pn->search_buf->buf)));
	}
    }

  if (hdrpos_addr)
    *hdrpos_addr = best_bufptr;
  
  if (return_hdr)
    *return_hdr = best_hdr;

  D(("Returning %i\n", result));
  return result;
}

