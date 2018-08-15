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
#include <sys/types.h>
#include <sys/stat.h>
#include "pcapnav_debug.h"
#include "pcapnav_private.h"
#include "pcapnav_macros.h"

/**
 * append_fix_trunc_packet - fixes the last packet in a truncated trace.
 * @pn: pcapnav handle of input trace.
 * @result: file stream pointer.
 *
 * The function attempts to fix the last packet in a truncated trace.
 * If the pcap header of the last packet is not present completely,
 * then @result is positioned so that the next packet that is appended
 * overwrites this last packet completely. If the pcap header is present
 * but the packet data is truncated, then the packet header gets fixed
 * to reflect only the amount of packet data present.
 *
 * Returns: value > 0 if fix succeeded, 0 othewise.
 */
static int
append_fix_trunc_packet(pcapnav_t *pn, FILE *result)
{
  off_t end;
  struct pcap_pkthdr hdr;

  /* Make sure we initialize timespan and offsets */
  (void) pcapnav_get_span(pn);
  
  /* "end" is the offset after the last valid packet */
  end = pn->end_offset + sizeof(struct pcap_pkthdr) + pn->end_caplen;
  
  /* Check if the last packet is in fact the end of the trace,
   * or if there is a truncated packet at the very end.
   */
  if (end  == pn->size)
    /* It's good, no truncated packet. Just return. */
    return 1;
  
  /* There is still space in the file after the last valid packet.
   * Deal with the last packet accordingly: if the packet header is
   * fully present, we adjust its values so that the packet is no
   * longer truncated (setting caplen to zero if only the header is
   * present). If not even the packet header is fully present, we
   * position the resulting file pointer so that it overwrites 
   * this packet.
   */      
  if (fseek(result, end, SEEK_SET) < 0)
    {
      D(("Error seeking to position of truncated packet.\n"));
      return 0;
    }
      
  if (end + sizeof(struct pcap_pkthdr) < pn->end_caplen)
    {
      /* Not even packet header is fully present. The stream
       * is located correctly for overwriting, so just return.
       */
      D(("Final packet header corrupted -- will overwrite.\n"));
      return 1;
    }
  
  /* We need to fix the packet header of the truncated packet.
   * Read in the header, calculate the real number of bytes present
   * after it, fix the header, write it back to disk, and seek to
   * the end of the file.
   */
  if (fread((void *) &hdr, sizeof(struct pcap_pkthdr), 1, result) != 1)
    {
      D(("Couldn't read broken packet header.\n"));
      return 0;
    }
  
  D(("Updating caplen of truncated packet from %lu to %llu.\n",
     (long unsigned) hdr.caplen, pn->size - (end + sizeof(struct pcap_pkthdr))));
  hdr.caplen = pn->size - (end + sizeof(struct pcap_pkthdr));
  
  if (fseek(result, end, SEEK_SET) < 0)
    {
      D(("Error seeking to position of truncated packet.\n"));
      return 0;
    }
  
  if (fwrite(&hdr, sizeof(struct pcap_pkthdr), 1, result) != 1)
    {
      D(("Couldn't write corrected packet header.\n"));
      return 0;
    }
  
  if (fseek(result, 0, SEEK_END) < 0)
    {
      D(("Error seeking to eof.\n"));
      return 0;
    }

  return 1;
}


static pcap_dumper_t *
append_impl(pcap_t *pcap, const char *filename, pcapnav_dumpmode_t mode, const char* classdirectory)
{
  pcapnav_t *pn = NULL;
  FILE *result = NULL;
  struct stat st;

  /* Check if the file exists */
  if (stat(filename, &st) < 0)
    {
      if (errno == ENOENT)
	{
	  D(("File '%s' doesn't exist, handling as usual.\n", filename));
	  return pcap_dump_open(pcap, filename);
	}
      
      /* For all other file open errors we just rely on
       * pcapnav_open_offline() to detect them next.
       */
    }
  
  if (! (pn = pcapnav_open_offline_tm(filename, classdirectory)))
    {
      D(("Error opening '%s'\n", filename));
      return NULL;
    }
  
  /* Check whether the linklayer protocols are compatible -- if not,
   * then we cannot append (at least not without linklayer adaptors).
   *
   * Note that we do NOT check against pn->trace.filehdr.linktype
   * directly. Pcap's internal mapping mechanism may cause a different
   * value to be stored in the header structure than reported through
   * pcap_datalink(), so we must make sure we use pcap_datalink() in
   * both cases to ensure comparability.
   */
  if (pcap_datalink(pn->pcap) != pcap_datalink(pcap))
    {
      char *errbuf = pcap_geterr(pcap);
      
      if (errbuf)
	snprintf(errbuf, PCAP_ERRBUF_SIZE, "linklayer protocols incompatible (%i/%i)",
		 (int) pn->trace.filehdr.linktype, pcap_datalink(pcap));
      pcapnav_close(pn);
      return NULL;
    }
    
  if (! (result = fopen(filename, "r+")))
    {
      D(("Error opening '%s' in r+ mode.\n", filename)); 
      goto error_return;
    }
  
  /* Check whether the snaplen will need to be updated: */
  if (pn->trace.filehdr.snaplen < (unsigned) pcap_snapshot(pcap))
    {
      struct pcap_file_header filehdr;
      
      D(("snaplen needs updating from %u to %u.\n",
	 pn->trace.filehdr.snaplen, (unsigned) pcap_snapshot(pcap)));
      
      filehdr = pn->trace.filehdr;
      filehdr.snaplen = pcap_snapshot(pcap);
      
      if (fwrite(&filehdr, sizeof(struct pcap_file_header), 1, result) != 1)
	{
	  D(("Couldn't write corrected file header.\n"));
	  goto error_return;
	}
    }
  
  if (fseek(result, 0, SEEK_END) < 0)
    {
      D(("Error seeking to end of file.\n"));
      goto error_return;
    }	  
  
  if (mode == PCAPNAV_DUMP_APPEND_SAFE)
    {
      if (! append_fix_trunc_packet(pn, result))
	{
	  D(("Fixing truncated packet failed.\n"));
	  goto error_return;
	}
    }
  
  pcapnav_close(pn);
  return (pcap_dumper_t *) result;
  
 error_return:
  pcapnav_close(pn);
  return NULL;
}


pcap_dumper_t *
pcapnav_append_fast(pcap_t *pcap, const char *filename, const char* classdirectory)
{
  return append_impl(pcap, filename, PCAPNAV_DUMP_APPEND_FAST, classdirectory);
}


pcap_dumper_t *   
pcapnav_append_safe(pcap_t *pcap, const char *filename, const char* classdirectory)
{
  return append_impl(pcap, filename, PCAPNAV_DUMP_APPEND_SAFE, classdirectory);
}

