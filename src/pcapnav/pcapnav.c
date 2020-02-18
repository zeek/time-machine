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
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#include "pcapnav_globals.c"

#include "pcapnav_private.h"
#include "pcapnav_header.h"
#include "pcapnav_append.h"
#include "pcapnav_macros.h"
#include "pcapnav_trace.h"
#include "pcapnav_util.h"
#include "pcapnav_debug.h"


/* NOTE NOTE NOTE -- offsets to the user of this library are relative
 * to the *END* of the pcap file header. Hence, offset 0 means the first
 * byte after the pcap file header. This makes offset calculation
 * easier for the user, because usually the user doesn't care about
 * the trace file header when handling offsets in a trace file.
 * We thus save the user the error-prone addition/subtraction of
 * sizeof(struct pcap_file_header) all the time.
 */

static char pcap_errbuf[PCAP_ERRBUF_SIZE];

// mentioned in pcapnav.h and pcapnav_debug.c
// according to netdude online,
// debug: enables debugging output when set to a value >= 1, and disables it when set to 0. Initialially, it is disabled.
// calldepth_limit: you can limit the calldepth up to which debugging output is displayed, to avoid excessive logging. By default, everything is logged (loglevel 0) O.o
// The function initializes the static options of the library, such as debugging switches etc.
void
pcapnav_init(void)
{
  pcapnav_runtime_options.debug = 0;
  pcapnav_runtime_options.calldepth_limit = -1;
}


pcapnav_t      *
pcapnav_open_offline_tm(const char *fname, const char* classdirectory)
{
  pcapnav_t               *pn;
  u_int32_t                magic;
  struct pcap_file_header *filehdr = NULL;
  FILE                    *fp;
  struct stat              st;

  FILE *fp_log;

#ifdef HAVE_PATH_MAX
  char filepath[PATH_MAX];
#else
  char filepath[1024];
#endif

  if (fname[0] != '/') {
    strcpy(filepath, classdirectory);
    strcat(filepath, "/");
    strcat(filepath, fname);
  } else {
    strcpy(filepath, fname);
  }

  char logpath[] = "/home/neto/data/pcapLog.txt";

  if (chdir(classdirectory)) {
      fprintf(stderr, "cannot class(Fifo:query) chdir to %s\n", classdirectory);
      //return;
  }
  /*  
  fp_log = fopen(logpath, "a");

  if (fp_log == NULL) {
    fprintf(stderr, "Can't open the log file pcapLog.txt\n");
  }
  else
  {
      char pcappath[70];

      fprintf(fp_log, "The directory that we are in while in the pcapnav.c file is %s for filename %s\n", getcwd(pcappath, 70), filepath);
      fclose(fp_log);
  }
  */
  /*
  fp_log = fopen("/home/lakers/pcapLog.txt", "a");

  if (fp_log == NULL) {
    fprintf(stderr, "Can't open the log file pcapLog.txt\n");
  }
  else
  {
      fprintf(fp_log, "come on, work with filename %s!\n", fname);
      fclose(fp_log);
  }
  */
  //fclose(fp_log);

  //fp_log = fopen("/home/lakers/pcapLog.txt", "w");

  D_ENTER;

  if (filepath[0] == '\0')
    {
      fp_log = fopen(logpath, "a");

      if (fp_log == NULL) {
         fprintf(stderr, "Can't open the log file pcapLog.txt\n");
      }

      else
      {
          fprintf(fp_log, "Invalid filename: %s\n", fname);
          fclose(fp_log);
      }      

      D(("Invalid filename: %s\n", fname));

      //fprintf(stderr, "Invalid filename: %s\n", filepath); //fname);

      errno = ENOENT;
      D_RETURN_(NULL);
    }

  /* Allocate new pcapnav structure and initialize. */
  
  if (! (pn = NEW(pcapnav_t)))
    {
      fp_log = fopen(logpath, "a");

      if (fp_log == NULL) {
         fprintf(stderr, "Can't open the log file pcapLog.txt\n");
      }

      else
      {
          fprintf(fp_log, "Out of memory\n");
          fclose(fp_log);
      }
      //fclose(fp_log);

      D(("Out of memory.\n"));

      //fprintf(stderr, "Out of memory.\n");

      errno = ENOMEM;
      D_RETURN_(NULL);
    }
  /*
  if (chdir(classdirectory)) {
      fprintf(stderr, "cannot class(Fifo:query) chdir to %s\n", classdirectory);
      //return;
  }

  fp_log = fopen("/home/lakers/pcapLog.txt", "a");

  if (fp_log == NULL) {
    fprintf(stderr, "Can't open the log file pcapLog.txt\n");
  }
  else
  {
      char pcappath[70];

      fprintf(fp_log, "The directory that we are in while in the pcapnav.c file is %s for filename %s\n", getcwd(pcappath, 70), fname);
      fclose(fp_log);
  }  
  */
  
  //if (lstat(fname, &st) < 0)
  if (lstat(filepath, &st) < 0)
    {
      fp_log = fopen(logpath, "a");

      if (fp_log == NULL) {
         fprintf(stderr, "Can't open the log file pcapLog.txt\n");
      }

      else
      {
          char path[70];
          fprintf(fp_log, "lstat failed for file %s and error %s, we are in the path %s\n", filepath, strerror(errno), getcwd(path, 70));

          fclose(fp_log);
      }
      //fclose(fp_log);

      D(("lstat failed: %s\n", strerror(errno)));

      //fprintf("lstat failed: %s for file %s\n", strerror(errno), fname);

      goto free_return;
    }
  
  pn->size = st.st_size;

  /* Allocate pcap handle */
  if (! (pn->pcap = pcap_open_offline(filepath, pcap_errbuf)))
    {
        if (pn->pcap == NULL) {
            fp_log = fopen(logpath, "a");

            if (fp_log == NULL) {
                fprintf(stderr, "Can't open the log file pcapLog.txt\n");
            }

            else
            {
                char path[70];
                fprintf(fp_log, "Could not open the file %s and error %s, the path is %s\n", filepath, pcap_errbuf, getcwd(path, 70));
                fclose(fp_log);
            }
            //fclose(fp_log);

            //fprintf(stderr, "Couldn't open the file: %s\n", pcap_errbuf);
            //exit(EXIT_FAILURE);
        }

      D(("%s (from pcap, re. %s)\n", pcap_errbuf, filepath)); //fname));
      /* Let's hope errno is meaningful now ... */
      goto free_return;
    }

    /*
    if (pn->pcap == NULL) {
        fprintf(stderr, "Couldn't open the file: %s\n", pcap_errbuf);
        //exit(EXIT_FAILURE);
    }
    */
  
  /* Hook pcap's file stream into our own structure: */
  pn->fp = pcap_file(pn->pcap);

  if (chdir(classdirectory)) {
      fprintf(stderr, "cannot class(Fifo:query) chdir to %s\n", classdirectory);
      //return;
  }
  
  if ((fp = fopen(filepath, "r")) == NULL)
    {
      fp_log = fopen(logpath, "a");
      if (fp_log == NULL) {
         fprintf(stderr, "Can't open the log file pcapLog.txt\n");
      }

      else
      {
          char path[70];
          fprintf(fp_log, "Could not open trace file %s for reading. The path is %s\n", filepath, getcwd(path, 70));
          fclose(fp_log);
      }
      //fclose(fp_log);

      //fprintf(stderr, "Couldn't open the trace file for reading: %s\n", fname);

      D(("Could not open trace file %s for reading.\n", filepath));
      // errno set already
      goto free_return;
    }
  
  if (fread((char *)&pn->trace.filehdr, sizeof(struct pcap_file_header), 1, fp) != 1)
    {

      fp_log = fopen(logpath, "a");

      if (fp_log == NULL) {
         fprintf(stderr, "Can't open the log file pcapLog.txt\n");
      }
      else
      {
         fprintf(fp_log, "Could not read trace file header from %s\n", filepath); //fname);
         fclose(fp_log);
      }
      //fclose(fp_log);

      //fprintf(stderr, "Couldn't open the trace file header for reading: %s\n", fname);

      D(("Could not read trace file header from %s\n", filepath)); //fname));
      //errno set already
      goto cleanup_return;
    }
  
  /* Look at magic to determine byte order. */

  magic = pn->trace.filehdr.magic;
  filehdr = &pn->trace.filehdr;      

  if (magic != TCPDUMP_MAGIC && magic != PATCHED_TCPDUMP_MAGIC)
    {
      magic = SWAPLONG(magic);

      if (magic != TCPDUMP_MAGIC && magic != PATCHED_TCPDUMP_MAGIC)
	{
	  D(("Invalid trace file %s -- didn't recognize file magic.\n", filepath)); //fname));

          fp_log = fopen(logpath, "a");

          if (fp_log == NULL) {
               fprintf(stderr, "Can't open the log file pcapLog.txt\n");
           }
          else
          { 
              fprintf(fp_log, "Invalid trace file %s, did not recognize file magic.\n", filepath); //fname);
              fclose(fp_log);
          }
          //fclose(fp_log);

          //fprintf(stderr, "Invalid trace file %s -- didn't recognize file magic \n", fname);

	  goto cleanup_return;
	}

      pn->trace.swapped = TRUE;

      filehdr->version_major = SWAPSHORT(filehdr->version_major);
      filehdr->version_minor = SWAPSHORT(filehdr->version_minor);
      filehdr->thiszone = SWAPLONG(filehdr->thiszone);
      filehdr->sigfigs = SWAPLONG(filehdr->sigfigs);
      filehdr->snaplen = SWAPLONG(filehdr->snaplen);
      filehdr->linktype = SWAPLONG(filehdr->linktype);      
    }
  
  /* Store the size of the pcap packet header, *as* *on* *disk*,
   * in the handle, for convenience. It must be as on disk to
   * work on both 64- and 32-bit architectures.
   */
  if (magic == PATCHED_TCPDUMP_MAGIC)
    /*
     * XXX - the patch that's in some versions of libpcap
     * changes the packet header but not the magic number;
     * we'd have to use some hacks^H^H^H^H^Hheuristics to
     * detect that.
     */
    pn->trace.pkthdr_size = sizeof(struct pcapnav_patched_pkthdr);
  else
    pn->trace.pkthdr_size = sizeof(struct pcapnav_pkthdr);

  pn->chain_buf = __pcapnav_buf_new(MAX_PACKET_SIZE(pn) *
				    MAX_CHAIN_LENGTH);
  if (!pn->chain_buf)
    goto cleanup_return;

  pn->search_buf = __pcapnav_buf_new(MAX_BYTES_FOR_DEFINITE_HEADER(pn));
  if (!pn->search_buf)
    goto cleanup_return;

  /* Get length of file: */
  if (fseek(fp, 0, SEEK_END) != 0)
    {
      fp_log = fopen(logpath, "a");

      if (fp_log == NULL) {
         fprintf(stderr, "Can't open the log file pcapLog.txt\n");
      }

      else
      {
          fprintf(fp_log, "Could not determine file length, fseek failed: %s with error %s\n", filepath, strerror(errno)); //fname, strerror(errno));
          fclose(fp_log);
      }
      //fclose(fp_log);

      D(("Couldn't determine file length, fseek() failed: %s\n", strerror(errno)));

      //fprintf(stderr, "Couldn't determine the file length, fseek failed: %s for file %s", strerror(errno), fname);

      goto cleanup_return;
    }

  if ((pn->trace.length = ftell(fp)) < 0)
    {
      fp_log = fopen(logpath, "a");

      if (fp_log == NULL) {
         fprintf(stderr, "Can't open the log file pcapLog.txt\n");
      }
      else
      {
          fprintf(fp_log, "Could not determine file length, ftell failed: %s with error %s\n", filepath, strerror(errno)); //fname, strerror(errno));
          fclose(fp_log);
      }
      //fclose(fp_log);

      D(("Couldn't determine file length, ftell() failed: %s\n", strerror(errno)));

      //fprintf(stderr, "Coudln't determine file length, ftell failed: %s for file %s\n", strerror(errno), fname);

      goto cleanup_return;
    }

  //fclose(fp_log);

  fclose(fp);  
  D_RETURN_(pn);
  
 cleanup_return:
  fclose(fp);
  //fclose(fp_log);
  
 free_return:
  FREE(pn);
  D_RETURN_(NULL);
}


void	        
pcapnav_close(pcapnav_t *pn)
{
  D_ENTER;

  if (!pn)
    D_RETURN;

  if (pn->pcap)
    pcap_close(pn->pcap);

  /* No need to flclose(pn->fp) -- we stole it from pcap */

  __pcapnav_buf_free(pn->search_buf);
  __pcapnav_buf_free(pn->chain_buf);

  FREE(pn);
  D_RETURN;
}


int                
pcapnav_get_pkthdr_size(pcapnav_t *pn)
{
  if (!pn)
    return 0;

  return pn->trace.pkthdr_size;
}


const struct pcap_file_header *
pcapnav_get_file_header(pcapnav_t *pn)
{
  if (!pn)
    return 0;

  return (const struct pcap_file_header *) &pn->trace.filehdr;
}


off_t              
pcapnav_get_offset(pcapnav_t *pn)
{
  if (!pn)
    return 0;

  return ftell(pcap_file(pn->pcap)) - sizeof(struct pcap_file_header);
}


int
pcapnav_set_offset(pcapnav_t *pn, off_t offset)
{
  off_t result;

  D_ENTER;
  
  if (!pn)
    D_RETURN_(-1);

  result = fseek(pcap_file(pn->pcap), offset + sizeof(struct pcap_file_header), SEEK_SET);
  D_RETURN_(result < 0 ? -1 : 0);
}


void               
pcapnav_get_timestamp(pcapnav_t *pn, struct bpf_timeval *tv)
{
  off_t position;
  struct pcap_pkthdr header;

  D_ENTER;

  if (!pn || !tv)
    D_RETURN;

  position = pcapnav_get_offset(pn);
  memset(tv, 0, sizeof(struct bpf_timeval));
  
  if (pcapnav_next(pn, &header))
    *tv = header.ts;
  
  pcapnav_set_offset(pn, position);
  D_RETURN;
}


pcap_t            *
pcapnav_pcap(pcapnav_t *pn)
{
  if (!pn)
    return NULL;

  return pn->pcap;
}



int	        
pcapnav_loop(pcapnav_t *pn, int num_packets,
	     pcap_handler callback, u_char *user_data)
{
  int n;

  D_ENTER;

  if (!pn || !callback)
    {
      D(("Invalid input.\n"));
      D_RETURN_(0);
    }
  
  n = pcap_loop(pn->pcap, num_packets, callback, user_data);
  D_RETURN_(n);
}


int	        
pcapnav_dispatch(pcapnav_t *pn, int num_packets,
		 pcap_handler callback, u_char *user_data)
{
  if (!pn || !callback)
    {
      D(("Invalid input.\n"));
      return 0;
    }

  return pcap_dispatch(pn->pcap, num_packets, callback, user_data);
}


const u_char      *
pcapnav_next(pcapnav_t *pn, struct pcap_pkthdr *header)
{
  const u_char * result;
  struct pcap_pkthdr dummy;

  D_ENTER;

  if (!pn)
    D_RETURN_(NULL);

  if (!header)
    header = &dummy;

  result = pcap_next(pn->pcap, header);
  D_RETURN_(result);
}


int                
pcapnav_has_next(pcapnav_t *pn)
{
  int result = 1;
  off_t position;

  D_ENTER;

  if (!pn)
    D_RETURN_(0);

  position = pcapnav_get_offset(pn);
  
  if (!pcapnav_next(pn, NULL))
    D_RETURN_(0);
  
  pcapnav_set_offset(pn, position);

  D_RETURN_(result);
}


pcapnav_result_t
pcapnav_goto_timestamp(pcapnav_t *pn, struct bpf_timeval *timestamp)
{
  pcapnav_result_t result;

  D_ENTER;
  
  if (!pn || !timestamp)
    D_RETURN_(PCAPNAV_ERROR);
  
  /* Make sure timespan of trace is in pn: */
  pcapnav_get_timespan(pn, NULL, NULL);
  result = __pcapnav_trace_find_packet_at_timestamp(pn, timestamp);
  
  D_RETURN_(result);
}


pcapnav_result_t             
pcapnav_goto_fraction(pcapnav_t *pn, double fraction)
{
  pcapnav_result_t result;
  off_t offset = 0;

  D_ENTER;
  
  if (!pn)
    D_RETURN_(PCAPNAV_ERROR);

  /* Make sure span of trace is in pn: */
  pcapnav_get_timespan(pn, NULL, NULL);
  
  /* Assert 0 <= fraction <= 1: */
  
  if (fraction > 1.0)
    fraction = 1.0;

  if (fraction < 0.0)
    fraction = 0.0;
  
  offset = (pn->end_offset - pn->start_offset) * fraction;
  result = __pcapnav_trace_find_packet_at_offset(pn, offset, PCAPNAV_CMP_ANY);
  
  D_RETURN_(result);
}


pcapnav_result_t             
pcapnav_goto_offset(pcapnav_t *pn, off_t offset, pcapnav_cmp_t boundary)
{
  pcapnav_result_t result;

  D_ENTER;

  if (!pn)
    D_RETURN_(PCAPNAV_ERROR);

  /* Make sure span of trace is in pn: */
  pcapnav_get_timespan(pn, NULL, NULL);
  result = __pcapnav_trace_find_packet_at_offset(pn, offset, boundary);
  
  D_RETURN_(result);
}


int             
pcapnav_get_timespan(pcapnav_t *pn, struct bpf_timeval *start, struct bpf_timeval *end)
{
  D_ENTER;

  if (!pn)
    D_RETURN_(-1);

  if ((pn->start_time.tv_sec == 0)  &&
      (pn->start_time.tv_usec == 0) &&
      (pn->end_time.tv_sec == 0)    &&
      (pn->end_time.tv_usec == 0))
    {
      /* We have not yet looked up the timespan and offsets
       * of the trace file already. */

      __pcapnav_trace_find_start(pn);
      __pcapnav_trace_find_end(pn);
    }
  
  if (start)
    *start = pn->start_time;
  
  if (end)
    *end = pn->end_time;

  D_RETURN_(0);
}


off_t
pcapnav_get_span(pcapnav_t *pn)
{
  off_t result;

  D_ENTER;

  if (!pn)
    D_RETURN_(0);

  if ((pn->start_time.tv_sec == 0)  &&
      (pn->start_time.tv_usec == 0) &&
      (pn->end_time.tv_sec == 0)    &&
      (pn->end_time.tv_usec == 0))
    {
      /* We have not yet looked up the timespan and offsets of the trace file. */

      __pcapnav_trace_find_start(pn);
      __pcapnav_trace_find_end(pn);
    }
  
  result = pn->end_offset - pn->start_offset;
  D_RETURN_(result);
}


off_t
pcapnav_get_size(pcapnav_t *pn)
{
  if (!pn)
    return 0;

  return pn->size - sizeof(struct pcap_file_header);
}


void
pcapnav_timeval_init(struct bpf_timeval *tv,
		     int sec, int usec)
{
  if (! tv)
    return;

  memset(tv, 0, sizeof(struct bpf_timeval)); /* Let's be thorough. */
  tv->tv_sec = sec;
  tv->tv_usec = usec;
}


int
pcapnav_timeval_cmp(const struct bpf_timeval *tv1,
		    const struct bpf_timeval *tv2)
{
  if (!tv1 || !tv2)
    return 0;

  if (tv1->tv_sec < tv2->tv_sec)
    return -1;

  if (tv1->tv_sec > tv2->tv_sec)
    return 1;

  if (tv1->tv_usec < tv2->tv_usec)
    return -1;

  if (tv1->tv_usec > tv2->tv_usec)
    return 1;
  
  return 0;
}


void               
pcapnav_timeval_sub(const struct bpf_timeval *tv1,
		    const struct bpf_timeval *tv2,
		    struct bpf_timeval *tv_out)
{
  __pcapnav_util_timeval_sub(tv1, tv2, tv_out);
}


void               
pcapnav_timeval_add(const struct bpf_timeval *tv1,
		    const struct bpf_timeval *tv2,
		    struct bpf_timeval *tv_out)
{
  __pcapnav_util_timeval_add(tv1, tv2, tv_out);
}


double             
pcapnav_get_time_fraction(pcapnav_t *pn,
			  const struct bpf_timeval *tv)
{
  off_t offset;
  struct pcap_pkthdr hdr;
  double full_span, current_span, fraction, result;

  D_ENTER;

  if (!pn)
    D_RETURN_(0.0);

  /* Make sure timestamps are initialized */

  pcapnav_get_timespan(pn, NULL, NULL);
  full_span = __pcapnav_util_timeval_diff(&pn->end_time, &pn->start_time);

  if (!tv)
    {
      struct pcap_pkthdr hdr2;

      /* Obtain current packet header by reading one packet
       * and then rewinding back to original position. */
      
      if ((offset = ftell(pn->fp)) < 0)
	D_RETURN_(0.0);
      
      if (fread((void *) &hdr, sizeof(struct pcap_pkthdr), 1, pn->fp) != 1)
	D_RETURN_(0.0);
      
      if (fseek(pn->fp, offset, SEEK_SET) < 0)
	{
	  D(("fseek() failed: %s\n", strerror(errno)));
	  D_RETURN_(0.0);
	}

      __pcapnav_header_extract(pn, (u_char*) &hdr, &hdr2);
      current_span = __pcapnav_util_timeval_diff(&hdr2.ts, &pn->start_time);
    }
  else
    {
      current_span = __pcapnav_util_timeval_diff(tv, &pn->start_time);
    }

  fraction = current_span / full_span;

  if (fraction < 0.0)
    fraction = 0.0;

  if (fraction > 1.0)
    fraction = 1.0;

  result = fabs(fraction);
  D_RETURN_(result);
}


double             
pcapnav_get_space_fraction(pcapnav_t *pn, off_t offset)
{
  double fraction, result;
  
  D_ENTER;

  if (!pn || offset == 0)
    D_RETURN_(0.0);

  /* Make sure timestamps + offsets are initialized */

  pcapnav_get_timespan(pn, NULL, NULL);

  fraction =
    ((double)(offset)) /
    (pn->end_offset - pn->start_offset);

  if (fraction < 0.0)
    fraction = 0.0;

  if (fraction > 1.0)
    fraction = 1.0;

  result = fabs(fraction);
  D_RETURN_(fraction);
}


int
pcapnav_get_current_timestamp(pcapnav_t *pn, struct bpf_timeval *tv)
{
  struct pcap_pkthdr hdr;
  off_t position;

  D_ENTER;

  if (!pn || !tv)
    D_RETURN_(0);
  
  position = pcapnav_get_offset(pn);
  
  if (fread((void *) &hdr, sizeof(struct pcap_pkthdr), 1, pn->fp) != 1)
    {
      pcapnav_set_offset(pn, position);
      D_RETURN_(0);
    }

  *tv = hdr.ts;  
  pcapnav_set_offset(pn, position);

  D_RETURN_(1);
}


char *
pcapnav_geterr(pcapnav_t *pn)
{
  return pcap_geterr(pn->pcap);
}


pcap_dumper_t *
pcapnav_dump_open_tm(pcap_t *pcap, const char *filename, pcapnav_dumpmode_t mode, const char* classdirectory)
{
  if (!pcap)
    {
      D(("Input error.\n"));
      return NULL;
    }

  /* If the user requests standard output, just pass
   * through to pcap.
   */
  if (filename[0] == '-' && filename[1] == '\0')
    {
      D(("Passing through to pcap_dump_open().\n"));
      return pcap_dump_open(pcap, filename);
    }
  
  switch (mode)
    {
    case PCAPNAV_DUMP_APPEND_FAST:
      return pcapnav_append_fast(pcap, filename, classdirectory);
      
    case PCAPNAV_DUMP_APPEND_SAFE:
      return pcapnav_append_safe(pcap, filename, classdirectory);

    case PCAPNAV_DUMP_TRUNC:
    default:      
      return pcap_dump_open(pcap, filename);
    }
  
  return NULL;
}
