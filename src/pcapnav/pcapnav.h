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
con
*/
#ifndef __pcapnav_h
#define __pcapnav_h

#include <pcap.h>

#if !defined __OpenBSD__
#define bpf_timeval timeval
#endif

/* Similar to pcap, pcapnav provides opaque handles to
 * its clients, that need to be passed to its
 * functions as first parameter.
 */
typedef struct pcapnav pcapnav_t;

/* The various error codes that pcapnav functions
 * may return. Used by pcapnav_goto_fraction() and
 * pcapnav_goto_timestamp() to report the certainty
 * of the result.
 */
typedef enum {
  PCAPNAV_ERROR,
  PCAPNAV_NONE,
  PCAPNAV_CLASH,
  PCAPNAV_PERHAPS,
  PCAPNAV_DEFINITELY
} pcapnav_result_t;


/* pcapnav_goto_offset() can jump to a packet close to a given offset.
 * Using one of the values below, you can restrict the area around
 * the requested offset where the algorithm will look.
 */
typedef enum {
  PCAPNAV_CMP_LEQ, /* less than or equal */
  PCAPNAV_CMP_GEQ, /* greater than or equal */
  PCAPNAV_CMP_ANY  /* anything */
} pcapnav_cmp_t;

/* File modes for pcapnav_dump_open -- we can either truncate to
 * zero (and create if file doesn't exist), or we can append. When
 * appending, we can just blindly append at the end of the input
 * trace (PCAPNAV_DUMP_APPEND_FAST), or do safety checks to make
 * sure that the last packet of the trace is not corrupted
 * (PCAPNAV_DUMP_APPEND_SAFE).
 */
typedef enum {
  PCAPNAV_DUMP_TRUNC,
  PCAPNAV_DUMP_APPEND_SAFE,
  PCAPNAV_DUMP_APPEND_FAST
} pcapnav_dumpmode_t;


/* Runtime flags for the library. Right now this is
 * only debugging stuff: whether to display debugging
 * output or not, and the maximum calldepth up to which
 * output is printed.
 */
struct pcapnav_runtime_options
{
  int          debug;
  u_int        calldepth_limit;
};

extern struct pcapnav_runtime_options pcapnav_runtime_options;


#ifdef __cplusplus
extern "C" {
#endif


/**
 * pcapnav_init - initializes the library.
 *
 * The function initializes the static options of the
 * library, such as debugging switches etc.
 */
void               pcapnav_init(void);


/**
 * pcapnav_open_offline - opens a trace.
 * @filename: name of trace to open.
 *
 * The function opens the trace file with name @filename,
 * allocates a handle for the file, and returns it.
 * When you're done, get rid of the handle using
 * pcapnav_close().
 *
 * Returns: handle for trace, or %NULL when
 * an error occured (such as invalid file type,
 * file not readable etc). In that case check errno to
 * see what went wrong.
 */
pcapnav_t         *pcapnav_open_offline_tm(const char *filename, const char* classdirectory);


/**
 * pcapnav_close - closes the a trace.
 * @pn: pcapnav handle.
 *
 * The function closes the trace handled through @pcap
 * and cleans file and cleans up @pcap.
 */ 
void	           pcapnav_close(pcapnav_t *pn);


/**
 * pcapnav_pcap - provides pcap handler
 * @pn: pcapnav handler.
 *
 * Use this function for interaction with libpcap. It
 * returns the pcap handler for the given pcapnav handler.
 * Do *not* mess with this unless you have to -- do not
 * close the pcap handler etc behind pcapnav's back ...
 *
 * Returns: pcap handler, or %NULL on invalid input.
 */
pcap_t            *pcapnav_pcap(pcapnav_t *pn);


/**
 * pcapnav_get_file_header - returns pointer to this trace's file header.
 * @pn: pcapnav handle
 *
 * The function returns a pointer to the structure containing info about
 * the trace file handled through @pn. No data is allocated, nothing needs
 * to be freed by you.
 *
 * Returns: const pointer to struct pcap_pkthdr.
 */
const struct pcap_file_header * pcapnav_get_file_header(pcapnav_t *pn);


/**
 * pcapnav_get_pkthdr_size - returns this trace's packet header size.
 * @pn: pcapnav handle
 *
 * The function returns the actual bytesize of the packet
 * header structures in the trace for @pn.
 *
 * Returns: size in bytes.
 */
int                pcapnav_get_pkthdr_size(pcapnav_t *pn);


/**
 * pcapnav_get_offset - returns current file offset.
 * @pn: pcapnav handler.
 *
 * Returns: offset, or 0 on invalid input.
 */
off_t              pcapnav_get_offset(pcapnav_t *pn);


/**
 * pcapnav_get_timestamp - returns current packet's timestamp.
 * @pn: pcapnav handler.
 * @tv: result value.
 *
 * The function returns the timestamp of next packet to be read in @tv,
   without modifying the read marker.
 */
void               pcapnav_get_timestamp(pcapnav_t *pn, struct bpf_timeval *tv);


/**
 * pcapnav_set_offset - sets current file offset.
 * @pn: pcapnav handler.
 * @offset: new offset.
 *
 * You can use this function to set the file offset for
 * the given pcapnav handle to an offset relative to
 * the start of the file. You can use this to quickly
 * jump to a known valid offset in a trace. Caution:
 * this function does take into account the trace file
 * header, so a jump to offset 0 really jumps to offset
 * sizeof(struct pcap_file_header).
 *
 * Returns: 0 if successful, negative value otherwise.
 * On error, errno is set accordingly.
 */
int               pcapnav_set_offset(pcapnav_t *pn, off_t offset);


/**
 * pcapnav_get_current_timestamp - returns timestamp of current packet.
 * @pn: pcapnav handle.
 * @tv: pointer to timestamp receiving result
 *
 * The function returns the timestamp of the packet at the current
 * position in the file. It assumes that the handle currently points
 * to a valid pcap packet header. The stream position is unchanged
 * when the function returns.
 *
 * Returns: 0 on error, value > 0 on success, and timestamp in @ts
 */
int                pcapnav_get_current_timestamp(pcapnav_t *pn, struct bpf_timeval *tv);


/**
 * pcapnav_loop - reads multiple packets from trace.
 * @pn: pcapnav handle.
 * @num_packets: number of packets to read.
 * @handler: callback for each packet.
 * @user_data: arbitrary user data passed through.
 *
 * The function reads up to @num_packets from the
 * trace handled by @pcap and calls @handler for
 * each packet read. As in pcap, a negative value
 * for @num_packets will cause the function to loop
 * until the end of file is hit, or an error occurs.
 *
 * Returns: number of packets read, or 0 when there
 * are no more packets to be read, or a negative
 * value when there was an error.
 */
int	           pcapnav_loop(pcapnav_t *pn,
				int num_packets,
				pcap_handler handler,
				u_char *user_data);
  
/**
 * pcapnav_dispatch - alias for pcapnav_loop().
 * @pn: pcapnav handle.
 * @num_packets: number of packets to read.
 * @handler: callback for each packet.
 * @user_data: arbitrary user data passed through.
 *
 * This function is like pcapnav_loop(), except
 * it used pcap_dispatch() internally. There shouldn't
 * be any real difference for trace files; the function
 * is just here to anticipate changes in the pcap
 * implementation in the future. See the pcap documentation
 * for the remaining details.
 *
 * Returns: number of packets read, or 0 when there
 * are no more packets to be read, or a negative
 * value when there was an error.
 */ 
int	           pcapnav_dispatch(pcapnav_t *pn,
				    int num_packets,
				    pcap_handler handler,
				    u_char *user_data);

/**
 * pcapnav_next - reads a single packet.
 * @pn: pcapnav handle.
 * @header: pointer to allocated pcapnav packet header.
 *
 * The function reads a single packet into the internal
 * buffer and returns the packet's parameters through
 * @header. The packet data is returned. If you need to
 * keep the packet data around, you need to allocate
 * a chunk of data of size header->caplen and memcpy()
 * the data over. If no more packets can be read, %NULL
 * is returned. You don't need to pass @header if you
 * don't want to.
 *
 * Returns: packet data, and pcap packet header through @header.
 */
const u_char      *pcapnav_next(pcapnav_t *pn,
				struct pcap_pkthdr *header);

/**
 * pcapnav_has_next - checks whether more packets are readable.
 * @pn: pcapnav handle.
 *
 * The function checks whether more packets can be read from
 * the trace, from the current file position. The position
 * is not changed after the function returns.
 *
 * Returns: 0 if no more packets are readable, value > 0
 * otherwise.
 */
int                pcapnav_has_next(pcapnav_t *pn);


/**
 * pcapnav_goto_timestamp - jumps to given timestamp in trace.
 * @pn: pcapnav handle.
 * @timestamp: timestamp to jump to.
 *
 * The function tries to jump to the packet in the trace whose
 * timestamp is as close as possible to @timestamp.
 *
 * Returns: success state.
 */
pcapnav_result_t   pcapnav_goto_timestamp(pcapnav_t *pn,
					  struct bpf_timeval *timestamp);


/**
 * pcapnav_goto_fraction - jumps as closely as possible to percentage offset in trace.
 * @pn: pcapnav handle.
 * @fraction: position to jump to.
 *
 * The function tries to jump as closely as possible to a
 * given fraction in the file, passed through @fraction
 * as a percentage value between 0.0 and 1.0 (thus 0.5 means
 * middle of file). Values of @fraction outside the [0.0, 1.0]
 * interval are adjusted to 0.0 or 1.0, respectively.
 *
 * Returns: success state.
 */
pcapnav_result_t   pcapnav_goto_fraction(pcapnav_t *pn,
					 double fraction);


/**
 * pcapnav_goto_offset - jumps as closely as possible to a given offset.
 * @pn: pcapnav handle.
 * @offset: position to jump to.
 * @boundary: where around the offset to jump to.
 *
 * The function tries to jump as closely as possible to a
 * valid offset in the file near @offset. The difference
 * to pcapnav_set_offset() is that the latter simply modifies
 * the file stream position, trusting that you know what
 * you're doing. An offset of 0 is the first packet in the
 * trace (i.e., the trace file header is not included). Using &boundary,
 * you can limit the result to packets below, beyond, or anywhere around
 * the requested offset.
 *
 * Returns: success state.
 */
pcapnav_result_t   pcapnav_goto_offset(pcapnav_t *pn,
				       off_t offset,
				       pcapnav_cmp_t boundary);


/**
 * pcapnav_get_timeframe - retrieves trace's time span.
 * @pn: pcapnav handle.
 * @start: pointer to timeval that receives first packet's timestamp.
 * @end: pointer to timeval that receives last packet's timestamp.
 *
 * The function inspects the trace file and retrieves the timestamps
 * of the first and last packet in the trace. These timestamps are
 * then  returned through the @start and @end pointers. Subsequent
 * calls to this function are faster, because the timestamps are
 * cached. If you're not interested in either the start or end timestamp,
 * you can pass %NULL for these pointers.
 *
 * Returns: negative value on error, 0 on success, and the timestamps
 * in @start and @end, if provided.
 */
int                pcapnav_get_timespan(pcapnav_t *pn,
                                        struct bpf_timeval *start,
					struct bpf_timeval *end);

/**
 * pcapnav_get_span - retrieves the offset of the last packet.
 * @pn: pcapnav handle.
 *
 * Returns: the offset of the last packet in the trace.
 */
off_t              pcapnav_get_span(pcapnav_t *pn);

  
/**
 * pcapnav_get_size - returns the size of the packets in the trace file.
 * @pn: pcapnav handle.
 *
 * Returns: the size of the trace minus the file header size.
 */
off_t              pcapnav_get_size(pcapnav_t *pn);


/**
 * pcapnav_timeval_init - initialize timevals.
 * @tv: pointer to timeval
 * @sec: seconds.
 * @usec: microseconds.
 *
 * The function initializes the given timeval structure @tv
 * with @sec and @usec.
 */
void               pcapnav_timeval_init(struct bpf_timeval *tv,
					int sec, int usec);


/**
 * pcapnav_timeval_cmp - compares timevals.
 * @tv1: pointer to input timeval.
 * @tv2: pointer to input timeval.
 *
 * The function compares the timevals in @tv1 and @tv2.
 *
 * Returns: negative value if @tv1 is smaller than @tv2,
 * 0 if they're identical, and 1 if @tv1 is greater than @tv2.
 */
int                pcapnav_timeval_cmp(const struct bpf_timeval *tv1,
				       const struct bpf_timeval *tv2);


/**
 * pcapnav_timeval_sub - subtracts timevals.
 * @tv1: pointer to input timeval.
 * @tv2: pointer to input timeval.
 * @tv_out: pointer to result interval.
 *
 * The function subtracts @tv2 from @tv1 in the timeval pointed to
 * by @tv_out. If @tv1 represents an earlier time than @tv2, then
 * the result is a zero timestamp.
 */
void               pcapnav_timeval_sub(const struct bpf_timeval *tv1,
				       const struct bpf_timeval *tv2,
				       struct bpf_timeval *tv_out);

/**
 * pcapnav_timeval_add - adds timevals.
 * @tv1: pointer to input timeval.
 * @tv2: pointer to input timeval.
 * @tv_out: pointer to result interval.
 *
 * The function adds @tv2 to @tv1 and returns the result in the
 * timeval pointed to by @tv_out.
 */
void               pcapnav_timeval_add(const struct bpf_timeval *tv1,
				       const struct bpf_timeval *tv2,
				       struct bpf_timeval *tv_out);

/**
 * pcapnav_get_time_fraction - returns a time fraction.
 * @pn: pcapnav handle.
 * @tv: timestamp to calculate with.
 *
 * The function returns the fraction of the trace's timespan that
 * a timestamp is at. If @tv is %NULL, the timestamp at the
 * current file offset is used, @tv otherwise. If @tv is out of
 * range, 0 or 1 is returned.
 *
 * Returns: value in [0, 1].
 */
double             pcapnav_get_time_fraction(pcapnav_t *pn,
					     const struct bpf_timeval *tv);


/**
 * pcapnav_get_space_fraction - returns an offset's space fraction.
 * @pn: pcapnav handle.
 * @offset:  offset to calculate with.
 *
 * The function returns the fraction of the trace's size that
 * an offset is at. If @offset is out of range, 0 or 1 is returned.
 *
 * Returns: value in [0, 1].
 */
double             pcapnav_get_space_fraction(pcapnav_t *pn,
					      off_t offset);


/**
 * pcapnav_geterr - returns description of last error.
 * @pn: pcapnav handle.
 *
 * The function returns a string describing any errors that
 * may have occured. It's not your memory, so get your hands
 * off or strdup() when you want to keep it around.
 *
 * Returns: string containing error message
 */
char              *pcapnav_geterr(pcapnav_t *pn);


/**
 * pcapnav_dump_open - creates a pcap output dumper.
 * @pcap: pcap handle
 * @filename: name of the output file.
 * @mode: the output file mode.
 *
 * The function returns a pcap dumper for the file specified in @filename.
 * When @mode is %PCAPNAV_DUMP_TRUNC, the file is truncated if it exists,
 * otherwise created. When @mode is %PCAPNAV_DUMP_APPEND_FAST or
 * %PCAPNAV_DUMP_APPEND_SAFE, packets are appended at the end of the file.
 * The latter mode checks for truncated packets at the end of trace files,
 * whereas the former simply starts appending at the end of the file.
 * The mode is meaningless when @filename is "-" and the output stream is
 * standard output. In case of appending to a file, the snaplen of the
 * existing file is updated in case the one for @pcap is larger than the
 * existing one.
 *
 * Returns: a pcap dumper, or %NULL if something went wrong, in which
 * case you'll find the reason in the error buffer in the @pcap handle.
 */
pcap_dumper_t     *pcapnav_dump_open_tm(pcap_t *pcap, const char *filename,
				     pcapnav_dumpmode_t mode, const char* classdirectory);

#ifdef __cplusplus
}
#endif

#endif
