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
#ifndef __pcapnav_buf_h
#define __pcapnav_buf_h

/* This is a data buffer abstraction, supporting a fixed-size data buffer
 * as initialized upon construction, with an adjustable buffer pointer
 * pointing somewhere inside the buffer, and with an adjustable end-of-
 * buffer pointer for adjustable boundary checking.
 *
 * It also has an offset member that stores information about the stream
 * position from which data was last read into this buffer.
 */
struct pcapnav_buf {

  /* Actual data buffer */
  u_char                    *buf;     

  /* Buffer into buffer, for iteration etc. */
  u_char                    *bufptr;  

  /* End-of-buffer pointer, adjustable, but <= buf + size */
  u_char                    *bufend;  

  /* Allocated size of buf -- never changed. */
  int                        size;

  /* Offset of stream used for last read of disk data
   * into this buffer */
  off_t                      offset;
};

/**
 * __pcapnav_buf_new - allocates a buffer to a given size
 * @size: size of buffer.

 * Returns: new buffer structure, or NULL if out of memory.
 */
struct pcapnav_buf          *__pcapnav_buf_new(int size);

/**
 * __pcapnav_buf_fill - fills a buffer with disk data.
 * @buf: buffer to fill.
 * @fp: file pointer to use in fread().
 * @offset: offset to move @fp to before reading data.
 * @whence: where to set offset from, think fseek().
 * @size: number of bytes to read.
 *
 * The function fills @buf with disk data read through the
 * stream @fp. The stream is temporarily positioned through
 * @offset and @whence, but returned to the original position
 * before the function returns.
 */
int                          __pcapnav_buf_fill(struct pcapnav_buf *buf, FILE *fp,
						off_t offset, int whence, int size);

/**
 * pcapnav_buf_free - cleans up and deallocates buffer.
 * @buf: buffer to free.
 *
 * The function releases all memory held by the buffer structure.
 */
void                         __pcapnav_buf_free(struct pcapnav_buf *buf);


/**
 * __pcapnav_buf_get_pointer_offset - returns offset of pointer from start of buffer.
 * @buf: buffer to query.
 *
 * The function returns the offset of the bufptr member from the
 * beginning of the buffer, in bytes.
 * 
 * Returns: pointer offset.
 */
int                          __pcapnav_buf_get_pointer_offset(struct pcapnav_buf *buf);


/**
 * __pcapnav_buf_get_offset - returns offset in file represented by current buffer setting.
 * @buf: buffer to query.
 *
 * The function returns the offset in the file that the current buffer
 * offset pointer represents (i.e., the offset in the file of the byte
 * that is currently pointed at by bufptr). This value is relative to
 * the end of the pcap file header.
 *
 * Returns: offset in file.
 */
off_t                        __pcapnav_buf_get_offset(struct pcapnav_buf *buf);


/**
 * __pcapnav_buf_get_size - returns currently usable size of buffer.
 * @buf: buffer to query.
 *
 * The function returns the size of the buffer in bytes, as defined by
 * the space between the buf and bufend pointers in @buf. This is *not*
 * (necessarily) the size of the buffer as it was allocated (the size
 * member), as this never changed.
 *
 * Returns: size in bytes.
 */
int                          __pcapnav_buf_get_size(struct pcapnav_buf *buf);

/**
 * __pcapnav_buf_move_end - adjusts buffer-end pointer, relatively.
 * @buf: buffer to adjust.
 * @delta: how to move end-of-buffer, in bytes.
 *
 * The function adjusts the bufend member relative to its current
 * setting, by @delta bytes. Sanity-checking to see if the resulting
 * value is within legal bounds is performed.
 */
void                         __pcapnav_buf_move_end(struct pcapnav_buf *buf, int delta);

/**
 * __pcapnav_buf_set_end - adjusts buffer-end pointer, absolutely.
 * @buf: buffer to adjust.
 * @delta: where to move end-of-buffer, in bytes.
 *
 * The function adjusts the bufend member relative to the start of
 * the buffer, offsetting from it by @pos bytes. Sanity-checking to
 * see if the resulting value is within legal bounds is performed.
 */
void                         __pcapnav_buf_set_end(struct pcapnav_buf *buf, int pos);

/**
 * __pcapnav_buf_move_pointer - adjusts buffer pointer, relatively.
 * @buf: buffer to adjust.
 * @delta: how to move buffer pointer, in bytes.
 *
 * The function adjusts the bufptr member relative to its current
 * setting, by @delta bytes. Sanity-checking to see if the resulting
 * value is within legal bounds is performed.
 */
void                         __pcapnav_buf_move_pointer(struct pcapnav_buf *buf, int delta);

/**
 * __pcapnav_buf_set_pointer - adjusts buffer pointer, absolutely.
 * @buf: buffer to adjust.
 * @delta: where to move buffer pointer, in bytes.
 *
 * The function adjusts the bufptr member relative to the start of
 * the buffer, offsetting from it by @pos bytes. Sanity-checking to
 * see if the resulting value is within legal bounds is performed.
 */
void                         __pcapnav_buf_set_pointer(struct pcapnav_buf *buf, int pos);


/**
 * __pcapnav_buf_pointer_valid - checks if buffer pointer is in valid range.
 * @buf: buffer to query.
 *
 * The function checks whether the bufptr member is >= buf and <= bufend.
 *
 * Returns: 1 if bufptr is within range, 0 otherwise.
 */
int                          __pcapnav_buf_pointer_valid(struct pcapnav_buf *buf);

#endif
