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
#include <string.h>
#include <errno.h>
#include "pcapnav.h"
#include "pcapnav_debug.h"
#include "pcapnav_private.h"
#include "pcapnav_macros.h"
#include "pcapnav_buf.h"


struct pcapnav_buf          *
__pcapnav_buf_new(int size)
{
  struct pcapnav_buf *result;

  result = NEW(struct pcapnav_buf);
  
  if (!result)
    return NULL;

  result->buf = malloc(sizeof(u_char) * size);
  if (!result->buf)
    goto cleanup_return;

  result->bufptr = result->buf;
  result->bufend = result->buf + size;
  result->size   = size;
  
  return result;

 cleanup_return:
  free(result);
  return NULL;
}


int
__pcapnav_buf_fill(struct pcapnav_buf *buf, FILE *fp, off_t offset, int whence, int size)
{
  off_t old_offset = 0;
  int  result = 0;

  if (!buf || !fp)
    return 0;

  if (offset)
    {
      old_offset = ftell(fp);
      if (fseek(fp, offset, whence) < 0)
	{
	  D(("fseek() to %lli failed: %s\n", (long long) offset, strerror(errno)));
	  return 0;
	}
    }

  buf->offset = ftell(fp);

  if (size > buf->size)
    size = buf->size;

  result = fread((char *) buf->buf, 1, size, fp);

  buf->bufend = buf->buf + result;
  buf->bufptr = buf->buf;
  
  if (feof(fp))
    clearerr(fp);

  if (offset)
    {
      if (fseek(fp, old_offset, SEEK_SET) < 0)
	{
	  D(("fseek() failed: %s\n", strerror(errno)));
	  return 0;
	}
    }

  return result;
}


void                         
__pcapnav_buf_free(struct pcapnav_buf *buf)
{
  if (!buf)
    return;

  FREE(buf->buf);
  FREE(buf);
}


int                          
__pcapnav_buf_get_pointer_offset(struct pcapnav_buf *buf)
{
  if (!buf)
    return 0;

  return buf->bufptr - buf->buf;
}


off_t                        
__pcapnav_buf_get_offset(struct pcapnav_buf *buf)
{
  if (!buf)
    return 0;

  return buf->offset + __pcapnav_buf_get_pointer_offset(buf);
}


int                          
__pcapnav_buf_get_size(struct pcapnav_buf *buf)
{
  if (!buf)
    return 0;

  return buf->bufend - buf->buf;
}


void                         
__pcapnav_buf_move_end(struct pcapnav_buf *buf, int delta)
{
  if (!buf)
    return;

  if (buf->bufend + delta < buf->buf)
    {
      buf->bufend = buf->buf;
      return;
    }
  
  if (buf->bufend + delta > buf->buf + buf->size)
    {
      buf->bufend = buf->buf + buf->size;
      return;
    }
  
  buf->bufend += delta;
}


void                         
__pcapnav_buf_set_end(struct pcapnav_buf *buf, int pos)
{
  if (!buf)
    return;

  if (pos < 1)
    return;
  
  if (pos > buf->size)
    pos = buf->size;
  
  buf->bufend = buf->buf + pos;
}


int                          
__pcapnav_buf_pointer_valid(struct pcapnav_buf *buf)
{
  if (!buf)
    return 0;

  return (buf->bufptr < buf->bufend);
}


void                         
__pcapnav_buf_move_pointer(struct pcapnav_buf *buf, int delta)
{
  if (!buf)
    return;
  
  buf->bufptr += delta;
}


void                         
__pcapnav_buf_set_pointer(struct pcapnav_buf *buf, int pos)
{
  if (!buf)
    return;

  if (pos < 0 || pos >= buf->size)
    return;

  buf->bufptr = buf->buf + pos;
}

