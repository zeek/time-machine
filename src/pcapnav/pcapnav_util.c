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

#include "pcapnav_macros.h"
#include "pcapnav_util.h"

double
__pcapnav_util_timeval_diff(const struct bpf_timeval *tv1, const struct bpf_timeval *tv2)
{
  double result = (tv2->tv_sec - tv1->tv_sec);
  result += (tv2->tv_usec - tv1->tv_usec) / 1000000.0;
  
  return result;
}


int
__pcapnav_util_timeval_less_than(const struct bpf_timeval *t1, const struct bpf_timeval *t2 )
{
  return (t1->tv_sec < t2->tv_sec ||
	  (t1->tv_sec == t2->tv_sec &&
	   t1->tv_usec < t2->tv_usec));
}



void 
__pcapnav_util_timeval_sub(const struct bpf_timeval *tv1,
			   const struct bpf_timeval *tv2,
			   struct bpf_timeval *tv_out)
{
  struct bpf_timeval tmp1, tmp2;
  struct bpf_timeval *t1 = &tmp1, *t2 = &tmp2;

  if (!tv1 || !tv2 || !tv_out)
    return;

  if (tv1->tv_sec < tv2->tv_sec ||
      (tv1->tv_sec == tv2->tv_sec && tv1->tv_usec < tv2->tv_usec))
    {
      tv_out->tv_sec  = 0;
      tv_out->tv_usec = 0;
      return;
    }

  tmp1 = *tv1;
  tmp2 = *tv2;

  tv_out->tv_sec = t1->tv_sec - t2->tv_sec;
  
  if (t1->tv_usec < t2->tv_usec)
    {
      tv_out->tv_sec -= 1;
      tv_out->tv_usec = t1->tv_usec + 1000000 - t2->tv_usec;      
    }
  else
    {
      tv_out->tv_usec  = t1->tv_usec  - t2->tv_usec;
    }
}


void 
__pcapnav_util_timeval_add(const struct bpf_timeval *tv1,
			   const struct bpf_timeval *tv2,
			   struct bpf_timeval *tv_out)
{
  struct bpf_timeval tmp1, tmp2;
  struct bpf_timeval *t1 = &tmp1, *t2 = &tmp2;

  if (!tv1 || !tv2 || !tv_out)
    return;
  
  tmp1 = *tv1;
  tmp2 = *tv2;

  tv_out->tv_sec = t1->tv_sec + t2->tv_sec;
  tv_out->tv_usec = t1->tv_usec + t2->tv_usec;
  
  if (tv_out->tv_usec >= 1000000)
    {
      ++(tv_out->tv_sec);
      tv_out->tv_usec -= 1000000;
    }			
}
