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
#ifndef __pcapnav_util_h
#define __pcapnav_util_h

#include <stdlib.h>
#include <stdio.h>

/**
 * __pcapnav_util_timeval_diff - returns timestamp delta.
 * @tv1: first timeval.
 * @tv2: second timeval.
 *
 * The function takes two timevals and returns their
 * difference in time, tv2 - tv1, as a double, in seconds.
 *
 * Returns: time difference in seconds.
*/
double __pcapnav_util_timeval_diff(const struct bpf_timeval *tv1, const struct bpf_timeval *tv2);


/**
 * __pcapnav_util_timeval_less_than - timeval comparison.
 * @tv1: first timeval.
 * @tv2: second timeval.
 *
 * The function returns %TRUE if timestamp @tv1 is
 * chronologically less than timestamp @tv2, %FALSE
 * otherwise, or on error.
 *
 * Returns: result of comparison.
 */
int    __pcapnav_util_timeval_less_than(const struct bpf_timeval *t1, const struct bpf_timeval *t2);


/**
 * __pcapnav_util_timeval_sub - subtracts two timevals.
 * @tv1: first timeval.
 * @tv2: second timeval.
 *
 * The function returns the difference between the two
 * timevals ("@tv1 - @tv2") in @tv_out.
 */
void   __pcapnav_util_timeval_sub(const struct bpf_timeval *tv1,
				  const struct bpf_timeval *tv2,
				  struct bpf_timeval *tv_out);

/**
 * __pcapnav_util_timeval_add - adds two timevals.
 * @tv1: first timeval.
 * @tv2: second timeval.
 *
 * The function returns the sum of the two
 * timevals ("@tv1 - @tv2") in @tv_out.
 */
void   __pcapnav_util_timeval_add(const struct bpf_timeval *tv1,
				  const struct bpf_timeval *tv2,
				  struct bpf_timeval *tv_out);

#endif

