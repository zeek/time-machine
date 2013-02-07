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
#ifndef __pcapnav_debug_h
#define __pcapnav_debug_h

#include <pcapnav.h>

/* This stuff is declared no matter whether we have -DPCAPNAV_DEBUG or not.
 */

void     pcapnav_debug_enter(const char *function);
void     pcapnav_debug_return(const char *function);
int      pcapnav_debuggable(void);


#ifdef PCAPNAV_DEBUG
/**
 * D - prints debugging output
 * @x: debugging information.
 *
 * Use this macro to output debugging information. @x is
 * the content as you would pass it to printf(), including
 * braces to make the arguments appear as one argument to
 * the macro. The macro is automatically deleted if -DPCAPNAV_DEBUG
 * is not passed at build time.
 */
#define D(x)                  if (pcapnav_debuggable()) { printf("%s/%i: ", __FILE__, __LINE__); printf x ; }

/**
 * D_ASSERT - debugging assertion.
 * @exp: expression to evaluate.
 * @msg: message to output if @exp fails.
 *
 * The macro outputs @msg if the expression @exp evaluates
 * to %FALSE.
 */
#define D_ASSERT(exp, msg)    if (!(exp) && pcapnav_debuggable()) { printf("%s/%i: %s\n", __FILE__, __LINE__, msg); }

/**
 * D_ASSERT_PTR - pointer existence assertion.
 * @ptr: pointer to check.
 *
 * The macro asserts the existence (i.e. non-NULL-ness) of
 * the given pointer, and outpus a message if it is %NULL.
 */
#define D_ASSERT_PTR(ptr)     D_ASSERT(ptr, "pointer is NULL.")

/**
 * D_ENTER - function call tracing.
 * 
 * The macro updates internal debugging state when entering
 * the function where this macro is used. Use it at the beginning
 * of a function, but don't forget to properly match up %D_ENTER
 * with %D_RETURN! The macro outpus the name of the entered function
 * indented by the current nesting level.
 */
#define D_ENTER               pcapnav_debug_enter(__FUNCTION__)

/**
 * D_RETURN - function call tracing.
 *
 * The macro updates internal debugging state when leaving
 * the function where this macro is used. Use this macro
 * wherever the function can be left, and don't forget D_ENTER.
 */
#define D_RETURN              do { pcapnav_debug_return(__FUNCTION__); return; } while (0)

/**
 * D_RETURN_ - function call tracing.
 * @x:
 *
 * Same as %D_RETURN, but for return with an argument.
 */
#define D_RETURN_(x)          do { pcapnav_debug_return(__FUNCTION__); return (x); } while (0)

#else

#define D(x)                  
#define D_ASSERT(exp, msg)    
#define D_ASSERT_PTR(ptr)     
#define D_ENTER
#define D_RETURN              return
#define D_RETURN_(x)          return (x)

#endif

#endif 
