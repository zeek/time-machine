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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>

#include <pcapnav.h>
#include <pcapnav_debug.h>

static u_int calldepth = 0;

static void 
debug_whitespace(void)
{
  u_int i;
  
  for (i = 0; i < 2*calldepth; i++)
    printf("-");
}


void
pcapnav_debug_enter(const char *function)
{
  if (pcapnav_runtime_options.debug)
    {
      calldepth++;

      if (calldepth <= pcapnav_runtime_options.calldepth_limit)
	{
	  debug_whitespace();
	  printf("> %s()\n", function);
	}
    }
}


void
pcapnav_debug_return(const char *function)
{
  if (pcapnav_runtime_options.debug)
    {
      if (calldepth <= pcapnav_runtime_options.calldepth_limit)
	{
	  printf("<");
	  debug_whitespace();
	  printf(" %s()\n", function);
	}
      
      if (calldepth > 0)
	calldepth--;
    }
}


int
pcapnav_debuggable(void)
{
  return (pcapnav_runtime_options.debug &&
	  calldepth <= pcapnav_runtime_options.calldepth_limit);
}
