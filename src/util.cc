// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"
//#include "util-config.h"

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <string>
#include <vector>
#include <algorithm>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

//#include <openssl/hmac.h>


#ifdef HAVE_MALLINFO
# include <malloc.h>
#endif

//#include "input.h"
#include "util.h"
//#include "Obj.h"
//#include "Val.h"
//#include "NetVar.h"
//#include "Net.h"
//#include "Reporter.h"


static bool bro_rand_determistic = false;
static unsigned int bro_rand_state = 0;

unsigned int bro_prng(unsigned int  state)
	{
	// Use our own simple linear congruence PRNG to make sure we are
	// predictable across platforms.
	static const long int m = 2147483647;
	static const long int a = 16807;
	const long int q = m / a;
	const long int r = m % a;

	state = a * ( state % q ) - r * ( state / q );

	if ( state <= 0 )
		state += m;

	return state;
	}

long int bro_random()
	{
	if ( ! bro_rand_determistic )
		return random(); // Use system PRNG.

	bro_rand_state = bro_prng(bro_rand_state);

	return bro_rand_state;
	}

int hmac_key_set = 0;
uint8 shared_hmac_md5_key[16];

void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16])
{
/*
	if ( ! hmac_key_set )
	{
	}
        	//tmlog(TM_LOG_ERROR, "HMAC error", "HMAC-MD5 invoked before the HMAC key is set");
		//reporter->InternalError("HMAC-MD5 invoked before the HMAC key is set");
*/

    if (hmac_key_set)
    {
	    MD5(bytes, size, digest);

	    for ( int i = 0; i < 16; ++i )
		    digest[i] ^= shared_hmac_md5_key[i];

	    MD5(digest, 16, digest);
    }
}
