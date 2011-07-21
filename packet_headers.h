/*
Timemachine
Copyright (c) 2006 Technische Universitaet Muenchen,
                   Technische Universitaet Berlin,
                   The Regents of the University of California
All rights reserved.


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the names of the copyright owners nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// $Id: packet_headers.h 251 2009-02-04 08:14:24Z gregor $

#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#ifdef linux
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <netinet/tcp.h>

#ifdef linux
struct icmphdr {
	uint8_t type;                /* message type */
	uint8_t code;                /* type sub-code */
	uint16_t checksum;
	union
	{
		struct {
			uint16_t id;
			uint16_t sequence;
		}
		echo;                     /* echo datagram */
		uint32_t   gateway;        /* gateway address */
		struct {
			uint16_t unused;
			uint16_t mtu;
		}
		frag;                     /* path mtu discovery */
	} un;
};
#else
#include <netinet/ip_icmp.h>
#endif

/* locate header positions and structures */

/* this is in net/ethernet.h */
/* #define ETHER_HDR_LEN		sizeof(struct ether_header) */

#define ETHERNET(packet)    ((struct ether_header *)packet)
#define IP(packet)          ((struct ip *)(packet+ETHER_HDR_LEN))


#define IP_HDR_LEN(packet)	(IP(packet)->ip_hl*4)

#define TCP(packet)         ((struct tcphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))
#define UDP(packet)         ((struct udphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))

#endif
