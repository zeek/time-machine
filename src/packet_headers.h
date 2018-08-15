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
#include "net_util.h"

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

/* ether_header is from net/ethernet.h */
#define ETHERNET(packet)    ((struct ether_header *)packet)
/* struct ip is from netinet/ip.h */
#define IP(packet)          ((struct ip *)(packet+ETHER_HDR_LEN))
/* maybe use struct ip6_hdr from net_util.h in bro src code to define IP6(packet)? */
/* it looks pretty similar to the netinet/ip.h that was used earlier to parse the IPv4
   packets */
#define IP6(packet) ((struct ip6_hdr *)(packet + ETHER_HDR_LEN))

#define IP_HDR_LEN(packet)	(IP(packet)->ip_hl*4)

#define IP6_HDR_LEN 40

#define TCP(packet)         ((struct tcphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))
#define UDP(packet)         ((struct udphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))

#define TCP6(packet)         ((struct tcphdr *)((char*)IP6(packet)+IP6_HDR_LEN))
#define UDP6(packet)         ((struct udphdr *)((char*)IP6(packet)+IP6_HDR_LEN))

#endif
