#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <pcap/sll.h>
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
// XXX: This is exceptionally ugly hack:
//   Ethernet is by far not the only one link layer protocol and
//   therefore it MUST NOT be assumed! In case e.g. VLAN header
//   is present, packet pointer has to be set 4 bytes (length of
//   VLAN header) into the Ethernet header in order to accomodate
//   for this hack. Even more problems will occur in case we are
//   not on Ethernet at all (what if there is some other link layer
//   header which is actually shorter than Ethernet one? It will require
//   'packet' to point to memory which actually is not ours (delta
//   bytes before it)!!!
//   All of these hacks MUST to be found and corrected.
#define IP(packet)          ((struct ip *)(packet+ETHER_HDR_LEN))


#define IP_HDR_LEN(packet)	(IP(packet)->ip_hl*4)

#define TCP(packet)         ((struct tcphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))
#define UDP(packet)         ((struct udphdr *)((char*)IP(packet)+IP_HDR_LEN(packet)))

/* this is in pcap/sll.h */

#define LINUX_SLL_HDR_LEN   sizeof(struct sll_header)
#define LINUX_SLL(packet)   ((struct sll_header *)packet)

#endif
