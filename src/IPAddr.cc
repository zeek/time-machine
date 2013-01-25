#include <string>
#include <vector>
#include "IPAddr.hh"

const uint8_t IPAddr::v4_mapped_prefix[12] = { 0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0xff, 0xff };


void IPAddr::Mask(int top_bits_to_keep)
	{
	if ( top_bits_to_keep < 0 || top_bits_to_keep > 128 )
		{
		//reporter->Error("Bad IPAddr::Mask value %d", top_bits_to_keep);
		return;
		}

	uint32_t tmp[4];
	memcpy(tmp, in6.s6_addr, sizeof(in6.s6_addr));

	int word = 3;
	int bits_to_chop = 128 - top_bits_to_keep;

	while ( bits_to_chop >= 32 )
		{
		tmp[word] = 0;
		--word;
		bits_to_chop -= 32;
		}

	uint32_t w = ntohl(tmp[word]);
	w >>= bits_to_chop;
	w <<= bits_to_chop;
	tmp[word] = htonl(w);

	memcpy(in6.s6_addr, tmp, sizeof(in6.s6_addr));
	}

void IPAddr::ReverseMask(int top_bits_to_chop)
	{
	if ( top_bits_to_chop < 0 || top_bits_to_chop > 128 )
		{
		//reporter->Error("Bad IPAddr::ReverseMask value %d", top_bits_to_chop);
		return;
		}

	uint32_t tmp[4];
	memcpy(tmp, in6.s6_addr, sizeof(in6.s6_addr));

	int word = 0;
	int bits_to_chop = top_bits_to_chop;

	while ( bits_to_chop >= 32 )
		{
		tmp[word] = 0;
		++word;
		bits_to_chop -= 32;
		}

	uint32_t w = ntohl(tmp[word]);
	w <<= bits_to_chop;
	w >>= bits_to_chop;
	tmp[word] = htonl(w);

	memcpy(in6.s6_addr, tmp, sizeof(in6.s6_addr));
	}

void IPAddr::Init(const std::string& s)
	{
	if ( s.find(':') == std::string::npos ) // IPv4.
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));

		// Parse the address directly instead of using inet_pton since
		// some platforms have more sensitive implementations than others
		// that can't e.g. handle leading zeroes.
		int a[4];
		int n = sscanf(s.c_str(), "%d.%d.%d.%d", a+0, a+1, a+2, a+3);

		if ( n != 4 || a[0] < 0 || a[1] < 0 || a[2] < 0 || a[3] < 0 ||
		     a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 )
			{
			//reporter->Error("Bad IP address: %s", s.c_str());
			memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
			return;
			}

		uint32_t addr = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
		addr = htonl(addr);
		memcpy(&in6.s6_addr[12], &addr, sizeof(uint32_t));
		}

	else
		{
		if ( inet_pton(AF_INET6, s.c_str(), in6.s6_addr) <=0 )
			{
			//reporter->Error("Bad IP address: %s", s.c_str());
			memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
			}
		}
	}

std::string IPAddr::AsString() const
	{
	if ( GetFamily() == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET, &in6.s6_addr[12], s, INET_ADDRSTRLEN) )
			return "<bad IPv4 address conversion";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( ! inet_ntop(AF_INET6, in6.s6_addr, s, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
			return s;
		}
	}

std::string IPAddr::AsHexString() const
	{
	char buf[33];

	if ( GetFamily() == IPv4 )
		{
		uint32_t* p = (uint32_t*) &in6.s6_addr[12];
		snprintf(buf, sizeof(buf), "%08x", (uint32_t) ntohl(*p));
		}
	else
		{
		uint32_t* p = (uint32_t*) in6.s6_addr;
		snprintf(buf, sizeof(buf), "%08x%08x%08x%08x",
				(uint32_t) ntohl(p[0]), (uint32_t) ntohl(p[1]),
				(uint32_t) ntohl(p[2]), (uint32_t) ntohl(p[3]));
		}

	return buf;
	}

std::string IPAddr::PtrName() const
	{
	if ( GetFamily() == IPv4 )
		{
		char buf[256];
		uint32_t* p = (uint32_t*) &in6.s6_addr[12];
		uint32_t a = ntohl(*p);
		uint32_t a3 = (a >> 24) & 0xff;
		uint32_t a2 = (a >> 16) & 0xff;
		uint32_t a1 = (a >> 8) & 0xff;
		uint32_t a0 = a & 0xff;
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa", a0, a1, a2, a3);
		return buf;
		}
	else
		{
		static const char hex_digit[] = "0123456789abcdef";
		std::string ptr_name("ip6.arpa");
		uint32_t* p = (uint32_t*) in6.s6_addr;

		for ( unsigned int i = 0; i < 4; ++i )
			{
			uint32_t a = ntohl(p[i]);
			for ( unsigned int j = 1; j <=8; ++j )
				{
				ptr_name.insert(0, 1, '.');
				ptr_name.insert(0, 1, hex_digit[(a >> (32-j*4)) & 0x0f]);
				}
			}

		return ptr_name;
		}
	}

