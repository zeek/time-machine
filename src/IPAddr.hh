// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IPADDR_H
#define IPADDR_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include "types.h"
#include "jhash3.h"

typedef in_addr in4_addr;
/**
 * Class storing both IPv4 and IPv6 addresses.
 */
class IPAddr
{
public:
	/**
	 * Address family.
	 */
	typedef IPFamily Family;

	/**
	 * Byte order.
	 */
	enum ByteOrder { Host, Network };

	/**
	 * Constructs the unspecified IPv6 address (all 128 bits zeroed).
	 */
	IPAddr()
		{
		memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
		}

	/**
	 * Constructs an address instance from an IPv4 address.
	 *
	 * @param in6 The IPv6 address.
	 */
	explicit IPAddr(const in4_addr& in4)
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		memcpy(&in6.s6_addr[12], &in4.s_addr, sizeof(in4.s_addr));
		}

	/**
	 * Constructs an address instance from an IPv6 address.
	 *
	 * @param in6 The IPv6 address.
	 */
	explicit IPAddr(const in6_addr& arg_in6) : in6(arg_in6) { }

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IPv6 address.
	 */
	IPAddr(const std::string& s)
		{
		Init(s);
		}

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s ASCIIZ string containing an IP address as either a
	 * dotted IPv4 address or a hex IPv6 address.
	 */
	IPAddr(const char* s)
		{
		Init(s);
		}

	/**
	 * Constructs an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IPv6 address.
	 */
	IPAddr(const std::string s)
		{
		Init(s.c_str());
		}

	/**
	 * Constructs an address instance from a raw byte representation.
	 *
	 * @param family The address family.
	 *
	 * @param bytes A pointer to the raw byte representation. This must point
	 * to 4 bytes if \a family is IPv4, and to 16 bytes if \a family is
	 * IPv6.
	 *
	 * @param order Indicates whether the raw representation pointed to
	 * by \a bytes is stored in network or host order.
	 */
	IPAddr(Family family, const uint32_t* bytes, ByteOrder order);

	/**
	 * Copy constructor.
	 */
	IPAddr(const IPAddr& other) : in6(other.in6) { };

	/**
	 * Destructor.
	 */
	~IPAddr() { };

	/**
	 * Returns the address' family.
	 */
	Family GetFamily() const
		{
		if ( memcmp(in6.s6_addr, v4_mapped_prefix, 12) == 0 )
			return IPv4;
		else
			return IPv6;
		}

	/**
	 * Returns true if the address represents a loopback device.
	 */
	bool IsLoopback() const;

	/**
	 * Returns true if the address represents a multicast address.
	 */
	bool IsMulticast() const
		{
		if ( GetFamily() == IPv4 )
			return in6.s6_addr[12] == 224;
		else
			return in6.s6_addr[0] == 0xff;
		}

	/**
	 * Returns true if the address represents a broadcast address.
	 */
	bool IsBroadcast() const
		{
		if ( GetFamily() == IPv4 )
			return ((in6.s6_addr[12] == 0xff) && (in6.s6_addr[13] == 0xff)
				&& (in6.s6_addr[14] == 0xff) && (in6.s6_addr[15] == 0xff));
		else
			return false;
		}

	/**
	 * Retrieves the raw byte representation of the address.
	 *
	 * @param bytes The pointer to which \a bytes points will be set to
	 * the address of the raw representation in network-byte order.
	 * The return value indicates how many 32-bit words are valid starting at
	 * that address. The pointer will be valid as long as the address instance
	 * exists.
	 *
	 * @return The number of 32-bit words the raw representation uses. This
	 * will be 1 for an IPv4 address and 4 for an IPv6 address.
	 */
	int GetBytes(const uint32_t** bytes) const
		{
		if ( GetFamily() == IPv4 )
			{
			*bytes = (uint32_t*) &in6.s6_addr[12];
			return 1;
			}
		else
			{
			*bytes = (uint32_t*) in6.s6_addr;
			return 4;
			}
		}

	/**
	 * Retrieves a copy of the IPv6 raw byte representation of the address.
	 * If the internal address is IPv4, then the copied bytes use the
	 * IPv4 to IPv6 address mapping to return a full 16 bytes.
	 *
	 * @param bytes The pointer to a memory location in which the
	 * raw bytes of the address are to be copied.
	 *
	 * @param order The byte-order in which the returned raw bytes are copied.
	 * The default is network order.
	 */
	void CopyIPv6(uint32_t* bytes, ByteOrder order = Network) const
		{
		memcpy(bytes, in6.s6_addr, sizeof(in6.s6_addr));

		if ( order == Host )
			{
			for ( unsigned int i = 0; i < 4; ++i )
				bytes[i] = ntohl(bytes[i]);
			}
		}

	/**
	 * Retrieves a copy of the IPv6 raw byte representation of the address.
	 * @see CopyIPv6(uint32_t)
	 */
	void CopyIPv6(in6_addr* arg_in6) const
		{
		memcpy(arg_in6->s6_addr, in6.s6_addr, sizeof(in6.s6_addr));
		}

	/**
	 * Retrieves a copy of the IPv4 raw byte representation of the address.
	 * The caller should verify the address is of the IPv4 family type
	 * beforehand.  @see GetFamily().
	 *
	 * @param in4 The pointer to a memory location in which the raw bytes
	 * of the address are to be copied in network byte-order.
	 */
	void CopyIPv4(in4_addr* in4) const
		{
		memcpy(&in4->s_addr, &in6.s6_addr[12], sizeof(in4->s_addr));
		}

	uint32_t Hash() const
		{
		const uint32_t *bytes;
		int len = GetBytes(&bytes);
		if ( len == 1 )
			return hash1words(bytes[0], 0);
		else
			// TODO: this is only hashing the latter 96bits of the address.
			return hash3words(bytes[1], bytes[2], bytes[3], 0);
		}

	/**
	 * Masks out lower bits of the address.
	 *
	 * @param top_bits_to_keep The number of bits \a not to mask out,
	 * counting from the highest order bit. The value is always
	 * interpreted relative to the IPv6 bit width, even if the address
	 * is IPv4. That means if compute ``192.168.1.2/16``, you need to
	 * pass in 112 (i.e., 96 + 16). The value must be in the range from
	 * 0 to 128.
	 */
	void Mask(int top_bits_to_keep);

	/**
	 * Masks out top bits of the address.
	 *
	 * @param top_bits_to_chop The number of bits to mask out, counting
	 * from the highest order bit.  The value is always interpreted relative
	 * to the IPv6 bit width, even if the address is IPv4.  So to mask out
	 * the first 16 bits of an IPv4 address, pass in 112 (i.e., 96 + 16).
	 * The value must be in the range from 0 to 128.
	 */
	void ReverseMask(int top_bits_to_chop);

	/**
	 * Assignment operator.
	 */
	IPAddr& operator=(const IPAddr& other)
		{
		// No self-assignment check here because it's correct without it and
		// makes the common case faster.
		in6 = other.in6;
		return *this;
		}

	/**
	 * Bitwise OR operator returns the IP address resulting from the bitwise
	 * OR operation on the raw bytes of this address with another.
	 */
	IPAddr operator|(const IPAddr& other)
		{
		in6_addr result;
		for ( int i = 0; i < 16; ++i )
			result.s6_addr[i] = this->in6.s6_addr[i] | other.in6.s6_addr[i];

		return IPAddr(result);
		}

	/**
	 * Returns a string representation of the address. IPv4 addresses
	 * will be returned in dotted representation, IPv6 addresses in
	 * compressed hex.
	 */
	std::string AsString() const;

	/**
	 * Returns a string representation of the address suitable for inclusion
	 * in an URI.  For IPv4 addresses, this is the same as AsString(), but
	 * IPv6 addresses are encased in square brackets.
	 */
	std::string AsURIString() const
		{
		if ( GetFamily() == IPv4 )
			return AsString();
		else
			return std::string("[") + AsString() + "]";
		}

	/**
	 * Returns a host-order, plain hex string representation of the address.
	 */
	std::string AsHexString() const;

	/**
	 * Returns a string representation of the address. This returns the
	 * same as AsString().
	 */
	operator std::string() const { return AsString(); }

	/**
	 * Returns a reverse pointer name associated with the IP address.
	 * For example, 192.168.0.1's reverse pointer is 1.0.168.192.in-addr.arpa.
	 */
	std::string PtrName() const;

	/**
	 * Comparison operator for IP address.
	 */
	friend bool operator==(const IPAddr& addr1, const IPAddr& addr2)
		{
		return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) == 0;
		}

	friend bool operator!=(const IPAddr& addr1, const IPAddr& addr2)
		{
		return ! (addr1 == addr2);
		}

	/**
	 * Comparison operator IP addresses. This defines a well-defined order for
	 * IP addresses. However, the order does not necessarily correspond to
	 * their numerical values.
	 */
	friend bool operator<(const IPAddr& addr1, const IPAddr& addr2)
		{
		return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) < 0;
		}

	friend bool operator<=(const IPAddr& addr1, const IPAddr& addr2)
		{
		return addr1 < addr2 || addr1 == addr2;
		}

	friend bool operator>=(const IPAddr& addr1, const IPAddr& addr2)
		{
		return ! ( addr1 < addr2 );
		}

	friend bool operator>(const IPAddr& addr1, const IPAddr& addr2)
		{
		return ! ( addr1 <= addr2 );
		}

private:
	friend class IPPrefix;

	/**
	 * Initializes an address instance from a string representation.
	 *
	 * @param s String containing an IP address as either a dotted IPv4
	 * address or a hex IPv6 address.
	 */
	void Init(const std::string& s);

	in6_addr in6; // IPv6 or v4-to-v6-mapped address

	static const uint8_t v4_mapped_prefix[12]; // top 96 bits of v4-mapped-addr
};

inline IPAddr::IPAddr(Family family, const uint32_t* bytes, ByteOrder order)
	{
	if ( family == IPv4 )
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		memcpy(&in6.s6_addr[12], bytes, sizeof(uint32_t));

		if ( order == Host )
			{
			uint32_t* p = (uint32_t*) &in6.s6_addr[12];
			*p = htonl(*p);
			}
		}

	else
		{
		memcpy(in6.s6_addr, bytes, sizeof(in6.s6_addr));

		if ( order == Host )
			{
			for ( unsigned int i = 0; i < 4; ++ i)
				{
				uint32_t* p = (uint32_t*) &in6.s6_addr[i*4];
				*p = htonl(*p);
				}
			}
		}
	}

inline bool IPAddr::IsLoopback() const
	{
	if ( GetFamily() == IPv4 )
		return in6.s6_addr[12] == 127;

	else
		return ((in6.s6_addr[0] == 0) && (in6.s6_addr[1] == 0)
			&& (in6.s6_addr[2] == 0) && (in6.s6_addr[3] == 0)
			&& (in6.s6_addr[4] == 0) && (in6.s6_addr[5] == 0)
			&& (in6.s6_addr[6] == 0) && (in6.s6_addr[7] == 0)
			&& (in6.s6_addr[8] == 0) && (in6.s6_addr[9] == 0)
			&& (in6.s6_addr[10] == 0) && (in6.s6_addr[11] == 0)
			&& (in6.s6_addr[12] == 0) && (in6.s6_addr[13] == 0)
			&& (in6.s6_addr[14] == 0) && (in6.s6_addr[15] == 1));
	}

#endif
