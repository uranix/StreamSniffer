#ifndef __Connection_h__
#define __Connection_h__

#include <winsock2.h>
#include <ostream>

struct SockAddr
{
	unsigned long addr;
	unsigned short port;
	friend std::ostream& operator<<(std::ostream &o, const SockAddr &s)
	{
		byte *ip = (byte *)&s.addr;
		return o << (int)ip[0] << "." << (int)ip[1] << "." << 
			(int)ip[2] << "." << (int)ip[3] << ":" << s.port;
	}
	SockAddr(unsigned long _addr, unsigned short _port): addr(_addr), port(_port)
	{
	}
	SockAddr(in_addr _addr, unsigned short _port): port(_port)
	{
		addr = *(unsigned long *)&_addr;
	}
	SockAddr(const SockAddr &o): addr(o.addr), port(o.port)
	{
	}
	bool operator <(const SockAddr &o) const
	{
		if (addr < o.addr)
			return true;
		if (o.addr < addr)
			return false;
		return port < o.port;
	}
};

struct Connection
{
	SockAddr dst, src;
	Connection(const SockAddr &_dst, const SockAddr &_src): dst(_dst), src(_src)
	{
	}
	bool operator <(const Connection &o) const 
	{
		if (dst < o.dst)
			return true;
		if (o.dst < dst)
			return false;
		return src < o.src;
	}
	friend std::ostream& operator<<(std::ostream &o, const Connection &s)
	{
		return o << s.src << "->" << s.dst;
	}
};

#endif