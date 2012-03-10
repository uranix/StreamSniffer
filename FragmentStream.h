#ifndef __FragmentStream_h__
#define __FragmentStream_h__

#include <string.h>
#include <iostream>
#include <set>

#include "Sync.h"

#ifdef _WIN32

typedef unsigned __int8 byte;
typedef unsigned __int32 index;

#else

#include <stdint.h>
typedef uint8_t byte;
typedef uint32_t index;

#endif

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

struct Fragment 
{
	byte *buf;
	index start;
	size_t sz;
	static bool less(index i, index j)
	{
		// less(i, j) = less(i+c, j+c)
		// less(i, j) = less(0, j-i);
		// !less(a,b) && !less(b,a) is not the same (a == b)
		// Ex. b = 0x80000000 + a. less(a,b) = less(b,a) = false. a!=b = true
		index r = j-i;
		return (r < 0x80000000UL) && (r > 0);
	}
	Fragment(byte *_buf, index _start, size_t _sz)
	{
		start = _start;
		sz = _sz;
		buf = new byte[_sz];
		memcpy(buf, _buf, _sz);
	}
	Fragment(const Fragment &o)
	{
		start = o.start;
		sz = o.sz;
		buf = new byte[sz];
		memcpy(buf, o.buf, sz);
	}
	~Fragment()
	{
		delete[] buf;
	}
	bool operator< (const Fragment &o) const
	{
		if (less(start, o.start))
			return true;
		if (less(o.start, start))
			return false;
		return sz < o.sz;
	}
	bool has(index ptr) const
	{
		return (!less(ptr, start)) && less(ptr, start+sz);
	}
};

class FragmentStream
{
	std::multiset<Fragment> fragments;
	bool closed;
	bool error;
	index rdptr;
	Lock fraglock;
	Event readevent;
	int lag_size;
	unsigned long long tbt;
public:
	FragmentStream(const FragmentStream &o): fragments(o.fragments)
	{
		lag_size = o.lag_size;
		closed = o.closed;
		error = o.error;
		rdptr = o.rdptr;
		tbt = o.tbt;
	}
	FragmentStream(index _rdptr = 0):rdptr(_rdptr), 
		closed(false), lag_size(0), error(false), tbt(0)
	{		
	}
	void close()
	{
		closed = true;
		readevent.fire();
	}
	int insert(index offs, byte *data, size_t sz, bool push)
	{
		if (closed)
			return -1;
		fraglock.down();
		if (Fragment::less(rdptr, offs+sz))
			fragments.insert(Fragment(data, offs, sz));
		lag_size = std::max(lag_size, (int)fragments.size());
		fraglock.up();
		if (push)
			readevent.fire();
		return 0;
	}
	size_t read(byte *buf, size_t max)
	{
		index rdold = rdptr;
		while (rdptr == rdold)
		{
			readevent.wait();
			if (error)
				return (size_t)-1;
			fraglock.down();
			std::multiset<Fragment>::iterator i = fragments.begin();
			if ((i == fragments.end()) && closed)
			{
				fraglock.up();
				break;
			}
			for (i = fragments.begin();(i != fragments.end()) && (i->has(rdptr));i = fragments.begin())
			{
				size_t u = rdptr - i->start;
				size_t cp = std::min(i->sz - u, max);
				memcpy(buf+(rdptr-rdold), i->buf+u, cp);
				rdptr += cp;
				max -= cp;
				while (!(Fragment::less(rdptr, i->start+i->sz)))
				{
					fragments.erase(i);
					i = fragments.begin();
					if (i == fragments.end())
						break;
				}
				if (0 == max)
					break;
			}
			fraglock.up();
		}
		readevent.fire();
		tbt += (rdptr - rdold);
		return rdptr - rdold;
	}
	int getLag() const
	{
		return lag_size;
	}
	bool isClosed() const
	{
		return closed;
	}
	bool wasError() const
	{
		return error;
	}
	unsigned long long getTotalBytesTransmitted() const
	{
		return tbt;
	}
};

#endif