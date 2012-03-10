#ifndef __SnifferSocket_h__
#define __SnifferSocket_h__

#include "FragmentStream.h"
#include "Connection.h"

class SnifferSocket
{
	FragmentStream &fs;
	Connection c;
public:
	SnifferSocket(FragmentStream &_fs, Connection &_c): c(_c), fs(_fs)
	{
	}
	SnifferSocket(const SnifferSocket &o): fs(o.fs), c(o.c)
	{
	}
	size_t recv(byte *buf, size_t max)
	{
		return fs.read(buf, max);
	}
	void close()
	{
		fs.close();
	}
	Connection &getConn()
	{
		return c;
	}
};

#endif