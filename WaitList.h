#ifndef __WaitList_h__
#define __WaitList_h__

#include "Sync.h"
#include <list>

template <class T>
class WaitList
{
	Sem s;
	std::list<T> backlist;
public:
	void push(const T &o)
	{
		backlist.push_back(o);
		s.inc();
	}
	T pop()
	{
		s.dec();
		T fr = backlist.front();
		backlist.pop_front();
		return T(fr);
	}
};

#endif