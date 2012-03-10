#ifndef __Sync_h__
#define __Sync_h__

#include <windows.h>
#include <iostream>

class Lock
{
	CRITICAL_SECTION cs;
	Lock(const Lock &o);
public:
	Lock()
	{
		InitializeCriticalSection(&cs);
	}
	~Lock()
	{
		DeleteCriticalSection(&cs);
	}
	void up()
	{
		LeaveCriticalSection(&cs);
	}
	void down()
	{
		EnterCriticalSection(&cs);
	}
};

class Event
{
	HANDLE ev;
	Event(const Event &o);
public:
	Event()
	{
		ev = CreateEvent(0, FALSE, FALSE, 0);
	}
	~Event()
	{
		CloseHandle(ev);
	}
	void fire()
	{
		SetEvent(ev);
	}
	void wait()
	{
		WaitForSingleObject(ev, INFINITE);
	}
};

class Sem
{
	HANDLE hSem;
public:
	Sem()
	{
		hSem = CreateSemaphore(0, 0, 1024, 0);
	}
	~Sem()
	{
		CloseHandle(hSem);
	}
	void inc()
	{
		ReleaseSemaphore(hSem, 1, NULL);
	}
	void dec()
	{
		WaitForSingleObject(hSem, INFINITE);
	}
};

#endif