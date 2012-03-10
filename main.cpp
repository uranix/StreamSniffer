#include "Sniffer.h"
#include <io.h>

#include "windows.h"
#include <iostream>
#include <sstream>
#include <string>

DWORD WINAPI threadEp(LPVOID args)
{
	SnifferSocket *sa = (SnifferSocket *)args;
	int cnt;
	byte buf[1024];
	std::stringstream sfn;
	sfn << sa->getConn() << ".dmp";
	char fn[1024], *tmp;
	strcpy(fn, sfn.str().c_str());
	for (tmp=fn;*tmp;tmp++)
		if ((*tmp == ':') || (*tmp == '>'))
			*tmp = '_';

	int fd = _open(fn, _O_WRONLY | _O_CREAT | _O_TRUNC| _O_BINARY, 0666);
	while (cnt = sa->recv(buf, sizeof(buf)))
	{
		if (cnt == (size_t)-1)
			break;
		_write(fd, buf, cnt);
	}
	_close(fd);
	delete sa;
	return 0;
}

#define N 50

int main()
{
	std::list<SnifferDev> devs = SnifferDev::getDevices();
	SockAddr dst(0,0), src(0,20);

	Sniffer s(*devs.begin(), dst, src);
	HANDLE h[N];
	for (int naccept=0; naccept < N; naccept++) 
	{
		SnifferSocket *sarg = new SnifferSocket(s.accept(false));
		h[naccept] = CreateThread(0, 0, threadEp, sarg, 0, 0);
	};
	WaitForMultipleObjects(N, h, TRUE, INFINITE);
	std::cout << s;
}