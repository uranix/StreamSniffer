#ifndef __Sniffer_h__
#define __Sniffer_h__

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <map>
#include <string>
#include <list>
#include "Connection.h"
#include "FragmentStream.h"
#include "SnifferSocket.h"
#include "Sync.h"
#include "WaitList.h"

#include <windows.h>
#include <iostream>

#include "pcap.h"

struct SnifferDev
{
	std::string name;
	std::string desc;
	std::list<pcap_addr> addrs;
	SnifferDev(char *_name, char *_desc, pcap_addr *_addrs): name(_name), desc(_desc)
	{
		while (_addrs)
		{
			addrs.push_back(*_addrs);
			_addrs = _addrs->next;
		}
	}
	static std::list<SnifferDev> getDevices()
	{
		char err[1024];
		std::list<SnifferDev> ret;
		pcap_if_t *ifs;
		pcap_findalldevs(&ifs, err);
		while (ifs)
		{
			ret.push_back(SnifferDev(ifs->name, ifs->description, ifs->addresses));
			ifs = ifs->next;
		}
		pcap_freealldevs(ifs);
		return ret;
	}
};

class Sniffer;

struct captureArgs
{
	pcap_t *p;
	Sniffer *_this;
};

#pragma pack(1)
struct EthernetHdr
{
	unsigned char dst_mac[6];
	unsigned char src_mac[6];
	unsigned short type;
};

#pragma pack(1)
struct IpHdr
{
	byte hlen:4;
	byte ver:4;
	byte tos;
	unsigned short len;
	unsigned short id;
	byte froffs1:5;
	byte flags:3;
	byte froffs2;
	byte ttl;
	byte proto;
	unsigned short chksum;
	in_addr src_addr;
	in_addr dst_addr;
};

#pragma pack(1)
struct TCPHdr
{
	unsigned short sport;
	unsigned short dport;
	index seq;
	index ack;
	byte res:4;
	byte doffs:4;
	byte flags;
	unsigned short window;
	unsigned short chksum;
	unsigned short urg;

	static const byte FL_FIN = 0x01;
	static const byte FL_SYN = 0x02;
	static const byte FL_RST = 0x04;
	static const byte FL_PSH = 0x08;
	static const byte FL_ACK = 0x10;
};

#pragma pack(1)
struct Frame
{
	EthernetHdr eth_hdr;
	IpHdr ip_hdr;
};

class Sniffer
{
	std::multimap<Connection, FragmentStream> connTable;
	std::multimap<Connection, FragmentStream> connTableI;
	pcap_t *p;
	HANDLE capThr;
	WaitList<Connection> connI;
	WaitList<Connection> conn;

	static DWORD WINAPI captureThread(LPVOID _args)
	{
		captureArgs *args = (captureArgs *)_args;
		while (!args->_this->stop)
		{
			pcap_pkthdr *hdr;
			const u_char *pkt;
			int ret = pcap_next_ex(args->p, &hdr, &pkt);
			if (ret == 1)
				args->_this->cb(hdr, pkt);
		}
		
		delete args;
		return 0;
	}
	static unsigned short swap(unsigned short h)
	{
		return ((h & 0xff) << 8) | (h >> 8);
	}
	static index swap(index h)
	{
		return ((h & 0xff) << 24) | ((h & 0xff00) << 8) | 
			((h & 0xff0000) >> 8) | (h >> 24);
	}
	void cb(pcap_pkthdr *hdr, const u_char *pkt)
	{
		Frame *f = (Frame *)pkt;
		TCPHdr *t = (TCPHdr *)((byte *)&(f->ip_hdr)+(f->ip_hdr.hlen << 2));
		t->sport = swap(t->sport);
		t->dport = swap(t->dport);
		t->seq = swap(t->seq);
		t->ack = swap(t->ack);
		t->window = swap(t->window);
		t->chksum = swap(t->chksum);
		t->urg = swap(t->urg);
		byte *data = (byte *)t + (t->doffs << 2);
		size_t sz = swap(f->ip_hdr.len) - (data-(byte *)&f->ip_hdr);
		processTcp(&f->ip_hdr, t,data, sz);
	}
	void processTcp(IpHdr *iph, TCPHdr *hdr, byte *data, size_t sz)
	{
		Connection c = Connection(	SockAddr(iph->dst_addr, hdr->dport),
									SockAddr(iph->src_addr, hdr->sport));
		bool incomplete;

		if (hdr->flags & TCPHdr::FL_SYN)
		{
			connTable.insert(std::pair<Connection, FragmentStream>(c,FragmentStream(hdr->seq+1)));
			conn.push(c);
			incomplete = false;
		}
		incomplete = connTable.find(c) == connTable.end();
		if (incomplete)
		{
			if (connTableI.find(c) == connTableI.end())
			{
				connTableI.insert(std::pair<Connection, FragmentStream>(c,FragmentStream(hdr->seq)));
				connI.push(c);
			}
		}

		if (incomplete)
			connTableI.find(c)->second.insert(hdr->seq, data, sz, (hdr->flags & TCPHdr::FL_PSH) != 0);
		else
			connTable.find(c)->second.insert(hdr->seq, data, sz, (hdr->flags & TCPHdr::FL_PSH) != 0);

		if (hdr->flags & (TCPHdr::FL_FIN | TCPHdr::FL_RST))
		{
			if (connTable.find(c) != connTable.end())
				connTable.find(c)->second.close();
			if (connTableI.find(c) != connTableI.end())
				connTableI.find(c)->second.close();
		}
	}
public:
	bool stop;
	Sniffer(SnifferDev dev, SockAddr srv, SockAddr cli)
	{
		stop = false;
		char r1[64]="";
		char r2[64]="";
		char r3[64]="";
		char r4[64]="";
		char rule[1024];
		char err[1024];
		if (srv.addr != 0)
		{
			unsigned char *ip = (unsigned char *)&srv.addr;
			sprintf(r1, " and dst host %u.%u.%u.%u", ip[3], ip[2], ip[1], ip[0]);
		}
		if (cli.addr != 0)
		{
			unsigned char *ip = (unsigned char *)&cli.addr;
			sprintf(r2, " and src host %u.%u.%u.%u", ip[3], ip[2], ip[1], ip[0]);
		}
		if (srv.port != 0)
			sprintf(r3, " and dst port %u", srv.port);
		if (cli.port != 0)
			sprintf(r4, " and src port %u", cli.port);
		sprintf(rule, "ip and tcp%s%s%s%s", r1, r2, r3, r4);
		p = pcap_open_live(dev.name.c_str(), 65536, 0, 100, err);
		if (!p)
			throw err;
		bpf_program bpf;
		int ret = pcap_compile(p, &bpf, rule, 0, 0);
		pcap_setfilter(p, &bpf);
		captureArgs *args = new captureArgs;
		args->p = p;
		args->_this = this;
		capThr = CreateThread(0, 0, captureThread, args, 0, 0);
	}
	SnifferSocket accept(bool incomplete)
	{
		if (incomplete)
		{
			Connection &c = connI.pop();
			FragmentStream &fs = connTableI.find(c)->second;
			return SnifferSocket(fs, c);
		}
		else
		{
			Connection &c = conn.pop();
			FragmentStream &fs = connTable.find(c)->second;
			return SnifferSocket(fs, c);
		}
	}
	~Sniffer()
	{
		stop = true;
		WaitForSingleObject(capThr, INFINITE);
	}
	friend std::ostream& operator<<(std::ostream &o, const Sniffer &s)
	{
		std::multimap<Connection, FragmentStream>::const_iterator i = s.connTable.begin();
		o << "Entire connections:" << std::endl;
		for (;i != s.connTable.end();i++)
			o << i->first << " : Max queued packets " << i->second.getLag() 
			<< " Total bytes : " << i->second.getTotalBytesTransmitted()
			<< " Closed : " << i->second.isClosed() << " Error : " << i->second.wasError()
			<< std::endl;
		o << "Incomplete connections:" << std::endl;
		i = s.connTableI.begin();
		for (;i != s.connTableI.end();i++)
			o << i->first << " - Max queued packets : " << i->second.getLag() 
			<< " Total bytes : " << i->second.getTotalBytesTransmitted()
			<< " Closed : " << i->second.isClosed() << " Error : " << i->second.wasError()
			<< std::endl;
		return o;
	}
};

#endif