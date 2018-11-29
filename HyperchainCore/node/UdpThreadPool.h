/*Copyright 2016-2018 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#pragma once

#ifndef __UDP_THREADPOOL_H__
#define __UDP_THREADPOOL_H__





#include "../headers/platform.h"
#include "../headers/commonstruct.h"
#include "../utility/MutexObj.h"

#include "../crypto/crc32.h"
#ifdef WIN32
#include <winsock2.h>
#endif


#define CURRENT_VERSION '1'

#define UDP_INIT_PAKTYPE '1'
#define UDP_ACK_PAKTYPE  '2'

#define PACKET_HEADER '1'
#define SLICE_HEADER  '2'

#define UDP_SLICE_MAX_SIZE 16384			

#define MAX_BUFFER_SIZE 65536				
#define MAX_SEND_TIMES  5					
#define MAX_INTERVAL_TIME  1000				
#define MAX_RECV_LIST_COUNT  2000			

enum _erecvflag
{
	DEFAULT = 0,
	ACK_FLAG
};

typedef struct _tudpheader
{
	uint8_t HeaderType;
	uint32_t uPacketNum;
	uint32_t uDataBufCrc;
	uint32_t uBufLen;
	uint8_t PacketType;
	uint8_t Version;
	uint16_t uSliceTotalNum;
}T_UDPHEADER, *T_PUDPHEADER;

typedef struct _tudpnode
{
	string Ip;
	uint32_t Port;
	uint16_t ClearFlag;
	uint16_t RetryTimes;
	uint64_t NextSendTime;
	char bitmap[128];
	T_UDPHEADER UdpHeader;
	char *DataBuf;
}T_UDPNODE, *T_PUDPNODE;




typedef struct _tudpsliceheader
{
	uint8_t HeaderType;			
	uint8_t SliceType;			
	uint32_t uPacketNum;		
	uint16_t uSliceTotalNum;	
	uint16_t uSliceCurrIndex;   
	uint32_t uSliceBufCrc;
	uint32_t uSliceBufLen;		
	uint32_t uSliceDataOffset;  
}T_UDPSLICEHEADER, *T_PUDPSLICEHEADER;

typedef struct _tudpslicenode
{
	T_UDPSLICEHEADER SliceHeader;
	char *SliceBuf;
}T_UDPSLICENODE, *T_PUDPSLICENODE;

typedef struct _tpacketkey
{
	string Ip;
	uint32_t Port;
	uint32_t uPacketNum;

	_tpacketkey(string ip, uint32_t port, uint32_t packetnum)
	{
		Ip = ip;
		Port = port;
		uPacketNum = packetnum;
	}

	bool operator<(_tpacketkey const& other) const
	{

		if (Ip < other.Ip) { return true; }
		if (Ip > other.Ip) { return false; }
		if (Port < other.Port) { return true; }
		if (Port > other.Port) { return false; }
		return uPacketNum < other.uPacketNum;
	}
}T_PACKETKEY;

typedef list<T_UDPNODE>	LIST_T_UDPNODE;
typedef LIST_T_UDPNODE::iterator    ITR_LIST_T_UDPNODE;

typedef list<T_PUDPNODE>	LIST_T_PUDPNODE;
typedef LIST_T_PUDPNODE::iterator    ITR_LIST_T_PUDPNODE;

typedef list<T_UDPSLICENODE>	LIST_T_UDPSLICENODE;

typedef map<uint32_t, T_PUDPNODE>		MAP_T_PUDPNODE;
typedef MAP_T_PUDPNODE::iterator    ITR_MAP_T_PUDPNODE;

typedef map<T_PACKETKEY, T_UDPNODE> MAP_PACKETDATA;
typedef MAP_PACKETDATA::iterator	ITR_MAP_PACKETDATA;

typedef map<uint32_t, T_UDPSLICENODE> MAP_SLICEDATA;
typedef MAP_SLICEDATA::iterator    ITR_MAP_SLICEDATA;

typedef map<T_PACKETKEY, MAP_SLICEDATA> MULTI_MAP_PACKETDATA;
typedef MULTI_MAP_PACKETDATA::iterator    ITR_MULTI_MAP_PACKETDATA;

class UdpThreadPool 
{
public:

	UdpThreadPool();
	virtual ~UdpThreadPool();

	enum _esendresult
	{
		LOCAL_IP = -2,
		SEND_FAILED = -1,
		SEND_SUCCESS
	};

	enum _erecvresult
	{
		RECV_LIST_EMPTY = -1,
		RECV_SUCCESS = 1,
		RECV_BUF_NOT_ENOUGH
	};

public:
	int Init(const char* localIp, uint32_t localPort);
	int send(const string &peerIP, uint32_t peerPort, const char * buf, size_t len);
	

private:
	void Recv();
	void RecvData();
	void SendAgain();
	void slice_ack_resp_add(char *bitmap, uint16_t id);	
	int slice_ack_resp_check(char *bitmap, uint16_t id);
	static void THREAD_API PushDataEntry(void* pParam);
	static void THREAD_API RecvDataEntry(void* pParam);
	static void THREAD_API SendAgainEntry(void* pParam);

private:
	bool					m_bUsed;
	uint32_t				m_packetNum;
	uint32_t				m_localPort;
	const char				*m_localIp;
#ifdef WIN32
	SOCKET					m_listenFd;
#else
	int						m_listenFd;
#endif
	LIST_T_UDPNODE			m_recvList;
	LIST_T_PUDPNODE			m_sendList;
	MAP_T_PUDPNODE			m_sendMap;
	MAP_PACKETDATA			m_packetMap;
	MULTI_MAP_PACKETDATA	m_recvMap;
	CMutexObj				m_recvListLock;
	CMutexObj				m_sendListLock;
	CMutexObj				m_sendMapLock;
	CMutexObj				m_packetMapLock;
	CMutexObj				m_recvMapLock;
	semaphore_t				m_semSendList;
	semaphore_t				m_semRecvList;
};

#endif 