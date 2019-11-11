/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this?
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,?
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include "../crypto/crc32.h"

#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <memory>
#include <cstring>
#include <thread>
#include <ctime>
#include <map>
#ifdef WIN32
#include <winsock2.h>
#include<ws2tcpip.h>
#pragma comment(lib,"WS2_32.LIB")
#else
#include <sys/socket.h>
#include <sys/types.h>
#endif

using std::chrono::system_clock;
#include "SyncQueue.h"

#define CURRENT_VERSION '1'

#define UDP_INIT_PAKTYPE '1'
#define UDP_ACK_PAKTYPE  '2'

#define PACKET_HEADER '1'
#define SLICE_HEADER  '2'

#define UDP_SLICE_MAX_SIZE	1024
#define MAX_BUFFER_SIZE		1088			//
#define MAX_SEND_TIMES		3				//
#define MAX_INTERVAL_TIME	10				//
#define MAX_RECV_LIST_COUNT	5000			//

enum _erecvflag
{
    DEFAULT = 0,
    ACK_FLAG
};

typedef struct _tudpheader
{
    uint8_t HeaderType;			//
    uint32_t uPacketNum;
    uint32_t uDataBufCrc;
    uint32_t uBufLen;
    uint8_t PacketType;			//
    uint8_t Version;			//
    uint16_t uSliceTotalNum;
}T_UDPHEADER, *T_PUDPHEADER;

typedef struct _tudpnode
{
    string Ip;
    uint32_t Port;
    uint16_t ClearFlag;
    uint16_t RetryTimes;
    std::time_t NextSendTime;
    vector<uint8_t> bitmap;
    T_UDPHEADER UdpHeader;
    char *DataBuf;
}T_UDPNODE, *T_PUDPNODE;

//Slice Header
typedef struct _tudpsliceheader
{
    uint8_t HeaderType;			 //
    uint8_t SliceType;			 //
    uint32_t uPacketNum;		 //
    uint16_t uSliceTotalNum;	 //
    uint16_t uSliceCurrIndex;	 //
    uint32_t uSliceBufCrc;
    uint32_t uSliceBufLen;		 //
    uint32_t uSliceDataOffset;   //
}T_UDPSLICEHEADER, *T_PUDPSLICEHEADER;

typedef struct _tudpslicenode
{
    T_UDPSLICEHEADER SliceHeader;
    char SliceBuf[UDP_SLICE_MAX_SIZE];
}T_UDPSLICENODE, *T_PUDPSLICENODE;

typedef struct _trecvnode
{
    struct sockaddr_in fromAddr;
    char recvbuf[MAX_BUFFER_SIZE];
    int recvNum;
}T_RECVNODE, *T_PRECVNODE;

typedef struct _tpacketkey
{
    string Ip;
    uint32_t Port;
    uint32_t uPacketNum;

    _tpacketkey(string ip, uint32_t port, uint32_t packetnum) : Ip(ip), Port(port), uPacketNum(packetnum) {}

    bool operator<(_tpacketkey const& other) const
    {
        if (Ip < other.Ip) { return true; }
        if (Ip > other.Ip) { return false; }
        if (Port < other.Port) { return true; }
        if (Port > other.Port) { return false; }
        return uPacketNum < other.uPacketNum;
    }
}T_PACKETKEY;

typedef struct _tpacketnode
{
    T_UDPHEADER _udpheader;
    system_clock::time_point _tp;
public:
    _tpacketnode() : _tp(system_clock::now()) {}
    bool isTimeOut() {
        using minutes = std::chrono::duration<double, std::ratio<60>>;
        system_clock::time_point curr = system_clock::now();

        minutes timespan = std::chrono::duration_cast<minutes>(curr - _tp);
        if (timespan.count() > 20) {
            //
            return true;
        }
        return false;
    }
}T_PACKETNODE;

typedef list<T_UDPSLICENODE>	LIST_T_UDPSLICENODE;

typedef map<uint32_t, T_PUDPNODE>		MAP_T_PUDPNODE;
typedef MAP_T_PUDPNODE::iterator    ITR_MAP_T_PUDPNODE;

typedef map<T_PACKETKEY, T_PACKETNODE> MAP_PACKETDATA;
typedef MAP_PACKETDATA::iterator	ITR_MAP_PACKETDATA;

typedef map<uint32_t, T_UDPSLICENODE> MAP_SLICEDATA;
typedef MAP_SLICEDATA::iterator    ITR_MAP_SLICEDATA;

typedef map<T_PACKETKEY, MAP_SLICEDATA> MULTI_MAP_PACKETDATA;
typedef MULTI_MAP_PACKETDATA::iterator    ITR_MULTI_MAP_PACKETDATA;

class UdpThreadPool
{
public:
    UdpThreadPool(const char* localIp, uint32_t localPort = 8115, uint32_t numthreads = std::thread::hardware_concurrency(), uint32_t maxnumtasks = MAX_RECV_LIST_COUNT);
    ~UdpThreadPool();
    int send(const string &peerIP, uint32_t peerPort, const char * buf, size_t len);
    void start();
    void stop();
    size_t getUdpSendQueueSize() { return m_sendList.size(); }
    size_t getUdpRetryQueueSize() { return m_retryList.size(); }
    size_t getUdpRecvQueueSize() { return m_recvList.size(); }

private:
    void Recv();
    void RecvData();
    void Send();
    void SendData(T_PUDPNODE t);
    void SendAgain();
    void CheckExpired();
    int  OpenUdpSocket();
    void CloseUdpSocket();
    bool UdpSocketIsValid();
    void CleanExpiredCache();
    void slice_ack_resp_add(vector<uint8_t> &bitmap, uint16_t id);
    bool slice_ack_resp_check(vector<uint8_t> &bitmap, uint16_t id) const;

private:
    bool					m_isstop;
    std::atomic<uint32_t>	m_packetNum;
    uint32_t				m_localPort;
    const char				*m_localIp;
#ifdef WIN32
    SOCKET					m_listenFd;
#else
    int						m_listenFd;
#endif

    SyncQueue<T_PUDPNODE>	m_sendList;
    SyncQueue<T_PUDPNODE>	m_retryList;
    SyncQueue<T_RECVNODE>	m_recvList;
    std::thread				m_listenthread;
    std::thread				m_checkthread;
    std::list<std::thread>	m_sendthreads;
    std::list<std::thread>	m_retrythreads;
    std::list<std::thread>	m_recvthreads;
    uint32_t				m_sendthreads_num;
    uint32_t				m_retrythreads_num;
    uint32_t				m_recvthreads_num;

    MAP_T_PUDPNODE			m_sendMap;
    MAP_PACKETDATA			m_packetMap;
    MULTI_MAP_PACKETDATA	m_recvMap;

    std::mutex				m_sendMapLock;
    std::mutex				m_packetMapLock;
    std::mutex				m_recvMapLock;
};
#pragma once
