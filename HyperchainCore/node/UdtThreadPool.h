/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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
#include <wspiapi.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#endif
#include "../udt/udt.h"
#include "SyncQueue.h"

#define MAX_UDTBUF_SIZE 10240000		

#define MAX_LIST_COUNT	50000			


#ifdef FD_SETSIZE
#undef FD_SETSIZE // prevent redefinition compiler warning
#endif
#define FD_SETSIZE 1024 // max number of fds in fd_set

typedef struct _tudtnode
{
    string Ip;
    uint32_t Port;
    uint32_t BufLen;
    string DataBuf;
}T_UDTNODE, *T_PUDTNODE;

typedef struct _tudtrecvnode
{
    struct sockaddr_in fromAddr;
    string DataBuf;
}T_UDTRECV, *T_PUDTRECV;

typedef struct _tserverkey
{
    string Ip;
    uint32_t Port;

    _tserverkey(string ip, uint32_t port) : Ip(ip), Port(port) {}

    bool operator<(_tserverkey const& other) const
    {
        if (Ip < other.Ip) { return true; }
        if (Ip > other.Ip) { return false; }
        return Port < other.Port;
    }
}T_SERVERKEY;

typedef map<T_SERVERKEY/*string*/, UDTSOCKET>		  MAP_CONNECTED_SOCKET;
typedef MAP_CONNECTED_SOCKET::iterator    ITR_MAP_CONNECTED_SOCKET;

class UdtThreadPool
{
public:
    UdtThreadPool(const char* localIp, uint32_t localPort = 8115, uint32_t numthreads = std::thread::hardware_concurrency(), uint32_t maxnumtasks = MAX_LIST_COUNT);
    ~UdtThreadPool();
    int send(const string &peerIP, uint32_t peerPort, const char * buf, size_t len);
    void start();
    void stop();
    size_t getUdtSendQueueSize() { return m_sendList.size(); }
    size_t getUdtRecvQueueSize() { return m_recvList.size(); }

private:
    void Listen();
    void RecvData();
    void SendData();
    int  CreateListenSocket();
    void CloseAllConnectedSocket();
    void Recv(UDTSOCKET socket_fd);
    void FillFdSets(UDT::UDSET &readfds);
    void FillRecvSocketList(UDT::UDSET &readfds, int &activeNum);
    bool AcceptConnectionSocket(UDTSOCKET listenFd);
    void CloseConnectedSocket(UDTSOCKET &socket_fd);
    void CloseConnectedSocket(T_SERVERKEY &serverKey);
    int BindSocket(UDTSOCKET &socket_fd);
    UDTSOCKET GetConnectedSocket(T_SERVERKEY &serverAddr);
    UDTSOCKET CreateConnectionSocket(T_SERVERKEY &serverAddr);

private:
    bool					m_isstop;
    uint32_t				m_localPort;
    const char*             m_localIp;
    UDTSOCKET				m_listenFd;
    SyncQueue<T_UDTNODE>	m_sendList;
    SyncQueue<T_UDTRECV>	m_recvList;
    std::thread				m_listenthread;
    std::list<std::thread>	m_sendthreads;
    std::list<std::thread>	m_recvthreads;
    uint32_t				m_sendthreads_num;
    uint32_t				m_recvthreads_num;
    MAP_CONNECTED_SOCKET    m_socketMap;
    std::mutex              m_socketMapLock;
};