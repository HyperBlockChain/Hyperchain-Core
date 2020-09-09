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

#include "newLog.h"
#include "UdtThreadPool.h"
#include "UdpRecvDataHandler.hpp"

UdtThreadPool::UdtThreadPool(const char* localIp, uint32_t localPort, uint32_t numthreads, uint32_t maxnumtasks) :
    m_sendList(maxnumtasks), m_recvList(maxnumtasks)
{
    m_isstop = true;
    m_listenFd = UDT::INVALID_SOCK;
    m_localIp = localIp;
    m_localPort = localPort;
    m_sendthreads_num = numthreads;
    m_recvthreads_num = numthreads;

    UDT::startup();
}

UdtThreadPool::~UdtThreadPool()
{
    if (!m_isstop)
        stop();

    m_localIp = NULL;
    m_localPort = 0;

    UDT::cleanup();
}

void UdtThreadPool::start()
{
    g_daily_logger->info("UdtThreadPool::Start ...");

    m_isstop = false;

    m_listenthread = std::thread(&UdtThreadPool::Listen, this);

    for (size_t i = 0; i < m_sendthreads_num; i++)
        m_sendthreads.push_back(std::thread(&UdtThreadPool::SendData, this));

    for (size_t i = 0; i < m_recvthreads_num; i++)
        m_recvthreads.push_back(std::thread(&UdtThreadPool::RecvData, this));
}

void UdtThreadPool::stop()
{
    m_isstop = true;

    m_listenthread.join();

    m_sendList.stop();
    m_recvList.stop();

    for (auto& t : m_sendthreads)
        t.join();

    m_sendthreads.clear();

    for (auto& t : m_recvthreads)
        t.join();

    m_recvthreads.clear();

    CloseAllConnectedSocket();
    //UDT::close(m_listenFd);
    UDT::cleanup();
}

int UdtThreadPool::send(const string &peerIP, uint32_t peerPort, const char * buffer, size_t len)
{
    T_UDTNODE tTcpNode;

    tTcpNode.Ip = peerIP;
    tTcpNode.Port = peerPort;
    tTcpNode.BufLen = len;
    tTcpNode.DataBuf = std::move(string(buffer, len));

    if (false == m_sendList.push(std::move(tTcpNode))) {
        g_daily_logger->error("UdtThreadPool::Send() m_sendList.push() failed!");
        cout << "UdtThreadPool::Send() m_sendList.push() failed!" << endl;
        return -1;
    }

    return 0;
}

void UdtThreadPool::SendData()
{
    int sendlen = 0;
    uint32_t sended = 0;
    UDTSOCKET sendFd;
    list<T_UDTNODE> sendlist;

    while (!m_isstop) {
        m_sendList.pop(sendlist);

        for (auto &t : sendlist) {
            if (t.BufLen >= MAX_UDTBUF_SIZE) {
                g_daily_logger->error("UdtThreadPool::SendData(), can't send so much data(BufLen = {})", t.BufLen);
                continue;
            }

            T_SERVERKEY ServerKey(t.Ip, t.Port);
            sendFd = GetConnectedSocket(ServerKey);
            if (sendFd == UDT::INVALID_SOCK) {
                g_daily_logger->error("UdtThreadPool::SendData(), can't connect to serverAddr (ip = {}, port = {})", t.Ip.c_str(), t.Port);
                continue;
            }

            sended = 0;
            do
            {
                sendlen = UDT::sendmsg(sendFd, t.DataBuf.c_str() + sended, t.BufLen - sended);
                if (sendlen == UDT::ERROR) {
                    g_daily_logger->error("UdtThreadPool::SendData() send (ip = {}, port = {}, BufLen = {}) failed! [{}]",
                        t.Ip.c_str(), t.Port, t.BufLen, UDT::getlasterror().getErrorMessage());

                    int errCode = UDT::getlasterror().getErrorCode();
                    if (errCode == CUDTException::ECONNLOST ||
                        errCode == CUDTException::ENOCONN ||
                        errCode == CUDTException::EINVSOCK) {
                        CloseConnectedSocket(ServerKey);

                        UDT::close(sendFd);
                        sendFd = GetConnectedSocket(ServerKey);
                        if (sendFd == UDT::INVALID_SOCK) {
                            g_daily_logger->error("UdtThreadPool::SendData() can't connect to serverAddr (ip = {}, port = {})", t.Ip.c_str(), t.Port);
                            break;
                        }
                    }
                }
                else {
                    sended += sendlen;
                }
            } while (sended < t.BufLen);

            g_daily_logger->debug("UdtThreadPool::SendData() send (ip = {}, port = {}, BufLen = {})", t.Ip.c_str(), t.Port, t.BufLen);
        }

        sendlist.clear();
    }
}

UDTSOCKET UdtThreadPool::GetConnectedSocket(T_SERVERKEY &serverKey)
{
    UDTSOCKET socket_fd = UDT::INVALID_SOCK;

    std::lock_guard<std::mutex> lk(m_socketMapLock);
    ITR_MAP_CONNECTED_SOCKET iter_map = m_socketMap.find(serverKey/*.Ip*/);
    if (iter_map != m_socketMap.end()) {
        socket_fd = iter_map->second;
        return socket_fd;
    }

    socket_fd = CreateConnectionSocket(serverKey);

    return socket_fd;
}

int UdtThreadPool::BindSocket(UDTSOCKET &socket_fd)
{
    string bindIp;
    struct sockaddr_in my_addr;

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(m_localPort);

    if (m_localIp == NULL || strlen(m_localIp) == 0) {
        my_addr.sin_addr.s_addr = INADDR_ANY;
        bindIp = "INADDR_ANY";
    }
    else {
        my_addr.sin_addr.s_addr = inet_addr(m_localIp);
        bindIp = m_localIp;
    }

    int ret = UDT::bind(socket_fd, (const sockaddr *)&my_addr, sizeof(struct sockaddr));
    if (UDT::ERROR == ret) {
        g_daily_logger->error("UdtThreadPool::BindSocket(), bind [{}:{}] error: {}", bindIp.c_str(), m_localPort, UDT::getlasterror().getErrorMessage());
        g_console_logger->error("UdtThreadPool::BindSocket(), bind [{}:{}] error: {}", bindIp.c_str(), m_localPort, UDT::getlasterror().getErrorMessage());
    }

    return ret;
}

int UdtThreadPool::CreateListenSocket()
{
    UDTSTATUS status = UDT::getsockstate(m_listenFd);
    g_daily_logger->info("CreateListenSocket() UDT::getsockstate(m_listenFd): {}", status);
    if (LISTENING == status)
        return 0;

//    if (NONEXIST != status && CLOSED != status)
//        UDT::close(m_listenFd);

    m_listenFd = UDT::socket(AF_INET, SOCK_DGRAM, 0);
    if (m_listenFd == UDT::INVALID_SOCK) {
        g_daily_logger->error("UdtThreadPool::CreateListenSocket(), m_listenFd == UDT::INVALID_SOCK");
        g_console_logger->error("UdtThreadPool::CreateListenSocket(), m_listenFd == UDT::INVALID_SOCK");
        return -1;
    }

    int ret = BindSocket(m_listenFd);
    if (UDT::ERROR == ret) {
        UDT::close(m_listenFd);
        return -1;
    }

    ret = UDT::listen(m_listenFd, FD_SETSIZE);
    if (ret == UDT::ERROR) {
        g_daily_logger->error("UdtThreadPool::CreateListenSocket(), listen error: {}", UDT::getlasterror().getErrorMessage());
        g_console_logger->error("UdtThreadPool::CreateListenSocket(), listen error: {}", UDT::getlasterror().getErrorMessage());
        UDT::close(m_listenFd);
        return -1;
    }

    g_daily_logger->info("UdtThreadPool::CreateListenSocket(), socket_fd = {}", m_listenFd);
    g_console_logger->info("UdtThreadPool::CreateListenSocket(), socket_fd = {}", m_listenFd);

    return 0;
}

UDTSOCKET UdtThreadPool::CreateConnectionSocket(T_SERVERKEY &serverKey)
{
    int ret = 0;
    UDTSOCKET socket_fd;

    socket_fd = UDT::socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == UDT::INVALID_SOCK) {
        g_daily_logger->error("UdtThreadPool, socket_fd == UDT::INVALID_SOCK");
        g_console_logger->error("UdtThreadPool, socket_fd == UDT::INVALID_SOCK");
        return UDT::INVALID_SOCK;
    }

    ret = BindSocket(socket_fd);
    if (UDT::ERROR == ret) {
        UDT::close(socket_fd);
        return UDT::INVALID_SOCK;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(serverKey.Ip.c_str());
    serverAddr.sin_port = htons(serverKey.Port);

    ret = UDT::connect(socket_fd, (const sockaddr *)&serverAddr, sizeof(serverAddr));
    if (UDT::ERROR == ret) {
        UDT::close(socket_fd);
        return UDT::INVALID_SOCK;
    }

    m_socketMap[serverKey/*.Ip*/] = socket_fd;

    g_daily_logger->debug("UdtThreadPool [{}:{}] socket {}",
        serverKey.Ip.c_str(), serverKey.Port, socket_fd);

    return socket_fd;
}

bool UdtThreadPool::AcceptConnectionSocket(UDTSOCKET listenFd)
{
    std::lock_guard<std::mutex> lk(m_socketMapLock);
    if (m_socketMap.size() >= FD_SETSIZE)
        return false;

    struct sockaddr_in serverAddr;
    int serverAddrLen = sizeof(serverAddr);
    UDTSOCKET socket_fd = UDT::accept(listenFd, (struct sockaddr*) & serverAddr, &serverAddrLen);
    if (socket_fd == UDT::INVALID_SOCK) {
        g_daily_logger->error("UdtThreadPool accept : [{}]", UDT::getlasterror().getErrorMessage());
        g_console_logger->error("UdtThreadPool accept : [{}]", UDT::getlasterror().getErrorMessage());
        return false;
    }

    string fromIp = inet_ntoa(serverAddr.sin_addr);
    uint32_t fromPort = ntohs(serverAddr.sin_port);
    T_SERVERKEY ServerKey(fromIp, fromPort);

    ITR_MAP_CONNECTED_SOCKET iter_map = m_socketMap.find(ServerKey);
    if (iter_map != m_socketMap.end()) {
        g_daily_logger->warn("UdtThreadPool [{}:{}] socket {} already exist!",
            fromIp.c_str(), fromPort, iter_map->second);
        g_console_logger->warn("UdtThreadPool [{}:{}] socket {} already exist!",
            fromIp.c_str(), fromPort, iter_map->second);
        UDT::close(iter_map->second);
    }

    m_socketMap[ServerKey/*.Ip*/] = socket_fd;

    g_daily_logger->debug("UdtThreadPool [{}:{}] socket {}", fromIp.c_str(), fromPort, socket_fd);

    return true;
}

void UdtThreadPool::CloseConnectedSocket(T_SERVERKEY &serverKey)
{
    std::lock_guard<std::mutex> lk(m_socketMapLock);
    m_socketMap.erase(serverKey/*.Ip*/);
}

void UdtThreadPool::CloseConnectedSocket(UDTSOCKET &socket_fd)
{
    g_daily_logger->debug("UdtThreadPool::CloseConnectedSocket, socket_fd: {}", socket_fd);
    for (auto it = m_socketMap.begin(); it != m_socketMap.end(); it++) {
        if (it->second == socket_fd) {
            m_socketMap.erase(it);
            break;
        }
    }
}

void UdtThreadPool::CloseAllConnectedSocket()
{
    std::lock_guard<std::mutex> lk(m_socketMapLock);

    for (auto& t : m_socketMap)
        UDT::close(t.second);

    m_socketMap.clear();
}

void UdtThreadPool::Listen()
{
    UDT::UDSET fd;
    int selectRet = 0;
    timeval timeout;

    if (CreateListenSocket())
        exit(-1);

    while (!m_isstop) {
        timeout = { 10, 0 }; 

        FillFdSets(fd);
        selectRet = UDT::select(0, &fd, NULL, NULL, &timeout);
        if (selectRet == 0) {
            continue;
        }

        if (selectRet == -1) {
            int errCode = UDT::getlasterror().getErrorCode();
            g_daily_logger->error("UdtThreadPool::Listen() select error: [{}] {}", errCode, UDT::getlasterror().getErrorMessage());
            g_console_logger->error("UdtThreadPool::Listen() select error: [{}] {}", errCode, UDT::getlasterror().getErrorMessage());

            UDTSTATUS status = UDT::getsockstate(m_listenFd);
            g_daily_logger->debug("Listen() UDT::getsockstate(m_listenFd): {}", status);
            if (LISTENING != status) {
                CreateListenSocket();
            }

            continue;
        }

        if (UD_ISSET(m_listenFd, &fd)) {
            if (AcceptConnectionSocket(m_listenFd))
                selectRet--;
        }

        if (selectRet > 0) {
            FillRecvSocketList(fd, selectRet);
        }
    }

    UDT::close(m_listenFd);
}

void UdtThreadPool::FillFdSets(UDT::UDSET& readfds)
{
    UD_ZERO(&readfds);

    UDTSTATUS status = UDT::getsockstate(m_listenFd);
    g_daily_logger->debug("FillFdSets() UDT::getsockstate(m_listenFd): {}", status);
    if (LISTENING != status) {
        if (CreateListenSocket())
            exit(-1);
    }

    UD_SET(m_listenFd, &readfds);

    std::lock_guard<std::mutex> lk(m_socketMapLock);
    for (auto it = m_socketMap.begin(); it != m_socketMap.end();) {
        UDTSTATUS status = UDT::getsockstate(it->second);
        g_daily_logger->debug("FillFdSets() UDT::getsockstate({}): {}", it->second, status);
        if (CONNECTED != UDT::getsockstate(it->second)) {
            it = m_socketMap.erase(it);
            continue;
        }

        UD_SET(it->second, &readfds);
        ++it;
    }
}

void UdtThreadPool::FillRecvSocketList(UDT::UDSET &readfds, int &activeNum)
{
    std::lock_guard<std::mutex> lk(m_socketMapLock);

    MAP_CONNECTED_SOCKET tempSockMap = m_socketMap;
    for (auto &t : tempSockMap) {
        if (UD_ISSET(t.second, &readfds)) {
            Recv(t.second);
            activeNum--;
        }

        if (activeNum <= 0)
            break;
    }
}

void UdtThreadPool::Recv(UDTSOCKET socket_fd)
{
    if (socket_fd == UDT::INVALID_SOCK)
        return;

    T_UDTRECV RecvNode;
    struct sockaddr_in fromAddr;
    int fromLen = sizeof(fromAddr);
    char* recvBuf = new char[MAX_UDTBUF_SIZE];

    int recvNum = UDT::recvmsg(socket_fd, recvBuf, MAX_UDTBUF_SIZE);
    //g_daily_logger->info("UdtThreadPool::Recv(), recv data len ({})", recvNum);
    if (recvNum == UDT::ERROR) {
        g_daily_logger->error("UdtThreadPool::Recv() recv [fd: {}] error: {}", socket_fd, UDT::getlasterror().getErrorMessage());
        CloseConnectedSocket(socket_fd);
        UDT::close(socket_fd);
        delete[]recvBuf;
        return;
    }

    if (recvNum == 0) {
        g_daily_logger->error("UdtThreadPool::Recv() recv fd: {} closed!", socket_fd);
        CloseConnectedSocket(socket_fd);
        UDT::close(socket_fd);
        delete[]recvBuf;
        return;
    }

    int ret = UDT::getpeername(socket_fd, (struct sockaddr *)&fromAddr, &fromLen);
    if (ret == UDT::ERROR) {
        g_daily_logger->error("UdtThreadPool::Recv() getpeername error: [{}]", UDT::getlasterror().getErrorMessage());
        g_console_logger->error("UdtThreadPool::Recv() getpeername error: [{}]", UDT::getlasterror().getErrorMessage());
        CloseConnectedSocket(socket_fd);
        UDT::close(socket_fd);
        delete[]recvBuf;
        return;
    }

    RecvNode.DataBuf.append(recvBuf, recvNum);
    RecvNode.fromAddr = fromAddr;

    if (false == m_recvList.push(std::forward<T_UDTRECV>(RecvNode))) {
        g_daily_logger->error("UdtThreadPool::Recv() m_recvList.push() failed! m_recvList.size={}", m_recvList.size());
        cout << "UdtThreadPool::Recv() m_recvList.push() failed! m_recvList.size=" << m_recvList.size() << endl;
    }

    delete[]recvBuf;
}


void UdtThreadPool::RecvData()
{
    bool bret;
    list<T_UDTRECV> recvlist;
    uint32_t fromPort;
    string fromIp;
    UdpRecvDataHandler *udprecvhandler = Singleton<UdpRecvDataHandler>::getInstance();

    while (!m_isstop) {
        m_recvList.pop(recvlist);
        for (auto &t : recvlist)
        {
            fromIp = inet_ntoa(t.fromAddr.sin_addr);
            fromPort = ntohs(t.fromAddr.sin_port);

        RETRY:
            bret = udprecvhandler->put(fromIp.c_str(), fromPort, t.DataBuf.c_str(), t.DataBuf.size());
            if (bret == false) {
                g_daily_logger->error("UdtThreadPool::Recv() udprecvhandler->put == false!");
                if (m_isstop)
                    break;

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                goto RETRY;
            }
            g_daily_logger->debug("UdtThreadPool::udprecvhandler->put(serverAddr [{}:{}], len = {}) ",
                fromIp.c_str(), fromPort, t.DataBuf.size());
        }

        recvlist.clear();
    }
}
