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

#include "newLog.h"
#include "UdpThreadPool.h"
#include "UdpRecvDataHandler.hpp"

//deal with return 10054 error
//#ifdef WIN32
//#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
//#endif

uint32_t UdpHeaderSize = sizeof(T_UDPHEADER);
uint32_t UdpSliceHeaderSize = sizeof(T_UDPSLICEHEADER);

int UdpThreadPool::OpenUdpSocket()
{
    if (UdpSocketIsValid())
        return 0;

    m_listenFd = socket(AF_INET, SOCK_DGRAM, 0);

#ifdef WIN32
    if (m_listenFd == SOCKET_ERROR || m_listenFd == INVALID_SOCKET) {
        g_daily_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener create error: [{}]", WSAGetLastError());
        g_console_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener create error: [{}]", WSAGetLastError());
        return -1;
    }
#else
    if (m_listenFd < 0) {
        g_daily_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener create error: [errno {}] {}", errno, strerror(errno));
        g_console_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener create error: [errno {}] {}", errno, strerror(errno));
        return -1;
    }
#endif

    //deal with return 10054 error
    //#ifdef WIN32
    //	BOOL bNewBehavior = FALSE;
    //	DWORD dwBytesReturned = 0;
    //
    //	WSAIoctl(m_listenFd, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL);
    //#endif

    int bufsize = MAX_BUFFER_SIZE;
    int ret = 0;

    ret = setsockopt(m_listenFd, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    if (ret == -1)
    {
#ifdef WIN32
        g_daily_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener setsockopt SO_RCVBUF error: [{}]", WSAGetLastError());
        g_console_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener setsockopt SO_RCVBUF error: [{}]", WSAGetLastError());
#else
        g_daily_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener setsockopt SO_RCVBUF error: [errno {}] {}", errno, strerror(errno));
        g_console_logger->error("UdpThreadPool::OpenUdpSocket() ufd_listener setsockopt SO_RCVBUF error: [errno {}] {}", errno, strerror(errno));
#endif
        return -1;
    }

    string bindIp;
    struct sockaddr_in my_addr;
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;

    if (m_localIp == NULL || strlen(m_localIp) == 0)
    {
        my_addr.sin_addr.s_addr = INADDR_ANY;
        bindIp = "INADDR_ANY";
    }
    else
    {
        my_addr.sin_addr.s_addr = inet_addr(m_localIp);
        bindIp = m_localIp;
    }

    my_addr.sin_port = htons(m_localPort);
    ret = ::bind(m_listenFd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
    if (ret == -1)
    {
#ifdef WIN32
        g_daily_logger->error("UdpThreadPool::OpenUdpSocket(), ufd_listener bind [{}:{}] error: {}", bindIp.c_str(), this->m_localPort, WSAGetLastError());
        g_console_logger->error("UdpThreadPool::OpenUdpSocket(), ufd_listener bind [{}:{}] error: {}", bindIp.c_str(), this->m_localPort, WSAGetLastError());
#else
        g_daily_logger->error("UdpThreadPool::OpenUdpSocket(), ufd_listener bind [{}:{}] error: [errno {}] {}", bindIp.c_str(), this->m_localPort, errno, strerror(errno));
        g_console_logger->error("UdpThreadPool::OpenUdpSocket(), ufd_listener bind [{}:{}] error: [errno {}] {}", bindIp.c_str(), this->m_localPort, errno, strerror(errno));
#endif
        return -1;
    }

    return 0;
}

void UdpThreadPool::CloseUdpSocket()
{
#ifdef WIN32
    if (m_listenFd != INVALID_SOCKET)
    {
        shutdown(m_listenFd, SD_BOTH);
        closesocket(m_listenFd);
        m_listenFd = INVALID_SOCKET;
    }
#else
    if (m_listenFd != -1)
    {
        shutdown(m_listenFd, SHUT_RDWR);
        close(m_listenFd);
        m_listenFd = -1;
    }
#endif
}

bool UdpThreadPool::UdpSocketIsValid()
{
#ifdef WIN32
    if (m_listenFd == INVALID_SOCKET)
        return false;
#else
    if (m_listenFd == -1)
        return false;
#endif

    int type = 0;
    socklen_t type_len = sizeof(type);
    int ret = getsockopt(m_listenFd, SOL_SOCKET, SO_TYPE, (char*)&type, &type_len);
    if (ret == -1)
    {
#ifdef WIN32
        g_daily_logger->error("UdpThreadPool::UdpSocketIsValid() ufd_listener getsockopt SO_TYPE error: [{}]", WSAGetLastError());
        g_console_logger->error("UdpThreadPool::UdpSocketIsValid() ufd_listener getsockopt SO_TYPE error: [{}]", WSAGetLastError());
#else
        g_daily_logger->error("UdpThreadPool::UdpSocketIsValid() ufd_listener getsockopt SO_TYPE error: [errno {}] {}", errno, strerror(errno));
        g_console_logger->error("UdpThreadPool::UdpSocketIsValid() ufd_listener getsockopt SO_TYPE error: [errno {}] {}", errno, strerror(errno));
#endif
        return false;
    }

    return true;
}

UdpThreadPool::UdpThreadPool(const char* localIp, uint32_t localPort, uint32_t numthreads, uint32_t maxnumtasks) :
    m_sendList(maxnumtasks), m_retryList(maxnumtasks), m_recvList(maxnumtasks)
{
    m_isstop = false;
    m_packetNum = 0;
#ifdef WIN32
    m_listenFd = INVALID_SOCKET;
#else
    m_listenFd = -1;
#endif
    m_localIp = localIp;
    m_localPort = localPort;
    m_sendthreads_num = numthreads;
    m_retrythreads_num = numthreads;
    m_recvthreads_num = numthreads;

#ifdef WIN32
    WSADATA wsaData;
    WORD sockVersion = MAKEWORD(2, 2);

    if (WSAStartup(sockVersion, &wsaData) != 0)
    {
        g_daily_logger->error("UdpThreadPool::UdpThreadPool() WSAStartup() != 0");
        g_console_logger->error("UdpThreadPool::UdpThreadPool() WSAStartup() != 0");
        exit(-1);
    }
#endif
}

UdpThreadPool::~UdpThreadPool()
{
    if (!m_isstop) {
        stop();
    }

    m_packetNum = 0;
    m_localIp = NULL;
    m_localPort = 0;

    CloseUdpSocket();

#ifdef WIN32
    WSACleanup();
#endif
}

void UdpThreadPool::start()
{
    g_daily_logger->info("UdpThreadPool::Start ...");

    m_listenthread = thread(&UdpThreadPool::RecvData, this);

    for (size_t i = 0; i < m_sendthreads_num; i++) {
        m_sendthreads.push_back(thread(&UdpThreadPool::Send, this));
    }

    for (size_t i = 0; i < m_retrythreads_num; i++) {
        m_retrythreads.push_back(thread(&UdpThreadPool::SendAgain, this));
    }

    for (size_t i = 0; i < m_recvthreads_num; i++) {
        m_recvthreads.push_back(thread(&UdpThreadPool::Recv, this));
    }

    m_checkthread = thread(&UdpThreadPool::CheckExpired, this);
}

void UdpThreadPool::stop()
{
    m_isstop = true;

    m_listenthread.join();

    m_sendList.stop();
    m_retryList.stop();
    m_recvList.stop();

    for (auto& t : m_sendthreads) {
        t.join();
    }
    m_sendthreads.clear();

    for (auto& t : m_retrythreads) {
        t.join();
    }
    m_retrythreads.clear();

    for (auto& t : m_recvthreads) {
        t.join();
    }
    m_recvthreads.clear();

    m_checkthread.join();
}

std::time_t getTimeStamp()
{
    std::chrono::time_point<system_clock, std::chrono::milliseconds> tp;
    tp = std::chrono::time_point_cast<std::chrono::milliseconds>(system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    std::time_t timestamp = tmp.count();

    return timestamp;
}

int UdpThreadPool::send(const string &peerIP, uint32_t peerPort, const char * buffer, size_t len)
{
    T_UDPHEADER UdpHeader;

    UdpHeader.uPacketNum = this->m_packetNum;
    this->m_packetNum++;

    UdpHeader.HeaderType = PACKET_HEADER;
    UdpHeader.Version = CURRENT_VERSION;
    UdpHeader.PacketType = UDP_INIT_PAKTYPE;

    UdpHeader.uBufLen = len;
    UdpHeader.uDataBufCrc = crc32buf((char*)buffer, len);

    uint32_t lastSliceSize = 0;
    uint32_t sliceNum = 0;

    sliceNum = len / UDP_SLICE_MAX_SIZE;
    lastSliceSize = len % UDP_SLICE_MAX_SIZE;

    if (lastSliceSize > 0)
    {
        sliceNum++;
    }
    g_daily_logger->debug("UdpThreadPool::send(PacketNum = {}, BufLen = {}, sliceNum = {})", UdpHeader.uPacketNum, UdpHeader.uBufLen, sliceNum);

    UdpHeader.uSliceTotalNum = sliceNum;

    T_PUDPNODE tpUdpNode;
    std::time_t timeTemp;

    try {
        tpUdpNode = new T_UDPNODE;
    }
    catch (std::bad_alloc & e) {
        g_daily_logger->error("UdpThreadPool::send(new T_UDPNODE failed!) {}", e.what());
        cout << "UdpThreadPool::send(new T_UDPNODE failed!) " << e.what() << endl;
        //
        return -1;
    }

    tpUdpNode->Ip = peerIP;
    tpUdpNode->Port = peerPort;
    tpUdpNode->ClearFlag = DEFAULT;
    tpUdpNode->RetryTimes = 0;

    timeTemp = getTimeStamp();
    uint64_t intervaltime = sliceNum * MAX_INTERVAL_TIME;
    tpUdpNode->NextSendTime = timeTemp + intervaltime;
    tpUdpNode->bitmap.resize(128, 0);
    tpUdpNode->UdpHeader = UdpHeader;

    try {
        tpUdpNode->DataBuf = new char[len];
    }
    catch (std::bad_alloc & e) {
        g_daily_logger->error("UdpThreadPool::send(new DataBuf failed!) {}", e.what());
        cout << "UdpThreadPool::send(new DataBuf failed!) " << e.what() << endl;
        delete tpUdpNode;
        return -1;
    }
    memcpy(tpUdpNode->DataBuf, (char*)buffer, len);

    if (false == m_sendList.push(std::forward<T_PUDPNODE>(tpUdpNode))) {
        g_daily_logger->error("UdpThreadPool::send() m_sendList.push() failed!");
        cout << "UdpThreadPool::send() m_sendList.push() failed!" << endl;
        return -1;
    }

    lock_guard<mutex> lk(m_sendMapLock);
    m_sendMap[UdpHeader.uPacketNum] = tpUdpNode;

    return 0;
}

void UdpThreadPool::slice_ack_resp_add(vector<uint8_t> &bitmap, uint16_t id)
{
    //
    uint8_t bit_list[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    uint16_t p = id / 8;
    uint8_t site_value = id % 8;

    while (bitmap.size() < p + 1) {
        bitmap.resize(bitmap.size() + 128, 0);
    }
    g_daily_logger->debug("slice_ack_resp_add(), id = {}, bitmap.size() = {}", id, bitmap.size());

    bitmap[p] = bitmap[p] | bit_list[site_value];
}

bool UdpThreadPool::slice_ack_resp_check(vector<uint8_t> &bitmap, uint16_t id) const
{
    //
    uint8_t bit_list[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    uint16_t p = id / 8;
    uint8_t site_value = id % 8;

    if (bitmap.size() < p + 1) {
        g_daily_logger->info("slice_ack_resp_check(),bitmap.size() = {}, id = {}, OutOfBounds!", bitmap.size(), id);
        return false;
    }

    g_daily_logger->debug("slice_ack_resp_check(), id = {}, bitmap & bit_list = {}", id, bitmap[p] & bit_list[site_value]);
    if (bit_list[site_value] == (bitmap[p] & bit_list[site_value])) {
        return true;
    }
    return false;
}

void UdpThreadPool::SendData(T_PUDPNODE t)
{
    int sendlen = 0;
    std::time_t nowTime;
    unsigned char frameBuffer[MAX_BUFFER_SIZE];

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(t->Ip.c_str());
    serverAddr.sin_port = htons(t->Port);

    if (t->UdpHeader.uSliceTotalNum <= 1) {
        //
        memset(frameBuffer, 0, MAX_BUFFER_SIZE);
        memcpy(frameBuffer, &(t->UdpHeader), UdpHeaderSize);
        memcpy(frameBuffer + UdpHeaderSize, t->DataBuf, t->UdpHeader.uBufLen);

        uint32_t BufLen = UdpHeaderSize + t->UdpHeader.uBufLen;

        sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, BufLen, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        g_daily_logger->info("UdpThreadPool::SendAgain() sendto (ip = {}, port = {}, PacketNum = {}, BufLen = {}), sendlen = {})",
            inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), t->UdpHeader.uPacketNum, BufLen, sendlen);
        if (sendlen != BufLen) {
#ifdef WIN32
            g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, BufLen = {}, sendlen = {})",
                WSAGetLastError(), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), t->UdpHeader.uPacketNum, BufLen, sendlen);
#else
            g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, BufLen = {}, sendlen = {})",
                strerror(errno), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), t->UdpHeader.uPacketNum, BufLen, sendlen);
#endif
        }

        nowTime = getTimeStamp();
        t->NextSendTime = nowTime + MAX_INTERVAL_TIME;
        t->RetryTimes++;

        return;
    }

    //
    char tmp_buf[UDP_SLICE_MAX_SIZE];
    T_UDPSLICEHEADER UdpSliceHeader;
    uint32_t sliceNum = t->UdpHeader.uSliceTotalNum;
    uint32_t currentSliceIndex = 0;
    uint32_t needSendLen = 0;
    uint32_t TmpCount = 0;

    UdpSliceHeader.HeaderType = SLICE_HEADER;
    UdpSliceHeader.SliceType = UDP_INIT_PAKTYPE;
    UdpSliceHeader.uPacketNum = t->UdpHeader.uPacketNum;
    UdpSliceHeader.uSliceTotalNum = sliceNum;

    while (currentSliceIndex < sliceNum) {
        if (t->RetryTimes > 0 && slice_ack_resp_check(t->bitmap, currentSliceIndex)) {
            currentSliceIndex++;
            continue;
        }

        if (currentSliceIndex < (sliceNum - 1)) {
            UdpSliceHeader.uSliceBufLen = UDP_SLICE_MAX_SIZE;
            UdpSliceHeader.uSliceCurrIndex = currentSliceIndex;
            UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

            memcpy(tmp_buf, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
            UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, UDP_SLICE_MAX_SIZE);

            if (currentSliceIndex == 0) {
                memset(frameBuffer, 0, MAX_BUFFER_SIZE);
                memcpy(frameBuffer, &(t->UdpHeader), UdpHeaderSize);
                memcpy(frameBuffer + UdpHeaderSize, &UdpSliceHeader, UdpSliceHeaderSize);
                memcpy(frameBuffer + UdpHeaderSize + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
                needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize + UdpHeaderSize;
            }
            else {
                memset(frameBuffer, 0, MAX_BUFFER_SIZE);
                memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
                memcpy(frameBuffer + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
                needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
            }

        }
        else {
            int tmp_len = t->UdpHeader.uBufLen - currentSliceIndex * UDP_SLICE_MAX_SIZE;
            UdpSliceHeader.uSliceBufLen = tmp_len;
            UdpSliceHeader.uSliceCurrIndex = currentSliceIndex;
            UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

            memcpy(tmp_buf, t->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
            UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, tmp_len);

            memset(frameBuffer, 0, MAX_BUFFER_SIZE);
            memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
            memcpy(frameBuffer + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
            needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
        }

        sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, needSendLen, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        g_daily_logger->info("UdpThreadPool::SendAgain() sendto (ip = {}, port = {}, PacketNum = {}, SliceCurrIndex = {}, SliceSize = {}, sendlen = {})",
            inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), UdpSliceHeader.uPacketNum, UdpSliceHeader.uSliceCurrIndex, needSendLen, sendlen);
        if (sendlen != needSendLen) {
#ifdef WIN32
            g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, SliceSize = {}, sendlen = {}, SliceCurrIndex = {})",
                WSAGetLastError(), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), UdpSliceHeader.uPacketNum, needSendLen, sendlen, UdpSliceHeader.uSliceCurrIndex);
#else
            g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, SliceSize = {}, sendlen = {}, SliceCurrIndex = {})",
                strerror(errno), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), UdpSliceHeader.uPacketNum, needSendLen, sendlen, UdpSliceHeader.uSliceCurrIndex);
#endif
            break;
        }

        TmpCount++;
        currentSliceIndex++;

        //
        if ((TmpCount != 0) && (TmpCount % 100 == 0))
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    uint64_t intervaltime = TmpCount * MAX_INTERVAL_TIME;
    nowTime = getTimeStamp();
    t->NextSendTime = nowTime + intervaltime;
    t->RetryTimes++;

}

void UdpThreadPool::Send()
{
    list<T_PUDPNODE> sendlist;

    while (!m_isstop) {
        m_sendList.pop(sendlist);

        for (auto &t : sendlist) {
            SendData(t);

            if (false == m_retryList.push(std::forward<T_PUDPNODE>(t))) {
                g_daily_logger->error("UdpThreadPool::Send() m_retryList.push() failed!");
                cout << "UdpThreadPool::Send() m_retryList.push() failed!" << endl;
            }
        }

        sendlist.clear();
    }
}

void UdpThreadPool::SendAgain()
{
    //int sendlen = 0;
    uint32_t TmpCount = 0;
    std::time_t nowTime;
    list<T_PUDPNODE> sendlist;
    //unsigned char frameBuffer[MAX_BUFFER_SIZE];

    g_daily_logger->debug("SendAgain() this->m_listenFd = {}", this->m_listenFd);
    while (!m_isstop) {
        m_retryList.pop(sendlist);

        for (auto &t : sendlist) {
            if (t->RetryTimes >= MAX_SEND_TIMES || t->ClearFlag == ACK_FLAG) {
                //
                g_daily_logger->debug("PacketNum = {}, RetryTimes = {}, ClearFlag = {}", t->UdpHeader.uPacketNum, t->RetryTimes, t->ClearFlag);

                //
                {
                    lock_guard<mutex> lk(m_sendMapLock);
                    ITR_MAP_T_PUDPNODE iter_map = this->m_sendMap.find(t->UdpHeader.uPacketNum);
                    if (iter_map != this->m_sendMap.end()) {
                        if (iter_map->second != NULL)
                            iter_map->second = NULL;

                        this->m_sendMap.erase(iter_map);
                    }
                    else
                        g_daily_logger->debug("ERROR: not find PacketNum({}) in m_sendMap!", t->UdpHeader.uPacketNum);
                }

                //
                if (t->DataBuf != NULL) {
                    delete[]t->DataBuf;
                    t->DataBuf = NULL;
                }
                if (t != NULL) {
                    delete t;
                    t = NULL;
                }

                continue;
            }

            nowTime = getTimeStamp();
            if (/*(t->RetryTimes == 0) || */(nowTime > t->NextSendTime)) {
                g_daily_logger->debug("PacketNum = {}, RetryTimes = {}, sliceTotalNum = {}", t->UdpHeader.uPacketNum, t->RetryTimes, t->UdpHeader.uSliceTotalNum);
                SendData(t);
//                struct sockaddr_in serverAddr;
//                memset(&serverAddr, 0, sizeof(serverAddr));
//                serverAddr.sin_family = AF_INET;
//                serverAddr.sin_addr.s_addr = inet_addr(t->Ip.c_str());
//                serverAddr.sin_port = htons(t->Port);
//
//                if (t->UdpHeader.uSliceTotalNum <= 1) {
//                    //
//                    memset(frameBuffer, 0, MAX_BUFFER_SIZE);
//                    memcpy(frameBuffer, &(t->UdpHeader), UdpHeaderSize);
//                    memcpy(frameBuffer + UdpHeaderSize, t->DataBuf, t->UdpHeader.uBufLen);
//
//                    uint32_t BufLen = UdpHeaderSize + t->UdpHeader.uBufLen;
//
//                    sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, BufLen, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
//                    g_daily_logger->info("UdpThreadPool::SendAgain() sendto (ip = {}, port = {}, PacketNum = {}, BufLen = {}), sendlen = {})",
//                        inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), t->UdpHeader.uPacketNum, BufLen, sendlen);
//                    if (sendlen != BufLen) {
//#ifdef WIN32
//                        g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, BufLen = {}, sendlen = {})",
//                            WSAGetLastError(), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), t->UdpHeader.uPacketNum, BufLen, sendlen);
//#else
//                        g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, BufLen = {}, sendlen = {})",
//                            strerror(errno), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), t->UdpHeader.uPacketNum, BufLen, sendlen);
//#endif
//                    }
//
//                    nowTime = getTimeStamp();
//                    t->NextSendTime = nowTime + MAX_INTERVAL_TIME;
//                    t->RetryTimes++;
//
//                    if (false == m_sendList.push(std::forward<T_PUDPNODE>(t))) {
//                        g_daily_logger->error("UdpThreadPool::sendAgain() m_sendList.push() failed!");
//                        cout << "UdpThreadPool::sendAgain() m_sendList.push() failed!" << endl;
//                    }
//
//                    continue;
//                }
//
//                //
//                char tmp_buf[UDP_SLICE_MAX_SIZE];
//                T_UDPSLICEHEADER UdpSliceHeader;
//                uint32_t sliceNum = t->UdpHeader.uSliceTotalNum;
//                uint32_t currentSliceIndex = 0;
//                uint32_t needSendLen = 0;
//                uint32_t TmpCount = 0;
//
//                UdpSliceHeader.HeaderType = SLICE_HEADER;
//                UdpSliceHeader.SliceType = UDP_INIT_PAKTYPE;
//                UdpSliceHeader.uPacketNum = t->UdpHeader.uPacketNum;
//                UdpSliceHeader.uSliceTotalNum = sliceNum;
//
//                while (currentSliceIndex < sliceNum) {
//                    if (t->RetryTimes > 0 && slice_ack_resp_check(t->bitmap, currentSliceIndex)) {
//                        currentSliceIndex++;
//                        continue;
//                    }
//
//                    if (currentSliceIndex < (sliceNum - 1)) {
//                        UdpSliceHeader.uSliceBufLen = UDP_SLICE_MAX_SIZE;
//                        UdpSliceHeader.uSliceCurrIndex = currentSliceIndex;
//                        UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;
//
//                        memcpy(tmp_buf, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
//                        UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, UDP_SLICE_MAX_SIZE);
//
//                        if (currentSliceIndex == 0) {
//                            memset(frameBuffer, 0, MAX_BUFFER_SIZE);
//                            memcpy(frameBuffer, &(t->UdpHeader), UdpHeaderSize);
//                            memcpy(frameBuffer + UdpHeaderSize, &UdpSliceHeader, UdpSliceHeaderSize);
//                            memcpy(frameBuffer + UdpHeaderSize + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
//                            needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize + UdpHeaderSize;
//                        }
//                        else {
//                            memset(frameBuffer, 0, MAX_BUFFER_SIZE);
//                            memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
//                            memcpy(frameBuffer + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
//                            needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
//                        }
//
//                    }
//                    else {
//                        int tmp_len = t->UdpHeader.uBufLen - currentSliceIndex * UDP_SLICE_MAX_SIZE;
//                        UdpSliceHeader.uSliceBufLen = tmp_len;
//                        UdpSliceHeader.uSliceCurrIndex = currentSliceIndex;
//                        UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;
//
//                        memcpy(tmp_buf, t->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
//                        UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, tmp_len);
//
//                        memset(frameBuffer, 0, MAX_BUFFER_SIZE);
//                        memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
//                        memcpy(frameBuffer + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
//                        needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
//                    }
//
//                    sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, needSendLen, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
//                    g_daily_logger->info("UdpThreadPool::SendAgain() sendto (ip = {}, port = {}, PacketNum = {}, SliceCurrIndex = {}, SliceSize = {}, sendlen = {})",
//                        inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), UdpSliceHeader.uPacketNum, UdpSliceHeader.uSliceCurrIndex, needSendLen, sendlen);
//                    if (sendlen != needSendLen) {
//#ifdef WIN32
//                        g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, SliceSize = {}, sendlen = {}, SliceCurrIndex = {})",
//                            WSAGetLastError(), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), UdpSliceHeader.uPacketNum, needSendLen, sendlen, UdpSliceHeader.uSliceCurrIndex);
//#else
//                        g_daily_logger->error("Udp sendto failed! [{}] (ip = {}, port = {}, PacketNum = {}, SliceSize = {}, sendlen = {}, SliceCurrIndex = {})",
//                            strerror(errno), inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), UdpSliceHeader.uPacketNum, needSendLen, sendlen, UdpSliceHeader.uSliceCurrIndex);
//#endif
//                        break;
//                    }
//
//                    TmpCount++;
//                    currentSliceIndex++;
//
//                    //
//                    if ((TmpCount != 0) && (TmpCount % 100 == 0))
//                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
//
//                }
//
//                uint64_t intervaltime = TmpCount * MAX_INTERVAL_TIME;
//                nowTime = getTimeStamp();
//                t->NextSendTime = nowTime + intervaltime;
//                t->RetryTimes++;
            }

            if (false == m_retryList.push(std::forward<T_PUDPNODE>(t))) {
                g_daily_logger->error("UdpThreadPool::sendAgain() m_retryList.push() failed!");
                cout << "UdpThreadPool::sendAgain() m_retryList.push() failed!" << endl;
            }

            TmpCount++;

            //
            if ((TmpCount != 0) && (TmpCount % 100 == 0)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                TmpCount = 0;
            }
        }

        sendlist.clear();
    }
}

void UdpThreadPool::RecvData()
{
    fd_set fd;
    int selectRet = 0;
    int recvNum = 0;
    timeval timeout;
    char recvBuf[MAX_BUFFER_SIZE];
    struct sockaddr_in fromAddr;
    int fromLen = sizeof(fromAddr);

    OpenUdpSocket();

    while (!m_isstop) {
        timeout.tv_sec = 10; //
        timeout.tv_usec = 0;

        FD_ZERO(&fd);
        FD_SET(m_listenFd, &fd);

        selectRet = select(m_listenFd + 1, &fd, NULL, NULL, &timeout);
        if (selectRet == 0) {
            //
            continue;
        }
        if (selectRet == -1) {
#ifdef WIN32
            auto err_socket = WSAGetLastError();
            g_daily_logger->error("UdpThreadPool::RecvData() select error: {}", err_socket);
            g_console_logger->error("UdpThreadPool::RecvData() select error: {}", err_socket);
            if (err_socket == WSANOTINITIALISED) {
                WSADATA wsaData;
                WSAStartup(MAKEWORD(2, 2), &wsaData);
            }
            if (err_socket == WSAENOTSOCK || err_socket == WSAENOTCONN ||
                err_socket == WSANOTINITIALISED) {
#else
            g_daily_logger->error("UdpThreadPool::RecvData() select error: [errno {}] {}", errno, strerror(errno));
            g_console_logger->error("UdpThreadPool::RecvData() select error: [errno {}] {}", errno, strerror(errno));
            if (errno == ENOTSOCK || errno == ENOTCONN) {
#endif
                OpenUdpSocket();
            }

            continue;
        }

        memset(recvBuf, 0, MAX_BUFFER_SIZE);
        memset(&fromAddr, 0, sizeof(sockaddr_in));

#ifdef WIN32
        recvNum = recvfrom(this->m_listenFd, recvBuf, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&fromAddr, &fromLen);
#else
        recvNum = recvfrom(this->m_listenFd, recvBuf, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&fromAddr, (socklen_t*)&fromLen);
#endif
        g_daily_logger->info("UdpThreadPool::RecvData(), recv data len ({})", recvNum);
        if (recvNum == -1) {
#ifdef WIN32
            g_daily_logger->error("UdpThreadPool::RecvData() recvfrom() error: {}", WSAGetLastError());
            if (WSAGetLastError() == WSAENOTSOCK || WSAGetLastError() == WSAENOTCONN) {
#else
            g_daily_logger->error("UdpThreadPool::RecvData() recvfrom() error: [errno {}] {}", errno, strerror(errno));
            if (errno == ENOTSOCK || errno == ENOTCONN) {
#endif
                OpenUdpSocket();
            }

            continue;
        }
        else if (recvNum == 0) {
            g_daily_logger->debug("UdpThreadPool::RecvData() recvfrom() recvNum = 0");
            continue;
        }

        T_RECVNODE RecvNode;
        RecvNode.fromAddr = fromAddr;
        RecvNode.recvNum = recvNum;
        memcpy(RecvNode.recvbuf, recvBuf, recvNum);

        if (false == m_recvList.push(std::forward<T_RECVNODE>(RecvNode))) {
            g_daily_logger->error("UdpThreadPool::RecvData() m_recvList.push() failed! m_recvList.size={}", m_recvList.size());
            cout << "UdpThreadPool::RecvData() m_recvList.push() failed! m_recvList.size=" << m_recvList.size() << endl;
        }
    }

    CloseUdpSocket();
}

void print_test_data(const char* ip, uint32_t port, uint32_t uPacketNum, const char *buf, size_t len)
{
    g_rotating_logger->info("udprecvhandler->put(IP = {}, port = {}, PacketNum = {}, len = {})", ip, port, uPacketNum, len);
    return;
}

void UdpThreadPool::Recv()
{
    bool bret;
    UdpRecvDataHandler *udprecvhandler = Singleton<UdpRecvDataHandler>::getInstance();
    char *recvBuf = NULL;
    int fromLen = 0;
    uint32_t uiCrc = 0;

    list<T_RECVNODE> recvlist;
    char *dataBuf = NULL;
    char *sliceBuf = NULL;
    uint32_t fromPort;
    string fromIp;

    while (!m_isstop)
    {
        m_recvList.pop(recvlist, 50);
        for (auto &t : recvlist)
        {
            fromLen = sizeof(t.fromAddr);
            fromIp = inet_ntoa(t.fromAddr.sin_addr);
            fromPort = ntohs(t.fromAddr.sin_port);
            recvBuf = t.recvbuf;

            if (recvBuf[0] == PACKET_HEADER) //
            {
                T_PUDPHEADER udpHeader;
                udpHeader = (T_PUDPHEADER)recvBuf;
                dataBuf = recvBuf + UdpHeaderSize;

                if (udpHeader->PacketType == UDP_ACK_PAKTYPE)
                {
                    lock_guard<mutex> lk(m_sendMapLock);
                    ITR_MAP_T_PUDPNODE iter_map = this->m_sendMap.find(udpHeader->uPacketNum);
                    if (iter_map != this->m_sendMap.end())
                        (iter_map->second)->ClearFlag = ACK_FLAG;

                    continue;
                }

                //

                if (udpHeader->uSliceTotalNum <= 1)		//
                {
                    //
                    uiCrc = crc32buf(dataBuf, udpHeader->uBufLen);
                    if (uiCrc != udpHeader->uDataBufCrc) {
                        g_daily_logger->info("UdpThreadPool::Recv() crc wrong, id = {}", udpHeader->uPacketNum);
                        continue;
                    }

                    //
                    udpHeader->PacketType = UDP_ACK_PAKTYPE;

                    int sendlen = sendto(this->m_listenFd, (const char *)udpHeader, UdpHeaderSize, 0, (struct sockaddr*)&(t.fromAddr), fromLen);
                    g_daily_logger->debug("UdpThreadPool::Recv(), send data len ({})", sendlen);

                    if (sendlen != UdpHeaderSize) {
#ifdef WIN32
                        g_daily_logger->error("UdpThreadPool::Recv() send ack pack failed ({})! PacketNum = {}, BufLen = {}, sendlen = {}",
                            WSAGetLastError(), udpHeader->uPacketNum, UdpHeaderSize, sendlen);
#else
                        g_daily_logger->error("UdpThreadPool::Recv() send ack pack failed ({})! PacketNum = {}, BufLen = {}, sendlen = {}",
                            strerror(errno), udpHeader->uPacketNum, UdpHeaderSize, sendlen);
#endif
                    }
                    else
                        g_daily_logger->debug("UdpThreadPool::Recv() send ack pack (PacketNum = {})", udpHeader->uPacketNum);

                    //
                RETRY:
                    bret = udprecvhandler->put(fromIp.c_str(), fromPort, dataBuf, udpHeader->uBufLen);
                    if (bret == false) {
                        g_daily_logger->error("UdpThreadPool::Recv() udprecvhandler->put == false!");
                        if (m_isstop) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        goto RETRY;
                    }

                    print_test_data(fromIp.c_str(), fromPort, udpHeader->uPacketNum, dataBuf, udpHeader->uBufLen);

                    continue;
                }

                //
                //
                T_PACKETKEY PacketKey(fromIp, fromPort, udpHeader->uPacketNum);
                T_PACKETNODE PacketNode;
                memcpy(&(PacketNode._udpheader), udpHeader, UdpHeaderSize);
                {
                    lock_guard<mutex> lock(m_packetMapLock);
                    m_packetMap[PacketKey] = PacketNode;
                }

                recvBuf = dataBuf;
            }

            if (recvBuf[0] == SLICE_HEADER)	//
            {
                T_PUDPSLICEHEADER SliceHeader;
                SliceHeader = (T_PUDPSLICEHEADER)recvBuf;
                sliceBuf = recvBuf + UdpSliceHeaderSize;

                if (SliceHeader->SliceType == UDP_ACK_PAKTYPE)
                {
                    lock_guard<mutex> lk(m_sendMapLock);
                    ITR_MAP_T_PUDPNODE iter_map = this->m_sendMap.find(SliceHeader->uPacketNum);
                    if (iter_map != this->m_sendMap.end())
                        slice_ack_resp_add((iter_map->second)->bitmap, SliceHeader->uSliceCurrIndex);

                    continue;
                }

                //
                //
                uiCrc = crc32buf(sliceBuf, SliceHeader->uSliceBufLen);
                if (uiCrc != SliceHeader->uSliceBufCrc) {
                    g_daily_logger->info("UdpThreadPool::Recv() slice crc wrong, id = {}", SliceHeader->uSliceCurrIndex);
                    continue;
                }

                //
                SliceHeader->SliceType = UDP_ACK_PAKTYPE;

                int sendlen = sendto(this->m_listenFd, (const char *)SliceHeader, UdpSliceHeaderSize, 0, (struct sockaddr*)&(t.fromAddr), fromLen);
                g_daily_logger->debug("UdpThreadPool::Recv(), send data len ({})", sendlen);
                if (sendlen != UdpSliceHeaderSize) {
#ifdef WIN32
                    g_daily_logger->error("UdpThreadPool::Recv() send slice ack pack failed ({})! PacketNum = {}, BufLen = {}, sendlen = {}",
                        WSAGetLastError(), SliceHeader->uPacketNum, UdpSliceHeaderSize, sendlen);
#else
                    g_daily_logger->error("UdpThreadPool::Recv() send slice ack pack failed ({})! PacketNum = {}, BufLen = {}, sendlen = {}",
                        strerror(errno), SliceHeader->uPacketNum, UdpSliceHeaderSize, sendlen);
#endif
                }
                else
                    g_daily_logger->debug("UdpThreadPool::Recv() send slice ack pack (SliceId = {})", SliceHeader->uSliceCurrIndex);

                T_UDPSLICENODE UdpSliceNode;
                memcpy(&UdpSliceNode, (T_PUDPSLICENODE)recvBuf, UdpSliceHeaderSize + SliceHeader->uSliceBufLen);

                ITR_MAP_SLICEDATA iter;
                MAP_SLICEDATA tmp_slice_map;
                T_PACKETKEY PacketKey(fromIp, fromPort, SliceHeader->uPacketNum);
                {
                    lock_guard<mutex> lk(m_recvMapLock);
                    m_recvMap[PacketKey].insert(std::make_pair(SliceHeader->uSliceCurrIndex, UdpSliceNode));

                    if (m_recvMap[PacketKey].size() != SliceHeader->uSliceTotalNum)
                        continue;

                    //
                    tmp_slice_map = m_recvMap[PacketKey];
                }
                g_daily_logger->debug("Slice Together: tmp_slice_map.size() = {}", tmp_slice_map.size());

                ITR_MAP_PACKETDATA tit;
                T_PACKETNODE packetNode;
                {
                    lock_guard<mutex> lock(m_packetMapLock);
                    tit = m_packetMap.find(PacketKey);
                    if (tit == m_packetMap.end()) {
                        g_daily_logger->error("ERROR: PacketKey({}, {}, {}) m_packetMap not exist!", fromIp.c_str(), fromPort, SliceHeader->uPacketNum);

                        //
                        lock_guard<mutex> lk(m_recvMapLock);
                        m_recvMap.erase(PacketKey);

                        continue;
                    }
                    packetNode = tit->second;
                }

                string udpDataBuf;
                for (iter = tmp_slice_map.begin(); iter != tmp_slice_map.end(); iter++)
                    udpDataBuf.append((iter->second).SliceBuf, (iter->second).SliceHeader.uSliceBufLen);

                T_PUDPHEADER packetHeader = &(packetNode._udpheader);

                //
                uiCrc = crc32buf((char *)udpDataBuf.c_str(), packetHeader->uBufLen);
                if (uiCrc != packetHeader->uDataBufCrc) {
                    g_daily_logger->info("UdpThreadPool::Recv() crc wrong, id = {}", packetHeader->uPacketNum);
                }
                else {
                    //
                    packetHeader->PacketType = UDP_ACK_PAKTYPE;

                    int sendlen = sendto(this->m_listenFd, (const char *)packetHeader, UdpHeaderSize, 0, (struct sockaddr*)&(t.fromAddr), fromLen);
                    g_daily_logger->debug("UdpThreadPool::Recv(), send data len ({})", sendlen);
                    if (sendlen != UdpHeaderSize) {
#ifdef WIN32
                        g_daily_logger->error("UdpThreadPool::Recv() send ack pack failed ({})! PacketNum = {}, BufLen = {}, sendlen = {}",
                            WSAGetLastError(), packetHeader->uPacketNum, UdpHeaderSize, sendlen);
#else
                        g_daily_logger->error("UdpThreadPool::Recv() send ack pack failed({})! PacketNum = {}, BufLen = {}, sendlen = {}",
                            strerror(errno), packetHeader->uPacketNum, UdpHeaderSize, sendlen);
#endif
                    }
                    else
                        g_daily_logger->debug("UdpThreadPool::Recv() send ack pack (PacketNum = {})", packetHeader->uPacketNum);

                    //
                RETRY2:
                    bret = udprecvhandler->put(fromIp.c_str(), fromPort, udpDataBuf.c_str(), packetHeader->uBufLen);
                    if (bret == false) {
                        g_daily_logger->error("UdpThreadPool::Recv() udprecvhandler->put == false!");
                        if (m_isstop) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        goto RETRY2;
                    }

                    print_test_data(fromIp.c_str(), fromPort, packetHeader->uPacketNum, udpDataBuf.c_str(), packetHeader->uBufLen);
                }

                //
                {
                    lock_guard<mutex> lock(m_packetMapLock);
                    m_packetMap.erase(PacketKey);
                }

                //
                lock_guard<mutex> lk(m_recvMapLock);
                m_recvMap.erase(PacketKey);
            }
        }

        recvlist.clear();
    }

}

void UdpThreadPool::CleanExpiredCache()
{
    list<T_PACKETKEY> pkeylist;

    {
        lock_guard<mutex> lock(m_packetMapLock);
        auto it = m_packetMap.begin();
        for (; it != m_packetMap.end();) {
            if (it->second.isTimeOut()) {
                pkeylist.push_back(it->first);
                //
                m_packetMap.erase(it++);
                continue;
            }

            ++it;
        }
    }

    if (pkeylist.size() == 0)
        return;

    lock_guard<mutex> lk(m_recvMapLock);
    for (auto &t : pkeylist) {
        //
        m_recvMap.erase(t);
    }

}

void UdpThreadPool::CheckExpired()
{
    int num = 0;

    while (!m_isstop) {
        num = 0;
        while (num < 1800 && !m_isstop) {
            //
            std::this_thread::sleep_for(std::chrono::seconds(1));
            ++num;
        }

        CleanExpiredCache();
    }
}