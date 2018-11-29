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
#include "UdpThreadPool.h"
#include "UdpRecvDataHandler.hpp"
#include "../headers/UUFile.h"

uint32_t UdpHeaderSize = sizeof(T_UDPHEADER);
uint32_t UdpSliceHeaderSize = sizeof(T_UDPSLICEHEADER);

UdpThreadPool::UdpThreadPool()
{
	m_packetNum = 0;
	m_localIp = NULL;
	m_localPort = 0;
	m_listenFd = -1;
	m_bUsed = false;

#ifdef WIN32
	WSADATA wsaData;
	WORD sockVersion = MAKEWORD(2, 2);  

	if (WSAStartup(sockVersion, &wsaData) != 0)  
		
	{
		END_THREAD();
		THREAD_EXIT;
	}
#endif

	m_listenFd = socket(AF_INET, SOCK_DGRAM, 0);

#ifdef WIN32
	if (m_listenFd == SOCKET_ERROR || m_listenFd == INVALID_SOCKET)
#else
	if (m_listenFd < 0)
#endif 
	{
		END_THREAD();
		THREAD_EXIT;
	}
}

UdpThreadPool::~UdpThreadPool()
{
	m_packetNum = 0;
	m_localIp = NULL;
	m_localPort = 0;
	if (m_listenFd != -1)
	{
#ifdef WIN32
		closesocket(m_listenFd);
#else
		close(m_listenFd);
#endif
		m_listenFd = -1;
	}

#ifdef WIN32
	WSACleanup(); 
#endif
}

int UdpThreadPool::Init(const char* localIp, uint32_t localPort)
{
	printf("UdpThreadPool::Init IN...\r\n");
	m_localIp = localIp;
	m_localPort = localPort;

	DEFINE_THREAD(thread1);
	BEGIN_THREAD(thread1, SendAgainEntry, this);
	SLEEP(1000); 
	BEGIN_THREAD(thread1, RecvDataEntry, this);
	SLEEP(1000); 
	BEGIN_THREAD(thread1, PushDataEntry, this);

	return 1;
}

void THREAD_API UdpThreadPool::PushDataEntry(void* pParam)
{
	UdpThreadPool* pThis = static_cast<UdpThreadPool*>(pParam);
	if (NULL != pThis)
		pThis->Recv();
}

void THREAD_API UdpThreadPool::RecvDataEntry(void* pParam)
{
	UdpThreadPool* pThis = static_cast<UdpThreadPool*>(pParam);
	if (NULL != pThis)
		pThis->RecvData();
}

void THREAD_API UdpThreadPool::SendAgainEntry(void* pParam)
{
	UdpThreadPool* pThis = static_cast<UdpThreadPool*>(pParam);
	if (NULL != pThis)
		pThis->SendAgain();
}

int UdpThreadPool::send(const string &peerIP, uint32_t peerPort, const char * buffer, size_t len)
{
	this->m_sendListLock.Lock();

	T_UDPHEADER UdpHeader;

	UdpHeader.HeaderType = PACKET_HEADER;
	UdpHeader.Version = CURRENT_VERSION;
	UdpHeader.PacketType = UDP_INIT_PAKTYPE;
	UdpHeader.uPacketNum = m_packetNum;
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
	printf("BufLen = %d, sliceNum = %d, lastSliceSize = %d\r\n", UdpHeader.uBufLen, sliceNum, lastSliceSize);

	UdpHeader.uSliceTotalNum = sliceNum;

	T_PUDPNODE tpUdpNode = new T_UDPNODE;
	struct timeval timeTemp;

	tpUdpNode->Ip = peerIP;
	tpUdpNode->Port = peerPort;
	tpUdpNode->ClearFlag = DEFAULT;
	tpUdpNode->RetryTimes = 0;

	CCommonStruct::gettimeofday_update(&timeTemp);
	uint64_t intervaltime = sliceNum * MAX_INTERVAL_TIME;
	tpUdpNode->NextSendTime = timeTemp.tv_sec * 1000 + timeTemp.tv_usec / 1000 + intervaltime;

	memset(tpUdpNode->bitmap, 0, 128);
	tpUdpNode->UdpHeader = UdpHeader;
	tpUdpNode->DataBuf = new char[len];
	memcpy(tpUdpNode->DataBuf, (char*)buffer, len);

	m_sendList.push_back(tpUdpNode);

	m_sendMapLock.Lock();
	ITR_MAP_T_PUDPNODE iter = m_sendMap.find(m_packetNum);
	if (iter != m_sendMap.end())
	{
		printf("ERROR: m_sendMap [%d] had exist!\r\n", tpUdpNode->UdpHeader.uPacketNum);
	}
	m_sendMap[m_packetNum] = tpUdpNode;

	m_sendMapLock.UnLock();
	
	m_packetNum++;
	this->m_sendListLock.UnLock();

	m_semSendList.signal();

	return 0;
}

void UdpThreadPool::slice_ack_resp_add(char *bitmap, uint16_t id)
{
	uint16_t p = 0;
	uint16_t site_value = 0;

	
	uint16_t bit_list[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };

	p = id / 8;
	site_value = id % 8;

	printf("slice_ack_resp_add(), id = %d, bitmap = %0x\r\n", id, bitmap[p]);
	bitmap[p] = bitmap[p] | bit_list[site_value];
	printf("slice_ack_resp_add(), p = %d, site_value = %d, bitmap = %0x\r\n", p, site_value, bitmap[p]);

}

int UdpThreadPool::slice_ack_resp_check(char *bitmap, uint16_t id)
{
	uint16_t p = 0;
	uint16_t site_value = 0;

	
	uint16_t bit_list[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };

	p = id / 8;
	site_value = id % 8;

	printf("slice_ack_resp_check(), id = %d, bitmap = %0x, bit_list = %d\r\n", id, bitmap[p], bit_list[site_value]);
	printf("slice_ack_resp_check(), bitmap & bit_list = %d\r\n", bitmap[p] & bit_list[site_value]);
	if (bit_list[site_value] == (bitmap[p] & bit_list[site_value])) {
		return 1;
	}
	return 0;
}

void UdpThreadPool::SendAgain()
{
#ifndef WIN32
	pthread_detach(pthread_self());
#endif

	struct timeval tmNow, tmTemp;
	uint32_t sendlen = 0;
	unsigned char frameBuffer[MAX_BUFFER_SIZE];

	while (1)
	{
		this->m_sendListLock.Lock();
		if (this->m_sendList.empty())
		{
			this->m_sendListLock.UnLock();
			m_semSendList.wait();
		}
		else
		{
			this->m_sendListLock.UnLock();
		}

		SLEEP(10);

		ITR_LIST_T_PUDPNODE iter;
		this->m_sendListLock.Lock();
		for (iter = this->m_sendList.begin(); iter != this->m_sendList.end();)
		{
			if ((*iter)->RetryTimes >= MAX_SEND_TIMES || (*iter)->ClearFlag == ACK_FLAG)
			{
				printf("PacketNum = %d, RetryTimes = %d, ClearFlag = %d\r\n", (*iter)->UdpHeader.uPacketNum, (*iter)->RetryTimes, (*iter)->ClearFlag);

				
				ITR_MAP_T_PUDPNODE iter_map;
				this->m_sendMapLock.Lock();
				iter_map = this->m_sendMap.find((*iter)->UdpHeader.uPacketNum);
				if (iter_map != this->m_sendMap.end())
				{
					if (iter_map->second != NULL)
					{
						iter_map->second = NULL;
					}

					this->m_sendMap.erase(iter_map);
				}
				else
				{
					printf("ERROR: not find PacketNum(%d) in m_sendMap!\r\n", (*iter)->UdpHeader.uPacketNum);
				}
				this->m_sendMapLock.UnLock();


				
				if ((*iter)->DataBuf != NULL)
				{
					delete[](*iter)->DataBuf;
					(*iter)->DataBuf = NULL;
				}
				if ((*iter) != NULL)
				{
					delete (*iter);
					(*iter) = NULL;
				}

				iter = this->m_sendList.erase(iter);

				continue;
			}

			CCommonStruct::gettimeofday_update(&tmNow);
			uint64_t nowTime = (tmNow.tv_sec) * 1000 + (tmNow.tv_usec) / 1000;
			if (((*iter)->RetryTimes == 0) || (nowTime > (*iter)->NextSendTime))
			{
				printf("PacketNum = %d, RetryTimes = %d, sliceTotalNum = %ld\r\n", (*iter)->UdpHeader.uPacketNum, (*iter)->RetryTimes, (*iter)->UdpHeader.uSliceTotalNum);

				struct sockaddr_in serverAdd;
				memset(&serverAdd, 0, sizeof(serverAdd));
				serverAdd.sin_family = AF_INET;
				serverAdd.sin_addr.s_addr = inet_addr((*iter)->Ip.c_str());
				serverAdd.sin_port = htons((*iter)->Port);

				
				if ((*iter)->UdpHeader.uSliceTotalNum <= 1)
				{
					memset(frameBuffer, 0, MAX_BUFFER_SIZE);
					memcpy(frameBuffer, &((*iter)->UdpHeader), UdpHeaderSize);
					memcpy(frameBuffer + UdpHeaderSize, (*iter)->DataBuf, (*iter)->UdpHeader.uBufLen);

					uint32_t BufLen = UdpHeaderSize + (*iter)->UdpHeader.uBufLen;

					if (this->m_listenFd == -1)
					{
						printf("(UdpThreadPool::SendAgain) socket fd == -1 \r\n");
						iter++;
						continue;
					}

					sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, BufLen, 0, (struct sockaddr*)&serverAdd, sizeof(serverAdd));
					printf("send data len (%d)\r\n", sendlen);
					if (sendlen != BufLen)
					{
						printf("Udp sendto failed (%s)! PacketNum = %d, BufLen = %d, sendlen = %d\r\n",
							strerror(errno), (*iter)->UdpHeader.uPacketNum, BufLen, sendlen);
						iter++;
						continue;
					}

					CCommonStruct::gettimeofday_update(&tmTemp);
					(*iter)->NextSendTime = tmTemp.tv_sec * 1000 + tmTemp.tv_usec / 1000 + MAX_INTERVAL_TIME;
					(*iter)->RetryTimes++;

					this->m_sendList.push_back(*iter);
					iter = this->m_sendList.erase(iter);

					continue;
				}

				
				uint32_t currentSliceIndex = 0;
				uint32_t needSendLen = 0;
				uint32_t sliceNum = (*iter)->UdpHeader.uSliceTotalNum;
				T_UDPSLICEHEADER UdpSliceHeader;

				UdpSliceHeader.HeaderType = SLICE_HEADER;
				UdpSliceHeader.SliceType = UDP_INIT_PAKTYPE;
				UdpSliceHeader.uPacketNum = (*iter)->UdpHeader.uPacketNum;
				UdpSliceHeader.uSliceTotalNum = sliceNum;

				if ((*iter)->RetryTimes == 0)
				{
					while (currentSliceIndex < sliceNum)
					{
						if (currentSliceIndex < (sliceNum - 1))
						{
							UdpSliceHeader.uSliceBufLen = UDP_SLICE_MAX_SIZE;
							UdpSliceHeader.uSliceCurrIndex = currentSliceIndex + 1;
							UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

							char *tmp_buf = new char[UDP_SLICE_MAX_SIZE];
							memcpy(tmp_buf, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
							UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, UDP_SLICE_MAX_SIZE);
							delete[]tmp_buf;

							if (currentSliceIndex == 0)
							{
								memset(frameBuffer, 0, MAX_BUFFER_SIZE);
								memcpy(frameBuffer, &((*iter)->UdpHeader), UdpHeaderSize);
								memcpy(frameBuffer + UdpHeaderSize, &UdpSliceHeader, UdpSliceHeaderSize);
								memcpy(frameBuffer + UdpHeaderSize + UdpSliceHeaderSize, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
								needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize + UdpHeaderSize;
							}
							else
							{
								memset(frameBuffer, 0, MAX_BUFFER_SIZE);
								memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
								memcpy(frameBuffer + UdpSliceHeaderSize, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
								needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
							}

						}
						else
						{
							int tmp_len = (*iter)->UdpHeader.uBufLen - currentSliceIndex*UDP_SLICE_MAX_SIZE;
							UdpSliceHeader.uSliceBufLen = tmp_len;
							UdpSliceHeader.uSliceCurrIndex = currentSliceIndex + 1;
							UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

							char *tmp_buf = new char[tmp_len];
							memcpy(tmp_buf, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
							UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, tmp_len);
							delete[]tmp_buf;

							memset(frameBuffer, 0, MAX_BUFFER_SIZE);
							memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
							memcpy(frameBuffer + UdpSliceHeaderSize, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
							needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
						}

						if (this->m_listenFd == -1)
						{
							printf("(UdpThreadPool::SendAgain) socket fd == -1 \r\n");
							continue;
						}

						sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, needSendLen, 0, (struct sockaddr*)&serverAdd, sizeof(serverAdd));
						printf("send data len (%d)\r\n", sendlen);
						if (sendlen != needSendLen)
						{
							printf("Udp sendto Failed (%s)! PacketNum = %d, SliceSize = %d, sendlen = %d, SliceCurrIndex = %d\r\n",
								strerror(errno), UdpSliceHeader.uPacketNum, needSendLen, sendlen, UdpSliceHeader.uSliceCurrIndex);
							continue;
						}
						currentSliceIndex++;
						SLEEP(10);

					}

					

					CCommonStruct::gettimeofday_update(&tmTemp);
					uint64_t intervaltime = (*iter)->UdpHeader.uSliceTotalNum * MAX_INTERVAL_TIME;
					(*iter)->NextSendTime = tmTemp.tv_sec * 1000 + tmTemp.tv_usec / 1000 + intervaltime;
					(*iter)->RetryTimes++;

					this->m_sendList.push_back(*iter);
					iter = this->m_sendList.erase(iter);

					continue;
				}

				
				printf("SendAgain() (*iter)->RetryTimes = %d, (*iter)->bitmap = %0x\r\n", (*iter)->RetryTimes, (*iter)->bitmap[0]);
				uint32_t TmpCount = 0;
				while (currentSliceIndex < sliceNum)
				{
					int ret = slice_ack_resp_check((*iter)->bitmap, currentSliceIndex + 1);
					if (ret == 0)
					{
						printf("SendAgain() slice_ack_resp_check (currentSliceIndex = %d)\r\n", currentSliceIndex + 1);
						if (currentSliceIndex < (sliceNum - 1))
						{
							UdpSliceHeader.uSliceBufLen = UDP_SLICE_MAX_SIZE;
							UdpSliceHeader.uSliceCurrIndex = currentSliceIndex + 1;
							UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

							char *tmp_buf = new char[UDP_SLICE_MAX_SIZE];
							memcpy(tmp_buf, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
							UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, UDP_SLICE_MAX_SIZE);
							delete[]tmp_buf;

							if (currentSliceIndex == 0)
							{
								memset(frameBuffer, 0, MAX_BUFFER_SIZE);
								memcpy(frameBuffer, &((*iter)->UdpHeader), UdpHeaderSize);
								memcpy(frameBuffer + UdpHeaderSize, &UdpSliceHeader, UdpSliceHeaderSize);
								memcpy(frameBuffer + UdpHeaderSize + UdpSliceHeaderSize, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
								needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize + UdpHeaderSize;
							}
							else
							{
								memset(frameBuffer, 0, MAX_BUFFER_SIZE);
								memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
								memcpy(frameBuffer + UdpSliceHeaderSize, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
								needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
							}

						}
						else
						{
							int tmp_len = (*iter)->UdpHeader.uBufLen - currentSliceIndex*UDP_SLICE_MAX_SIZE;
							UdpSliceHeader.uSliceBufLen = tmp_len;
							UdpSliceHeader.uSliceCurrIndex = currentSliceIndex + 1;
							UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

							char *tmp_buf = new char[tmp_len];
							memcpy(tmp_buf, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
							UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, tmp_len);
							delete[]tmp_buf;

							memset(frameBuffer, 0, MAX_BUFFER_SIZE);
							memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
							memcpy(frameBuffer + UdpSliceHeaderSize, (*iter)->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
							needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
						}

						if (this->m_listenFd == -1)
						{
							printf("(CUdpSocket::SendAgain) socket fd == -1 \r\n");
							continue;
						}

						sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, needSendLen, 0, (struct sockaddr*)&serverAdd, sizeof(serverAdd));
						printf("send data len (%d)\r\n", sendlen);
						if (sendlen != needSendLen)
						{
							printf("Udp sendto Failed (%s)! PacketNum = %d, SliceSize = %d, sendlen = %d, SliceCurrIndex = %d\r\n",
								strerror(errno), UdpSliceHeader.uPacketNum, needSendLen, sendlen, UdpSliceHeader.uSliceCurrIndex);
							continue;
						}
						TmpCount++;
						SLEEP(10);
					}

					currentSliceIndex++;
				}

				CCommonStruct::gettimeofday_update(&tmTemp);
				uint64_t intervaltime = TmpCount * MAX_INTERVAL_TIME;
				(*iter)->NextSendTime = tmTemp.tv_sec * 1000 + tmTemp.tv_usec / 1000 + intervaltime;
				(*iter)->RetryTimes++;

				this->m_sendList.push_back(*iter);
				iter = this->m_sendList.erase(iter);

				continue;
			}
			else
			{
				break;
			}
		}

		this->m_sendListLock.UnLock();
	}

}

uint64_t out_len = 0;
char out_buf[2097153]; 

void UdpThreadPool::RecvData()
{
#ifndef WIN32
	pthread_detach(pthread_self());
#endif

	char recvBuf[MAX_BUFFER_SIZE];
	int bufsize = MAX_BUFFER_SIZE;
	int ret = 0;

	

	ret = setsockopt(this->m_listenFd, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
	if (ret == -1)
	{
		printf("ufd_listener setsockopt SO_RCVBUF error!\r\n");
		END_THREAD();
		THREAD_EXIT;
		
	}

	struct sockaddr_in my_addr;
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;

	if (this->m_localIp == NULL || strlen(this->m_localIp) == 0)
		my_addr.sin_addr.s_addr = INADDR_ANY;
	else
		my_addr.sin_addr.s_addr = inet_addr(this->m_localIp);

	my_addr.sin_port = htons(this->m_localPort);
	ret = ::bind(this->m_listenFd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
	if (ret == SOCKET_ERROR)
	{
		printf("ufd_listener bind error!\r\n");
		END_THREAD();
		THREAD_EXIT;
		
	}

	fd_set fd;
	int selectRet = 0;
	int recvNum = 0;

	timeval timeout;
	timeout.tv_sec = 100; 
	timeout.tv_usec = 0;

	bool throwFlag = false;
	
	uint32_t testID = 3;

	while (1)
	{
		FD_ZERO(&fd);
		FD_SET(this->m_listenFd, &fd);

		selectRet = select(this->m_listenFd + 1, &fd, NULL, NULL, &timeout);
		if (selectRet == SOCKET_ERROR)
		{
			printf("Recv select error(%s)", strerror(errno));
			break;
		}

		if (selectRet == 0)
		{
			printf("select() timeout!\r\n");
			continue;
		}

		struct sockaddr_in fromAddr;
		memset(&fromAddr, 0, sizeof(sockaddr_in));
		int fromLen = sizeof(fromAddr);

		memset(recvBuf, 0, MAX_BUFFER_SIZE);

#ifdef WIN32
		recvNum = recvfrom(this->m_listenFd, recvBuf, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&fromAddr, &fromLen);
#else
		recvNum = recvfrom(this->m_listenFd, recvBuf, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&fromAddr, (socklen_t*)&fromLen);
#endif
		printf("recv data len (%d)\r\n", recvNum);
		if (recvNum == -1)
		{
			printf("recv data error(%s) %d\r\n", strerror(errno), errno);
			continue;
		}
		else if (recvNum == 0)
		{
			printf("recvNum = 0 (%s)\r\n", strerror(errno));
			continue;
		}

		if (recvBuf[0] == PACKET_HEADER)
		{
			if (((T_PUDPHEADER)recvBuf)->PacketType == UDP_INIT_PAKTYPE)
			{
				this->m_recvListLock.Lock();
				unsigned short usRecvNum = this->m_recvList.size();
				this->m_recvListLock.UnLock();
				if (usRecvNum > MAX_RECV_LIST_COUNT)
				{
					printf("(UdpThreadPool::RecvData) recv list count more than MAX_RECV_LIST_COUNT, ignore\r\n");
					continue;
				}

				
				if (((T_PUDPHEADER)recvBuf)->uSliceTotalNum <= 1)
				{
					
					uint32_t uiCrc = crc32buf((recvBuf + UdpHeaderSize), ((T_PUDPHEADER)recvBuf)->uBufLen);
					if (uiCrc != ((T_PUDPHEADER)recvBuf)->uDataBufCrc)
					{
						printf("(UdpThreadPool::RecvData) crc wrong\r\n");
						continue;
					}

					
					T_UDPHEADER ackHeader;
					memcpy(&ackHeader, (T_PUDPHEADER)recvBuf, UdpHeaderSize);
					ackHeader.PacketType = UDP_ACK_PAKTYPE;
					ackHeader.uDataBufCrc = 0;

					int sendlen = sendto(this->m_listenFd, (const char *)(&ackHeader), UdpHeaderSize, 0, (struct sockaddr*)&fromAddr, fromLen);
					printf("send data len (%d)\r\n", sendlen);
					if (sendlen != UdpHeaderSize)
					{
						printf("(UdpThreadPool::RecvData) send ack pack failed (%s)! PacketNum = %d, BufLen = %d, sendlen = %d\r\n",
							strerror(errno), ackHeader.uPacketNum, UdpHeaderSize, sendlen);
					}
					else
					{
						printf("(UdpThreadPool::RecvData) send ack pack (PacketNum = %d)\r\n", ackHeader.uPacketNum);
					}

					T_UDPNODE UdpNode;
					UdpNode.Ip = inet_ntoa(fromAddr.sin_addr);
					UdpNode.Port = ntohs(fromAddr.sin_port);
					memcpy(&(UdpNode.UdpHeader), (T_PUDPHEADER)recvBuf, UdpHeaderSize);
					UdpNode.DataBuf = new char[UdpNode.UdpHeader.uBufLen];
					memcpy(UdpNode.DataBuf, (char*)((T_UDPHEADER*)recvBuf + 1), UdpNode.UdpHeader.uBufLen);

					
					this->m_recvListLock.Lock();
					this->m_recvList.push_back(UdpNode);
					this->m_recvListLock.UnLock();
					this->m_semRecvList.signal();


	

					continue;
				}

				
				uint32_t uiCrc = crc32buf((recvBuf + UdpHeaderSize + UdpSliceHeaderSize), ((T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize))->uSliceBufLen);
				if (uiCrc != ((T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize))->uSliceBufCrc)
				{
					printf("(CUdpSocket::RecvData) slice crc wrong\r\n");
					continue;
				}

				
				T_UDPSLICEHEADER SliceAckHeader;
				memcpy(&SliceAckHeader, (T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize), UdpSliceHeaderSize);
				SliceAckHeader.SliceType = UDP_ACK_PAKTYPE;
				SliceAckHeader.uSliceBufCrc = 0;

				int sendlen = sendto(this->m_listenFd, (const char *)(&SliceAckHeader), UdpSliceHeaderSize, 0, (struct sockaddr*)&fromAddr, fromLen);
				printf("send data len (%d)\r\n", sendlen);
				if (sendlen != UdpSliceHeaderSize)
				{
					printf("(CUdpSocket::RecvData) send slice ack pack failed (%s)! PacketNum = %d, BufLen = %d, sendlen = %d\r\n",
						strerror(errno), SliceAckHeader.uPacketNum, UdpSliceHeaderSize, sendlen);
				}
				else
				{
					printf("(CUdpSocket::RecvData) send slice ack pack (PacketNum = %d)\r\n", SliceAckHeader.uPacketNum);
				}

				T_UDPNODE UdpNode;
				UdpNode.Ip = inet_ntoa(fromAddr.sin_addr);
				UdpNode.Port = ntohs(fromAddr.sin_port);
				memcpy(&(UdpNode.UdpHeader), (T_PUDPHEADER)recvBuf, UdpHeaderSize);

				T_PACKETKEY PacketKey(UdpNode.Ip, UdpNode.Port, UdpNode.UdpHeader.uPacketNum);
				m_packetMapLock.Lock();
				m_packetMap[PacketKey] = UdpNode;
				m_packetMapLock.UnLock();

				T_UDPSLICENODE UdpSliceNode;
				memcpy(&(UdpSliceNode.SliceHeader), (T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize), UdpSliceHeaderSize);
				UdpSliceNode.SliceBuf = new char[UdpSliceNode.SliceHeader.uSliceBufLen];
				memcpy(UdpSliceNode.SliceBuf, (char*)(recvBuf + UdpHeaderSize + UdpSliceHeaderSize), UdpSliceNode.SliceHeader.uSliceBufLen);

				ITR_MAP_SLICEDATA iter;
				MAP_SLICEDATA tmp_slice_map;
				ITR_MULTI_MAP_PACKETDATA it = m_recvMap.find(PacketKey);
				if (it != m_recvMap.end())
				{
					tmp_slice_map = it->second;
					iter = tmp_slice_map.find(UdpSliceNode.SliceHeader.uSliceCurrIndex);
					if (iter != tmp_slice_map.end())
					{
						printf("ERROR: (%d) map_slice [%d] had exist!\r\n", UdpSliceNode.SliceHeader.uPacketNum, UdpSliceNode.SliceHeader.uSliceCurrIndex);
					}
				}

				tmp_slice_map[UdpSliceNode.SliceHeader.uSliceCurrIndex] = UdpSliceNode;
				m_recvMapLock.Lock();
				m_recvMap[PacketKey] = tmp_slice_map;
				m_recvMapLock.UnLock();
				printf("tmp_slice_map.size() = %d\r\n", tmp_slice_map.size());

		
				if (tmp_slice_map.size() == UdpSliceNode.SliceHeader.uSliceTotalNum)
				{
					printf("Slice Together: tmp_slice_map.size() = %d\r\n", tmp_slice_map.size());
					ITR_MAP_PACKETDATA tit = m_packetMap.find(PacketKey);
					if (tit == m_packetMap.end())
					{
						printf("ERROR: PacketKey(%s, %d, %d) m_packetMap not exist!\r\n", UdpNode.Ip.c_str(), UdpNode.Port, UdpNode.UdpHeader.uPacketNum);
					}
					else
					{
						T_UDPNODE UdpNode = tit->second;
						UdpNode.DataBuf = new char[UdpNode.UdpHeader.uBufLen];

						for (iter = tmp_slice_map.begin(); iter != tmp_slice_map.end(); iter++)
						{
							T_UDPSLICENODE SliceNode = iter->second;
							memcpy(UdpNode.DataBuf + SliceNode.SliceHeader.uSliceDataOffset, SliceNode.SliceBuf, SliceNode.SliceHeader.uSliceBufLen);
						}

						
						uint32_t uiCrc = crc32buf(UdpNode.DataBuf, UdpNode.UdpHeader.uBufLen);
						if (uiCrc != UdpNode.UdpHeader.uDataBufCrc)
						{
							printf("(UdpThreadPool::RecvData) crc wrong\r\n");
							delete[] UdpNode.DataBuf;
						}
						else
						{
							
							T_UDPHEADER ackHeader;
							memcpy(&ackHeader, &(UdpNode.UdpHeader), UdpHeaderSize);
							ackHeader.PacketType = UDP_ACK_PAKTYPE;
							ackHeader.uDataBufCrc = 0;

							int sendlen = sendto(this->m_listenFd, (const char *)(&ackHeader), UdpHeaderSize, 0, (struct sockaddr*)&fromAddr, fromLen);
							printf("send data len (%d)\r\n", sendlen);
							if (sendlen != UdpHeaderSize)
							{
								printf("(UdpThreadPool::RecvData) send ack pack failed (%s)! PacketNum = %d, BufLen = %d, sendlen = %d\r\n",
									strerror(errno), ackHeader.uPacketNum, UdpHeaderSize, sendlen);
							}
							else
							{
								printf("(UdpThreadPool::RecvData) send ack pack (PacketNum = %d)\r\n", ackHeader.uPacketNum);
							}

							
							this->m_recvListLock.Lock();
							this->m_recvList.push_back(UdpNode);
							this->m_recvListLock.UnLock();
							this->m_semRecvList.signal();

						
						}

						
						m_packetMapLock.Lock();
						m_packetMap.erase(tit);
						m_packetMapLock.UnLock();


						
						for (iter = tmp_slice_map.begin(); iter != tmp_slice_map.end(); iter++)
						{
							if (iter->second.SliceBuf != NULL)
							{
								delete[]iter->second.SliceBuf;
								iter->second.SliceBuf = NULL;
							}
						}
						tmp_slice_map.clear();

						
						m_recvMapLock.Lock();
						m_recvMap.erase(it);
						m_recvMapLock.UnLock();
					}
				}

				
			}
			else if (((T_PUDPHEADER)recvBuf)->PacketType == UDP_ACK_PAKTYPE)
			{
				this->m_sendMapLock.Lock();
				ITR_MAP_T_PUDPNODE iter_map;
				iter_map = this->m_sendMap.find(((T_PUDPHEADER)recvBuf)->uPacketNum);
				if (iter_map != this->m_sendMap.end())
				{
					(iter_map->second)->ClearFlag = ACK_FLAG;
				}
				this->m_sendMapLock.UnLock();
			}
		}
		else 
		{
			if (((T_PUDPSLICEHEADER)recvBuf)->SliceType == UDP_INIT_PAKTYPE)
			{
				if (throwFlag == true && testID == ((T_PUDPSLICEHEADER)recvBuf)->uSliceCurrIndex)
				{
					printf("(CUdpSocket::RecvData) testID = %d throw away!\r\n", testID);
					throwFlag = false;
					continue;
				}

				
				uint32_t uiCrc = crc32buf((recvBuf + UdpSliceHeaderSize), ((T_PUDPSLICEHEADER)recvBuf)->uSliceBufLen);
				if (uiCrc != ((T_PUDPSLICEHEADER)recvBuf)->uSliceBufCrc)
				{
					printf("(CUdpSocket::RecvData) slice crc wrong\r\n");
					continue;
				}

				
				T_UDPSLICEHEADER SliceAckHeader;
				memcpy(&SliceAckHeader, (T_PUDPSLICEHEADER)recvBuf, UdpSliceHeaderSize);
				SliceAckHeader.SliceType = UDP_ACK_PAKTYPE;
				SliceAckHeader.uSliceBufCrc = 0;

				int sendlen = sendto(this->m_listenFd, (const char *)(&SliceAckHeader), UdpSliceHeaderSize, 0, (struct sockaddr*)&fromAddr, fromLen);
				printf("send data len (%d)\r\n", sendlen);
				if (sendlen != UdpSliceHeaderSize)
				{
					printf("(CUdpSocket::RecvData) send slice ack pack failed (%s)! PacketNum = %d, BufLen = %d, sendlen = %d\r\n",
						strerror(errno), SliceAckHeader.uPacketNum, UdpSliceHeaderSize, sendlen);
				}
				else
				{
					printf("(CUdpSocket::RecvData) send slice ack pack (PacketNum = %d)\r\n", SliceAckHeader.uPacketNum);
				}

				string fromIp = inet_ntoa(fromAddr.sin_addr);
				uint32_t fromPort = ntohs(fromAddr.sin_port);

				T_UDPSLICENODE UdpSliceNode;
				memcpy(&(UdpSliceNode.SliceHeader), (T_PUDPSLICEHEADER)recvBuf, UdpSliceHeaderSize);
				UdpSliceNode.SliceBuf = new char[UdpSliceNode.SliceHeader.uSliceBufLen];
				memcpy(UdpSliceNode.SliceBuf, (char*)(recvBuf + UdpSliceHeaderSize), UdpSliceNode.SliceHeader.uSliceBufLen);

				T_PACKETKEY PacketKey(fromIp, fromPort, UdpSliceNode.SliceHeader.uPacketNum);

				ITR_MAP_SLICEDATA iter;
				MAP_SLICEDATA tmp_slice_map;
				ITR_MULTI_MAP_PACKETDATA it = m_recvMap.find(PacketKey);
				if (it != m_recvMap.end())
				{
					tmp_slice_map = it->second;
					iter = tmp_slice_map.find(UdpSliceNode.SliceHeader.uSliceCurrIndex);
					if (iter != tmp_slice_map.end())
					{
						printf("ERROR: (%d) map_slice [%d] had exist!\r\n", UdpSliceNode.SliceHeader.uPacketNum, UdpSliceNode.SliceHeader.uSliceCurrIndex);
					}
				}

				tmp_slice_map[UdpSliceNode.SliceHeader.uSliceCurrIndex] = UdpSliceNode;
				m_recvMapLock.Lock();
				m_recvMap[PacketKey] = tmp_slice_map;
				m_recvMapLock.UnLock();
				printf("tmp_slice_map.size() = %d\r\n", tmp_slice_map.size());

				
				if (tmp_slice_map.size() == UdpSliceNode.SliceHeader.uSliceTotalNum)
				{
					printf("Slice Together: tmp_slice_map.size() = %d\r\n", tmp_slice_map.size());
					ITR_MAP_PACKETDATA tit = m_packetMap.find(PacketKey);
					if (tit == m_packetMap.end())
					{
						printf("ERROR: PacketKey(%s, %d, %d) m_packetMap not exist!\r\n", fromIp.c_str(), fromPort, UdpSliceNode.SliceHeader.uPacketNum);
					}
					else
					{
						T_UDPNODE UdpNode = tit->second;
						UdpNode.DataBuf = new char[UdpNode.UdpHeader.uBufLen];

						for (iter = tmp_slice_map.begin(); iter != tmp_slice_map.end(); iter++)
						{
							T_UDPSLICENODE SliceNode = iter->second;
							uint32_t offset = SliceNode.SliceHeader.uSliceDataOffset;
							memcpy(UdpNode.DataBuf + SliceNode.SliceHeader.uSliceDataOffset, SliceNode.SliceBuf, SliceNode.SliceHeader.uSliceBufLen);
						}

						
						uint32_t uiCrc = crc32buf(UdpNode.DataBuf, UdpNode.UdpHeader.uBufLen);
						if (uiCrc != UdpNode.UdpHeader.uDataBufCrc)
						{
							printf("(UdpThreadPool::RecvData) crc wrong\r\n");
							delete[] UdpNode.DataBuf;
						}
						else
						{
							
							T_UDPHEADER ackHeader;
							memcpy(&ackHeader, &(UdpNode.UdpHeader), UdpHeaderSize);
							ackHeader.PacketType = UDP_ACK_PAKTYPE;
							ackHeader.uDataBufCrc = 0;

							int sendlen = sendto(this->m_listenFd, (const char *)(&ackHeader), UdpHeaderSize, 0, (struct sockaddr*)&fromAddr, fromLen);
							printf("send data len (%d)\r\n", sendlen);
							if (sendlen != UdpHeaderSize)
							{
								printf("(UdpThreadPool::RecvData) send ack pack failed (%s)! PacketNum = %d, BufLen = %d, sendlen = %d\r\n",
									strerror(errno), ackHeader.uPacketNum, UdpHeaderSize, sendlen);
							}
							else
							{
								printf("(UdpThreadPool::RecvData) send ack pack (PacketNum = %d)\r\n", ackHeader.uPacketNum);
							}

							
							this->m_recvListLock.Lock();
							this->m_recvList.push_back(UdpNode);
							this->m_recvListLock.UnLock();
							this->m_semRecvList.signal();

							
						}

						
						m_packetMapLock.Lock();
						m_packetMap.erase(tit);
						m_packetMapLock.UnLock();

						
						for (iter = tmp_slice_map.begin(); iter != tmp_slice_map.end(); iter++)
						{
							if (iter->second.SliceBuf != NULL)
							{
								delete[]iter->second.SliceBuf;
								iter->second.SliceBuf = NULL;
							}
						}
						tmp_slice_map.clear();

						
						m_recvMapLock.Lock();
						m_recvMap.erase(it);
						m_recvMapLock.UnLock();
					}
				}
			}
			else if (((T_PUDPSLICEHEADER)recvBuf)->SliceType == UDP_ACK_PAKTYPE)
			{
				this->m_sendMapLock.Lock();
				ITR_MAP_T_PUDPNODE iter_map;
				iter_map = this->m_sendMap.find(((T_PUDPSLICEHEADER)recvBuf)->uPacketNum);
				if (iter_map != this->m_sendMap.end())
				{
					slice_ack_resp_add((iter_map->second)->bitmap, ((T_PUDPSLICEHEADER)recvBuf)->uSliceCurrIndex);
				}
				this->m_sendMapLock.UnLock();
			}
		}
	}
}

void UdpThreadPool::Recv()
{
	bool bret;
	UdpRecvDataHandler *udprecvhandler = Singleton<UdpRecvDataHandler>::getInstance();
	while (true)
	{
		m_recvListLock.Lock();
		if (m_recvList.empty())
		{
			m_recvListLock.UnLock();
			m_semRecvList.wait();
		}

		ITR_LIST_T_UDPNODE iter;
		
		m_recvListLock.Lock();
		
		for (iter = m_recvList.begin(); iter != m_recvList.end();)
		{
			RETRY:
			bret = udprecvhandler->put(iter->Ip.c_str(), iter->Port, iter->DataBuf, iter->UdpHeader.uBufLen);
			if (bret == false)
			{
				printf("udprecvhandler->put == false!\r\n");
				goto RETRY;
			}

			

			if (iter->DataBuf != NULL)
			{
				delete[] iter->DataBuf;
				iter->DataBuf = NULL;
			}

			iter = m_recvList.erase(iter);
		}

		m_recvListLock.UnLock();

	}
}

