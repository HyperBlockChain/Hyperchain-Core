/*Copyright 2016-2018 hyperchain.net (Hyperchain)

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

#include "UdpThreadPool.h"
#include "UdpRecvDataHandler.hpp"

uint32_t UdpHeaderSize = sizeof(T_UDPHEADER);
uint32_t UdpSliceHeaderSize = sizeof(T_UDPSLICEHEADER);

UdpThreadPool::UdpThreadPool(const char* localIp, uint32_t localPort, uint32_t numthreads, uint32_t maxnumtasks) :
	m_sendList(maxnumtasks), m_recvList(maxnumtasks)/*, m_recvTmpList(maxnumtasks)*/
{
	m_isstop = false;
	m_packetNum = 0;
	m_listenFd = -1;
	m_localIp = localIp;
	m_localPort = localPort;
	m_recvthreads_num = numthreads;


#ifdef WIN32
	WSADATA wsaData;
	WORD sockVersion = MAKEWORD(2, 2); 

	if (WSAStartup(sockVersion, &wsaData) != 0)  
	{
		
		return;
	}
#endif


	m_listenFd = socket(AF_INET, SOCK_DGRAM, 0);

#ifdef WIN32
	if (m_listenFd == SOCKET_ERROR || m_listenFd == INVALID_SOCKET)
#else
	if (m_listenFd < 0)
#endif 
	{
#ifdef WIN32
		
#else
		
#endif
		return;
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

void UdpThreadPool::start()
{
	

	listen_thread = thread(&UdpThreadPool::RecvData, this);
	
	send_thread = thread(&UdpThreadPool::SendAgain, this);
	

	for (size_t i = 0; i < m_recvthreads_num; i++) {
		m_recvthreads.push_back(thread(&UdpThreadPool::Recv, this));
	}
}

void UdpThreadPool::stop()
{
	m_sendList.stop();
	m_recvList.stop();
	
	m_isstop = true;

	send_thread.join();
	listen_thread.join();

	for (auto& t : m_recvthreads) {
		t.join();
	}
	m_recvthreads.clear();
}

std::time_t getTimeStamp()
{
	std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp;
	tp = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
	auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
	std::time_t timestamp = tmp.count();

	return timestamp;
}

int UdpThreadPool::send(const string &peerIP, uint32_t peerPort, const char * buffer, size_t len)
{
	uint32_t tmp_packetNum = 0;

	m_packetNumLock.lock();
	tmp_packetNum = this->m_packetNum;
	this->m_packetNum++;
	m_packetNumLock.unlock();

	T_UDPHEADER UdpHeader;

	UdpHeader.HeaderType = PACKET_HEADER;
	UdpHeader.Version = CURRENT_VERSION;
	UdpHeader.PacketType = UDP_INIT_PAKTYPE;
	UdpHeader.uPacketNum = tmp_packetNum;
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


	UdpHeader.uSliceTotalNum = sliceNum;

	T_PUDPNODE tpUdpNode = new T_UDPNODE;

	std::time_t timeTemp;

	tpUdpNode->Ip = peerIP;
	tpUdpNode->Port = peerPort;
	tpUdpNode->ClearFlag = DEFAULT;
	tpUdpNode->RetryTimes = 0;

	timeTemp = getTimeStamp();
	uint64_t intervaltime = sliceNum * MAX_INTERVAL_TIME;
	tpUdpNode->NextSendTime = timeTemp + intervaltime;

	memset(tpUdpNode->bitmap, 0, 128);
	tpUdpNode->UdpHeader = UdpHeader;
	tpUdpNode->DataBuf = new char[len];
	memcpy(tpUdpNode->DataBuf, (char*)buffer, len);

	bool bret;
	bret = m_sendList.push(std::forward<T_PUDPNODE>(tpUdpNode));
	if (false == bret)

	m_sendMapLock.lock();
	ITR_MAP_T_PUDPNODE iter = m_sendMap.find(tmp_packetNum);
	if (iter != m_sendMap.end())
	{
	}
	m_sendMap[tmp_packetNum] = tpUdpNode;

	m_sendMapLock.unlock();

	return 0;
}

void UdpThreadPool::slice_ack_resp_add(char *bitmap, uint16_t id)
{
	uint16_t p = 0;
	uint16_t site_value = 0;

	uint16_t bit_list[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };

	p = id / 8;
	site_value = id % 8;

	bitmap[p] = bitmap[p] | bit_list[site_value];
}

int UdpThreadPool::slice_ack_resp_check(char *bitmap, uint16_t id)
{
	uint16_t p = 0;
	uint16_t site_value = 0;

	uint16_t bit_list[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };

	p = id / 8;
	site_value = id % 8;

	if (bit_list[site_value] == (bitmap[p] & bit_list[site_value])) {
		return 1;
	}
	return 0;
}

void UdpThreadPool::SendAgain()
{
	bool bret;
	std::time_t nowTime;
	uint32_t sendlen = 0;
	list<T_PUDPNODE> sendlist;
	unsigned char frameBuffer[MAX_BUFFER_SIZE];

	while (!m_isstop)
	{
		m_sendList.pop(sendlist);

		for (auto t : sendlist)
		{
			if (t->RetryTimes >= MAX_SEND_TIMES || t->ClearFlag == ACK_FLAG)
			{

				ITR_MAP_T_PUDPNODE iter_map;
				this->m_sendMapLock.lock();
				iter_map = this->m_sendMap.find(t->UdpHeader.uPacketNum);
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
				}
				this->m_sendMapLock.unlock();


				if (t->DataBuf != NULL)
				{
					delete[]t->DataBuf;
					t->DataBuf = NULL;
				}
				if (t != NULL)
				{
					delete t;
					t = NULL;
				}

				continue;
			}

			nowTime = getTimeStamp();
			if ((t->RetryTimes == 0) || (nowTime > t->NextSendTime))
			{

				struct sockaddr_in serverAdd;
				memset(&serverAdd, 0, sizeof(serverAdd));
				serverAdd.sin_family = AF_INET;
				serverAdd.sin_addr.s_addr = inet_addr(t->Ip.c_str());
				serverAdd.sin_port = htons(t->Port);

				if (t->UdpHeader.uSliceTotalNum <= 1)
				{
					memset(frameBuffer, 0, MAX_BUFFER_SIZE);
					memcpy(frameBuffer, &(t->UdpHeader), UdpHeaderSize);
					memcpy(frameBuffer + UdpHeaderSize, t->DataBuf, t->UdpHeader.uBufLen);

					uint32_t BufLen = UdpHeaderSize + t->UdpHeader.uBufLen;

					if (this->m_listenFd == -1)
					{
						continue;
					}

					sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, BufLen, 0, (struct sockaddr*)&serverAdd, sizeof(serverAdd));
					if (sendlen != BufLen)
					{

						
						continue;
					}

					nowTime = getTimeStamp();
					t->NextSendTime = nowTime + MAX_INTERVAL_TIME;
					t->RetryTimes++;

					bret = m_sendList.push(std::forward<T_PUDPNODE>(t));
					if (false == bret)
				
					
					continue;
				}

		
				T_UDPSLICEHEADER UdpSliceHeader;
				uint32_t sliceNum = t->UdpHeader.uSliceTotalNum;
				uint32_t currentSliceIndex = 0;
				uint32_t needSendLen = 0;
				uint32_t TmpCount = 0;

				UdpSliceHeader.HeaderType = SLICE_HEADER;
				UdpSliceHeader.SliceType = UDP_INIT_PAKTYPE;
				UdpSliceHeader.uPacketNum = t->UdpHeader.uPacketNum;
				UdpSliceHeader.uSliceTotalNum = sliceNum;

				while (currentSliceIndex < sliceNum)
				{
					if (t->RetryTimes > 0 && 1 == slice_ack_resp_check(t->bitmap, currentSliceIndex + 1))
					{
						currentSliceIndex++;
						continue;
					}

					if (currentSliceIndex < (sliceNum - 1))
					{
						UdpSliceHeader.uSliceBufLen = UDP_SLICE_MAX_SIZE;
						UdpSliceHeader.uSliceCurrIndex = currentSliceIndex + 1;
						UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

						char *tmp_buf = new char[UDP_SLICE_MAX_SIZE];
						memcpy(tmp_buf, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
						UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, UDP_SLICE_MAX_SIZE);
						delete[]tmp_buf;

						if (currentSliceIndex == 0)
						{
							memset(frameBuffer, 0, MAX_BUFFER_SIZE);
							memcpy(frameBuffer, &(t->UdpHeader), UdpHeaderSize);
							memcpy(frameBuffer + UdpHeaderSize, &UdpSliceHeader, UdpSliceHeaderSize);
							memcpy(frameBuffer + UdpHeaderSize + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
							needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize + UdpHeaderSize;
						}
						else
						{
							memset(frameBuffer, 0, MAX_BUFFER_SIZE);
							memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
							memcpy(frameBuffer + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, UDP_SLICE_MAX_SIZE);
							needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
						}

					}
					else
					{
						int tmp_len = t->UdpHeader.uBufLen - currentSliceIndex*UDP_SLICE_MAX_SIZE;
						UdpSliceHeader.uSliceBufLen = tmp_len;
						UdpSliceHeader.uSliceCurrIndex = currentSliceIndex + 1;
						UdpSliceHeader.uSliceDataOffset = currentSliceIndex * UDP_SLICE_MAX_SIZE;

						char *tmp_buf = new char[tmp_len];
						memcpy(tmp_buf, t->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
						UdpSliceHeader.uSliceBufCrc = crc32buf(tmp_buf, tmp_len);
						delete[]tmp_buf;

						memset(frameBuffer, 0, MAX_BUFFER_SIZE);
						memcpy(frameBuffer, &UdpSliceHeader, UdpSliceHeaderSize);
						memcpy(frameBuffer + UdpSliceHeaderSize, t->DataBuf + UdpSliceHeader.uSliceDataOffset, tmp_len);
						needSendLen = UdpSliceHeader.uSliceBufLen + UdpSliceHeaderSize;
					}

					if (this->m_listenFd == -1)
					{
						continue;
					}

					sendlen = sendto(this->m_listenFd, (const char*)frameBuffer, needSendLen, 0, (struct sockaddr*)&serverAdd, sizeof(serverAdd));
					if (sendlen != needSendLen)
					{
					
						continue;
					}

					TmpCount++;
					currentSliceIndex++;
					
					std::this_thread::sleep_for(std::chrono::milliseconds(3));

				}

				uint64_t intervaltime = TmpCount * MAX_INTERVAL_TIME;
				nowTime = getTimeStamp();
				t->NextSendTime = nowTime + intervaltime;
				t->RetryTimes++;

				bret = m_sendList.push(std::forward<T_PUDPNODE>(t));
				if (false == bret)
				
				continue;
			}

			bret = m_sendList.push(std::forward<T_PUDPNODE>(t));
		}

		sendlist.clear();
	}
}

void UdpThreadPool::RecvData()
{
	char recvBuf[MAX_BUFFER_SIZE];
	int bufsize = MAX_BUFFER_SIZE;
	int ret = 0;

	ret = setsockopt(this->m_listenFd, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
	if (ret == -1)
	{
		return;
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
	if (ret == -1)
	{

		return;
	}

	fd_set fd;
	int selectRet = 0;
	int recvNum = 0;

	timeval timeout;
	timeout.tv_sec = 100; 
	timeout.tv_usec = 0;

	struct sockaddr_in fromAddr;
	memset(&fromAddr, 0, sizeof(sockaddr_in));
	int fromLen = sizeof(fromAddr);

	while (!m_isstop)
	{
		FD_ZERO(&fd);
		FD_SET(this->m_listenFd, &fd);

		selectRet = select(this->m_listenFd + 1, &fd, NULL, NULL, &timeout);
		if (selectRet == -1)
		{

			return;
		}

		if (selectRet == 0) 
		{
			
			continue;
		}

		memset(recvBuf, 0, MAX_BUFFER_SIZE);

#ifdef WIN32
		recvNum = recvfrom(this->m_listenFd, recvBuf, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&fromAddr, &fromLen);
#else
		recvNum = recvfrom(this->m_listenFd, recvBuf, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&fromAddr, (socklen_t*)&fromLen);
#endif
		if (recvNum == -1)
		{

			continue;
		}
		else if (recvNum == 0)
		{
			
			continue;
		}

		T_PRECVNODE pRecvNode = new T_RECVNODE;

		pRecvNode->fromAddr = fromAddr;

		pRecvNode->recvbuf = new char[recvNum];
		memcpy(pRecvNode->recvbuf, recvBuf, recvNum);

		m_recvList.push(std::forward<T_PRECVNODE>(pRecvNode));
	}
}

void print_test_data(const char* ip, uint32_t port, const char *buf, size_t len)
{


	return;
}

void UdpThreadPool::Recv()
{
	bool bret;
	UdpRecvDataHandler *udprecvhandler = Singleton<UdpRecvDataHandler>::getInstance();
	list<T_PRECVNODE> recvlist;
	char *recvBuf = NULL;
	int fromLen = 0;

	bool throwFlag = false;

	uint32_t testID = 3;
	std::thread::id this_id = std::this_thread::get_id();


	while (!m_isstop)
	{
		m_recvList.pop(recvlist);
		for (auto t : recvlist)
		{
			fromLen = sizeof(t->fromAddr);
			recvBuf = t->recvbuf;

			if (recvBuf[0] == PACKET_HEADER)
			{
				if (((T_PUDPHEADER)recvBuf)->PacketType == UDP_INIT_PAKTYPE)
				{
	
					if (((T_PUDPHEADER)recvBuf)->uSliceTotalNum <= 1)
					{

						uint32_t uiCrc = crc32buf((recvBuf + UdpHeaderSize), ((T_PUDPHEADER)recvBuf)->uBufLen);
						if (uiCrc != ((T_PUDPHEADER)recvBuf)->uDataBufCrc)
						{

							if (t->recvbuf != NULL)
							{
								delete[] t->recvbuf;
								t->recvbuf = NULL;
							}
							if (t != NULL)
							{
								delete t;
								t = NULL;
							}

							continue;
						}

				
						T_UDPHEADER ackHeader;
						memcpy(&ackHeader, (T_PUDPHEADER)recvBuf, UdpHeaderSize);
						ackHeader.PacketType = UDP_ACK_PAKTYPE;
						ackHeader.uDataBufCrc = 0;

						int sendlen = sendto(this->m_listenFd, (const char *)(&ackHeader), UdpHeaderSize, 0, (struct sockaddr*)&(t->fromAddr), fromLen);


						if (sendlen != UdpHeaderSize)
						{

						}
						else
						{

						}

						string fromIp = inet_ntoa(t->fromAddr.sin_addr);
						uint32_t fromPort = ntohs(t->fromAddr.sin_port);

				
					RETRY:
						bret = udprecvhandler->put(fromIp.c_str(), fromPort, (char*)((T_PUDPHEADER)recvBuf + 1), ackHeader.uBufLen);
						if (bret == false)
						{
					
							goto RETRY;
						}

			

						if (t->recvbuf != NULL)
						{
							delete[] t->recvbuf;
							t->recvbuf = NULL;
						}
						if (t != NULL)
						{
							delete t;
							t = NULL;
						}

						continue;
					}

					uint32_t uiCrc = crc32buf((recvBuf + UdpHeaderSize + UdpSliceHeaderSize), ((T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize))->uSliceBufLen);
					if (uiCrc != ((T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize))->uSliceBufCrc)
					{

						if (t->recvbuf != NULL)
						{
							delete[] t->recvbuf;
							t->recvbuf = NULL;
						}
						if (t != NULL)
						{
							delete t;
							t = NULL;
						}

						continue;
					}

	
					T_UDPSLICEHEADER SliceAckHeader;
					memcpy(&SliceAckHeader, (T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize), UdpSliceHeaderSize);
					SliceAckHeader.SliceType = UDP_ACK_PAKTYPE;
					SliceAckHeader.uSliceBufCrc = 0;

					int sendlen = sendto(this->m_listenFd, (const char *)(&SliceAckHeader), UdpSliceHeaderSize, 0, (struct sockaddr*)&(t->fromAddr), fromLen);

					if (sendlen != UdpSliceHeaderSize)
					{

					}
					else
					{

					}

					T_UDPNODE UdpNode;
					UdpNode.Ip = inet_ntoa(t->fromAddr.sin_addr);
					UdpNode.Port = ntohs(t->fromAddr.sin_port);
					memcpy(&(UdpNode.UdpHeader), (T_PUDPHEADER)recvBuf, UdpHeaderSize);

					T_PACKETKEY PacketKey(UdpNode.Ip, UdpNode.Port, UdpNode.UdpHeader.uPacketNum);
					m_packetMapLock.lock();
					m_packetMap[PacketKey] = UdpNode;
					m_packetMapLock.unlock();

					T_UDPSLICENODE UdpSliceNode;
					memcpy(&(UdpSliceNode.SliceHeader), (T_PUDPSLICEHEADER)(recvBuf + UdpHeaderSize), UdpSliceHeaderSize);
					UdpSliceNode.SliceBuf = new char[UdpSliceNode.SliceHeader.uSliceBufLen];
					memcpy(UdpSliceNode.SliceBuf, (char*)(recvBuf + UdpHeaderSize + UdpSliceHeaderSize), UdpSliceNode.SliceHeader.uSliceBufLen);

					ITR_MAP_SLICEDATA iter;
					MAP_SLICEDATA tmp_slice_map;

					m_recvMapLock.lock();
					ITR_MULTI_MAP_PACKETDATA it = m_recvMap.find(PacketKey);
					if (it != m_recvMap.end())
					{
						tmp_slice_map = it->second;
						iter = tmp_slice_map.find(UdpSliceNode.SliceHeader.uSliceCurrIndex);
						if (iter != tmp_slice_map.end())
						{
				
						}
					}

					tmp_slice_map.insert(std::make_pair(UdpSliceNode.SliceHeader.uSliceCurrIndex, UdpSliceNode));

					m_recvMap[PacketKey] = tmp_slice_map;
					m_recvMapLock.unlock();
		

		
					if (tmp_slice_map.size() == UdpSliceNode.SliceHeader.uSliceTotalNum)
					{


						m_packetMapLock.lock();
						ITR_MAP_PACKETDATA tit = m_packetMap.find(PacketKey);
						if (tit == m_packetMap.end())
						{
							m_packetMapLock.unlock();

							continue;
						}

						UdpNode = tit->second;
						m_packetMapLock.unlock();

						UdpNode.DataBuf = new char[UdpNode.UdpHeader.uBufLen];

						T_UDPSLICENODE SliceNode;
						for (iter = tmp_slice_map.begin(); iter != tmp_slice_map.end(); iter++)
						{
							SliceNode = iter->second;
							memcpy(UdpNode.DataBuf + SliceNode.SliceHeader.uSliceDataOffset, SliceNode.SliceBuf, SliceNode.SliceHeader.uSliceBufLen);
							if (SliceNode.SliceBuf != NULL)
							{
								delete[]SliceNode.SliceBuf;
								SliceNode.SliceBuf = NULL;
							}
						}

						tmp_slice_map.clear();

						uint32_t uiCrc = crc32buf(UdpNode.DataBuf, UdpNode.UdpHeader.uBufLen);
						if (uiCrc != UdpNode.UdpHeader.uDataBufCrc)
						{
							if (UdpNode.DataBuf != NULL)
							{
								delete[] UdpNode.DataBuf;
								UdpNode.DataBuf = NULL;
							}
						}
						else
						{
							T_UDPHEADER ackHeader;
							memcpy(&ackHeader, &(UdpNode.UdpHeader), UdpHeaderSize);
							ackHeader.PacketType = UDP_ACK_PAKTYPE;
							ackHeader.uDataBufCrc = 0;

							int sendlen = sendto(this->m_listenFd, (const char *)(&ackHeader), UdpHeaderSize, 0, (struct sockaddr*)&(t->fromAddr), fromLen);
							if (sendlen != UdpHeaderSize)

							}
							else
							{

							}

		
						RETRY2:
							bret = udprecvhandler->put(UdpNode.Ip.c_str(), UdpNode.Port, UdpNode.DataBuf, UdpNode.UdpHeader.uBufLen);
							if (bret == false)
							{
						
								goto RETRY2;
							}

			

							if (UdpNode.DataBuf != NULL)
							{
								delete[] UdpNode.DataBuf;
								UdpNode.DataBuf = NULL;
							}

						}

	
						m_packetMapLock.lock();
						tit = m_packetMap.find(PacketKey);
						if (tit != m_packetMap.end())
						{
							m_packetMap.erase(tit);
						}
						m_packetMapLock.unlock();

				
						m_recvMapLock.lock();
						ITR_MULTI_MAP_PACKETDATA it = m_recvMap.find(PacketKey);
						if (it != m_recvMap.end())
						{
							m_recvMap.erase(it);
						}
						m_recvMapLock.unlock();
					}
					else
					{
						tmp_slice_map.clear();
					}

					if (t->recvbuf != NULL)
					{
						delete[] t->recvbuf;
						t->recvbuf = NULL;
					}
					if (t != NULL)
					{
						delete t;
						t = NULL;
					}
				
				}
				else if (((T_PUDPHEADER)recvBuf)->PacketType == UDP_ACK_PAKTYPE)
				{
					this->m_sendMapLock.lock();
					ITR_MAP_T_PUDPNODE iter_map;
					iter_map = this->m_sendMap.find(((T_PUDPHEADER)recvBuf)->uPacketNum);
					if (iter_map != this->m_sendMap.end())
					{
						(iter_map->second)->ClearFlag = ACK_FLAG;
					}
					this->m_sendMapLock.unlock();

					if (t->recvbuf != NULL)
					{
						delete[] t->recvbuf;
						t->recvbuf = NULL;
					}
					if (t != NULL)
					{
						delete t;
						t = NULL;
					}
				}
			}
			else if (recvBuf[0] == SLICE_HEADER)	
			{
				if (((T_PUDPSLICEHEADER)recvBuf)->SliceType == UDP_INIT_PAKTYPE)
				{
					if (throwFlag == true && testID == ((T_PUDPSLICEHEADER)recvBuf)->uSliceCurrIndex)
					{
		
						throwFlag = false;
						if (t->recvbuf != NULL)
						{
							delete[] t->recvbuf;
							t->recvbuf = NULL;
						}
						if (t != NULL)
						{
							delete t;
							t = NULL;
						}

						continue;
					}

					uint32_t uiCrc = crc32buf((recvBuf + UdpSliceHeaderSize), ((T_PUDPSLICEHEADER)recvBuf)->uSliceBufLen);
					if (uiCrc != ((T_PUDPSLICEHEADER)recvBuf)->uSliceBufCrc)
					{
						if (t->recvbuf != NULL)
						{
							delete[] t->recvbuf;
							t->recvbuf = NULL;
						}
						if (t != NULL)
						{
							delete t;
							t = NULL;
						}

						continue;
					}

					T_UDPSLICEHEADER SliceAckHeader;
					memcpy(&SliceAckHeader, (T_PUDPSLICEHEADER)recvBuf, UdpSliceHeaderSize);
					SliceAckHeader.SliceType = UDP_ACK_PAKTYPE;
					SliceAckHeader.uSliceBufCrc = 0;

					int sendlen = sendto(this->m_listenFd, (const char *)(&SliceAckHeader), UdpSliceHeaderSize, 0, (struct sockaddr*)&(t->fromAddr), fromLen);
					if (sendlen != UdpSliceHeaderSize)
					{

					}
					else
					{
					}

					string fromIp = inet_ntoa(t->fromAddr.sin_addr);
					uint32_t fromPort = ntohs(t->fromAddr.sin_port);

					T_UDPSLICENODE UdpSliceNode;
					memcpy(&(UdpSliceNode.SliceHeader), (T_PUDPSLICEHEADER)recvBuf, UdpSliceHeaderSize);
					UdpSliceNode.SliceBuf = new char[UdpSliceNode.SliceHeader.uSliceBufLen];
					memcpy(UdpSliceNode.SliceBuf, (char*)(recvBuf + UdpSliceHeaderSize), UdpSliceNode.SliceHeader.uSliceBufLen);

					T_PACKETKEY PacketKey(fromIp, fromPort, UdpSliceNode.SliceHeader.uPacketNum);

					ITR_MAP_SLICEDATA iter;
					MAP_SLICEDATA tmp_slice_map;

					m_recvMapLock.lock();
					ITR_MULTI_MAP_PACKETDATA it = m_recvMap.find(PacketKey);
					if (it != m_recvMap.end())
					{
						tmp_slice_map = it->second;
						iter = tmp_slice_map.find(UdpSliceNode.SliceHeader.uSliceCurrIndex);
						if (iter != tmp_slice_map.end())
						{
						}
					}

					tmp_slice_map.insert(std::make_pair(UdpSliceNode.SliceHeader.uSliceCurrIndex, UdpSliceNode));
					m_recvMap[PacketKey] = tmp_slice_map;
					m_recvMapLock.unlock();

					if (tmp_slice_map.size() == UdpSliceNode.SliceHeader.uSliceTotalNum)
					{

						m_packetMapLock.lock();
						ITR_MAP_PACKETDATA tit = m_packetMap.find(PacketKey);
						if (tit == m_packetMap.end())
						{
							m_packetMapLock.unlock();

							continue;
						}

						T_UDPNODE UdpNode = tit->second;
						m_packetMapLock.unlock();

						UdpNode.DataBuf = new char[UdpNode.UdpHeader.uBufLen];

						T_UDPSLICENODE SliceNode;
						for (iter = tmp_slice_map.begin(); iter != tmp_slice_map.end(); iter++)
						{
							SliceNode = iter->second;
							memcpy(UdpNode.DataBuf + SliceNode.SliceHeader.uSliceDataOffset, SliceNode.SliceBuf, SliceNode.SliceHeader.uSliceBufLen);
							if (SliceNode.SliceBuf != NULL)
							{
								delete[]SliceNode.SliceBuf;
								SliceNode.SliceBuf = NULL;
							}
						}

						tmp_slice_map.clear();

						uint32_t uiCrc = crc32buf(UdpNode.DataBuf, UdpNode.UdpHeader.uBufLen);
						if (uiCrc != UdpNode.UdpHeader.uDataBufCrc)
						{
							if (UdpNode.DataBuf != NULL)
							{
								delete[] UdpNode.DataBuf;
								UdpNode.DataBuf = NULL;
							}
						}
						else
						{
							T_UDPHEADER ackHeader;
							memcpy(&ackHeader, &(UdpNode.UdpHeader), UdpHeaderSize);
							ackHeader.PacketType = UDP_ACK_PAKTYPE;
							ackHeader.uDataBufCrc = 0;

							int sendlen = sendto(this->m_listenFd, (const char *)(&ackHeader), UdpHeaderSize, 0, (struct sockaddr*)&(t->fromAddr), fromLen);
							if (sendlen != UdpHeaderSize)
							{

							}
							else
							{
							}

						RETRY3:
							bret = udprecvhandler->put(UdpNode.Ip.c_str(), UdpNode.Port, UdpNode.DataBuf, UdpNode.UdpHeader.uBufLen);
							if (bret == false)
							{
								goto RETRY3;
							}


							if (UdpNode.DataBuf != NULL)
							{
								delete[] UdpNode.DataBuf;
								UdpNode.DataBuf = NULL;
							}

						}

						m_packetMapLock.lock();
						tit = m_packetMap.find(PacketKey);
						if (tit != m_packetMap.end())
						{
							m_packetMap.erase(tit);
						}
						m_packetMapLock.unlock();

		
						m_recvMapLock.lock();
						ITR_MULTI_MAP_PACKETDATA it = m_recvMap.find(PacketKey);
						if (it != m_recvMap.end())
						{
							m_recvMap.erase(it);
						}
						m_recvMapLock.unlock();
					}
					else
					{
						tmp_slice_map.clear();
					}

					if (t->recvbuf != NULL)
					{
						delete[] t->recvbuf;
						t->recvbuf = NULL;
					}
					if (t != NULL)
					{
						delete t;
						t = NULL;
					}
				}
				else if (((T_PUDPSLICEHEADER)recvBuf)->SliceType == UDP_ACK_PAKTYPE)
				{
					this->m_sendMapLock.lock();
					ITR_MAP_T_PUDPNODE iter_map;
					iter_map = this->m_sendMap.find(((T_PUDPSLICEHEADER)recvBuf)->uPacketNum);
					if (iter_map != this->m_sendMap.end())
					{
						slice_ack_resp_add((iter_map->second)->bitmap, ((T_PUDPSLICEHEADER)recvBuf)->uSliceCurrIndex);
					}
					this->m_sendMapLock.unlock();

					if (t->recvbuf != NULL)
					{
						delete[] t->recvbuf;
						t->recvbuf = NULL;
					}
					if (t != NULL)
					{
						delete t;
						t = NULL;
					}
				}
			}
		}

		recvlist.clear();
	}
}
