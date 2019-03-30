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

#include <iostream>
using namespace std;

#include "headers/lambda.h"
#include "../crypto/sha2.h"
#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "buddyinfo.h"

extern bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);
extern void copyLocalBuddyList(LIST_T_LOCALCONSENSUS &endList, LIST_T_LOCALCONSENSUS fromList);
extern void ChangeLocalBlockPreHash(LIST_T_LOCALCONSENSUS &localList);
extern void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum,const string &hash, uint8 type);
extern bool isHyperBlockMatched(uint64 hyperblockid,const T_SHA256 &hash,const CUInt128 &peerid);

class OnChainRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_RSP> {
public:
	using ITask::ITask;
	OnChainRspTask(const CUInt128 &peerid, string && pBuf, unsigned int uiBufLen) : 
					_peerid(peerid), _pBuf(std::forward<string>(pBuf)), _uiBufLen(uiBufLen) {}
	~OnChainRspTask() {};
	void exec() override
	{
		g_consensus_console_logger->trace("enter OnChainRspTask: {}", _peerid.ToHexString());
		
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		size_t nodeSize = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
		if (nodeSize == 0) {
			g_consensus_console_logger->trace("OnChainRspTask: my consensus block size is 0 ");
			return;
		}

		T_PP2PPROTOCOLONCHAINREQ pP2pProtocolOnChainReqRecv = (T_PP2PPROTOCOLONCHAINREQ)(const_cast<char*>(_pBuf.c_str()));

		if (!isHyperBlockMatched(pP2pProtocolOnChainReqRecv->GetHyperBlockID(), pP2pProtocolOnChainReqRecv->tHyperBlockHash, _peerid)) {
			g_consensus_console_logger->warn("OnChainRspTask: PreHyperBlock isn't matched. recv:{} local:{} from: {}",
				pP2pProtocolOnChainReqRecv->GetHyperBlockID(),
				g_tP2pManagerStatus.GetMaxBlockID(), _peerid.ToHexString());
			return;
		}

		bool index = false;

		if (nodeSize != ONE_LOCAL_BLOCK && pP2pProtocolOnChainReqRecv->GetBlockCount() != ONE_LOCAL_BLOCK) {
			g_consensus_console_logger->trace("OnChainRspTask: cannot make buddy, my consensus block size:{}, recv block: {}", 
										nodeSize, pP2pProtocolOnChainReqRecv->GetBlockCount());
			return;
		}

		
		g_tP2pManagerStatus.updateLocalBuddyBlockToLatest();

		T_BUDDYINFOSTATE buddyInfo;
		copyLocalBuddyList(buddyInfo.localList, g_tP2pManagerStatus.listLocalBuddyChainInfo);
		
		T_PLOCALCONSENSUS  pLocalBlockTemp;
		pLocalBlockTemp = (T_PLOCALCONSENSUS)(pP2pProtocolOnChainReqRecv + 1);

		for (uint64 i = 0; i < pP2pProtocolOnChainReqRecv->GetBlockCount(); i++) {
			T_LOCALCONSENSUS  LocalBlockInfo;
			LocalBlockInfo = *(pLocalBlockTemp + i);

			index = JudgExistAtLocalBuddy(buddyInfo.localList, LocalBlockInfo);

			if (index)
				continue;
			buddyInfo.localList.push_back(LocalBlockInfo);
			buddyInfo.localList.sort(CmpareOnChain());
			ChangeLocalBlockPreHash(buddyInfo.localList);
		}

		T_PLOCALCONSENSUS pPeerInfosTemp;
		size_t blockNumTemp = buddyInfo.localList.size();
		int pPeerInfosTempLen = blockNumTemp * sizeof(T_LOCALCONSENSUS);

		string msgbufpeerInfo(pPeerInfosTempLen, 0);
		pPeerInfosTemp = reinterpret_cast<T_PLOCALCONSENSUS>(const_cast<char*>(msgbufpeerInfo.c_str()));

		int j = 0;
		ITR_LIST_T_LOCALCONSENSUS itrTemp = buddyInfo.localList.begin();
		for (; itrTemp != buddyInfo.localList.end(); itrTemp++) {
			pPeerInfosTemp[j] = (*itrTemp);
			j++;
		}
		buddyInfo.SetPeerAddrOut(T_PEERADDRESS(_peerid));
		buddyInfo.SetBuddyState(SEND_ON_CHAIN_RSP);


		T_SHA256 tempHash(0);
		GetSHA256(tempHash.pID, (const char*)(pPeerInfosTemp), pPeerInfosTempLen);

		char strLocalHashTemp[FILESIZES] = { 0 };
		CCommonStruct::Hash256ToStr(strLocalHashTemp, &tempHash);

		buddyInfo.SetBuddyHashInit(0);
		buddyInfo.SetBuddyHash(strLocalHashTemp);

		CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyReq);
		ITR_LIST_T_BUDDYINFOSTATE itrReq = g_tP2pManagerStatus.listCurBuddyReq.begin();
		for (; itrReq != g_tP2pManagerStatus.listCurBuddyReq.end(); itrReq++) {
			if (0 == memcmp((*itrReq).GetBuddyHash(), buddyInfo.GetBuddyHash(), DEF_STR_HASH256_LEN)) {
				return;
			}
		}
		g_tP2pManagerStatus.listCurBuddyReq.push_back(buddyInfo);

		T_PP2PPROTOCOLONCHAINRSP pP2pProtocolOnChainRsp = NULL;
		size_t blockNum = buddyInfo.localList.size();
		int ipP2pProtocolOnChainRspLen = sizeof(T_P2PPROTOCOLONCHAINRSP) + blockNum * sizeof(T_LOCALCONSENSUS);
		
		DataBuffer<OnChainRspTask> msgbuf(ipP2pProtocolOnChainRspLen);
		pP2pProtocolOnChainRsp = reinterpret_cast<T_PP2PPROTOCOLONCHAINRSP>(msgbuf.payload());

		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);
		pP2pProtocolOnChainRsp->SetInitHash(0);

		T_SHA256 tPreHyperBlockHash;
		uint64 hyperblockid = 0;
		g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(hyperblockid, tPreHyperBlockHash);

		pP2pProtocolOnChainRsp->SetP2pprotocolonchainrsp(T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_RSP, timeTemp.tv_sec), P2P_PROTOCOL_SUCCESS),
														hyperblockid, blockNum, strLocalHashTemp);
		pP2pProtocolOnChainRsp->tHyperBlockHash = tPreHyperBlockHash;

		T_PLOCALCONSENSUS pPeerInfos = (T_PLOCALCONSENSUS)(pP2pProtocolOnChainRsp + 1);

		int i = 0;
		ITR_LIST_T_LOCALCONSENSUS itr = buddyInfo.localList.begin();
		for (; itr != buddyInfo.localList.end(); itr++) {
			pPeerInfos[i] = (*itr);
			i++;
		}

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		g_consensus_console_logger->info("Send out OnChainRspTask");
		nodemgr->sendTo(_peerid,msgbuf);
	}

	void execRespond() override
	{
		g_consensus_console_logger->info("Received OnChainRspTask");
		T_BUDDYINFO localBuddyInfo;

		T_PEERADDRESS peerAddrOut(_sentnodeid);
		localBuddyInfo.Set(RECV_RSP, _payloadlen, _payload, peerAddrOut);

		bool index = false;
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
		LIST_T_BUDDYINFO::iterator itr = g_tP2pManagerStatus.listRecvLocalBuddyRsp.begin();
		for (; itr != g_tP2pManagerStatus.listRecvLocalBuddyRsp.end(); itr++) {
			if ((*itr).GetRequestAddress() == localBuddyInfo.GetRequestAddress()) {
				index = true;
				break;
			}
		}
		if (!index) {
			g_tP2pManagerStatus.listRecvLocalBuddyRsp.push_back(localBuddyInfo);
		}
	}

private:
	CUInt128 _peerid;
	string _pBuf;
	unsigned int _uiBufLen;
};

class OnChainTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN> {
public:
	using ITask::ITask;

	~OnChainTask() {};
	void exec() override
	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		T_PP2PPROTOCOLONCHAINREQ pP2pProtocolOnChainReq = nullptr;
		size_t blockNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();

		int ipP2pProtocolOnChainReqLen = sizeof(T_P2PPROTOCOLONCHAINREQ) + blockNum * sizeof(T_LOCALCONSENSUS);

		DataBuffer<OnChainTask> msgbuf(ipP2pProtocolOnChainReqLen);
		pP2pProtocolOnChainReq = reinterpret_cast<T_PP2PPROTOCOLONCHAINREQ>(msgbuf.payload());

		T_SHA256 tPreHyperBlockHash;
		uint64 hyperblockid = 0;
		g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(hyperblockid, tPreHyperBlockHash);

		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);

		
		pP2pProtocolOnChainReq->SetP2pprotocolonchainreq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_REQ, timeTemp.tv_sec), 
														hyperblockid, tPreHyperBlockHash, blockNum);

		T_PLOCALCONSENSUS pPeerInfos = nullptr;
		pPeerInfos = (T_PLOCALCONSENSUS)(pP2pProtocolOnChainReq + 1);

		uint32_t i = 0;
		ITR_LIST_T_LOCALCONSENSUS itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();

		
		g_tP2pManagerStatus.updateLocalBuddyBlockToLatest();

		for (; itr != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itr++) {
			pPeerInfos[i].SetLoaclConsensus((*itr).GetPeer(), (*itr).GetLocalBlock());
			i++;
		}

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		g_consensus_console_logger->info("Broadcast OnChainTask...block number:{} prehyperblockid:{}",i, 
										pP2pProtocolOnChainReq->GetHyperBlockID());
		nodemgr->sendToAllNodes(msgbuf);
	}

	void execRespond() override
	{
		T_BUDDYINFO localBuddyInfo;

		T_PEERADDRESS peerAddrOut(_sentnodeid);
		localBuddyInfo.Set(RECV_REQ, _payloadlen, _payload, peerAddrOut);

		char logmsg[128] = { 0 };
		snprintf(logmsg, 128, "OnChain request from peer:%s reached\n", _sentnodeid.ToHexString().c_str());
		g_consensus_console_logger->trace(logmsg);

		bool index = false;
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);

		LIST_T_BUDDYINFO::iterator itr = g_tP2pManagerStatus.listRecvLocalBuddyReq.begin();
		for (; itr != g_tP2pManagerStatus.listRecvLocalBuddyReq.end(); itr++) {
			const T_PP2PPROTOCOLONCHAINREQ pP2pProtocolOnChainReq = (const T_PP2PPROTOCOLONCHAINREQ)(localBuddyInfo.GetBuffer().c_str());
			const T_PP2PPROTOCOLONCHAINREQ currReq = (const T_PP2PPROTOCOLONCHAINREQ)(itr->GetBuffer().c_str());
			if ((*itr).GetRequestAddress() == localBuddyInfo.GetRequestAddress()) {
				if (pP2pProtocolOnChainReq->tType.GetTimeStamp() <= currReq->tType.GetTimeStamp()) {
					index = true;
				} else {
					g_tP2pManagerStatus.listRecvLocalBuddyReq.erase(itr);
				}
				break;
			}
		}

		if (!index) {
			g_tP2pManagerStatus.listRecvLocalBuddyReq.push_back(localBuddyInfo);
			g_tP2pManagerStatus.SetRecvRegisReqNum(g_tP2pManagerStatus.GetRecvRegisReqNum() + 1);
			g_tP2pManagerStatus.SetRecvConfirmingRegisReqNum(g_tP2pManagerStatus.GetRecvConfirmingRegisReqNum() + 1);
		}
	}
};

class OnChainRefuseTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_REFUSE> {
public:
	using ITask::ITask;

	OnChainRefuseTask(const CUInt128 &peerid, const string & hash, uint8 type) : _peerid(peerid), _hash(hash), _type(type) {}

	~OnChainRefuseTask() {};

	void exec() override
	{
		char logmsg[128] = { 0 };

		snprintf(logmsg, 128, "Refuse peer:%s chain respond\n", _peerid.ToHexString().c_str());
		g_consensus_console_logger->info(logmsg);

		T_PP2PPROTOCOLREFUSEREQ pP2pProtocolRefuseReq = nullptr;
		int ipP2pProtocolRefuseReqLen = sizeof(T_P2PPROTOCOLREFUSEREQ);
		
		DataBuffer<OnChainRefuseTask> msgbuf(ipP2pProtocolRefuseReqLen);
		pP2pProtocolRefuseReq = reinterpret_cast<T_PP2PPROTOCOLREFUSEREQ>(msgbuf.payload());

		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);
		pP2pProtocolRefuseReq->SetP2pprotocolrefusereq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_REFUSE_REQ, timeTemp.tv_sec), (char*)_hash.c_str(), _type);

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

		nodemgr->sendTo(_peerid, msgbuf);
	}

	void execRespond() override
	{
		T_PP2PPROTOCOLREFUSEREQ pP2pProtocolRefuseReq = (T_PP2PPROTOCOLREFUSEREQ)(_payload);

		if (pP2pProtocolRefuseReq->GetSubType() == RECV_RSP) {
			bool isfound = false;
			CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
			auto itr = g_tP2pManagerStatus.listCurBuddyRsp.begin();
			for (; itr != g_tP2pManagerStatus.listCurBuddyRsp.end();) {
				if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolRefuseReq->GetHash(), DEF_STR_HASH256_LEN)) {
					itr = g_tP2pManagerStatus.listCurBuddyRsp.erase(itr);
					isfound = true;
				}
				else {
					itr++;
				}
			}

			if (!isfound) {
				return;
			}
			g_consensus_console_logger->info( "Confirm refused from: {}: select another buddy to confirm: listCurBuddyRsp size:{}",
										_sentnodeid.ToHexString(), g_tP2pManagerStatus.listCurBuddyRsp.size());

			if ( g_tP2pManagerStatus.listCurBuddyRsp.size() > 0) {
				auto itr = g_tP2pManagerStatus.listCurBuddyRsp.begin();
				for (auto &b : itr->GetList()) {
					g_consensus_console_logger->info("Confirm selected: {}", b.GetLocalBlock().GetPayLoad().GetPayLoad());
				}

				LIST_T_LOCALCONSENSUS& c = itr->GetLocalConsensus();
				T_LOCALBLOCK &tLocalBlock = c.begin()->GetLocalBlock();

				SendConfirmReq(itr->GetPeerAddrOut()._nodeid, tLocalBlock.GetBlockBaseInfo().GetID(), 
					itr->GetBuddyHash(), P2P_PROTOCOL_SUCCESS);
			}
		}
		else if (pP2pProtocolRefuseReq->GetSubType() == RECV_REQ)
		{
			CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyReq);
			auto itr = g_tP2pManagerStatus.listCurBuddyReq.begin();
			for (; itr != g_tP2pManagerStatus.listCurBuddyReq.end();) {
				if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolRefuseReq->GetHash(), DEF_STR_HASH256_LEN)) {
					itr = g_tP2pManagerStatus.listCurBuddyReq.erase(itr);
				}
				else {
					itr++;
				}
			}
		}
	}

private:
	CUInt128 _peerid;
	string _hash;
	int _type;
};

class OnChainWaitTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_WAIT> {
public:
	using ITask::ITask;

	OnChainWaitTask(const CUInt128 &peerid, const string &hash) : _peerid(peerid), _hash(hash) {}

	~OnChainWaitTask() {};

	void exec() override
	{
		char logmsg[128] = { 0 };

		snprintf(logmsg, 128, "I am waiting for confirm respond,inform peer to wait: %s \n", _peerid.ToHexString().c_str());
		g_consensus_console_logger->info(logmsg);

		DataBuffer<OnChainWaitTask> msgbuf(DEF_STR_HASH256_LEN);
		memcpy(msgbuf.payload(), _hash.c_str(), DEF_STR_HASH256_LEN);

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		nodemgr->sendTo(_peerid, msgbuf);
	}

	void execRespond() override
	{
		const char *pHash = _payload;

		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
		for (auto &buddy : g_tP2pManagerStatus.listCurBuddyRsp) {
			if (0 == strncmp(buddy.strBuddyHash, pHash, DEF_STR_HASH256_LEN) && buddy.GetBuddyState() == SEND_CONFIRM) {

				g_consensus_console_logger->info( "Confirm wait from {}: select another buddy to confirm : listCurBuddyRsp size:{}",
					_sentnodeid.ToHexString(), g_tP2pManagerStatus.listCurBuddyRsp.size());

				buddy.SetBuddyState(RECV_ON_CHAIN_RSP);
				for (auto &buddyCon : g_tP2pManagerStatus.listCurBuddyRsp) {
					if (&buddyCon != &buddy) {
						LIST_T_LOCALCONSENSUS& c = buddyCon.GetLocalConsensus();
						T_LOCALBLOCK &tLocalBlock = c.begin()->GetLocalBlock();
						SendConfirmReq(buddyCon.GetPeerAddrOut()._nodeid,tLocalBlock.GetBlockBaseInfo().GetID(), 
							buddyCon.GetBuddyHash(), P2P_PROTOCOL_SUCCESS);
						break;
					}
				}

				//Todo:

				break;
			}
		}
	}

private:
	CUInt128 _peerid;
	string _hash;
};
