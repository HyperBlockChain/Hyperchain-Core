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

#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "../node/TaskThreadPool.h"
#include "buddyinfo.h"
#include "headers/lambda.h"

extern void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type);
extern void ChangeLocalBlockPreHash(LIST_T_LOCALCONSENSUS &localList);
extern bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);

extern void SendCopyLocalBlock(T_LOCALCONSENSUS &localBlock);
extern void PutIntoConsensusList(T_BUDDYINFOSTATE &buddyinfostate);
extern bool makeBuddy(const string & confirmhash);
extern bool isConfirming(string &currBuddyHash);


class OnChainConfirmRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_CONFIRM_RSP> {
public:
	using ITask::ITask;

	OnChainConfirmRspTask(const CUInt128 &peerid, uint64 uiHyperBlockNum, const string & hash) :
		_peerid(peerid), _uiHyperBlockNum(uiHyperBlockNum),_hash(hash) {}

	~OnChainConfirmRspTask() {};

	void exec() override
	{
		g_consensus_console_logger->info("Send OnChainConfirmRspTask to {}\n", _peerid.ToHexString().c_str());

		
		T_PP2PPROTOCOLONCHAINCONFIRMRSP pP2pProtocolOnChainConfirmRsp = nullptr;

		int ipP2pProtocolOnChainConfirmRspLen = sizeof(T_P2PPROTOCOLONCHAINCONFIRMRSP);

		DataBuffer<OnChainConfirmRspTask> msgbuf(ipP2pProtocolOnChainConfirmRspLen);
		pP2pProtocolOnChainConfirmRsp = reinterpret_cast<T_PP2PPROTOCOLONCHAINCONFIRMRSP>(msgbuf.payload());

		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);

		pP2pProtocolOnChainConfirmRsp->uiHyperBlockNum = _uiHyperBlockNum;
		pP2pProtocolOnChainConfirmRsp->SetInitHash(0);
		pP2pProtocolOnChainConfirmRsp->SetP2pprotocolonchainconfirmrsp(
			T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_CONFIRM_RSP, timeTemp.tv_sec), P2P_PROTOCOL_SUCCESS), 
			const_cast<char*>(_hash.c_str()));

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

		nodemgr->sendTo(_peerid, msgbuf);

	}

	void execRespond() override
	{
		g_consensus_console_logger->info("Received OnChainConfirmRspTask from {}",_sentnodeid.ToHexString());
		T_PP2PPROTOCOLONCHAINCONFIRMRSP pP2pProtocolOnChainConfirmRspRecv = (T_PP2PPROTOCOLONCHAINCONFIRMRSP)(_payload);

		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		{
			CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
			auto itr = g_tP2pManagerStatus.listCurBuddyRsp.begin();
			for (; itr != g_tP2pManagerStatus.listCurBuddyRsp.end();) {
				if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolOnChainConfirmRspRecv->GetHash(), DEF_STR_HASH256_LEN) &&
					(*itr).GetBuddyState() == SEND_CONFIRM) {
					PutIntoConsensusList(*itr);
					int i = 0;
					for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
						g_consensus_console_logger->info("OnChainConfirmRspTask: listLocalBuddyChainInfo: {} {}", ++i, b.GetLocalBlock().GetPayLoad().GetPayLoad());
					}
				}
				else if ((*itr).GetBuddyState() != CONSENSUS_CONFIRMED) {
					SendRefuseReq((*itr).GetPeerAddrOut()._nodeid,
						string((*itr).strBuddyHash, DEF_STR_HASH256_LEN), RECV_REQ);
					itr = g_tP2pManagerStatus.listCurBuddyRsp.erase(itr);
					continue;
				}
				++itr;
			}
		}

		{
			CAutoMutexLock muxAuto2(g_tP2pManagerStatus.MuxlistCurBuddyReq);
			auto itrReq = g_tP2pManagerStatus.listCurBuddyReq.begin();
			for (; itrReq != g_tP2pManagerStatus.listCurBuddyReq.end();) {
				if (0 == strncmp((*itrReq).strBuddyHash, pP2pProtocolOnChainConfirmRspRecv->strHash, DEF_STR_HASH256_LEN)) {
					itrReq->uibuddyState = CONSENSUS_CONFIRMED;
				}
				else {

					SendRefuseReq((*itrReq).GetPeerAddrOut()._nodeid,
						string((*itrReq).strBuddyHash, DEF_STR_HASH256_LEN), RECV_RSP);
					itrReq = g_tP2pManagerStatus.listCurBuddyReq.erase(itrReq);
					continue;
				}
				++itrReq;
			}
		}

		g_consensus_console_logger->info("OnChainConfirmRspTask: listCurBuddyReq size: {} listCurBuddyRsp size: {}", 
										g_tP2pManagerStatus.listCurBuddyReq.size(),
										g_tP2pManagerStatus.listCurBuddyRsp.size());

		CAutoMutexLock muxAuto3(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
		g_tP2pManagerStatus.listRecvLocalBuddyRsp.clear();

		CAutoMutexLock muxAuto4(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
		g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();
	}

private:
	CUInt128 _peerid;
	uint64_t _uiHyperBlockNum;
	string _hash;
};

class OnChainConfirmTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::ON_CHAIN_CONFIRM> {
public:
	using ITask::ITask;

	OnChainConfirmTask(const CUInt128 &peerid, uint64 uiHyperBlockNum,
		string hash, uint8 state) : _peerid(peerid), _uiHyperBlockNum(uiHyperBlockNum), _hash(hash), _state(state) {}

	~OnChainConfirmTask() {};
	void exec() override
	{
		{
			CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
			for (auto &buddy : g_tP2pManagerStatus.listCurBuddyRsp) {
				if (buddy.GetBuddyState() == SEND_CONFIRM) {
					g_consensus_console_logger->info("OnChainConfirmTask: already sent out Confirm");
					return;
				}
			}

			bool isFind = false;
			for (auto &chain : g_tP2pManagerStatus.listCurBuddyRsp) {
				if (0 == strncmp(chain.GetBuddyHash(), _hash.c_str(), DEF_STR_HASH256_LEN)) {
					chain.SetBuddyState(SEND_CONFIRM);
					g_consensus_console_logger->info("OnChainConfirmTask: set buddy state SEND_CONFIRM");
					isFind = true;
					break;
				}
			}
			if (!isFind) {
				return;
			}
		}

		char logmsg[128] = { 0 };
		snprintf(logmsg, 128, "Send OnChainConfirmTask to peer:%s\n", _peerid.ToHexString().c_str());
		g_consensus_console_logger->info(logmsg);

		T_PP2PPROTOCOLONCHAINCONFIRM pP2pProtocolOnChainConfirm = nullptr;

		int ipP2pProtocolOnChainConfirmLen = sizeof(T_P2PPROTOCOLONCHAINCONFIRM);

		DataBuffer<OnChainConfirmTask> msgbuf(ipP2pProtocolOnChainConfirmLen);
		pP2pProtocolOnChainConfirm = reinterpret_cast<T_PP2PPROTOCOLONCHAINCONFIRM>(msgbuf.payload());

		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);
		pP2pProtocolOnChainConfirm->SetInitHash(0);
		pP2pProtocolOnChainConfirm->uiHyperBlockNum = _uiHyperBlockNum;
		pP2pProtocolOnChainConfirm->SetP2pprotocolonchainconfirm(
			T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_ON_CHAIN_CONFIRM, timeTemp.tv_sec), _state), 
			const_cast<char*> (_hash.c_str()));

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		nodemgr->sendTo(_peerid, msgbuf);
		
	}

	void execRespond() override
	{
		T_PP2PPROTOCOLONCHAINCONFIRM pP2pProtocolOnChainConfirmRecv = (T_PP2PPROTOCOLONCHAINCONFIRM)(_payload);

		bool isFind = false;

		auto f = [&](T_BUDDYINFOSTATE &buddyinfostate) {
			if (0 == strncmp(buddyinfostate.strBuddyHash,
				pP2pProtocolOnChainConfirmRecv->GetHash(), DEF_STR_HASH256_LEN)) {
				isFind = true;
				return true;
			}
			return false;
		};

		g_consensus_console_logger->info("Received confirm from {}", _sentnodeid.ToHexString());
		string confirmbuddyhash = string(pP2pProtocolOnChainConfirmRecv->GetHash(), DEF_STR_HASH256_LEN);

		string currBuddyHash;
		bool isconfirming = isConfirming(currBuddyHash);

		{
			CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyReq);
			std::find_if(g_tP2pManagerStatus.listCurBuddyReq.begin(), g_tP2pManagerStatus.listCurBuddyReq.end(), f);
		}
		if (isFind) {
			if (!isconfirming || currBuddyHash == confirmbuddyhash) {
				g_consensus_console_logger->info("confirm from {}: will makebuddy, isconfirming:{}", _sentnodeid.ToHexString(), isconfirming);

				if (makeBuddy(confirmbuddyhash)) {
					SendConfirmRsp(confirmbuddyhash, pP2pProtocolOnChainConfirmRecv->uiHyperBlockNum);
				}
			}
		}
		else {
			
			SendWaitRsp(confirmbuddyhash);
		}

		if (!isFind) {
			g_consensus_console_logger->info("Confirm refused: cannot find the buddy hash from {} ",
				_sentnodeid.ToHexString().c_str());
			SendRefuseReq(_sentnodeid, confirmbuddyhash, RECV_RSP);
		}
	}

	void SendConfirmRsp(string hash, uint64_t uiHyperBlockNum)
	{
		TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
		taskpool->put(make_shared<OnChainConfirmRspTask>(_sentnodeid, uiHyperBlockNum, hash));
	}
	void SendWaitRsp(string hash)
	{
		TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
		taskpool->put(make_shared<OnChainWaitTask>(_sentnodeid, hash));
	}

private:
	CUInt128 _peerid;
	uint64_t _uiHyperBlockNum;
	string _hash;
	int _state;
};


class CopyBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::COPY_BLOCK> {
public:
	using ITask::ITask;

	CopyBlockTask(const T_LOCALCONSENSUS &localBlock) : _localBlock(localBlock) {}

	~CopyBlockTask() {};

	void exec() override
	{
		g_consensus_console_logger->info("Send CopyBlockLocalTask: {}", 
			_localBlock.GetLocalBlock().GetPayLoad().GetPayLoad());

		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		size_t nodeSize = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
		if (nodeSize > NOT_START_BUDDY_NUM) {
			T_PP2PPROTOCOLCOPYBLOCKREQ pP2pProtocolCopyBlockReq = nullptr;
			int ipP2pProtocolCopyBlockReqLen = sizeof(T_P2PPROTOCOLCOPYBLOCKREQ)  + sizeof(T_LOCALCONSENSUS) + nodeSize * DEF_SHA256_LEN;

			DataBuffer<CopyBlockTask> msgbuf(ipP2pProtocolCopyBlockReqLen);
			pP2pProtocolCopyBlockReq = reinterpret_cast<T_PP2PPROTOCOLCOPYBLOCKREQ>(msgbuf.payload());

			struct timeval timeTemp;
			CCommonStruct::gettimeofday_update(&timeTemp);
			pP2pProtocolCopyBlockReq->SetType(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_COPY_BLOCK_REQ, timeTemp.tv_sec));
			

			T_PLOCALCONSENSUS pLocalBlockInfo = (T_PLOCALCONSENSUS)(pP2pProtocolCopyBlockReq + 1);
			pLocalBlockInfo->SetLocalBlock(_localBlock.GetLocalBlock());
			pLocalBlockInfo->SetPeer(_localBlock.GetPeer());
			
			char *p = msgbuf.payload() + ipP2pProtocolCopyBlockReqLen - nodeSize * DEF_SHA256_LEN;
			uint16 num = 0;
			for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
				if ((b.GetLocalBlock().GetBlockBaseInfo().GetHashSelf() == _localBlock.GetLocalBlock().GetBlockBaseInfo().GetHashSelf())) {
					continue;
				}
				memcpy(p, b.GetLocalBlock().GetBlockBaseInfo().GetHashSelf().pID, DEF_SHA256_LEN);
				num++;
				if (num >= nodeSize) {
					break;
				}
				p += DEF_SHA256_LEN;
			}
			pP2pProtocolCopyBlockReq->uiBuddyNum = num;

			NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
			HCNodeSH me = nodemgr->myself();

			ITR_LIST_T_LOCALCONSENSUS itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
			for (; itr != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itr++) {
				if ((*itr).tLocalBlock.GetBlockBaseInfo().GetHashSelf() == _localBlock.GetLocalBlock().GetBlockBaseInfo().GetHashSelf()) {
					continue;
				}
				if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
					continue;
				}
				g_consensus_console_logger->info("Send {} blocks hash and CopyBlockLocalTask to {}",
					pP2pProtocolCopyBlockReq->uiBuddyNum,
					(*itr).GetPeer().GetPeerAddr()._nodeid.ToHexString());
				nodemgr->sendTo((*itr).GetPeer().GetPeerAddr()._nodeid, msgbuf);
			}
		}
	}

	void execRespond() override
	{
		g_consensus_console_logger->trace("Received CopyBlockTask");
		T_PP2PPROTOCOLCOPYBLOCKREQ pP2pProtocolCopyBlockReqRecv = (T_PP2PPROTOCOLCOPYBLOCKREQ)(_payload);

		T_PLOCALCONSENSUS  pLocalBlockTemp;
		pLocalBlockTemp = (T_PLOCALCONSENSUS)(pP2pProtocolCopyBlockReqRecv + 1);

		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		ITR_LIST_T_LOCALCONSENSUS itrList = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
		for (; itrList != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itrList++) {
			if (((*itrList).GetLocalBlock().GetBlockBaseInfo().GetHashSelf() == pLocalBlockTemp->GetLocalBlock().GetBlockBaseInfo().GetHashSelf())) {
				return;
			}
		}

		uint16 num = 0;
		const char * pHashID = _payload + sizeof(T_P2PPROTOCOLCOPYBLOCKREQ) + sizeof(T_LOCALCONSENSUS);
		for (uint16 i = 0; i< pP2pProtocolCopyBlockReqRecv->uiBuddyNum; i++ ) {
			for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
				if (memcmp(pHashID, b.GetLocalBlock().GetBlockBaseInfo().GetHashSelf().pID, DEF_SHA256_LEN) == 0) {
					num++;
					break;
				}
			}
			pHashID += DEF_SHA256_LEN;
		}
		g_consensus_console_logger->info("CopyBlockTask: recv {} copy block data,{} block is same.", 
			pP2pProtocolCopyBlockReqRecv->uiBuddyNum, num);
		
		if (num < 2) {
			g_consensus_console_logger->warn("CopyBlockTask: cannot accept the copy data,maybe I have entered next phase.");
			return;
		}
		g_consensus_console_logger->trace("CopyBlockTask: push block into listLocalBuddyChainInfo,payload:{}",
								pLocalBlockTemp->GetLocalBlock().GetPayLoad().GetPayLoad());
		g_tP2pManagerStatus.listLocalBuddyChainInfo.push_back(*pLocalBlockTemp);
		g_tP2pManagerStatus.listLocalBuddyChainInfo.sort(CmpareOnChain());
		ChangeLocalBlockPreHash(g_tP2pManagerStatus.listLocalBuddyChainInfo);
		g_tP2pManagerStatus.tBuddyInfo.usBlockNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();

		g_tP2pManagerStatus.SetRecvRegisReqNum(g_tP2pManagerStatus.GetRecvRegisReqNum() + 1);
		g_tP2pManagerStatus.SetRecvConfirmingRegisReqNum(g_tP2pManagerStatus.GetRecvConfirmingRegisReqNum() + 1);
	}

private:
	T_LOCALCONSENSUS _localBlock;
};
