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

#include "../newLog.h"
#include "globalbuddytask.h"
extern bool JudgExistAtGlobalBuddy(LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo);
extern bool isEndNode();

void GlobalBuddyStartTask::exec()
{
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
	g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();

	uint64 hyperblocknum = g_tP2pManagerStatus.GetConsensusHyperBlockID();
	CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0 || g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 1) {
		return;
	}

	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH & me = nodemgr->myself();

	LIST_T_LOCALCONSENSUS::iterator itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.end();
	itr--;
	if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {

		T_PP2PPROTOCOLGLOBALBUDDYREQ pP2pProtocolGlobalBuddyReq = NULL;

		uint32_t blockNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
		int ipP2pProtocolGlobalBuddyReqLen = sizeof(T_P2PPROTOCOLGLOBALBUDDYREQ) + blockNum * sizeof(T_GLOBALCONSENSUS);

		DataBuffer<GlobalBuddyStartTask> msgbuf(ipP2pProtocolGlobalBuddyReqLen);
		pP2pProtocolGlobalBuddyReq = reinterpret_cast<T_PP2PPROTOCOLGLOBALBUDDYREQ>(msgbuf.payload());

		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);
		pP2pProtocolGlobalBuddyReq->uiHyperBlockNum = hyperblocknum;
		pP2pProtocolGlobalBuddyReq->SetP2pprotocolglobalconsensusreq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GLOBAL_BUDDY_REQ, timeTemp.tv_sec), 
			T_PEERADDRESS(me->getNodeId<CUInt128>()), blockNum,1);

		T_PGLOBALCONSENSUS pPeerInfos;
		pPeerInfos = (T_PGLOBALCONSENSUS)(pP2pProtocolGlobalBuddyReq + 1);

		int i = 0;
		ITR_LIST_T_LOCALCONSENSUS itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
		for (; itr != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itr++) {
			pPeerInfos[i].SetGlobalconsenus((*itr).GetPeer(), (*itr).GetLocalBlock(), 1);
			i++;
		}

		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
		g_tP2pManagerStatus.listGlobalBuddyChainInfo.push_back(g_tP2pManagerStatus.listLocalBuddyChainInfo);
		g_tP2pManagerStatus.tBuddyInfo.usChainNum = g_tP2pManagerStatus.listGlobalBuddyChainInfo.size();

		nodemgr->sendToAllNodes(msgbuf);
	}
}

void GlobalBuddyStartTask::execRespond()
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<GlobalBuddyRspTask>(_payload, _payloadlen));
}

void GlobalBuddyRspTask::exec()
{
	T_PP2PPROTOCOLGLOBALBUDDYREQ pP2pProtocolGlobalBuddyReqRecv = (T_PP2PPROTOCOLGLOBALBUDDYREQ)(const_cast<char*>(_buf.c_str()));

	if (!g_tP2pManagerStatus.StartGlobalFlag()) {
		return;
	}
	
	uint64 hyperblocknum = g_tP2pManagerStatus.GetConsensusHyperBlockID();
	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		if (g_tP2pManagerStatus.listLocalBuddyChainInfo.empty()) {
			return;
		}
	}

	bool isEndNodeBuddyChain = isEndNode();

	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH & me = nodemgr->myself();

	if (isEndNodeBuddyChain) {
		if (pP2pProtocolGlobalBuddyReqRecv->uiHyperBlockNum != hyperblocknum) {
			g_consensus_console_logger->error("Refuse GlobalBuddyReq for hyper block number error, local: {}, recv:{}",
				hyperblocknum, pP2pProtocolGlobalBuddyReqRecv->uiHyperBlockNum);
			return;
		}

		T_PGLOBALCONSENSUS  pLocalBlockTemp;
		pLocalBlockTemp = (T_PGLOBALCONSENSUS)(pP2pProtocolGlobalBuddyReqRecv + 1);

		LIST_T_LOCALCONSENSUS listLocalConsensusInfo;
		uint64 uiChainCountNum = 0;
		
		for (uint64 i = 0; i < pP2pProtocolGlobalBuddyReqRecv->GetBlockCount(); i++) {
			T_GLOBALCONSENSUS  localBlockInfo;
			localBlockInfo.SetLocalBlock((*(pLocalBlockTemp + i)).GetLocalBlock());
			localBlockInfo.SetPeer((*(pLocalBlockTemp + i)).GetPeer());
			localBlockInfo.SetChainNo((*(pLocalBlockTemp + i)).GetChainNo());

			T_LOCALCONSENSUS localInfo;
			localInfo.tLocalBlock = localBlockInfo.GetLocalBlock();
			localInfo.tPeer = localBlockInfo.GetPeer();

			if (uiChainCountNum != localBlockInfo.GetChainNo()) {
				uiChainCountNum = localBlockInfo.GetChainNo();
				if (listLocalConsensusInfo.size() != 0) {
					JudgExistAtGlobalBuddy(listLocalConsensusInfo);
					listLocalConsensusInfo.clear();
				}
			}
			  
			listLocalConsensusInfo.push_back(localInfo);

			if (i == pP2pProtocolGlobalBuddyReqRecv->GetBlockCount() - 1) {
				JudgExistAtGlobalBuddy(listLocalConsensusInfo);
				listLocalConsensusInfo.clear();
			}
		}

		T_PP2PPROTOCOLGLOBALBUDDYRSP pP2pProtocolGlobalBuddyRsp = NULL;
		uint32_t blockNum = 0;
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
		ITR_LIST_LIST_GLOBALBUDDYINFO itrGlobal = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
		for (; itrGlobal != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itrGlobal++) {
			blockNum += itrGlobal->size();
		}

		int ipP2pProtocolGlobalBuddyRspLen = sizeof(T_P2PPROTOCOLGLOBALBUDDYRSP) + blockNum * sizeof(T_GLOBALCONSENSUS);

		DataBuffer<GlobalBuddyRspTask> msgbuf(ipP2pProtocolGlobalBuddyRspLen);
		pP2pProtocolGlobalBuddyRsp = reinterpret_cast<T_PP2PPROTOCOLGLOBALBUDDYRSP>(msgbuf.payload());

		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);
		uint64 tempNum = g_tP2pManagerStatus.listGlobalBuddyChainInfo.size();
		pP2pProtocolGlobalBuddyRsp->uiHyperBlockNum = pP2pProtocolGlobalBuddyReqRecv->uiHyperBlockNum;
		pP2pProtocolGlobalBuddyRsp->SetResult(T_P2PPROTOCOLRSP(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GLOBAL_BUDDY_RSP, timeTemp.tv_sec), P2P_PROTOCOL_SUCCESS));
		pP2pProtocolGlobalBuddyRsp->SetBlockCount(blockNum);
		pP2pProtocolGlobalBuddyRsp->SetPeerAddr(T_PEERADDRESS(me->getNodeId<CUInt128>()));
		pP2pProtocolGlobalBuddyRsp->SetChainCount(tempNum);

		T_PGLOBALCONSENSUS pPeerInfos;
		pPeerInfos = (T_PGLOBALCONSENSUS)(pP2pProtocolGlobalBuddyRsp + 1);

		uint32_t i = 0;
		uint32_t chainNum = 0;
		itrGlobal = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
		for (; itrGlobal != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itrGlobal++) {
			chainNum++;
			ITR_LIST_T_LOCALCONSENSUS subItr = itrGlobal->begin();
			for (; subItr != itrGlobal->end(); subItr++) {
				pPeerInfos[i].SetLocalBlock((*subItr).GetLocalBlock());
				pPeerInfos[i].SetPeer((*subItr).GetPeer());
				pPeerInfos[i].SetChainNo(chainNum);
				i++;
			}
		}

		if (pP2pProtocolGlobalBuddyReqRecv->GetPeerAddr()._nodeid != me->getNodeId<CUInt128>()) {
			CUInt128 _peerid = pP2pProtocolGlobalBuddyReqRecv->GetPeerAddr()._nodeid;
			nodemgr->sendTo(_peerid, msgbuf);
		}
	} else {
		
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		auto endItr = g_tP2pManagerStatus.listLocalBuddyChainInfo.end();
		endItr--;

		DataBuffer<GlobalBuddySendTask> datamsgbuf(std::move(_buf));
		nodemgr->sendTo(endItr->GetPeer().GetPeerAddr()._nodeid, datamsgbuf);
	}
}

void GlobalBuddyRspTask::execRespond()
{
	if (!g_tP2pManagerStatus.StartGlobalFlag()) {
		return;
	}

	uint64 hyperblocknum = g_tP2pManagerStatus.GetConsensusHyperBlockID();
	T_PP2PPROTOCOLGLOBALBUDDYRSP pP2pProtocolGlobalBuddyRsp = (T_PP2PPROTOCOLGLOBALBUDDYRSP)(_payload);

	if (P2P_PROTOCOL_SUCCESS != pP2pProtocolGlobalBuddyRsp->GetResult().GetResult()) {
		return;
	}

	T_PGLOBALCONSENSUS  pLocalBlockTemp;
	pLocalBlockTemp = (T_PGLOBALCONSENSUS)(pP2pProtocolGlobalBuddyRsp + 1);

	LIST_T_LOCALCONSENSUS listLocalConsensusInfo;
	uint64 uiChainCountNum = 0;

	if (pP2pProtocolGlobalBuddyRsp->uiHyperBlockNum != hyperblocknum) {
		g_consensus_console_logger->error("Refuse GlobalBuddyRsp for hyper block number error, local: {}, recv:{}",
			g_tP2pManagerStatus.GetConsensusHyperBlockID(), pP2pProtocolGlobalBuddyRsp->uiHyperBlockNum);
		return;
	}

	for (uint64 i = 0; i < pP2pProtocolGlobalBuddyRsp->GetBlockCount(); i++) {
		T_GLOBALCONSENSUS  localBlockInfo;
		localBlockInfo.tLocalBlock = (*(pLocalBlockTemp + i)).GetLocalBlock();
		localBlockInfo.tPeer = (*(pLocalBlockTemp + i)).GetPeer();
		localBlockInfo.uiAtChainNum = (*(pLocalBlockTemp + i)).GetChainNo();

		T_LOCALCONSENSUS  blockInfo;
		blockInfo.SetLocalBlock(localBlockInfo.GetLocalBlock());
		blockInfo.SetPeer(localBlockInfo.GetPeer());

		if (uiChainCountNum != localBlockInfo.GetChainNo()) {
			uiChainCountNum = localBlockInfo.GetChainNo();
			if (listLocalConsensusInfo.size() != 0) {
				JudgExistAtGlobalBuddy(listLocalConsensusInfo);
				listLocalConsensusInfo.clear();
			}
		}

		listLocalConsensusInfo.push_back(blockInfo);
		char localHash[FILESIZES] = { 0 };
		CCommonStruct::Hash256ToStr(localHash, &localBlockInfo.GetLocalBlock().GetBlockBaseInfo().GetHashSelf());

		if (i == pP2pProtocolGlobalBuddyRsp->GetBlockCount() - 1) {
			JudgExistAtGlobalBuddy(listLocalConsensusInfo);
			listLocalConsensusInfo.clear();
		}
	}
}

void GlobalBuddySendTask::exec()
{
	if (!g_tP2pManagerStatus.StartGlobalFlag()) {
		return;
	}
	uint64 hyperblocknum = g_tP2pManagerStatus.GetConsensusHyperBlockID();

	if (!isEndNode()) {
		return;
	}

	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH & me = nodemgr->myself();

	T_PP2PPROTOCOLGLOBALBUDDYREQ pP2pProtocolGlobalBuddyReq = NULL;
	uint32_t blockNum = 0;
	CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
	ITR_LIST_LIST_GLOBALBUDDYINFO itr = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
	for (; itr != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itr++) {
		blockNum += itr->size();
	}

	int ipP2pProtocolGlobalBuddyReqLen = sizeof(T_P2PPROTOCOLGLOBALBUDDYREQ) + blockNum * sizeof(T_GLOBALCONSENSUS);
	DataBuffer<GlobalBuddySendTask> msgbuf(ipP2pProtocolGlobalBuddyReqLen);
	pP2pProtocolGlobalBuddyReq = reinterpret_cast<T_PP2PPROTOCOLGLOBALBUDDYREQ>(msgbuf.payload());

	struct timeval timeTemp;
	CCommonStruct::gettimeofday_update(&timeTemp);

	pP2pProtocolGlobalBuddyReq->uiHyperBlockNum = hyperblocknum;
	pP2pProtocolGlobalBuddyReq->SetP2pprotocolglobalconsensusreq(T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GLOBAL_BUDDY_REQ, timeTemp.tv_sec),
		T_PEERADDRESS(me->getNodeId<CUInt128>()), blockNum, g_tP2pManagerStatus.listGlobalBuddyChainInfo.size());

	T_PGLOBALCONSENSUS pPeerInfos;
	pPeerInfos = (T_PGLOBALCONSENSUS)(pP2pProtocolGlobalBuddyReq + 1);

	uint32_t i = 0;
	uint32_t chainNum = 0;
	ITR_LIST_LIST_GLOBALBUDDYINFO itrSend = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
	for (; itrSend != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itrSend++)
	{
		chainNum++;
		ITR_LIST_T_LOCALCONSENSUS subItr = itrSend->begin();
		for (; subItr != itrSend->end(); subItr++)
		{
			pPeerInfos[i].SetGlobalconsenus((*subItr).GetPeer(), (*subItr).GetLocalBlock(), chainNum);
			i++;

		/*	char localHash[FILESIZES] = { 0 };
			CCommonStruct::Hash256ToStr(localHash, &(*subItr).GetLocalBlock().GetBlockBaseInfo().GetHashSelf());*/
		}
	}
	g_consensus_console_logger->info("Boardcast My HyperBlock chain to do Global Consensus: {}", pP2pProtocolGlobalBuddyReq->uiHyperBlockNum);
	nodemgr->sendToAllNodes(msgbuf);
}

void GlobalBuddySendTask::execRespond()
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<GlobalBuddyRspTask>(_payload, _payloadlen));
}