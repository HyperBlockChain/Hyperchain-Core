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


#include <iostream>
using namespace std;

#include "../node/ITask.hpp"
#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "buddyinfo.h"
#include "headers/lambda.h"
#include "../crypto/sha2.h"
#include "../db/HyperchainDB.h"
#include <openssl/evp.h>

extern void ReOnChainFun();
extern void GetOnChainInfo();
extern void SaveHyperBlockToLocal(T_HYPERBLOCK &tHyperBlock);
extern void SaveLocalBlockToLocal(const T_HYPERBLOCK &tHyperBlock);
extern bool isEndNode();

class BoardcastHyperBlockTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::BOARDCAST_HYPER_BLOCK> {
public:
	using ITask::ITask;
	BoardcastHyperBlockTask() {};
	~BoardcastHyperBlockTask() {};

	void exec() override
	{
		if (!isEndNode()) {
			return;
		}

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		HCNodeSH & me = nodemgr->myself();

		DataBuffer<BoardcastHyperBlockTask> msgbuf(0);
		{
			CAutoMutexLock muxAuto(g_tP2pManagerStatus.m_MuxHchainBlockList);
			T_HYPERBLOCK &tHyperChainBlock = g_tP2pManagerStatus.GetPreHyperBlock();

			T_PP2PPROTOCOLCOPYHYPERBLOCKREQ pP2pProtocolCopyHyperBlockReq = nullptr;

			uint32_t blockNum = tHyperChainBlock.GetChildBlockCount();

			size_t ipP2pProtocolCopyHyperBlockReqLen = sizeof(T_P2PPROTOCOLCOPYHYPERBLOCKREQ) + sizeof(T_HYPERBLOCKSEND) + blockNum * sizeof(T_LOCALBLOCK);

			
			msgbuf.resize(ipP2pProtocolCopyHyperBlockReqLen);
			pP2pProtocolCopyHyperBlockReq = reinterpret_cast<T_PP2PPROTOCOLCOPYHYPERBLOCKREQ>(msgbuf.payload());

			T_P2PPROTOCOLTYPE pType;
			struct timeval timeTemp;
			CCommonStruct::gettimeofday_update(&timeTemp);
			pType.SetP2pprotocoltype(P2P_PROTOCOL_COPY_HYPER_BLOCK_REQ, timeTemp.tv_sec);
			T_PEERADDRESS pPeerAddr(me->getNodeId<CUInt128>());
			pP2pProtocolCopyHyperBlockReq->SetP2pprotocolcopyhyperblockreq(pType, pPeerAddr,
				tHyperChainBlock.GetBlockBaseInfo().GetID(), 3, blockNum, tHyperChainBlock.GetlistPayLoad().size());

			T_PHYPERBLOCKSEND pHyperBlockSend;
			pHyperBlockSend = (T_PHYPERBLOCKSEND)(pP2pProtocolCopyHyperBlockReq + 1);
			pHyperBlockSend->SetHyperBlockSend(tHyperChainBlock.GetBlockBaseInfo(), 
											tHyperChainBlock.GetMerkleHash(),
											tHyperChainBlock.version,tHyperChainBlock.difficulty);

			T_PLOCALBLOCK pPeerInfos;
			pPeerInfos = (T_PLOCALBLOCK)(pHyperBlockSend + 1);

			

			int i = 0;
			auto itrH = tHyperChainBlock.listPayLoad.begin();
			for (; itrH != tHyperChainBlock.listPayLoad.end(); itrH++) {
				ITR_LIST_T_LOCALBLOCK subItrH = (*itrH).begin();
				for (; subItrH != (*itrH).end(); subItrH++) {
					pPeerInfos[i] = (*subItrH);					
					i++;
				}
			}
		}
		
		nodemgr->sendToAllNodes(msgbuf);
	}

	void execRespond() override
	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxRecvHyperblock);
		if (!g_tP2pManagerStatus.isHyperblockReceivable) {
			return;
		}

		T_PP2PPROTOCOLCOPYHYPERBLOCKREQ pP2pProtocolCopyHyperBlockReqRecv = (T_PP2PPROTOCOLCOPYHYPERBLOCKREQ)(_payload);

		
		T_HYPERBLOCK hyperblock;
		T_PHYPERBLOCKSEND pHyperBlockInfosTemp;
		pHyperBlockInfosTemp = (T_PHYPERBLOCKSEND)(pP2pProtocolCopyHyperBlockReqRecv + 1);
		hyperblock.tBlockBaseInfo = pHyperBlockInfosTemp->GetBlockBaseInfo();
		hyperblock.tMerkleHashAll = pHyperBlockInfosTemp->GetHashAll();
		strncpy(hyperblock.version,pHyperBlockInfosTemp->version,MAX_VER_LEN);
		hyperblock.difficulty = pHyperBlockInfosTemp->difficulty;

		T_PLOCALBLOCK pLocalBlockTemp;
		pLocalBlockTemp = (T_PLOCALBLOCK)(pHyperBlockInfosTemp + 1);

		uint64 chainNumTemp = 1;
		LIST_T_LOCALBLOCK listLocakBlockTemp;
		for (uint64 i = 0; i < pP2pProtocolCopyHyperBlockReqRecv->GetBlockCount(); i++) {
			T_LOCALBLOCK pLocalTemp;
			pLocalTemp = *(pLocalBlockTemp + i);

			if (pLocalTemp.GetAtChainNum() == chainNumTemp) {
				listLocakBlockTemp.push_back(pLocalTemp);
			}
			else {
				listLocakBlockTemp.sort(CmpareOnChainLocal());
				hyperblock.listPayLoad.push_back(listLocakBlockTemp);
				chainNumTemp = pLocalTemp.GetAtChainNum();
				listLocakBlockTemp.clear();
				listLocakBlockTemp.push_back(pLocalTemp);
			}

			if (i == pP2pProtocolCopyHyperBlockReqRecv->GetBlockCount() - 1) {
				listLocakBlockTemp.sort(CmpareOnChainLocal());
				hyperblock.listPayLoad.push_back(listLocakBlockTemp);
			}
		}
		
		if (g_tP2pManagerStatus.updateHyperBlockCache(hyperblock)) {
			SaveHyperBlockToLocal(hyperblock);
			SaveLocalBlockToLocal(hyperblock);
		}
	}
};

class GetHyperBlockByNoReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_HYPERBLOCK_BY_NO_REQ> {
public:
	using ITask::ITask;
	GetHyperBlockByNoReqTask(uint64 blockNum)
	{
		m_blockNum = blockNum;
	}

	~GetHyperBlockByNoReqTask() {};

	void exec() override
	{
		struct timeval timePtr;
		CCommonStruct::gettimeofday_update(&timePtr);

		DataBuffer<GetHyperBlockByNoReqTask> msgbuf(sizeof(T_P2PPROTOCOLGETHYPERBLOCKBYNOREQ));
		T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ tGetHyperBlockByNoReq = reinterpret_cast<T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ>(msgbuf.payload());
		tGetHyperBlockByNoReq->SetP2pprotocolgethyperblockbynoreq(
								T_P2PPROTOCOLTYPE(P2P_PROTOCOL_GET_HYPERBLOCK_BY_NO_REQ, timePtr.tv_sec), m_blockNum);

		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		nodemgr->sendToAllNodes(msgbuf);
	}

	void execRespond() override
	{		
		NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
		HCNodeSH & me = nodemgr->myself();

		T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ pP2pProtocolGetHyperBlockByNoReq = (T_PP2PPROTOCOLGETHYPERBLOCKBYNOREQ)(_payload);
		uint64 reqblockNum = pP2pProtocolGetHyperBlockByNoReq->GetBlockNum();

		T_HYPERBLOCK hyperBlock;
		if (!g_tP2pManagerStatus.getHyperBlock(reqblockNum, hyperBlock)) {
			
			return;
		}

		
		T_PP2PPROTOCOLCOPYHYPERBLOCKREQ pP2pProtocolCopyHyperBlockReq = nullptr;

		uint32_t childblockcount = hyperBlock.GetChildBlockCount();

		size_t iHyperBlockLen = sizeof(T_P2PPROTOCOLCOPYHYPERBLOCKREQ) + 
												sizeof(T_HYPERBLOCKSEND) + 
												childblockcount * sizeof(T_LOCALBLOCK);

		
		DataBuffer<BoardcastHyperBlockTask> msgbuf(iHyperBlockLen);
		pP2pProtocolCopyHyperBlockReq = reinterpret_cast<T_PP2PPROTOCOLCOPYHYPERBLOCKREQ>(msgbuf.payload());

		T_P2PPROTOCOLTYPE pType;
		struct timeval timeTemp;
		CCommonStruct::gettimeofday_update(&timeTemp);
		pType.SetP2pprotocoltype(P2P_PROTOCOL_COPY_HYPER_BLOCK_REQ, timeTemp.tv_sec);
		T_PEERADDRESS pPeerAddr(me->getNodeId<CUInt128>());
		pP2pProtocolCopyHyperBlockReq->SetP2pprotocolcopyhyperblockreq(pType, pPeerAddr,
			hyperBlock.GetBlockBaseInfo().GetID(), 0, childblockcount, hyperBlock.GetlistPayLoad().size());

		T_PHYPERBLOCKSEND pHyperBlockSend;
		pHyperBlockSend = (T_PHYPERBLOCKSEND)(pP2pProtocolCopyHyperBlockReq + 1);
		pHyperBlockSend->SetHyperBlockSend(hyperBlock.GetBlockBaseInfo(), hyperBlock.GetMerkleHash(),
											hyperBlock.version, hyperBlock.difficulty);

		T_PLOCALBLOCK pPeerInfos;
		pPeerInfos = (T_PLOCALBLOCK)(pHyperBlockSend + 1);

		
		int i = 0;
		list<LIST_T_LOCALBLOCK>::iterator itrH = hyperBlock.listPayLoad.begin();
		for (; itrH != hyperBlock.listPayLoad.end(); itrH++) {
			ITR_LIST_T_LOCALBLOCK subItrH = itrH->begin();
			for (; subItrH != itrH->end(); subItrH++) {
				pPeerInfos[i] = *subItrH;
				
				i++;
			}
		}

		
		nodemgr->sendTo(_sentnodeid, msgbuf);
	}

	uint64_t m_blockNum;
};




