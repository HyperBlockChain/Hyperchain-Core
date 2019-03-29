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
#include "buddyinfo.h"
#include "onchaintask.hpp"
#include "onchainconfirmtask.hpp"
#include "../node/TaskThreadPool.h"
#include "db/HyperchainDB.h"
#include "consensus_engine.h"
#include "consensus/globalbuddytask.h"
#include "consensus/hyperblockTask.hpp"

#include "headers/commonstruct.h"
#include "headers/lambda.h"
#include "headers/inter_public.h"

#include "../node/IAccessPoint.h"
#include "../node/UdpAccessPoint.hpp"
#include "../HyperChain/HyperData.h"
#include "../HyperChain/HyperChainSpace.h"


#define MAX_BUF_LEN (1024 * 32)

void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type);
void ChangeLocalBlockPreHash(LIST_T_LOCALCONSENSUS &localList);
bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo);
void ReOnChainFun();
void GetOnChainInfo();
void updateMyBuddyBlock();
void SaveLocalBlockToLocal(const T_HYPERBLOCK &tHyperBlock);
void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum, const string &hash, uint8 type);
void mergeChains(LIST_T_LOCALCONSENSUS &globallist, LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo);
void CreateHyperBlock(T_HYPERBLOCK &tHyperChainBlock);
bool isConfirming(string &currBuddyHash);
bool isHyperBlockMatched(uint64 hyperblockid, const T_SHA256 &hash, const CUInt128 &peerid);
bool isEndNode();

void ConsensusEngine::TestOnchain()
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH & me = nodemgr->myself();

	UdpAccessPoint udpAP("127.0.0.1",0);
	HCNode::APList &aplist = me->getAPList();

	string strIP("127.0.0.1");
	auto ap = aplist.begin();
	if (ap != aplist.end() && udpAP.id() == ap->get()->id()) {
		strIP = (reinterpret_cast<UdpAccessPoint*>(ap->get()))->ip();
	}

	std::function<void(int)> sleepfn = [this](int sleepseconds) {
		int i = 0;
		int maxtimes = sleepseconds * 1000/200;
		while (i++ < maxtimes) {
			if (_isstoptest) {
				break;
			}
			this_thread::sleep_for(chrono::milliseconds(200));
		}
	};

	int i = 0;
	while (!_isstoptest) {
		size_t s = 0;
		{
			CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
			s = g_tP2pManagerStatus.GetListOnChainReq().size();
		}
		if (s > 3) {
			sleepfn(30);
			continue;
		}

		string sPayLoad = strIP + "-" + to_string(i);
		string requestid;

		AddNewBlockEx(sPayLoad, requestid);
		cout << "Created a test block: " << requestid << endl;

		i++;
		sleepfn(30);
	}
}

void ConsensusEngine::AddNewBlockEx(const string &strdata, string& requestid)
{
	g_tP2pManagerStatus.SetSendRegisReqNum(g_tP2pManagerStatus.GetSendRegisReqNum() + 1);
	g_tP2pManagerStatus.SetSendConfirmingRegisReqNum(g_tP2pManagerStatus.GetSendConfirmingRegisReqNum() + 1);

	T_FILEINFO pFileInfo(strdata);

	T_BLOCKBASEINFO pBaseInfo(time(NULL), (char*)AUTHKEY, (char*)BUDDYSCRIPT, T_SHA256(0));
	T_PRIVATEBLOCK tPrivateBlock(pBaseInfo, g_tP2pManagerStatus.GetPreHyperBlockHash(), pFileInfo);
	GetSHA256(tPrivateBlock.GetBlockBaseInfo().GetHashSelf().pID, (const char*)(&tPrivateBlock), sizeof(tPrivateBlock));

	T_BLOCKBASEINFO LBaseInfo(time(NULL), (char*)AUTHKEY, (char*)BUDDYSCRIPT, T_SHA256(0));

	T_SHA256 preHyperBlockHash;
	uint64 localprehyperblockid = 0;
	g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(localprehyperblockid, preHyperBlockHash);

	T_LOCALBLOCK tLocalBlock(LBaseInfo, 1, localprehyperblockid, preHyperBlockHash, 1, tPrivateBlock);

	GetSHA256(tLocalBlock.GetBlockBaseInfo().GetHashSelf().pID, (const char*)(&tLocalBlock), sizeof(tLocalBlock));
	requestid = tLocalBlock.getUUID(); 

	g_tP2pManagerStatus.trackLocalBlock(tLocalBlock);

	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH & me = nodemgr->myself();

	T_SHA256 h;
	GetSHA256(h.pID, pFileInfo.data(), pFileInfo.datalen());

	T_LOCALCONSENSUS LocalConsensusInfo(
		T_BLOCKSTATEADDR(T_PEERADDRESS(me->getNodeId<CUInt128>()), T_PEERADDRESS(me->getNodeId<CUInt128>())),
		tLocalBlock, 
		0,
		(char*)h.pID);

	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
	g_tP2pManagerStatus.GetListOnChainReq().push_back(std::move(LocalConsensusInfo));
	g_tP2pManagerStatus.SetSendPoeNum(g_tP2pManagerStatus.GetSendPoeNum() + 1);
}

void ConsensusEngine::start()
{
	g_tP2pManagerStatus.loadHyperBlockCache();
	if (g_tP2pManagerStatus.GetMaxBlockID() == 0) {
		GreateGenesisBlock();
	}

	_threads.emplace_back(std::thread(&ConsensusEngine::exec, this));
	_threads.emplace_back(std::thread(&ConsensusEngine::localBuddyReqThread, this));
	_threads.emplace_back(std::thread(&ConsensusEngine::localBuddyRspThread, this));
	_threads.emplace_back(std::thread(&ConsensusEngine::SearchOnChainStateThread, this));
	
	g_tP2pManagerStatus.tBuddyInfo.uiCurBuddyNo = g_tP2pManagerStatus.GetMaxBlockID() + 1;
	g_tP2pManagerStatus.tBuddyInfo.eBuddyState = IDLE;
}

void ConsensusEngine::stop()
{
	_isstop = true;
	for (auto& t : _threads) {
		t.join();
	}
	_threads.clear();
}

bool ConsensusEngine::checkConsensusCond()
{
	uint64 currMaxBlockNum = g_tP2pManagerStatus.GetMaxBlockID();
	CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
	uint64 maxBlockNum = hyperchainspace->GetGlobalLatestHyperBlockNo();

	if (maxBlockNum > currMaxBlockNum) {
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0 &&
			g_tP2pManagerStatus.GetListOnChainReq().size() > 0 ) {

			g_tP2pManagerStatus.setRecvHyperblockFlag(true);
			g_tP2pManagerStatus.SetHaveOnChainReq(true);
			if (!_is_requested_latest_hyperblock) {
				GetLatestHyperBlock();
				_is_requested_latest_hyperblock = true;
			}
			SLEEP(2 * ONE_SECOND);
		}
		_is_able_to_consensus = false;
	}
	else {

		g_tP2pManagerStatus.setRecvHyperblockFlag(false);
		_is_able_to_consensus = true;
	}

	return _is_able_to_consensus;
}

void ConsensusEngine::prepareLocalBuddy()
{
	if (g_tP2pManagerStatus.HaveOnChainReq()) {
		{
			CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);

			ReOnChainFun();
		}

		g_tP2pManagerStatus.SetHaveOnChainReq(false);
	}

	this_thread::sleep_for(chrono::milliseconds(200));
}

void ConsensusEngine::exec()
{
	bool indexGlobal = true;
	bool bFirstTimes = true;
	bool bCreatBlock = false;
	bool bNeedGetLastBlock = true;
	system_clock::time_point sendtimepoint = system_clock::now();
	while (!_isstop) {
		switch (g_tP2pManagerStatus.GetCurrentConsensusPhase())
		{
		case CONSENSUS_PHASE::PREPARE_LOCALBUDDY_PHASE:
			bFirstTimes = true;
			bNeedGetLastBlock = true;


			g_tP2pManagerStatus.setRecvHyperblockFlag(false);

			updateMyBuddyBlock();

			g_tP2pManagerStatus.cleanConsensusEnv();

			if (checkConsensusCond()) {
				prepareLocalBuddy();
			}
			break;
		case CONSENSUS_PHASE::LOCALBUDDY_PHASE:
		{
			if (!_is_able_to_consensus) {
				if (checkConsensusCond()) {
					prepareLocalBuddy();
				}
				break;
			}

			bCreatBlock = false;
			uint64 tempNum = 0;
			{
				CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
				tempNum = g_tP2pManagerStatus.listCurBuddyRsp.size();
			}
			if (tempNum != 0 ) {
				SLEEP(2 * ONE_SECOND);
				break;
			}

			indexGlobal = false;

			if (!g_tP2pManagerStatus.HaveOnChainReq()) {

				GetOnChainInfo();
			}

			uint64 tempNum2 = 0;
			{
				CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
				tempNum2 = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
			}

			if (tempNum2 == 0) {
				SLEEP(2 * ONE_SECOND);
				break;
			}

			g_consensus_console_logger->trace("The Node enter LOCAL_BUDDY status, broadcast Local Consensus Request");
			g_tP2pManagerStatus.tBuddyInfo.eBuddyState = LOCAL_BUDDY;

			SendLocalBuddyReq();
			SLEEP(10 * ONE_SECOND);

			break;
		}
		case CONSENSUS_PHASE::GLOBALBUDDY_PHASE:
		{
			uint64 tempNum = 0;
			{
				CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
				tempNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
			}
			if (tempNum == 0 || tempNum == 1) {
				SLEEP(2 * ONE_SECOND);
				break;
			}

			if (!indexGlobal) {
				indexGlobal = true;
				g_consensus_console_logger->trace("The Node enter GLOBAL_BUDDY status");
				g_tP2pManagerStatus.SetStartGlobalFlag(true);
				g_tP2pManagerStatus.tBuddyInfo.eBuddyState = GLOBAL_BUDDY;
				StartGlobalBuddy();
			}
			else {
				
				if(system_clock::now() - sendtimepoint > std::chrono::seconds(20)) {
					SendGlobalBuddyReq();
					sendtimepoint = system_clock::now();
				}
			}
			SLEEP(2 * ONE_SECOND);
			break;
		}
		case CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE:
		{

			g_tP2pManagerStatus.setRecvHyperblockFlag(true);

			g_tP2pManagerStatus.SetStartGlobalFlag(false);
			indexGlobal = false;
			_is_able_to_consensus = false;
			_is_requested_latest_hyperblock = false;

			uint64 tempNum = 0;
			uint64 tempNum1 = 0;

			if (bFirstTimes) {
				{
					CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
					tempNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();

					CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
					tempNum1 = g_tP2pManagerStatus.listGlobalBuddyChainInfo.size();
				}
				if (tempNum != 0 && tempNum1 != 0) {
					bCreatBlock = isEndNode();
					if (bCreatBlock) {
						
						T_HYPERBLOCK tHyperChainBlock;
						CreateHyperBlock(tHyperChainBlock);

						
						if (g_tP2pManagerStatus.updateHyperBlockCache(tHyperChainBlock)) {

							bNeedGetLastBlock = false;
							
							SaveHyperBlockToLocal(tHyperChainBlock);
							SaveLocalBlockToLocal(tHyperChainBlock);

							
							TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
							taskpool->put(make_shared<BoardcastHyperBlockTask>());
						}
					}
				}
				if (bNeedGetLastBlock) {
					GetLatestHyperBlock();
				}
				
				bFirstTimes = false;
			}
			SLEEP(5 * ONE_SECOND);
			break;
		}
		}
	}
}

void ConsensusEngine::localBuddyReqThread()
{
	while (!_isstop) {
		if (g_tP2pManagerStatus.GetCurrentConsensusPhase() != CONSENSUS_PHASE::LOCALBUDDY_PHASE) {
			{
				CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyReq);
				g_tP2pManagerStatus.listCurBuddyReq.clear();

				CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
				g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();
			}
			SLEEP(2 * ONE_SECOND);
			continue;
		}

		uint64 tempNum = 0;
		uint64 tempNum1 = 0;
		{
			CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyReq);
			tempNum1 = g_tP2pManagerStatus.listCurBuddyReq.size();

			CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
			tempNum = g_tP2pManagerStatus.listRecvLocalBuddyReq.size();
		}

		if (tempNum == 0) {
			SLEEP(2 * ONE_SECOND);
			continue;
		}

		if (tempNum1 > LIST_BUDDY_RSP_NUM) {
			SLEEP(2 * ONE_SECOND);
			continue;
		} else {
			T_BUDDYINFO localInfo;
			{
				CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
				localInfo = g_tP2pManagerStatus.listRecvLocalBuddyReq.front();
				g_tP2pManagerStatus.listRecvLocalBuddyReq.pop_front();
			}
			g_tP2pManagerStatus.tLocalBuddyAddr = localInfo.GetRequestAddress();

			TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
			taskpool->put(make_shared<OnChainRspTask>(localInfo.GetRequestAddress()._nodeid,
														std::move(localInfo.GetBuffer()),
														localInfo.GetBufferLength()));
		}
	}
}

void ConsensusEngine::localBuddyRspThread()
{
	while (!_isstop) {
		if (g_tP2pManagerStatus.GetCurrentConsensusPhase() != CONSENSUS_PHASE::LOCALBUDDY_PHASE) {
			{
				CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
				g_tP2pManagerStatus.listCurBuddyRsp.clear();

				CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
				g_tP2pManagerStatus.listRecvLocalBuddyRsp.clear();
			}
			SLEEP(2 * ONE_SECOND);
			continue;
		}

		uint64 tempNumTest = 0;
		uint64 tempNum = 0;
		{
			CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
			tempNum = g_tP2pManagerStatus.listCurBuddyRsp.size();

			CAutoMutexLock muxAuto2(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
			tempNumTest = g_tP2pManagerStatus.listRecvLocalBuddyRsp.size();
		}

		if (tempNumTest == 0) {
			SLEEP(2 * ONE_SECOND);
			continue;
		}

		if (tempNum > LIST_BUDDY_RSP_NUM) {
			SLEEP(2 * ONE_SECOND);
			continue;
		} else {
			T_BUDDYINFO localInfo;
			{
				CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
				localInfo = g_tP2pManagerStatus.listRecvLocalBuddyRsp.front();
				g_tP2pManagerStatus.listRecvLocalBuddyRsp.pop_front();
			}
			g_tP2pManagerStatus.tLocalBuddyAddr = localInfo.GetRequestAddress();

			ProcessOnChainRspMsg(localInfo.GetRequestAddress()._nodeid, 
				const_cast<char*>(localInfo.GetBuffer().c_str()), localInfo.GetBufferLength());
		}
	}
}

time_t convert_str_to_tm(const char * str_time)
{
	struct tm tt;
	memset(&tt, 0, sizeof(tt));
	tt.tm_year = atoi(str_time) - 1900;
	tt.tm_mon = atoi(str_time + 5) - 1;
	tt.tm_mday = atoi(str_time + 8);
	tt.tm_hour = atoi(str_time + 11);
	tt.tm_min = atoi(str_time + 14);
	tt.tm_sec = atoi(str_time + 17);
	return mktime(&tt);
}

const uint64 GENESISBLOCKID = -1;

void ConsensusEngine::GreateGenesisBlock()
{
	T_SHA512 h(1);
	ostringstream oss;
	oss << "Paralism Chain, 2019/1/17" << h.pID;
	T_FILEINFO fileInfo(oss.str());

	time_t t = convert_str_to_tm("2019-03-06 15:50:52");

	T_BLOCKBASEINFO PBaseInfo(t, (char*)AUTHKEY, (char*)BUDDYSCRIPT, T_SHA256(1), T_SHA256(1));
	T_PRIVATEBLOCK tPrivateBlock(PBaseInfo, T_SHA256(1), fileInfo);

	T_BLOCKBASEINFO LBaseInfo(t, (char*)AUTHKEY, (char*)BUDDYSCRIPT, T_SHA256(1), T_SHA256(1));
	
	T_LOCALBLOCK tLocalBlock(LBaseInfo, 1, GENESISBLOCKID, T_SHA256(1), tPrivateBlock);

	LIST_T_LOCALBLOCK ListLocalBlock;
	ListLocalBlock.push_back(tLocalBlock);

	T_HYPERBLOCK tHyperChainBlock;
	T_BLOCKBASEINFO HBaseInfo(t, (char*)AUTHKEY, (char*)BUDDYSCRIPT, T_SHA256(1), T_SHA256(1));

	tHyperChainBlock.SetBlockBaseInfo(HBaseInfo);
	tHyperChainBlock.SetMerkleHash(T_SHA256(1));
	tHyperChainBlock.PushBack(ListLocalBlock);

	g_tP2pManagerStatus.updateHyperBlockCache(tHyperChainBlock);
	SaveHyperBlockToLocal(tHyperChainBlock);

	g_tP2pManagerStatus.SetHaveOnChainReq(false);

}


void ConsensusEngine::ProcessOnChainRspMsg(const CUInt128 &peerid, char* pBuf, unsigned int uiBufLen)
{
	T_PP2PPROTOCOLONCHAINRSP pP2pProtocolOnChainRspRecv = (T_PP2PPROTOCOLONCHAINRSP)(pBuf);

	size_t nodeSize = 0;
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	nodeSize = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();
	if (nodeSize == 0) {
		return;
	}

	if (nodeSize != ONE_LOCAL_BLOCK && pP2pProtocolOnChainRspRecv->GetBlockCount() != ONE_LOCAL_BLOCK) {
		return;
	}


	uint64 hyperchainnum = pP2pProtocolOnChainRspRecv->GetHyperBlockNum();
	if (!isHyperBlockMatched(hyperchainnum,pP2pProtocolOnChainRspRecv->tHyperBlockHash,peerid)) {
		g_consensus_console_logger->info("Refuse buddy request for different hyper block from {}", peerid.ToHexString());
		SendRefuseReq(peerid, 
			string(pP2pProtocolOnChainRspRecv->GetHash(), DEF_STR_HASH256_LEN) , RECV_REQ);
		return;
	}


	CAutoMutexLock muxAuto3(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
	ITR_LIST_T_BUDDYINFOSTATE itr = g_tP2pManagerStatus.listCurBuddyRsp.begin();
	for (; itr != g_tP2pManagerStatus.listCurBuddyRsp.end(); itr++) {
		if (0 == strncmp((*itr).strBuddyHash, pP2pProtocolOnChainRspRecv->GetHash(), DEF_STR_HASH256_LEN)) {
			return;
		}
	}

	T_BUDDYINFOSTATE buddyInfo;
	copyLocalBuddyList(buddyInfo.localList, g_tP2pManagerStatus.listLocalBuddyChainInfo);

	T_PLOCALCONSENSUS  pLocalBlockTemp;
	pLocalBlockTemp = (T_PLOCALCONSENSUS)(pP2pProtocolOnChainRspRecv + 1);

	bool index = false;
	bool isExistMyBlock = false;
	NodeManager *nodemanger = Singleton<NodeManager>::getInstance();
	HCNodeSH me = nodemanger->myself();


	for (uint64 i = 0; i < pP2pProtocolOnChainRspRecv->GetBlockCount(); i++) {
		T_LOCALCONSENSUS  LocalBlockInfo;
		LocalBlockInfo = *(pLocalBlockTemp + i);

		isExistMyBlock = false;
		if (LocalBlockInfo.GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
			isExistMyBlock = true;
		}
		index = JudgExistAtLocalBuddy(buddyInfo.GetList(), LocalBlockInfo);
		if (isExistMyBlock && !index) {

			g_consensus_console_logger->error("There are my two blocks in a consensus period,Skip...");
			
			return;
		}

		if (index)
			continue;

		buddyInfo.LocalListPushBack(LocalBlockInfo);

		buddyInfo.LocalListSort();
		ChangeLocalBlockPreHash(buddyInfo.GetLocalConsensus());
	}

	buddyInfo.Set(pP2pProtocolOnChainRspRecv->GetHash(), RECV_ON_CHAIN_RSP, _tpeeraddress(peerid));


	g_tP2pManagerStatus.listCurBuddyRsp.push_back(buddyInfo);

	
	
	for (auto &buddy : g_tP2pManagerStatus.listCurBuddyRsp) {
		if (buddy.GetBuddyState() == SEND_CONFIRM) {
			return;
		}
	}
	SendConfirmReq(peerid, pP2pProtocolOnChainRspRecv->uiHyperBlockNum,
		pP2pProtocolOnChainRspRecv->GetHash(), P2P_PROTOCOL_SUCCESS);
}

void GetOnChainInfo()
{
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	{
		if (g_tP2pManagerStatus.listOnChainReq.empty()) {
			g_tP2pManagerStatus.tBuddyInfo.eBuddyState = IDLE;
			return;
		}

		T_LOCALCONSENSUS onChainInfo;
		onChainInfo = g_tP2pManagerStatus.listOnChainReq.front();
		g_tP2pManagerStatus.listOnChainReq.pop_front();

		g_tP2pManagerStatus.listLocalBuddyChainInfo.push_back(onChainInfo);

		g_consensus_console_logger->info("GetOnChainInfo,listLocalBuddyChainInfo phase:{} push a block:{}",
			(uint8)g_tP2pManagerStatus.GetCurrentConsensusPhase(),
			onChainInfo.GetLocalBlock().GetPayLoad().GetPayLoad());

		g_tP2pManagerStatus.listLocalBuddyChainInfo.sort(CmpareOnChain());
		ChangeLocalBlockPreHash(g_tP2pManagerStatus.listLocalBuddyChainInfo);

		int i = 0;
		for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
			g_consensus_console_logger->info("GetOnChainInfo,listLocalBuddyChainInfo:{} {}", ++i, b.GetLocalBlock().GetPayLoad().GetPayLoad());
		}

		g_tP2pManagerStatus.tBuddyInfo.usBlockNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();

		g_tP2pManagerStatus.tBuddyInfo.uiCurBuddyNo = g_tP2pManagerStatus.GetMaxBlockID() + 1;
		g_tP2pManagerStatus.tBuddyInfo.eBuddyState = LOCAL_BUDDY;
		g_tP2pManagerStatus.uiNodeState = CONFIRMING;

		g_tP2pManagerStatus.curBuddyBlock = onChainInfo;

	}

	g_tP2pManagerStatus.SetHaveOnChainReq(true);

	return;
}

void SendConfirmReq(const CUInt128 &peerid, uint64 hyperblocknum, const string &hash, uint8 type)
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<OnChainConfirmTask>(peerid, hyperblocknum, hash, type));
}

void ConsensusEngine::SendLocalBuddyReq()
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<OnChainTask>());
}

void copyLocalBuddyList(LIST_T_LOCALCONSENSUS &endList, LIST_T_LOCALCONSENSUS fromList)
{
	ITR_LIST_T_LOCALCONSENSUS itrList = fromList.begin();
	for (; itrList != fromList.end(); itrList++)
	{
		T_LOCALCONSENSUS tempBlock;
		tempBlock.SetLoaclConsensus((*itrList).GetPeer(), (*itrList).GetLocalBlock());
		endList.push_back(tempBlock);
	}
}

void SaveLocalBlockToLocal(const T_HYPERBLOCK &tHyperBlock)
{
	auto subItr = tHyperBlock.GetlistPayLoad().begin();
	for (; subItr != tHyperBlock.GetlistPayLoad().end(); subItr++)
	{
		auto ssubItr = (*subItr).begin();
		for (; ssubItr != (*subItr).end(); ssubItr++)
		{
			string spayload;
			spayload.append((*ssubItr).tPayLoad.GetPayLoad().data(), (*ssubItr).tPayLoad.GetPayLoad().datalen());

			T_HYPERBLOCKDBINFO hyperBlockInfo(T_SHA256(0), 
				tHyperBlock.GetBlockBaseInfo().GetHashSelf(), 
				(*ssubItr).GetBlockBaseInfo().GetHashSelf(), (*ssubItr).GetBlockBaseInfo().GetPreHash(), spayload,
				(*ssubItr).GetBlockBaseInfo().GetScript(), (*ssubItr).GetBlockBaseInfo().GetAuth(), 
				LOCAL_BLOCK, 
				(*ssubItr).GetBlockBaseInfo().GetID(),	
				tHyperBlock.GetBlockBaseInfo().GetID(),
				(*ssubItr).GetBlockBaseInfo().GetTime(), 
				(*ssubItr).GetAtChainNum(),
				0,	
				(*ssubItr).version,
				(*ssubItr).difficulty);

			CHyperchainDB::saveHyperBlockToDB(hyperBlockInfo);
		}
	}
}

void SendRefuseReq(const CUInt128 &peerid, const string &hash, uint8 type)
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<OnChainRefuseTask>(peerid,hash,type));
}

void ChangeLocalBlockPreHash(LIST_T_LOCALCONSENSUS &localList)
{
	int localSize = localList.size();
	ITR_LIST_T_LOCALCONSENSUS itr = localList.begin();
	ITR_LIST_T_LOCALCONSENSUS itrNext = itr++;
	itrNext->GetLocalBlock().GetBlockBaseInfo().GetPreHash().SetInit(0);

	uint16 num = 1;
	while (num < localSize) {
		(*itr).GetLocalBlock().GetBlockBaseInfo().SetPreHash((*itrNext).GetLocalBlock().GetBlockBaseInfo().GetHashSelf());
		itr++;
		itrNext++;
		num += 1;
	}
}

void SendCopyLocalBlock(T_LOCALCONSENSUS &localBlock)
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<CopyBlockTask>(localBlock));
}

bool JudgExistAtLocalBuddy(LIST_T_LOCALCONSENSUS localList, T_LOCALCONSENSUS localBlockInfo)
{
	bool index = false;
	ITR_LIST_T_LOCALCONSENSUS itrList = localList.begin();
	for (; itrList != localList.end(); itrList++) {
		if (((*itrList).GetPeer().GetPeerAddr() == localBlockInfo.GetPeer().GetPeerAddr())
			&& ((*itrList).GetPeer().GetPeerAddrOut() == localBlockInfo.GetPeer().GetPeerAddrOut())
			&& (*itrList).GetLocalBlock().GetBlockBaseInfo().GetHashSelf() == localBlockInfo.GetLocalBlock().GetBlockBaseInfo().GetHashSelf()) {
			index = true;
			break;
		}
	}
	return index;
}

bool JudgExistAtGlobalBuddy(LIST_T_LOCALCONSENSUS &listLocalBuddyChainInfo)
{
	bool isNewChain = true;
	int num = 0;
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
	ITR_LIST_LIST_GLOBALBUDDYINFO itr = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
	for (; itr != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); itr++) {
		num++;

		int globalchainlen = itr->size();
		int localchainlen = listLocalBuddyChainInfo.size();

		LIST_T_LOCALCONSENSUS *localchain = &listLocalBuddyChainInfo;
		LIST_T_LOCALCONSENSUS *globalchain = &(*itr);
		if (globalchainlen < localchainlen) {

			globalchain = &listLocalBuddyChainInfo;
			localchain = &(*itr);
		}
		auto globalblock = globalchain->begin();
		auto localblock = localchain->begin();

		bool isContained = true;
		LIST_T_LOCALCONSENSUS sameblocklist;
		for (; localblock != localchain->end(); localblock++) {
			globalblock = globalchain->begin();
			for (; globalblock != globalchain->end() && isContained; globalblock++) {
				if ((localblock->GetLocalBlock().GetBlockBaseInfo().GetHashSelf()
					== globalblock->GetLocalBlock().GetBlockBaseInfo().GetHashSelf())) {
					
					sameblocklist.push_back(*localblock);
					break;
				}
			}
			if (globalblock == globalchain->end()) {
				isContained = false;
				break;
			}
		}

		int sameblocknumber = sameblocklist.size();
		if (sameblocknumber > 0 && !isContained) {

			if (sameblocknumber > 1) {
				
				g_consensus_console_logger->info("merge two chains");
				mergeChains(*itr, listLocalBuddyChainInfo);
				return false;
			
			} else {
				
				
				g_consensus_console_logger->critical("Two chains have {} same block: ", sameblocknumber);
				for (auto &b : listLocalBuddyChainInfo) {
					g_consensus_console_logger->critical("ReceivedChainInfo block: {} {}", 
						b.tLocalBlock.GetBlockBaseInfo().GetID(),
						b.tLocalBlock.GetPayLoad().GetPayLoad());
				}
				for (auto &b : *itr) {
					g_consensus_console_logger->critical("ExistedChainInfo block is: {} {}", 
						b.tLocalBlock.GetBlockBaseInfo().GetID(),
						b.tLocalBlock.GetPayLoad().GetPayLoad());
				}
				for (auto &b : sameblocklist) {
					g_consensus_console_logger->critical("same block is: {} {}",
						b.tLocalBlock.GetBlockBaseInfo().GetID(),
						b.tLocalBlock.GetPayLoad().GetPayLoad());
				}
			}
		}
		
		if (sameblocknumber == 0 && !isContained) {
			continue;
		}
		if (isContained) {
			if (globalchainlen == localchainlen) {
				g_consensus_console_logger->trace("The chain is same with another one.");
			}
			else {
				g_consensus_console_logger->warn("The chain contains another one.");
			}
			if (globalchainlen < localchainlen) {
				g_tP2pManagerStatus.listGlobalBuddyChainInfo.erase(itr);
				isNewChain = true;
			} else {
				isNewChain = false;
			}
			break;
		}
	}

	if (isNewChain) {
		if (listLocalBuddyChainInfo.size() >= LEAST_START_GLOBAL_BUDDY_NUM) {
			g_tP2pManagerStatus.listGlobalBuddyChainInfo.push_back(listLocalBuddyChainInfo);
			g_tP2pManagerStatus.tBuddyInfo.usChainNum = g_tP2pManagerStatus.listGlobalBuddyChainInfo.size();
			g_tP2pManagerStatus.listGlobalBuddyChainInfo.sort(CmpareGlobalBuddy());
		}
	}

	return isNewChain;
}

void mergeChains(LIST_T_LOCALCONSENSUS &globallist,LIST_T_LOCALCONSENSUS &locallist)
{
	for (auto &localblock : locallist) {
		auto r = std::find_if(globallist.begin(), globallist.end(), [&](const T_LOCALCONSENSUS &globalblock) {
			if ((localblock.GetLocalBlock().GetBlockBaseInfo().GetHashSelf()
				== globalblock.GetLocalBlock().GetBlockBaseInfo().GetHashSelf())) {
				return true;
			}
			return false;
		});

		if (r == globallist.end()) {
			globallist.emplace_back(localblock);
		}
	}
}


void ReOnChainFun()
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH me = nodemgr->myself();

	T_LOCALCONSENSUS localInfo;
	ITR_LIST_T_LOCALCONSENSUS itrList = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
	for (; itrList != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itrList++) {
		if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
			localInfo = (*itrList);

			localInfo.uiRetryTime += 1;
			g_tP2pManagerStatus.listLocalBuddyChainInfo.clear();
			g_tP2pManagerStatus.listOnChainReq.push_front(localInfo);
			g_consensus_console_logger->info("***ReOnChainFun***: phase:{} block:{}",
						(uint8)g_tP2pManagerStatus.GetCurrentConsensusPhase(), 
						localInfo.GetLocalBlock().GetPayLoad().GetPayLoad());
			break;
		}
	}
}

bool CurBuddyBlockInTheHyperBlock(T_HYPERBLOCK &blockInfos, T_LOCALCONSENSUS *buddyblock)
{
	bool index = false;
	list<LIST_T_LOCALBLOCK>::iterator itr = blockInfos.GetlistPayLoad().begin();
	for (; itr != blockInfos.GetlistPayLoad().end(); itr++) {
		ITR_LIST_T_LOCALBLOCK subItr = itr->begin();
		for (; subItr != itr->end(); subItr++) {
			if (subItr->GetBlockBaseInfo().GetHashSelf() == buddyblock->GetLocalBlock().GetBlockBaseInfo().GetHashSelf()) {
				index = true;
				break;
			}
		}

		if (index) {
			break;
		}
	}
	return index;
}


void updateMyBuddyBlock()
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH me = nodemgr->myself();

	
	bool isfound = false;
	T_LOCALCONSENSUS *localInfo;
	CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0) {
		return;
	}
	ITR_LIST_T_LOCALCONSENSUS itrList = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
	for (; itrList != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itrList++) {
		if ((*itrList).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
			localInfo = &(*itrList);
			isfound = true;
			break;
		}
	}

	bool isIncluded = false;
	if(isfound)	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.m_MuxHchainBlockList);
		isIncluded = CurBuddyBlockInTheHyperBlock(g_tP2pManagerStatus.GetPreHyperBlock(), localInfo);
	}
	g_consensus_console_logger->info("updateMyBuddyBlock: current buddy block included in hyperblock? {}", isIncluded);
	if (!isIncluded) {
		ReOnChainFun();
	}
	else {
		
		g_tP2pManagerStatus.uiSendConfirmingRegisReqNum -= 1;
		g_tP2pManagerStatus.listLocalBuddyChainInfo.clear();
	}
}


void ConsensusEngine::StartGlobalBuddy()
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<GlobalBuddyStartTask>());
}

void ConsensusEngine::SendGlobalBuddyReq()
{
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
	taskpool->put(make_shared<GlobalBuddySendTask>());
}


void ConsensusEngine::GetLatestHyperBlock()
{
	if (g_tP2pManagerStatus.HaveOnChainReq()) {
		uint64 localHID = g_tP2pManagerStatus.GetMaxBlockID();
		CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
		uint64 globalHID = hyperchainspace->GetGlobalLatestHyperBlockNo();

		if (globalHID > localHID) {
			
			hyperchainspace->GetRemoteHyperBlockByID(globalHID);

			g_consensus_console_logger->info("Downloading Hyperblock {} from Hyperchain network.", globalHID);
		}
	}
}

void ConsensusEngine::WriteBlockLog(T_HYPERBLOCK hyperBlock)
{
	string strStatuFile = g_confFile.strLogDir;
	strStatuFile += "p2p_status.log";

	FILE* fp = fopen(strStatuFile.c_str(), "a");
	if (NULL == fp)
		return;

	string strTxt("");
	strTxt = getBlockInfo(hyperBlock);
	fprintf(fp, "%s\n", strTxt.c_str());
	fflush(fp);

	fclose(fp);
}

string ConsensusEngine::getBlockInfo(T_HYPERBLOCK hyperBlock)
{

	string retData = "";
	char buf[BUFFERLEN] = { 0 };
	retData += "==================BLOCKINFO==================\n";

	{
		retData += "Block No:	";
		memset(buf, 0, BUFFERLEN);
#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__MSVCRT__)
		sprintf(buf, "%I64d\n", hyperBlock.GetBlockBaseInfo().GetID());
#else
		sprintf(buf, "%lu\n", hyperBlock.GetBlockBaseInfo().GetID());
#endif

		retData += buf;

		retData += "Block Hash:	";
		memset(buf, 0, BUFFERLEN);
		retData += "0x";
		CCommonStruct::Hash256ToStr(buf, &hyperBlock.GetBlockBaseInfo().GetHashSelf());
		retData += buf;
		retData += "\n";

		retData += "Time:		";
		memset(buf, 0, BUFFERLEN);
		struct tm * t;
		uint64 time = hyperBlock.GetBlockBaseInfo().GetTime();
		t = localtime((time_t*)&(time));
		sprintf(buf, "%d-%d-%d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
		retData += buf;

		retData += "Previous Hash:	";
		retData += "0x";
		memset(buf, 0, BUFFERLEN);
		CCommonStruct::Hash256ToStr(buf, &hyperBlock.GetBlockBaseInfo().GetPreHash());
		retData += buf;
		retData += "\n";

		retData += "Extra:		";
		retData += "chainbeta9 (Raw: 0x657696e646865726d52d657539)\n";

		retData += "Payload:\n";

		retData += "\n";

		uint16 chainNum = 0;

		list<LIST_T_LOCALBLOCK>::iterator subItr = hyperBlock.GetlistPayLoad().begin();
		for (; subItr != hyperBlock.GetlistPayLoad().end(); subItr++) {
			chainNum += 1;
			list<T_LOCALBLOCK>::iterator ssubItr = (*subItr).begin();
			for (; ssubItr != (*subItr).end(); ssubItr++) {
				T_PLOCALBLOCK localBlock = &(*ssubItr);

				T_PPRIVATEBLOCK privateBlock = &(localBlock->GetPayLoad());
				T_FILEINFO &fileInfo = privateBlock->GetPayLoad();

				retData += "HyperBlockHash:	";
				memset(buf, 0, BUFFERLEN);
				retData += "0x";
				CCommonStruct::Hash256ToStr(buf, &hyperBlock.GetBlockBaseInfo().GetHashSelf());
				retData += buf;
				retData += "";

				retData += "AtChainNum:";
				memset(buf, 0, BUFFERLEN);
				sprintf(buf, "%u ", chainNum);
				retData += buf;

				retData += "LocalBlockHash:";
				memset(buf, 0, BUFFERLEN);
				retData += "0x";
				CCommonStruct::Hash256ToStr(buf, &localBlock->GetBlockBaseInfo().GetHashSelf());
				retData += buf;
				retData += "";


				retData += "Payload hash=";
				memset(buf, 0, BUFFERLEN);
				T_SHA256 h;
				GetSHA256(h.pID, fileInfo.data(), fileInfo.datalen());
				CCommonStruct::Hash256ToStr(buf, &h);
				retData += buf;
				retData += "";

				retData += "Payload size=";
				memset(buf, 0, BUFFERLEN);
				sprintf(buf, "%zu\n", fileInfo.datalen());

				retData += buf;

				retData += "\n";

			}
		}
	}

	retData += "================================================\n";
	return retData;
}

void SaveHyperBlockToLocal(T_HYPERBLOCK &tHyperBlock)
{
	T_HYPERBLOCKDBINFO hyperBlockInfo(tHyperBlock.GetMerkleHash(), 
		tHyperBlock.GetBlockBaseInfo().GetHashSelf(), 
		tHyperBlock.GetBlockBaseInfo().GetHashSelf(), 
		tHyperBlock.GetBlockBaseInfo().GetPreHash(), "", 
		tHyperBlock.GetBlockBaseInfo().GetScript(),
		tHyperBlock.GetBlockBaseInfo().GetAuth(), 
		HYPER_BLOCK, 
		tHyperBlock.GetBlockBaseInfo().GetID(), 
		tHyperBlock.GetBlockBaseInfo().GetID(), 
		tHyperBlock.GetBlockBaseInfo().GetTime(), 
		0,
		tHyperBlock.GetVersionString(),
		tHyperBlock.difficulty);

	CHyperchainDB::saveHyperBlockToDB(hyperBlockInfo);
}

ONCHAINSTATUS ConsensusEngine::GetOnChainState(const LB_UUID& requestId, T_LOCALBLOCKADDRESS &addr)
{
	addr.hid = -1;
	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
		LIST_T_LOCALCONSENSUS::iterator itrOnChain = g_tP2pManagerStatus.listOnChainReq.begin();
		for (; itrOnChain != g_tP2pManagerStatus.listOnChainReq.end(); itrOnChain++) {
			if (0 == requestId.compare((*itrOnChain).GetLocalBlockUUID().c_str())) {
				return ONCHAINSTATUS::waiting;
			}
		}
	}

	{
		CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
		LIST_T_LOCALCONSENSUS::iterator itrOnChaining = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
		for (; itrOnChaining != g_tP2pManagerStatus.listLocalBuddyChainInfo.end(); itrOnChaining++) {
			if (0 == requestId.compare((*itrOnChaining).GetLocalBlockUUID().c_str())) {
				return ONCHAINSTATUS::onchaining;
			}
		}
	}

	return ONCHAINSTATUS::unknown;
}

bool ConsensusEngine::CheckSearchOnChainedPool(const LB_UUID& requestId, T_LOCALBLOCKADDRESS& addr)
{
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxMapSearchOnChain);
	if (g_tP2pManagerStatus.mapSearchOnChain.count(requestId) > 0) {
		addr = g_tP2pManagerStatus.mapSearchOnChain.at(requestId).addr;
		return true;
	}
	return false;
}


void ConsensusEngine::SearchOnChainStateThread()
{
	std::function<void(int)> sleepfn = [this](int sleepseconds) {
		int i = 0;
		int maxtimes = sleepseconds * 1000 / 200;
		while (i++ < maxtimes) {
			if (_isstop) {
				break;
			}
			this_thread::sleep_for(chrono::milliseconds(200));
		}
	};
	while (_isstop)
	{
		{
			CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxMapSearchOnChain);
			ITR_MAP_T_SEARCHONCHAIN itr = g_tP2pManagerStatus.mapSearchOnChain.begin();
			for (; itr != g_tP2pManagerStatus.mapSearchOnChain.end();) {
				T_LOCALBLOCKADDRESS addr;
				ONCHAINSTATUS status = GetOnChainState((*itr).first, addr);
				uint64 timeNow = (uint64)time(nullptr);
				if ( timeNow - (*itr).second.uiTime > MATURITY_TIME &&
					status == ONCHAINSTATUS::unknown ) {

					itr = g_tP2pManagerStatus.mapSearchOnChain.erase(itr);
				}
				else {
					itr++;
				}
			}
		}
	
		sleepfn(5 * 60);
	}
}

LIST_T_LOCALCONSENSUS ConsensusEngine::GetPoeRecordList()
{
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistOnChainReq);
	return g_tP2pManagerStatus.listOnChainReq;
}

uint16 ConsensusEngine::GetStateOfCurrentConsensus(uint64 &blockNo, uint16 &blockNum, uint16 &chainNum)
{
	blockNo = g_tP2pManagerStatus.GetBuddyInfo().GetCurBuddyNo();
	blockNum = g_tP2pManagerStatus.GetBuddyInfo().GetBlockNum();
	chainNum = g_tP2pManagerStatus.GetBuddyInfo().GetChainNum();

	return g_tP2pManagerStatus.GetBuddyInfo().GetBuddyState();
}

void PutIntoConsensusList(T_BUDDYINFOSTATE &buddyinfostate)
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH & me = nodemgr->myself();

	buddyinfostate.uibuddyState = CONSENSUS_CONFIRMED;
	bool index = false;
	
	ITR_LIST_T_LOCALCONSENSUS itrSub = buddyinfostate.localList.begin();
	for (; itrSub != buddyinfostate.localList.end(); itrSub++) {
		index = JudgExistAtLocalBuddy(g_tP2pManagerStatus.listLocalBuddyChainInfo, (*itrSub));
		if (index)
			continue;

		g_consensus_console_logger->info("PutIntoConsensusList: push block into listLocalBuddyChainInfo: {}",
			(*itrSub).GetLocalBlock().GetPayLoad().GetPayLoad());
		g_tP2pManagerStatus.listLocalBuddyChainInfo.push_back((*itrSub));
		g_tP2pManagerStatus.listLocalBuddyChainInfo.sort(CmpareOnChain());
		ChangeLocalBlockPreHash(g_tP2pManagerStatus.listLocalBuddyChainInfo);
		g_tP2pManagerStatus.tBuddyInfo.usBlockNum = g_tP2pManagerStatus.listLocalBuddyChainInfo.size();

		if ((*itrSub).GetPeer().GetPeerAddr()._nodeid != me->getNodeId<CUInt128>()) {
			g_tP2pManagerStatus.SetRecvPoeNum(g_tP2pManagerStatus.GetRecvPoeNum() + 1);
		}
		SendCopyLocalBlock((*itrSub));

		g_tP2pManagerStatus.SetRecvRegisReqNum(g_tP2pManagerStatus.GetRecvRegisReqNum() + 1);
		g_tP2pManagerStatus.SetRecvConfirmingRegisReqNum(g_tP2pManagerStatus.GetRecvConfirmingRegisReqNum() + 1);
	}
}

bool makeBuddy(const string & confirmhash)
{
	bool ismakebuddy = false;
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	{
		CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
		ITR_LIST_T_BUDDYINFOSTATE itrRsp = g_tP2pManagerStatus.listCurBuddyRsp.begin();
		for (; itrRsp != g_tP2pManagerStatus.listCurBuddyRsp.end();) {
			if (0 == strncmp((*itrRsp).strBuddyHash, confirmhash.c_str(), DEF_STR_HASH256_LEN)) {
				(*itrRsp).uibuddyState = CONSENSUS_CONFIRMED;
			}
			else if((*itrRsp).GetBuddyState() != CONSENSUS_CONFIRMED) {
				SendRefuseReq((*itrRsp).GetPeerAddrOut()._nodeid,
					string((*itrRsp).strBuddyHash, DEF_STR_HASH256_LEN), RECV_REQ);
				itrRsp = g_tP2pManagerStatus.listCurBuddyRsp.erase(itrRsp);
				continue;
			}
			++itrRsp;
		}
	}

	{
		CAutoMutexLock muxAutoReq(g_tP2pManagerStatus.MuxlistCurBuddyReq);

		auto itr = g_tP2pManagerStatus.listCurBuddyReq.begin();
		for (; itr != g_tP2pManagerStatus.listCurBuddyReq.end();) {
			if (0 == strncmp((*itr).strBuddyHash, confirmhash.c_str(), DEF_STR_HASH256_LEN) && (*itr).uibuddyState != CONSENSUS_CONFIRMED) {
				PutIntoConsensusList(*itr);
				int i = 0;
				for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
					g_consensus_console_logger->info("makeBuddy: listLocalBuddyChainInfo: {} {}", ++i, b.GetLocalBlock().GetPayLoad().GetPayLoad());
				}
				ismakebuddy = true;
			}
			else if((*itr).GetBuddyState() != CONSENSUS_CONFIRMED) {
				SendRefuseReq((*itr).GetPeerAddrOut()._nodeid,
					string((*itr).strBuddyHash, DEF_STR_HASH256_LEN), RECV_RSP);
				itr = g_tP2pManagerStatus.listCurBuddyReq.erase(itr);
				continue;
			}
			++itr;
		}
	}

	g_consensus_console_logger->info("makeBuddy: listCurBuddyReq size: {} listCurBuddyRsp size: {}, makebuddy:{}",
		g_tP2pManagerStatus.listCurBuddyReq.size(),
		g_tP2pManagerStatus.listCurBuddyRsp.size(), ismakebuddy);

	if (ismakebuddy) {
		CAutoMutexLock muxAuto2(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
		g_tP2pManagerStatus.listRecvLocalBuddyRsp.clear();

		CAutoMutexLock muxAuto3(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
		g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();
	}
	return ismakebuddy;
}

bool isConfirming(string &currBuddyHash)
{
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
	for (auto &buddy : g_tP2pManagerStatus.listCurBuddyRsp) {
		if (buddy.GetBuddyState() == SEND_CONFIRM) {
			currBuddyHash = string(buddy.GetBuddyHash(), DEF_STR_HASH256_LEN);
			return true;
		}
	}
	return false;
}

T_SHA256& computeHyperBlockHash(T_HYPERBLOCK &tHyperChainBlock)
{
	Digest<DT::sha256> digest;
	digest.AddData(&tHyperChainBlock.tBlockBaseInfo, sizeof(tHyperChainBlock.tBlockBaseInfo));
	digest.AddData(tHyperChainBlock.tMerkleHashAll.pID, DEF_SHA256_LEN);

	for (auto &chain : tHyperChainBlock.listPayLoad) {
		for (auto &block: chain) {
			digest.AddData(&block, sizeof(T_LOCALBLOCK));
		}
	}
	digest.AddData(tHyperChainBlock.version);

	std::string d = digest.getDigest();
	memcpy(tHyperChainBlock.GetBlockBaseInfo().GetHashSelf().pID, d.data(), d.size());
	return tHyperChainBlock.tMerkleHashAll;
}

void CreateHyperBlock(T_HYPERBLOCK &tHyperChainBlock)
{
	uint64 hyperblockid = g_tP2pManagerStatus.GetConsensusHyperBlockID();

	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);

	auto localconsensus = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();

	T_BLOCKBASEINFO BlockBaseInfo;
	BlockBaseInfo.SetPreHash(localconsensus->GetLocalBlock().GetPreHHash());
	BlockBaseInfo.SetBlockBaseInfo(hyperblockid,
									g_tP2pManagerStatus.GettTimeOfConsensus(), (char*)AUTHKEY, (char*)BUDDYSCRIPT);
	tHyperChainBlock.SetBlockBaseInfo(BlockBaseInfo);

	uint16 blockNum = 0;
	uint32 diff = 0;
	LIST_T_LOCALBLOCK listLocalBlockInfo;
	list<LIST_T_LOCALBLOCK> listPayLoad;

	g_consensus_console_logger->anyway("Creating HyperBlock: {}", BlockBaseInfo.GetID());

	uint32_t chainnum = 0;
	auto itr = g_tP2pManagerStatus.listGlobalBuddyChainInfo.begin();
	for (; itr != g_tP2pManagerStatus.listGlobalBuddyChainInfo.end(); ++itr) {

		chainnum++;
		blockNum = 0;
		ITR_LIST_T_LOCALCONSENSUS subItr = (*itr).begin();
		for (; subItr != (*itr).end(); ++subItr) {

			uint64 hblockid = subItr->GetLocalBlock().GetPreHID() + 1;
			if (BlockBaseInfo.GetID() != hblockid) {
				g_consensus_console_logger->error("Error prehyperblock id: {} {} payload:{},skip the block...",
					BlockBaseInfo.GetID(),
					hblockid, subItr->tLocalBlock.GetPayLoad().GetPayLoad());
				continue;
			}
			g_consensus_console_logger->anyway("\t HyperBlock: {}:{} payload:{}", chainnum, blockNum,
				subItr->tLocalBlock.GetPayLoad().GetPayLoad());

			blockNum += 1;
			diff += subItr->tLocalBlock.difficulty;
			subItr->tLocalBlock.uiAtChainNum = chainnum;
			subItr->tLocalBlock.GetBlockBaseInfo().uiID = blockNum;
			listLocalBlockInfo.emplace_back((*subItr).tLocalBlock);
		}

		listLocalBlockInfo.sort(CmpareOnChainLocal());
		listPayLoad.emplace_back(listLocalBlockInfo);
		listLocalBlockInfo.clear();
	}
	tHyperChainBlock.SetlistPayLoad(std::move(listPayLoad));
	tHyperChainBlock.difficulty = diff;

	T_SHA256 HashAll(0);
	tHyperChainBlock.SetMerkleHash(HashAll);

	computeHyperBlockHash(tHyperChainBlock);

	char HyperblockHash[FILESIZEL] = { 0 };
	CCommonStruct::Hash256ToStr(HyperblockHash, &tHyperChainBlock.GetBlockBaseInfo().GetHashSelf());
	g_consensus_console_logger->anyway("New HyperBlock: {} hash:{}", BlockBaseInfo.GetID(), HyperblockHash);
	
}


bool isEndNode()
{
	bool isEndNodeBuddyChain = false;
	
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH me = nodemgr->myself();
	
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0)
		return false;
	LIST_T_LOCALCONSENSUS::iterator itr = g_tP2pManagerStatus.listLocalBuddyChainInfo.end();
	itr--;

	if ((*itr).GetPeer().GetPeerAddr() == me->getNodeId<CUInt128>()) {
		isEndNodeBuddyChain = true;
	}

	return isEndNodeBuddyChain;
}

bool isHyperBlockMatched(uint64 hyperblockid,const T_SHA256 &hash, const CUInt128 &peerid)
{
	T_SHA256 preHyperBlockHash;
	uint64 localhyperblockid = 0;
	g_tP2pManagerStatus.GetPreHyperBlockIDAndHash(localhyperblockid, preHyperBlockHash);

	bool isMatched = true;
	bool isNeedUpdateHyperBlock = false;
	if (localhyperblockid != hyperblockid) {
		g_consensus_console_logger->info("Refuse: local previous HyperBlockID:{}, recv buddy HyperBlockID:{}",
			localhyperblockid, hyperblockid);

		isMatched = false;
		if (localhyperblockid < hyperblockid) {
			isNeedUpdateHyperBlock = true;
		}
	}
	else if (hash != preHyperBlockHash) {
		g_consensus_console_logger->info("Refuse: local previous HyperBlock Hash:{}, recv hash:{}",
			preHyperBlockHash.toHexString(), hash.toHexString());

		isMatched = false;
		if (hash < preHyperBlockHash) {
			isNeedUpdateHyperBlock = true;
		}
	}

	if (isNeedUpdateHyperBlock) {
		
		g_consensus_console_logger->info("Hello friend, give me your HyperBlock:{}", hyperblockid);
		CHyperData hyperdata;
		hyperdata.PullHyperDataByHID(hyperblockid, peerid.ToHexString());
	}
	return isMatched;
}
