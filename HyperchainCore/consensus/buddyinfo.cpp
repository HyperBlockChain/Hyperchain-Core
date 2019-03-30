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
#include "db/HyperchainDB.h"
#include "headers/lambda.h"

uint64 _tBuddyInfo::GetCurBuddyNo()const
{
	return uiCurBuddyNo;
}

uint16 _tBuddyInfo::GetBlockNum()const
{
	return usBlockNum;
}

uint16 _tBuddyInfo::GetChainNum()const
{
	return usChainNum;
}

uint8 _tBuddyInfo::GetBuddyState()const
{
	return eBuddyState;
}

void _tBuddyInfo::SetBlockNum(uint16 num)
{
	usBlockNum = num;
}

uint64 _tOnChainHashInfo::GetTime()const
{
	return uiTime;
}

string _tOnChainHashInfo::GetHash()const
{
	return strHash;
}

void _tOnChainHashInfo::Set(uint64 t, string h)
{
	uiTime = t;
	strHash = h;
}

void _tp2pmanagerstatus::clearStatus()
{
	bStartGlobalFlag = false;
	bHaveOnChainReq = false;
	uiMaxBlockNum = 0;
	uiNodeState = DEFAULT_REGISREQ_STATE;
	usBuddyPeerCount = 0;
	uiSendRegisReqNum = 0;
	uiSendConfirmingRegisReqNum = 0;
	uiRecvRegisReqNum = 0;
	uiRecvConfirmingRegisReqNum = 0;
	listLocalBuddyChainInfo.clear();
	uiSendPoeNum = 0;
	uiRecivePoeNum = 0;
	tBuddyInfo.uiCurBuddyNo = 0;
	tBuddyInfo.eBuddyState = IDLE;
	tBuddyInfo.usBlockNum = 0;
	tBuddyInfo.usChainNum = 0;
}

bool _tp2pmanagerstatus::StartGlobalFlag()const
{
	return bStartGlobalFlag;
}

bool _tp2pmanagerstatus::HaveOnChainReq()const
{
	return bHaveOnChainReq;
}

uint64 _tp2pmanagerstatus::GetConsensusHyperBlockID()const
{
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	if (g_tP2pManagerStatus.listLocalBuddyChainInfo.size() == 0) {
		return 0;
	}

	LIST_T_LOCALCONSENSUS::iterator itrLocal = g_tP2pManagerStatus.listLocalBuddyChainInfo.begin();
	return itrLocal->GetLocalBlock().GetPreHID() + 1;
}

uint16 _tp2pmanagerstatus::GetBuddyPeerCount()const
{
	return usBuddyPeerCount;
}

uint16 _tp2pmanagerstatus::GetNodeState()const
{
	return uiNodeState;
}

uint64 _tp2pmanagerstatus::GetSendRegisReqNum()const
{
	return uiSendRegisReqNum;
}

uint64 _tp2pmanagerstatus::GetRecvRegisReqNum()const
{
	return uiRecvRegisReqNum;
}

uint64 _tp2pmanagerstatus::GetSendConfirmingRegisReqNum()const
{
	return uiSendConfirmingRegisReqNum;
}

uint64 _tp2pmanagerstatus::GetRecvConfirmingRegisReqNum()const
{
	return uiRecvConfirmingRegisReqNum;
}

uint64 _tp2pmanagerstatus::GettTimeOfConsensus()
{
	time_t now = time(nullptr);
	uint32 pos = now % NEXTBUDDYTIME;
	return (now - pos + NEXTBUDDYTIME);
}

CONSENSUS_PHASE _tp2pmanagerstatus::GetCurrentConsensusPhase() const
{
	time_t now = time(nullptr);
	uint32 pos = now % NEXTBUDDYTIME;
	if (pos <= LOCALBUDDYTIME) {
		return CONSENSUS_PHASE::LOCALBUDDY_PHASE;
	}
	if (pos <= GLOBALBUDDYTIME) {
		return CONSENSUS_PHASE::GLOBALBUDDY_PHASE;
	}

	if (pos < NEXTBUDDYTIME - 8) {
		return CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE;
	}
	return CONSENSUS_PHASE::PREPARE_LOCALBUDDY_PHASE;
}


T_PEERADDRESS _tp2pmanagerstatus::GetLocalBuddyAddr()const
{
	return tLocalBuddyAddr;
}

T_HYPERBLOCK& _tp2pmanagerstatus::GetPreHyperBlock()
{
	return tPreHyperBlock;
}

LIST_T_LOCALCONSENSUS& _tp2pmanagerstatus::GetListOnChainReq()
{
	return listOnChainReq;
}

void _tp2pmanagerstatus::SetGlobalBuddyAddr(T_PEERADDRESS addr)
{
	tLocalBuddyAddr = addr;;
}

void _tp2pmanagerstatus::SetStartGlobalFlag(bool flag)
{
	bStartGlobalFlag = flag;
}

void _tp2pmanagerstatus::SetHaveOnChainReq(bool haveOnChainReq)
{
	bHaveOnChainReq = haveOnChainReq;
}

void _tp2pmanagerstatus::SetRecvRegisReqNum(uint64 num)
{
	uiRecvRegisReqNum = num;
}

uint64 _tp2pmanagerstatus::GetSendPoeNum()const
{
	return uiSendPoeNum;
}

void _tp2pmanagerstatus::SetSendPoeNum(uint64 num)
{
	uiSendPoeNum = num;
}


void _tp2pmanagerstatus::SetNodeState(uint16 state)
{
	uiNodeState = state;
}

void _tp2pmanagerstatus::SetSendRegisReqNum(uint64 num)
{
	uiSendRegisReqNum = num;
}

void _tp2pmanagerstatus::SetSendConfirmingRegisReqNum(uint64 num)
{
	uiSendConfirmingRegisReqNum = num;
}

void _tp2pmanagerstatus::SetRecvConfirmingRegisReqNum(uint64 num)
{
	uiRecvConfirmingRegisReqNum = num;
}

void _tp2pmanagerstatus::SetMaxBlockNum(uint64 num)
{
	uiMaxBlockNum = num;
}

void _tp2pmanagerstatus::SetPreHyperBlock(const T_HYPERBLOCK&block)
{
	tPreHyperBlock = block;
}

uint64 _tp2pmanagerstatus::GetRecvPoeNum()const
{
	return uiRecivePoeNum;
}

void _tp2pmanagerstatus::SetRecvPoeNum(uint64 num)
{
	uiRecivePoeNum = num;
}

T_STRUCTBUDDYINFO _tp2pmanagerstatus::GetBuddyInfo()const
{
	return tBuddyInfo;
}

void _tp2pmanagerstatus::SetBuddyInfo(T_STRUCTBUDDYINFO info)
{
	tBuddyInfo = info;
}

bool _tp2pmanagerstatus::getHyperBlock(uint64 blockNum, T_HYPERBLOCK &hyperblock)
{
	CAutoMutexLock muxAuto(m_MuxHchainBlockList);
	auto itrList = m_HchainBlockList.begin();
	for (; itrList != m_HchainBlockList.end(); itrList++) {
		if ((*itrList).GetBlockBaseInfo().GetID() == blockNum) {
			
			hyperblock = (*itrList);
			return true;
		}
	}

	
	return loadHyperBlock(blockNum, hyperblock);
}

#define ATMOSTHYPERBLOCKINMEMORY 5

void _tp2pmanagerstatus::loadHyperBlockCache()
{
	uint64 nHyperId = DBmgr::instance()->getLatestHyperBlockNo();

	CAutoMutexLock muxAuto1(m_MuxHchainBlockList);
	m_HchainBlockList.clear();

	uint64 lowerBord = (nHyperId >= ATMOSTHYPERBLOCKINMEMORY) ? (nHyperId - ATMOSTHYPERBLOCKINMEMORY) : 0;
	for (size_t i = nHyperId; i > lowerBord; i--) {
		T_HYPERBLOCK hyperBlock;
		if (loadHyperBlock(i, hyperBlock)) {
			updateHyperBlockCache(hyperBlock);
		}
	}
}


bool _tp2pmanagerstatus::updateHyperBlockCache(T_HYPERBLOCK &hyperblock)
{
	uint64_t currblockid = hyperblock.GetBlockBaseInfo().GetID();
	uint64_t blockcount = hyperblock.GetChildBlockCount();

	
	
	

	char HyperblockHash[FILESIZEL] = { 0 };
	CCommonStruct::Hash256ToStr(HyperblockHash, &hyperblock.GetBlockBaseInfo().GetHashSelf());

	
	bool isBlockAlreadyExisted = false;
	if (!isAcceptHyperBlock(currblockid, blockcount, hyperblock.GetBlockBaseInfo().GetHashSelf(), isBlockAlreadyExisted)) {
		g_consensus_console_logger->info("I have the hyper block or local is more well, refuse it: {} {} {}",
			currblockid, blockcount, HyperblockHash);
		return false;
	}

	
	g_consensus_console_logger->info("I accept the hyper block: {} {} {}",
		currblockid, blockcount, HyperblockHash);

	CAutoMutexLock muxAuto(m_MuxHchainBlockList);
	auto itr = m_HchainBlockList.begin();
	for (; itr != m_HchainBlockList.end();) {
		uint64_t blocknum = (*itr).GetBlockBaseInfo().GetID();
		if (blocknum == currblockid || blocknum < currblockid - ATMOSTHYPERBLOCKINMEMORY) {
			itr = m_HchainBlockList.erase(itr);
			continue;
		}
		++itr;
	}

	if (GetMaxBlockID() <= hyperblock.GetBlockBaseInfo().GetID()) {
		
		if (tPreHyperBlock.GetBlockBaseInfo().GetID() != 0) {
			m_HchainBlockList.emplace_back(std::move(tPreHyperBlock));
		}
		SetMaxBlockNum(hyperblock.GetBlockBaseInfo().GetID());
		
		SetPreHyperBlock(hyperblock);
	}
	else {
		
		m_HchainBlockList.push_back(hyperblock);
	}

	/*SetP2pmanagerstatus(hyperblock, GetMaxBlockNum() + 1, true, true, false, false,
		hyperblock.GetBlockBaseInfo().GetTime(),
		GetSendConfirmingRegisReqNum() - 1, CONFIRMED);*/


	
	bool isfound = false;

	if (isBlockAlreadyExisted) {
		initOnChainingState(hyperblock.GetBlockBaseInfo().GetID());
	}
	auto childchainlist = hyperblock.GetlistPayLoad();

	for (auto childchain : childchainlist) {
		std::find_if(childchain.begin(), childchain.end(), [this,&isfound,&hyperblock](const T_LOCALBLOCK & elem) {
			LB_UUID uuid = elem.getUUID();
			if (mapSearchOnChain.count(uuid) > 0) {
				isfound = true;
				T_SEARCHINFO searchInfo;
				searchInfo.addr.set(hyperblock.GetBlockBaseInfo().GetID(),
					elem.uiAtChainNum,
					elem.GetBlockBaseInfo().GetID());
				CAutoMutexLock muxAuto1(MuxMapSearchOnChain);
				mapSearchOnChain[uuid] = searchInfo;

				
				DBmgr::instance()->updateOnChainState(uuid, searchInfo.addr);
				return true;
			}
			return false;
		});

		if (isfound) {
			break;
		}
	}

	return true;
}



bool _tp2pmanagerstatus::isMoreWellThanLocal(const T_HYPERBLOCK &localHyperBlock,
	uint64 blockid, uint64 blockcount, const T_SHA256 &hhashself)
{
	assert(blockid == localHyperBlock.GetBlockBaseInfo().GetID());

	uint64 currentchildcount = localHyperBlock.GetChildBlockCount();
	if (blockcount > currentchildcount) {
		return true;
	}
	if (blockcount == currentchildcount) {
		T_SHA256 h = localHyperBlock.GetBlockBaseInfo().GetHashSelf();
		if (hhashself < h) {
			return true;
		}
	}
	return false;
}

bool _tp2pmanagerstatus::isAcceptHyperBlock(uint64 blockid, uint64 blockcount, T_SHA256 hhashself, bool isAlreadyExisted)
{
	if (blockid == tPreHyperBlock.GetBlockBaseInfo().GetID()) {
		if (isMoreWellThanLocal(tPreHyperBlock, blockid, blockcount, hhashself)) {
			g_consensus_console_logger->info("isMoreWellThanLocal is true {} {}", blockid, blockcount);
			isAlreadyExisted = true;
			return true;
		}
		return false;
	}

	CAutoMutexLock muxAuto(m_MuxHchainBlockList);
	ITR_LIST_T_HYPERBLOCK itrList = m_HchainBlockList.begin();
	for (; itrList != m_HchainBlockList.end(); itrList++) {
		if ((*itrList).GetBlockBaseInfo().GetID() == blockid) {
			if (isMoreWellThanLocal(*itrList, blockid, blockcount, hhashself)) {
				g_consensus_console_logger->info("isMoreWellThanLocal is true {} {}", blockid, blockcount);
				isAlreadyExisted = true;
				return true;
			}
			return false;
		}
	}
	isAlreadyExisted = false;
	return true;
}

bool _tp2pmanagerstatus::loadHyperBlock(uint64 blockNum, T_HYPERBLOCK &hyperBlock)
{
	HyperchainDB  hyperchainDB;
	if (CHyperchainDB::getHyperBlocks(hyperchainDB, blockNum, blockNum) == 0) {
		
		return false;
	}
	HyperBlockDB & hyperblockdb = hyperchainDB.at(blockNum);
	const T_HYPERBLOCKDBINFO& hbi = hyperblockdb.GetHyperBlock();
	if (hbi.GetBlockId() != 0) {
		T_BLOCKBASEINFO tBBI;
		tBBI.SetBlockBaseInfo(hbi.GetBlockId(), hbi.GetBlockTimeStamp(), (int8*)hbi.GetAuth().c_str(), (int8*)hbi.GetScript().c_str(),
			hbi.GetHashSelf(), hbi.GetPreHash());
		hyperBlock.SetBlockBaseInfo(tBBI);

		
		LIST_T_LOCALBLOCK listLocakBlockTemp;
		LocalChainDB::iterator itrMap = hyperblockdb.GetMapLocalChain().begin();
		for (; itrMap != hyperblockdb.GetMapLocalChain().end(); itrMap++) {
			LIST_T_LOCALBLOCK listLocalBlockTemp;
			LocalBlockDB::iterator itrMapBlock = (*itrMap).second.begin();
			for (; itrMapBlock != (*itrMap).second.end(); itrMapBlock++) {
				const _tBlockPersistStru& lbd = (*itrMapBlock).second;

				T_BLOCKBASEINFO baseinfo = T_BLOCKBASEINFO(lbd.GetBlockTimeStamp(),
					(int8*)lbd.GetAuth().c_str(),
					(int8*)lbd.GetScript().c_str(),
					lbd.GetHashSelf(),
					lbd.GetPreHash());
				baseinfo.SetID(lbd.GetBlockId());
				T_LOCALBLOCK pLocalTemp(baseinfo,
					lbd.difficulty,
					lbd.GetReferHyperBlockId() - 1,
					lbd.GetHyperBlockHash(),
					lbd.GetLocalChainId());
				pLocalTemp.GetPayLoad().SetPayLoad(T_FILEINFO((*itrMapBlock).second.GetPayload()));

				listLocalBlockTemp.emplace_back(std::move(pLocalTemp));
			}
			listLocakBlockTemp.sort(CmpareOnChainLocal());
			hyperBlock.PushBack(listLocalBlockTemp);
		}
		return true;
	}
	return false;
}

void _tp2pmanagerstatus::updateLocalBuddyBlockToLatest()
{
	if (listLocalBuddyChainInfo.size() == ONE_LOCAL_BLOCK) {
		
		T_SHA256 preHyperBlockHash;
		uint64 localhyperblockid = 0;
		GetPreHyperBlockIDAndHash(localhyperblockid, preHyperBlockHash);
		auto itr = listLocalBuddyChainInfo.begin();
		itr->GetLocalBlock().updatePreHyperBlockInfo(localhyperblockid, preHyperBlockHash);
	}
}


void _tp2pmanagerstatus::cleanConsensusEnv()
{
	{
		CAutoMutexLock muxAuto2(g_tP2pManagerStatus.MuxlistGlobalBuddyChainInfo);
		g_tP2pManagerStatus.listGlobalBuddyChainInfo.clear();
	}

	{
		CAutoMutexLock muxAuto1(g_tP2pManagerStatus.MuxlistCurBuddyRsp);
		g_tP2pManagerStatus.listCurBuddyRsp.clear();
	}

	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyRsp);
		g_tP2pManagerStatus.listRecvLocalBuddyRsp.clear();
	}

	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistCurBuddyReq);
		g_tP2pManagerStatus.listCurBuddyReq.clear();
	}

	{
		CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistRecvLocalBuddyReq);
		g_tP2pManagerStatus.listRecvLocalBuddyReq.clear();
	}
}

void _tp2pmanagerstatus::setRecvHyperblockFlag(bool isReceivable)
{
	CAutoMutexLock muxAuto(MuxRecvHyperblock);
	isHyperblockReceivable = isReceivable;
}

void _tp2pmanagerstatus::trackLocalBlock(const T_LOCALBLOCK & localblock)
{
	LB_UUID uuid = localblock.getUUID();

	T_LOCALBLOCKADDRESS addr;
	T_SEARCHINFO searchinfo;
	CAutoMutexLock muxAuto(MuxMapSearchOnChain);
	mapSearchOnChain[uuid] = searchinfo;
}

void _tp2pmanagerstatus::initOnChainingState(uint64 hid)
{
	CAutoMutexLock muxAuto(MuxMapSearchOnChain);
	for (auto & elem : mapSearchOnChain) {
		if (hid == elem.second.GetHyperID()) {
			T_SEARCHINFO &searchInfo = elem.second;
			searchInfo.addr.set(hid, -1, -1);
		}
	}
	DBmgr::instance()->removeOnChainState(hid);
}


T_P2PMANAGERSTATUS g_tP2pManagerStatus;