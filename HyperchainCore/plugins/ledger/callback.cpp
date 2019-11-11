/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or?https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this? software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED,? INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"

#include "headers.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "cryptopp/sha.h"
#include "ledgermain.h"
#include "cryptotoken.h"


#include <boost/any.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;
using namespace boost;


extern map<uint256, CBlock> mapBlocks;
extern CCriticalSection cs_mapBlocks;

bool ResolveBlock(CBlock &block, const char *payload, size_t payloadlen);
extern bool CommitToConsensus(CBlock* pblock, string& requestid, string& errmsg);

typedef struct tagConsensusBlock {
    CBlock* block = nullptr;
    uint256 hash = {0};

    tagConsensusBlock(CBlock* b) : block(b)
    {
        hash = block->GetHash();
    }
} ConsensusBlock;

std::mutex g_muxConsensusBlock;
std::shared_ptr<ConsensusBlock> g_spConsensusBlock;

bool IsGenesisBlock(const T_APPTYPE& t)
{
    uint32_t hid = 0;
    uint16 chainnum = 0;
    uint16 localid = 0;
    t.get(hid, chainnum, localid);

    if (hid == 0 && chainnum == 0 && localid == 0) {
        //genesis block
        return true;
    }
    return false;
}

//
std::map<uint32_t, time_t> mapPullingHyperBlock;
CCriticalSection cs_pullingHyperBlock;
void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "")
{
    CRITICAL_BLOCK(cs_pullingHyperBlock)
    {
        time_t now = time(nullptr);
        if (mapPullingHyperBlock.count(hid) == 0) {
            mapPullingHyperBlock.insert({ hid, now });
        }
        else {
            if (now - mapPullingHyperBlock[hid] < 20) {
                //
                return;
            }
            else {
                mapPullingHyperBlock[hid] = now;
            }
        }
        auto bg = mapPullingHyperBlock.begin();
        for (; bg != mapPullingHyperBlock.end();) {
            if (bg->second + 300 < now) {
                bg = mapPullingHyperBlock.erase(bg);
            }
            else {
                ++bg;
            }
        }
    }
    std::thread t([hid, nodeid]() {
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        if (hyperchainspace) {
            if (nodeid.empty()) {
                hyperchainspace->GetRemoteHyperBlockByID(hid);
                INFO_FL("GetRemoteHyperBlockByID: %d", hid);
            }
            else {
                hyperchainspace->GetRemoteHyperBlockByID(hid, nodeid);
                INFO_FL("GetRemoteHyperBlockByID: %d, from node: %s", hid, nodeid.c_str());
            }
        }
    });
    t.detach();
}

bool UpdateAppAddress(const CBlock& genesisblock, const T_LOCALBLOCKADDRESS& addr)
{
    CryptoToken cryptoToken(false);
    cryptoToken.ParseToken(genesisblock);

    CryptoToken cryptoTokenFromLocal(false);
    cryptoTokenFromLocal.SetName(cryptoToken.GetName());

    string tokenhash = cryptoToken.GetHashPrefixOfGenesis();
    string errmsg;
    if (!cryptoTokenFromLocal.ReadTokenFile(cryptoToken.GetName(), tokenhash, errmsg)) {
        //
        return ERROR_FL("%s", errmsg.c_str());
    }

    uint256 hash = genesisblock.GetHash();
    if (cryptoTokenFromLocal.GetHashGenesisBlock() == hash) {
        if (!cryptoTokenFromLocal.SetGenesisAddr(addr.hid, addr.chainnum, addr.id)) {
            ERROR_FL("SetGenesisAddr failed");
        }
    }
    return true;
}

bool IsMyBlock(const T_APPTYPE& t)
{
    uint32_t hid = 0;
    uint16 chainnum = 0;
    uint16 localid = 0;
    t.get(hid, chainnum, localid);
    
    if (hid != g_cryptoToken.GetHID() ||
        chainnum != g_cryptoToken.GetChainNum() ||
        localid != g_cryptoToken.GetLocalID()) {
        return false;
    }

    return true;
}

bool HandleGenesisBlockCb(vector<T_PAYLOADADDR>& vecPA)
{
    for (auto& b : vecPA) {

        CBlock block;
        if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        UpdateAppAddress(block, b.addr);
    }
    return true;
}

//
bool PutTxsChainCb()
{
    //
    std::lock_guard<std::mutex> lck(g_muxConsensusBlock);
    if (g_spConsensusBlock) {
        //
        return false;
    }

    CReserveKey reservekey(pwalletMain);
    CBlock* pBlock = CreateNewBlock(reservekey);
    if (!pBlock) {
        //no transactions need to commit
        return false;
    }

    std::shared_ptr<ConsensusBlock> spBlock(new ConsensusBlock(pBlock),
        [](ConsensusBlock* p) {
        delete p->block;
        delete p;
    });

    if (spBlock && spBlock->block->vtx.size() >= 1) {
        string requestid, errmsg;
        if (!CommitToConsensus(spBlock.get()->block, requestid, errmsg)) {
            return ERROR_FL("CommitToConsensus() Error: %s", errmsg.c_str());
        }
        g_spConsensusBlock = spBlock;
        return true;
    }
    return false;
}


//
bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA)
{
    if (vecPA.size() == 0) {
        return false;
    }
    vector<CBlock> vecBlock;
    vector<const T_PAYLOADADDR*> vecPPA;

    for (auto& b : vecPA) {
        vecPPA.push_back(&b);
    }
    std::sort(vecPPA.begin(), vecPPA.end(),
        [](const T_PAYLOADADDR* a, const T_PAYLOADADDR* b) { return a->addr < b->addr; });

    for (auto b : vecPPA) {
        CBlock block;
        if (!ResolveBlock(block, b->payload.c_str(), b->payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        vecBlock.push_back(std::move(block));
    }

    uint256 hashPrev = vecBlock.front().hashPrevBlock;
    for (auto& b : vecBlock) {
        if (b.hashPrevBlock != hashPrev)
            return ERROR_FL("hashPrevBlock are different");
    }

    CRITICAL_BLOCK(cs_main)
    {
        for (size_t i = 0; i < vecBlock.size(); i++) {
            if (vecBlock[i].AcceptBlock()) {
                uint256 hash = vecBlock[i].GetHash();
                printf("CheckChainCb() : (%s) %s is accepted\n", vecPPA[i]->addr.tostring().c_str(),
                    hash.ToString().substr(0, 20).c_str());
            }
            else {
                return ERROR_FL("(%s) cannot be accepted", vecPPA[i]->addr.tostring().c_str());
            }
        }
    }

    return true;
}


//
bool LedgeAcceptChainCb(const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA, uint32_t& hid, T_SHA256& thhash)
{
    T_APPTYPE meApp(APPTYPE::ledger, g_cryptoToken.GetHID(), g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID());
    if (app != meApp) {
        return false;
    }

    if (vecPA.size() == 0) {
        return false;
    }
    vector<CBlock> vecBlock;

    for (auto b: vecPA) {
        CBlock block;
        if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        vecBlock.push_back(std::move(block));
    }

    CRITICAL_BLOCK(cs_main)
    {
        for (size_t i = 0; i < vecBlock.size(); i++) {
			CBlock *prevSibling = (i == 0 ? nullptr : &vecBlock[i - 1]);
            if (vecBlock[i].AcceptBlock(vecPA[i].addr, prevSibling)) {
                uint256 hash = vecBlock[i].GetHash();
                printf("LedgeAcceptChainCb() : (%s) %s is accepted\n", vecPA[i].addr.tostring().c_str(),
                    hash.ToString().substr(0, 20).c_str());
            }
            else {
                return ERROR_FL("(%s) cannot be accepted", vecPA[i].addr.tostring().c_str());
            }
        }
    }

    {
        std::lock_guard<std::mutex> lck(g_muxConsensusBlock);
        if (g_spConsensusBlock) {
            for (auto& elm : vecBlock) {
                if (elm.GetHash() == g_spConsensusBlock->hash) {
                    //BOOST_FOREACH(CTransaction& tx, g_spConsensusBlock->block->vtx)
                    //    tx.RemoveFromMemoryPool();

                    g_spConsensusBlock = nullptr;
                    break;
                }
            }
        }
    }

    //
    PutTxsChainCb();

    return true;
}

namespace boost {
    bool operator<(const boost::any& _Left, const boost::any& _Right)
    {
        if (_Left.type() != _Right.type())
            throw logic_error("type error");
        if (_Left.type() == typeid(COutPoint)) {
            return any_cast<COutPoint>(_Left) < any_cast<COutPoint>(_Right);
        }
        throw logic_error("unimplemented");
    }
}

//
//
bool ValidateLedgeDataCb(T_PAYLOADADDR& payloadaddr,
                        map<boost::any,T_LOCALBLOCKADDRESS>& mapOutPt,
                        boost::any& hashPrevBlock)
{
    CBlock block;
    if (!ResolveBlock(block, payloadaddr.payload.c_str(), payloadaddr.payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }
    if (hashPrevBlock.empty()) {
        hashPrevBlock = block.hashPrevBlock;
    }
    else if (block.hashPrevBlock != any_cast<uint256>(hashPrevBlock)) {
        return ERROR_FL("hashPrevBlock is different");
    }

    // Preliminary checks
    if (!block.CheckBlock())
        return ERROR_FL("CheckBlock FAILED");

    if (!block.CheckTrans())
        return ERROR_FL("CheckTrans FAILED");

    //
    for (auto tx : block.vtx) {
        if (tx.IsCoinBase()) {
            continue;
        }
        for (auto vin : tx.vin) {
            if (mapOutPt.count(vin.prevout)) {
                return ERROR_FL("localblock %s confilicts with localblock %s,try to take over the same tx.",
                    payloadaddr.addr.tostring().c_str(),
                    mapOutPt[vin.prevout].tostring().c_str());
            }
            else {
                mapOutPt.insert(std::make_pair(vin.prevout, payloadaddr.addr));
            }
        }
    }

    return true;
}

bool UpdateLedgeDataCb(string& payload, string &newpaylod)
{
    CBlock block;
    if (!ResolveBlock(block, payload.c_str(), payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }

    CBlockIndex* pindexPrev = pindexBest;
    if (block.hashPrevBlock == pindexBest->GetBlockHash()) {
        //don't need update.
        return false;
    }
    //
    block.hashPrevBlock = pindexPrev->GetBlockHash();
    //block.nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    CDataStream datastream(SER_BUDDYCONSENSUS);
    try {
        datastream << block;
        newpaylod = datastream.str();
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Cannot extract ledger block data, %s\n", e.what());
    }
    return true;
}

//
bool LedgeBlockUUIDCb(string& payload, string& uuidpayload)
{
    //
    //
    uuidpayload = payload.substr(0, sizeof(int));
    //
    uuidpayload += payload.substr(sizeof(int) + sizeof(uint256));
    return true;
}


bool GetVPath(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath)
{
    CRITICAL_BLOCK(cs_main)
    {
        CBlockIndex* p = pindexBest;
        while (p) {
            if (p->addr.hid > sAddr.hid) {
                p = p->pprev;
                continue;
            } else if (p->addr.hid < sAddr.hid) {
                //
                return false;
            }
            else {
                for (;p && p->addr.hid <= eAddr.hid;) {
                    vecVPath.push_back(p->addr.tostring());
                    if (p->pnextSibling) {
                        p = p->pnextSibling;
                    }
                    else {
                        p = p->pnext;
                    }
                }
                return true;
            }
        }
    }
    return false;
}

/*
void checkLedge()
{
    vector<uint256> vWorkQueue;
    CDataStream vMsg(vRecv);
    CTransaction tx;
    vRecv >> tx;

    CInv inv(MSG_TX, tx.GetHash());
    pfrom->AddInventoryKnown(inv);

    bool fMissingInputs = false;
    if (tx.AcceptToMemoryPool(true, &fMissingInputs))
    {
        SyncWithWallets(tx, NULL, true);
        mapAlreadyAskedFor.erase(inv);
        vWorkQueue.push_back(inv.hash);

        // Recursively process any orphan transactions that depended on this one
        for (int i = 0; i < vWorkQueue.size(); i++)
        {
            uint256 hashPrev = vWorkQueue[i];
            for (multimap<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev.lower_bound(hashPrev);
                mi != mapOrphanTransactionsByPrev.upper_bound(hashPrev);
                ++mi)
            {
                const CDataStream& vMsg = *((*mi).second);
                CTransaction tx;
                CDataStream(vMsg) >> tx;
                CInv inv(MSG_TX, tx.GetHash());

                if (tx.AcceptToMemoryPool(true))
                {
                    printf("   accepted orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
                    SyncWithWallets(tx, NULL, true);
                    RelayMessage(inv, vMsg);
                    mapAlreadyAskedFor.erase(inv);
                    vWorkQueue.push_back(inv.hash);
                }
            }
        }

        BOOST_FOREACH(uint256 hash, vWorkQueue)
            EraseOrphanTx(hash);
    }
    else if (fMissingInputs)
    {
        printf("storing orphan tx %s\n", inv.hash.ToString().substr(0, 10).c_str());
        AddOrphanTx(vMsg);
    }
}
*/


typedef struct _t_block_search_pos
{
    T_LOCALBLOCKADDRESS startaddr;
    T_LOCALBLOCKADDRESS endaddr;
    bool operator == (const _t_block_search_pos& right) {
        return startaddr == right.startaddr && endaddr == right.endaddr;
    }
}BLOCK_SEARCH_POS;

std::mutex muxGetBlock;
list<BLOCK_SEARCH_POS> listGetBlock;
BLOCK_SEARCH_POS searchBlockOngoing;
time_t tOngoingTimePoint;

void UpdateMaxBlockAddr(const T_LOCALBLOCKADDRESS& addr)
{
    if (addrMaxChain < addr) {
        addrMaxChain = addr;
        CTxDB txdb;
        if (!txdb.WriteAddrMaxChain(addrMaxChain)) {
            ERROR_FL("WriteAddrMaxChain failed");
        }
        txdb.Close();
    }
}
//
void UpdateBlockIndex()
{
    if(pindexBest->addr < addrMaxChain) {
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        T_APPTYPE app(APPTYPE::ledger);
        vector<T_PAYLOADADDR> vecPA;
		uint32 hid = pindexBest->addr.hid + 1;
        while (hid <= addrMaxChain.hid) {
            //
            if (!hyperchainspace->GetLocalBlocksByHID(hid++, app, vecPA)) {
                //
                break;
            }
            CheckChainCb(vecPA);
            vecPA.clear();
        }
    }

}

void mergeSearchPos(list<BLOCK_SEARCH_POS>& listBlock)
{
    BLOCK_SEARCH_POS search_pos;

    if (listBlock.size() == 0) {
        return;
    }
    auto itr = listBlock.begin();

    search_pos = *itr;
    for (;itr!= listBlock.end(); ++itr) {
        if (itr->startaddr < search_pos.startaddr ) {
            search_pos.startaddr = itr->startaddr;
        }
        if (search_pos.endaddr  < itr->endaddr ) {
            search_pos.endaddr = itr->endaddr;
        }
    }
    listBlock.clear();
    listBlock.push_back(search_pos);
}

void ThreadRSyncGetBlock(void* parg)
{
    return;

	std::function<void(int)> SleepFn = [](int sleepseconds) {
		int i = 0;
		int maxtimes = sleepseconds * 1000 / 200;
		while (i++ < maxtimes) {
			if (fShutdown) {
				break;
			}
			Sleep(200);
		}
	};

    list<BLOCK_SEARCH_POS> tmplistGetBlock;
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    while (!fShutdown) {
        SleepFn(10);
        UpdateMaxBlockAddr(pindexBest->addr);
        UpdateBlockIndex();
        {
            std::lock_guard<std::mutex> lck(muxGetBlock);
            tmplistGetBlock = std::move(listGetBlock);
        }

        mergeSearchPos(tmplistGetBlock);
        auto itergb = tmplistGetBlock.begin();
        if (itergb == tmplistGetBlock.end()) {
            continue;
        }

        {
            CCriticalBlock criticalblock(cs_main, "cs_main", __FILE__, __LINE__);
            if (pindexBest->addr >= itergb->endaddr) {
                tmplistGetBlock.erase(itergb);
                continue;
            }
            itergb->startaddr = pindexBest->addr;
        }

        T_APPTYPE app(APPTYPE::ledger);
        //
        if (!searchBlockOngoing.startaddr.isValid()) {
            hyperchainspace->GetAppBlocksByAddr(itergb->startaddr, itergb->endaddr, app);
            tOngoingTimePoint = std::time(nullptr);
            searchBlockOngoing = *itergb;
        }
        else if (itergb->startaddr < searchBlockOngoing.startaddr) {
            hyperchainspace->GetAppBlocksByAddr(itergb->startaddr, searchBlockOngoing.startaddr, app);
            searchBlockOngoing.startaddr = itergb->startaddr;
            tOngoingTimePoint = std::time(nullptr);
        }
        else if (searchBlockOngoing.endaddr < itergb->endaddr) {
            hyperchainspace->GetAppBlocksByAddr(searchBlockOngoing.endaddr, itergb->endaddr, app);
            searchBlockOngoing.endaddr = itergb->endaddr;
            tOngoingTimePoint = std::time(nullptr);
        }

        auto now = std::time(nullptr);
        if (now - tOngoingTimePoint > 120) {
            //
            hyperchainspace->GetAppBlocksByAddr(searchBlockOngoing.startaddr, searchBlockOngoing.endaddr, app);
            tOngoingTimePoint = std::time(nullptr);
        }

        {
            std::lock_guard<std::mutex> lck(muxGetBlock);
            std::copy(listGetBlock.begin(), listGetBlock.end(), std::back_inserter(tmplistGetBlock));
            listGetBlock = std::move(tmplistGetBlock);
        }
    }
}

//
void RSyncGetBlock(const T_LOCALBLOCKADDRESS& addr)
{
    RSyncRemotePullHyperBlock(addr.hid);
    return;

    if (pindexBest->addr >= addr) {
        return;
    }

    std::lock_guard<std::mutex> lck(muxGetBlock);

    BLOCK_SEARCH_POS pos;

    if (listGetBlock.size() > 0 && listGetBlock.rbegin()->endaddr.hid ) {
        auto searchpos = listGetBlock.rbegin()->endaddr;
        if (searchpos >= addr) {
            //
            return;
        }
        pos.startaddr = searchpos;
    }
    else {
        pos.startaddr = pindexBest->addr;
    }

    UpdateMaxBlockAddr(addr);
    UpdateBlockIndex();
    pos.endaddr = addr;
    listGetBlock.push_back(pos);
}

void showBlockIndex()
{
#undef printf
    std::printf("Best chain Ledge block addr:%s Height:%d \nPrev Block Hash:%s\n Hash:%s \n%p\n", pindexBest->addr.tostring().c_str(),
        pindexBest->Height(), pindexBest->pprev->GetBlockHash().ToString().c_str(),
        pindexBest->GetBlockHash().ToString().c_str(),
        pindexBest);
    std::printf("Show more details: ld hid [+/-count]\n\n");
}

void showBlockIndex(uint32 startingHID, int64 count)
{
	uint32 endingHID = startingHID + count;
	uint32 sHID = std::min(startingHID, endingHID);
	uint32 eHID = std::max(startingHID, endingHID);
    if (count < 0) {
        sHID++;
        eHID++;
    }

#undef printf
    std::list<CBlockIndex*> listBlockIndex;
    std::printf("Best chain ledger block addr:%s Height:%d %p\n", pindexBest->addr.tostring().c_str(),
        pindexBest->Height(), pindexBest);
    for (auto& idx : mapBlockIndex) {
        if (idx.second->addr.hid < sHID || idx.second->addr.hid >= eHID) {
            continue;
        }
        listBlockIndex.push_back(idx.second);
    }

    listBlockIndex.sort([](const CBlockIndex* a, const CBlockIndex* b) {
        if (a->addr < b->addr) {
            return true;
        }
        return false;
    });

    for(auto idx : listBlockIndex) {
        std::printf("Address:%s %p\n", idx->addr.tostring().c_str(), idx);
        std::printf("Height:%d\n", pindexBest->Height());
        std::printf("PreHash:%s\n", pindexBest->pprev->GetBlockHash().ToString().c_str());
        std::printf("Hash:%s\n", pindexBest->GetBlockHash().ToString().c_str());
        std::printf("\tpnext:%p", idx->pnext);
        std::printf("\tpprev:%p", idx->pprev);
        std::printf("\tpprevSibling:%p", idx->pprevSibling);
        std::printf("\tpnextSibling:%p\n", idx->pnextSibling);
    }
    std::printf("\n");
}

void AppRunningArg(int& app_argc, string& app_argv)
{
    app_argc = mapArgs.size();

    for (auto& elm : mapArgs)
    {
        string stroption = elm.first; 
        if (!elm.second.empty()) {
            stroption += "=";
            stroption += elm.second;
        }
        stroption += " ";
        app_argv += stroption;
    }
}

void AppInfo(string& info)
{
    ostringstream oss;
    oss << "Ledge module's current token name: " << g_cryptoToken.GetName() << " - "
        << g_cryptoToken.GetHashPrefixOfGenesis() <<endl
        << "block message: " << g_cryptoToken.GetDesc() << endl
        << "Genesis block address: " << g_cryptoToken.GetHID() << " " 
        << g_cryptoToken.GetChainNum() << " " 
        << g_cryptoToken.GetLocalID() << endl;

    info = oss.str();

    if (!pindexBest) {
        info = "Best block is unknown\n";
        return;
    }
    const char* fmt = "Best block height: %d\n"
        "Address: %s \n"
        "HashPrevBlock: %s\n"
        "Hash: %s\n"
        "Pointer: %p\n";

    char buff[1024] = {0};
    int sz = std::snprintf(buff, 1024, fmt,
        pindexBest->Height(),
        pindexBest->addr.tostring().c_str(),
        pindexBest->pprev ? (pindexBest->pprev->GetBlockHash().ToString().c_str()) : "null",
        pindexBest->GetBlockHash().ToString().c_str() 
        );

    info += buff;

}


bool ResolveBlock(CBlock &block, const char *payload, size_t payloadlen)
{
    CDataStream datastream(payload, payload + payloadlen);
    try {
        datastream >> block;
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Error: Cannot resolve ledger block data, %s\n", e.what());
    }
    return true;
}

bool ResolveHeight(int height, string& info)
{
    CBlockIndex* p = pindexBest;
    while (p) {
        if (p->Height() == height) {
            break;
        }
        p = p->pprev;
    }
    if (!p) {
        return false;
    }
    info = p->ToString();

    return true;
}


bool ResolvePayload(const string& payload, string& info)
{
    CBlock block;
    if (!ResolveBlock(block, payload.c_str(), payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }

    info = block.ToString();
    return true;
}
