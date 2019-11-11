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
#include "random.h"
#include "dllmain.h"
#include "cryptocurrency.h"


#include <boost/any.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;
using namespace boost;


extern map<uint256, CBlock> mapBlocks;
extern CCriticalSection cs_mapBlocks;
extern map<uint256, CBlock*> mapOrphanBlocks;

extern std::tuple<uint32_t, uint256> tplLatestHyperBlock;
extern CCriticalSection cs_lastHyperBlock;


extern void ProcessOrphanBlocks(const uint256& hash);
bool ResolveBlock(CBlock &block, const char *payload, size_t payloadlen);

void SyncLastHyperBlock()
{
    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    uint64 hid;
    T_SHA256 thhash;
    hyperchainspace->GetLatestHyperBlockIDAndHash(hid, thhash);
    CRITICAL_BLOCK(cs_lastHyperBlock)
    {
        tplLatestHyperBlock = make_tuple(hid, uint256S(thhash.toHexString()));
    }
}

void CompareAndUpdateLastHyperBlock(uint32_t hid, const T_SHA256& thhash)
{
    CRITICAL_BLOCK(cs_lastHyperBlock)
    {
        uint32_t currrhid = std::get<0>(tplLatestHyperBlock);
        if (currrhid <= hid) {
            tplLatestHyperBlock = make_tuple(hid, uint256S(thhash.toHexString()));
        }
    }
}

uint32_t GetLastHyperBlockID(uint256* hhash = nullptr)
{
    CRITICAL_BLOCK(cs_lastHyperBlock)
    {
        if (hhash) {
            *hhash = std::get<1>(tplLatestHyperBlock);
        }
        return std::get<0>(tplLatestHyperBlock);
    }
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


bool UpdateAppAddress(const CBlock& genesisblock, const T_LOCALBLOCKADDRESS& addr)
{
    CryptoCurrency cryptoCurrency(false);
    cryptoCurrency.ParseCoin(genesisblock);

    CryptoCurrency cryptoCurrencyFromLocal(false);

    string currencyhash = cryptoCurrency.GetHashPrefixOfGenesis();
    string errmsg;
    if (!cryptoCurrencyFromLocal.ReadCoinFile("", currencyhash, errmsg)) {
        //
        return ERROR_FL("%s", errmsg.c_str());
    }

    uint256 hash = genesisblock.GetHash();
    if (cryptoCurrencyFromLocal.GetHashGenesisBlock() == hash) {
        if (!cryptoCurrencyFromLocal.SetGenesisAddr(addr.hid, addr.chainnum, addr.id)) {
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
    
    if (hid != g_cryptoCurrency.GetHID() ||
        chainnum != g_cryptoCurrency.GetChainNum() ||
        localid != g_cryptoCurrency.GetLocalID()) {
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

bool GetNeighborNodes(list<string>& listNodes)
{
    CRITICAL_BLOCK(cs_vNodes)
    for (auto& n : vNodes) {
        listNodes.push_back(n->nodeid);
    }
    return true;
}

//
bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA)
{
    return true;

}

bool AcceptBlocks(vector<T_PAYLOADADDR>& vecPA)
{
    if (vecPA.size() == 0) {
        return false;
    }

    vector<CBlock> vecBlock;
    for (auto b : vecPA) {
        CBlock block;
        if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        vecBlock.push_back(std::move(block));
    }

    for (size_t i = 0; i < vecBlock.size(); i++) {
        //if (vecBlock[i].AcceptBlock(vecPA[i].addr)) {
        if (ProcessBlockFromAcceptedHyperBlock(&vecBlock[i], &vecPA[i].addr)) {
            uint256 hash = vecBlock[i].GetHash();
            printf("AcceptBlocks() : (%s) %s is accepted\n", vecPA[i].addr.tostring().c_str(),
                hash.ToString().substr(0, 20).c_str());
        }
        else {
            WARNING_FL("(%s) cannot be accepted", vecPA[i].addr.tostring().c_str());
        }
    }

    //
    auto& lastblock = vecBlock.back();
    uint32_t hid = lastblock.nPrevHID;
    uint256 hash = lastblock.GetHash();

    CBlockIndex* pindexLast = nullptr;
    if (!mapBlockIndex.count(hash)) {
        return true;
    }

    pindexLast = mapBlockIndex.at(hash);
    bool bchainSwitch = false;

    //
    if (pindexBest->nPrevHID <= hid) {
        bchainSwitch = true;
    }
    else {

        bchainSwitch = true;

        CBlockIndex* pfork = pindexBest;
        CBlockIndex* pbetter = pindexLast;
        while (pfork != pindexLast) {
            while (pbetter->nHeight > pfork->nHeight)
                if (!(pbetter = pbetter->pprev))
                    break;
            if (pfork == pbetter) {
                bchainSwitch = false;
                break;
            }
            if (!(pfork = pfork->pprev))
                break;
        }
    }

    if (bchainSwitch) {
       
        CTxDB txdb;
        lastblock.SetBestChain(txdb, pindexLast);
        INFO_FL("Switch to: %d,hid:%d,%s, %s, BestIndex: %d hid:%d,%s, %s LastHID: %u", pindexLast->nHeight,
            pindexLast->nPrevHID,
            pindexLast->addr.tostring().c_str(),
            pindexLast->GetBlockHash().ToPreViewString().c_str(),
            pindexBest->nHeight, pindexBest->nPrevHID,
            pindexBest->addr.tostring().c_str(),
            pindexBest->GetBlockHash().ToPreViewString().c_str(),
            GetLastHyperBlockID());

        ProcessOrphanBlocks(pindexBest->GetBlockHash());
    }

    return true;
}


//
bool AcceptChainCb(const T_APPTYPE& app, vector<T_PAYLOADADDR>& vecPA, uint32_t& hid, T_SHA256& thhash)
{
    CRITICAL_BLOCK(cs_main)
    {
        CompareAndUpdateLastHyperBlock(hid, thhash);
        T_APPTYPE meApp(APPTYPE::paracoin, g_cryptoCurrency.GetHID(),
                                           g_cryptoCurrency.GetChainNum(),
                                           g_cryptoCurrency.GetLocalID());
        if (app == meApp) {
            return AcceptBlocks(vecPA);
        }
    }
    return true;
}

bool CheckChainCbWhenOnChaining(vector<T_PAYLOADADDR>& vecPA, uint32_t prevhid, T_SHA256& tprevhhash)
{
    if (vecPA.size() == 0) {
        return false;
    }

    vector<CBlock> vecBlock;
    for (auto b : vecPA) {
        CBlock block;
        if (!ResolveBlock(block, b.payload.c_str(), b.payload.size())) {
            return ERROR_FL("ResolveBlock FAILED");
        }
        vecBlock.push_back(std::move(block));
    }

    uint256 prevhhash = uint256S(tprevhhash.toHexString());
    for (size_t i = 0; i < vecBlock.size(); i++) {
        if (vecBlock[i].nPrevHID != prevhid ||
            vecBlock[i].hashPrevHyperBlock != prevhhash) {
            return false;
        }
    }

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
    CRITICAL_BLOCK(cs_main)
    {
        if (!block.CheckBlock())
            return ERROR_FL("CheckBlock FAILED");

        if (!block.CheckTrans())
            return ERROR_FL("CheckTrans FAILED");

        CTxDB txdb("r");
        for (auto tx : block.vtx) {
            if (tx.IsCoinBase()) {
                continue;
            }

            //
            map<uint256, CTxIndex> mapUnused;
            int64 nFees = 0;
            if (!tx.ConnectInputs(txdb, mapUnused, CDiskTxPos(1), pindexBest, nFees, false, false)) {
                return ERROR_FL("ConnectInputs failed %s",
                    payloadaddr.addr.tostring().c_str());
            }
        }
    }

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

/*
bool UpdateParaCoinDataCb(string& payload, string &newpaylod)
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
    //block.nBits = GetNextWorkRequired(pindexPrev);
    //block.nNonce = 0;

    block.SetHyperBlockInfo();

    CDataStream datastream(SER_BUDDYCONSENSUS);
    try {
        datastream << block;
        newpaylod = datastream.str();
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Error: Cannot extract block data, %s\n", e.what());
    }
    return true;
}
*/

//
bool BlockUUIDCb(string& payload, string& uuidpayload)
{
    //
    //
    uuidpayload = payload.substr(0, sizeof(int));
    //
    uuidpayload += payload.substr(sizeof(int) + sizeof(uint256));
    return true;
}

//
bool PutParaCoinChainCb()
{
    deque<CBlock> deqblock;

    uint256 hhash;

    bool isSwithBestToValid = false;
    CBlockIndex* pindexValidStarting = nullptr;
    CRITICAL_BLOCK(cs_main)
    {
        CRITICAL_BLOCK(cs_mapBlocks)
        {
            uint64 nHID = GetLastHyperBlockID(&hhash);
            CBlockIndex* p = pindexBest;

            while (p && (p->nPrevHID >= nHID)) {
                if (!p->pprev) {
                    break;
                }
                p = p->pprev;
                continue;
            }

            if (p && p->nPrevHID != nHID) {
                p = p->pnext;
            }

            if (p && p == pindexGenesisBlock)
                p = p->pnext;

            if (!p) {
                return false;
            }

            //
            if (!p->pprev->addr.isValid()) {
                isSwithBestToValid = true;
                pindexValidStarting = p->pprev;
                 WARNING_FL("Paracoin previous block is not onchained: %d", p->pprev->nHeight);
            }
            else {

                //
                //if (p->hashPrevHyperBlock != uint256S(hash.toHexString())) {
                //    return ERROR_FL("Paracoin block's previous hyper block hash is different: %d", nHID);
                //}
                while (p && p->nPrevHID == nHID && p->hashPrevHyperBlock == hhash) {
                    if (mapBlocks.count(p->GetBlockHash())) {
                        deqblock.push_back(mapBlocks[p->GetBlockHash()]);
                        p = p->pnext;
                        continue;
                    }
                    break;
                }
            }
        }
    
    //
    
        if (isSwithBestToValid) {
            CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
            for (;pindexValidStarting;) {
                if (!pindexValidStarting->addr.isValid()) {
                    pindexValidStarting = pindexValidStarting->pprev;
                }
                else {
                    string payload;
                    if (!hyperchainspace->GetLocalBlockPayload(pindexValidStarting->addr, payload)) {
                        //
                        RSyncRemotePullHyperBlock(pindexValidStarting->addr.hid);
                        WARNING_FL("Lack of hyper block: %d, pulling from remote nodes", pindexValidStarting->addr.hid);
                        break;
                    }
                    CBlock tailblock;
                    if (!ResolveBlock(tailblock, payload.c_str(), payload.length())) {
                        ERROR_FL("Failed to resolve paracoin block: %s", pindexValidStarting->addr.tostring().c_str());
                        pindexValidStarting = pindexValidStarting->pprev;
                        continue;
                    }
               
                    CTxDB txdb;
                    tailblock.SetBestChain(txdb, pindexValidStarting);

                    INFO_FL("Switch to: %d,hid:%d,%s, %s, BestIndex: %d hid:%d,%s, %s LastHID: %u", pindexValidStarting->nHeight,
                        pindexValidStarting->nPrevHID,
                        pindexValidStarting->addr.tostring().c_str(),
                        pindexValidStarting->GetBlockHash().ToPreViewString().c_str(),
                        pindexBest->nHeight, pindexBest->nPrevHID,
                        pindexBest->addr.tostring().c_str(),
                        pindexBest->GetBlockHash().ToPreViewString().c_str(),
                        GetLastHyperBlockID());

                    ProcessOrphanBlocks(pindexValidStarting->GetBlockHash());
                    break;
                }
            }
        }

    }

    if (deqblock.size() <= 0) {
        return true;
    }

    auto tail_block = deqblock.back();
    if (!tail_block.IsMine()) {
        //
        return true;
    }

    string requestid, errmsg;
    if (!CommitChainToConsensus(deqblock, requestid, errmsg)) {
        printf("CommitChainToConsensus() Error: %s", errmsg.c_str());
        return false;
    }

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
                    p = p->pnext;
                }
                return true;
            }
        }
    }
    return false;
}

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

#define one_day 24 * 60 * 60
void ThreadBlockPool(void* parg)
{
    while (!fShutdown) {
        int nRemoved = 0;
        CRITICAL_BLOCK(cs_mapBlocks)
        {
            CBlockDB blockdb;
            blockdb.TxnBegin();
            auto begBlock = mapBlocks.begin();
            auto t = GetTime();
            for (; begBlock != mapBlocks.end();) {

                bool isInBestChain = false;
                CBlockIndex* p = pindexBest;
                while (p && !p->addr.isValid()) {
                    if (p->GetBlockHash() == begBlock->first) {
                        isInBestChain = true;
                        break;
                    }
                    p = p->pprev;
                }

                if (isInBestChain || begBlock->second.nTime > t - one_day) {
                    ++begBlock;
                    continue;
                }

                blockdb.EraseBlock(begBlock->first);
                begBlock = mapBlocks.erase(begBlock);
                nRemoved++;
            }
            blockdb.TxnCommit();
        }
        INFO_FL("Removed %d expired blocks in the block pool\n", nRemoved);
        SleepFn(one_day);
    }
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
    CRITICAL_BLOCK(cs_main)
    {
        if (pindexBest->addr < addrMaxChain) {
            CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
            T_APPTYPE app(APPTYPE::paracoin);
            vector<T_PAYLOADADDR> vecPA;
            uint64 hid = pindexBest->addr.hid + 1;
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

void ThreadForwardBestIndex(void* parg)
{
    T_APPTYPE app(APPTYPE::paracoin, g_cryptoCurrency.GetHID(), g_cryptoCurrency.GetChainNum(), g_cryptoCurrency.GetLocalID());

    while (!fShutdown) {
        SleepFn(60);
        time_t now = time(nullptr);
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        CRITICAL_BLOCK(cs_main)
        {
            CBlockIndex* pIndex = pindexBest;
            while (pIndex && !pIndex->addr.isValid()) {
                pIndex = pIndex->pprev;
            }
            if (!pIndex) {
                continue;
            }
            uint32_t hid = pIndex->addr.hid + 1;
            uint32_t last_hid = GetLastHyperBlockID();
            //
            for (;;hid++) {
                vector<T_PAYLOADADDR> vecPA;
                T_SHA256 thhash;
                if (!hyperchainspace->GetLocalBlocksByHID(hid, app, thhash, vecPA)) {
                    //
                    if (hid < last_hid)
                        RSyncRemotePullHyperBlock(hid);
                    break;
                }
                INFO_FL("Forward best index to hyper block: %d", hid);
                if (vecPA.size() > 0 && !AcceptChainCb(app, vecPA, hid, thhash)) {
                    WARNING_FL("Failed to forward best index to hyper block: %d", hid);
                    break;
                }
            }
        }
    }
}

//
//
void ThreadRSyncGetBlock(void* parg)
{
    while (!fShutdown) {
        time_t now = time(nullptr);
        CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        CRITICAL_BLOCK(cs_pullingHyperBlock)
        {
            auto bg = mapPullingHyperBlock.begin();
            for (; bg != mapPullingHyperBlock.end();) {
                if (bg->second + 120 < now) {
                    T_HYPERBLOCK h;
                    if (hyperchainspace->getHyperBlockFromDB(bg->first, h)) {
                        bg = mapPullingHyperBlock.erase(bg);
                    }
                    else {
                        hyperchainspace->GetRemoteHyperBlockByID(bg->first);
                        bg->second = now;
                    }
                }
                else {
                    ++bg;
                }
            }
        }
        SleepFn(20);
    }

    return;

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
    std::printf("Best chain Paracoin block addr:%s Height:%d \nPrev Block Hash:%s\n Hash:%s \n%p\n", pindexBest->addr.tostring().c_str(),
        pindexBest->nHeight, pindexBest->pprev->GetBlockHash().ToString().c_str(),
        pindexBest->GetBlockHash().ToString().c_str(),
        pindexBest);
    std::printf("Show more details: ld hid [+/-count]\n\n");
}

void showBlockIndex(uint32 startingHID, uint32 count)
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
    std::printf("Best chain block addr:%s Height:%d %p\n", pindexBest->addr.tostring().c_str(),
        pindexBest->nHeight, pindexBest);
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
        std::printf("Height:%d\n", pindexBest->nHeight);
        std::printf("PreHash:%s\n", pindexBest->pprev->GetBlockHash().ToString().c_str());
        std::printf("Hash:%s\n", pindexBest->GetBlockHash().ToString().c_str());
        std::printf("\tpnext:%p", idx->pnext);
        std::printf("\tpprev:%p\n", idx->pprev);
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
    oss << "Paracoin module's current coin name: " << g_cryptoCurrency.GetName() << " - "
        << g_cryptoCurrency.GetHashPrefixOfGenesis() << endl
        << "block message: " << g_cryptoCurrency.GetDesc() << endl
        << "model: " << g_cryptoCurrency.GetModel() << endl
        << "Genesis block address: " << g_cryptoCurrency.GetHID() << " " 
        << g_cryptoCurrency.GetChainNum() << " " 
        << g_cryptoCurrency.GetLocalID() << endl
        << "Neighbor node amounts: " << vNodes.size() << endl
        << "Allow Mining: " << g_cryptoCurrency.AllowMining() << endl;
    info = oss.str();

    if (!pindexBest) {
        info += "Best block is unknown\n";
        return;
    }
    string strOrphanBlocks;
    CRITICAL_BLOCK(cs_main)
    {
        for (auto& elm : mapOrphanBlocks) {
            strOrphanBlocks += std::to_string(elm.second->nHeight);
            strOrphanBlocks += ";";
        }
    }

    const char *fmt = "Best block height: %d\n"
        "Address: %s \n"
        "HashPrevBlock: %s\n"
        "Hash: %s\n"
        "Work: %s\n"
        "Pointer: %p\n"
        "OrphanBlocks: %s\n"
        "block cache size: %u \n";

    int sz = std::snprintf(nullptr, 0, fmt,
        pindexBest->nHeight,
        pindexBest->addr.tostring().c_str(),
        pindexBest->pprev ? (pindexBest->pprev->GetBlockHash().ToString().c_str()) : "null",
        pindexBest->GetBlockHash().ToString().c_str(), bnBestChainWork.ToString().c_str(),
        pindexBest,strOrphanBlocks.c_str(),
        mapBlocks.size());

    std::string buf(sz, 0);
    std::snprintf(&buf[0], buf.size()+1, fmt,
        pindexBest->nHeight,
        pindexBest->addr.tostring().c_str(),
        pindexBest->pprev ? (pindexBest->pprev->GetBlockHash().ToString().c_str()) : "null",
        pindexBest->GetBlockHash().ToString().c_str(), bnBestChainWork.ToString().c_str(),
        pindexBest,strOrphanBlocks.c_str(),
        mapBlocks.size());

    info += buf;

}

bool ResolveBlock(CBlock &block, const char *payload, size_t payloadlen)
{
    CDataStream datastream(payload, payload + payloadlen, SER_BUDDYCONSENSUS);
    try {
        datastream >> block;
    }
    catch (const std::ios_base::failure& e) {
        return ERROR_FL("Error: Cannot resolve block data, %s\n", e.what());
    }
    return true;
}

bool ResolveHeight(int height, string& info)
{
    CBlockIndex* p = pindexBest;
    while (p) {
        if (p->nHeight == height) {
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
