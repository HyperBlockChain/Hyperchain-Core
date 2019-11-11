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


#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"

#include "headers.h"
#include "util.h"
#include "random.h"
#include "dllmain.h"
#include "cryptocurrency.h"


#ifndef __WXMSW__
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <map>
#include <vector>
#include <string>
using namespace std;

#define GENESISBLOCK_VIN_COUNT 1

#include <boost/program_options/detail/config_file.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

extern string CreateChildDir(const string& childdir);
extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);
extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");

std::mutex CryptoCurrency::muxUUID;
std::map<std::string, std::string> CryptoCurrency::mapUUIDRequestID;


CBlock CreateGenesisBlock(const string& name, const string& desc, const string& model, vector<unsigned char> logo,
    const CScript& genesisOutputScript, uint32_t nTime, uint64 nNonce,
    const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const int64_t& genesisReward)
{
    CTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(GENESISBLOCK_VIN_COUNT);
    txNew.vout.resize(1);
    //
    //txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) 
    txNew.vin[0].scriptSig = CScript()
        << std::vector<unsigned char>((const unsigned char*)(&name[0]), (const unsigned char*)(&name[0]) + name.size());

    txNew.vin[0].scriptSig
        << std::vector<unsigned char>((const unsigned char*)(&desc[0]), (const unsigned char*)(&desc[0]) + desc.size());

    txNew.vin[0].scriptSig
        << std::vector<unsigned char>((const unsigned char*)(&model[0]), (const unsigned char*)(&model[0]) + model.size());

    txNew.vin[0].scriptSig << logo;

    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nHeight = 0;
    genesis.nSolution = nSolution;
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}



/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
CBlock CreateGenesisBlock(uint32_t nTime, const string& name, const string& desc, const string& model, vector<unsigned char> logo, uint64 nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const int64_t& genesisReward)
{
    //
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(name, desc, model, logo, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

CBlock SearchGenesisBlock(progpow::search_result& r,
    uint32_t nTime, const string& name, const string& desc, const string& model, vector<unsigned char> logo, uint32_t nBits, int32_t nVersion, const int64_t& genesisReward)
{
    CBlock genesis;
    while (!fShutdown)
    {
        uint64 nonce = GetRandHash().GetUint64(3);
        genesis = CreateGenesisBlock(nTime, name, desc, model, logo,
            nonce,
            ParseHex("0000000000000000000000000000000000000000000000000000000000000000"), nBits, nVersion, genesisReward);

        CBigNum bnNew;
        bnNew.SetCompact(genesis.nBits);
        uint256 hashTarget = bnNew.getuint256();

        ethash::hash256 target;
        std::reverse_copy(hashTarget.begin(), hashTarget.end(), target.bytes);

        ethash::hash256 header_hash = genesis.GetHeaderHash();

        uint64_t start_nonce = genesis.nNonce;
        uint32_t epoch = ethash::get_epoch_number(genesis.nHeight);
        ethash_epoch_context epoch_ctx = ethash::get_global_epoch_context(epoch);

        uint64_t nMaxTries = 1000000;

        int64 nStart = GetTime();
        r = progpow::search_light(epoch_ctx, genesis.nHeight, header_hash, target, start_nonce, nMaxTries,
            [&nStart]() {
            //
            if (fShutdown) {
                return true;
            }
            if (GetTime() - nStart > 60 * 10) {
                return true;
            }
            return false;
        });
        if (r.solution_found) {
            //found, set nonce & mix hash
            genesis.nNonce = r.nonce;

            std::vector<unsigned char> soln;
            soln.resize(32);
            unsigned char* p = &*(soln.begin());
            memcpy(&p[0], r.mix_hash.bytes, 32);

            genesis.nSolution = soln;
            break;
        }
    }
    return genesis;
}

//
void NewGenesisBlock(uint32_t nTime, const string& name, const string& desc, const string& model, vector<unsigned char> logo, uint32_t nBits, int32_t nVersion, const int64_t& genesisReward)
{
    progpow::search_result r;

    int64 start = GetTime();
    CBlock genesis = SearchGenesisBlock(r, nTime, name, desc, model, logo, nBits, nVersion, genesisReward);
    int64 endtime = GetTime();

    string mix;
    string strhash;
    string strMerkleRoothash;
    if (r.solution_found) {
        //
        vector<unsigned char> vecMix(sizeof(r.mix_hash.bytes));
        std::reverse_copy(std::begin(r.mix_hash.bytes), std::end(r.mix_hash.bytes), vecMix.begin());

        uint256 mixhash(vecMix);
        mix = mixhash.ToString();

        uint256 hashGenesis = genesis.GetHash();
        strhash = hashGenesis.ToString();

        uint256 hashMerkleRoot = genesis.hashMerkleRoot;
        strMerkleRoothash = hashMerkleRoot.ToString();
    }
#undef printf
    std::printf("%s:\n Nonce: %" PRIx64 "\n Mix Hash(nSolution): %s\n Block Hash: %s\n MerkleRootHash: %s\n",
        __FUNCTION__, r.nonce, mix.c_str(), strhash.c_str(), strMerkleRoothash.c_str());
    std::printf(" nTime: %d\n", nTime);
    std::printf("time consuming: %d seconds\n\n", endtime - start);
}


string CurrencyConfigPath(const string& shorthash)
{
    const char* fmt = "%s";

    int sz = std::snprintf(nullptr, 0, fmt, shorthash.c_str());
    std::string relpath(sz, 0);
    std::snprintf(&relpath[0], relpath.size() + 1, fmt, shorthash.c_str());

    return relpath;
}

string CryptoCurrency::GetCurrencyConfigPath()
{
    return CurrencyConfigPath(GetHashPrefixOfGenesis());
}

string CryptoCurrency::GetCurrencyConfigFile(const string& shorthash)
{
    namespace fs = boost::filesystem;
    fs::path pathConfig;

    std::string relpath = CurrencyConfigPath(shorthash);
    pathConfig.append(relpath);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "coin.ini";
    return pathConfig.string();
}

string CryptoCurrency::GetCurrencyConfigFile()
{
    namespace fs = boost::filesystem;
    fs::path pathConfig;

    std::string relpath = GetCurrencyConfigPath();
    pathConfig.append(relpath);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "coin.ini";
    return pathConfig.string();
}

bool CryptoCurrency::ParseTimestamp(const CBlock& genesis)
{
    if (genesis.vtx[0].vin.size() != GENESISBLOCK_VIN_COUNT) {
        return false;
    }

    const CScript& scriptSig = genesis.vtx[0].vin[0].scriptSig;
    opcodetype opcode;
    vector<unsigned char> vch;

    auto script_iter = scriptSig.cbegin();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }
    mapSettings["name"] = string(vch.begin(), vch.end());

    vch.clear();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }
    mapSettings["description"] = string(vch.begin(), vch.end());

    vch.clear();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }
    mapSettings["model"] = string(vch.begin(), vch.end());

    vch.clear();
    if (!scriptSig.GetOp(script_iter, opcode, vch)) {
        return false;
    }
    mapSettings["logo"] = string(vch.begin(), vch.end());

    return true;
}

bool CryptoCurrency::ParseCoin(const CBlock& genesis)
{
    mapSettings["time"] = std::to_string(genesis.nTime);
    mapSettings["version"] = std::to_string(genesis.nVersion);

    try {
        if (!ParseTimestamp(genesis))
            return false;

        mapSettings["reward"] = std::to_string(genesis.vtx[0].vout[0].nValue / COIN);

        std::ostringstream oss;
        oss << "0x" << std::hex << genesis.nNonce;
        mapSettings["nonce"] = oss.str();

        oss.str("");
        oss << "0x" << std::hex << genesis.nBits;
        mapSettings["genesisbits"] = oss.str();

        vector<unsigned char> vecMix(genesis.nSolution.size());
        std::reverse_copy(std::begin(genesis.nSolution), std::end(genesis.nSolution), vecMix.begin());

        uint256 mixhash(vecMix);
        mapSettings["hashmix"] = mixhash.ToString();

        mapSettings["hashgenesisblock"] = genesis.GetHash().ToString();
        mapSettings["hashmerkleroot"] = genesis.hashMerkleRoot.ToString();
    }
    catch (std::exception & e) {
        std::printf("%s Failed %s\n", __FUNCTION__, e.what());
        return false;
    }

    return true;
}

bool CryptoCurrency::IsSysParaCoin(const string& shorthash)
{
    return shorthash == GetHashPrefixOfSysGenesis();
}

//
bool CryptoCurrency::ReadCoinFile(const string& name, string& shorthash, string& errormsg)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    if (shorthash.empty() && !name.empty()) {
        if (!SearchCoinByName(name, shorthash, errormsg)) {
            return false;
        }
    }

    string datapath = CurrencyConfigPath(shorthash);

    if (IsSysParaCoin(shorthash)) {
        SelectNetWorkParas();
        return true;
    }

    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;

    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            if (item_begin->path().filename().string() == datapath) {

                fs::ifstream streamConfig(GetCurrencyConfigFile(shorthash));
                if (!streamConfig.good()) {
                    errormsg = "cannot open coin configuration file";
                    return false;
                }

                set<string> setOptions;
                setOptions.insert("*");

                for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
                    mapSettings[it->string_key] = it->value[0];
                }
                return true;
            }
        }
    }
    errormsg = "cannot find the coin named " + name;
    return false;
}

bool CryptoCurrency::SearchCoinByTriple(uint32_t hid, uint16 chainnum, uint16 localid,
                                        string& coinname, string& coinshorthash)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            string shorthash = item_begin->path().filename().string();

            CryptoCurrency cc;
            string errmsg;
            if(cc.ReadCoinFile("", shorthash, errmsg)) {
                if (cc.IsCurrencySame(hid, chainnum, localid)) {
                    coinname = cc.GetName();
                    coinshorthash = cc.GetHashPrefixOfGenesis();
                    return true;
                }
            }
        }
    }

    return false;
}

bool CryptoCurrency::SearchCoinByName(const string& coinname, string& coinshorthash, string& errormsg)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {

            string currpath = item_begin->path().filename().string();
            CryptoCurrency t;
            if (t.ReadCoinFile("", currpath, errormsg)) {
                if (t.GetName() == coinname) {
                    listPath.push_back(currpath);
                }
            }
        }
    }

    if (listPath.size()== 0 || listPath.size() > 1) {
        //I don't know read which one
        listPath.size() > 1 ? (errormsg = "found multiple coins named " + coinname) :
            (errormsg = "cannot find coin named " + coinname);
        return false;
    }

    coinshorthash = *listPath.begin();
    return true;
}

bool CryptoCurrency::WriteCoinFile()
{
    namespace fs = boost::filesystem;
    CreateChildDir(GetCurrencyConfigPath());
    fs::ofstream streamConfig(GetCurrencyConfigFile());
    if (!streamConfig.good())
        return false;

    for (auto& optional : mapSettings) {
        streamConfig << optional.first << " = " << optional.second << endl;
    }
    return true;
}

CBlock CryptoCurrency::GetGenesisBlock()
{
    string& logo = mapSettings["logo"];
    vector<unsigned char> veclogo(logo.begin(), logo.end());

    string strBits = mapSettings["genesisbits"];

    return CreateGenesisBlock(std::stol(mapSettings["time"]),
        mapSettings["name"],
        mapSettings["description"],
        mapSettings["model"],
        veclogo,
        std::stoull(mapSettings["nonce"], 0, 16),
        ParseHex(mapSettings["hashmix"]),
        std::stol(strBits, 0, 16),
        std::stoi(mapSettings["version"]),
        std::stoi(mapSettings["reward"]) * COIN);
}



//
CBlock CryptoCurrency::MineGenesisBlock()
{
    string& logo = mapSettings["logo"];
    vector<unsigned char> veclogo(logo.begin(), logo.end());

    int64 start = GetTime();

    progpow::search_result r;
    CBlock genesis = SearchGenesisBlock(r,
        std::stol(mapSettings["time"]),
        mapSettings["name"],
        mapSettings["description"],
        mapSettings["model"],
        veclogo,
        std::stol(mapSettings["genesisbits"], 0, 16),
        std::stoi(mapSettings["version"]),
        std::stoi(mapSettings["reward"]) * COIN);
    int64 endtime = GetTime();

    string mix;
    string strhash;
    string strMerkleRoothash;
    if (r.solution_found) {
        //
        vector<unsigned char> vecMix(sizeof(r.mix_hash.bytes));
        std::reverse_copy(std::begin(r.mix_hash.bytes), std::end(r.mix_hash.bytes), vecMix.begin());

        std::ostringstream oss;
        oss << "0x" << std::hex << r.nonce;
        mapSettings["nonce"] = oss.str();

        uint256 h(vecMix);
        mapSettings["hashmix"] = h.ToString();
        mix = mapSettings["hashmix"];

        mapSettings["hashgenesisblock"] = genesis.GetHash().ToString();
        strhash = mapSettings["hashgenesisblock"];

        mapSettings["hashmerkleroot"] = genesis.hashMerkleRoot.ToString();
        strMerkleRoothash = mapSettings["hashmerkleroot"];
    }
#undef printf
    std::printf("%s:\n Nonce: %" PRIx64 "\n Mix Hash(nSolution): %s\n Block Hash: %s\n MerkleRootHash: %s\n",
        __FUNCTION__, r.nonce, mix.c_str(), strhash.c_str(), strMerkleRoothash.c_str());
    std::printf(" nTime: %s\n", mapSettings["time"].c_str());
    std::printf("time consuming: %d seconds\n\n", endtime - start);

    return genesis;
}

bool CryptoCurrency::ContainCurrency(const string& currencyhash)
{
    bool isDefaultCoin = (currencyhash == GetHashPrefixOfSysGenesis());

    CryptoCurrency currency(isDefaultCoin);
    string coinhash = currencyhash;
    string errmsg;

    if (!isDefaultCoin && !currency.ReadCoinFile("", coinhash, errmsg)) {
        return false;
    }

    if (!currency.CheckGenesisBlock()) {
        return false;
    }

    return true;
}

bool CryptoCurrency::CheckGenesisBlock()
{
    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stol(mapSettings["hid"]),
        std::stol(mapSettings["chainnum"]),
        std::stol(mapSettings["localid"]));

    if (!addr.isValid()) {
        return ERROR_FL("The genesis block address of cryptocurrency is invalid");
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!hyperchainspace->GetLocalBlockPayload(addr, payload)) {
        RSyncRemotePullHyperBlock(addr.hid);
        return ERROR_FL("The genesis block of cryptocurrency: %s not exists...", addr.tostring().c_str());
    }

    CBlock genesis;
    if (!ResolveBlock(genesis, payload.c_str(), payload.size())) {
        return ERROR_FL("ResolveBlock FAILED");
    }

    uint256 hashGenesis = genesis.GetHash();
    uint256 hashG = uint256S(mapSettings["hashgenesisblock"].c_str());
    if (hashGenesis != hashG) {
        return ERROR_FL("hashGenesis FAILED");
    }
    return true;
}

string CryptoCurrency::GetHashPrefixOfSysGenesis()
{
    CryptoCurrency cc;
    cc.SelectNetWorkParas();
    return cc.GetHashPrefixOfGenesis();
}

string CryptoCurrency::GetNameOfSysGenesis() {
    CryptoCurrency cc;
    cc.SelectNetWorkParas();
    return cc.GetName();

};

string CryptoCurrency::GetRequestID(const string& uuid)
{
    std::lock_guard<std::mutex> guard(CryptoCurrency::muxUUID);

    if (CryptoCurrency::mapUUIDRequestID.count(uuid) == 0) {
        throw runtime_error("uuid not exist");
    }

    return CryptoCurrency::mapUUIDRequestID[uuid];
}

bool CryptoCurrency::RsyncMiningGenesiBlock()
{
    string uuid = GetUUID();
    
    {
        std::lock_guard<std::mutex> guard(CryptoCurrency::muxUUID);
        CryptoCurrency::mapUUIDRequestID[uuid] = "";
    }

    CBlock genesis = MineGenesisBlock();
    string hash = GetHashPrefixOfGenesis();
    string errmsg;
    if (ReadCoinFile(GetName(), hash, errmsg)) {
        return ERROR_FL("The CryptoCoin already existed");
    }

    if (!WriteCoinFile()) {
        return ERROR_FL("WriteCoinFile failed");
    }

    string requestid;
    if (!CommitGenesisToConsensus(&genesis, requestid, errmsg)) {
        string tmp = string("CommitGenesisToConsensus failed: ") + errmsg;
        return ERROR_FL("%s",tmp.c_str());
    }

    std::lock_guard<std::mutex> guard(CryptoCurrency::muxUUID);
    CryptoCurrency::mapUUIDRequestID[uuid] = requestid ;

    return true;
}

string CryptoCurrency::GetUUID()
{
    string& name = mapSettings["name"];
    string& desc = mapSettings["description"];
    string& t = mapSettings["time"];

    uint256 hash = Hash(name.begin(), name.end(),
        desc.begin(), desc.end(),
        t.begin(), t.end());
    return hash.ToString();
}

void CryptoCurrency::SetDefaultParas()
{
    //
    mapSettings = { {"name", "paracoin"},
                       {"description",""},
                       {"model","PARA"},                //PARA or Satoshi
                       {"logo",""},
                       {"bits","0x20000fff"},           //
                       {"genesisbits","0x21000fff"},    //
                       {"version","1"},
                       {"reward","8"},
                       {"time","1568277586"},
                       {"nonce","0xcb72d774d27c9d06"}, //
                       {"hashmix","0a51a7b9b8b96dcccf603559d4d7b172ebd8e5c0cc38a41facac1169e6507379"},
                       {"hashgenesisblock","01aed9dfab9efda53f10f7db02e7282a0d09bb73f73be7bc3ed7d22db011f1f8"},
                       {"hashmerkleroot","929eaf2c7db95f8283a8df8d1a2bacf7c579ddfc8f5ee1f70d19ef3de0a57d93"},
                       {"hid","0"},
                       {"chainnum","1"},
                       {"localid","2"},
                       {"mining","1"},                  //
    };

}

void CryptoCurrency::SelectNetWorkParas()
{
    string model = "sanbox";
    if (mapArgs.count("-model")) {
        model = mapArgs["-model"];
        if (model == "informal" || model == "formal") {
            mapSettings = { {"name", "paracoin"},
                                     {"description","www.hyperchain.net"},
                                     {"model","PARA"},                //PARA or Satoshi
                                     {"logo",""},
                                     {"bits","0x20000fff"},           //
                                     {"genesisbits","0x21000fff"},    //
                                     {"version","1"},
                                     {"reward","8"},
                                     {"time","1572513998"},
                                     {"nonce","0x1ff121f8a2638ac6"}, //
                                     {"hashmix","3c8faf8d061dc1d72690548cd34eb92a7aaaf73547138fbbd0672fdeb80b1a7d"},
                                     {"hashgenesisblock","0de3d1c7ff6c53ca2572cf26b72a2d9decc3d84ed800a03a4474daf34b055ba5"},
                                     {"hashmerkleroot","0034968dfbbcd0c04f0e2f83d4ddcd0d113d4bc62726eecc34f007ad9f970ed7"},
                                     {"hid","22008"},
                                     {"chainnum","1"},
                                     {"localid","2"},
                                     {"mining","1"},                  //
            };
            return;
        }
    }
    //
    SetDefaultParas();
}

CryptoCurrency g_cryptoCurrency;
