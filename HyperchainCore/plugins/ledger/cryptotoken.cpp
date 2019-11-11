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
#include "cryptotoken.h"


#ifndef __WXMSW__
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <map>
#include <vector>
#include <string>
using namespace std;

#include <boost/program_options/detail/config_file.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#define GENESISBLOCK_VIN_COUNT 1

extern string CreateChildDir(const string& childdir);
extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);
extern void RSyncRemotePullHyperBlock(uint32_t hid, string nodeid = "");

string GetKeyConfigFile()
{
    namespace fs = boost::filesystem;
    fs::path pathConfig;

    pathConfig = fs::path(GetHyperChainDataDir()) / "key.db";
    return pathConfig.string();
}

bool ReadKeyFromFile(CKey& key)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    //fs::ifstream streamConfig(GetKeyConfigFile("ledger"), std::ios::out | std::ios::binary);
    fs::ifstream streamConfig(GetKeyConfigFile());
    if (!streamConfig.good())
        return false;

    set<string> setOptions;
    setOptions.insert("*");

    std::map<std::string, std::string> mapKey;
    for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it) {
        mapKey[it->string_key] = it->value[0];
    }
    auto& k = mapKey["publickey"];
    std::vector<unsigned char> vchPubKey = ParseHex(k);
    key.SetPubKey(vchPubKey);

    auto& strkey = mapKey["privatekey"];
    auto vchPriKey = ParseHex(strkey);
    CPrivKey privkey;
    privkey.resize(vchPriKey.size());
    std::copy(vchPriKey.begin(), vchPriKey.end(), privkey.begin());

    key.SetPrivKey(privkey);
    return true;
}

bool WriteKeyToFile(const CKey& key)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    fs::ofstream streamConfig(GetKeyConfigFile());
    if (!streamConfig.good())
        return false;

    std::vector<unsigned char> vecPub = key.GetPubKey();
    string pubkey = HexStr(vecPub);
    streamConfig << "publickey" << " = " << pubkey << endl;

    CPrivKey vecPriv = key.GetPrivKey();
    string prikey = HexStr(vecPriv.begin(), vecPriv.end());
    streamConfig << "privatekey" << " = " << prikey << endl;

    return true;
}


CBlock CreateGenesisBlock(const string& name, const string& desc, vector<unsigned char> logo,
    const CScript& genesisOutputScript, uint32_t nTime,
    int32_t nVersion, const int64_t& genesisSupply)
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

    txNew.vin[0].scriptSig << logo;

    txNew.vout[0].nValue = genesisSupply;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
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

extern CWallet* pwalletMain;
CBlock CreateGenesisBlock(uint32_t nTime, const string& name, const string& desc, vector<unsigned char> logo, int32_t nVersion,
    const int64_t& genesisSupply, const std::vector<unsigned char>& newPublicKey)
{
    //const CScript genesisOutputScript = CScript() 
    //    << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;

    //
    const CScript genesisOutputScript = CScript() << newPublicKey << OP_CHECKSIG;

    return CreateGenesisBlock(name, desc, logo, genesisOutputScript, nTime, nVersion, genesisSupply);
}

CBlock SearchGenesisBlock(uint32_t nTime, const string& name, const string& desc, vector<unsigned char> logo, int32_t nVersion, const int64_t& genesisReward,
    const CKey& newKey)
{
    CBlock genesis;
    genesis = CreateGenesisBlock(nTime, name, desc, logo, nVersion, genesisReward, newKey.GetPubKey());

    return genesis;
}

//
void NewGenesisBlock(uint32_t nTime, const string& name, const string& desc, vector<unsigned char> logo, int32_t nVersion, const int64_t& genesisSupply,
    CKey& newKey)
{
    CBlock genesis = SearchGenesisBlock(nTime, name, desc, logo, nVersion, genesisSupply, newKey);

    string strhash;
    string strMerkleRoothash;

    uint256 hashGenesis = genesis.GetHash();
    strhash = hashGenesis.ToString();

    uint256 hashMerkleRoot = genesis.hashMerkleRoot;
    strMerkleRoothash = hashMerkleRoot.ToString();

    vector<unsigned char> newPublicKey = newKey.GetPubKey();
    CBitcoinAddress address(newPublicKey);

    string pubkey(newPublicKey.begin(), newPublicKey.end());


#undef printf
    std::printf("%s:\nPublicKey: %s \nAddress: %s \nBlock Hash: %s\n MerkleRootHash: %s\n",
        __FUNCTION__,
        pubkey.c_str(),
        address.ToString().c_str(),
        strhash.c_str(),
        strMerkleRoothash.c_str());
    std::printf(" nTime: %d\n", nTime);
}

string GetTokenWalletFile(const string& name)
{
    namespace fs = boost::filesystem;
    fs::path pathConfig;
    pathConfig.append(name);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "wallet.dat";
    return pathConfig.string();
}

string TokenConfigPath(const string& shorthash)
{
    const char* fmt = "%s";

    int sz = std::snprintf(nullptr, 0, fmt, shorthash.c_str());
    std::string relpath(sz, 0);
    std::snprintf(&relpath[0], relpath.size() + 1, fmt, shorthash.c_str());

    return relpath;
}

string CryptoToken::GetTokenConfigPath()
{
    return TokenConfigPath(GetHashPrefixOfGenesis());
}

string CryptoToken::GetTokenConfigFile(const string& shorthash)
{
    namespace fs = boost::filesystem;
    fs::path pathConfig;

    std::string relpath = TokenConfigPath(shorthash);
    pathConfig.append(relpath);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "token.ini";
    return pathConfig.string();
}

string CryptoToken::GetTokenConfigFile()
{
    namespace fs = boost::filesystem;
    fs::path pathConfig;

    std::string relpath = GetTokenConfigPath();
    pathConfig.append(relpath);

    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetHyperChainDataDir()) / pathConfig / "token.ini";
    return pathConfig.string();
}

bool CryptoToken::ParseTimestamp(const CBlock& genesis)
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
    mapSettings["logo"] = string(vch.begin(), vch.end());

    return true;
}

bool CryptoToken::ParseToken(const CBlock& genesis)
{
    mapSettings["time"] = std::to_string(genesis.nTime);
    mapSettings["version"] = std::to_string(genesis.nVersion);

    try {
        if (!ParseTimestamp(genesis))
            return false;

        mapSettings["supply"] = std::to_string(genesis.vtx[0].vout[0].nValue / COIN);

        opcodetype opcode;
        vector<unsigned char> vch;
        CScript scriptSig = genesis.vtx[0].vout[0].scriptPubKey;
        auto script_iter = scriptSig.cbegin();
        if (!scriptSig.GetOp(script_iter, opcode, vch)) {
            return false;
        }

        mapSettings["publickey"] = HexStr(vch);

        std::vector<unsigned char> ownerPublicKey(vch.begin(), vch.end());

        CBitcoinAddress addr(ownerPublicKey);
        mapSettings["address"] = addr.ToString();

        mapSettings["hashgenesisblock"] = genesis.GetHash().ToString();
        mapSettings["hashmerkleroot"] = genesis.hashMerkleRoot.ToString();
    }
    catch (std::exception & e) {
        std::printf("%s Failed %s\n", __FUNCTION__, e.what());
        return false;
    }

    return true;
}

bool CryptoToken::IsSysToken(const string& shorthash)
{
    return shorthash == GetHashPrefixOfSysGenesis();
}

//
bool CryptoToken::ReadTokenFile(const string& name, string& shorthash, string& errormsg)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    if (shorthash.empty() && !name.empty()) {
        if (!SearchTokenByName(name, shorthash, errormsg)) {
            return false;
        }
    }

    string datapath = TokenConfigPath(shorthash);

    if (IsSysToken(shorthash)) {
        SelectNetWorkParas();
        return true;
    }
    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {
            if (item_begin->path().filename().string() == datapath) {

                fs::ifstream streamConfig(GetTokenConfigFile(shorthash));
                if (!streamConfig.good()) {
                    errormsg = "cannot open token configuration file";
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
    errormsg = "cannot find the token named " + name;
    return false;
}

bool CryptoToken::SearchTokenByTriple(uint32_t hid, uint16 chainnum, uint16 localid,
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

            CryptoToken cc;
            string errmsg;
            if (cc.ReadTokenFile("", shorthash, errmsg)) {
                if (cc.IsTokenSame(hid, chainnum, localid)) {
                    coinname = cc.GetName();
                    coinshorthash = cc.GetHashPrefixOfGenesis();
                    return true;
                }
            }
        }
    }

    return false;
}

bool CryptoToken::SearchTokenByName(const string& tokenname, string& tokenshorthash, string& errormsg)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    fs::directory_iterator item_begin(GetHyperChainDataDir());
    fs::directory_iterator item_end;

    std::list<string> listPath;
    for (; item_begin != item_end; item_begin++) {
        if (fs::is_directory(*item_begin)) {

            string currpath = item_begin->path().filename().string();
            CryptoToken t;
            if (t.ReadTokenFile("", currpath, errormsg)) {
                if (t.GetName() == tokenname) {
                    listPath.push_back(currpath);
                }
            }
        }
    }

    if (listPath.size() == 0 || listPath.size() > 1) {
        //I don't know read which one
        listPath.size() > 1 ? (errormsg = "found multiple token named " + tokenname) :
            (errormsg = "cannot find token named " + tokenname);
        return false;
    }

    tokenshorthash = *listPath.begin();
    return true;
}

bool CryptoToken::WriteTokenFile()
{
    namespace fs = boost::filesystem;
    CreateChildDir(GetTokenConfigPath());
    fs::ofstream streamConfig(GetTokenConfigFile());
    if (!streamConfig.good())
        return false;

    for (auto& optional : mapSettings) {
        streamConfig << optional.first << " = " << optional.second << endl;
    }
    return true;
}

CBlock CryptoToken::GetGenesisBlock()
{
    string& logo = mapSettings["logo"];
    vector<unsigned char> veclogo(logo.begin(), logo.end());

    vector<unsigned char> pubkey = ParseHex(mapSettings["publickey"]);

    return CreateGenesisBlock(std::stol(mapSettings["time"]),
        mapSettings["name"],
        mapSettings["description"],
        veclogo,
        std::stoi(mapSettings["version"]),
        std::stoll(mapSettings["supply"]) * COIN, pubkey);
}


//
CBlock CryptoToken::MineGenesisBlock(const CKey& newKey)
{
    string& logo = mapSettings["logo"];
    vector<unsigned char> veclogo(logo.begin(), logo.end());

    CBlock genesis = SearchGenesisBlock(
        std::stol(mapSettings["time"]),
        mapSettings["name"],
        mapSettings["description"],
        veclogo,
        std::stoi(mapSettings["version"]),
        std::stoll(mapSettings["supply"]) * COIN, newKey);

    string strhash;
    string strMerkleRoothash;

    mapSettings["hashgenesisblock"] = genesis.GetHash().ToString();
    strhash = mapSettings["hashgenesisblock"];

    mapSettings["hashmerkleroot"] = genesis.hashMerkleRoot.ToString();
    strMerkleRoothash = mapSettings["hashmerkleroot"];

    std::vector<unsigned char> newPublicKey = newKey.GetPubKey();
    CBitcoinAddress address(newPublicKey);

    string pubkey = HexStr(newPublicKey);
    mapSettings["publickey"] = pubkey;
    mapSettings["address"] = address.ToString();


#undef printf
    std::printf("%s:\nPublicKey: %s \nAddress: %s \nBlock Hash: %s\n MerkleRootHash: %s\n",
        __FUNCTION__,
        pubkey.c_str(),
        address.ToString().c_str(),
        strhash.c_str(),
        strMerkleRoothash.c_str());

    return genesis;
}

bool CryptoToken::AddKeyToWallet(const CKey& newKey)
{
    //
    string currenttoken = g_cryptoToken.GetName();

    string strWallet = GetTokenWalletFile(GetTokenConfigPath());
    {
        CWallet wallet(strWallet.c_str());
        {
            CWalletDB db(wallet.strWalletFile, "cr+");
        }
        if (!wallet.AddKey(newKey)) {
            return false;
        }

        std::vector<unsigned char> vchDefaultKey = newKey.GetPubKey();
        wallet.SetDefaultKey(newKey.GetPubKey());
        wallet.SetAddressBookName(CBitcoinAddress(vchDefaultKey), "");
    }

    /*namespace fs = boost::filesystem;
    fs::path pathSrc = fs::path(GetHyperChainDataDir()) / currenttoken / strWallet;
    fs::path pathDest = fs::path(GetHyperChainDataDir()) / mapSettings["name"] / "wallet.dat";


    fs::copy_file(pathSrc, pathDest, fs::copy_option::overwrite_if_exists);
    fs::remove(pathSrc);*/

    return true;

}

bool CryptoToken::ContainToken(const string& tokenhash)
{
    bool isDefaultCoin = (tokenhash == GetHashPrefixOfSysGenesis());

    CryptoToken currency(isDefaultCoin);
    string tknhash = tokenhash;
    string errmsg;
    if (!isDefaultCoin && !currency.ReadTokenFile("", tknhash, errmsg)) {
        return false;
    }

    if (!currency.CheckGenesisBlock()) {
        return false;
    }

    return true;
}

bool CryptoToken::CheckGenesisBlock()
{
    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stol(mapSettings["hid"]),
        std::stol(mapSettings["chainnum"]),
        std::stol(mapSettings["localid"]));

    if (!addr.isValid()) {
        return ERROR_FL("The genesis block address of cryptotoken is invalid");
    }

    CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!hyperchainspace->GetLocalBlockPayload(addr, payload)) {
        RSyncRemotePullHyperBlock(addr.hid);
        return ERROR_FL("The genesis block of cryptotoken: %s not exists...", addr.tostring().c_str());
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


string CryptoToken::GetPath()
{
    namespace fs = boost::filesystem;
    string apppath = (fs::path(GetHyperChainDataDir()) / GetTokenConfigPath()).string();
    return apppath;
}

string CryptoToken::GetHashPrefixOfSysGenesis()
{
    CryptoToken cc;
    cc.SelectNetWorkParas();
    return cc.GetHashPrefixOfGenesis();
}

string CryptoToken::GetNameOfSysGenesis() {
    CryptoToken cc;
    cc.SelectNetWorkParas();
    return cc.GetName();

};

void CryptoToken::SetDefaultParas()
{
    mapSettings = { {"name", "ledger"},
                       {"description",""},
                       {"logo",""},
                       {"version","1"},
                       {"supply","100000000"},   //
                       {"time","1568277586"},
                       {"address","16RmSuJuiEjaZYSRCb3VYzEKLXp8zxjvXX"}, //
                       {"publickey","040b387e6c74db8aa3ea38d6708dba46ce345c9a3a2772021ef9ac5809663bff84f17e22cf4bc824d7848d932178a72b40a45050f3e5f5be97dc359019e91b5f6c"},
                       {"hashgenesisblock","1dc4e125f97802dc42d27e4b6f017ae44c49fbb07ded1a356e9f1ce3e816f3d7"},
                       {"hashmerkleroot","941c6319e19fd5c534f3341be13f2e219c48c053c3d524537aa977342b93a432"},
                       {"hid","0"},
                       {"chainnum","1"},
                       {"localid","3"},
    };
}

void CryptoToken::SelectNetWorkParas()
{
    string model = "sanbox";
    if (mapArgs.count("-model")) {
        model = mapArgs["-model"];
        if (model == "informal" || model == "formal") {
            mapSettings = { {"name", "ledger"},
                      {"description","www.hyperchain.net"},
                      {"logo",""},
                      {"version","1"},
                      {"supply","100000000"},                           //
                      {"time","1572531412"},
                      {"address","1Ao8Rk36otR5uksWQffCgcvQ6Y5YNkDB8J"}, //
                      {"publickey","040b29eb299db9348698e3bad3fa0532e98a4ceccf4d55786ea97222647ad0bf3327fca5cfef0809638bb67c5f9ca0b5badad32ff78203408eef64b75702990ba8"},
                      {"hashgenesisblock","9c7a96e0670a81e9071ae6cd438eb4579292bcc5046ed0233031ac3682431f7d"},
                      {"hashmerkleroot","bb076e94df2fc651e7040d2e7ba0232fc37b9b2bb511b33f967ce1d5b9cee4cd"},
                      {"hid","22030"},
                      {"chainnum","1"},
                      {"localid","2"},
            };
            return;
        }
    }
    //
    SetDefaultParas();
}
CryptoToken g_cryptoToken;
