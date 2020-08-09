/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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


#ifndef __WXMSW__
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <map>
#include <vector>
#include <string>
#include <iterator>
using namespace std;


bool ReadKeyFromFile(CKey& key);
bool WriteKeyToFile(const CKey& key);

CBlock CreateGenesisBlock(uint32_t nTime, const char* pszTimestamp, uint64 nNonce,
    const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const int64_t& genesisSupply);

class CryptoToken
{
public:
    CryptoToken(bool isParaCoin = true)
    {
        SetDefaultParas();
        if (!isParaCoin) {
            clear();
        }
    }
    typedef std::map<std::string, std::string>::iterator iterator;
    typedef std::map<std::string, std::string>::const_iterator const_iterator;
    iterator begin() { return mapSettings.begin(); }
    iterator end() { return mapSettings.end(); }

    const_iterator begin() const { return mapSettings.begin(); }
    const_iterator end() const { return mapSettings.end(); }


    uint32_t GetHID() { return std::stoul(mapSettings["hid"]); }
    uint16_t GetChainNum() { return std::stoul(mapSettings["chainnum"]); }
    uint16_t GetLocalID() { return std::stoul(mapSettings["localid"]); }

    std::string GetName() { return mapSettings["name"]; }
    std::string GetDesc() { return mapSettings["description"]; }
    std::string GetLogo() { return mapSettings["logo"]; }
    std::string GetPublickey() { return mapSettings["publickey"]; }
    std::string GetAddress() { return mapSettings["address"]; }
    string GetPath();

    int64_t GetSupply() { return std::stoull(mapSettings["supply"]); }

    uint256 GetHashGenesisBlock() { return uint256S(mapSettings["hashgenesisblock"]); }
    string GetHashPrefixOfGenesis() { return mapSettings["hashgenesisblock"].substr(0, 10); }

    static string GetHashPrefixOfSysGenesis();
    static string GetNameOfSysGenesis();

    static bool ContainToken(const string& tokenhash);

    bool AddKeyToWallet(const CKey& newKey);

    void SetName(const std::string& appname) { mapSettings["name"] = appname; }
    void SetParas(const std::map<string, string>& settings)
    {
        for (auto& optional : mapSettings) {
            if (settings.count(optional.first)) {
                optional.second = settings.at(optional.first);
            }
        }
    }

    bool SetGenesisAddr(uint32_t hid, uint16_t chainnum, uint16_t localid)
    {
        mapSettings["hid"] = std::to_string(hid);
        mapSettings["chainnum"] = std::to_string(chainnum);
        mapSettings["localid"] = std::to_string(localid);
        return WriteTokenFile();
    }

    bool ParseToken(const CBlock& genesis);

    bool IsSysToken()
    {
        return GetNameOfSysGenesis() == GetName() && GetHashPrefixOfGenesis() == GetHashPrefixOfGenesis();
    }

    static bool IsSysToken(const string& shorthash);

    bool IsTokenSame(uint32_t hid, uint16_t chainnum, uint16_t localid) {
        return GetHID() == hid && GetChainNum() == chainnum && GetLocalID() == localid;
    }
    

    bool ReadTokenFile(const string& name, string& shorthash, string& errormsg);

    static bool SearchTokenByName(const string& coinname, string& coinshorthash, string& errormsg);
    static bool SearchTokenByTriple(uint32_t hid, uint16 chainnum, uint16 localid, string& coinname, string& coinshorthash);
    bool WriteTokenFile();
    bool CheckGenesisBlock();

    CBlock MineGenesisBlock(const CKey& key);
    CBlock GetGenesisBlock();

    void clear() {
        for (auto& optional : mapSettings) {
            if (optional.first != "version" &&
                optional.first != "supply" &&
                optional.first != "time") {
                optional.second = "";
            }
        }
        mapSettings["hid"] = "0";
        mapSettings["chainnum"] = "0";
        mapSettings["localid"] = "0";
    }

    void SetDefaultParas();
    void SelectNetWorkParas();
    string GetTokenConfigPath();

    static string GetTokenConfigFile(const string& shorthash);

private:
    bool ParseTimestamp(const CBlock& genesis);
    string GetTokenConfigFile();

private:

    std::map<std::string, std::string> mapSettings;

    CKey _key;

};

extern CryptoToken g_cryptoToken;
