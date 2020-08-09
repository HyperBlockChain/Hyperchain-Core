/*Copyright 2016-2020 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#include "headers/commonstruct.h"
#include "headers/UUFile.h"
#include "util/sole.hpp"
#include "Log.h"
#include "consensus/buddyinfo.h"

#ifdef WIN32
#include <winsock2.h>
#endif

#include <chrono>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
using std::chrono::system_clock;
#include <unordered_map>

T_CONFFILE	g_confFile;
UUFile			m_uufile;

CCommonStruct::CCommonStruct()
{
}

CCommonStruct::~CCommonStruct()
{
}

time_t CCommonStruct::gettimeofday_update()
{
    std::chrono::time_point<system_clock, std::chrono::seconds> tp;
    tp = std::chrono::time_point_cast<std::chrono::seconds>(system_clock::now());
    std::time_t timestamp = tp.time_since_epoch().count();

    return timestamp;
}

int CCommonStruct::CompareHash(const T_SHA256& arhashFirst, const T_SHA256& arhashSecond)
{
    const unsigned char* pFirst = NULL;
    const unsigned char* pSecond = NULL;
    for (int i = 0; i < DEF_SHA256_LEN; i++)
    {
        pFirst = arhashFirst.data() + i;
        pSecond = arhashSecond.data() + i;
        if (*pFirst > *pSecond)
            return 1;
        if (*pFirst < *pSecond)
            return -1;
    }
    return 0;
}

void CCommonStruct::Hash256ToStr(char* getStr, const T_SHA256& hash)
{
    char ucBuf[10] = { 0 };

    unsigned int uiNum = 0;
    for (; uiNum < 32; uiNum++)
    {
        memset(ucBuf, 0, 10);
        sprintf(ucBuf, "%02x", hash.pID[uiNum]);
        strcat(getStr, ucBuf);
    }
}

std::vector<unsigned char> hexToBin(const std::string &hex)
{
    std::vector<unsigned char> dest;
    auto len = hex.size();
    dest.reserve(len / 2);
    for (decltype(len) i = 0; i < len; i += 2)
    {
        unsigned int element;
        std::istringstream strHex(hex.substr(i, 2));
        strHex >> std::hex >> element;
        dest.push_back(static_cast<unsigned char>(element));
    }
    return dest;
}

T_SHA256 CCommonStruct::StrToHash256(string hashStr)
{
    T_SHA256 hash(0);

    if (hashStr.size() == 0)
        return hash;

    int i = 0;
    auto charVec = hexToBin(hashStr);
    for (auto element : charVec) {
        hash.pID[i] = element;
        i++;
    }

    return hash;
}

void CCommonStruct::Hash512ToStr(char* getStr, T_PSHA512 phash)
{
    memcpy(getStr, phash->data(), DEF_SHA512_LEN);
}

void CCommonStruct::StrToHash512(unsigned char *out, char* szHash)
{
    memcpy(out, szHash, DEF_SHA512_LEN);
}

T_SHA256 DistanceHash(const T_SHA256& arLeft, const T_SHA256& arRight)
{
    T_SHA256 guidDistance;
    T_SHA256 left = arLeft;
    T_SHA256 right = arRight;
    if (arLeft < arRight)
    {
        left = arRight;
        right = arLeft;
    }

    for (int i = 0; i < DEF_SHA256_LEN; i++)
    {
        guidDistance.pID[i] = left.pID[i] - right.pID[i];
    }

    return guidDistance;
}

void CCommonStruct::ReplaceAll(string& str, const string& old_value, const string& new_value)
{
    if (old_value.empty())
        return;

    size_t Pos = 0;
    while ((Pos = str.find(old_value, Pos)) != string::npos) {
        str.erase(Pos, old_value.size());
        str.insert(Pos, new_value);
        Pos += new_value.size();
    }
}

void CCommonStruct::ReparePath(string& astrPath)
{
#ifdef WIN32
    ReplaceAll(astrPath, "/", "\\");
#else
    ReplaceAll(astrPath, "\\", "/");
#endif
}
string CCommonStruct::GetLocalIp()
{
    char ipTempBuf[64] = { 0 };
    m_uufile.getlocalip(ipTempBuf);
    return ipTempBuf;
}
#if 0
bool CCommonStruct::ReadConfig()
{
    string localPath = m_uufile.GetAppPath();
    string confPath = localPath + "hychain_conf.xml";
    string peerListPath = localPath + "peerlist.xml";

    m_uufile.ReparePath(confPath);
    m_uufile.ReparePath(peerListPath);

    string strXmlFile = m_uufile.LoadFile(confPath).c_str();
    if (strXmlFile.empty()) {
        return false;
    }

    string strTemp = m_uufile.GetItemData(strXmlFile, "savenodenum");
    g_confFile.uiSaveNodeNum = atoi(strTemp.c_str());

    //////////////////////////////////////////////
    //2018-07-03
    g_confFile.uiSaveNodeNum += 2;
    //////////////////////////////////////////////
    strTemp = m_uufile.GetItemData(strXmlFile, "logfile");
    if (0 == strTemp.compare("")) {
        QString path = QDir::tempPath();
        g_confFile.strLogDir = path.toStdString();
        g_confFile.strLogDir += "hyperchainlog\\";
    }
    else {
        g_confFile.strLogDir = strTemp;
    }

    QString strLogPath = QString::fromStdString(g_confFile.strLogDir);
    QDir kDir;
    if (!kDir.exists(strLogPath)) {
        kDir.mkpath(strLogPath);
    }


    strTemp = m_uufile.GetItemData(strXmlFile, "localip").c_str();
    if (0 == strTemp.compare("")) {
        char ipTempBuf[64] = { 0 };
        m_uufile.getlocalip(ipTempBuf);
        g_confFile.uiLocalIP = inet_addr(ipTempBuf);

    }
    else {
        g_confFile.uiLocalIP = inet_addr(strTemp.c_str());
    }

    strTemp = m_uufile.GetItemData(strXmlFile, "localport").c_str();
    if (0 == strTemp.compare("")) {
        g_confFile.uiLocalPort = LISTEN_PORT;
    }
    else {
        g_confFile.uiLocalPort = atoi(strTemp.c_str());
    }

    strTemp = m_uufile.GetItemData(strXmlFile, "localnodename").c_str();
    if (0 == strTemp.compare("")) {
        g_confFile.strLocalNodeName = "node";
        char ipTempBuf[64] = { 0 };
        m_uufile.getlocalip(ipTempBuf);
        g_confFile.strLocalNodeName += ipTempBuf;
    }
    else {
        g_confFile.strLocalNodeName = strTemp;
    }


    strXmlFile = m_uufile.LoadFile(peerListPath).c_str();
    if (strXmlFile.empty()) {
        return false;
    }

    /*vector<string> vec_str = m_uufile.ExtractStringList(strXmlFile, "nodeinfo");
    vector<string>::iterator itr = vec_str.begin();
    for (; itr != vec_str.end(); itr++) {
        T_PPEERCONF pPeerConf = new T_PEERCONF;

        pPeerConf->tPeerAddr.uiIP = inet_addr(m_uufile.GetItemData((*itr), "serverip").c_str());
        pPeerConf->tPeerAddr.uiPort = atoi((m_uufile.GetItemData((*itr), "serverport")).c_str());
        pPeerConf->tPeerAddrOut.uiIP = inet_addr(m_uufile.GetItemData((*itr), "outserverip").c_str());
        pPeerConf->tPeerAddrOut.uiPort = atoi((m_uufile.GetItemData((*itr), "outserverport")).c_str());
        pPeerConf->uiPeerState = atoi(m_uufile.GetItemData((*itr), "nodestate").c_str());
        strncpy(pPeerConf->strName, m_uufile.GetItemData((*itr), "nodename").c_str(), MAX_NODE_NAME_LEN);

        g_confFile.vecPeerConf.push_back(pPeerConf);
    }*/

    return true;
}
#endif
string CCommonStruct::Time2String(time_t time1)
{
    char szTime[128] = {0};
    struct tm tm1;
#ifdef WIN32
    localtime_s(&tm1, &time1);
#else
    localtime_r(&time1, &tm1);
#endif
    sprintf(szTime, "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
        tm1.tm_year + 1900, tm1.tm_mon + 1, tm1.tm_mday,
        tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
    return string(szTime);
}

string CCommonStruct::generateNodeId(bool isbase62)
{
    /*boost::uuids::uuid r_uuid = boost::uuids::random_generator()();
    string struuid = boost::uuids::to_string(r_uuid);
    struuid.erase(std::remove(struuid.begin(), struuid.end(), '-'), struuid.end());*/

    

    sole::uuid u4 = sole::uuid4();
    string struuid;
    if (isbase62) {
        struuid = u4.base62();
    }
    else {
        struuid = u4.str();
    }
    struuid.erase(std::remove(struuid.begin(), struuid.end(), '-'), struuid.end());
    return struuid;
}

T_SHA256 calculateMerkleTreeRoot(vector<const T_SHA256*> &mttree)
{
    size_t s = mttree.size();
    if (s == 0) {
        return T_SHA256(0);
    }

    vector<T_SHA256> vMerkleTree;
    for (size_t i = 0; i < s; i += 2) {
        Digest<DT::sha256> digest;
        int i2 = (i + 1 < s - 1) ? i + 1 : s - 1;
        digest.AddData(mttree[i]->data(), sizeof(mttree[i]->pID));
        digest.AddData(mttree[i2]->data(), sizeof(mttree[i2]->pID));
        vMerkleTree.emplace_back(digest.getDigest());
    }

    int j = 0;
    for (size_t nSize = vMerkleTree.size(); nSize > 1; nSize = (nSize + 1) / 2) {
        for (size_t i = 0; i < nSize; i += 2) {
            size_t i2 = (i + 1 < nSize - 1) ? i + 1 : nSize - 1;
            Digest<DT::sha256> digest;
            digest.AddData(vMerkleTree[j + i].data(), sizeof(vMerkleTree[j + i].pID));
            digest.AddData(vMerkleTree[j + i2].data(), sizeof(vMerkleTree[j + i2].pID));

            vMerkleTree.emplace_back(digest.getDigest());
        }
        j += nSize;
    }
    return (vMerkleTree.empty() ? T_SHA256(0) : vMerkleTree.back());
}

string T_LOCALBLOCK::GetUUID() const {

    string uuidpayload;
    

    string payload = GetPayLoad();
    

    //CBRET ret =
    //    g_tP2pManagerStatus->appCallback<cbindex::GETUUIDIDX>(GetAppType(), payload, uuidpayload);

    Digest<DT::sha1> digest;
    digest.AddData(&header.uiTime, sizeof(header.uiTime));
    //if (ret == CBRET::REGISTERED_TRUE) {
    //    digest.AddData(uuidpayload.c_str(), uuidpayload.size());
    //}
    //else {
        digest.AddData(body.payload.c_str(), body.payload.size());
    //}
    std::string d = digest.getDigestBase58();
    return string(d.data(), d.size());
}



