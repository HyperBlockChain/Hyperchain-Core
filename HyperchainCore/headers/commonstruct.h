/*Copyright 2016-2019 hyperchain.net (Hyperchain)

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
#ifndef __COMMON_STRUCT_H__
#define __COMMON_STRUCT_H__


#include "includeComm.h"
#include "gen_int.h"
#include "inter_public.h"
#include "crypto/sha2.h"

#include "shastruct.h"
#include "node/UInt128.h"

#include <boost/any.hpp>
#include <boost/serialization/binary_object.hpp>
#include <functional>
#include <numeric>
#include <cctype>
using namespace std;

#define DEF_ONE_DAY     (60 * 60 * 24)
#define MAX_IP_LEN		(32)
#define MAX_RECV_BUF_LEN (1024)
#define MAX_SEND_BUF_LEN (1024)
#define MAX_FILE_NAME_LEN (1024)
#define MAX_NODE_NAME_LEN (64)
#define MAX_CUSTOM_INFO_LEN (512)
#define MAX_SCRIPT_LEN (1024*2)
#define MAX_AUTH_LEN (64)
#define MAX_QUEED_LEN (32)
#define LISTEN_PORT (8115)
#define MAX_VER_LEN		(8)
#define MAX_USER_DEFINED_DATA (1024* 16)

//
//
//
//

#define MAJOR_VER 1
#define MINOR_VER 0
#define PATCH_VER 0


T_SHA256 calculateMerkleTreeRoot(vector<const T_SHA256*> &mttree);

#pragma pack(1)

enum _ep2pprotocoltypestate
{
    DEFAULT_STATE = 0,
    SEND_ON_CHAIN_RSP,
    RECV_ON_CHAIN_RSP,
    SEND_CONFIRM,
    CONSENSUS_CONFIRMED
};

enum _erecvpagestate
{
    DEFAULT_RECV_STATE = 0,
    RECV_RSP,
    RECV_REQ
};
enum _eerrorno
{
    DEFAULT_ERROR_NO = 0,
    ERROR_NOT_NEWEST,
    ERROR_EXIST
};

typedef struct _tpeeraddress
{
    CUInt128 _nodeid;

    _tpeeraddress() : _nodeid(CUInt128()) {};
    _tpeeraddress(const CUInt128 &peerid) : _nodeid(peerid) {};
    _tpeeraddress(const _tpeeraddress&) = default;
    _tpeeraddress(_tpeeraddress&&) = default;
    _tpeeraddress& operator=(const _tpeeraddress&) = default;
    _tpeeraddress& operator=(_tpeeraddress&&) = default;

    bool operator==(const struct _tpeeraddress &other)
    {
        return _nodeid == other._nodeid;
    }

    CUInt128 GetNodeid()
    {
        return _nodeid;
    }

private:
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        ar & _nodeid;
    }

}T_PEERADDRESS, *T_PPEERADDRESS;
BOOST_CLASS_VERSION(T_PEERADDRESS, 0)


const size_t FILEINFOLEN = 2 * 1024 * 1024;

typedef struct _tprivateblock
{
    //_tblockbaseinfo   tBlockBaseInfo;
    //T_SHA256 tHHash;
    //T_FILEINFO tPayLoad;

    T_LOCALBLOCKADDRESS preBlockAddr;       //
    T_SHA256 tpreBlockHash;                 //
    string sData;

    /*
    _tprivateblock()
    {
    }
    _tprivateblock(const _tprivateblock &other) : tHHash(other.tHHash), tPayLoad(other.tPayLoad) {
        tBlockBaseInfo = other.tBlockBaseInfo;
    }
    _tprivateblock(_tblockbaseinfo tBBI, T_SHA256 tHH, T_FILEINFO tPL);
    _tprivateblock& operator = (const _tprivateblock& arRes);
    void SetPrivateBlock(_tblockbaseinfo tBBI, T_SHA256 tHH, T_FILEINFO tPL);
    void SetBlockBaseInfo(_tblockbaseinfo tBBI);
    void SetHHash(T_SHA256 tHH);
    void SetPayLoad(T_FILEINFO tPL);

    _tblockbaseinfo GetBlockBaseInfo()const;
    _tblockbaseinfo& GetBlockBaseInfo();
    T_SHA256 GetHHash()const;
    T_FILEINFO GetPayLoad()const;
    T_FILEINFO& GetPayLoad();
    */
}T_PRIVATEBLOCK, *T_PPRIVATEBLOCK;
BOOST_CLASS_VERSION(T_PRIVATEBLOCK, 0)

typedef struct _tversion
{
    union {
        struct {
            char _major;         //
            char _minor;         //
            int16 _patch;        //
        };
        uint32 ver;             //
    };
    _tversion() : _major(MAJOR_VER), _minor(MINOR_VER), _patch(PATCH_VER) {}
    _tversion(char mj, char mi, int16 ptch) : _major(mj), _minor(mi), _patch(ptch) {}

    string tostring() const {
        char verinfo[64] = { 0 };
        std::snprintf(verinfo, 64, "%d.%d.%d", _major, _minor, _patch);
        return string(verinfo);
    }

private:
    friend class boost::serialization::access;
    template <typename Archive>
    void serialize(Archive &ar, unsigned int version)
    {
        ar & ver;
    }
} T_VERSION;

enum class APPTYPE : uint16 {
    appdefault = 0,
    ledger = 0x11,       //
    paracoin = 0x21,    //
};

typedef struct _tapptype
{
    typedef union {
        struct {
            unsigned char mt : 1;         //
            unsigned char reserve : 3;    //
            unsigned char val : 4;        //
        };
        unsigned char app = 0;            //
    } _INNER_AT;

    explicit _tapptype(APPTYPE a = APPTYPE::appdefault) {
        vecAT[0].app = static_cast<char>(a);
        //if a > 2^4 - 1 , need to add element into array
        //if application has merkle tree hash, let mt = 1
    }

    explicit _tapptype(APPTYPE a, uint32_t hid, uint16 chainnum, uint16 localid) {
        vecAT[0].app = static_cast<char>(a);
        set(hid, chainnum, localid);
    }

    typedef vector<_INNER_AT>::iterator iterator;
    typedef vector<_INNER_AT>::const_iterator const_iterator;
    iterator begin() { return vecAT.begin(); }
    iterator end() { return vecAT.end(); }
    const_iterator begin() const { return vecAT.begin(); }
    const_iterator end() const { return vecAT.end(); }

    void set(uint32_t hid, uint16 chainnum, uint16 localid)
    {
        vecAT.resize(9);

        vecAT[1].app = static_cast<char>(hid);
        vecAT[2].app = static_cast<char>(hid >> 8);
        vecAT[3].app = static_cast<char>(hid >> 16);
        vecAT[4].app = static_cast<char>(hid >> 24);

        vecAT[5].app = static_cast<char>(chainnum);
        vecAT[6].app = static_cast<char>(chainnum >> 8);

        vecAT[7].app = static_cast<char>(localid);
        vecAT[8].app = static_cast<char>(localid >> 8);
    }

    void get(uint32_t& hid, uint16& chainnum, uint16& localid) const
    {
        if (vecAT.size() < 9) {
            return;
        }
        hid = vecAT[1].app | vecAT[2].app << 8 | vecAT[3].app << 16 | vecAT[4].app << 24;
        chainnum = vecAT[5].app | vecAT[6].app << 8;
        localid = vecAT[7].app | vecAT[8].app << 8;

    }

    bool isMT() const { return vecAT[0].mt == 1; }

    bool containAddr() const {
        uint32_t hid = 0;
        uint16 chainnum = 0;
        uint16 localid = 0;
        get(hid,chainnum,localid);

        if (hid == 0 && chainnum == 0 && localid == 0) {
            return false;
        }
        return true;
    }
    
    bool isParaCoin() const { return (vecAT[0].app == static_cast<char>(APPTYPE::paracoin)) && containAddr(); }
    bool isLedge() const { return (vecAT[0].app == static_cast<char>(APPTYPE::ledger)) && containAddr(); }

    size_t size() const { return vecAT.size(); }
    bool operator==(const _tapptype& v) const throw() {
        size_t s = size();
        if (v.size() != size()) return false;

        for (size_t i = 0; i < s; i++) {
            if (vecAT[i].app != v.vecAT[i].app) {
                return false;
            }
        }
        return true;
    }

    bool operator!=(const _tapptype& v) const throw() {
        return !(*this == v);
    }

    bool operator <(const _tapptype& v) const {
        size_t s = size();
        if (s < v.size()) return true;
        if (s > v.size()) return false;

        for (size_t i = 0; i < s; i++) {
            if (vecAT[i].app == v.vecAT[i].app) {
                continue;
            }
            if (vecAT[i].app < v.vecAT[i].app) {
                return true;
            }
            return false;
        }
        return false;
    }

    size_t unserialize(const string& s)
    {
        size_t len = s[0];

        vecAT.resize(len);

        int i = 1;
        for (auto& elm : vecAT) {
            elm.app = s[i++];
        }
        return len;
    }

    string serialize()
    {
        string appValue;
        
        size_t len = vecAT.size();
        assert(len < 128);

        appValue.resize(len + 1);
        appValue[0] = static_cast<char>(len);

        int i = 1;
        for (auto elm : vecAT) {
            appValue[i++] = elm.app;
        }
        return appValue;
    }

    string tohexstring()
    {
        string appValue;
        char hex[5] {0};
        for (auto elm: vecAT) {
            std::snprintf(hex, 5, "%02x", elm.app);
            appValue += hex;
        }

        const char* strAppType = nullptr;
        switch (vecAT[0].app)
        {
            case static_cast<char>(APPTYPE::appdefault) : strAppType = "appdefault"; break;
            case static_cast<char>(APPTYPE::ledger) : strAppType = "ledger"; break;
            case static_cast<char>(APPTYPE::paracoin) : strAppType = "paracoin"; break;
        default:
            strAppType = "unknown"; break;
        }

        const char *fmt = "%s (0x%s)";

        int sz = std::snprintf(nullptr, 0, fmt, strAppType, appValue.c_str());
        std::string buf(sz, 0);
        std::snprintf(&buf[0], buf.size() + 1, fmt, strAppType, appValue.c_str());

        return buf;
    }

private:
    vector<_INNER_AT> vecAT = { _INNER_AT() };

private:
    friend class boost::serialization::access;
    template <typename Archive>
    void save(Archive &ar, const unsigned int version) const {
        char l = static_cast<char>(vecAT.size());
        ar << l;
        for (auto a : vecAT) {
            ar << a.app;
        }
    }
    template <typename Archive>
    void load(Archive &ar, const unsigned int version) {
        char l = 0;
        ar >> l;
        vecAT.resize(static_cast<size_t>(l));
        for (auto& a : vecAT) {
            ar >> a.app;
        }
    }
    BOOST_SERIALIZATION_SPLIT_MEMBER()
} T_APPTYPE;

namespace std {
    template<>
    struct hash<T_APPTYPE>
    {
        typedef T_APPTYPE argument_type;
        typedef size_t result_type;

        result_type operator () (const argument_type& x) const
        {
            using type = char;
            result_type r = 0;
            for (auto e : x) {
                r += std::hash<type>()(e.app);
            }
            return r;
        }
    };
}

struct _tlocalblock;
typedef struct _tlocalblockheader
{
    T_VERSION uiVersion;
    uint16 uiID = 1;                                    //
    T_SHA256 tPreHash = T_SHA256(1);                    //
    T_SHA256 tPreHHash = T_SHA256(1);                   //
    uint64 uiTime;                                      //
    uint32 uiNonce = 0;                                 //

    T_APPTYPE appType;                                  //

    //
    //
    T_SHA256 tMTRootorBlockBodyHash = T_SHA256(0);
    T_SHA256 tScriptHash = T_SHA256(0);                 //


    _tlocalblockheader() : uiTime(time(nullptr)) {}

    _tlocalblockheader(const _tlocalblockheader&) = default;
    _tlocalblockheader& operator=(const _tlocalblockheader&) = default;
    _tlocalblockheader(_tlocalblockheader&&) = default;
    _tlocalblockheader& operator=(_tlocalblockheader&&) = default;

    size_t GetSize() const {
        return sizeof(_tlocalblockheader) - sizeof(appType) + sizeof(T_APPTYPE) * appType.size();
    }
    bool ContainMTData() const { return appType.isMT(); }
private:
    friend class boost::serialization::access;
    template <typename Archive>
    void serialize(Archive &ar, unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        ar & uiVersion.ver;
        ar & uiID;
        ar & tPreHash;
        ar & tPreHHash;
        ar & tPreHash;
        ar & uiTime;
        ar & uiNonce;
        ar & appType;
        ar & tMTRootorBlockBodyHash;
        ar & tScriptHash;
    }

    //
    friend struct _tlocalblock;
    template <typename D>
    void AddData(D &d) const
    {
        d.AddData(uiVersion.ver);
        d.AddData(uiID);
        d.AddData(tPreHash.data(), tPreHash.size());
        d.AddData(tPreHHash.data(), tPreHHash.size());
        d.AddData(uiTime);
        d.AddData(uiNonce);

        for (auto a : appType) {
            d.AddData(&a.app, sizeof(a.app));
        }
        d.AddData(tMTRootorBlockBodyHash.data(), tMTRootorBlockBodyHash.size());
        d.AddData(tScriptHash.data(), tScriptHash.size());
    }
} T_LOCALBLOCKHEADER;
BOOST_CLASS_VERSION(T_LOCALBLOCKHEADER, 0)


typedef struct _tlocalblockbody {
    string sScript;                         //
    string sAuth;                           //
    string payload;

    _tlocalblockbody() {}
    _tlocalblockbody(const _tlocalblockbody&) = default;
    _tlocalblockbody& operator=(const _tlocalblockbody&) = default;
    _tlocalblockbody(_tlocalblockbody&&) = default;
    _tlocalblockbody& operator=(_tlocalblockbody&&) = default;

    size_t GetSize() const {
        return sScript.size() + sAuth.size() + payload.size();
    }
private:
    friend class boost::serialization::access;
    template <typename Archive>
    void save(Archive& ar, const unsigned int version) const
    {
        uint32 len = static_cast<uint32>(sScript.size());
        ar << len;
        ar << boost::serialization::make_binary_object(sScript.c_str(), len);

        uint16 authlen = static_cast<uint16>(sAuth.size());
        ar << authlen;
        ar << boost::serialization::make_binary_object(sAuth.c_str(), authlen);

        uint32 payloadlen = static_cast<uint32>(payload.size());
        ar << payloadlen;
        ar << boost::serialization::make_binary_object(payload.c_str(), payloadlen);
    }

    template<class Archive>
    void load(Archive& ar, const unsigned int version)
    {
        uint32 len;
        ar >> len;
        sScript.resize(len);
        ar >> boost::serialization::make_binary_object(const_cast<char*>(sScript.data()), len);

        uint16 lenAuth;
        ar >> lenAuth;
        sAuth.resize(lenAuth);
        ar >> boost::serialization::make_binary_object(const_cast<char*>(sAuth.data()), lenAuth);

        uint32 payloadlen;
        ar >> payloadlen;
        payload.resize(payloadlen);
        ar >> boost::serialization::make_binary_object(const_cast<char*>(payload.data()), payloadlen);
    }
    BOOST_SERIALIZATION_SPLIT_MEMBER()
    //
    friend struct _tlocalblock;
    template <typename D>
    void AddData(D &d) const
    {
        d.AddData(sScript);
        d.AddData(sAuth);
        d.AddData(payload);
    }
}T_LOCALBLOCKBODY;


typedef struct _tlocalblock
{
    T_LOCALBLOCKHEADER header;
    T_LOCALBLOCKBODY body;

    _tlocalblock() {};

    _tlocalblock(const _tlocalblock&) = default;
    _tlocalblock& operator=(const _tlocalblock&) = default;
    _tlocalblock(_tlocalblock&&) = default;
    _tlocalblock& operator=(_tlocalblock&&) = default;

    //
    vector<T_SHA256> payloadMTree;

    void BuildBlockBodyHash()
    {
        Digest<DT::sha256> digest;
        digest.AddData(body.payload);
        header.tMTRootorBlockBodyHash = digest.getDigest();
    }

    void SetBlockBodyHash(T_SHA256& tBlockBodyHash)
    {
        header.tMTRootorBlockBodyHash = tBlockBodyHash;
    }

    string CalculateHashHeader() const {
        Digest<DT::sha256> digest;
        header.AddData(digest);
        return digest.getDigest();
    }

    void CalculateHashSelf() const {
        Digest<DT::sha256> digest;
        header.AddData(digest);
        body.AddData(digest);
        if (header.ContainMTData()) {
            for (auto h : payloadMTree) {
                digest.AddData(h.data(), h.size());
            }
        }
        _myselfHash = digest.getDigest();
    }

    inline T_VERSION GetVersion() const { return header.uiVersion; }
    inline uint16 GetID() const { return header.uiID; }
    inline uint64 GetHID() const { return _prehid + 1; }
    inline uint64 GetCTime() const { return header.uiTime; }
    inline uint16 GetChainNum() const { return _chain_num; }
    inline T_APPTYPE GetAppType() const { return header.appType; }
    //inline bool isAppTxType() const { return header.appType.isLedge() || header.appType.isParaCoin(); }
    inline bool isAppTxType() const { return header.appType.isParaCoin(); }
    inline uint32 GetNonce() const { return header.uiNonce; }
    inline const string& GetPayload() const { return body.payload; }
	inline const string& GetAuth() const { return body.sAuth; }
	inline const string& GetScript() const { return body.sScript; }
    size_t GetSize() const {
        return header.GetSize() + body.GetSize() + payloadMTree.size() * sizeof(T_SHA256);
    }
	inline const T_SHA256& GetRootHash()const { return header.tMTRootorBlockBodyHash; }
	inline const T_SHA256& GetScriptHash()const { return header.tScriptHash; }
    inline T_SHA256& GetPreHash() { return header.tPreHash; }
    inline const T_SHA256& GetPreHash() const { return header.tPreHash; }
    inline const T_SHA256& GetPreHHash() const { return header.tPreHHash; }
    const T_SHA256& GetHashSelf() const {
        if (_myselfHash.isNull()) {
            CalculateHashSelf();
        }
        return _myselfHash;
    }

    string GetPayLoadPreview(int row = 2) const {
        string str;

        const unsigned char *p = (const unsigned char*)(body.payload.data());
        size_t payloadlen = body.payload.size();
        size_t nRowLen = 32;
        size_t nTotalLen = 0;
        for (int r = 0; r < row && nTotalLen < payloadlen; r++) {
            str += "\n\t";
            p = p + r * nRowLen;

            //
            char sPrint[33] = { 0 };
            char buff[64 + 1] = { 0 };

            for (size_t i = 0; i < nRowLen; i++) {
                std::snprintf(buff + 2 * i, 4, "%02x", (int)*(p + i));

                sPrint[i] = std::isprint(*(p + i)) ? *(p + i) : '.';
                nTotalLen++;

                if (nTotalLen >= payloadlen) {
                    break;
                }
            }

            str += buff;
            str += "    ";
            str += sPrint;
        }
        return str;
    }

    void SetID(uint16 id) { header.uiID = id; }
    void SetCTime(uint64 t) { header.uiTime = t; }
    void SetPreHID(uint64 hid) { _prehid = hid; }
    void SetPreHash(const T_SHA256& hash) { header.tPreHash = hash; };
    void SetChainNum(uint16 chain_nm) { _chain_num = chain_nm; }
    void SetPreHyperBlock(uint64 hid, const T_SHA256& hhash) { _prehid = hid; header.tPreHHash = hhash; }
    void SetAppType(const T_APPTYPE& app) { header.appType = app; }

    void SetPayLoad(const string & pl) { body.payload = pl; }
    void SetPayLoad(string && pl) { body.payload = std::forward<string>(pl); }
    string GetPayLoad()const { return body.payload; }
    string& GetPayLoad() { return body.payload; }

    string GetUUID() const;
    void updatePreHyperBlockInfo(uint64_t preHID, const T_SHA256 &preHHash);

private:
    friend class boost::serialization::access;
    template <typename Archive>
    void save(Archive& ar, const unsigned int version) const
    {
        VERSION_CHECK(*this, 0)
            ar << header;
        ar << body;
        assert(header.appType.size() > 0);
        if (header.appType.isMT()) {
            uint32 payloadnum = static_cast<uint32>(payloadMTree.size());
            ar << payloadnum;
            ar << boost::serialization::make_array(payloadMTree.data(), payloadnum);
        }
    }

    template<class Archive>
    void load(Archive& ar, const unsigned int version)
    {
        VERSION_CHECK(*this, 0)
            ar >> header;
        ar >> body;
        assert(header.appType.size() > 0);
        if (header.appType.isMT()) {
            uint32 payloadnum;
            ar >> payloadnum;
            payloadMTree.resize(payloadnum);
            ar >> boost::serialization::make_array(payloadMTree.data(), payloadnum);
        }
    }
    BOOST_SERIALIZATION_SPLIT_MEMBER()

private:
    //The following member is in-memory
    uint64 _prehid = -1;
    uint16 _chain_num = -1;
    mutable T_SHA256 _myselfHash = T_SHA256(0);

}T_LOCALBLOCK, *T_PLOCALBLOCK;
BOOST_CLASS_VERSION(T_LOCALBLOCK, 0)

typedef list<T_LOCALBLOCK> LIST_T_LOCALBLOCK;
typedef LIST_T_LOCALBLOCK::iterator ITR_LIST_T_LOCALBLOCK;

struct _thyperblock;
typedef struct _thyperblockheader
{
    T_VERSION  uiVersion;
    uint32  uiWeight = 2;                   //

    uint64 uiID = -1;                       //
    T_SHA256 tPreHash = T_SHA256(1);        //
    T_SHA256 tPreHeaderHash = T_SHA256(1);  //
    uint64 uiTime;                          //

    T_SHA256 tMerkleHashAll;                //
    T_SHA256 tBRRoot = T_SHA256(1);         //
    T_SHA256 tXWHash = T_SHA256(1);         //
    T_SHA256 tScriptHash = T_SHA256(1);     //
    uint16 uiBRRule = 0;                    //
    list<T_SHA256> listTailLocalBlockHash;  //
    vector<uint16> vecChildChainBlockCount;      //

    _thyperblockheader() {}

    _thyperblockheader(const _thyperblockheader&) = default;
    _thyperblockheader(_thyperblockheader&&) = default;
    _thyperblockheader& operator=(const _thyperblockheader&) = default;
    _thyperblockheader& operator=(_thyperblockheader&&) = default;

    size_t GetSize() const {
        return sizeof(_thyperblockheader) - sizeof(listTailLocalBlockHash)
            - sizeof(vecChildChainBlockCount) +
            listTailLocalBlockHash.size() * sizeof(T_SHA256) +
            vecChildChainBlockCount.size() * sizeof(uint16);
    }
private:
    friend struct _thyperblock;
    template <typename D>
    void AddData(D &d) const
    {
        d.AddData(uiVersion.ver);
        d.AddData(uiWeight);
        d.AddData(uiID);
        d.AddData(tPreHash.data(), tPreHash.size());
        d.AddData(tPreHeaderHash.data(), tPreHeaderHash.size());
        d.AddData(uiTime);

        d.AddData(tMerkleHashAll.data(), tMerkleHashAll.size());
        d.AddData(tBRRoot.data(), tBRRoot.size());
        d.AddData(tXWHash.data(), tXWHash.size());
        d.AddData(tScriptHash.data(), tScriptHash.size());
        d.AddData(uiBRRule);

        for (auto &h : listTailLocalBlockHash) {
            d.AddData(h.data(), h.size());
        }
        for (auto &c : vecChildChainBlockCount) {
            d.AddData(c);
        }
    }
    friend class boost::serialization::access;
    template <typename Archive>
    void save(Archive& ar, const unsigned int version) const
    {
        VERSION_CHECK(*this, 0)
        ar << uiVersion.ver;
        ar << uiWeight;
        ar << uiID;
        ar << tPreHash;
        ar << tPreHeaderHash;
        ar << uiTime;
        ar << tMerkleHashAll;
        ar << tBRRoot;
        ar << tXWHash;
        ar << tScriptHash;
        ar << uiBRRule;

        uint32 len = static_cast<uint32>(listTailLocalBlockHash.size());
        ar << len;
        for (T_SHA256 hash : listTailLocalBlockHash) {
            ar << hash;
        }

        uint32 blockcount = static_cast<uint32>(vecChildChainBlockCount.size());
        ar << blockcount;
        ar << boost::serialization::make_array(vecChildChainBlockCount.data(), blockcount);
    }

    template<class Archive>
    void load(Archive& ar, const unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        ar >> uiVersion.ver;
        ar >> uiWeight;
        ar >> uiID;
        ar >> tPreHash;
        ar >> tPreHeaderHash;
        ar >> uiTime;
        ar >> tMerkleHashAll;
        ar >> tBRRoot;
        ar >> tXWHash;
        ar >> tScriptHash;
        ar >> uiBRRule;

        uint32 len;
        ar >> len;
        for (uint32 i = 0; i < len; i++) {
            T_SHA256 hash;
            ar >> hash;
            listTailLocalBlockHash.push_back(hash);
        }

			uint32 blockcount;
			ar >> blockcount;
			vecChildChainBlockCount.resize(blockcount);
			ar >> boost::serialization::make_array(vecChildChainBlockCount.data(), blockcount);
	}
	BOOST_SERIALIZATION_SPLIT_MEMBER()
}T_HYPERBLOCKHEADER;
BOOST_CLASS_VERSION(T_HYPERBLOCKHEADER, 0)

typedef struct _tuint160 {
    std::array<uint8, 20> v;

    string toHexString() const
    {
        char ucBuf[41] = { 0 };
        char* p = ucBuf;
        for (uint8 c : v)
        {
            sprintf(p, "%02x", c);
            p += 2;
        }

        return string(ucBuf);
    }

private:
    friend class boost::serialization::access;
    template <typename Archive>
    void serialize(Archive &ar, unsigned int version) {
        ar & boost::serialization::make_array(v.data(), 20);
    }
}T_UINT160;

typedef struct _thyperblockbody
{
    vector<list<T_SHA256>> localBlocksHeaderHash;     //

    vector<T_UINT160> listBRAddr;                   //
    string sScript;                                 //
    string sAuth;                                   //

    _thyperblockbody() {}

    _thyperblockbody(const _thyperblockbody&) = default;
    _thyperblockbody& operator=(const _thyperblockbody&) = default;
    _thyperblockbody(_thyperblockbody&&) = default;
    _thyperblockbody& operator=(_thyperblockbody&&) = default;

    size_t GetSize() const {
        auto s = [](size_t acc, const list<T_SHA256>& elm) {
            return acc + elm.size();
        };
        size_t count = accumulate(localBlocksHeaderHash.begin(), localBlocksHeaderHash.end(), 0, s);

        return count * sizeof(T_SHA256) +
            listBRAddr.size() * sizeof(T_UINT160) +
            sScript.size() + sAuth.size();
    }

    T_SHA256 MTRoot() const
    {
        vector<const T_SHA256*> v;
        for (auto &l : localBlocksHeaderHash) {
            for (auto &h : l) {
                v.push_back(&h);
            }
        }
        return calculateMerkleTreeRoot(v);
    }

private:
    friend struct _thyperblock;
    template <typename D>
    void AddData(D &d) const
    {
        for (auto &chain : localBlocksHeaderHash) {
            for (auto &h : chain) {
                d.AddData(h.data(), h.size());
            }
        }
        for (auto &h : listBRAddr) {
            d.AddData(h.v.data(), sizeof(h.v));
        }
        d.AddData(sScript);
        d.AddData(sAuth);
    }
    friend class boost::serialization::access;
    template <typename Archive>
    void save(Archive& ar, const unsigned int version) const
    {
        VERSION_CHECK(*this, 0)
        uint32 listnum = static_cast<uint32>(localBlocksHeaderHash.size());
        ar << listnum;
        for (auto list : localBlocksHeaderHash) {
            uint32 hashnum = static_cast<uint32>(list.size());
            ar << hashnum;
            for (T_SHA256 hash : list) {
                ar << hash;
            }
        }

        uint32 addrnum = static_cast<uint32>(listBRAddr.size());
        ar << addrnum;
        ar << boost::serialization::make_array(listBRAddr.data(), addrnum);

        uint32 len = static_cast<uint32>(sScript.size());
        ar << len;
        ar << boost::serialization::make_binary_object(sScript.c_str(), len);

        uint16 authlen = static_cast<uint16>(sAuth.size());
        ar << authlen;
        ar << boost::serialization::make_binary_object(sAuth.c_str(), authlen);
    }

    template<class Archive>
    void load(Archive& ar, const unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        uint32 listnum = 0;
        ar >> listnum;
        localBlocksHeaderHash.resize(listnum);
        for (uint32 i = 0; i < listnum; i++) {
            uint32 hashnum;
            ar >> hashnum;
            for (uint32 j = 0; j < hashnum; j++) {
                T_SHA256 hash;
                ar >> hash;
                localBlocksHeaderHash[i].push_back(hash);
            }
        }

		uint32 addrnum;
		ar >> addrnum;
		listBRAddr.resize(addrnum);
		ar >> boost::serialization::make_array(listBRAddr.data(), addrnum);

        uint32 len;
        ar >> len;
        sScript.resize(len);
        ar >> boost::serialization::make_binary_object(const_cast<char*>(sScript.data()), len);

        uint16 lenAuth;
        ar >> lenAuth;
        sAuth.resize(lenAuth);
        ar >> boost::serialization::make_binary_object(const_cast<char*>(sAuth.data()), lenAuth);
    }
    BOOST_SERIALIZATION_SPLIT_MEMBER()
}T_HYPERBLOCKBODY;
BOOST_CLASS_VERSION(T_HYPERBLOCKBODY, 0)

typedef struct _thyperblock
{
    T_HYPERBLOCKHEADER header;
    T_HYPERBLOCKBODY body;

    _thyperblock() {}
    _thyperblock(const _thyperblock&) = default;
    _thyperblock& operator=(const _thyperblock&) = default;
    _thyperblock(_thyperblock&&) = default;
    _thyperblock& operator=(_thyperblock&&) = default;

    inline T_VERSION GetVersion() const { return header.uiVersion; }
    inline uint64 GetID() const { return header.uiID; }
    inline uint64 GetCTime() const { return header.uiTime; }
    inline uint32 GetWeight() const { return header.uiWeight; }
    inline uint16 GetChildChainsCount() const { return static_cast<uint16>(header.vecChildChainBlockCount.size()); }
    inline uint32 GetChildChainBlockCount(uint16 idx) const { return static_cast<uint32>(header.vecChildChainBlockCount[idx]); }
    const list<T_SHA256>& GetChildTailHashList() const { return header.listTailLocalBlockHash; }

    size_t GetSize() const {
        return header.GetSize() + body.GetSize();
    }

	inline const T_SHA256& GetMerkleHash() const { return header.tMerkleHashAll; }
	inline const T_SHA256& GetXWHash() const { return header.tXWHash; }
	inline const T_SHA256& GetScriptHash() const { return header.tScriptHash; }
	inline const T_SHA256& GetBRRoot() const { return header.tBRRoot; }
	inline const uint16& GetBRRule() const { return header.uiBRRule; }

    inline const T_SHA256& GetPreHash() const { return header.tPreHash; }
    inline const T_SHA256& GetPreHeaderHash() const { return header.tPreHeaderHash; }

    inline const string& GetAuth() const { return body.sAuth; }
    inline const string& GetScript() const { return body.sScript; }
    inline const vector<T_UINT160>& GetBRAddr() const { return body.listBRAddr; }

    const T_SHA256& GetHashSelf() const {
        if (_myselfHash.isNull()) {
            calculateHashSelf();
        }
        return _myselfHash;
    }

    vector<LIST_T_LOCALBLOCK>& GetChildChains() { return vecChildChain; }
    const vector<LIST_T_LOCALBLOCK>& GetChildChains() const { return vecChildChain; }

    uint32 GetChildBlockCount() const {
        return accumulate(header.vecChildChainBlockCount.begin(),
            header.vecChildChainBlockCount.end(), 0);
    }

    void AddChildChain(LIST_T_LOCALBLOCK && childchain) {
        if (childchain.size() == 0) {
            return;
        }
        uint16 chainnum = static_cast<uint16>(vecChildChain.size()) + 1;
        for (auto &l : childchain) {
            l.SetPreHID(GetID() - 1);
            l.SetChainNum(chainnum);
        }
        vecChildChain.push_back(std::forward<LIST_T_LOCALBLOCK>(childchain));
    }

    void SetID(uint64 id) { header.uiID = id; }
    void SetCTime(uint64 t) { header.uiTime = t; }
    void SetWeight(uint32 w) { header.uiWeight = w; }
    void SetPreHash(const T_SHA256 &h) { header.tPreHash = h; }
    void SetPreHeaderHash(const T_SHA256 &h) { header.tPreHeaderHash = h; }
    void Rebuild() {
        body.localBlocksHeaderHash.clear();
        header.listTailLocalBlockHash.clear();
        header.vecChildChainBlockCount.clear();

        uint32_t chainnum = 0;
        for (auto &chain : vecChildChain) {

            chainnum++;
            header.vecChildChainBlockCount.push_back(static_cast<uint16>(chain.size()));

            uint16 blockNum = 0;
            list<T_SHA256> listhash;

            auto itr = chain.begin();
            itr->SetPreHash(0);
            itr->SetID(++blockNum);
            itr->SetChainNum(chainnum);
            itr->SetPreHID(GetID() - 1);
            itr->CalculateHashSelf();
            listhash.emplace_back(itr->CalculateHashHeader());

            auto itrPrev = itr++;
            for (; itr != chain.end(); ++itr) {
                itr->SetID(++blockNum);
                itr->SetChainNum(chainnum);
                itr->SetPreHID(GetID() - 1);
                itr->SetPreHash(itrPrev->GetHashSelf());
                itr->CalculateHashSelf();
                listhash.emplace_back(itr->CalculateHashHeader());
                itrPrev = itr;
            }

            chain.rbegin()->CalculateHashSelf();
            header.listTailLocalBlockHash.push_back(chain.rbegin()->GetHashSelf());
            body.localBlocksHeaderHash.push_back(std::move(listhash));
        }
        header.tMerkleHashAll = body.MTRoot();
        calcuateWeight();

        //
        //tBRroot
        //tXWHash
        //tScriptHash

        calculateHashSelf();
    }
    bool verify() const {
        size_t chaincount = vecChildChain.size();
        if (chaincount != header.vecChildChainBlockCount.size()) {
            return false;
        }
        if (chaincount != header.listTailLocalBlockHash.size()) {
            return false;
        }

        auto itrblockhash = header.listTailLocalBlockHash.begin();
        for (size_t i = 0; i < chaincount; ++i) {
            if (vecChildChain[i].size() != header.vecChildChainBlockCount[i]) {
                return false;
            }
            vecChildChain[i].rbegin()->CalculateHashSelf();
            if (vecChildChain[i].rbegin()->GetHashSelf() != *itrblockhash) {
                return false;
            }
            ++itrblockhash;
        }
        if (header.tMerkleHashAll != body.MTRoot()) {
            return false;
        }
        //
        //....
        return true;
    }
    void calculateHashSelf() const {
        Digest<DT::sha256> digest;
        header.AddData(digest);
        body.AddData(digest);

        _myselfHash = digest.getDigest();
    }

    T_SHA256 calculateHeaderHashSelf() const {
        Digest<DT::sha256> digest;
        header.AddData(digest);
        return T_SHA256(digest.getDigest());
    }
private:
    void calcuateWeight()
    {
        //TODO:
        header.uiWeight = GetChildBlockCount();
    }
    friend class boost::serialization::access;
    template <typename Archive>
    void serialize(Archive &ar, unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        ar & header;
        ar & body;
    }
private:
    //The following member is in-memory.
    mutable T_SHA256 _myselfHash = 0;
    vector<LIST_T_LOCALBLOCK> vecChildChain;
}T_HYPERBLOCK, *T_PHYPERBLOCK;
BOOST_CLASS_VERSION(T_HYPERBLOCK, 0)


///////////////////////////////////////////////////////////////////////////////////////////
typedef struct _tchainStateinfo //
{
    uint64 uiBlockNum;			//

    _tchainStateinfo& operator = (const _tchainStateinfo& arRes);
    void SetBlockNum(uint64 BlockNum);
    uint64 GetBlockNum()const;

}T_CHAINSTATEINFO, *T_PCHAINSTATEINFO;


typedef struct _tpeerinfo
{
    T_PEERADDRESS tPeerInfoByMyself;	//
    T_PEERADDRESS tPeerInfoByOther;		//
    uint16 uiState;						//
    uint16 uiNatTraversalState;
    uint64 uiTime;						//
    int8 strName[MAX_NODE_NAME_LEN];	//
    uint16 uiNodeState;					//

    _tpeerinfo() : tPeerInfoByMyself(CUInt128()), tPeerInfoByOther(CUInt128())
    {
        uiState = 0;
        uiNatTraversalState = 0;
        uiTime = 0;
        uiNodeState = DEFAULT_REGISREQ_STATE;
        memset(strName, 0, MAX_NODE_NAME_LEN);
    }

    _tpeerinfo& operator = (const _tpeerinfo& arRes);
    void SetPeerinfo(T_PEERADDRESS PeerInfoByMyself, T_PEERADDRESS PeerInfoByOther, uint16 State, uint16 NatTraversalState, uint64 Time, uint16 NodeState, int8 *Name);
    void SetPeerInfoByMyself(T_PEERADDRESS PeerInfoByMyself);
    void SetPeerInfoByOther(T_PEERADDRESS PeerInfoByOther);
    void SetState(uint16 State);
    void SetNatTraversalState(uint16 NatTraversalState);
    void SetTime(uint64 Time);
    void SetNodeState(uint16 NodeState);
    void SetName(int8 *Name);

    T_PEERADDRESS GetPeerInfoByMyself()const;
    T_PEERADDRESS GetPeerInfoByOther()const;
    uint16 GetState()const;
    uint16 GetNatTraversalState()const;
    uint64 GetTime()const;
    uint16 GetNodeState()const;
    int8* GetName();

}T_PEERINFO, *T_PPEERINFO;


typedef struct _tblockstateaddr
{
    T_PEERADDRESS tPeerAddr;
    T_PEERADDRESS tPeerAddrOut;

    _tblockstateaddr() :tPeerAddr(CUInt128()), tPeerAddrOut(CUInt128()) {};
    _tblockstateaddr(T_PEERADDRESS PeerAddr, T_PEERADDRESS PeerAddrOut);
    _tblockstateaddr& operator = (const _tblockstateaddr& arRes);

    _tblockstateaddr(const _tblockstateaddr&) = default;
    _tblockstateaddr(_tblockstateaddr&&) = default;
    _tblockstateaddr& operator=(_tblockstateaddr&&) = default;

    void SetBlockStateAddr(T_PEERADDRESS PeerAddr, T_PEERADDRESS PeerAddrOut);
    void SetPeerAddr(T_PEERADDRESS PeerAddr);
    void SetPeerAddrOut(T_PEERADDRESS PeerAddrOut);

    T_PEERADDRESS GetPeerAddr()const;
    T_PEERADDRESS GetPeerAddrOut()const;

private:
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        ar & tPeerAddr;
        ar & tPeerAddrOut;
    }
}T_BLOCKSTATEADDR, *T_PBLOCKSTATEADDR;
BOOST_CLASS_VERSION(T_BLOCKSTATEADDR, 0)

typedef struct _tlocalconsensus             //
{
    T_BLOCKSTATEADDR tPeer;                 //
    T_LOCALBLOCK  tLocalBlock;              //
    uint64 uiRetryTime = 0;                       //
    char strFileHash[DEF_SHA512_LEN + 1] = { 0 };   //

    _tlocalconsensus() {}

    _tlocalconsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime, const char *FileHash);
    _tlocalconsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime);
    _tlocalconsensus& operator = (const _tlocalconsensus& arRes);

    _tlocalconsensus(const _tlocalconsensus&) = default;
    _tlocalconsensus(_tlocalconsensus&&) = default;
    _tlocalconsensus& operator=(_tlocalconsensus&&) = default;

    void SetLoaclConsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime, const char *FileHash);
    void SetLoaclConsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime);
    void SetLoaclConsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock);
    void SetPeer(T_BLOCKSTATEADDR  Peer);
    void SetLocalBlock(T_LOCALBLOCK  LocalBlock);
    void SetRetryTime(uint64 RetryTime);
    void SetFileHash(char *FileHash);

    T_BLOCKSTATEADDR GetPeer()const;
    T_LOCALBLOCK GetLocalBlock()const;
    T_LOCALBLOCK& GetLocalBlock();
    string GetLocalBlockUUID() {
        return tLocalBlock.GetUUID();
    }
    uint64 GetRetryTime()const;
    char * GetFileHash();

private:
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        ar & tPeer;
        ar & tLocalBlock;
        ar & uiRetryTime;
        ar & boost::serialization::make_array(strFileHash, DEF_SHA512_LEN + 1);
    }

}T_LOCALCONSENSUS, *T_PLOCALCONSENSUS;
BOOST_CLASS_VERSION(T_LOCALCONSENSUS, 0)

typedef struct _tglobalconsenus //
{
    T_BLOCKSTATEADDR tPeer;     //
    T_LOCALBLOCK  tLocalBlock;  //
    uint64 uiAtChainNum;        //

    T_BLOCKSTATEADDR GetPeer()const;
    uint64 GetChainNo()const;

    T_LOCALBLOCK GetLocalBlock()const;

    void SetGlobalconsenus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK LocalBlock, uint64 AtChainNum);

    void SetPeer(const T_BLOCKSTATEADDR&addr);
    void SetLocalBlock(const T_LOCALBLOCK&block);
    void SetChainNo(uint64 no);

private:
    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive & ar, unsigned int version)
    {
        VERSION_CHECK(*this, 0)
        ar & tPeer;
        ar & tLocalBlock;
        ar & uiAtChainNum;
    }

}T_GLOBALCONSENSUS, *T_PGLOBALCONSENSUS;
BOOST_CLASS_VERSION(T_GLOBALCONSENSUS, 0)

typedef struct _tbuddyinfo
{
    uint8 tType;                //
    size_t bufLen;
    string recvBuf;             //
    T_PEERADDRESS tPeerAddrOut; //

    uint8 GetType()const;
    size_t GetBufferLength()const;
    string& GetBuffer();
    T_PEERADDRESS GetRequestAddress()const;
    void Set(uint8 t, size_t bufferLen, const char*receiveBuf, T_PEERADDRESS peerAddrOut);

}T_BUDDYINFO, *T_PBUDDYINFO;

typedef list<T_LOCALCONSENSUS> LIST_T_LOCALCONSENSUS;
typedef LIST_T_LOCALCONSENSUS::iterator ITR_LIST_T_LOCALCONSENSUS;

typedef list<T_PLOCALCONSENSUS> LIST_T_PLOCALCONSENSUS;
typedef LIST_T_PLOCALCONSENSUS::iterator ITR_LIST_T_PLOCALCONSENSUS;

typedef struct _tbuddyinfostate
{
    int8 strBuddyHash[DEF_STR_HASH256_LEN];
    uint8 uibuddyState;     //
    T_PEERADDRESS tPeerAddrOut;

    LIST_T_LOCALCONSENSUS localList;
    _tbuddyinfostate()
    {
        memset(strBuddyHash, 0, DEF_STR_HASH256_LEN);
        uibuddyState = DEFAULT_STATE;
    }

    uint8 GetBuddyState()const;

    LIST_T_LOCALCONSENSUS GetList()const;

    T_PEERADDRESS GetPeerAddrOut()const;

    void Set(int8 buddyHash[], uint8 uibuddyState, T_PEERADDRESS addr);

    void LocalListPushBack(T_LOCALCONSENSUS  localBlockInfo);
    void LocalListClear();
    void LocalListSort();
    LIST_T_LOCALCONSENSUS& GetLocalConsensus();

    const int8 *GetBuddyHash()const;
    void SetPeerAddrOut(T_PEERADDRESS PeerAddrOut);
    void SetBuddyState(uint8 BuddyState);
    void SetBuddyHash(int8 * BuddyHash);
    void SetBuddyHashInit(int Num);

}T_BUDDYINFOSTATE, *T_PBUDDYINFOSTATE;

typedef struct _tsearchinfo
{
    T_LOCALBLOCKADDRESS addr;   //
    uint64 uiTime;              //
    _tsearchinfo() : uiTime(time(nullptr)) {
    }
    uint64 GetHyperID()const {
        return addr.hid;
    }

    uint64 GetCreateTime()const {
        return uiTime;
    }

}T_SEARCHINFO, *T_PSEARCHINFO;

typedef list<LIST_T_LOCALCONSENSUS> LIST_LIST_GLOBALBUDDYINFO;
typedef LIST_LIST_GLOBALBUDDYINFO::iterator ITR_LIST_LIST_GLOBALBUDDYINFO;

typedef list<T_BUDDYINFO> LIST_T_BUDDYINFO;
typedef LIST_T_BUDDYINFO::iterator ITR_LIST_T_BUDDYINFO;

typedef list<T_PBUDDYINFOSTATE> LIST_T_PBUDDYINFOSTATE;
typedef LIST_T_PBUDDYINFOSTATE::iterator ITR_LIST_T_PBUDDYINFOSTATE;

typedef list<T_BUDDYINFOSTATE> LIST_T_BUDDYINFOSTATE;
typedef LIST_T_BUDDYINFOSTATE::iterator ITR_LIST_T_BUDDYINFOSTATE;

using LB_UUID = string; //

typedef struct _tpalyloadaddr
{
    _tpalyloadaddr(const T_LOCALBLOCKADDRESS& a, const string& p) :addr(a), payload(p) {}
    T_LOCALBLOCKADDRESS addr;
    string payload;
}T_PAYLOADADDR;

//
using HANDLEGENESISCBFN = std::function<bool(vector<T_PAYLOADADDR>&)>;

//
using CONSENSUSCBFN = std::function<bool(T_PAYLOADADDR&, map<boost::any, T_LOCALBLOCKADDRESS>&, boost::any&)>;
using VALIDATEFN = CONSENSUSCBFN;

//
using VALIDATECHAINFN = std::function<bool(vector<T_PAYLOADADDR>& vecPA)>;

//
using ACCEPTCHAINFN = std::function<bool(T_APPTYPE&, vector<T_PAYLOADADDR>& vecPA, uint32_t& hid, T_SHA256& thhash)>;

//
using CHECKCHAINFN = std::function<bool(vector<T_PAYLOADADDR>& vecPA, uint32_t& prevhid, T_SHA256& tprevhhash)>;

//
using REONCHAINFN = std::function<bool(string& payload, std::string& newpayload)>;

//
using UUIDFN = std::function<bool(string& payload, string& uuid)>;

//
using PUTONCHAINFN = std::function<bool()>;

//
using GETVPATHFN = std::function<bool(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath)>;

//
using PUTGLOBALCHAINFN = std::function<bool()>;

using GETNEIGHBORNODES = std::function<bool(list<string>&)>;

//
using CONSENSUSNOTIFY = std::tuple<HANDLEGENESISCBFN, 
                                    PUTONCHAINFN, 
                                    PUTGLOBALCHAINFN, 
                                    REONCHAINFN, 
                                    VALIDATEFN, 
                                    VALIDATECHAINFN, 
                                    ACCEPTCHAINFN,
                                    CHECKCHAINFN,
                                    UUIDFN, 
                                    GETVPATHFN,
                                    GETNEIGHBORNODES>;

enum class cbindex : char {
    HANDLEGENESISIDX = 0, 
    PUTONCHAINIDX, 
    PUTGLOBALCHAINIDX, 
    REONCHAINIDX, 
    VALIDATEFNIDX, 
    VALIDATECHAINIDX, 
    ACCEPTCHAINIDX,
    CHECKCHAINIDX,
    GETUUIDIDX, 
    GETVPATHIDX, 
    GETNEIGHBORNODESIDX 
};

enum class CBRET : char { UNREGISTERED = 0, REGISTERED_TRUE, REGISTERED_FALSE };


typedef map<LB_UUID, T_SEARCHINFO> MAP_T_SEARCHONCHAIN;
typedef MAP_T_SEARCHONCHAIN::iterator ITR_MAP_T_SEARCHONCHAIN;

#pragma pack()

typedef list<T_PPEERINFO> LIST_T_PPEERINFO;
typedef LIST_T_PPEERINFO::iterator ITR_LIST_T_PPEERINFO;

typedef list<T_HYPERBLOCK> LIST_T_HYPERBLOCK;
typedef LIST_T_HYPERBLOCK::iterator ITR_LIST_T_HYPERBLOCK;

typedef list<T_BLOCKSTATEADDR> LIST_T_BLOCKSTATEADDR;
typedef LIST_T_BLOCKSTATEADDR::iterator ITR_LIST_T_PBLOCKSTATEADDR;

typedef map<uint64, LIST_T_BLOCKSTATEADDR> MAP_BLOCK_STATE;
typedef MAP_BLOCK_STATE::iterator ITR_MAP_BLOCK_STATE;


typedef struct _tpeerconf       //
{
    T_PEERADDRESS tPeerAddr;    //
    T_PEERADDRESS tPeerAddrOut; //
    uint16 uiPeerState;         //
    int8 strName[MAX_NODE_NAME_LEN];    //

    T_PEERADDRESS GetIntranetAddress()const;
    T_PEERADDRESS GetInternetAddress()const;

    uint16 GetPeerState()const;

    int8* GetNodeName()const;

}T_PEERCONF, *T_PPEERCONF;

typedef std::vector<T_PPEERCONF>    VEC_T_PPEERCONF;
typedef VEC_T_PPEERCONF::iterator   ITR_VEC_T_PPEERCONF;

typedef struct _tconffile           //
{
    uint16          uiSaveNodeNum;  //
    uint32          uiLocalIP;
    uint32          uiLocalPort;
    string          strLocalNodeName;
    string          strLogDir;
    VEC_T_PPEERCONF vecPeerConf;

    uint16 GetSaveNodeNum()const;

    uint32 GetLocalIP()const;

    uint32 GetLocalPort()const;

    string GetLocalNodeName()const;

    string GetLogDir()const;


}T_CONFFILE, *T_PCONFFILE;

class CCommonStruct
{
private:

    CCommonStruct();
    virtual ~CCommonStruct();

public:
    static time_t gettimeofday_update();
    static int CompareHash(const T_SHA256& arhashLocal, const T_SHA256& arhashGlobal);
    static void Hash256ToStr(char* getStr, const T_SHA256& hash);
    static T_SHA256 StrToHash256(string hashStr);

    static void Hash512ToStr(char* getStr, const T_PSHA512 phash);
    static void StrToHash512(unsigned char *des, char* getStr);

    static T_SHA256 DistanceHash(const T_SHA256& arLeft, const T_SHA256& arRight);
    static void ReplaceAll(string& str, const string& old_value, const string& new_value);
    static void ReparePath(string& astrPath);

    static string GetLocalIp();
    static char* Time2String(time_t time1);

    static string generateNodeId(bool isbase62 = false);

};

extern T_CONFFILE	g_confFile;

#endif //__COMMON_STRUCT_H__
