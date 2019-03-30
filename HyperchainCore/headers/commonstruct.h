﻿/*Copyright 2016-2019 hyperchain.net (Hyperchain)

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





#define BLOCK_VER "0.7.2"
#define BLOCK_VER_ARRAY '0','.','7','.','2'


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
	_tpeeraddress() : _nodeid(CUInt128()) {};
	_tpeeraddress(const CUInt128 &peerid) : _nodeid(peerid) {};
	CUInt128 _nodeid;
	bool operator==(const struct _tpeeraddress &other)
	{
		return _nodeid == other._nodeid;
	}

}T_PEERADDRESS, *T_PPEERADDRESS;


typedef struct _tblockbaseinfo
{
	
	uint64 uiID = 0;				
	T_SHA256 tPreHash;				
	uint64 uiTime;					
	int8  strScript[MAX_SCRIPT_LEN];
	int8  strAuth[MAX_AUTH_LEN];	
	T_SHA256 tHashSelf;				

	_tblockbaseinfo()
	{
		uiID = 0;
		uiTime = 0;
		memset(strScript, 0, MAX_SCRIPT_LEN);
		memset(strAuth, 0, MAX_AUTH_LEN);
		memset(tPreHash.pID, 0, DEF_SHA256_LEN);
		memset(tHashSelf.pID, 0, DEF_SHA256_LEN);
	}

	_tblockbaseinfo(uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf, T_SHA256 PreHash);
	_tblockbaseinfo(uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf);
	_tblockbaseinfo(T_SHA256 PreHash, uint64 Time, int8 *Auth, int8 *Script);

	_tblockbaseinfo& operator = (const _tblockbaseinfo& arRes);
	void SetBlockBaseInfo(uint64 ID, uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf, T_SHA256 PreHash);
	void SetBlockBaseInfo(uint64 ID, uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf);
	void SetBlockBaseInfo(uint64 ID, uint64 Time, int8 *Auth, int8 *Script);

	void SetID(uint64 ID);
	void SetTime(uint64 Time);
	void SetAuth(const char *Auth);
	void SetScript(const char *Script);
	void SetPreHash(T_SHA256 PreHash);
	void SetHashSelf(T_SHA256 HashSelf);

	uint64 GetID()const;
	uint64 GetTime()const;
	int8 * GetAuth();
	int8 * GetScript();
	T_SHA256 GetPreHash()const;
	T_SHA256& GetPreHash();
	T_SHA256 GetHashSelf()const;
	T_SHA256& GetHashSelf();

}T_BLOCKBASEINFO, *T_PBLOCKBASEINFO;

const size_t FILEINFOLEN = 16 * 1024;

typedef struct _fileinfo
{
	_fileinfo() :  _uiTime(time(nullptr)),_datalen(0), _data{ 0 } {}

	explicit _fileinfo(const string &externdata) : 
			_uiTime(time(nullptr)), _datalen(externdata.size()),_data{0} {
		if(_datalen > FILEINFOLEN) _datalen = FILEINFOLEN;
		memcpy(_data, externdata.c_str(), _datalen);
	}

	~_fileinfo() {}
	_fileinfo(const _fileinfo & other): _uiTime(other._uiTime),_datalen(other._datalen), _data{ 0 } {
		memcpy(_data, other._data, _datalen);
	}

	_fileinfo& operator = (const _fileinfo & other) {
		if (this == &other) {
			return *this;
		}
		_datalen = other._datalen;
		memset(_data, 0, FILEINFOLEN);
		memcpy(_data, other._data, _datalen);
		_uiTime = other._uiTime;
		return *this;
	}

	bool operator==(const _fileinfo & other) {
		if (this == &other) {
			return true;
		}
		return (memcmp(_data, other._data, FILEINFOLEN)==0);
	}
	
	char* data() { return _data; }
	size_t datalen() { return _datalen; }
	uint64_t createTime() { return _uiTime; }

	template<typename OStream>
	friend OStream& operator<<(OStream &os, const _fileinfo &c)
	{
		char content[32] = { 0 };
		memcpy(content, c._data, 31);
		return os << content;
	}

private:
	uint64_t _uiTime;
	uint32_t _datalen;
	char _data[FILEINFOLEN];

}T_FILEINFO, *T_PFILEINFO;

typedef struct _tprivateblock
{
	_tblockbaseinfo   tBlockBaseInfo;
	T_SHA256 tHHash;
	T_FILEINFO tPayLoad;

	_tprivateblock()
	{
		memset(tHHash.pID, 0, DEF_SHA256_LEN);
	}
	_tprivateblock(const _tprivateblock &other) : tHHash(other.tHHash),tPayLoad(other.tPayLoad){
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


}T_PRIVATEBLOCK, *T_PPRIVATEBLOCK;


typedef struct _tlocalblock
{
	char version[MAX_VER_LEN] = { BLOCK_VER_ARRAY };
	_tblockbaseinfo   tBlockBaseInfo;
	uint32  difficulty = 1;
	uint64_t uiPreHID;						
	T_SHA256 tPreHHash;						
	uint16  uiAtChainNum;					
	T_PRIVATEBLOCK tPayLoad;

	_tlocalblock()
	{
		memset(tPreHHash.pID, 0, DEF_SHA256_LEN);
		uiPreHID = 0;
		uiAtChainNum = 1;
	}

	_tlocalblock(const _tblockbaseinfo& tBBI, uint32 diff, uint64_t hPreID, T_SHA256 tPreHH, const T_PRIVATEBLOCK& tPL) :
				tBlockBaseInfo(tBBI), difficulty(diff), uiPreHID(hPreID), tPreHHash(tPreHH), tPayLoad(tPL){};

	_tlocalblock(const _tblockbaseinfo& tBBI, uint32 diff, uint64_t hPreID, T_SHA256 tPreHH, uint32 AtChainNu, const T_PRIVATEBLOCK& tPL) :
				tBlockBaseInfo(tBBI), difficulty(diff), uiPreHID(hPreID), tPreHHash(tPreHH), uiAtChainNum(AtChainNu), tPayLoad(tPL){};

	_tlocalblock(const _tblockbaseinfo& tBBI, uint32 diff, uint64_t hPreID, T_SHA256 tPreHH, uint32 AtChainNu):
				tBlockBaseInfo(tBBI), difficulty(diff),uiPreHID(hPreID), tPreHHash(tPreHH), uiAtChainNum(AtChainNu){};

	_tlocalblock& operator = (const _tlocalblock& arRes) {
		if (this != &arRes) {
			uiPreHID = arRes.uiPreHID;
			tPreHHash = arRes.tPreHHash;
			tBlockBaseInfo = arRes.tBlockBaseInfo;
			uiAtChainNum = arRes.uiAtChainNum;
			tPayLoad = arRes.tPayLoad;
			difficulty = arRes.difficulty;
			strcpy(version,arRes.version);
		}
		return *this;
	}
	
	void SetBlockBaseInfo(_tblockbaseinfo tBBI);
	void SetPreHHash(T_SHA256 tPreHH);

	void SetPreHID(uint64 hPreID) {
		uiPreHID = hPreID;
	}
	uint64_t GetPreHID() {
		return uiPreHID;
	}

	string getUUID() const {
		Digest<DT::sha1> digest;
		digest.AddData(&tBlockBaseInfo.uiTime,sizeof(tBlockBaseInfo.uiTime));
		digest.AddData(tPayLoad.GetPayLoad().data(), tPayLoad.GetPayLoad().datalen());
		std::string d = digest.getDigestBase58();
		return string(d.data(), d.size());
	}

	void SetAtChainNum(uint32 Num);
	void SetPayLoad(T_PRIVATEBLOCK tPL);

	void updatePreHyperBlockInfo(uint64_t preHID, const T_SHA256 &preHHash);
	
	_tblockbaseinfo GetBlockBaseInfo()const;
	_tblockbaseinfo& GetBlockBaseInfo();
	T_SHA256 GetPreHHash()const;
	uint32 GetAtChainNum()const;
	T_PRIVATEBLOCK GetPayLoad()const;
	T_PRIVATEBLOCK& GetPayLoad();

}T_LOCALBLOCK, *T_PLOCALBLOCK;

typedef list<T_LOCALBLOCK> LIST_T_LOCALBLOCK;
typedef LIST_T_LOCALBLOCK::iterator ITR_LIST_T_LOCALBLOCK;

typedef struct _thyperblock
{
	char version[MAX_VER_LEN] = { BLOCK_VER_ARRAY };
	_tblockbaseinfo   tBlockBaseInfo;
	uint32  difficulty = 1;
	T_SHA256 tMerkleHashAll;						
	list<LIST_T_LOCALBLOCK> listPayLoad;

	_thyperblock()
	{   
		memset(tMerkleHashAll.pID, 0, DEF_SHA256_LEN);
	}

	_thyperblock(const _thyperblock& arRes);
	_thyperblock& operator = (const _thyperblock& arRes);
	void SetHyperBlock(_tblockbaseinfo tBBI, T_SHA256 tHA, list<LIST_T_LOCALBLOCK>&& LPayLoad);
	void SetBlockBaseInfo(_tblockbaseinfo tBBI);
	void SetMerkleHash(T_SHA256 &tHA);
	void SetMerkleHash(T_SHA256 &&tHA);
	void SetlistPayLoad(list<LIST_T_LOCALBLOCK>&& LPayLoad);

	_tblockbaseinfo GetBlockBaseInfo()const;
	_tblockbaseinfo& GetBlockBaseInfo();
	size_t GetChildBlockCount() const
	{
		size_t blockNum = 0;
		auto childchain = GetlistPayLoad().begin();
		for (; childchain != GetlistPayLoad().end(); childchain++) {
			blockNum += (*childchain).size();
		}
		return blockNum;
	}

	T_SHA256 GetMerkleHash();
	list<LIST_T_LOCALBLOCK>& GetlistPayLoad();
	const list<LIST_T_LOCALBLOCK>& GetlistPayLoad() const {
		return listPayLoad;
	}
	void PushBack(LIST_T_LOCALBLOCK lb);

	int8* GetVersionString();
	
}T_HYPERBLOCK, *T_PHYPERBLOCK;


/*
typedef struct _thyperblocknew
{
	_tblockbaseinfonew   tBlockBaseInfo;
	T_SHA256 tHashAll;
	list<LIST_T_LOCALBLOCKNEW> listPayLoad;
	T_SHA256 merkleRoot;
	std::vector<T_SHA256> leaves;

	_thyperblocknew()
	{
		memset(tHashAll.pID, 0, DEF_SHA256_LEN);
	}

	_thyperblocknew(const _thyperblock&block);

	_thyperblocknew& operator = (const _thyperblocknew& arRes);

	std::vector<T_SHA256> GetLeavesHash()const;	

	T_SHA256 GetMerkleRoot()const;

	T_SHA256 GetHashAll()const;

	const _tblockbaseinfonew& GetBaseInfo()const;

	void Clear();

private:

	void GetRoot();

}T_HYPERBLOCKNEW, *T_PHYPERBLOCKNEW;
*/

typedef struct _thyperblocksend
{
	char version[MAX_VER_LEN] = {0};
	_tblockbaseinfo   tBlockBaseInfo;
	uint32  difficulty;
	T_SHA256 tHashAll;

	_thyperblocksend()
	{
		memset(tHashAll.pID, 0, DEF_SHA256_LEN);
	}

	_thyperblocksend& operator = (const _thyperblocksend& arRes);
	void SetHyperBlockSend(_tblockbaseinfo tBBI, T_SHA256 tHA, char* ver, uint32 diff);
	void SetBlockBaseInfo(_tblockbaseinfo tBBI);
	void SetHashAll(T_SHA256 tHA);


	_tblockbaseinfo GetBlockBaseInfo()const;
	T_SHA256 GetHashAll()const;

}T_HYPERBLOCKSEND, *T_PHYPERBLOCKSEND;
///////////////////////////////////////////////////////////////////////////////////////////
typedef struct _tchainStateinfo 
{
	uint64 uiBlockNum;			

	_tchainStateinfo& operator = (const _tchainStateinfo& arRes);
	void SetBlockNum(uint64 BlockNum);
	uint64 GetBlockNum()const;
	
}T_CHAINSTATEINFO, *T_PCHAINSTATEINFO;


typedef struct _tpeerinfo
{
	T_PEERADDRESS tPeerInfoByMyself;	
	T_PEERADDRESS tPeerInfoByOther;		
	uint16 uiState;						
	uint16 uiNatTraversalState;
	uint64 uiTime;						
	int8 strName[MAX_NODE_NAME_LEN];	
	uint16 uiNodeState;					

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

	_tblockstateaddr():tPeerAddr(CUInt128()),tPeerAddrOut(CUInt128()){};
	_tblockstateaddr(T_PEERADDRESS PeerAddr, T_PEERADDRESS PeerAddrOut);
	_tblockstateaddr& operator = (const _tblockstateaddr& arRes);
	void SetBlockStateAddr(T_PEERADDRESS PeerAddr, T_PEERADDRESS PeerAddrOut);
	void SetPeerAddr(T_PEERADDRESS PeerAddr);
	void SetPeerAddrOut(T_PEERADDRESS PeerAddrOut);

	T_PEERADDRESS GetPeerAddr()const;
	T_PEERADDRESS GetPeerAddrOut()const;
	
}T_BLOCKSTATEADDR, *T_PBLOCKSTATEADDR;

typedef struct _tlocalconsensus				
{
	T_BLOCKSTATEADDR tPeer;					
	T_LOCALBLOCK  tLocalBlock;				
	uint64 uiRetryTime;						
	char strFileHash[DEF_SHA512_LEN+1];		

	_tlocalconsensus()
	{
		memset(strFileHash, 0, DEF_SHA512_LEN + 1);
		uiRetryTime = 0;
	}

	_tlocalconsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime, const char *FileHash);
	_tlocalconsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime);
	_tlocalconsensus& operator = (const _tlocalconsensus& arRes);
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
		return tLocalBlock.getUUID();
	}
	uint64 GetRetryTime()const;
	char * GetFileHash();


}T_LOCALCONSENSUS, *T_PLOCALCONSENSUS;

typedef struct _tglobalconsenus		
{
	T_BLOCKSTATEADDR tPeer;		
	T_LOCALBLOCK  tLocalBlock;	
	uint64 uiAtChainNum;		

	T_BLOCKSTATEADDR GetPeer()const;
	uint64 GetChainNo()const;

	T_LOCALBLOCK GetLocalBlock()const;

	void SetGlobalconsenus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK LocalBlock, uint64 AtChainNum);

	void SetPeer(const T_BLOCKSTATEADDR&addr);
	void SetLocalBlock(const T_LOCALBLOCK&block);
	void SetChainNo(uint64 no);

}T_GLOBALCONSENSUS, *T_PGLOBALCONSENSUS;

typedef struct _tbuddyinfo
{
	uint8 tType;				
	uint32 bufLen;
	string recvBuf;				
	T_PEERADDRESS tPeerAddrOut;	

	uint8 GetType()const;
	uint32 GetBufferLength()const;
	string& GetBuffer();
	T_PEERADDRESS GetRequestAddress()const;
	void Set(uint8 t, uint32 bufferLen, const char*receiveBuf, T_PEERADDRESS peerAddrOut);

}T_BUDDYINFO, *T_PBUDDYINFO;

typedef list<T_LOCALCONSENSUS> LIST_T_LOCALCONSENSUS;
typedef LIST_T_LOCALCONSENSUS::iterator ITR_LIST_T_LOCALCONSENSUS;

typedef list<T_PLOCALCONSENSUS> LIST_T_PLOCALCONSENSUS;
typedef LIST_T_PLOCALCONSENSUS::iterator ITR_LIST_T_PLOCALCONSENSUS;

typedef struct _tbuddyinfostate
{
	int8 strBuddyHash[DEF_STR_HASH256_LEN];
	uint8 uibuddyState;		
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

	void Set(int8 buddyHash[],uint8 uibuddyState,T_PEERADDRESS addr);

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
	T_LOCALBLOCKADDRESS addr; 
	uint64 uiTime;		
	_tsearchinfo() : uiTime(time(nullptr)){
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

using LB_UUID = string; 
typedef map<LB_UUID,T_SEARCHINFO> MAP_T_SEARCHONCHAIN;
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


typedef struct _tpeerconf		
{
	T_PEERADDRESS tPeerAddr;	
	T_PEERADDRESS tPeerAddrOut;	
	uint16 uiPeerState;			
	int8 strName[MAX_NODE_NAME_LEN];	

	T_PEERADDRESS GetIntranetAddress()const;
	T_PEERADDRESS GetInternetAddress()const;

	uint16 GetPeerState()const;

	int8* GetNodeName()const;

}T_PEERCONF, *T_PPEERCONF;

typedef std::vector<T_PPEERCONF>	VEC_T_PPEERCONF;
typedef VEC_T_PPEERCONF::iterator   ITR_VEC_T_PPEERCONF;

typedef struct _tconffile			
{
	uint16			uiSaveNodeNum;	
	uint32			uiLocalIP;
	uint32			uiLocalPort;
	string          strLocalNodeName;
	string			strLogDir;
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
	//static void GetGUID(char* acpBuf, unsigned int auiBufLen, T_PGUID pguid);
	void static gettimeofday_update(struct timeval *ptr);
	static int CompareHash(const T_SHA256& arhashLocal, const T_SHA256& arhashGlobal);
	static void Hash256ToStr(char* getStr, T_PSHA256 phash);

	static void Hash512ToStr(char* getStr, T_PSHA512 phash);
	static void StrToHash512(unsigned char *des, char* getStr);

	static T_SHA256 DistanceHash(const T_SHA256& arLeft, const T_SHA256& arRight);
	static void ReplaceAll(string& str,const string& old_value,const string& new_value);
	static void ReparePath(string& astrPath);

	//static bool ReadConfig();
	static string GetLocalIp();
	static char* Time2String(time_t time1);	

	static string generateNodeId(bool isbase62 = false);

private:
#ifdef WIN32
	void static win_gettimeofday(struct timeval *tp);
#endif	
};

extern T_CONFFILE	g_confFile;

#endif //__COMMON_STRUCT_H__
