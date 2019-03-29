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

#ifdef _WIN32

#include <WinSock2.h>

#endif

#include "../headers/commonstruct.h"
#include "../headers/lambda.h"
#include "../crypto/sha2.h"

_tblockbaseinfo& _tblockbaseinfo::operator = (const _tblockbaseinfo& arRes)
{
	if (this != &arRes)
	{
		uiID = arRes.uiID;
		uiTime = arRes.uiTime;
		tPreHash = arRes.tPreHash;
		tHashSelf = arRes.tHashSelf;
		memcpy(strScript, arRes.strScript, MAX_SCRIPT_LEN);
		memcpy(strAuth, arRes.strAuth, MAX_AUTH_LEN);
	}

	return *this;
}

_tblockbaseinfo::_tblockbaseinfo(uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf, T_SHA256 PreHash)
{
	uiTime = Time;
	strncpy(strAuth, Auth, MAX_AUTH_LEN);
	strncpy(strScript, Script, MAX_SCRIPT_LEN);
	tHashSelf = HashSelf;
	tPreHash = PreHash;
}

_tblockbaseinfo::_tblockbaseinfo(uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf)
{
	uiTime = Time;
	strncpy(strAuth, Auth, MAX_AUTH_LEN);
	strncpy(strScript, Script, MAX_SCRIPT_LEN);
	tHashSelf = HashSelf;
}

_tblockbaseinfo::_tblockbaseinfo(T_SHA256 PreHash, uint64 Time, int8 *Auth, int8 *Script)
{
	uiTime = Time;
	strncpy(strAuth, Auth, MAX_AUTH_LEN);
	strncpy(strScript, Script, MAX_SCRIPT_LEN);
	tPreHash = PreHash;
}

void _tblockbaseinfo::SetBlockBaseInfo(uint64 ID, uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf, T_SHA256 PreHash)
{
	uiID = ID;
	uiTime = Time;
	strncpy(strAuth, Auth, MAX_AUTH_LEN);
	strncpy(strScript, Script, MAX_SCRIPT_LEN);
	tHashSelf = HashSelf;
	tPreHash = PreHash;
}

void _tblockbaseinfo::SetBlockBaseInfo(uint64 ID, uint64 Time, int8 *Auth, int8 *Script, T_SHA256 HashSelf)
{
	uiID = ID;
	uiTime = Time;
	strncpy(strAuth, Auth, MAX_AUTH_LEN);
	strncpy(strScript, Script, MAX_SCRIPT_LEN);
	tHashSelf = HashSelf;
}


void _tblockbaseinfo::SetBlockBaseInfo(uint64 ID, uint64 Time, int8 *Auth, int8 *Script)
{
	uiID = ID;
	uiTime = Time;
	strncpy(strAuth, Auth, MAX_AUTH_LEN);
	strncpy(strScript, Script, MAX_SCRIPT_LEN);
}


void _tblockbaseinfo::SetID(uint64 ID)
{
	uiID = ID;
}

void _tblockbaseinfo::SetTime(uint64 Time)
{
	uiTime = Time;
}

void _tblockbaseinfo::SetAuth(const char *Auth)
{
	strncpy(strAuth, Auth, MAX_AUTH_LEN);
}

void _tblockbaseinfo::SetScript(const char *Script)
{
	strncpy(strScript, Script, MAX_SCRIPT_LEN);
}

void _tblockbaseinfo::SetPreHash(T_SHA256 PreHash)
{
	tPreHash = PreHash;
}

void _tblockbaseinfo::SetHashSelf(T_SHA256 HashSelf)
{
	tHashSelf = HashSelf;
}

uint64 _tblockbaseinfo::GetID()const
{
	return uiID;
}

uint64 _tblockbaseinfo::GetTime()const
{
	return uiTime;
}

int8 * _tblockbaseinfo::GetAuth()
{
	return strAuth;
}

int8 * _tblockbaseinfo::GetScript()
{
	return strScript;
}

T_SHA256 _tblockbaseinfo::GetPreHash()const
{
	return tPreHash;
}

T_SHA256& _tblockbaseinfo::GetPreHash()
{
	return tPreHash;

}

T_SHA256 _tblockbaseinfo::GetHashSelf()const
{
	return tHashSelf;
}

T_SHA256& _tblockbaseinfo::GetHashSelf()
{
	return tHashSelf;
}

_tprivateblock::_tprivateblock(_tblockbaseinfo tBBI, T_SHA256 tHH, T_FILEINFO tPL)
{
	tBlockBaseInfo = tBBI;
	tHHash = tHH;
	tPayLoad = tPL;
}

_tprivateblock& _tprivateblock::operator = (const _tprivateblock& arRes)
{
	if (this != &arRes) {
		tHHash = arRes.tHHash;
		tBlockBaseInfo = arRes.tBlockBaseInfo;
		tPayLoad = arRes.tPayLoad;
	}

	return *this;
}

void _tprivateblock::SetPrivateBlock(_tblockbaseinfo tBBI, T_SHA256 tHH, T_FILEINFO tPL)
{
	tBlockBaseInfo = tBBI;
	tHHash = tHH;
	tPayLoad = tPL;
}

void _tprivateblock::SetBlockBaseInfo(_tblockbaseinfo tBBI)
{
	tBlockBaseInfo = tBBI;
}

void _tprivateblock::SetHHash(T_SHA256 tHH)
{
	tHHash = tHH;
}

void _tprivateblock::SetPayLoad(T_FILEINFO tPL)
{
	tPayLoad = tPL;
}

_tblockbaseinfo _tprivateblock::GetBlockBaseInfo()const
{
	return tBlockBaseInfo;
}

_tblockbaseinfo& _tprivateblock::GetBlockBaseInfo()
{
	return tBlockBaseInfo;
}

T_SHA256 _tprivateblock::GetHHash()const
{
	return tHHash;
}

T_FILEINFO _tprivateblock::GetPayLoad() const
{
	return tPayLoad;
}

T_FILEINFO& _tprivateblock::GetPayLoad()
{
	return tPayLoad;
}

void _tlocalblock::SetBlockBaseInfo(_tblockbaseinfo tBBI)
{
	tBlockBaseInfo = tBBI;
}

void _tlocalblock::SetPreHHash(T_SHA256 tPreHH)
{
	tPreHHash = tPreHH;
}

void _tlocalblock::SetAtChainNum(uint32 Num)
{
	uiAtChainNum = Num;
}

void _tlocalblock::SetPayLoad(T_PRIVATEBLOCK tPL)
{
	tPayLoad = tPL;
}


_tblockbaseinfo _tlocalblock::GetBlockBaseInfo()const
{
	return tBlockBaseInfo;
}

_tblockbaseinfo& _tlocalblock::GetBlockBaseInfo()
{
	return tBlockBaseInfo;
}

T_SHA256 _tlocalblock::GetPreHHash()const
{
	return tPreHHash;
}

uint32 _tlocalblock::GetAtChainNum()const
{
	return uiAtChainNum;
}

T_PRIVATEBLOCK _tlocalblock::GetPayLoad()const
{
	return tPayLoad;
}
T_PRIVATEBLOCK& _tlocalblock::GetPayLoad()
{
	return tPayLoad;
}

void _tlocalblock::updatePreHyperBlockInfo(uint64_t preHID, const T_SHA256 &preHHash)
{
	if (preHID == uiPreHID && preHHash == tPreHHash) {
		return;
	}

	
	T_BLOCKBASEINFO payloadLBaseInfo(tPayLoad.tBlockBaseInfo.GetTime(),
		tPayLoad.tBlockBaseInfo.strAuth,
		tPayLoad.tBlockBaseInfo.strScript, T_SHA256(0));
	T_PRIVATEBLOCK tPrivateBlock(payloadLBaseInfo, preHHash, tPayLoad.GetPayLoad());
	tPayLoad = tPrivateBlock;
	
	GetSHA256(tPayLoad.GetBlockBaseInfo().GetHashSelf().pID, (const char*)(&tPayLoad), sizeof(tPayLoad));

	
	T_BLOCKBASEINFO LBaseInfo(tBlockBaseInfo.GetTime(), tBlockBaseInfo.strAuth, tBlockBaseInfo.strScript, T_SHA256(0));
	tBlockBaseInfo = LBaseInfo;
	uiPreHID = preHID;
	tPreHHash = preHHash;

	
	GetSHA256(tBlockBaseInfo.GetHashSelf().pID, (const char*)this, sizeof(_tlocalblock));
}


_thyperblock::_thyperblock(const _thyperblock& arRes) : tMerkleHashAll(arRes.tMerkleHashAll),
	tBlockBaseInfo(arRes.tBlockBaseInfo),difficulty(arRes.difficulty),
	listPayLoad(arRes.listPayLoad)
{
	memcpy(version,arRes.version, MAX_VER_LEN);
}

_thyperblock& _thyperblock:: operator = (const _thyperblock& arRes)
{
	if (this != &arRes)
	{
		tMerkleHashAll = arRes.tMerkleHashAll;
		tBlockBaseInfo = arRes.tBlockBaseInfo;
		//{
		//	list<LIST_T_LOCALBLOCK>::iterator itr = (const_cast<_thyperblock&>(arRes)).listPayLoad.begin();
		//	for (; itr != (const_cast<_thyperblock&>(arRes)).listPayLoad.end(); itr++)
		//	{
		//		list<T_LOCALBLOCK> vectTemp;
		//		list<T_LOCALBLOCK>::iterator subItr = (*itr).begin();

		//		for (; subItr != (*itr).end(); subItr++)
		//		{
		//			vectTemp.push_back(*subItr);
		//		}

		//		listPayLoad.push_back(vectTemp);
		//	}			
		//}

		listPayLoad = arRes.listPayLoad;
		memcpy(version, arRes.version, MAX_VER_LEN);
		difficulty = arRes.difficulty;
	}

	return *this;
}

void _thyperblock::SetHyperBlock(_tblockbaseinfo tBBI, T_SHA256 tHA, list<LIST_T_LOCALBLOCK>&& LPayLoad)
{
	tBlockBaseInfo = tBBI;
	tMerkleHashAll = tHA;

	//list<LIST_T_LOCALBLOCK>::iterator itr = LPayLoad.begin();
	//for (; itr != LPayLoad.end(); itr++)
	//{
	//	list<T_LOCALBLOCK> vectTemp;
	//	list<T_LOCALBLOCK>::iterator subItr = (*itr).begin();

	//	for (; subItr != (*itr).end(); subItr++)
	//	{
	//		vectTemp.push_back(*subItr);
	//	}

	//	listPayLoad.push_back(vectTemp);
	//}
	listPayLoad = std::forward<list<LIST_T_LOCALBLOCK>>(LPayLoad);

}

void _thyperblock::SetBlockBaseInfo(_tblockbaseinfo tBBI)
{
	tBlockBaseInfo = tBBI;
}

void _thyperblock::SetMerkleHash(T_SHA256 &tHA)
{
	tMerkleHashAll = tHA;
}

void _thyperblock::SetMerkleHash(T_SHA256 &&tHA)
{
	tMerkleHashAll = tHA;
}

void _thyperblock::SetlistPayLoad(list<LIST_T_LOCALBLOCK>&& LPayLoad)
{
	//list<LIST_T_LOCALBLOCK>::iterator itr = LPayLoad.begin();
	//for (; itr != LPayLoad.end(); itr++)
	//{
	//	list<T_LOCALBLOCK> vectTemp;
	//	list<T_LOCALBLOCK>::iterator subItr = (*itr).begin();

	//	for (; subItr != (*itr).end(); subItr++)
	//	{
	//		vectTemp.push_back(*subItr);
	//	}

	//	listPayLoad.push_back(vectTemp);
	//}
	listPayLoad = std::forward<list<LIST_T_LOCALBLOCK>>(LPayLoad);
}

_tblockbaseinfo _thyperblock::GetBlockBaseInfo()const
{
	return tBlockBaseInfo;
}

_tblockbaseinfo& _thyperblock::GetBlockBaseInfo()
{
	return tBlockBaseInfo;
}

T_SHA256 _thyperblock::GetMerkleHash()
{
	return tMerkleHashAll;
}

list<LIST_T_LOCALBLOCK> &_thyperblock::GetlistPayLoad()
{
	return listPayLoad;
}

void _thyperblock::PushBack(LIST_T_LOCALBLOCK lb)
{
	listPayLoad.push_back(lb);
}

int8* _thyperblock::GetVersionString()
{
	return version;
}



_thyperblocksend& _thyperblocksend::operator = (const _thyperblocksend& arRes)
{
	if (this != &arRes)
	{
		tHashAll = arRes.tHashAll;
		tBlockBaseInfo = arRes.tBlockBaseInfo;
	}
	return *this;
}

void _thyperblocksend::SetHyperBlockSend(_tblockbaseinfo tBBI, T_SHA256 tHA, char* ver, uint32 diff)
{
	tBlockBaseInfo = tBBI;
	tHashAll = tHA;
	strncpy(version,ver, MAX_VER_LEN);
	difficulty = diff;

}

void _thyperblocksend::SetBlockBaseInfo(_tblockbaseinfo tBBI)
{
	tBlockBaseInfo = tBBI;
}

void _thyperblocksend::SetHashAll(T_SHA256 tHA)
{
	tHashAll = tHA;

}

_tblockbaseinfo _thyperblocksend::GetBlockBaseInfo()const
{
	return tBlockBaseInfo;
}

T_SHA256 _thyperblocksend::GetHashAll()const
{
	return tHashAll;
}

_tchainStateinfo& _tchainStateinfo:: operator = (const _tchainStateinfo& arRes)
{
	if (this != &arRes)
	{
		uiBlockNum = arRes.uiBlockNum;
	}
	return *this;
}

void _tchainStateinfo::SetBlockNum(uint64 BlockNum)
{
	uiBlockNum = BlockNum;
}

uint64 _tchainStateinfo::GetBlockNum()const
{
	return uiBlockNum;
}



_tpeerinfo& _tpeerinfo::operator = (const _tpeerinfo& arRes)
{
	if (this != &arRes)
	{
		tPeerInfoByMyself = arRes.tPeerInfoByMyself;
		tPeerInfoByOther = arRes.tPeerInfoByOther;

		uiState = arRes.uiState;
		uiNatTraversalState = arRes.uiNatTraversalState;
		uiTime = arRes.uiTime;
		strncpy(strName, arRes.strName, MAX_NODE_NAME_LEN);
		uiNodeState = arRes.uiNodeState;
	}
	return *this;
}

void _tpeerinfo::SetPeerinfo(T_PEERADDRESS PeerInfoByMyself, T_PEERADDRESS PeerInfoByOther, uint16 State, uint16 NatTraversalState, uint64 Time, uint16 NodeState, int8 *Name)
{
	tPeerInfoByMyself = PeerInfoByMyself;
	tPeerInfoByOther = PeerInfoByOther;
	
	uiState = State;
	uiNatTraversalState = NatTraversalState;
	uiTime = Time;
	uiNodeState = NodeState;
	strncpy(strName, Name, MAX_NODE_NAME_LEN);
}

void _tpeerinfo::SetPeerInfoByMyself(T_PEERADDRESS PeerInfoByMyself)
{
	tPeerInfoByMyself = PeerInfoByMyself;
}

void _tpeerinfo::SetPeerInfoByOther(T_PEERADDRESS PeerInfoByOther)
{
	tPeerInfoByOther = PeerInfoByOther;
}

void _tpeerinfo::SetState(uint16 State)
{
	uiState = State;
}

void _tpeerinfo::SetNatTraversalState(uint16 NatTraversalState)
{
	uiNatTraversalState = NatTraversalState;
}

void _tpeerinfo::SetTime(uint64 Time)
{
	uiTime = Time;
}

void _tpeerinfo::SetNodeState(uint16 NodeState)
{
	uiNodeState = NodeState;
}

void _tpeerinfo::SetName(int8 *Name)
{
	strncpy(strName, Name, MAX_NODE_NAME_LEN);
}

T_PEERADDRESS _tpeerinfo::GetPeerInfoByMyself()const
{
	return tPeerInfoByMyself;
}

T_PEERADDRESS _tpeerinfo::GetPeerInfoByOther()const
{
	return tPeerInfoByOther;
}

uint16 _tpeerinfo::GetState()const
{
	return uiState;
}

uint16 _tpeerinfo::GetNatTraversalState()const
{
	return uiNatTraversalState;
}

uint64 _tpeerinfo::GetTime()const
{
	return uiTime;
}

uint16 _tpeerinfo::GetNodeState()const
{
	return uiNodeState;
}

int8 *_tpeerinfo::GetName()
{
	return strName;
}


_tblockstateaddr::_tblockstateaddr(T_PEERADDRESS PeerAddr, T_PEERADDRESS PeerAddrOut)
{
	tPeerAddr = PeerAddr;
	tPeerAddrOut = PeerAddrOut;
}

_tblockstateaddr& _tblockstateaddr:: operator = (const _tblockstateaddr& arRes)
{
	if (this != &arRes)
	{
		tPeerAddr = arRes.tPeerAddr;
		tPeerAddrOut = arRes.tPeerAddrOut;

	}
	return *this;
}

void _tblockstateaddr::SetBlockStateAddr(T_PEERADDRESS PeerAddr, T_PEERADDRESS PeerAddrOut)
{
	tPeerAddr = PeerAddr;
	tPeerAddrOut = PeerAddrOut;
}

void _tblockstateaddr::SetPeerAddr(T_PEERADDRESS PeerAddr)
{
	tPeerAddr = PeerAddr;
}

void _tblockstateaddr::SetPeerAddrOut(T_PEERADDRESS PeerAddrOut)
{
	tPeerAddrOut = PeerAddrOut;
}

T_PEERADDRESS _tblockstateaddr::GetPeerAddr()const
{
	return tPeerAddr;
}

T_PEERADDRESS _tblockstateaddr::GetPeerAddrOut()const
{
	return tPeerAddrOut;
}

_tlocalconsensus::_tlocalconsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime, const char *FileHash)
{
	memset(strFileHash, 0, DEF_SHA512_LEN + 1);
	uiRetryTime = 0;

	tPeer = Peer;
	tLocalBlock = LocalBlock;
	memcpy(strFileHash, FileHash, DEF_SHA512_LEN + 1);
	uiRetryTime = RetryTime;
}

_tlocalconsensus::_tlocalconsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime)
{
	memset(strFileHash, 0, DEF_SHA512_LEN + 1);

	tPeer = Peer;
	tLocalBlock = LocalBlock;
	uiRetryTime = RetryTime;
}

_tlocalconsensus& _tlocalconsensus:: operator = (const _tlocalconsensus& arRes)
{
	if (this != &arRes)
	{
		tPeer = arRes.tPeer;
		tLocalBlock = arRes.tLocalBlock;
		memcpy(strFileHash, arRes.strFileHash, DEF_SHA512_LEN + 1);
		uiRetryTime = arRes.uiRetryTime;
	}
	return *this;
}

void _tlocalconsensus::SetLoaclConsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime, const char *FileHash)
{
	tPeer = Peer;
	tLocalBlock = LocalBlock;
	memcpy(strFileHash, FileHash, DEF_SHA512_LEN + 1);
	uiRetryTime = RetryTime;
}

void _tlocalconsensus::SetLoaclConsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock, uint64 RetryTime)
{
	tPeer = Peer;
	tLocalBlock = LocalBlock;
	uiRetryTime = RetryTime;
}

void _tlocalconsensus::SetLoaclConsensus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK  LocalBlock)
{
	tPeer = Peer;
	tLocalBlock = LocalBlock;
}

void _tlocalconsensus::SetPeer(T_BLOCKSTATEADDR  Peer)
{
	tPeer = Peer;
}

void _tlocalconsensus::SetLocalBlock(T_LOCALBLOCK  LocalBlock)
{
	tLocalBlock = LocalBlock;
}

void _tlocalconsensus::SetRetryTime(uint64 RetryTime)
{
	uiRetryTime = RetryTime;

}

void _tlocalconsensus::SetFileHash(char *FileHash)
{
	memcpy(strFileHash, FileHash, DEF_SHA512_LEN + 1);
}

T_BLOCKSTATEADDR _tlocalconsensus::GetPeer()const
{
	return tPeer;
}

T_LOCALBLOCK _tlocalconsensus::GetLocalBlock()const
{
	return tLocalBlock;
}

T_LOCALBLOCK& _tlocalconsensus::GetLocalBlock()
{
	return tLocalBlock;
}


uint64 _tlocalconsensus::GetRetryTime()const
{
	return uiRetryTime;
}

char * _tlocalconsensus::GetFileHash()
{
	return strFileHash;
}


T_BLOCKSTATEADDR _tglobalconsenus::GetPeer()const
{
	return tPeer;
}

uint64 _tglobalconsenus::GetChainNo()const
{
	return uiAtChainNum;
}


T_LOCALBLOCK _tglobalconsenus::GetLocalBlock()const
{
	return tLocalBlock;
}

void _tglobalconsenus::SetChainNo(uint64 no)
{
	uiAtChainNum = no;
}

void _tglobalconsenus::SetLocalBlock(const T_LOCALBLOCK&block)
{
	tLocalBlock = block;
}

void _tglobalconsenus::SetPeer(const T_BLOCKSTATEADDR&addr)
{
	tPeer = addr;
}

void _tglobalconsenus::SetGlobalconsenus(T_BLOCKSTATEADDR Peer, T_LOCALBLOCK LocalBlock, uint64 AtChainNum)
{
	tPeer = Peer;
	tLocalBlock = LocalBlock;
	uiAtChainNum = AtChainNum;
}

uint8 _tbuddyinfo::GetType()const
{
	return tType;
}

uint32 _tbuddyinfo::GetBufferLength()const
{
	return bufLen;
}

string& _tbuddyinfo::GetBuffer()
{
	return recvBuf;
}

T_PEERADDRESS _tbuddyinfo::GetRequestAddress()const
{
	return tPeerAddrOut;
}

void _tbuddyinfo::Set(uint8 t, uint32 bufferLen, const char*receiveBuf, T_PEERADDRESS peerAddrOut)
{
	tType = t;
	bufLen = bufferLen;
	
	recvBuf = string(receiveBuf,bufLen);
	tPeerAddrOut = peerAddrOut;
}

uint8 _tbuddyinfostate::GetBuddyState()const
{
	return uibuddyState;
}

LIST_T_LOCALCONSENSUS _tbuddyinfostate::GetList()const
{
	return localList;
}

T_PEERADDRESS _tbuddyinfostate::GetPeerAddrOut()const
{
	return tPeerAddrOut;
}

void _tbuddyinfostate::LocalListSort()
{
	localList.sort(CmpareOnChain());
}

LIST_T_LOCALCONSENSUS& _tbuddyinfostate::GetLocalConsensus()
{
	return localList;
}

void _tbuddyinfostate::Set(int8 buddyHash[], uint8 buddyState, T_PEERADDRESS addr)
{
	memcpy(strBuddyHash, buddyHash, sizeof(int8)*DEF_STR_HASH256_LEN);
	uibuddyState = buddyState;
	tPeerAddrOut = addr;
}

void _tbuddyinfostate::LocalListPushBack(T_LOCALCONSENSUS localBlockInfo)
{
	localList.push_back(localBlockInfo);
}

void _tbuddyinfostate::LocalListClear()
{
	localList.clear();
}

const int8 * _tbuddyinfostate::GetBuddyHash()const
{
	return strBuddyHash;
}

void _tbuddyinfostate::SetPeerAddrOut(T_PEERADDRESS PeerAddrOut)
{
	tPeerAddrOut = PeerAddrOut;
}

void _tbuddyinfostate::SetBuddyState(uint8 BuddyState)
{
	uibuddyState = BuddyState;
}

void _tbuddyinfostate::SetBuddyHash(int8* BuddyHash)
{

	memcpy(strBuddyHash, BuddyHash, DEF_STR_HASH256_LEN);
}

void _tbuddyinfostate::SetBuddyHashInit(int Num)
{
	memset(strBuddyHash, Num, DEF_STR_HASH256_LEN);
}

T_PEERADDRESS _tpeerconf::GetIntranetAddress()const
{
	return tPeerAddr;
}

T_PEERADDRESS _tpeerconf::GetInternetAddress()const
{
	return tPeerAddrOut;
}

uint16 _tpeerconf::GetPeerState()const
{
	return uiPeerState;
}

int8* _tpeerconf::GetNodeName()const
{
	return (int8*)strName;
}

uint16 _tconffile::GetSaveNodeNum()const
{
	return uiSaveNodeNum;
}

uint32 _tconffile::GetLocalIP()const
{
	return uiLocalIP;
}

uint32 _tconffile::GetLocalPort()const
{
	return uiLocalPort;
}

string _tconffile::GetLocalNodeName()const
{
	return strLocalNodeName;
}

string _tconffile::GetLogDir()const
{
	return strLogDir;
}
