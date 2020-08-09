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

#ifdef _WIN32

#include <WinSock2.h>

#endif

#include <sstream>
using namespace std;
#include "../headers/commonstruct.h"
#include "../headers/lambda.h"
#include "../crypto/sha2.h"


void _tlocalblock::updatePreHyperBlockInfo(uint64_t preHID, const T_SHA256 &preHHash)
{
    if (preHHash == header.tPreHHash) {
        return;
    }
    


    header.tPreHHash = preHHash;
    _prehid = preHID;

    

    CalculateHashSelf();
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

void _tlocalconsensus::SetLoaclConsensus(T_BLOCKSTATEADDR Peer,const T_LOCALBLOCK &LocalBlock, uint64 RetryTime, const char *FileHash)
{
    tPeer = Peer;
    tLocalBlock = LocalBlock;
    memcpy(strFileHash, FileHash, DEF_SHA512_LEN + 1);
    uiRetryTime = RetryTime;
}

void _tlocalconsensus::SetLoaclConsensus(T_BLOCKSTATEADDR Peer, const T_LOCALBLOCK &LocalBlock, uint64 RetryTime)
{
    tPeer = Peer;
    tLocalBlock = LocalBlock;
    uiRetryTime = RetryTime;
}

void _tlocalconsensus::SetLoaclConsensus(T_BLOCKSTATEADDR Peer, const T_LOCALBLOCK &LocalBlock)
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

size_t _tbuddyinfo::GetBufferLength()const
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

void _tbuddyinfo::Set(uint8 t, size_t bufferLen, const char*receiveBuf, T_PEERADDRESS peerAddrOut)
{
    tType = t;
    bufLen = bufferLen;

    recvBuf = string(receiveBuf, bufLen);
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
