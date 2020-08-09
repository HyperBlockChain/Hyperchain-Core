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

#include "../headers/inter_public.h"
#include "../wnd/common.h"

#include <cpprest/json.h>
using namespace web;


void _tLocalChain::Set(uint16 id, uint64 allChainNodeNum, _eChainState state)
{
    iId = id;
    iAllChainNodeNum = allChainNodeNum;
    eState = state;
}

uint16 _tLocalChain::GetID()const
{
    return iId;
}

uint64 _tLocalChain::GetChainNodesNum()const
{
    return iAllChainNodeNum;
}

_eChainState _tLocalChain::GetChainState()const
{
    return eState;
}


void _tPoeInfo::Set(string fileName, string customInfo, string rightOwner, string fileHash,
    int16 fileState, uint64 regisTime, uint64 fileSize, uint64 blockNum)
{
    cFileName = fileName;
    cCustomInfo = customInfo;
    cRightOwner = rightOwner;
    cFileHash = fileHash;
    iFileState = fileState;
    tRegisTime = regisTime;
    iFileSize = fileSize;
    iBlocknum = blockNum;
}

string _tPoeInfo::GetFileName()const
{
    return cFileName;
}

string _tPoeInfo::GetFileHash()const
{
    return cFileHash;
}

int16 _tPoeInfo::GetFileState()const
{
    return iFileState;
}

uint64 _tPoeInfo::GetFileSize()const
{
    return iFileSize;
}

string _tPoeInfo::GetRightOwner()const
{
    return cRightOwner;
}

uint64 _tPoeInfo::GetRegisTime()const
{
    return tRegisTime;
}

string _tPoeInfo::GetCustomInfo()const
{
    return cCustomInfo;
}



void _tChainQueryStru::Set(uint64 blockNo, uint64 joinedNodeNum, uint64 localBlockNum, uint16 localChainNum,
    uint64 timeStamp, _tPoeInfo poeRecordInfo)
{
    iBlockNo = blockNo;
    iJoinedNodeNum = joinedNodeNum;
    iLocalBlockNum = localBlockNum;
    iLocalChainNum = localChainNum;
    tTimeStamp = timeStamp;
    tPoeRecordInfo = poeRecordInfo;
}

uint64 _tChainQueryStru::GetBlockNo()const
{
    return iBlockNo;
}

uint64 _tChainQueryStru::GetJoinedNodeNum()const
{
    return iJoinedNodeNum;
}

uint64 _tChainQueryStru::GetLocalBlockNum()const
{
    return iLocalChainNum;
}

uint16 _tChainQueryStru::GetLocalChainNUm()const
{
    return iLocalChainNum;
}

uint64 _tChainQueryStru::GetTimeStamp()const
{
    return tTimeStamp;
}

_tPoeInfo _tChainQueryStru::GetPoeRecordInfo()const
{
    return tPoeRecordInfo;
}

void _tBlockInfo::Set(uint64 blockNo, uint64 createTime, _tPoeInfo poeRecordInfo)
{
    iBlockNo = blockNo;
    iCreatTime = createTime;
    tPoeRecordInfo = poeRecordInfo;
}

uint64 _tBlockInfo::GetBlockNo()const
{
    return iBlockNo;
}

uint64 _tBlockInfo::GetCreateTime()const
{
    return iCreatTime;
}

_tPoeInfo _tBlockInfo::GetPoeRecordInfo()const
{
    return tPoeRecordInfo;
}

void _tHBlockDlgInfo::Set(uint64 blockNo, uint64 createTime, uint64 localBlockNum, string HHash, string version)
{
    iBlockNo = blockNo;
    iCreatTime = createTime;
    iLocalBlockNum = localBlockNum;
    strHHash = HHash;
    strVersion = version;
}

uint64 _tHBlockDlgInfo::GetBlockNo()const
{
    return iBlockNo;
}

uint64 _tHBlockDlgInfo::GetCreateTime()const
{
    return iCreatTime;
}

uint64 _tHBlockDlgInfo::GetLocalBlockNum()const
{
    return iLocalBlockNum;
}

string _tHBlockDlgInfo::GetParentHash()const
{
    return strHHash;
}

_tNodeInfo::_tNodeInfo(uint64 nodeState, string nodeIp)
{
    uiNodeState = nodeState;
    strNodeIp = nodeIp;
}

void _tNodeInfo::Set(uint64 nodeState, string nodeIp)
{
    uiNodeState = nodeState;
    strNodeIp = nodeIp;
}

uint64 _tNodeInfo::GetNodeState()const
{
    return uiNodeState;
}

string _tNodeInfo::GetNodeIp()const
{
    return strNodeIp;
}

