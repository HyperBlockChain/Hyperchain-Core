/*Copyright 2016-2018 hyperchain.net (Hyperchain)

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
#include <QDateTime>
#include "QtNotifyConsole.h"
#include "../../db/dbmgr.h"
#include "QtInterface.h"
#include "../../wnd/common.h"


QtNotifyConsole::QtNotifyConsole(bool isGUI) :
	_currentblocknumber(0),
	_gBuddyChainNum(0),
	_buddystatus(0),
	_betternum(0),
	_normalnum(0),
	_badnum(0),
	_downnum(0),
	_sendpoenum(0),
	_recvepoenum(0),
	_identity(""),
	_ip("")
{
}

QtNotifyConsole::~QtNotifyConsole()
{
}

void QtNotifyConsole::SetHyperBlock(string hash, time_t time, uint64 blocknumber)
{	
	_currentblocknumber = blocknumber;

	if (!hash.empty() && time > 0) {
		updateEvidenceByHash(hash, time, blocknumber);
	}
}

uint64 QtNotifyConsole::GetHyperBlock()
{
	return _currentblocknumber;
}

void QtNotifyConsole::SetNodeStatus(uint16 status)
{
	_buddystatus = status;
}

string QtNotifyConsole::GetNodeStatus()
{
	switch (_buddystatus) {
	case IDLE:
		return string("IDLE");

	case LOCAL_BUDDY:
		return string("LOCAL_BUDDY");

	case GLOBAL_BUDDY:
		return string("GLOBAL_BUDDY");

	default:
		return string("IDLE");
	}
}

void QtNotifyConsole::SetBuddyStartTime(time_t stime, uint64 blocknumber)
{
}

void QtNotifyConsole::SetGlobleBuddyChainNum(uint16 number)
{
	_gBuddyChainNum = number;
}

uint16 QtNotifyConsole::GetGlobleBuddyChainNum()
{
	return _gBuddyChainNum ;
}

void QtNotifyConsole::SetLocalBuddyChainInfo(LIST_T_LOCALCONSENSUS chaininfo)
{
	_vecnode.clear();
	for (auto item : chaininfo) {
		TNODEINFO info;
		info.strNodeIp = to_string(item.tPeer.tPeerAddrOut.uiIP) + ":" + to_string(item.tPeer.tPeerAddrOut.uiPort);
		info.uiNodeState = CONFIRMED;
		_vecnode.push_back(info);

	}
}

const VEC_T_NODEINFO& QtNotifyConsole::GetLocalBuddyChainInfo()
{
	return _vecnode;
}

void QtNotifyConsole::SetConnectNodeUpdate(uint32 betternum, uint32 normalnum, uint32 badnum, uint32 downnum)
{
	_betternum = betternum;
	_normalnum = normalnum;
	_badnum = badnum;
	_downnum = downnum;
}

void QtNotifyConsole::GetConnectNode(uint32 &betternum, uint32 &normalnum, uint32 &badnum, uint32 &downnum)
{
	betternum = _betternum;
	normalnum = _normalnum;
	badnum = _badnum;
	downnum = _downnum;
}


void QtNotifyConsole::SetSendPoeNum(uint32 number)
{
	_sendpoenum = number;
}


uint32 QtNotifyConsole::GetSendPoeNum()
{
	return _sendpoenum;
}

void QtNotifyConsole::SetReceivePoeNum(uint32 number)
{
	_recvepoenum = number;
}

uint32 QtNotifyConsole::GetReceivePoeNum()
{
	return _recvepoenum;
}


void  QtNotifyConsole::SetNodeInfo(string info, string ip, uint16 port)
{
	_identity = ip + ":" + to_string(port);
	_ip = _identity;
}

void  QtNotifyConsole::GetNodeInfo(string &info)
{
	info = _identity;
}

void  QtNotifyConsole::SetServerInfo(VEC_T_PPEERCONF info)
{
}


const VEC_T_PPEERCONF &  QtNotifyConsole::GetServerInfo()
{
	return g_confFile.vecPeerConf;
}

void QtNotifyConsole::SetBuddyStop()
{
	_gBuddyChainNum = 0;
	_buddystatus = IDLE;
}

void QtNotifyConsole::SetHyperBlockNumFromLocal(list<uint64> HyperBlockNum)
{
}

void QtNotifyConsole::SetBuddyFailed(string hash, time_t time)
{
	Update_BuddyFailed(hash,time);
}

void QtNotifyConsole::SetStatusMes(string msg)
{
	if (msg != _msgcurrstatus) {
		cout << endl;
		cout << msg;
		_msgcurrstatus = msg;
	}
	else {
		cout << ".";
	}
}


void QtNotifyConsole::Update_BuddyFailed(string hash, time_t time)
{
	for (auto evi : _listEvi)
	{
		if ((hash.compare(evi->cFileHash) == 0) && (time == evi->tRegisTime))
		{
			evi->iFileState = REJECTED;
			DBmgr::instance()->updateEvidence(*evi, 2);
			break;
		}
	}
}

void QtNotifyConsole::addEvidence(QSharedPointer<TEVIDENCEINFO> evi, int index)
{
	_listEvi.append(evi);
	DBmgr::instance()->insertEvidence(*evi.data());
}

void QtNotifyConsole::updateEvidence()
{
	for (auto evi : _listEvi) {
		if (evi->iFileState == CONFIRMING) {
			evi->iFileState = CONFIRMED;

			DBmgr::instance()->updateEvidence(*evi, 1);

			break;
		}
	}
}

void QtNotifyConsole::updateEvidenceByHash(string hash, time_t time, uint64 blocknumber)
{
	for (auto evi : _listEvi)
	{
		if ((hash.compare(evi->cFileHash) == 0) && (time == evi->tRegisTime))
		{
			evi->iBlocknum = blocknumber;
			evi->iFileState = CONFIRMED;
			DBmgr::instance()->updateEvidence(*evi, 4); 
			break;
		}
	}
}


void QtNotifyConsole::queryBlock(uint64 nblocknum, QList<T_HYPERBLOCKDBINFO> &listblock)
{
	int nStartId = nblocknum;
	int nEndId = nblocknum;

	listblock.clear();
	int nRet = DBmgr::instance()->getHyperblocks(listblock, nStartId, nEndId);
	if (nRet == 0 && listblock.size() == 0) {
		throw std::runtime_error("Not found the hyper block");
	} 

	if (nRet != 0) {
		throw std::runtime_error("Failed to query database for the hyper block");
	}
}
