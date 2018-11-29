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
#pragma once
#include "../headers/inter_public.h"
#include "../headers/commonstruct.h"
#include <QObject>
#include <QSharedPointer>
#include "QtNotify.h"


class QtNotifyConsole : public QtNotify 
{
	Q_OBJECT
public:
	QtNotifyConsole(bool isGUI = true);
	~QtNotifyConsole();

	void SetHyperBlock(string hash, time_t time, uint64 blocknumber);
	void SetNodeStatus(uint16 status);	
	void SetGlobleBuddyChainNum(uint16 number);
	void SetLocalBuddyChainInfo(LIST_T_LOCALCONSENSUS chaininfo);
	void SetConnectNodeUpdate(uint32 betternum, uint32 normalnum, uint32 badnum, uint32 downnum);
	void SetSendPoeNum(uint32 number);
	void SetReceivePoeNum(uint32 number);
	void SetBuddyStartTime(time_t stime, uint64 blocknumber);
	void SetNodeInfo(string info, string ip, uint16 port);
	void SetServerInfo(VEC_T_PPEERCONF info);
	void SetBuddyStop();
	void SetHyperBlockNumFromLocal(list<uint64> HyperBlockNum);
	void SetBuddyFailed(string hash, time_t time);
	void SetStatusMes(string msg);


	uint64 GetHyperBlock();
	uint16 GetGlobleBuddyChainNum();
	string GetNodeStatus();
	void GetConnectNode(uint32 &betternum, uint32 &normalnum, uint32 &badnum, uint32 &downnum);
	uint32 GetSendPoeNum();
	uint32 GetReceivePoeNum();
	void  GetNodeInfo(string &info);
	const VEC_T_NODEINFO& GetLocalBuddyChainInfo();

	void queryBlock(uint64 nblocknum, QList<T_HYPERBLOCKDBINFO> &listblock);
	const VEC_T_PPEERCONF & GetServerInfo();

private:

	void addEvidence(QSharedPointer<TEVIDENCEINFO> evi, int index);
	void updateEvidence();
	void updateEvidenceByHash(string hash, time_t time, uint64 blocknumber);
	void Update_BuddyFailed(string hash, time_t time);

private:

	uint64 _currentblocknumber;
	uint16 _gBuddyChainNum;

	uint16 _buddystatus;
	VEC_T_NODEINFO _vecnode;

	uint32 _betternum;
	uint32 _normalnum;
	uint32 _badnum;
	uint32 _downnum;

	uint32 _sendpoenum;
	uint32 _recvepoenum;

	string _identity;
	string _ip;
	string _msgcurrstatus;

	VEC_T_PPEERCONF _peerinfo;

    QList<QSharedPointer<TEVIDENCEINFO> > _listEvi;

};

