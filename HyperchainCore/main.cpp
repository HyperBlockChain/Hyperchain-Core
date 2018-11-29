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
#include "qttestp2p.h"

#include <QtWidgets/QApplication>
#include <QDir>
#include <QStandardPaths>
#include <iostream>
#include <sstream>


#include "db/dbmgr.h"

#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/TaskThreadPool.h"
#include "node/UdpAccessPoint.hpp"
#include "node/SearchNeighbourTask.hpp"
#include "node/UpChainTask.hpp"
#include "node/UdpRecvDataHandler.hpp"

#include "HyperChain/HyperChainSpace.h"
#include "HyperChain/HyperData.h"
#include "HyperChain/PullChainSpaceTask.hpp"
#include "HyperChain/PullHyperDataTask.hpp"
#include "consolecommandhandler.h"


static std::string make_db_path(){
	QString doc = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
	doc += QString("/hyperchain/hp");

	QDir d;
	d.mkpath(doc);

	return doc.toStdString();
}

void testhyperchaindata(string nodeid)
{
	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();
	CHyperData * HData = Singleton<CHyperData>::instance();
	if (!HSpce || !HData)
		return;


	map<uint64, set<string>> hyperdata;
	hyperdata.clear();
	uint64 num = 0;
	cout << "µÈ´ý»ñÈ¡Á´¿Õ¼ä.............." << endl;
	HSpce->PullDataFromChainSpace();
	while (num == 0)
	{		
		SLEEP(5000);
		HSpce->GetHyperChainData(hyperdata);
		num = hyperdata.size();

	}
	

	for (auto mdata : hyperdata)
	{
		for (auto sid : mdata.second)
		{
			cout << "»ñµÃÁ´¿Õ¼äHyperID = " << mdata.first << "¶ÔÓ¦nodeid = " << sid << endl;
		}
	}

	uint64 nhyperid = 0;
	string strnodeid = "";
	cout << "ÊäÈëÐèÒª»ñÈ¡µÄ³¬¿éºÅID: ";
	cin >> nhyperid;
	vector<string> vnode(hyperdata[nhyperid].begin(), hyperdata[nhyperid].end());

	while (vnode.size() == 0)
	{
		cout << "Á´¿Õ¼äÎÞ´ËID£¬ÖØÐÂÊäÈëÐèÒª»ñÈ¡µÄ³¬¿éºÅID: ";
		cin >> nhyperid;
		vnode.clear();
		vnode.assign(hyperdata[nhyperid].begin(), hyperdata[nhyperid].end());
	}



	int i = 0;
	cout << "´Ë³¬¿é´æÔÚÓÚÁ´¿Õ¼äµÄÒÔÏÂ½ÚµãÖÐ" << endl;

	for (auto nid : vnode)
	{
		cout << "½Úµã[" << i << "]µÄnodeid = " << nid << endl;
		i++;
	}

	cout << "Ñ¡ÔñÏÂÔØ½Úµã,ÊäÈëÊý×Ö¼´¿É" << endl;
	int nindex = 0;
	cin >> nindex;
	strnodeid = vnode[nindex];

	HData->PullHyperDataByHID(nhyperid, strnodeid);

	
}


int main(int argc, char *argv[])
{



	std::string dbpath = make_db_path();
	dbpath += "/hyperchain.db";
	DBmgr::instance()->open(dbpath.c_str());



	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::instance();
	NodeManager *nodemgr = Singleton<NodeManager>::instance();
	UdpRecvDataHandler *udprecvhandler = Singleton<UdpRecvDataHandler>::instance();
	UdpThreadPool *up = Singleton<UdpThreadPool>::instance();
	up->Init("", 6666);
	
	


	CUInt128 uid1(string("e0a7688ad0f611e8a8d5f2801f1b9fd1"));
	CNode node1(uid1);
	node1.addAP(std::make_shared<UdpAccessPoint>("192.168.0.83", 6666));
	

	nodemgr->addNode(std::move(node1));
	nodemgr->saveNeighbourNodes();

	nodemgr->loadNeighbourNodes();


	string mynodeid;	
	nodemgr->loadMyself();
	try
	{
		CNode me = nodemgr->myself();		
		if (!me.isValid()) 
		{
			string str = CNode::generateNodeId();
			mynodeid = str;
			me = CNode(CUInt128(str));
			nodemgr->myself(me);
			nodemgr->saveMyself();
		}
		else
		{
			mynodeid = me.getNodeId<string>();
		}
	}
	catch (std::exception &e) {
		string s = e.what();
		string s1 = s;
	}


	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::instance(mynodeid);
	CHyperData * hd = Singleton<CHyperData>::instance();


	ConsoleCommandHandler console;
	console.run();

	return 0;
}
