/*Copyright 2016-2018 hyperchain.net (Hyperchain)

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
#include "node/UpChainTask.hpp"
#include "node/UdpRecvDataHandler.hpp"
#include "node/seedcommu.hpp"

#include "HyperChain/HyperChainSpace.h"
#include "HyperChain/HyperData.h"
#include "HyperChain/PullChainSpaceTask.hpp"
#include "HyperChain/PullHyperDataTask.hpp"

#include "consolecommandhandler.h"

#include <boost/program_options.hpp>
using namespace boost::program_options;

static std::string make_db_path(){
	QString doc = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
	doc += QString("/hyperchain/hp");

	QDir d;
	d.mkpath(doc);

	return doc.toStdString();
}

void makeSeedServer(const string & seedserver)
{
	string nodeid("1234567879012345678901234567890ab", CUInt128::value);
	CNode seed(std::move(CUInt128(nodeid)));

	string server;
	int port = 8116;
	size_t found = seedserver.find_first_of(':');
	if(found == std::string::npos) {
		server = seedserver;
	}
	else {
		server = seedserver.substr(0, found);
		port = std::stoi(seedserver.substr(found+1));
	}

	seed.addAP(make_shared<UdpAccessPoint>(server, port));

	NodeManager *nodemgr = Singleton<NodeManager>::instance();
	nodemgr->seedServer(std::move(seed));
}



int main(int argc, char *argv[])
{
	std::string command = "command line options";
	options_description desc(command);

	desc.add_options()
		("help,h", "print help message")
		("runasss,s", value<int>(), "run as a seed server,default port is 8116")
		("me,m", value<string>(), "specify myself,for example:10.0.0.1:8116,cannot use with runasss")
		("seedserver", value<std::string>(), "specify a seed server,for example:127.0.0.1:8116");

	variables_map vm;

	store(parse_command_line(argc, argv, desc), vm);
	notify(vm);

	if (vm.count("help")) {
		cout << desc << endl;
		return 0;
	}

	int udpport = 8115;
	if (vm.count("runasss")) {
		if (vm.count("me")) {
			cout << desc << endl;
			return -1;
		}
		udpport = vm["runasss"].as<int>();
		cout << "Run as a seed server,listen UDP port is " << udpport << endl;
	}

	string seedserver = "127.0.0.1:8116";
	if (vm.count("seedserver")) {
		seedserver = vm["seedserver"].as<string>();
		cout << "Run as a seed client,seed server is " << seedserver << endl;
		makeSeedServer(seedserver);
	}



	std::string dbpath = make_db_path();
	dbpath += "/hyperchain.db";
	DBmgr::instance()->open(dbpath.c_str());

	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::instance();
	NodeManager *nodemgr = Singleton<NodeManager>::instance();
	

	string mynodeid;
	nodemgr->loadMyself();
	CNode me = nodemgr->myself();
	try
	{
		if (!me.isValid()) {
			string str = CNode::generateNodeId();
			mynodeid = str;
			me = CNode(CUInt128(str));
			nodemgr->myself(std::move(me));
			nodemgr->saveMyself();
		}
		else {
			mynodeid = me.getNodeId<string>();
		}
	}
	catch (std::exception &e) {
		string s = e.what();
		string s1 = s;
	}	

	if (vm.count("me")) {
		string strMe = vm["me"].as<string>();
		cout << "My IP and port is " << strMe << endl;

		string ip;
		size_t found = strMe.find_first_of(':');
		if (found == std::string::npos) {
			ip = strMe;
		}
		else {
			ip = strMe.substr(0, found);
			udpport = std::stoi(strMe.substr(found + 1));
		}

		me.addAP(std::make_shared<UdpAccessPoint>(ip, udpport));
	}

	nodemgr->myself(std::move(me));
	nodemgr->saveMyself();

	UdpRecvDataHandler *udprecvhandler = Singleton<UdpRecvDataHandler>::instance();
	UdpThreadPool *up = Singleton<UdpThreadPool, const char*, uint32_t, uint32_t>::instance("", udpport, 2);
	up->start();
	
	nodemgr->loadNeighbourNodes();



	SeedCommunication seedcomm;
	if (vm.count("runasss") <= 0) {
		seedcomm.start();
	}
	
	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::instance(mynodeid);
	CHyperData * hd = Singleton<CHyperData>::instance();


	ConsoleCommandHandler console;
	console.run();

	return 0;
}
