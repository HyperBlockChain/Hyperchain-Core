/*Copyright 2016-2019 hyperchain.net (Hyperchain)

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

#include <boost/algorithm/string.hpp>
#include <map>
#include <set>
#include "consolecommandhandler.h"

#include "headers/inter_public.h"
#include "headers/commonstruct.h"
#include "db/dbmgr.h"
#include "node/Singleton.h"
#include "node/TaskThreadPool.h"
#include "HyperChain/HyperChainSpace.h"
#include "HyperChain/HyperData.h"
#include "node/NodeManager.h"
#include "consensus/buddyinfo.h"
#include "consensus/consensus_engine.h"



using namespace std;

string FileNameFromFullPath(const string &fullpath)
{
	size_t s = fullpath.find_last_of("/\\");
	if (s != std::string::npos) {
		return fullpath.substr(s + 1);
	}
	return fullpath;
}

void trim(string &str)
{
	std::string whitespaces(" \t\f\v\n\r");

	std::size_t found = str.find_last_not_of(whitespaces);
	if (found != std::string::npos) {
		str.erase(found + 1);
	}
	else {
		str.clear();
		return;
	}

	found = str.find_first_not_of(whitespaces);
	if (found != std::string::npos)
		str.erase(0, found);
}

void stringTostringlist(const string & str, list<string> &l, char delimiter = ' ')
{
	string piece;
	string tmp = str;

	size_t len = tmp.size();

	std::size_t found = tmp.find_first_of(delimiter);
	while (found < len) {
		piece = tmp.substr(0, found);
		l.push_back(piece);

		size_t pos = tmp.find_first_not_of(delimiter, found);
		if (pos > found + 1) {
			tmp.erase(0, pos);
		}
		else {
			tmp.erase(0, found + 1);
		}
		found = tmp.find_first_of(delimiter);
	}

	if (tmp.size() > 0) {
		l.push_back(tmp);
	}
}


void queryBlock(uint64 nblocknum, std::list<T_HYPERBLOCKDBINFO> &listblock)
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


ConsoleCommandHandler::ConsoleCommandHandler() :
	_isRunning(true)
{
	cmdstruct cmd("help", std::bind(&ConsoleCommandHandler::showUsages, this));

	_commands.emplace_back(cmdstruct("help", std::bind(&ConsoleCommandHandler::showUsages, this)));
	_commands.emplace_back(cmdstruct("?", std::bind(&ConsoleCommandHandler::showUsages, this)));
	_commands.emplace_back(cmdstruct("node", std::bind(&ConsoleCommandHandler::showNeighborNode, this)));
	_commands.emplace_back(cmdstruct("n", std::bind(&ConsoleCommandHandler::showNeighborNode, this)));
	_commands.emplace_back(cmdstruct("space", std::bind(&ConsoleCommandHandler::showHyperChainSpace, this)));
	_commands.emplace_back(cmdstruct("sp", std::bind(&ConsoleCommandHandler::showHyperChainSpace, this)));
	_commands.emplace_back(cmdstruct("spacemore", std::bind(&ConsoleCommandHandler::showHyperChainSpaceMore, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("spm", std::bind(&ConsoleCommandHandler::showHyperChainSpaceMore, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("local", std::bind(&ConsoleCommandHandler::showLocalData, this)));
	_commands.emplace_back(cmdstruct("l", std::bind(&ConsoleCommandHandler::showLocalData, this)));
	_commands.emplace_back(cmdstruct("down", std::bind(&ConsoleCommandHandler::downloadHyperBlock, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("d", std::bind(&ConsoleCommandHandler::downloadHyperBlock, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("search", std::bind(&ConsoleCommandHandler::searchLocalHyperBlock, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("se", std::bind(&ConsoleCommandHandler::searchLocalHyperBlock, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("i", std::bind(&ConsoleCommandHandler::showInnerDataStruct, this)));
	_commands.emplace_back(cmdstruct("ll", std::bind(&ConsoleCommandHandler::setLoggerLevel, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("llcss", std::bind(&ConsoleCommandHandler::setConsensusLoggerLevel, this, std::placeholders::_1)));
	_commands.emplace_back(cmdstruct("exit", std::bind(&ConsoleCommandHandler::exit, this)));
	_commands.emplace_back(cmdstruct("quit", std::bind(&ConsoleCommandHandler::exit, this)));
	_commands.emplace_back(cmdstruct("q", std::bind(&ConsoleCommandHandler::exit, this)));
	
}

ConsoleCommandHandler::~ConsoleCommandHandler()
{

}

void ConsoleCommandHandler::showUsages()
{
	cout << "These are common commands used in various situations:" << endl << endl;
	cout << "   help(?):			show all available commands" << endl;
	cout << "   node(n):			show neighbor node information" << endl;
	cout << "   space(sp):			show HyperChain-Space information" << endl;
	cout << "   spacemore(spm):		show a specified hyper block from HyperChain-Space more information" << endl;
	cout << "						spm  'HyperBlockID'" << endl;
	cout << "   local(l):			show local data information" << endl;
	cout << "   down(d):			download a specified hyper block from HyperChain-Space to local" << endl;
	cout << "						d 'HyperBlockID' 'NodeID' "<< endl;
	cout << "   search(se):			search detail information for a specified hyper block number" << endl;	
	cout << "						se 'HyperBlockID'" << endl;
	cout << "   inner(i):			show inner information" << endl;
	cout << "   loggerlevel(ll):		set logger level(trace=0,debug=1,info=2,warn=3,err=4,critical=5,off=6)" << endl;
	cout << "   consensusloggerlevel(llcss):	set consensus logger level(trace=0,debug=1,info=2,warn=3,err=4,critical=5,off=6)" << endl;
	cout << "   exit(quit/q):		exit the program" << endl;
}

void ConsoleCommandHandler::exit()
{
	cout << "Are you sure you want to exit(y/n)?";
	string sInput;
	cin >> sInput;
	if (sInput == "y" || sInput == "Y") {
		_isRunning = false;
	}
	cin.ignore((numeric_limits<std::streamsize>::max)(), '\n');
}

void ConsoleCommandHandler::handleCommand(const string &command)
{
	string cmdWord = command;
	size_t pos = command.find_first_of(' ');
	if (pos != std::string::npos) {
		cmdWord = command.substr(0, pos);
	}

	auto it = std::find_if(_commands.begin(), _commands.end(), [&cmdWord](cmdstruct &cmd)->bool {
		if (cmdWord == cmd.key) {
			return true;
		}

		return false;
	});

	list<string> commlist;
	stringTostringlist(command, commlist);

	if (it != _commands.end()) {
		it->func(commlist);
	}
}

void ConsoleCommandHandler::run() {
	cout << "Copyright 2016-2019 hyperchain.net (Hyperchain)." << endl;
	cout << "Input help for detail usages" << endl;

	string command;
	while (_isRunning) {
		showPrompt();

		getline(cin, command);
		handleCommand(command);
	}
}



void ConsoleCommandHandler::showNeighborNode()
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	cout << nodemgr->toString();
}

void ConsoleCommandHandler::showHyperChainSpace()
{
	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();

	map<string, string> HyperChainSpace;
	HSpce->GetHyperChainShow(HyperChainSpace);
	
	if (HyperChainSpace.size() <= 0)
	{
		cout << "HyperChainSpace is empty..." << endl;
		return;

	}

	cout << "HyperChainSpace:" << endl;
	for (auto mdata : HyperChainSpace)
	{
		cout << "NodeID = " << mdata.first << ",HyperIDs = " << mdata.second << endl;
	}

}

void ConsoleCommandHandler::showHyperChainSpaceMore(const list<string> &commlist)
{
	size_t s = commlist.size();
	if (s <= 1)
	{
		cout << "Please specify the block number." << endl;
		return;
	}

	try
	{
		auto iterCurrPos = commlist.begin();
		std::advance(iterCurrPos, 1);
		if (iterCurrPos != commlist.end())
		{
			uint64 nblocknum = std::stol(*iterCurrPos);

			CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();
			MULTI_MAP_HPSPACEDATA HyperChainSpace;
			HSpce->GetHyperChainData(HyperChainSpace);

			if (HyperChainSpace.size() <= 0)
			{
				cout << "HyperChainSpace is empty." << endl;
				return;
			}

			for (auto mdata : HyperChainSpace)
			{
				if (mdata.first != nblocknum)
					continue;

				for (auto sid : mdata.second)
					cout << "HyperChainSpace: HyperID = " << nblocknum << ",NodeID = " << sid.first << endl;
				break;
			}
		}

	}
	catch (std::exception &e)
	{
		cout << e.what() << endl;
	}
	
}

void ConsoleCommandHandler::showLocalData()
{
	string Ldata;
	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();
	vector<string> LocalChainSpace;
	HSpce->GetLocalChainShow(LocalChainSpace);

	if (LocalChainSpace.size() <= 0)
	{
		cout << "Local HyperData is empty." << endl;
		return;
	}

	for (auto t : LocalChainSpace)
	{
		Ldata += t;
		Ldata += ";";
	}

	cout << "LocalHyperData : HyperID = " << Ldata << endl;

}

void ConsoleCommandHandler::downloadHyperBlock(const list<string> &commlist)
{
	size_t s = commlist.size();
	if (s < 3)
	{
		cout << "Please specify the block number." << endl;
		cout << "Please specify the node id." << endl;
		return;
	}

	try
	{
		auto iterCurrPos = commlist.begin();
		std::advance(iterCurrPos, 1);
		if (iterCurrPos != commlist.end())
		{
			uint64 nblocknum = std::stol(*iterCurrPos);			
			std::advance(iterCurrPos, 1);
			if (iterCurrPos != commlist.end())
			{
				string strnodeid = *iterCurrPos;


				CHyperData * hd = Singleton<CHyperData>::instance();
				hd->PullHyperDataByHID(nblocknum, strnodeid);
			
			}

		}
	}
	catch (std::exception &e)
	{
		cout << e.what() << endl;
	}
}

void ConsoleCommandHandler::searchLocalHyperBlock(const list<string> &commlist)
{
	size_t s = commlist.size();
	if (s <= 1) {
		cout << "Please specify the block number." << endl;
		return;
	}
	std::list<T_HYPERBLOCKDBINFO> listblock;

	try {
		auto iterCurrPos = commlist.begin();
		std::advance(iterCurrPos, 1);

		uint64 nblocknum = std::stol(*iterCurrPos);
		queryBlock(nblocknum, listblock);

		T_SHA256 tmphash;
		bool isshowedhyperblock = false;
		for(auto h : listblock) {

			if (!isshowedhyperblock) {
				cout << "Hyper Block Id:" << h.GetReferHyperBlockId() << endl;
				cout << "Hyper Block Hash: " << DBmgr::instance()->hash256tostring(h.strHyperBlockHash) << endl;		
				cout << endl;
				isshowedhyperblock = true;
			}

			cout << "Block Id:     " << h.GetBlockId() << endl;
			cout << "Chain number: " << h.GetLocalChainId() << endl;
			time_t t = h.GetBlockTimeStamp();
			char strstamp[32] = { 0 };
			strftime(strstamp, 32, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
			cout << "Time:         " << strstamp << endl;
			cout << "Version:      " << h.GetVersion() << endl;
			cout << "Hash:         " << DBmgr::instance()->hash256tostring(h.strHashSelf) << endl;
			cout << "PreHash:      " << DBmgr::instance()->hash256tostring(h.strPreHash) << endl;
			cout << "Payload:      " << h.GetPayload() << endl;
			cout << endl;
		}
	}
	catch (std::exception &e) {
		cout << e.what() << endl;
	}
}

void showTaskDetails()
{
	uint16 num = Singleton<TaskThreadPool>::getInstance()->getQueueSize();
	cout << "Task numbers in task pool:" << num << endl;
	cout << Singleton<TaskThreadPool>::getInstance()->getQueueDetails() << endl;
}

void ConsoleCommandHandler::showInnerDataStruct()
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	HCNodeSH me = nodemgr->myself();
	cout << "My nodeid:" << me->getNodeId<string>() << endl;

	showNeighborNode();
	cout << endl;
	showTaskDetails();

	ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
	switch (g_tP2pManagerStatus.GetCurrentConsensusPhase())
	{
	case CONSENSUS_PHASE::PREPARE_LOCALBUDDY_PHASE:
		cout << "Phase: Prepare to enter LOCALBUDDY_PHASE, "
			 << "Consensus condition : " << consensuseng->isAbleToConsensus();
		break;
	case CONSENSUS_PHASE::LOCALBUDDY_PHASE:
		cout << "Phase: LOCALBUDDY_PHASE" << endl;
		cout << "Request block number(listRecvLocalBuddyReq):" << g_tP2pManagerStatus.listRecvLocalBuddyReq.size() << endl;
		cout << "Respond block number(listRecvLocalBuddyRsp):" << g_tP2pManagerStatus.listRecvLocalBuddyRsp.size() << endl;
		cout << "Standby block chain number(listCurBuddyReq):" << g_tP2pManagerStatus.listCurBuddyReq.size() << endl;
		cout << "Standby block chain number(listCurBuddyRsp):" << g_tP2pManagerStatus.listCurBuddyRsp.size() << endl;
		break;
	case CONSENSUS_PHASE::GLOBALBUDDY_PHASE:
		cout << "Phase: GLOBALBUDDY_PHASE" << endl;
		break;
	case CONSENSUS_PHASE::PERSISTENCE_CHAINDATA_PHASE:
		cout << "Phase: PERSISTENCE_CHAINDATA_PHASE" << endl;
	}

	int i = 0;
	CAutoMutexLock muxAuto(g_tP2pManagerStatus.MuxlistLocalBuddyChainInfo);
	cout << "listLocalBuddyChainInfo Number:" << g_tP2pManagerStatus.listLocalBuddyChainInfo.size() << endl;
	for (auto &b : g_tP2pManagerStatus.listLocalBuddyChainInfo) {
		char content[32] = { 0 };
		memcpy(content, b.GetLocalBlock().GetPayLoad().GetPayLoad().data(),31);
		std::printf("listLocalBuddyChainInfo: %d %s\n", ++i, content);
	}
}

void ConsoleCommandHandler::setLoggerLevelHelp(std::shared_ptr<spdlog::logger> & logger,
										const list<string> &level)
{
	spdlog::level::level_enum lev = logger->level();;
	if (level.size() > 1) {
		auto pos = ++level.begin();
		int i = std::stoi(pos->c_str());
		lev = (spdlog::level::level_enum)i;
		lev = lev > spdlog::level::off ? spdlog::level::off : lev;
		logger->set_level(lev);
	}

	std::printf("%s level is %d (trace=0,debug=1,info=2,warn=3,err=4,critical=5,off=6)\n",
		logger->name().c_str(),
		logger->level());
}

void ConsoleCommandHandler::setLoggerLevel(const list<string> &level)
{
	setLoggerLevelHelp(g_console_logger, level);
	return;
	spdlog::level::level_enum lev = g_console_logger->level();;
	if (level.size() > 1) {
		auto pos = ++level.begin();
		int i = std::stoi(pos->c_str());
		lev = (spdlog::level::level_enum)i;
		lev = lev > spdlog::level::off ? spdlog::level::off : lev;
		g_console_logger->set_level(lev);
	}

	std::printf("Logger level is %d (trace=0,debug=1,info=2,warn=3,err=4,critical=5,off=6)\n",
		g_console_logger->level());
}

void ConsoleCommandHandler::setConsensusLoggerLevel(const list<string> &level)
{
	setLoggerLevelHelp(g_consensus_console_logger, level);
	return;
}