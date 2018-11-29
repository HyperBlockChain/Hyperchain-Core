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

#include <boost/algorithm/string.hpp>
#include <map>
#include <set>
#include <QList>
#include "consolecommandhandler.h"


#include "headers/inter_public.h"
#include "headers/commonstruct.h"
#include "db/dbmgr.h"
#include "node/Singleton.h"
#include "HyperChain/HyperChainSpace.h"
#include "HyperChain/HyperData.h"


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


void queryBlock(uint64 nblocknum, QList<T_HYPERBLOCKDBINFO> &listblock)
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

	_commands.push_back(cmdstruct("help", std::bind(&ConsoleCommandHandler::showUsages, this)));
	_commands.push_back(cmdstruct("?", std::bind(&ConsoleCommandHandler::showUsages, this)));
	_commands.push_back(cmdstruct("exit", std::bind(&ConsoleCommandHandler::exit, this)));
	_commands.push_back(cmdstruct("quit", std::bind(&ConsoleCommandHandler::exit, this)));
	_commands.push_back(cmdstruct("q", std::bind(&ConsoleCommandHandler::exit, this)));


}
ConsoleCommandHandler::~ConsoleCommandHandler()
{

}

void ConsoleCommandHandler::showUsages()
{
	cout << "These are common commands used in various situations:" << endl << endl;
	cout << "   help(?):		show all available commands" << endl;

	cout << "   status(s):      show Hyperchain running status" << endl;

	cout << "   node(n):	    show neighbor node information" << endl;

	cout << "   space(sp):	    show HyperChain-Space information" << endl;
	cout << "   spacemore(spm):	show HyperChain-Space more information" << endl;


	cout << "   local(l):		show local data information" << endl;

	cout << "   down(d):        download a specified hyper block from HyperChain-Space to local" << endl;

	cout << "   search(se):   search detail information for a specified hyper block number" << endl;
	cout << "                 search hyperblocknumber" << endl;
	cout << "   exit(quit/q): exit the program" << endl;
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
	cout << "Copyright 2016-2018 hyperchain.net (Hyperchain)." << endl;
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

}

void ConsoleCommandHandler::showHyperChainSpace()
{
	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();
	map<uint64, set<string>> HyperChainSpace;
	HSpce->GetHyperChainData(HyperChainSpace);

	if (HyperChainSpace.size() <= 0)
	{
		cout << "HyperChainSpace is empty..." << endl;
		return;

	}


	for (auto mdata : HyperChainSpace)
	{
		cout << "HyperChainSpace: HyperID = " << mdata.first << ",Number of holders = " << mdata.second.size() << endl;

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
			map<uint64, set<string>> HyperChainSpace;
			HSpce->GetHyperChainData(HyperChainSpace);

			if (HyperChainSpace.size() <= 0)
			{
				cout << "HyperChainSpace is empty." << endl;
				return;

			}

			for (auto mdata : HyperChainSpace)
			{
				if (mdata.first == nblocknum)
				{
					for (auto sid : mdata.second)
					{
						cout << "HyperChainSpace: HyperID = " << nblocknum << ",NodeID = " << sid << endl;

					}
					break;

				}
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
	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();
	list<uint64> LoadHyperNoList;
	HSpce->GetLocalChainIDList(LoadHyperNoList);

	if (LoadHyperNoList.size() <= 0)
	{
		cout << "Local HyperData is empty." << endl;
		return;
	}

	for (auto Ldata : LoadHyperNoList)
	{
		cout << "LocalHyperData : HyperID = " << Ldata << endl;
	}


}

void ConsoleCommandHandler::downloadHyperBlock(const list<string> &commlist)
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
			std::advance(iterCurrPos, 2);
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
	string chainnum;
	string gentime;
	string localblocknum;
	string hash;
	string hhash;
	string version;
	QList<T_HYPERBLOCKDBINFO> listblock;
	char buf[BUFFERLEN] = { 0 };

	try {
		auto iterCurrPos = commlist.begin();
		std::advance(iterCurrPos, 1);

		uint64 nblocknum = std::stol(*iterCurrPos);
		queryBlock(nblocknum, listblock);

		T_SHA256 tmphash;
		bool isshowedhyperblock = false;
		foreach(T_HYPERBLOCKDBINFO h, listblock) {

			if (!isshowedhyperblock) {
				cout << "Hyper Block Id:" << h.GetReferHyperBlockId() << endl;
				memset(buf, 0, BUFFERLEN);

				T_SHA256 tmphash = h.GetHyperBlockHash();
				CCommonStruct::Hash256ToStr(buf, &tmphash);
				cout << "Hyper Block Hash: " << buf << endl;
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

			memset(buf, 0, BUFFERLEN);
			T_SHA256 tmphash = h.GetHashSelf();
			CCommonStruct::Hash256ToStr(buf, &tmphash);
			cout << "Hash:         " << buf << endl;

			memset(buf, 0, BUFFERLEN);
			T_SHA256 thash = h.GetPreHash();
			CCommonStruct::Hash256ToStr(buf, &thash);
			cout << "PreHash:      " << buf << endl;

			cout << "Payload:      " << h.GetPayload() << endl;
			cout << endl;
		}
	}
	catch (std::exception &e) {
		cout << e.what() << endl;
	}
}



