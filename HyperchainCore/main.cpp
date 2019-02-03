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

#include "newLog.h"
#include "config.h"

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#include <direct.h>
#pragma comment(lib, "shell32.lib")
#else
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <signal.h>
#include <string.h>
#include <execinfo.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#endif

#include <iostream>
#include <sstream>

#include "db/RestApi.h"
#include "db/dbmgr.h"

#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/TaskThreadPool.h"
#include "node/UdpAccessPoint.hpp"
#include "node/UdpRecvDataHandler.hpp"
#include "node/seedcommu.hpp"

#include "HyperChain/HyperChainSpace.h"
#include "HyperChain/HyperData.h"
#include "HyperChain/PullChainSpaceTask.hpp"
#include "HyperChain/PullHyperDataTask.hpp"

#include "consolecommandhandler.h"
#include "consensus/consensus_engine.h"

#include <boost/program_options.hpp>
using namespace boost::program_options;


void Restore()
{
#ifdef WIN32

#else
	signal(SIGSEGV, SIG_DFL);
	signal(SIGILL, SIG_DFL);
	signal(SIGFPE, SIG_DFL);
	signal(SIGABRT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGKILL, SIG_DFL);
	signal(SIGXFSZ, SIG_DFL);
#endif
}

void saveBackTrace(int sig)
{
#ifdef WIN32

#else
	time_t tSetTime;
	time(&tSetTime);
	struct tm* ptm = localtime(&tSetTime);
	char fname[256] = { 0 };
	sprintf(fname, "core.%d-%d-%d_%d_%d_%d",
		ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	FILE* f = fopen(fname, "a");
	if (f == NULL) {
		return;
	}
	int fd = fileno(f);

	//lock the file
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_pid = getpid();
	fcntl(fd, F_SETLKW, &fl);

	char buffer[4096];
	memset(buffer, 0, sizeof(buffer));
	int count = readlink("/proc/self/exe", buffer, sizeof(buffer));
	if (count > 0) {
		buffer[count] = '\n';
		buffer[count + 1] = 0;
		fwrite(buffer, 1, count + 1, f);
	}

	memset(buffer, 0, sizeof(buffer));
	sprintf(buffer, "Dump Time: %d-%d-%d %d:%d:%d\n",
		ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
	fwrite(buffer, 1, strlen(buffer), f);

	sprintf(buffer, "Curr thread: %u, Catch signal:%d\n", (int)pthread_self(), sig);
	fwrite(buffer, 1, strlen(buffer), f);

	void* DumpArray[256];
	int nSize = backtrace(DumpArray, 256);
	sprintf(buffer, "backtrace rank = %d\n", nSize);
	fwrite(buffer, 1, strlen(buffer), f);
	if (nSize > 0) {
		char** symbols = backtrace_symbols(DumpArray, nSize);
		if (symbols != NULL) {
			for (int i = 0; i < nSize; i++) {
				fwrite(symbols[i], 1, strlen(symbols[i]), f);
				fwrite("\n", 1, 1, f);
			}
			free(symbols);
		}
	}

	//unlock file and close
	fl.l_type = F_UNLCK;
	fcntl(fd, F_SETLK, &fl);
	fclose(f);
	//exit(1);
	Restore();

#endif
}

void Crashdump()
{
#ifdef WIN32

#else
	signal(SIGSEGV, saveBackTrace);
	signal(SIGILL, saveBackTrace);
	signal(SIGFPE, saveBackTrace);
	signal(SIGABRT, saveBackTrace);
	signal(SIGTERM, saveBackTrace);
	signal(SIGKILL, saveBackTrace);
	signal(SIGXFSZ, saveBackTrace);
#endif

}

static std::string make_log_path() 
{
	std::string log_path;
#ifdef WIN32
	CHAR my_documents[MAX_PATH];
	HRESULT result = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, my_documents);
	if (result != S_OK) {
		std::cout << "Error: " << result << endl;
		return NULL;
	}

	log_path = my_documents;
	log_path += "\\hyperchain";
	if ((_access(log_path.c_str(), F_OK)) == -1)
		_mkdir(log_path.c_str());
	log_path += "\\hyperchain_logs";
	if ((_access(log_path.c_str(), F_OK)) == -1)
		_mkdir(log_path.c_str());
#else
	char *path = getenv("HOME");
	log_path = path;
	log_path += "/Documents";
	if ((access(log_path.c_str(), F_OK)) == -1)
		mkdir(log_path.c_str(), 0755);
	log_path += "/hyperchain";
	if ((access(log_path.c_str(), F_OK)) == -1)
		mkdir(log_path.c_str(), 0755);
	log_path += "/hyperchain_logs";
	if ((access(log_path.c_str(), F_OK)) == -1)
		mkdir(log_path.c_str(), 0755);
#endif
	return log_path.c_str();
}

static std::string make_db_path()
{
	std::string db_path;
#ifdef WIN32
	CHAR my_documents[MAX_PATH];
	HRESULT result = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, my_documents);
	if (result != S_OK)
	{
		std::cout << "Error: " << result << endl;
		return NULL;
	}

	db_path = my_documents;
	db_path += "\\hyperchain";
	if ((_access(db_path.c_str(), F_OK)) == -1)
		_mkdir(db_path.c_str());
	db_path += "\\hp";
	if ((_access(db_path.c_str(), F_OK)) == -1)
		_mkdir(db_path.c_str());
#else
	char *path = getenv("HOME");
	db_path = path;
	db_path += "/Documents";
	if ((access(db_path.c_str(), F_OK)) == -1)
		mkdir(db_path.c_str(), 0755);
	db_path += "/hyperchain";
	if ((access(db_path.c_str(), F_OK)) == -1)
		mkdir(db_path.c_str(), 0755);
	db_path += "/hp";
	if ((access(db_path.c_str(), F_OK)) == -1)
		mkdir(db_path.c_str(), 0755);
#endif
	return db_path.c_str();
}



void makeSeedServer(const string & seedserver)
{
	string nodeid("1234567879012345678901234567890ab", CUInt128::value * 2);
	HCNodeSH seed = make_shared<HCNode>(std::move(CUInt128(nodeid)));

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

	seed->addAP(make_shared<UdpAccessPoint>(server, port));

	NodeManager *nodemgr = Singleton<NodeManager>::instance();
	nodemgr->seedServer(seed);
}

void initNode(const variables_map &vm, string &udpip, int &udpport)
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	nodemgr->loadMyself();

	string mynodeid;
	HCNodeSH me = nodemgr->myself();
	try
	{
		if (!me->isValid()) {
			cout << "The machine is a new node, generating nodeid..." << endl;
			string str = HCNode::generateNodeId();
			mynodeid = str;
			HCNodeSH tmp = make_shared<HCNode>(CUInt128(str));
			nodemgr->myself(tmp);
			me = nodemgr->myself();

			nodemgr->saveMyself();
		}
		else {
			mynodeid = me->getNodeId<string>();
		}
	}
	catch (std::exception &e) {
		cout << e.what();
		exit(-1);
	}

	if (vm.count("me")) {
		string strMe = vm["me"].as<string>();
		cout << "My IP and port is " << strMe << endl;

		size_t found = strMe.find_first_of(':');
		if (found == std::string::npos) {
			udpip = strMe;
		}
		else {
			udpip = strMe.substr(0, found);
			udpport = std::stoi(strMe.substr(found + 1));
		}

		me->removeAPs();
		me->addAP(std::make_shared<UdpAccessPoint>(udpip, udpport));
	}

	nodemgr->myself(me);
	nodemgr->saveMyself();
}

class hclogger
{
public:
	hclogger()
	{
		std::string logpath = make_log_path();
		std::string dlog = logpath + "/hyperchain.log";
		std::string flog = logpath + "/hyperchain_basic.log";
		std::string rlog = logpath + "/hyperchain_rotating.log";
		spdlog::set_level(spdlog::level::err); // Set specific logger's log level
		spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
		g_daily_logger = spdlog::daily_logger_mt("daily_logger", dlog.c_str(), 0, 30);
		g_basic_logger = spdlog::basic_logger_mt("file_logger", flog.c_str());
		// Create a file rotating logger with 100M size max and 3 rotated files.
		g_rotating_logger = spdlog::rotating_logger_mt("rotating_logger", rlog.c_str(), 1048576 * 100, 3);
		g_console_logger = spdlog::stdout_color_mt("console");
		g_console_logger->set_level(spdlog::level::err);
		g_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

		g_consensus_console_logger = spdlog::stdout_color_mt("consensus");
		g_consensus_console_logger->set_level(spdlog::level::err);
		g_consensus_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

		spdlog::flush_every(std::chrono::seconds(3));

	}

	~hclogger()
	{
		spdlog::shutdown();
	}
};

int main(int argc, char *argv[])
{
	Crashdump();

	std::string command = "command line options";
	options_description desc(command);

	desc.add_options()
		("help,h", "print help message")
		("version,v", "print version message")
		("runasss", value<int>(), "run as a seed server")
		("me,m", value < std::string > (), "specify myself,for example:10.0.0.1:8116,cannot use with runasss")
		("seedserver", value<std::string>(), "specify a seed server,for example:127.0.0.1:8116");

	variables_map vm;

	store(parse_command_line(argc, argv, desc), vm);
	notify(vm);

	if (vm.count("help")) {
		cout << desc << endl;
		return 0;
	}

	if (vm.count("version")) {
		cout << VERSION_STRING << endl;
		return 0;
	}

	string udpip;
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

	hclogger log;

	std::string dbpath = make_db_path();
	dbpath += "/hyperchain.db";
	DBmgr::instance()->open(dbpath.c_str());

	Singleton<CHyperData>::instance();
	Singleton<TaskThreadPool>::instance();
	NodeManager *nodemgr = Singleton<NodeManager>::instance();

	initNode(vm, udpip, udpport);
	nodemgr->loadNeighbourNodes();

	HCNodeSH me = nodemgr->myself();
	string mynodeid = me->getNodeId<string>();
	CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::instance(mynodeid);

	Singleton<UdpRecvDataHandler>::instance();
	UdpThreadPool *udpthreadpool = Singleton<UdpThreadPool, const char*, uint32_t>::instance(/*udpip.c_str()*/"", udpport);
	udpthreadpool->start();
	
	SeedCommunication seedcomm;
	bool isSeedServer = true;
	if (vm.count("runasss") == 0) {
		seedcomm.start();
		isSeedServer = false;
	}
	
	hyperchainspace->start();
	if (!isSeedServer) {

		RestApi::startRest();

		ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::instance();
		if (!isSeedServer) {
			consensuseng->start();
		}
	}

	ConsoleCommandHandler console;
	console.run();

	if (!isSeedServer) {
		RestApi::stopRest();
	}

	return 0;
}
