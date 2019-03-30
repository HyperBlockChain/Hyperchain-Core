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
#include <sys/wait.h>

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

#ifdef WIN32
#include <client/windows/handler/exception_handler.h>
#else
#include <client/linux/handler/exception_handler.h>
#endif

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

void testhyperchaindata(string nodeid)
{
	CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();
	CHyperData * HData = Singleton<CHyperData>::instance();
	if (!HSpce || !HData)
		return;


	MULTI_MAP_HPSPACEDATA hyperdata;
	hyperdata.clear();
	uint64 num = 0;
	cout << "等待获取链空间.............." << endl;
	HSpce->PullDataFromChainSpace();
	while (num == 0) {		
		SLEEP(5000);
		HSpce->GetHyperChainData(hyperdata);
		num = hyperdata.size();

	}
	

	for (auto mdata : hyperdata) {
		for (auto sid : mdata.second) {
			cout << "获得链空间HyperID = " << mdata.first << "对应nodeid = " << sid.first << endl;
		}
	}

	uint64 nhyperid = 0;
	string strnodeid = "";
	cout << "输入需要获取的超块号ID: ";
	cin >> nhyperid;
	vector<string> vnode;
	MAP_NODE nodemap = hyperdata[nhyperid];
	for (auto n : nodemap) {
		vnode.push_back(n.first);
	}

	while (vnode.size() == 0) {
		cout << "链空间无此ID，重新输入需要获取的超块号ID: ";
		cin >> nhyperid;
		vnode.clear();
		for (auto n : nodemap)
		{
			vnode.push_back(n.first);
		}
	}

	int i = 0;
	cout << "此超块存在于链空间的以下节点中" << endl;

	for (auto nid : vnode) {
		cout << "节点[" << i << "]的nodeid = " << nid << endl;
		i++;
	}

	cout << "选择下载节点,输入数字即可" << endl;
	int nindex = 0;
	cin >> nindex;
	strnodeid = vnode[nindex];

	HData->PullHyperDataByHID(nhyperid, strnodeid);
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
		cout << "Exception occurs in "<< __FUNCTION__ << ": " << e.what() << endl;
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
		spdlog::set_level(spdlog::level::err); 
		spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
		g_daily_logger = spdlog::daily_logger_mt("daily_logger", dlog.c_str(), 0, 30);
		g_basic_logger = spdlog::basic_logger_mt("file_logger", flog.c_str());
		g_rotating_logger = spdlog::rotating_logger_mt("rotating_logger", rlog.c_str(), 1048576 * 100, 3);
		g_console_logger = spdlog::stdout_color_mt("console");
		g_console_logger->set_level(spdlog::level::err);
		g_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

		g_consensus_console_logger = spdlog::stdout_color_mt("consensus");
		g_consensus_console_logger->set_level(spdlog::level::info);
		g_consensus_console_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

		spdlog::flush_every(std::chrono::seconds(3));

	}

	~hclogger()
	{
		spdlog::shutdown();
	}
};

bool g_isSeedServer = true;
char **g_argv;

void stopAll()
{
	ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
	if (consensuseng) {
		cout << "Stopping Consensuseng..." << endl;
		consensuseng->stop();
	}
	CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
	if (hyperchainspace) {
		cout << "Stopping Hyperchain space..." << endl;
		hyperchainspace->stop();
	}
	auto pool = Singleton<TaskThreadPool>::getInstance();
	if (pool) {
		cout << "Stopping TaskThreadPool..." << endl;
		pool->stop();
	}
	UdpThreadPool *udpthreadpool = Singleton<UdpThreadPool, const char*, uint32_t>::getInstance();
	if (udpthreadpool) {
		cout << "Stopping UDP..." << endl;
		udpthreadpool->stop();
	}

	if (!g_isSeedServer) {
		cout << "Stopping Rest Server..." << endl;
		RestApi::stopRest();
	}
	if (DBmgr::instance()->isOpen()) {
		cout << "Closing Database..." << endl;
		DBmgr::instance()->close();
	}
}

#ifdef WIN32
bool dumpCallback(const wchar_t* dump_path,
	const wchar_t* minidump_id,
	void* context,
	EXCEPTION_POINTERS* exinfo,
	MDRawAssertionInfo* assertion,
	bool succeeded)
{
	cout << "Exception occurs:" << (char*)context << endl;
	stopAll();
	cout << "Rebooting..." << endl;

	std::system((char*)context);
	this_thread::sleep_for(chrono::milliseconds(1000));
	return succeeded;
}
#else

bool dumpCallback(const google_breakpad::MinidumpDescriptor& descriptor, void* context, bool succeeded)
{
	int ret;

	cout << "Exception occurs:" << g_argv[0] << endl;
	stopAll();
	cout << "Rebooting..." << endl;
	while (1) {
		pid_t pid = fork();
		if (pid == -1) {
			fprintf(stderr, "fork() error.errno:%d error:%s\n", errno, strerror(errno));
			break;
		}
		if (pid == 0) {
			ret = execv(g_argv[0], g_argv);
			if (ret < 0) {
				fprintf(stderr, "execv ret:%d errno:%d error:%s\n", ret, errno, strerror(errno));
				continue;
			}
			break;
		}

		if (pid > 0) {
			fprintf(stdout, "Parent process enter waiting status\n");

			int status;
			pid_t childpid = wait(&status);
			fprintf(stdout, "Created a child process %d\n", childpid);
			if (WIFEXITED(status)) {			
				fprintf(stdout, "Child process exited with code %d\n", WEXITSTATUS(status));
				break;
			}
			else if (WIFSIGNALED(status)) {		
				fprintf(stdout, "Child process terminated by signal %d\n", WTERMSIG(status));
			}
			else if (WIFSTOPPED(status)) {		
				fprintf(stdout, "%d signal case child stopped\n", WSTOPSIG(status));
			}
			else if (WIFCONTINUED(status)) {	
				fprintf(stdout, "Child was resumed by SIGCONT\n");
			}
			cout << "Rebooted" << endl;
		}
	}
	return succeeded;
}

#endif

string getMyCommandLine(int argc, char *argv[])
{
	string commandline;
	for (int i=0; i < argc; ++i) {
		commandline += argv[i];
		commandline += " ";
	}
	return commandline;
}

static bool foreground = true;
static google_breakpad::ExceptionHandler* exceptionhandler = nullptr;

int main(int argc, char *argv[])
{
	std::string command = "command line options";
	options_description desc(command);

	desc.add_options()
		("help,h", "print help message")
		("version,v", "print version message")
		("runasss", value<int>(), "run as a seed server")
		("bg", "run as a background server,only for *nux")
		("me,m", value < std::string >(), "specify myself,for example:10.0.0.1:8116,cannot use with runasss")
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

	if (vm.count("bg")) {
		foreground = false;
	}

	g_argv = argv;

#ifdef WIN32
	string commandline = getMyCommandLine(argc, argv);
	exceptionhandler = new google_breakpad::ExceptionHandler( L"./",
		nullptr,
		dumpCallback,
		(char*)commandline.c_str(),
		google_breakpad::ExceptionHandler::HANDLER_ALL);
#else
	
	umask(0);
	while (!foreground) {
		pid_t pid = fork();
		if (pid == -1) {
			fprintf(stderr, "fork() error.errno:%d error:%s\n", errno, strerror(errno));
			exit(-1);
		}	
		if (pid > 0) {
			fprintf(stdout, "parent process exit");
			exit(0);
		}
		setsid();
		close(0);
		close(1);
		close(2);
		signal(SIGCHLD, SIG_IGN);
		break;
	}

	google_breakpad::MinidumpDescriptor descriptor("./"); 
	exceptionhandler = new google_breakpad::ExceptionHandler(descriptor, 
		nullptr, dumpCallback, nullptr, true, -1);
#endif

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
	UdpThreadPool *udpthreadpool = Singleton<UdpThreadPool, const char*, uint32_t>::instance("", udpport);
	udpthreadpool->start();
	
	SeedCommunication seedcomm;
	g_isSeedServer = true;
	if (vm.count("runasss") == 0) {
		seedcomm.start();
		g_isSeedServer = false;
	}
	
	hyperchainspace->start();
	if (!g_isSeedServer) {

		RestApi::startRest();

		ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::instance();
		if (!g_isSeedServer) {
			consensuseng->start();
		}
	}

	ConsoleCommandHandler console;
	console.run();

	stopAll();

	return 0;
}
