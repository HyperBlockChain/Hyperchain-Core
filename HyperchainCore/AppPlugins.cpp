//////////////////////////////////////////////////////////////////////////
//
#ifdef WIN32
#include <WinSock2.h>
#include <windows.h>
#endif

#include "AppPlugins.h"
#include "consensus/consensus_engine.h"
#include "node/UdpRecvDataHandler.hpp"

#include <boost/filesystem.hpp>
#include <boost/dll/import.hpp>


MAPARGS mapHCArgs;
MAPMULTIARGS mapHCMultiArgs;

AppPlugins* g_appPlugin = nullptr;

void AppPlugins::Init()
{
    if (mapHCArgs.count("-with")) {
        for (string& strApp : mapHCMultiArgs["-with"]) {
            AddApplication(strApp);
        }
    }
}

void AppPlugins::AddApplication(const string& appname)
{
    boost::filesystem::path pathHC = boost::filesystem::system_complete(".");
    pathHC /= appname;
    if (_mapAppFunc.count(appname) == 0) {
        APPFUNC f;
        if (f.load(appname)) {
            _mapAppFunc[appname] = f;
        }
    }
}


void AppPlugins::StartApp(const string& appname)
{
    PluginContext context;
    context.nodemgr = Singleton<NodeManager>::getInstance();
    context.hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
    context.consensuseng = Singleton<ConsensusEngine>::getInstance();
    context.dbmgr = Singleton<DBmgr>::getInstance();
    context.tP2pManagerStatus = Singleton<T_P2PMANAGERSTATUS>::getInstance();
    context.inproc_context = g_inproc_context;

#ifdef WIN32
    context.daily_logger = g_daily_logger;
    context.basic_logger = g_basic_logger;
    context.rotating_logger = g_rotating_logger;
    context.console_logger = g_console_logger;
    context.consensus_console_logger = g_consensus_console_logger;
#endif


    UdpRecvDataHandler* handler = Singleton<UdpRecvDataHandler>::getInstance();

    if (!_mapAppFunc.count(appname)) {
        AddApplication(appname);
    }

    if (_mapAppFunc.count(appname)) {
        auto & f = _mapAppFunc[appname];

        

        int app_argc = _argc + f.appargv.size();
        std::shared_ptr<char*> app_argv(new char*[app_argc]);

        int i = 0;
        int j = 0;
        char ** p = app_argv.get();
        for (; i < _argc; i++) {
        

            if (string(_argv[i]).find("-with") == 0 ||
                string(_argv[i]).find("-seedserver") == 0 ||
                string(_argv[i]).find("-me") == 0 ) {
                continue;
            }
            p[j++] = _argv[i];
        }

        for (auto& v : f.appargv) {
            p[j++] = &v[0];
        }

        context.pc_argc = j;
        context.pc_argv = p;
        try {
            if (f.appIsStopped()) {
                if (f.appStart(&context)) {
                    f.appRegisterTask(handler);
                    std::cout << "Module " << appname << " is started" << endl;
                }
            }
            else {
                std::cout << "Module " << appname << " has already run" << endl;
            }
        }
        catch (boost::system::system_error& e) {
            std::printf("(%s) : %s %s \n", __FUNCTION__, appname.c_str(), e.what());
        }
        catch (std::system_error& e) {
            std::printf("(%s) : %s %s \n", __FUNCTION__, appname.c_str(), e.what());
        }
    }
}

void AppPlugins::StopApp(const string& appname, bool isErase)
{
    UdpRecvDataHandler* handler = Singleton<UdpRecvDataHandler>::getInstance();
    if (_mapAppFunc.count(appname)) {
        auto & f = _mapAppFunc[appname];
        if (!f.appIsStopped()) {
            f.appStop();
            std::cout << "Module " << appname << " is stopped" << endl;
        }
        else {
            std::cout << "Module " << appname << " has stopped" << endl;
        }
        f.appUnregisterTask(handler);
        

        if (isErase) {
            f.unload();
            _mapAppFunc.erase(appname);
        }
    }
    else {
        std::cout << "Module " << appname << " without running"<< endl;
    }
}

void AppPlugins::StartAllApp()
{
    for (auto& app : _mapAppFunc) {
        StartApp(app.first);
    }
}

void AppPlugins::StopAllApp()
{
    for (auto& app : _mapAppFunc) {
        StopApp(app.first, false);
    }
}

void AppPlugins::GetAllAppStatus(map<string, string>& mapappstatus)
{
    for (auto& app : _mapAppFunc) {
        if (!app.second.appIsStopped.empty()) {

            stringstream ss;
            ss << (app.second.appIsStopped() ? "stopped" : "running");
            ss << "    ";

            int nArgn = 0;
            string strArgv;
            app.second.appRunningArg(nArgn, strArgv);
            ss << strArgv;

            mapappstatus[app.first] = ss.str();
        }
        else {
            mapappstatus[app.first] = "unknown";
        }
    }
}

void AppPlugins::RegisterAllAppTasks(void* objFactory)
{
    for (auto& app : _mapAppFunc) {
        if (!app.second.appRegisterTask(objFactory)) {
            std::printf("Failed to register tasks for application %s \n", app.first.c_str());
        }
    }
}

