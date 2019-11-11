#pragma once

#include "plugins/PluginContext.h"
#include "node/ObjectFactory.hpp"

#include <boost/function.hpp>
#include <boost/dll/shared_library.hpp>
using namespace boost;

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
using namespace std;


using MAPARGS = std::map<std::string, std::string>;
using MAPMULTIARGS = std::map<std::string, std::vector<std::string>>;

extern MAPARGS mapHCArgs;
extern MAPMULTIARGS mapHCMultiArgs;

class AppPlugins
{
public:
    AppPlugins(int argc, char *argv[]) : _argc(argc), _argv(argv)
    {
        Init();
    }

    ~AppPlugins() {}

    void AddApplication(const string& appname);

    string GetGenesisBlock(const string& appname, string& payload)
    {
        bool isNeedUnloaded = false;
        if (!_mapAppFunc.count(appname)) {
            AddApplication(appname);
            isNeedUnloaded = true;
        }

        if (!_mapAppFunc.count(appname)) {
            return "";
        }

        auto& f = _mapAppFunc[appname];
        string hashmtroot = f.appGetGenesisBlock(payload);

        if (isNeedUnloaded) {
            StopApp(appname);
        }

        return hashmtroot;
    }

    template<class InputIt>
    void StartApp(const string& appname, InputIt first, InputIt last)
    {
        if (_mapAppFunc.count(appname)) {
            auto & f = _mapAppFunc[appname];
            if (f.appIsStopped()) {
                StopApp(appname);
            }
            else {
                std::cout << "Module " << appname << " has already run" << endl;
                return;
            }
        }

        if (!_mapAppFunc.count(appname)) {
            AddApplication(appname);
        }

        if (_mapAppFunc.count(appname)) {
            auto & f = _mapAppFunc[appname];

            while (first != last) {
                //
                if ((*first)[0] != '-') {
                    string param = *first;
                    param.insert(0, "-");
                    f.appargv.push_back(param);
                }
                else {
                    f.appargv.push_back(*first);
                }
               ++first;
            }

            StartApp(appname);
        }
    }

    void StartApp(const string& appname);
    void StopApp(const string& appname, bool isErase = true);
    void StartAllApp();
    void StopAllApp();
    void GetAllAppStatus(map<string, string>& mapappstatus);
    void RegisterAllAppTasks(objectFactory& objFactory);

    typedef struct _appfunc {

        std::list<string> appargv;
        boost::dll::shared_library applib;

        boost::function<void(string&)> appInfo;
        boost::function<void(int&,string&)> appRunningArg;
        boost::function<bool(PluginContext*)> appStart;
        boost::function<bool()> appIsStopped;
        boost::function<void()> appStop;
        boost::function<bool(void* objFa)> appRegisterTask;
        boost::function<void(void* objFa)> appUnregisterTask;
        boost::function<bool(int, string&)> appResolveHeight;
        boost::function<bool(const string&, string&)> appResolvePayload;
        boost::function<bool(const string&, string&)> appTurnOnOffDebugOutput;
        boost::function<string(string& payload)> appGetGenesisBlock;

        bool load(const string& appname)
        {
            boost::filesystem::path pathHC = boost::filesystem::system_complete(".");
            pathHC /= appname;

            try {
                applib.load(pathHC, boost::dll::load_mode::append_decorations);
                appInfo = applib.get<void(string&)>("AppInfo");
                appRunningArg = applib.get<void(int&, string&)>("AppRunningArg");
                appIsStopped = applib.get<bool()>("IsStopped");

                appStart = applib.get<bool(PluginContext *)>("StartApplication");
                appStop = applib.get<void()>("StopApplication");
                appRegisterTask = applib.get<bool(void*)>("RegisterTask");
                appUnregisterTask = applib.get<void(void*)>("UnregisterTask");
                appResolveHeight = applib.get<bool(int, string&)>("ResolveHeight");
                appResolvePayload = applib.get<bool(const string&, string&)>("ResolvePayload");
                appTurnOnOffDebugOutput = applib.get<bool(const string&, string&)>("TurnOnOffDebugOutput");
                appGetGenesisBlock = applib.get<string(string & payload)>("GetGenesisBlock");
                return true;
            }
            catch (boost::system::system_error& e) {
                std::fprintf(stderr, "(%s) : %s %s \n", __FUNCTION__, appname.c_str(), e.what());
            }
            return false;
        }

        void unload()
        {
            appInfo.clear();
            appRunningArg.clear();
            appStart.clear();
            appIsStopped.clear();
            appStop.clear();
            appRegisterTask.clear();
            appUnregisterTask.clear();
            appResolveHeight.clear();
            appTurnOnOffDebugOutput.clear();
            appGetGenesisBlock.clear();
            applib.unload();
        }
    } APPFUNC;

    APPFUNC* operator [](const string& appname) {
        if (_mapAppFunc.count(appname)) {
            return &(_mapAppFunc[appname]);
        }
        return nullptr;
    }

    typedef unordered_map<string, APPFUNC>::iterator iterator;
    typedef unordered_map<string, APPFUNC>::const_iterator const_iterator;
    iterator begin() { return _mapAppFunc.begin(); }
    iterator end() { return _mapAppFunc.end(); }
    const_iterator begin() const { return _mapAppFunc.begin(); }
    const_iterator end() const { return _mapAppFunc.end(); }

private:

    void Init();

private:
    int _argc;
    char** _argv;          //


    unordered_map<string, APPFUNC> _mapAppFunc;
};

extern AppPlugins* g_appPlugin;
