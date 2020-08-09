/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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
#pragma once
#include <iostream>
using namespace std;

#include "node/ITask.hpp"
#include "HyperChain/HyperChainSpace.h"
#include "consensus/buddyinfo.h"
#include "node/NodeManager.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

class ApplicationChainRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::APP_CHAIN_RSP> {
public:
    using ITask::ITask;

    ApplicationChainRspTask(const CUInt128 &peerid,
        const T_LOCALBLOCKADDRESS& sAddr,
        const T_LOCALBLOCKADDRESS& eAddr,
        const T_APPTYPE& app) : _peerid(peerid), _sAddr(sAddr), _eAddr(eAddr), _app(app) {}

    ~ApplicationChainRspTask() {};

    void exec() override
    {
        //vector<string> vpath;
        //CBRET ret = g_tP2pManagerStatus->appCallback<cbindex::GETVPATHIDX>(_app, _sAddr, _eAddr, vpath);
        //if (ret == CBRET::REGISTERED_TRUE) {
        //    stringstream ssBuf;
        //    boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        //    try {
        //        uint32 vpathnum = static_cast<uint32>(vpath.size());
        //        oa << vpathnum;
        //        oa << boost::serialization::make_array(vpath.data(), vpathnum);
        //    }
        //    catch (runtime_error& e) {
        //        g_console_logger->warn("{} : {}", __FUNCTION__, e.what());
        //        return;
        //    }

        //    DataBuffer<ApplicationChainRspTask> msgbuf(std::move(ssBuf.str()));

        //    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        //    nodemgr->sendTo(_peerid, msgbuf);
        //}
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);

        vector<string> vpath;
        stringstream ssBuf(std::move(sBuf));
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
        CHyperChainSpace *hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
        try {
            uint32 vpathnum;
            ia >> vpathnum;
            vpath.resize(vpathnum);
            ia >> boost::serialization::make_array(vpath.data(), vpathnum);

            for (auto v : vpath) {
                //TODO: the best method is to get local block according to address.
                T_LOCALBLOCKADDRESS addr;
                addr.fromstring(v);
                hyperchainspace->GetRemoteHyperBlockByID(addr.hid);
            }
        }
        catch (runtime_error& e) {
            g_console_logger->warn("{} : {}", __FUNCTION__, e.what());
            return;
        }
    }

private:
    CUInt128 _peerid;
    T_LOCALBLOCKADDRESS _sAddr;
    T_LOCALBLOCKADDRESS _eAddr;
    T_APPTYPE _app;
};

class ApplicationChainTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::APP_CHAIN> {
public:
    using ITask::ITask;

    ApplicationChainTask(const T_LOCALBLOCKADDRESS& sAddr, const T_LOCALBLOCKADDRESS& eAddr, const T_APPTYPE& app) :
        _sAddr(sAddr), _eAddr(eAddr), _app(app) {}

    ~ApplicationChainTask() {};

    void exec() override
    {
        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);
        try {
            oa << _sAddr;
            oa << _eAddr;
            oa << _app;
        }
        catch (runtime_error& e) {
            g_console_logger->warn("{} : {}", __FUNCTION__, e.what());
            return;
        }

        DataBuffer<ApplicationChainTask> msgbuf(std::move(ssBuf.str()));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        nodemgr->sendToAllNodes(msgbuf);
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);

        stringstream ssBuf(std::move(sBuf));
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);
        try {
            ia >> _sAddr;
            ia >> _eAddr;
            ia >> _app;
        }
        catch (runtime_error& e) {
            g_console_logger->warn("{} : {}", __FUNCTION__, e.what());
            return;
        }

        ApplicationChainRspTask tsk(_sentnodeid, _sAddr, _eAddr, _app);
        tsk.exec();
    }

private:
    T_LOCALBLOCKADDRESS _sAddr;
    T_LOCALBLOCKADDRESS _eAddr;
    T_APPTYPE _app;
};


