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

#include "../newLog.h"

#include "node/ITask.hpp"
#include "node/Singleton.h"
#include "HyperChainSpace.h"
#include "node/NodeManager.h"
//#include "consensus/buddyinfo.h"
//#include "headers/inter_public.h"
//#include "consensus/p2pprotocol.h"
//#include "headers/lambda.h"
//#include "../crypto/sha2.h"

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

//#include <iostream>
//using namespace std;

extern void putStream(boost::archive::binary_oarchive &oa, const vector<T_HYPERBLOCKHEADER>& hyperblockheader);

class NoBlockHeaderRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::NO_BLOCKHEADER_RSP> {
public:
    using ITask::ITask;
    NoBlockHeaderRspTask() {};
    ~NoBlockHeaderRspTask() {};

    void exec() override {};

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        uint64_t hid = stoull(msgbuf);
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->NoHyperBlockHeader(hid, _sentnodeid.ToHexString());
    }
};

class GetBlockHeaderRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_BLOCKHEADER_RSP> {
public:
    using ITask::ITask;
    GetBlockHeaderRspTask() {};
    GetBlockHeaderRspTask(CUInt128 nodeid, uint64 hid, uint16 range) : ITask(), m_startHid(hid), m_range(range) { _sentnodeid = nodeid; }
    ~GetBlockHeaderRspTask() {};

    void exec() override
    {
        vector<T_HYPERBLOCKHEADER> hyperBlockHeaderList;
        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        if (!sp->GetHyperBlockHeader(m_startHid, m_range, hyperBlockHeaderList)) {
            

            DataBuffer<NoBlockHeaderRspTask> msgbuf(std::move(to_string(m_startHid)));
            nodemgr->sendTo(_sentnodeid, msgbuf);
            g_daily_logger->info("GetBlockHeaderRspTask, I haven't hyper block header: [{}], sentnodeid: [{}]", m_startHid, _sentnodeid.ToHexString());
            return;
        }

        

        stringstream ssBuf;
        boost::archive::binary_oarchive oa(ssBuf, boost::archive::archive_flags::no_header);

        putStream(oa, hyperBlockHeaderList);
        DataBuffer<GetBlockHeaderRspTask> datamsg(std::move(ssBuf.str()));

        nodemgr->sendTo(_sentnodeid, datamsg);
    }

    void execRespond() override
    {
        string sBuf(_payload, _payloadlen);
        stringstream ssBuf(sBuf);
        boost::archive::binary_iarchive ia(ssBuf, boost::archive::archive_flags::no_header);

        vector<T_HYPERBLOCKHEADER> hyperBlockHeaderList;
        try {
            uint32 headernum;
            ia >> headernum;
            for (uint32 j = 0; j < headernum; j++) {
                T_HYPERBLOCKHEADER blockheader;
                ia >> blockheader;
                hyperBlockHeaderList.push_back(std::move(blockheader));
            }
        }
        catch (runtime_error& e) {
            g_consensus_console_logger->warn("{}", e.what());
            return;
        }

        CHyperChainSpace * sp = Singleton<CHyperChainSpace, string>::getInstance();
        sp->PutHyperBlockHeader(hyperBlockHeaderList, _sentnodeid.ToHexString());
    }

    uint64_t m_startHid;
    uint16_t m_range;
};

class GetBlockHeaderReqTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::GET_BLOCKHEADER_REQ> {
public:
    using ITask::ITask;
    GetBlockHeaderReqTask(uint64 startHid, uint16 range, string nodeid) : m_startHid(startHid), m_range(range), m_nodeid(nodeid) {};
    ~GetBlockHeaderReqTask() {};

    void exec() override
    {
        string datamsg = to_string(m_startHid) + ":" + to_string(m_range);
        DataBuffer<GetBlockHeaderReqTask> msgbuf(std::move(datamsg));

        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        nodemgr->sendTo(CUInt128(m_nodeid), msgbuf);
    }

    void execRespond() override
    {
        string msgbuf(_payload, _payloadlen);
        string::size_type ns = msgbuf.find(":");
        if ((ns == string::npos) || (ns == 0)) {
            

            return;
        }

        uint64_t hid = stoull(msgbuf.substr(0, ns));
        uint16_t range = stoul(msgbuf.substr(ns + 1, msgbuf.length() - 1));

        GetBlockHeaderRspTask tsk(_sentnodeid, hid, range);
        tsk.exec();
    }

    uint64_t m_startHid;
    uint16_t m_range;
    string m_nodeid;
};
