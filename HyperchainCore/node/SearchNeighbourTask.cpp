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

#include "../newLog.h"
#include "Singleton.h"
#include "NodeManager.h"
#include "TaskThreadPool.h"
#include "SearchNeighbourTask.h"
#include "../wnd/common.h"

#include <iostream>
#include <map>
#include <ratio>
#include <chrono>
using namespace std;
using std::chrono::system_clock;

#include <cpprest/json.h>
using namespace web;

#include "ITask.hpp"
namespace SEED {

    typedef struct tagnode
    {
        string _nodeinfo;
        system_clock::time_point _tp;
    public:
        tagnode() {}
        tagnode(string nodeinfo) : _nodeinfo(nodeinfo), _tp(system_clock::now()) {}
        bool isTimeOut() {
            using minutes = std::chrono::duration<double, ratio<60>>;
            system_clock::time_point curr = system_clock::now();

            minutes timespan = std::chrono::duration_cast<minutes>(curr - _tp);
            if (timespan.count() > 3) {
                //
                return true;
            }
            return false;
        }
    } NODE;

    std::map<string, NODE> g_mapNodes;
    std::mutex	_guard;

    int getPeerList(const string& nodeid, string& peerlist)
    {
        json::value obj = json::value::array();

        int i = 0;
        size_t maxlen = (64 - 1) * 1024;
        size_t len = 0;
        auto it = g_mapNodes.begin();
        for (; it != g_mapNodes.end();) {
            if (it->second.isTimeOut()) {
                g_mapNodes.erase(it++);
                continue;
            }
            if (it->first == nodeid) {
                ++it;
                continue;
            }

            if (len + it->second._nodeinfo.size() > maxlen) {
                break;
            }

            len += it->second._nodeinfo.size();
            obj[i] = json::value::parse(s2t(it->second._nodeinfo));
            ++i;
            ++it;
        }
        std::stringstream oss;
        obj.serialize(oss);
        peerlist = std::move(oss.str());

        return i;
    }
}
///////////////////////////////////////////
///////////////////////////////////////////
int g_nTaskID = 1; // µ˜ ‘”√
void AddIDToMsgBuf(int& nID, string& msgBuff)
{
    char szID[9];
    sprintf(szID, "%08d", nID);
    msgBuff.insert(0, 8, '0');
    memcpy((void*)msgBuff.c_str(), szID, 8);
    nID++;
    nID = nID % 0x7fffffff;
}
void ParseIDMsgBuf(string input, int& nID, string& msgBuf)
{
    string szID = input.substr(0, 8);
    msgBuf = input.substr(8, input.length() - 8);
    sscanf(szID.c_str(), "%8d", &nID);
}

int SearchNeighbourRspTask::getPeerList(CUInt128 nodeid, const string& targetid, string& peerlist)
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    CKBuckets* kBuckets = nodemgr->GetKBuckets();
    int nMaxNum = 100;
    CUInt128 targetID = nodeid;// std::move(CUInt128(targetid));
    vector<CUInt128> vecResult;
    int nNum = kBuckets->PickNeighbourNodes(nMaxNum, targetID, vecResult);

    return nodemgr->getPeerList(nodeid, vecResult, peerlist);
}

//
void SearchNeighbourRspTask::exec()
{
    //
    int nTaskID;
    ParseIDMsgBuf(_msg, nTaskID, _msg);

    string nodeid(_fromNodeId.ToHexString());
    string targetNodeID = _msg.substr(0, 32);
    string nodemsg = _msg.substr(32, _msg.length() - 32);
    //	nodemgr->parseNode(nodemsg);

    char logmsg[128] = { 0 };
    snprintf(logmsg, 128, "Handling SearchNeighbourRspTask from peer:%s\n", nodeid.c_str());
    //   g_console_logger->debug(logmsg);

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    //---
    HCNodeSH nodeClient = nodemgr->getNode(_fromNodeId);
    string msgbuf;

    int num = getPeerList(_fromNodeId, targetNodeID, msgbuf);
    //---------------------------

    snprintf(logmsg, 128, "TaskID = %d found %d neighbours for peer:%s\n", nTaskID, num, nodeid.c_str());
    g_console_logger->debug(logmsg);

    //
    AddIDToMsgBuf(nTaskID, msgbuf);
    //---
    DataBuffer<SearchNeighbourRspTask> datamsgbuf(std::move(msgbuf));
    nodemgr->sendTo(_fromNodeId, datamsgbuf);
}

void SearchNeighbourRspTask::execRespond()
{
    string msg = _payload;
    //
    int nTaskID;
    ParseIDMsgBuf(_payload, nTaskID, msg);
    // ---

    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    NodeUPKeepThreadPool* nodeUpkeep = Singleton<NodeUPKeepThreadPool>::instance();

    //
    vector<CUInt128> vecNewNode;
    nodemgr->ParseNodeList(msg, vecNewNode);
    nodeUpkeep->AddToPingList(vecNewNode); //
    //--
    nodeUpkeep->RemoveNodeFromPullList(_sentnodeid);

    g_console_logger->debug("SearchNeighbourRspTask::execRespond(), taskID ={} , Nodes Num = {} from peer= {}", nTaskID, vecNewNode.size(), _sentnodeid.ToHexString());
}

void SearchNeighbourTask::exec()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
    HCNodeSH toServer = nodemgr->getNode(_toNodeId);
    if (toServer == 0)
        return;

    //
    CUInt128 _targetNodeId = nodemgr->myself()->getNodeId<CUInt128>();

    string msgbuf = nodemgr->myself()->serialize();
    string strID = _targetNodeId.ToHexString();
    msgbuf.insert(0, 32, '\0');
    memcpy((void*)msgbuf.c_str(), strID.c_str(), 32);

    //
    AddIDToMsgBuf(g_nTaskID, msgbuf);
    //---

    DataBuffer<SearchNeighbourTask> datamsgbuf(std::move(msgbuf));
    nodemgr->sendTo(toServer, datamsgbuf);

    g_console_logger->debug("SearchNeighbourTask::exec(), taskID ={} ,toID = {}, targetID = {}", g_nTaskID - 1, _toNodeId.ToHexString(), strID);

}

void SearchNeighbourTask::execRespond()
{
    TaskThreadPool* taskpool = Singleton<TaskThreadPool>::instance();
    taskpool->put(make_shared<SearchNeighbourRspTask>(std::move(_sentnodeid), _payload));
}


