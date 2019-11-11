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

#pragma once

#include <sstream>
#include <list>
#include <thread>
#include <memory>
#include <functional>
#include <unordered_map>
using namespace std;

#include "ITask.hpp"
#include "SyncQueue.h"

using std::chrono::system_clock;
class PingPullNode
{
public:
    PingPullNode() { ; }
    PingPullNode(const CUInt128 &nodeid);

    bool isSendAgain();							//

    CUInt128 m_nodeID;
    int m_nSendNum;								//
    system_clock::time_point  m_lastSendTime;	//
};

//
class NodeUPKeepThreadPool
{
public:
    NodeUPKeepThreadPool();
    ~NodeUPKeepThreadPool() { stop(); }

    void start();
    void stop();

    void PreparePullList();
    void RemoveNodeFromPullList(const CUInt128 &nodeid);
    bool RemoveFrontFromPullList(const CUInt128 &nodeid);
    bool GetFrontNodeFromPullList(PingPullNode& node);
    void AppendToPullList(PingPullNode& node);
    bool IsPullListEmpty();
    size_t  GetPullListSize() {
        return m_lstPullNode.size();
    }

    void InitPullList();
    bool IsNodeInPingList(const CUInt128 &nodeid);
    void AddToPingList(vector<CUInt128> vecNewNode);//HC：K桶里被挤走的节点进入Ping列表
    void AddToPingList(const CUInt128 &nodeid);
    void RemoveNodeFromPingList(const CUInt128 &nodeid);
    bool RemoveFrontFromPingList(const CUInt128 &nodeid);
    bool GetFrontNodeFromPingList(PingPullNode &node);
    void AppendToPingList(PingPullNode& node);
    bool IsPingListEmpty();
    size_t  GetPingListSize() {
        return m_lstPingNode.size();
    }

private:
    void NodeFind();
    void NodePing();
    std::thread		m_NodeFindThread;
    std::thread		m_NodePingThread;
    bool m_isstop;

    std::list<PingPullNode> m_lstPullNode;
    std::list<PingPullNode> m_lstPingNode;
    mutex _guardPull;  //
    mutex _guardPing;  //
};