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

#include "NodeUpkeepThreadPool.h"
#include "newLog.h"

#include "NodeManager.h"
#include "Singleton.h"
#include "SearchNeighbourTask.h"
#include "PingPongTask.h"

NodeType g_nodetype = NodeType::Bootstrap;

void NodeUPKeepThreadPool::start()
{
    InitPullList();
}

void NodeUPKeepThreadPool::stop()
{
    m_lstPullNode.clear();
    m_setPingNode1.clear();
    m_setPingNode2.clear();
}



void NodeUPKeepThreadPool::InitPullList()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    vector<CUInt128> vecNodes;
    nodemgr->GetNodeMapNodes(vecNodes);
    for (CUInt128& id : vecNodes)
        m_lstPullNode.push_back(id);

    if (g_nodetype == NodeType::Normal)
    {
        CUInt128 seedID = nodemgr->seedServer()->getNodeId<CUInt128>();
        m_lstPullNode.push_back(seedID);
    }
}

void NodeUPKeepThreadPool::PreparePullList()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    std::set<CUInt128> setResult;
    nodemgr->PickRandomNodes(16, setResult);
    for (CUInt128 id : setResult)
        m_lstPullNode.push_back(id);

    if (g_nodetype == NodeType::Normal)
    {
        CUInt128 seedID = nodemgr->seedServer()->getNodeId<CUInt128>();
        if (!nodemgr->IsNodeInKBuckets(seedID))
            m_lstPullNode.push_back(seedID);
    }
}



void NodeUPKeepThreadPool::NodeFind()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    

    if (m_lstPullNode.empty())
        PreparePullList();
    g_console_logger->debug("Pickup {} nodes to refresh K Buckets", m_lstPullNode.size());

    for (CUInt128& node : m_lstPullNode) {
        nodemgr->EnableNodeActive(node, false);
        SearchNeighbourTask tsk(node);
        tsk.exec();
    }
    m_lstPullNode.clear();
    g_console_logger->debug("Finish Refresh K Buckets");
}

std::set<CUInt128>& NodeUPKeepThreadPool::getPingNodeSet()
{
    return m_pingSecSet ? m_setPingNode2 : m_setPingNode1;
}

std::set<CUInt128>& NodeUPKeepThreadPool::getAddNodeSet()
{
    return m_pingSecSet ? m_setPingNode1 :m_setPingNode2;
}

void NodeUPKeepThreadPool::PreparePingSet()
{
    NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

    

    string str = HCNode::generateNodeId();
    vector<CUInt128> vecResult;
    nodemgr->PickNeighbourNodes(CUInt128(str), 30, vecResult);

    std::set<CUInt128>& addNodeSet = getAddNodeSet();
    for (CUInt128& id : vecResult)
        addNodeSet.insert(id);
    m_pingSecSet = !m_pingSecSet;
}


void NodeUPKeepThreadPool::DoPing()
{
    std::set<CUInt128>& pingNodeSet = getPingNodeSet();
    

    vector<CUInt128> vNodes(20);
    int pkgNum = pingNodeSet.size() / 20 + 1;
    auto iter = pingNodeSet.begin();
    for (int j = 0; j < pkgNum; j++) {
        int count = 0;
        vNodes.clear();
        for (; iter != pingNodeSet.end() && count < 20; iter++, count++)
            vNodes.push_back(*iter);

        if (!vNodes.empty()) {
            PingPongTask task(vNodes);
            task.exec();
        }
    }
}

void NodeUPKeepThreadPool::NodePing()
{
    switch (m_pingstate) {
        case pingstate::prepare: {
            PreparePingSet();
            std::set<CUInt128>& pingNodeSet = getPingNodeSet();
            if (!pingNodeSet.size()) {
                EmitPingSignal(5);
                break;
            }

            m_pingstate = pingstate::ping1;
            DoPing();

            m_pingstate = pingstate::ping2;
            EmitPingSignal(5);
            break;
        }
        case pingstate::ping2: {
            DoPing();
            m_pingstate = pingstate::check;
            EmitPingSignal(5);
            break;
        }
        case pingstate::check: {
            

            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
            std::set<CUInt128>& pingNodeSet = getPingNodeSet();
            for (auto &node : pingNodeSet)
                nodemgr->EnableNodeActive(node, false);
            pingNodeSet.clear();

            

            m_pingstate = pingstate::prepare;
            EmitPingSignal(30);
            break;
        }
    }
}


void NodeUPKeepThreadPool::EmitPingSignal(int nDelaySecond)
{
    MsgHandler& msgh = Singleton<NodeManager>::getInstance()->GetMsgHandler();
    msgh.registerTimer(nDelaySecond * 1000, std::bind(&NodeUPKeepThreadPool::NodePing, this), true);
}

void NodeUPKeepThreadPool::AddToPingList(const CUInt128 nodeid)
{
    std::set<CUInt128>& addNodeSet = getAddNodeSet();
    addNodeSet.insert(nodeid);
}

void NodeUPKeepThreadPool::AddToPingList(vector<CUInt128>& vecNewNode)
{
    std::set<CUInt128>& addNodeSet = getAddNodeSet();
    for (CUInt128& id : vecNewNode)
        addNodeSet.insert(id);
}

void NodeUPKeepThreadPool::RemoveNodeFromPingList(const CUInt128 &nodeid)
{
    std::set<CUInt128>& pingNodeSet = getPingNodeSet();
    pingNodeSet.erase(nodeid);
}