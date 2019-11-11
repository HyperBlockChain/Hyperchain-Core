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

#include "NodeUpkeepThreadPool.h"
#include "newLog.h"

#include "NodeManager.h"
#include "Singleton.h"
#include "TaskThreadPool.h"
#include "SearchNeighbourTask.h"
#include "PingPongTask.h"

NodeType g_nodetype = NodeType::Bootstrap;

PingPullNode::PingPullNode(const CUInt128 &nodeid)
{
    m_nodeID = nodeid;// std::move(nodeid);
    m_nSendNum = 0;
    m_lastSendTime = system_clock::now();

}

bool PingPullNode::isSendAgain()
{
    using minutes = std::chrono::duration<double, ratio<60>>;
    system_clock::time_point curr = system_clock::now();

    minutes timespan = std::chrono::duration_cast<minutes>(curr - m_lastSendTime);
    if (timespan.count() > 1) {
        //
        return true;
    }
    return false;
}

///////////////////////////////
//////////////////////////////

NodeUPKeepThreadPool::NodeUPKeepThreadPool()
{
    m_isstop = false;
}
void NodeUPKeepThreadPool::start()
{
    InitPullList();
    m_NodeFindThread = thread(&NodeUPKeepThreadPool::NodeFind, this);
    m_NodePingThread = thread(&NodeUPKeepThreadPool::NodePing, this);
}
void NodeUPKeepThreadPool::stop()
{
    m_isstop = true;

    m_lstPullNode.clear();
    m_lstPingNode.clear();

    if (m_NodeFindThread.joinable()) {
        m_NodeFindThread.join();
    }
    if (m_NodePingThread.joinable()) {
        m_NodePingThread.join();
    }
}
void NodeUPKeepThreadPool::NodeFind()
{
    while (!m_isstop)
    {
        TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

        //
        if (IsPullListEmpty())
            PreparePullList();

        char logmsg[128] = { 0 };
        snprintf(logmsg, 128, "Pickup %zd nodes to refresh K Buckets\n", m_lstPullNode.size());
        g_console_logger->debug(logmsg);

        //
        while (!IsPullListEmpty() && !m_isstop)
        {
            {
                std::lock_guard<std::mutex> lck(_guardPull);
                PingPullNode node;
                bool bret = GetFrontNodeFromPullList(node);
                if (!bret)
                    break;
                if (node.m_nSendNum < 2)
                {
                    if (node.m_nSendNum == 0 || node.isSendAgain())
                    {
                        node.m_nSendNum++;
                        node.m_lastSendTime = system_clock::now();
                        CUInt128 seedID = nodemgr->seedServer()->getNodeId<CUInt128>();
                        if (RemoveFrontFromPullList(node.m_nodeID))
                        {
                            if (seedID != node.m_nodeID)
                                AppendToPullList(node);
                            taskpool->put(make_shared<SearchNeighbourTask>(node.m_nodeID));
                        }
                    }
                    else
                    {
                        if (RemoveFrontFromPullList(node.m_nodeID))
                            AppendToPullList(node);
                    }
                }
                else
                {
                    RemoveFrontFromPullList(node.m_nodeID);
                    nodemgr->EnableNodeActive(node.m_nodeID, false);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        g_console_logger->debug("Finish  Refresh K  Buckets");

        nodemgr->SaveLastActiveNodesToDB();

        //Sleep() //
        int num = 0;
        while (num < 100 && !m_isstop)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            ++num;
        }
    }
}
void NodeUPKeepThreadPool::NodePing()
{
    while (!m_isstop)
    {
        //
        TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();
        NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
        while (!IsPingListEmpty() && !m_isstop)
        {
            {
                std::lock_guard<std::mutex> lck(_guardPing);
                PingPullNode node;
                bool bret = GetFrontNodeFromPingList(node);
                if (!bret)
                    break;
                if (node.m_nSendNum < 2)
                {
                    if (node.m_nSendNum == 0 || node.isSendAgain())
                    {
                        node.m_nSendNum++;
                        node.m_lastSendTime = system_clock::now();
                        if (RemoveFrontFromPingList(node.m_nodeID))
                        {
                            AppendToPingList(node);
                            taskpool->put(make_shared<PingPongTask>(std::move(node.m_nodeID)));
                        }
                    }
                    else
                    {
                        if (RemoveFrontFromPingList(node.m_nodeID))
                            AppendToPingList(node);
                    }
                }
                else
                {
                    RemoveFrontFromPingList(node.m_nodeID);
                    nodemgr->EnableNodeActive(node.m_nodeID, false);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        int num = 0;
        while (num < 100 && !m_isstop)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            ++num;
        }
    }
}



void NodeUPKeepThreadPool::PreparePullList()
{
    std::lock_guard<std::mutex> lck(_guardPull);
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    vector<CUInt128> vecResult;

    int nNum = nodemgr->GetKBuckets()->PickPullNodes(20, vecResult);
    for (int i = 0; i < nNum; i++)
        m_lstPullNode.push_back(PingPullNode(vecResult[i]));
    if (g_nodetype == NodeType::Normal)
    {
        CUInt128 seedID = nodemgr->seedServer()->getNodeId<CUInt128>();
        if (!nodemgr->GetKBuckets()->IsNodeInKBuckets(seedID))
            m_lstPullNode.push_back(PingPullNode(seedID));
    }

}

void NodeUPKeepThreadPool::RemoveNodeFromPullList(const CUInt128 &nodeid)
{
    std::lock_guard<std::mutex> lck(_guardPull);
    std::list<PingPullNode>::iterator Itor;
    for (Itor = m_lstPullNode.begin(); Itor != m_lstPullNode.end(); )
    {
        if ((*Itor).m_nodeID == nodeid)
        {
            m_lstPullNode.erase(Itor);
            break;
        }
        else
        {
            Itor++;
        }
    }
}
bool NodeUPKeepThreadPool::RemoveFrontFromPullList(const CUInt128 &nodeid)
{
    if (m_lstPullNode.empty())
        return false;
    PingPullNode node = m_lstPullNode.front();
    if (node.m_nodeID == nodeid)
    {
        m_lstPullNode.pop_front();
        return true;
    }
    return false;
}
bool NodeUPKeepThreadPool::GetFrontNodeFromPullList(PingPullNode& node)
{
    if (m_lstPullNode.empty())
        return false;
    node = m_lstPullNode.front();
    return true;
}
void NodeUPKeepThreadPool::AppendToPullList(PingPullNode& node)
{
    m_lstPullNode.push_back(node);
}
bool NodeUPKeepThreadPool::IsPullListEmpty()
{
    return m_lstPullNode.empty();
}

//
void NodeUPKeepThreadPool::InitPullList()
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
    vector<CUInt128> vecNodes;
    nodemgr->GetNodeMapNodes(vecNodes);
    size_t nNum = vecNodes.size();
    for (size_t i = 0; i < nNum; i++)
        m_lstPullNode.push_back(PingPullNode(vecNodes[i]));

    if (g_nodetype == NodeType::Normal)
    {
        CUInt128 seedID = nodemgr->seedServer()->getNodeId<CUInt128>();
        m_lstPullNode.push_back(PingPullNode(seedID));
    }
}

bool NodeUPKeepThreadPool::IsNodeInPingList(const CUInt128 &nodeid)
{
    std::list<PingPullNode>::iterator Itor;
    for (Itor = m_lstPingNode.begin(); Itor != m_lstPingNode.end(); )
    {
        if ((*Itor).m_nodeID == nodeid)
        {
            return true;
        }
        else
        {
            Itor++;
        }
    }
    return false;
}

void NodeUPKeepThreadPool::AddToPingList(const CUInt128 &nodeid)
{
	std::lock_guard<std::mutex> lck(_guardPing);
	if (!IsNodeInPingList(nodeid))
		m_lstPingNode.push_back(PingPullNode(nodeid));
}
void NodeUPKeepThreadPool::AddToPingList(vector<CUInt128> vecNewNode)
{
    NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

    std::lock_guard<std::mutex> lck(_guardPing);
    size_t nNum = vecNewNode.size();
    for (size_t i = 0; i < nNum; i++)
    {
        CUInt128 id = vecNewNode[i];
        //
        if (!nodemgr->GetKBuckets()->IsNodeInKBuckets(id) && !nodemgr->IsNodeInDeactiveList(id))
        {
            if (!IsNodeInPingList(id))
                m_lstPingNode.push_back(PingPullNode(id));
        }
    }
}
void NodeUPKeepThreadPool::RemoveNodeFromPingList(const CUInt128 &nodeid)
{
    std::lock_guard<std::mutex> lck(_guardPing);
    std::list<PingPullNode>::iterator Itor;
    for (Itor = m_lstPingNode.begin(); Itor != m_lstPingNode.end(); )
    {
        if ((*Itor).m_nodeID == nodeid)
        {
            m_lstPingNode.erase(Itor);
            break;
        }
        else
        {
            Itor++;
        }
    }
}
bool NodeUPKeepThreadPool::RemoveFrontFromPingList(const CUInt128 &nodeid)
{
    if (m_lstPingNode.empty())
        return false;
    PingPullNode node = m_lstPingNode.front();
    if (node.m_nodeID == nodeid)
    {
        m_lstPingNode.pop_front();
        return true;
    }
    return false;
}
bool NodeUPKeepThreadPool::GetFrontNodeFromPingList(PingPullNode &node)
{
    if (m_lstPingNode.size() <= 0)
        return false;
    node = m_lstPingNode.front();
    return true;
}
void NodeUPKeepThreadPool::AppendToPingList(PingPullNode& node)
{
    m_lstPingNode.push_back(node);
}
bool NodeUPKeepThreadPool::IsPingListEmpty()
{
    return m_lstPingNode.empty();
}