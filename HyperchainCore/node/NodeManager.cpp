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

#include <ctime>

#include "NodeManager.h"
#include "../db/dbmgr.h"
#include "../wnd/common.h"
#include "NodeUpkeepThreadPool.h"
#include "Singleton.h"


#include <cpprest/json.h>
using namespace web;
ProtocolVer pro_ver = 0;


HCNodeSH& NodeManager::getNode(const CUInt128 &nodeid)
{
    std::lock_guard<std::mutex> lck(_guard);
    auto result = std::find_if(_nodemap.begin(), _nodemap.end(), [&](HCNodeMap::reference n) {
        if (n.second->getNodeId<CUInt128>() == nodeid) {
            return true;
        }
        return false;
    });

    if (result == _nodemap.end()) {
        //return null node
        HCNodeSH no;
        return no;
    }
    return result->second;
}

const HCNodeMap* NodeManager::getNodeMap()
{
    return &_nodemap;
}

size_t NodeManager::getNodeMapSize()
{
    return _nodemap.size();
}

void NodeManager::addNode(HCNodeSH & node)
{
    _nodemap[node->getNodeId<CUInt128>()] = node;
}


void NodeManager::updateNode(HCNodeSH & node)
{
    std::lock_guard<std::mutex> lck(_guard);
    auto result = std::find_if(_nodemap.begin(), _nodemap.end(), [&](HCNodeMap::reference n) {
        if (n.second->getNodeId<CUInt128>() == node->getNodeId<CUInt128>()) {
            HCNode::APList &aplist = node->getAPList();
            for (auto &ap : aplist) {
                n.second->updateAP(ap);
            }
            return true;
        }
        return false;
    });

    if (result == _nodemap.end()) {
        addNode(node);
    }
}


void NodeManager::loadMyself()
{
    DBmgr *pDb = Singleton<DBmgr>::instance();

    std::lock_guard<std::mutex> lck(_guard);
    pDb->query("SELECT * FROM myself;",
        [this](CppSQLite3Query & q) {
        string id = q.getStringField("id");
        string aps = q.getStringField("accesspoint");

        _me->setNodeId(id);
        _me->parseAP(aps);
    });
}

void NodeManager::saveMyself()
{
    int num = 0;
    DBmgr *pDb = Singleton<DBmgr>::instance();

    std::lock_guard<std::mutex> lck(_guard);
    pDb->query("SELECT count(*) as num FROM myself;",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    });

    if (num > 0) {
        pDb->exec("delete from myself;");
    }
    pDb->exec("insert into myself(id,accesspoint) values(?,?);",
        _me->getNodeId<string>().c_str(),
        _me->serializeAP().c_str());
}

void NodeManager::loadNeighbourNodes()
{
    _nodemap.clear();
    DBmgr *pDb = Singleton<DBmgr>::instance();

    std::lock_guard<std::mutex> lck(_guard);
    pDb->query("SELECT * FROM neighbornodes ORDER BY lasttime DESC;",
        [this](CppSQLite3Query & q) {
        string id = q.getStringField("id");
        string aps = q.getStringField("accesspoint");

        CUInt128 nodeid(id);
        HCNodeSH node = make_shared<HCNode>(std::move(nodeid));
        node->parseAP(aps);
        _nodemap[CUInt128(id)] = node;
    });
}


void NodeManager::saveNeighbourNodes()
{
    DBmgr *pDb = Singleton<DBmgr>::instance();

    std::lock_guard<std::mutex> lck(_guard);
    std::for_each(_nodemap.begin(), _nodemap.end(), [&](HCNodeMap::reference node) {

        int num = 0;
        pDb->query("SELECT count(*) as num FROM neighbornodes where id=?;",
            [this, &num](CppSQLite3Query & q) {
            num = q.getIntField("num");
        }, node.second->getNodeId<string>().c_str());

        if (num > 0) {
            pDb->exec("update neighbornodes set accesspoint = ? where id=?;",
                node.second->serializeAP().c_str(),
                node.second->getNodeId<string>().c_str());
        }
        else {
            pDb->exec("insert into neighbornodes(id,accesspoint) values(?,?);",
                node.second->getNodeId<string>().c_str(),
                node.second->serializeAP().c_str());
        }

    });
}


string NodeManager::toString()
{
    ostringstream oss;

    std::lock_guard<std::mutex> lck(_guard);
    std::for_each(_nodemap.begin(), _nodemap.end(), [&](HCNodeMap::reference node) {
        oss << node.second->serialize();
    });

    return oss.str();
}

string NodeManager::toFormatString()
{
    ostringstream oss;

    std::lock_guard<std::mutex> lck(_guard);
    if (0)
    {
        std::for_each(_nodemap.begin(), _nodemap.end(), [&](HCNodeMap::reference node) {
            oss << "\t" << node.second->serialize() << endl;
        });
    }
    else
    {
        vector<CUInt128> vecResult;
        int nNum = m_actKBuchets.GetAllNodes(vecResult);
        for (int i = 0; i < nNum; i++)
        {
            std::find_if(_nodemap.begin(), _nodemap.end(), [&, this](const HCNodeMap::reference n) {
                if (n.second->getNodeId<CUInt128>() == vecResult[i]) {
                    oss << "\t" << n.second->serialize() << endl;
                    return true;
                }
                return false;
            });
        }
    }

    if (oss.str().empty()) {
        oss.str("\n\tempty");
    }

    return oss.str();
}



HCNodeSH NodeManager::parseNode(const string &node)
{
    json::value obj = json::value::parse(s2t(node));

    string objstr = t2s(obj.serialize());
    auto n = make_shared<HCNode>();

    HCNode::parse(objstr, *n.get());

    std::lock_guard<std::mutex> lck(_guard);
    _nodemap[n->getNodeId<CUInt128>()] = n;

    return n;
}


void NodeManager::parseList(const string &nodes)
{
    json::value obj = json::value::parse(s2t(nodes));
    assert(obj.is_array());

    size_t num = obj.size();
    std::lock_guard<std::mutex> lck(_guard);
    for (size_t i = 0; i < num; i++) {

        string objstr = t2s(obj[i].serialize());

        auto n = make_shared<HCNode>();
        HCNode::parse(objstr, *n.get());
        _nodemap[n->getNodeId<CUInt128>()] = n;
    }
}

const CUInt128* NodeManager::FindNodeId(IAccessPoint *ap)
{
    std::lock_guard<std::mutex> lck(_guard);
    auto r = std::find_if(_nodemap.begin(), _nodemap.end(), [&](HCNodeMap::reference n) {

        HCNode::APList &aplist = n.second->getAPList();
        auto ret = std::find_if(aplist.begin(), aplist.end(), [&](const shared_ptr<IAccessPoint> &apCurr) {
            if (apCurr->isSame(ap)) {
                return true;
            }
            return false;
        });

        if (ret == std::end(aplist)) {
            return false;
        }
        return true;
    });

    if (r == _nodemap.end()) {
        //cannot find the target node"
        return nullptr;
    }

    return r->second->getNodeId<CUInt128*>();
}

bool NodeManager::IsSeedServer(HCNodeSH & node)
{
    //
    std::lock_guard<std::mutex> lck(_guard);
    if (_seed->getNodeId<CUInt128>() == node->getNodeId<CUInt128>())
        return true;

    //
    string ap = _seed->serializeAP();
    if (!ap.empty() && 0 == ap.compare(node->serializeAP()))
    {
        _seed = std::move(node);
        _nodemap[_seed->getNodeId<CUInt128>()] = _seed;
        return true;
    }

    return false;
}


/////////////////////////////
/////////////////////////////
void NodeManager::InitKBuckets()
{
    m_actKBuchets.InitKbuckets(_me->getNodeId<CUInt128>());
}
void NodeManager::PushToKBuckets(const CUInt128 &nodeid)
{
    CKBuckets* KBuckets = GetKBuckets();
    CUInt128 idRemove;
    bool bret = KBuckets->AddNode(nodeid, idRemove);
    if (!bret)
    {
        //
        NodeUPKeepThreadPool* nodeUpkeepThreadpool = Singleton<NodeUPKeepThreadPool>::instance();
        nodeUpkeepThreadpool->AddToPingList(idRemove);
    }
}


//
void NodeManager::ParseNodeList(const string &nodes, vector<CUInt128> &vecNewNode)
{
    if (nodes == "")
        return;
    json::value obj = json::value::parse(s2t(nodes));
    assert(obj.is_array());

    size_t num = obj.size();
    std::lock_guard<std::mutex> lck(_guard);
    for (size_t i = 0; i < num; i++)
    {
        string objstr = t2s(obj[i].serialize());

        auto n = make_shared<HCNode>();
        HCNode::parse(objstr, *n.get());

        vecNewNode.push_back(n->getNodeId<CUInt128>());

        auto result = std::find_if(_nodemap.begin(), _nodemap.end(), [&](HCNodeMap::reference node) {
            if (node.second->getNodeId<CUInt128>() == n->getNodeId<CUInt128>()) {
                return true;
            }
            return false;
        });

        if (result == _nodemap.end())
        {
            addNode(n);
        }

    }
}
bool NodeManager::IsNodeInDeactiveList(CUInt128 nID)
{
	std::lock_guard<std::mutex> lck(_guardDeactive);

	bool bFind = false;
	std::list<PingPullNode>::iterator Itor;
	for (Itor = m_lstDeactiveNode.begin(); Itor != m_lstDeactiveNode.end(); )
	{
		if ((*Itor).m_nodeID == nID)
		{
			bFind = true;
			break;
		}
		else
		{
			Itor++;
		}
	}
	return bFind;
}
void NodeManager::AddToDeactiveNodeList(PingPullNode& node)
{
    //
    std::lock_guard<std::mutex> lck(_guardDeactive);

    bool bFind = false;
    std::list<PingPullNode>::iterator Itor;
    for (Itor = m_lstDeactiveNode.begin(); Itor != m_lstDeactiveNode.end(); )
    {
        if ((*Itor).m_nodeID == node.m_nodeID)
        {
            bFind = true;
            break;
        }
        else
        {
            Itor++;
        }
    }
    //
    if (!bFind)
        m_lstDeactiveNode.push_back(node);


    //
    if (m_lstDeactiveNode.size() > 100)
    {
        std::lock_guard<std::mutex> lck(_guard);
        //
        int nNum = 0;
        while (nNum < 50 && !m_lstDeactiveNode.empty())
        {
            PingPullNode nodeT = m_lstDeactiveNode.front();
            m_lstDeactiveNode.pop_front();
            if (SaveNodeToDB(nodeT.m_nodeID, nodeT.m_lastSendTime))
                nNum++;
        }
    }
}

void NodeManager::RemoveNodeFromDeactiveList(const CUInt128 &nodeid)
{
    std::lock_guard<std::mutex> lck(_guardDeactive);
    std::list<PingPullNode>::iterator Itor;
    for (Itor = m_lstDeactiveNode.begin(); Itor != m_lstDeactiveNode.end(); )
    {
        if ((*Itor).m_nodeID == nodeid)
        {
            m_lstDeactiveNode.erase(Itor);
            break;
        }
        else
        {
            Itor++;
        }
    }
}

bool NodeManager::SaveNodeToDB(const CUInt128 &nodeid, system_clock::time_point  lastActTime)
{
    HCNodeSH& nodeSH = _nodemap[nodeid];// getNode(nodeid);
    if (!nodeSH->isValid())
        return false;

    std::time_t lasttime = system_clock::to_time_t(lastActTime);

    //
    DBmgr *pDb = Singleton<DBmgr>::instance();

    int num = 0;
    pDb->query("SELECT count(*) as num FROM neighbornodes where id=?;",
        [this, &num](CppSQLite3Query & q) {
        num = q.getIntField("num");
    }, nodeid.ToHexString().c_str());

    if (num > 0) {
        pDb->exec("update neighbornodes set accesspoint = ?,lasttime=? where id=?;",
            nodeSH->serializeAP().c_str(),
            lasttime,
            nodeSH->getNodeId<string>().c_str());
    }
    else {
        pDb->exec("insert into neighbornodes(id,accesspoint,lasttime) values(?,?,?);",
            nodeSH->getNodeId<string>().c_str(),
            nodeSH->serializeAP().c_str(),
            lasttime);
    }

    return true;
}
void NodeManager::loadNeighbourNodes_New()
{
    //
    DBmgr *pDb = Singleton<DBmgr>::instance();

    std::lock_guard<std::mutex> lck(_guard);
    pDb->query("SELECT * FROM neighbornodes ORDER BY lasttime DESC limit 100;",
        [this](CppSQLite3Query & q) {
        string id = q.getStringField("id");
        string aps = q.getStringField("accesspoint");
        int time = q.getIntField("lasttime");

        CUInt128 nodeid(id);
        HCNodeSH node = make_shared<HCNode>(std::move(nodeid));
        node->parseAP(aps);
        _nodemap[CUInt128(id)] = node;
    });
    m_lasttimeForDBSave = system_clock::now();
}
void NodeManager::saveNeighbourNodes_New()
{
    //
    vector<CUInt128> vecResult;
    int nNum = GetKBuckets()->GetAllNodes(vecResult);
    system_clock::time_point  lastActTime = system_clock::now();
    for (int i = 0; i < nNum; i++)
        SaveNodeToDB(vecResult[i], lastActTime);

    //
    while (!m_lstDeactiveNode.empty())
    {
        PingPullNode nodeT = m_lstDeactiveNode.front();
        m_lstDeactiveNode.pop_front();
        SaveNodeToDB(nodeT.m_nodeID, nodeT.m_lastSendTime);
    }
}
void  NodeManager::GetNodeMapNodes(vector<CUInt128>& vecNodes)
{
    HCNodeMap::iterator iter;
    for (iter = _nodemap.begin(); iter != _nodemap.end(); iter++)
    {
        CUInt128 nodeID = iter->first;
        if (nodeID != _seed->getNodeId<CUInt128>())
            vecNodes.push_back(nodeID);
    }
}

void NodeManager::EnableNodeActive(const CUInt128 &nodeid, bool bEnable)
{
    if (bEnable)
    {
        PushToKBuckets(nodeid);
        RemoveNodeFromDeactiveList(nodeid);
    }
    else
    {
        GetKBuckets()->RemoveNode(nodeid);
        PingPullNode node = PingPullNode(nodeid);
        AddToDeactiveNodeList(node);
    }
}

void NodeManager::SaveLastActiveNodesToDB()
{
    using minutes = std::chrono::duration<double, ratio<60>>;
    system_clock::time_point curr = system_clock::now();

    int nMinutes = 10;
    minutes timespan = std::chrono::duration_cast<minutes>(curr - m_lasttimeForDBSave);
    if (timespan.count() < nMinutes)
        return;

    //------
    vector<CUInt128> vecResult;
    int nNum = m_actKBuchets.PickLastActiveNodes(nMinutes, 20, vecResult);
    if (nNum > 0)
    {
        std::lock_guard<std::mutex> lck(_guard);
        for (int i = 0; i < nNum; i++)
            SaveNodeToDB(vecResult[i], curr);
    }
    //-------
    m_lasttimeForDBSave = system_clock::now();
}

int NodeManager::getPeerList(CUInt128 excludeID, vector<CUInt128>& vecNodes, string & peerlist)
{
    std::lock_guard<std::mutex> lck(_guard);
    int nNum = vecNodes.size();
    json::value obj = json::value::array();
    int k = 0;
    for (int i = 0; i < nNum; i++)
    {
        CUInt128 id = vecNodes[i];
        if (id != excludeID)
        {
            HCNodeSH node = _nodemap[id];// getNode(id);
            obj[k] = json::value::parse(s2t(node->serialize()));
            k++;
        }
    }
    if (k > 0)
    {
        std::stringstream oss;
        obj.serialize(oss);
        peerlist = std::move(oss.str());
    }
    else
        peerlist = "";
    return k;
}