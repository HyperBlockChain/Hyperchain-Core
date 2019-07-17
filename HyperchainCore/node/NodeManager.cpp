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
#include "NodeManager.h"
#include "../db/dbmgr.h"
#include "../wnd/common.h"

#include <cpprest/json.h>
using namespace web;


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
    DBmgr *pDb = DBmgr::instance();

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
    DBmgr *pDb = DBmgr::instance();

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
    DBmgr *pDb = DBmgr::instance();

    std::lock_guard<std::mutex> lck(_guard);
    pDb->query("SELECT * FROM neighbornodes",
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
    DBmgr *pDb = DBmgr::instance();

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


void NodeManager::parse(const string &nodes)
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
        g_console_logger->error("cannot find the target node");
        return nullptr;
    }

    return r->second->getNodeId<CUInt128*>();
}

bool NodeManager::IsSeedServer(HCNodeSH & node)
{
    if (_seed->getNodeId<CUInt128>() == node->getNodeId<CUInt128>())
        return true;

    string ap = _seed->serializeAP();
    if (!ap.empty() && 0 == ap.compare(node->serializeAP())) {
        _seed = std::move(node);
        return true;
    }

    return false;
}