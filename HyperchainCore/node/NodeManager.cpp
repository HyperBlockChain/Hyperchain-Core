/*Copyright 2016-2018 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#include "NodeManager.h"
#include "../db/dbmgr.h"

void NodeManager::myself(const CNode &me) 
{
	_me = me;
}

CNode & NodeManager::myself() 
{
	return _me;
}

CNode * NodeManager::searchBuddy() 
{
	return NULL;
}

CNode * NodeManager::getNode(const CUInt128 &nodeid) 
{
	return NULL;
}

const CNodeList* NodeManager::getNodeList() 
{
	return &_nodelist;
}

void NodeManager::addNode(CNode && node)
{
	_nodelist.push_back(std::forward<CNode>(node));
}


void NodeManager::updateNode(CNode && node)
{
	std::lock_guard<std::mutex> lck(_guard);
	auto result = std::find_if(_nodelist.begin(), _nodelist.end(), [&](CNode &n) {
		if (n.getNodeId<CUInt128>() == node.getNodeId<CUInt128>()) {
			CNode::APList &aplist = node.getAPList();
			for (auto &ap : aplist) {
				n.updateAP(ap);
			}
			return true;
		}
		return false;
	});

	if (result == std::end(_nodelist)) {
		addNode(std::move(node));
	}
}

int NodeManager::sendTo(const CNode &targetNode, string & msgbuf)
{
	msgbuf.insert(0, _me.getNodeId<string>());
	return targetNode.send(msgbuf);
}

int NodeManager::sendTo(const CUInt128 &targetNodeid, string & msgbuf)
{
	int result = 0;
	auto r = std::find_if(_nodelist.begin(), _nodelist.end(), [&](const CNode &n) {
		if (n.getNodeId<CUInt128>() == targetNodeid) {
			result = sendTo(n, msgbuf);
			return true;
		}
		return false;
	});

	if (r == std::end(_nodelist)) {
		cout << "cannot find the target node" << endl;
		return 0;
	}

	return result;
}

void NodeManager::loadMyself()
{
	DBmgr *pDb = DBmgr::instance();

	pDb->query("SELECT * FROM myself;",
		[this](CppSQLite3Query & q) {
		string id = q.getStringField("id");
		string aps = q.getStringField("accesspoint");

		_me.setNodeId(id);
		_me.parseAP(aps);
	});
}

void NodeManager::saveMyself()
{
	int num = 0;
	DBmgr *pDb = DBmgr::instance();
	pDb->query("SELECT count(*) as num FROM myself;",
		[this, &num](CppSQLite3Query & q) {
		num = q.getIntField("num");
	});

	if (num > 0) {
		pDb->exec("delete from myself;");
	}
	pDb->exec("insert into myself(id,accesspoint) values(?,?);",
		_me.getNodeId<string>().c_str(),
		_me.serializeAP().c_str());
}

void NodeManager::loadNeighbourNodes()
{
	_nodelist.clear();
	DBmgr *pDb = DBmgr::instance();

	pDb->query("SELECT * FROM neighbornodes",
		[this](CppSQLite3Query & q) {
		string id = q.getStringField("id");
		string aps = q.getStringField("accesspoint");

		CUInt128 nodeid(id);
		CNode node(std::move(nodeid));
		node.parseAP(aps);
		_nodelist.push_back(std::move(node));
		});
}

void NodeManager::saveNeighbourNodes()
{
	DBmgr *pDb = DBmgr::instance();

	for (auto node: _nodelist)
	{
		int num = 0;
		pDb->query("SELECT count(*) as num FROM neighbornodes where id=?;",
			[this,&num](CppSQLite3Query & q) {
			num = q.getIntField("num");
		}, node.getNodeId<string>().c_str());

		if (num > 0) {
			pDb->exec("update neighbornodes set accesspoint = ? where id=?;",
				node.serializeAP().c_str(),
				node.getNodeId<string>().c_str());
		}
		else {
			pDb->exec("insert into neighbornodes(id,accesspoint) values(?,?);",
				node.getNodeId<string>().c_str(),
				node.serializeAP().c_str());
		}
	}
}
