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

#include "../newLog.h"
#include "UInt128.h"
#include "HCNode.h"
#include "ITask.hpp"

#include <map>
#include <mutex>
using namespace std;

using HCNodeMap = std::map<CUInt128, std::shared_ptr<HCNode> >;

template<typename T>
class DataBuffer {

public:
	DataBuffer(size_t payloadlen) :_data(std::string(payloadlen + CUInt128::value + sizeof(TASKTYPE), 0)) {
		setTaskMetaHeader();
	}

	DataBuffer(string &&payload) :_data(std::forward<string>(payload)) {
		_data.insert(0, CUInt128::value + sizeof(TASKTYPE), '\0');
		setTaskMetaHeader();
	}

	operator string() {
		return _data;
	}

	string& tostring()
	{
		return _data;
	}

	char *payload() { return const_cast<char*>(_data.c_str() + CUInt128::value + sizeof(TASKTYPE)); }

	typename std::enable_if<std::is_base_of<ITask, T>::value>::type
	setHeader(uint8_t h[CUInt128::value]) {
		memcpy(payloadoffset(0), h, CUInt128::value);
	}

	typename std::enable_if<std::is_base_of<ITask, T>::value>::type
	setHeader(CUInt128 &nodeid) {

		uint8_t h[CUInt128::value];
		nodeid.ToByteArray(h);
		memcpy(payloadoffset(0), h, CUInt128::value);
	}
		
private:
	typename std::enable_if<std::is_base_of<ITask, T>::value>::type
	setTaskMetaHeader() {
		TASKTYPE t = T::value;
		memcpy(payloadoffset(CUInt128::value), (char*)&(t), sizeof(TASKTYPE));
	}
	char * payloadoffset(size_t offset) { return const_cast<char*>(_data.c_str() + offset); }

	string _data;
};

class NodeManager {

public: 
	
	NodeManager() : _me(make_shared<HCNode>()) {}
	NodeManager(const NodeManager &) = delete;
	NodeManager & operator=(const NodeManager &) = delete;

	~NodeManager() {}

	void myself(HCNodeSH &me) { _me = std::move(me); }
	HCNodeSH & myself() { return _me; }

	void seedServer(HCNodeSH &seed) {_seed = std::move(seed);}
	HCNodeSH & seedServer() { return _seed; }

	HCNodeSH& getNode(const CUInt128 &nodeid);
    
	void addNode(HCNodeSH & node);
	void updateNode(HCNodeSH & node);

	template<typename T> 
	void sendToAllNodes(DataBuffer<T> & msgbuf)
	{
		std::lock_guard<std::mutex> lck(_guard);

		uint8_t b[CUInt128::value];
		_me->getNodeId(b);
		msgbuf.setHeader(b);

		std::for_each(_nodemap.begin(), _nodemap.end(), [&, this](HCNodeMap::reference node) {
			node.second->send(msgbuf.tostring());
		});
	}

	template<typename T>
	int sendTo(HCNodeSH &targetNode, DataBuffer<T> & msgbuf)
	{
		uint8_t b[CUInt128::value];
		_me->getNodeId(b);

		msgbuf.setHeader(b);
		return targetNode->send(msgbuf.tostring());
	}

	template<typename T>
	int sendTo(const CUInt128 &targetNodeid, DataBuffer<T> & msgbuf)
	{
		int result = 0;
		std::lock_guard<std::mutex> lck(_guard);
		auto r = std::find_if(_nodemap.begin(), _nodemap.end(), [&, this](const HCNodeMap::reference n) {
			if (n.second->getNodeId<CUInt128>() == targetNodeid) {
				result = this->sendTo(n.second, msgbuf);
				return true;
			}
			return false;
		});

		if (r == _nodemap.end()) {
			g_console_logger->error( "cannot find the target node:{}", targetNodeid.ToHexString().c_str());
			return 0;
		}

		return result;
	}

	const HCNodeMap* getNodeMap();
	size_t getNodeMapSize();
	void loadMyself();
	void saveMyself();
	void loadNeighbourNodes();
	void saveNeighbourNodes();

	void parse(const string &nodes);

	const CUInt128 * FindNodeId(IAccessPoint *ap);


	string toString();

private: 

    HCNodeSH _me;
    HCNodeSH _seed;
	HCNodeMap _nodemap;
	mutex _guard;
};
