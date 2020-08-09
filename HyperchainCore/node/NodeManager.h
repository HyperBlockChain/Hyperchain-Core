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

#include "UInt128.h"
#include "HCNode.h"
#include "ITask.hpp"
#include "KBuckets.h"
#include "NodeUpkeepThreadPool.h"
#include "MsgHandler.h"

#include <map>
#include <mutex>
using namespace std;

class UdpAccessPoint;
enum class NodeType :char {
    Normal = 0,     

    Bootstrap,      

    LedgerRPCClient  

};



const uint16_t SAND_BOX = 0xD000;
const uint16_t INFORMAL_NET = 0xE000;
const uint16_t FORMAL_NET = 0xF000;

using HCNodeMap = std::map<CUInt128, std::shared_ptr<HCNode> >;
extern ProtocolVer pro_ver;

template<typename T>
class DataBuffer {

public:
    DataBuffer(size_t payloadlen) :_data(std::string(payloadlen + ProtocolHeaderLen, 0)) {
        setTaskMetaHeader();
    }

    DataBuffer(string &&payload) :_data(std::forward<string>(payload)) {
        _data.insert(0, ProtocolHeaderLen, '\0');
        setTaskMetaHeader();
    }

    operator string() {
        return _data;
    }

    string& tostring()
    {
        return _data;
    }

    void resize(size_t payloadlen)
    {
        _data.resize(payloadlen + ProtocolHeaderLen);
    }

    char *payload() { return const_cast<char*>(_data.c_str() + ProtocolHeaderLen); }

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
        ProtocolVer::setVerNetType(payloadoffset(CUInt128::value), pro_ver.net());
        memcpy(payloadoffset(CUInt128::value + sizeof(ProtocolVer)), (char*)&(t), sizeof(TASKTYPE));
    }
    char * payloadoffset(size_t offset) { return const_cast<char*>(_data.c_str() + offset); }

    string _data;
};

class NodeManager {

public:

    NodeManager();

    NodeManager(const NodeManager &) = delete;
    NodeManager & operator=(const NodeManager &) = delete;

    ~NodeManager() {}

    void myself(HCNodeSH &me) { _me = std::move(me); }
    HCNodeSH & myself() { return _me; }

    bool isSpecfySeedServer() {
        if (_me->getNodeId<CUInt128>() == _seed->getNodeId<CUInt128>())
            return false;
        return true;
    }

    void seedServer(HCNodeSH &seed) {
        _seed = std::move(seed);
        _nodemap[_seed->getNodeId<CUInt128>()] = _seed;
    }
    HCNodeSH & seedServer() { return _seed; }

    HCNodeSH getNode(const CUInt128 &nodeid);
    bool getNodeAP(const CUInt128 &nodeid, UdpAccessPoint *ap);

    void addNode(HCNodeSH & node);
    void updateNode(const CUInt128 &strnodeid, const string &ip, uint32_t port);

    template<typename T>
    void sendToAllNodes(DataBuffer<T> & msgbuf)
    {
        uint8_t b[CUInt128::value];
        _me->getNodeId(b);
        msgbuf.setHeader(b);

        ToAllNodes(msgbuf.tostring());
    }

    template<typename T>
    int sendTo(HCNodeSH &targetNode, DataBuffer<T> & msgbuf)
    {
        uint8_t b[CUInt128::value];
        _me->getNodeId(b);

        msgbuf.setHeader(b);
        return targetNode->send(msgbuf.tostring());
    }

    void sendToHlp(const string &targetNode, const string &msgbuf)
    {
        CUInt128 targetNodeid(targetNode);
        if (_nodemap.count(targetNodeid)) {
            _nodemap[targetNodeid]->send(msgbuf);
        }
    }

    template<typename T>
    void sendTo(const CUInt128 &targetNodeid, DataBuffer<T> & msgbuf)
    {
        uint8_t b[CUInt128::value];
        _me->getNodeId(b);
        msgbuf.setHeader(b);

        if (_msghandler.getID() == std::this_thread::get_id()) {
            

            if (!IsNodeInKBuckets(targetNodeid))
                return;

            if (_nodemap.count(targetNodeid)) {
                _nodemap[targetNodeid]->send(msgbuf);
            }
        }
        else {
            string strnodeid = targetNodeid.ToHexString();
            string buff = msgbuf.tostring();
            MQRequestNoWaitResult(NODE_SERVICE, (int)SERVICE::SendTo, strnodeid, buff);
        }
    }

    const HCNodeMap* getNodeMap();
    size_t getNodeMapSize();
    void loadMyself();
    void saveMyself();

    size_t GetNodesJson(vector<string>& vecNodes);

    bool parseNode(const string &node, UdpAccessPoint *ap);

    bool IsSeedServer(HCNodeSH & node);

    string toFormatString();

    void PickNeighbourNodes(const CUInt128 &nodeid, int num, vector<CUInt128> &vnodes);
    bool IsNodeInKBuckets(const CUInt128 &nodeid);
    void PickRandomNodes(int nNum, std::set<CUInt128> &nodes);
    void GetAllNodes(std::set<CUInt128> &setNodes);
    int GetNodesNum();

    CKBuckets* GetKBuckets() {
        return &m_actKBuchets;
    }
    void InitKBuckets();
    void EnableNodeActive(const CUInt128 &nodeid, bool bEnable);


    

    void ParseNodeList(const string &nodes, vector<CUInt128> &vecNewNode);

    

    void loadNeighbourNodes_New();

    void  GetNodeMapNodes(vector<CUInt128>& vecNodes);
    void SaveLastActiveNodesToDB();
    int getPeerList(CUInt128 excludeID, vector<CUInt128>& vecNodes, string & peerlist);

    void start()
    {
        startMQHandler();
    }

    void stop()
    {
        _msghandler.stop();
    }

    std::thread::id MQID()
    {
        return _msghandler.getID();
    }


    MsgHandler& GetMsgHandler() { return _msghandler; }

private:

    void startMQHandler();
    void DispatchService(void *wrk, zmsg *msg);

    void ToAllNodes(const string& data);

    

    bool SaveNodeToDB(const CUInt128 &nodeid, system_clock::time_point  lastActTime);

    void PushToKBuckets(const CUInt128 &nodeid);
    void AddToDeactiveNodeList(const CUInt128& nodeid);
    void RemoveNodeFromDeactiveList(const CUInt128 &nodeid);

private:

    enum class SERVICE : short
    {
        ToAllNodes = 1,
        UpdateNode,
        GetNodesJson,
        ParseNode,
        ParseNodeList,
        GetNodeAP,
        EnableNodeActive,
        GetNodeMapNodes,
        ToFormatString,
        PickNeighbourNodes,
        IsNodeInKBuckets,
        GetAllNodes,
        PickRandomNodes,
        GetNodesNum,
        SendTo,
    };

    HCNodeSH _me;
    HCNodeSH _seed;
    HCNodeMap _nodemap;

    CKBuckets m_actKBuchets;
    std::list<CKBNode> m_lstDeactiveNode;

    MsgHandler _msghandler;
 };
