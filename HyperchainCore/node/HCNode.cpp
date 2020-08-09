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

#include <iostream>
#include <random>
#include <sstream>
#include <iomanip>
using namespace std;

#include "../newLog.h"
#include "UdpAccessPoint.hpp"
#include "TcpAccessPoint.hpp"
#include "UInt128.h"
#include "NodeManager.h"
#include "../wnd/common.h"
#include "../headers/commonstruct.h"
#include "HCNode.h"

#include <cpprest/json.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
using namespace web;

/**
 * CNode implementation
 */

utility::string_t UdpAccessPoint::CLASSNAME_U = _XPLATSTR("UdpAP");
std::string UdpAccessPoint::CLASSNAME = "UdpAP";;
utility::string_t TcpAccessPoint::CLASSNAME_U = _XPLATSTR("TcpAP");
std::string TcpAccessPoint::CLASSNAME = "TcpAP";

HCNode::HCNode(const CUInt128 & nodeid) : _nodeid(nodeid)
{
}

HCNode::HCNode(CUInt128 && nodeid) : _nodeid(std::move(nodeid))
{
}

HCNode::HCNode(HCNode && node) : _nodeid(std::move(node._nodeid)), _aplist(std::move(node._aplist))
{
}

HCNode::HCNode(const HCNode & node) : _nodeid(node._nodeid)
{
    _aplist.clear();
    for (auto &ap : node._aplist) {
        _aplist.push_back(ap);
    }
}

void HCNode::registerType()
{
    if (_isReg) {
        return;
    }
    _apFactory.RegisterType<IAccessPoint, UdpAccessPoint, string>(UdpAccessPoint::CLASSNAME);
    _apFactory.RegisterType<IAccessPoint, TcpAccessPoint, string>(TcpAccessPoint::CLASSNAME);
    _isReg = true;
}

string HCNode::generateNodeId()
{
    return CCommonStruct::generateNodeId();
}

HCNode & HCNode::operator=(const HCNode & node)
{
    _nodeid = node._nodeid;
    _aplist.clear();
    for (auto &ap : node._aplist) {
        _aplist.push_back(ap);
    }
    return *this;
}

bool HCNode::getUDPAP(string& ip, int& nport)
{
    if (_aplist.size() > 0) {
        UdpAccessPoint* ap = reinterpret_cast<UdpAccessPoint*>(_aplist.begin()->get());
        if (ap) {
            ip = ap->ip();
            nport = ap->port();
            return true;
        }
    }
    return false;
}

int HCNode::send(const string &msgbuf) const
{
    

    

    for (auto &ap : _aplist) {
        return ap->write(msgbuf.c_str(), msgbuf.size());
    }
    return 0;
}


string HCNode::serialize()
{
    json::value objAP = json::value::array(_aplist.size());

    int i = 0;
    for (auto &ap : _aplist) {
        objAP[i] = json::value::parse(s2t(ap->serialize()));
        ++i;
    }

    json::value obj;
    obj[_XPLATSTR("ap")] = objAP;
    obj[_XPLATSTR("id")] = json::value::string(s2t(_nodeid.ToHexString()));

    std::stringstream oss;
    obj.serialize(oss);
    return oss.str();
}

void HCNode::parse(const string &nodeinfo, HCNode &node)
{
    json::value obj = json::value::parse(s2t(nodeinfo));

    if (!obj.has_field(_XPLATSTR("id"))) {
        throw std::invalid_argument("Invalid CNode type");
    }

    string id = t2s(obj[_XPLATSTR("id")].as_string());
    node.setNodeId(id);

    string aplist = t2s(obj[_XPLATSTR("ap")].serialize());
    node.parseAP(aplist);
}


string HCNode::serializeAP()
{
    json::value obj = json::value::array(_aplist.size());

    int i = 0;
    for (auto &ap : _aplist) {
        obj[i] = json::value::parse(s2t(ap->serialize()));
        ++i;
    }
    std::stringstream oss;
    obj.serialize(oss);
    return oss.str();
}


void HCNode::parseAP(const string &aps)
{
    json::value obj = json::value::parse(s2t(aps));
    assert(obj.is_array());

    _aplist.clear();
    registerType();
    size_t num = obj.size();
    for (size_t i = 0; i < num; i++) {
        if (!obj[i].has_field(_XPLATSTR("typename"))) {
            throw std::invalid_argument("Invalid access point type");
        }

        string tn = t2s(obj[i][_XPLATSTR("typename")].as_string());
        string objstr = t2s(obj[i].serialize());
        shared_ptr<IAccessPoint> ap = _apFactory.CreateShared<IAccessPoint>(tn, objstr);
        if (!ap) {
            throw std::invalid_argument("Failed to create access point");
        }
        _aplist.push_back(ap);
    }
}
