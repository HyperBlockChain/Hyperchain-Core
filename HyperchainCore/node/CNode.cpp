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

#include <random>
#include <sstream>
#include <iomanip>
using namespace std;



#include "UdpAccessPoint.hpp"
#include "TcpAccessPoint.hpp"
#include "UInt128.h"
#include "NodeManager.h"
#include "../wnd/common.h"
#include "CNode.h"

#include <cpprest/json.h>
using namespace web;


CNode::CNode(const CUInt128 & nodeid) :  _nodeid(nodeid)
{
}

CNode::CNode(CUInt128 && nodeid) : _nodeid(std::move(nodeid))
{
}

CNode::CNode(CNode && node) : _aplist(std::move(node._aplist)), _nodeid(std::move(node._nodeid))
{
}

CNode::CNode(const CNode & node) :  _nodeid(node._nodeid)
{
	_aplist.clear();
	for (auto ap : node._aplist) {
		_aplist.push_back(ap);
	}
}

void CNode::registerType()
{
	if (_isReg) {
		return;
	}
	_apFactory.RegisterType<IAccessPoint,UdpAccessPoint,string>(UdpAccessPoint::CLASSNAME);
	_apFactory.RegisterType<IAccessPoint,TcpAccessPoint,string>(TcpAccessPoint::CLASSNAME);
	_isReg = true;
}


string CNode::generateNodeId()
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(1, 255);
	string str;
	ostringstream oss;
	oss.flags(ios::hex);
	for (int n = 0; n < CUInt128::value/2; ++n) {
		oss << setw(2) << setfill('0') << dis(gen);
	}

	return oss.str();
}

CNode & CNode::operator=(const CNode & node)
{
	_nodeid = node._nodeid;
	_aplist.clear();
	for (auto ap : node._aplist) {
		_aplist.push_back(ap);
	}
	return *this;
}

int CNode::send(string &msgbuf) const 
{
	
	for (auto ap : _aplist) {
		return ap->write(msgbuf.c_str(), msgbuf.size());
	}
	return 0;
}

string CNode::serializeAP()
{
	json::value obj = json::value::array(_aplist.size());

	int i = 0;
	for (auto ap : _aplist) {
		obj[i] = json::value::parse(s2t(ap->serialize()));
		++i;
	}
	std::stringstream oss;
	obj.serialize(oss);
	return oss.str();
}


void CNode::parseAP(const string &aps)
{
	json::value obj = json::value::parse(s2t(aps));
	assert(obj.is_array());

	_aplist.clear();
	registerType();
	size_t num = obj.size();
	for (int i = 0; i < num; i++) {
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
