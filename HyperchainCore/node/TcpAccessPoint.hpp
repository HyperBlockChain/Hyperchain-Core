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

#ifndef _TCPACCESSPOINT_H
#define _TCPACCESSPOINT_H

#include "IAccessPoint.h"


class TcpAccessPoint : public IAccessPoint {

public:
    TcpAccessPoint(const string& ip, uint32_t port) : _IP(ip), _port(port) {}
    bool open() override
    {
        return true;
    }
    TcpAccessPoint(const string& objjsonstring)
    {
        string s = objjsonstring;
        init(std::move(s));
    }

    TcpAccessPoint(string&& objjsonstring)
    {
        init(std::move(objjsonstring));
    }

    bool isSame(IAccessPoint* other) const override
    {
        if (other->id() != id()) {
            return false;
        }
        TcpAccessPoint* p = dynamic_cast<TcpAccessPoint*>(other);
        if (p->_port == _port && p->_IP == _IP) {
            return true;
        }
        return false;
    }

    int id() const override { return 2; }

    int write(const char* buf, size_t len) override
    {
        return 0;
    }

    void close() override
    {

    }

    string serialize()
    {
        json::value obj;
        obj[_XPLATSTR("typename")] = json::value::string(CLASSNAME_U);
        obj[_XPLATSTR("IP")] = json::value::string(s2t(_IP));
        obj[_XPLATSTR("port")] = json::value::number(_port);
        std::stringstream oss;
        obj.serialize(oss);
        return oss.str();
    }

private:
    void init(string&& objjsonstring)
    {
        std::error_code err;
        std::istringstream oss(objjsonstring);
        json::value obj = json::value::parse(oss, err);

        utility::string_t tn = obj[_XPLATSTR("typename")].as_string();
        if (tn != CLASSNAME_U) {
            throw std::invalid_argument("Invalid type when constructs TcpAccessPoint");
        }

        _IP = t2s(obj[_XPLATSTR("IP")].as_string());
        _port = obj[_XPLATSTR("port")].as_integer();
    }

public:
    static utility::string_t CLASSNAME_U;
    static std::string CLASSNAME;


private:
    string _IP;
    uint32_t _port;
};

#endif //_TCPACCESSPOINT_H