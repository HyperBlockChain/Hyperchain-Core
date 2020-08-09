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


#include "zmsg.h"
#include "mdp.h"


class HCMQClient
{
public:
    HCMQClient(int socktype = ZMQ_DEALER);
    virtual ~HCMQClient();

    HCMQClient(const HCMQClient &) = delete;
    HCMQClient & operator=(const HCMQClient &) = delete;

    zmsg* synccall(const char *servicename, zmsg *request);
    void rsynccall(const char *servicename, zmsg *request);
    void* cocall(const char *servicename, zmsg *request);

protected:
    void connect_to_broker();
    zmsg* send(std::string service, zmsg *request);
    void rsyncsend(std::string service, zmsg *request);

protected:

    std::string m_mdptype = MDPC_CLIENT;

 private:

    zmq::context_t * m_context = nullptr;
    int m_socktype;
    int m_timeout;                

    int m_retries;                

    std::shared_ptr<zmq::socket_t> m_client;
};


class HCMQMonitor : public HCMQClient
{
public:
    HCMQMonitor() : HCMQClient(ZMQ_REQ)
    {
        m_mdptype = MDP_MON;
    }
};
