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

class HCMQWrk {
public:

    HCMQWrk(const char *servicename, int socktype = ZMQ_DEALER);
    virtual ~HCMQWrk() {}

    void send_to_broker(char *command, std::string option, zmsg *_msg);
    void connect_to_broker();
    void set_heartbeat_at();
    void live();
    void keepalive(zmq::pollitem_t &poll_item);
    void idle();
    void reply(string reply_who, zmsg *&reply_p);

    zmq::socket_t* getsocket() { return m_worker.get(); }

private:

    void heartbeat();

private:
    std::string m_broker;
    std::string m_service;
    zmq::context_t *m_context = nullptr;
    int m_socktype;
    std::shared_ptr<zmq::socket_t> m_worker;      


    

    int64_t m_heartbeat_at;       

    size_t m_liveness;            

    int m_heartbeat = 2500;              

    int m_reconnect = 2500;              


    

    bool m_expect_reply = false;         


    

    std::string m_reply_to;
};

