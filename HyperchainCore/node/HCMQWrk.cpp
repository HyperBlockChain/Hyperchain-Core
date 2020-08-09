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

#include "HCMQWrk.h"



#define HEARTBEAT_LIVENESS  3       


HCMQWrk::HCMQWrk(const char *servicename, int socktype) :
    m_broker(HC_BROKER),
    m_service(servicename),
    m_context(g_inproc_context),
    m_socktype(socktype)
{
    s_version_assert(4, 0);

    connect_to_broker();
}

void HCMQWrk::send_to_broker(char *command, std::string option, zmsg *_msg)
{
    zmsg emptymsg;
    zmsg *msg = nullptr;
    if (_msg) {
        msg = _msg;
    }
    else {
        msg = &emptymsg;
    }

    

    if (option.length() != 0) {
        msg->push_front((char*)option.c_str());
    }
    msg->push_front(command);
    msg->push_front((char*)MDPW_WORKER);
    msg->push_front((char*)"");

    msg->send(*m_worker);
}

void HCMQWrk::connect_to_broker()
{
    m_worker.reset(new zmq::socket_t(*m_context, m_socktype));

    int linger = 0;
    m_worker->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));
    s_set_id(*m_worker);
    m_worker->connect(m_broker.c_str());

    

    send_to_broker((char*)MDPW_READY, m_service, NULL);

    

    m_liveness = HEARTBEAT_LIVENESS;
    m_heartbeat_at = s_clock() + m_heartbeat;
}

void HCMQWrk::set_heartbeat_at()
{
    m_heartbeat_at = s_clock() + m_heartbeat;
}

void HCMQWrk::live()
{
    m_liveness = HEARTBEAT_LIVENESS;
}

void HCMQWrk::keepalive(zmq::pollitem_t &poll_item)
{
    if (m_liveness == 0) {
        connect_to_broker();
        poll_item.socket = static_cast<void*>(*getsocket());
    }
    else {
        heartbeat();
    }
}

void HCMQWrk::idle()
{
    set_heartbeat_at();
    send_to_broker((char*)MDPW_IDLE, m_service, NULL);
}

void HCMQWrk::reply(string reply_who, zmsg *&reply_p)
{
    if (reply_p) {
        reply_p->wrap(reply_who.c_str(), "");
        send_to_broker((char*)MDPW_REPLY, "", reply_p);
    }
}

void HCMQWrk::heartbeat()
{
    if (s_clock() > m_heartbeat_at) {
        m_liveness--;
        idle();
    }
}

