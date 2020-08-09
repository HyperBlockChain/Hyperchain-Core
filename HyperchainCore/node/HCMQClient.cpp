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

#include "HCMQClient.h"

#include <boost/fiber/all.hpp>


HCMQClient::HCMQClient(int socktype) : m_socktype(socktype),
    m_context(g_inproc_context),
    m_timeout(2500),           //  msecs
    m_retries(3)
{
    connect_to_broker();
}

HCMQClient::~HCMQClient()
{}

zmsg* HCMQClient::synccall(const char *servicename, zmsg *request)
{
    return send(servicename, request);
}

void HCMQClient::rsynccall(const char *servicename, zmsg *request)
{
    rsyncsend(servicename, request);
}

void* HCMQClient::cocall(const char *servicename, zmsg *request)
{
    assert(request);

    request->push_front((char*)servicename);
    request->push_front(m_mdptype.c_str());
    if (m_socktype != ZMQ_REQ)
        request->push_front("");

    int total_retries = 0;
    int retries = 0;
    int max_retries = m_timeout / 100;
    zmq::pollitem_t items[1];

    zmsg msg(*request);
    msg.send(*m_client);

    boost::this_fiber::yield();

    int npolltimes = 0;
    while (!g_sys_interrupted) {
        items[0] = { static_cast<void*>(*m_client), 0, ZMQ_POLLIN, 0 };

        auto rc = zmq::poll(items, 1, 0);
        if (!rc) {
            npolltimes++;
            boost::this_fiber::sleep_for(std::chrono::milliseconds(100));
            if (npolltimes < 5) {
                continue;
            }
        }
        npolltimes = 0;

        

        if (items[0].revents & ZMQ_POLLIN) {
            zmsg * recv_msg = new zmsg(*m_client);

            

            assert(recv_msg->parts() >= 1);

            if (m_socktype != ZMQ_REQ)
                recv_msg->pop_front(); 


            std::string header = recv_msg->pop_front();
            assert(header.compare(m_mdptype) == 0);

            return recv_msg;
        }
        else {
            retries++;

            

            if (retries > max_retries) {
                connect_to_broker();
                zmsg msg(*request);
                msg.send(*m_client);
                retries = 0;

                total_retries++;

                

                //cout << time2string() << " " << this_thread::get_id() << "(" << servicename
                //    << "): retry already " << total_retries << " times" << endl;
            }
        }
    }

    return nullptr;
}

void HCMQClient::connect_to_broker()
{
    m_client.reset(new zmq::socket_t(*m_context, m_socktype));
    s_set_id(*m_client);
    int linger = 500;
    m_client->setsockopt(ZMQ_LINGER, &linger, sizeof(linger));

    int interval = 100;
    m_client->setsockopt(ZMQ_RECONNECT_IVL, &interval, sizeof(interval));
    m_client->connect(HC_BROKER);
}

zmsg* HCMQClient::send(std::string service, zmsg *request)
{
    assert(request);

    request->push_front((char*)service.c_str());
    request->push_front(m_mdptype.c_str());
    if (m_socktype != ZMQ_REQ)
        request->push_front("");

    int retries = 0;
    int max_retries = m_timeout / 100;
    while (!g_sys_interrupted) {
        zmsg msg(*request);
        msg.send(*m_client);

        while (!g_sys_interrupted) {
            zmq::pollitem_t items[] = {
                { static_cast<void*>(*m_client), 0, ZMQ_POLLIN, 0 } };
            zmq::poll(items, 1, 100);

            

            if (items[0].revents & ZMQ_POLLIN) {
                zmsg * recv_msg = new zmsg(*m_client);

                

                assert(recv_msg->parts() >= 1);

                if (m_socktype != ZMQ_REQ)
                    recv_msg->pop_front(); 


                std::string header = recv_msg->pop_front();
                assert(header.compare(m_mdptype) == 0);

                return recv_msg;
            }
            else {
                retries++;

                

                if (retries > max_retries) {
                    connect_to_broker();
                    zmsg msg(*request);
                    msg.send(*m_client);
                    retries = 0;
                }
            }
        }
    }
    return nullptr;
}

void HCMQClient::rsyncsend(std::string service, zmsg *request)
{
    assert(request);

    request->push_front((char*)service.c_str());
    request->push_front((char*)m_mdptype.c_str());

    if (m_socktype != ZMQ_REQ)
        request->push_front("");

    request->send(*m_client);
}

