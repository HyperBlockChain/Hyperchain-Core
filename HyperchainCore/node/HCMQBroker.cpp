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

#include "zmsg.h"
#include "mdp.h"
#include "HCMQBroker.h"

#include <map>
#include <set>
#include <deque>
#include <list>
#include <thread>


#define HEARTBEAT_LIVENESS  3       //  3-5 is reasonable
#define HEARTBEAT_INTERVAL  2500    //  msecs
#define HEARTBEAT_EXPIRY    HEARTBEAT_INTERVAL * HEARTBEAT_LIVENESS


HCMQBroker::HCMQBroker()
{
    int nNum = std::thread::hardware_concurrency();
    if (nNum > 1) {
        nNum--;
    }
    m_context = new zmq::context_t(nNum);
}

HCMQBroker::~HCMQBroker()
{
    while (!m_services.empty()) {
        delete m_services.begin()->second;
        m_services.erase(m_services.begin());
    }
    while (!m_workers.empty()) {
        delete m_workers.begin()->second;
        m_workers.erase(m_workers.begin());
    }
}

void HCMQBroker::bind(std::string endpoint)
{
    m_endpoint = endpoint;
    m_socket->bind(m_endpoint.c_str());
    s_console("HC broker is active at %s", endpoint.c_str());
}


service * HCMQBroker::service_require(std::string name)
{
    assert(name.size() > 0);
    if (m_services.count(name)) {
        return m_services.at(name);
    }
    else {
        service * srv = new service(name);
        m_services.insert(std::make_pair(name, srv));
        return srv;
    }
}


void HCMQBroker::service_dispatch(service *srv, zmsg *msg)
{
    assert(srv);
    if (msg) {
        srv->m_requests.push_back(make_tuple(std::move(*msg), std::time(nullptr)));
    }

    

    //if (srv->m_requests.size() > 50 && srv->m_waiting.empty()) {
    //    cout << time2string() << " " << srv->m_name << " very busy, too many requests :" << srv->m_requests.size()
    //        << " waiting: " << srv->m_waiting.size() << endl;
    //}

    while (!srv->m_waiting.empty() && !srv->m_requests.empty()) {
        

        auto wrk = srv->m_waiting.begin();
        auto next = wrk;
        for (++next; next != srv->m_waiting.end(); ++next) {
            if ((*next)->m_expiry > (*wrk)->m_expiry)
                wrk = next;
        }

        auto now = std::time(nullptr);
        int ntimeout = 5; // 5 seconds

        while (!srv->m_requests.empty() && (*wrk)->has_strength()) {

            auto &req = srv->m_requests.front();
            auto t = std::get<1>(req);
            if (t + ntimeout < now) {
                

                srv->m_requests.pop_front();
                srv->m_req_abandoned++;
                continue;
            }

            zmsg &msg = std::get<0>(req);
            worker_send(*wrk, (char*)MDPW_REQUEST, "", &msg);
            (*wrk)->become_weaker();

            srv->m_requests.pop_front();
            srv->m_req_handled++;
        }

        if (!(*wrk)->has_strength()) {
            m_waiting.erase(*wrk);
            srv->m_waiting.erase(wrk);
        }
    }
}

worker * HCMQBroker::worker_require(std::string identity)
{
    assert(identity.length() != 0);

    

    if (m_workers.count(identity)) {
        return m_workers.at(identity);
    }
    else {
        worker *wrk = new worker(identity);
        m_workers.insert(std::make_pair(identity, wrk));
        return wrk;
    }
}

void HCMQBroker::worker_delete(worker *&wrk, int disconnect)
{
    assert(wrk);
    if (disconnect) {
        worker_send(wrk, (char*)MDPW_DISCONNECT, "", NULL);
    }

    if (wrk->m_service) {
        for (auto it = wrk->m_service->m_waiting.begin();
            it != wrk->m_service->m_waiting.end();) {
            if (*it == wrk) {
                it = wrk->m_service->m_waiting.erase(it);
            }
            else {
                ++it;
            }
        }
        wrk->m_service->m_workers--;
    }
    m_waiting.erase(wrk);

    

    cout << "ZMQ:  worker_delete " << wrk->m_identity << endl;
    m_workers.erase(wrk->m_identity);
    delete wrk;
}

void HCMQBroker::worker_process(std::string sender, zmsg *msg)
{
    assert(msg && msg->parts() >= 1);

    std::string command = msg->pop_front();
    bool worker_ready = m_workers.count(sender) > 0;
    worker *wrk = worker_require(sender);

    if (command.compare(MDPW_IDLE) == 0) {
        if(!worker_ready) {
            std::string service_name = msg->pop_front();
            wrk->m_service = service_require(service_name);
            wrk->m_service->m_workers++;
        }
        wrk->idle();
        worker_waiting(wrk);
    }
    else if (command.compare(MDPW_READY) == 0) {
        if (worker_ready) {              

            worker_delete(wrk, 1);
        }
        else {
            

            std::string service_name = msg->pop_front();
            wrk->m_service = service_require(service_name);
            wrk->m_service->m_workers++;
            wrk->idle();
            worker_waiting(wrk);
        }
    }
    else {
        if (command.compare(MDPW_REPLY) == 0) {
            if (worker_ready) {
                

                

                std::string client = msg->unwrap();
                msg->push_front(MDPC_CLIENT);
                msg->wrap(client.c_str(), "");
                msg->send(*m_socket);
                worker_waiting(wrk);
            }
            else {
                worker_delete(wrk, 1);
            }
        }
        else {
            if (command.compare(MDPW_HEARTBEAT) == 0) {
                if (worker_ready) {
                    wrk->m_expiry = s_clock() + HEARTBEAT_EXPIRY;
                }
                else {
                    worker_delete(wrk, 1);
                }
            }
            else {
                if (command.compare(MDPW_DISCONNECT) == 0) {
                    worker_delete(wrk, 0);
                }
                else {
                    s_console("E: invalid input message (%d)", (int)*command.c_str());
                    msg->dump();
                }
            }
        }
    }
}

void HCMQBroker::worker_send(worker *worker, char *command, std::string option, zmsg *_msg)
{
    zmsg emptymsg;
    zmsg *msg = nullptr;
    if (_msg) {
        msg = _msg;
    }
    else {
        msg = &emptymsg;
    }

    

    if (option.size() > 0) {
        msg->push_front((char*)option.c_str());
    }
    msg->push_front(command);
    msg->push_front((char*)MDPW_WORKER);
    

    msg->wrap(worker->m_identity.c_str(), "");

    msg->send(*m_socket);
}

void HCMQBroker::worker_waiting(worker *wrk)
{
    assert(wrk);
    m_waiting.insert(wrk);

    wrk->m_service->m_waiting.insert(wrk);
    wrk->m_expiry = s_clock() + HEARTBEAT_EXPIRY;
    wrk->become_stronger();
    service_dispatch(wrk->m_service, 0);
}

void HCMQBroker::monitor_process(std::string sender, zmsg *msg)
{
    std::stringstream ss;
    for (auto& ser : m_services) {
        ss << "\t" << std::setw(20) << setiosflags(ios::right) << ser.first;
        ss << " waiting requests : " << std::resetiosflags(ios::right) <<
            std::setw(8) << setiosflags(ios::left) << ser.second->m_requests.size();
        ss << " handled : " << std::setw(12) << ser.second->m_req_handled
           << " abandoned: " << ser.second->m_req_abandoned << endl;
    }
    msg->push_front(ss.str());
    msg->push_front(MDP_MON);
    msg->wrap(sender.c_str(), "");
    msg->send(*m_socket);
}


void HCMQBroker::client_process(std::string sender, zmsg *msg)
{
    assert(msg && msg->parts() >= 2);

    std::string service_name = msg->pop_front();
    service *srv = service_require(service_name);
    msg->wrap(sender.c_str(), "");
    

    //if (service_name == NODE_SERVICE)
    //{
    //    zmsg clonemsg(*msg);
    //    clonemsg.unwrap();
    //    std::string tt  = clonemsg.pop_front();
    //    int t;
    //    memcpy(&t, tt.c_str(), 4);
    //    if (t == 1) {
    //        cout << "------------------Broker recv SERVICE::ToAllNodes..................." << endl;
    //    }
    //}
    service_dispatch(srv, msg);
}

void HCMQBroker::start()
{
    if (m_brokerthread) {
        return;
    }
    m_brokerthread.reset(new std::thread(&HCMQBroker::broker_handler, this));

    while (!m_isbinded) {
        this_thread::sleep_for(chrono::milliseconds(200));
    }
}

void HCMQBroker::stop()
{
    if (!m_brokerthread) {
        return;
    }
    if (m_brokerthread->joinable()) {
        m_brokerthread->join();
    }
    m_brokerthread.release();
}

void HCMQBroker::broker_handler()
{
    m_socket = new zmq::socket_t(*m_context, ZMQ_ROUTER);
    bind(HCMQBroker::endpoint());
    m_isbinded = true;

    zmq::pollitem_t items[] = {
        { static_cast<void*>(*m_socket), 0, ZMQ_POLLIN, 0} };

    while (!g_sys_interrupted) {
        zmq::poll(items, 1, (long)HEARTBEAT_INTERVAL);

        if (items[0].revents & ZMQ_POLLIN) {
            zmsg recvmsg(*m_socket);

            std::string sender = recvmsg.pop_front();
            recvmsg.pop_front();
            std::string header = recvmsg.pop_front();

            if (header.compare(MDPC_CLIENT) == 0) {
                client_process(sender, &recvmsg);
            }
            else if (header.compare(MDPW_WORKER) == 0) {
                worker_process(sender, &recvmsg);
            }
            else if (header.compare(MDP_MON) == 0) {
                monitor_process(sender, &recvmsg);
            }
            else {
                

                recvmsg.dump();
            }
        }
    }

    if (m_socket) {
        delete m_socket;
    }
}


zmq::context_t * g_inproc_context;
int g_sys_interrupted = 0;


