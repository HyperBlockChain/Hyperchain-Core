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

#include <map>
#include <set>
#include <deque>
#include <list>
#include <thread>


struct service;


static constexpr int maximum_process_ability = 20;

struct worker
{
    std::string m_identity;   

    service * m_service;      

    int64_t m_expiry;         

    int32_t m_process_ability = 0;

    worker(std::string identity, service * service = 0, int64_t expiry = 0)
    {
        m_identity = identity;
        m_service = service;
        m_expiry = expiry;
    }

    

    inline void idle()
    {
        m_process_ability = maximum_process_ability;
    }

    inline bool has_strength()
    {
        return m_process_ability > 0;
    }

    

    inline void become_stronger()
    {
        if (m_process_ability >= maximum_process_ability) {
            m_process_ability = maximum_process_ability;
            return;
        }
        m_process_ability++;
    }

    inline void become_weaker()
    {
        if (m_process_ability <= 0) {
            m_process_ability = 0;
            return;
        }
        m_process_ability--;
    }
};

struct service
{
    ~service()
    {}

    std::string m_name;                 

    std::deque<std::tuple<zmsg,std::time_t>> m_requests;        

    std::set<worker*> m_waiting;        

    size_t m_workers = 0;               

    size_t m_req_handled = 0;           

    size_t m_req_abandoned= 0;          


    service(std::string name)
    {
        m_name = name;
    }
};

class HCMQBroker
{
public:

    HCMQBroker();
    virtual ~HCMQBroker();

    void bind(std::string endpoint);

    zmq::context_t * context() { return m_context; }

    static const char * endpoint() { return HC_BROKER; }

    void start();
    void stop();

private:

    service * service_require(std::string name);

    void service_dispatch(service *srv, zmsg *msg);

    worker * worker_require(std::string identity);
    void worker_delete(worker *&wrk, int disconnect);
    void worker_process(std::string sender, zmsg *msg);
    void monitor_process(std::string sender, zmsg *msg);
    void worker_send(worker *worker, char *command, std::string option, zmsg *msg);
    void worker_waiting(worker *worker);

    void client_process(std::string sender, zmsg *msg);

    void broker_handler();

private:
    zmq::context_t * m_context;
    zmq::socket_t * m_socket;
    std::string m_endpoint;
    std::map<std::string, service*> m_services;
    std::map<std::string, worker*> m_workers;
    std::set<worker*> m_waiting;

    std::unique_ptr<std::thread> m_brokerthread;

    bool m_isbinded = false;
};



