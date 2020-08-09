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


#include "MsgHandler.h"
#include "defer.h"
#include "algo.h"

#include <boost/fiber/all.hpp>


boost::thread_specific_ptr<HCMQClient> mqrsyncclient;

MsgHandler::MsgHandler()
{
}

MsgHandler::~MsgHandler()
{
    for (auto& wrk: _wrks) {
        delete wrk;
    }
    _wrks.clear();
}

size_t MsgHandler::registerTimer(int delaymilliseconds, std::function<void()> func, bool isticket)
{
    if (!isticket) {
        _poll_func_timers.push_back(timer{ delaymilliseconds, delaymilliseconds + s_clock(), func });
        return _poll_func_timers.size() - 1;
    }
    else {
        _poll_func_tickets.push_back(timer{ delaymilliseconds, delaymilliseconds + s_clock(), func });
        return _poll_func_tickets.size() - 1;
    }
}

void MsgHandler::registerWorker(const char* servicename, std::function<void(void*,zmsg*)> func)
{
    _pending_service.push_back(pendingservice{ servicename, func });
}

void MsgHandler::registerSocket(std::function<zmq::socket_t*()> sockcreatefunc,
                                std::function<void(void*, zmsg*)> func)
{
    _pending_sock.push_back(pendingsock{ sockcreatefunc, func });
}

void MsgHandler::registerSocket(zmq::socket_t* s, std::function<void(void*, zmsg*)> func)
{
    _socks.push_back(s);
    _poll_items.push_back(zmq::pollitem_t{static_cast<void*>(*s), 0, ZMQ_POLLIN, 0 });
    _poll_funcs_s.push_back(func);
}

void MsgHandler::registerRequestWorker(const char* servicename)
{
    std::function<void(void*, zmsg*)> f =
        std::bind(&MsgHandler::handleRequest, this, std::placeholders::_1, std::placeholders::_2);
    registerWorker(servicename, f);
}

void MsgHandler::registerTaskWorker(const char* servicename)
{
    std::function<void(void*, zmsg*)> f =
        std::bind(&MsgHandler::handleTask, this, std::placeholders::_1, std::placeholders::_2);
    registerWorker(servicename, f);
}

void MsgHandler::registerTaskWorker(const char* servicename, std::function<void(void*, zmsg*)> func)
{
    registerWorker(servicename, func);
}

void MsgHandler::start()
{
    _eventloopthread.reset(new thread(&MsgHandler::dispatchMQEvent, this));
    while (!_isstarted) {
        this_thread::sleep_for(chrono::milliseconds(200));
    }
}

void MsgHandler::stop()
{
    _isstop = true;
    if (_eventloopthread && _eventloopthread->joinable())
        _eventloopthread->join();
}

using co_tasks= std::list<boost::fibers::fiber>;

inline
void co_create_start(void *sck, zmsg &&msg, std::function<void(void*, zmsg*)> f)
{
    boost::fibers::fiber fb(Newfiber([](void *sck, zmsg &&msg, std::function<void(void*, zmsg*)> fn) {
        fn(sck, &msg);
    }, "child_task", 0, sck, msg, f));
    fb.detach();
    return;
}

inline
void co_create_start(std::function<void()> f)
{
    boost::fibers::fiber fb(Newfiber([](std::function<void()> fn) {
        fn();
    }, "timer_child_task", 0, f));
    fb.detach();
    return;
}


void MsgHandler::dispatchMQEvent()
{
    

	

    boost::fibers::use_scheduling_algorithm<priority_scheduler>();
    boost::this_fiber::properties< priority_props >().name = "main";
    boost::fibers::fiber fdispatch(Newfiber([&]() {
        dispatchMQEvent_fb();
    }, "dispatchMQEvent", 0));
    fdispatch.join();
}

void MsgHandler::dispatchMQEvent_fb()
{
    for (auto &sck : _pending_service) {
        _wrks.push_back(new HCMQWrk(sck.servicename.c_str(), ZMQ_DEALER));
        HCMQWrk *wrk = _wrks.back();
        _poll_items.push_back(zmq::pollitem_t{ static_cast<void*>(*wrk->getsocket()), 0, ZMQ_POLLIN, 0 });
        _poll_funcs.push_back(sck.func);
    }

    for (auto &sck : _pending_sock) {
        auto *s = sck.sockcreatefunc();
        registerSocket(s, sck.func);
    }

    _isstarted = true;
    size_t wrkcount = _poll_funcs.size();
    co_tasks tasks;

    int npolltimes = 0;
    while (!_isstop) {

        auto rc = zmq::poll(&_poll_items[0], _poll_items.size(), 0);
        if (!rc) {
            npolltimes++;
            boost::this_fiber::sleep_for(std::chrono::milliseconds(50));
            if (npolltimes < 5) {
                continue;
            }

            

            for (auto &w : _wrks) {
                w->idle();
            }
        }
        npolltimes = 0;

        zmsg *msg = nullptr;
        for (size_t i = 0; i < _poll_items.size(); i++) {
            if (_poll_items[i].revents & ZMQ_POLLIN) {
                if (i >= wrkcount) {
                    size_t j = i - wrkcount;
                    zmsg recvmsg(*_socks[j]);

                    

                    co_create_start(_socks[j], std::move(recvmsg), _poll_funcs_s[j]);
                }
                else {
                    

                    zmsg recvmsg(*_wrks[i]->getsocket());
                    msg = &recvmsg;

                    assert(msg->parts() >= 3);

                    std::string empty = msg->pop_front();
                    assert(empty.compare("") == 0);

                    std::string header = msg->pop_front();
                    assert(header.compare(MDPW_WORKER) == 0);

                    std::string command = msg->pop_front();
                    if (command.compare(MDPW_REQUEST) == 0) {
                        

                        co_create_start(_wrks[i], std::move(recvmsg), _poll_funcs[i]);
                    }
                    else {
                        s_console("MsgHandler: invalid input message (%d)", (int) *(command.c_str()));
                        msg->dump();
                    }
                }
            }
        }
        

        auto now = s_clock();
        for (auto &t : _poll_func_timers) {
            if (t.when < now) {
                co_create_start(t.func);
                t.when += t.delay;
            }
        }

        

        now = s_clock();
        auto a_ticket = _poll_func_tickets.begin();
        for (; a_ticket != _poll_func_tickets.end(); ) {
            if (a_ticket->when < now) {
                timer t = *a_ticket;

                a_ticket = _poll_func_tickets.erase(a_ticket);
                co_create_start(t.func);

                

                break;
            }
            ++a_ticket;
        }

        boost::this_fiber::yield();
    }
}


void MsgHandler::handleTask(void *wrk, zmsg *msg)
{
    msg->unwrap();
    string buf = msg->pop_front();
    auto taskbuf = std::make_shared<string>(std::move(buf));

    TASKTYPE tt = *(TASKTYPE*)(taskbuf->c_str() + CUInt128::value + sizeof(ProtocolVer));

    std::shared_ptr<ITask> task = _taskFactory.CreateShared<ITask>(static_cast<uint32_t>(tt), std::move(taskbuf));
    if (!task) {
        

        

        return;
    }

    task->execRespond();
}

void MsgHandler::handleRequest(void *wrk, zmsg *msg)
{
    HCMQWrk *realwrk = reinterpret_cast<HCMQWrk*>(wrk);

    string reply_who = msg->unwrap();

    realwrk->reply(reply_who, msg);
}

