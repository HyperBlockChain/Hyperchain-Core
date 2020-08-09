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

#include "ITask.hpp"
#include "ObjectFactory.hpp"
#include "HCMQWrk.h"
#include "HCMQClient.h"

#include <boost/thread/tss.hpp>

#include <vector>
#include <functional>
#include <thread>
using namespace std;

class MsgHandler
{
public:

    MsgHandler();
    MsgHandler(const MsgHandler &) = delete;
    MsgHandler & operator=(const MsgHandler &) = delete;

    ~MsgHandler();

    template<class TASK>
    void registerTaskType(TASKTYPE tt)
    {
        _taskFactory.RegisterType<ITask, TASK, TASKBUF>(static_cast<uint32_t>(tt));
    }

    void registerTaskWorker(const char* servicename);
    void registerTaskWorker(const char* servicename, std::function<void(void*, zmsg*)> func);
    void registerRequestWorker(const char* servicename);

    void registerWorker(const char* servicename, std::function<void(void*, zmsg*)> func);
    size_t registerTimer(int delaymilliseconds, std::function<void()> func, bool isticket = false);

    

    void registerSocket(std::function<zmq::socket_t*()> sockcreatefunc, std::function<void(void*, zmsg*)> func);

    void start();
    void stop();

    std::thread::id getID()
    {
        return _eventloopthread->get_id();
    }

private:
    void dispatchMQEvent();
    void dispatchMQEvent_fb();
    void handleTask(void *wrk, zmsg *msg);
    void handleRequest(void *wrk, zmsg *msg);
    void registerSocket(zmq::socket_t* s, std::function<void(void*, zmsg*)> func);

private:

    bool _isstop = false;
    bool _isstarted = false;

    std::unique_ptr<std::thread> _eventloopthread;

    objectFactory _taskFactory;

    std::vector<HCMQWrk*> _wrks;
    std::vector<zmq::socket_t*> _socks;
    std::vector<zmq::pollitem_t> _poll_items;
    std::vector<std::function<void(void*, zmsg*)>> _poll_funcs;
    std::vector<std::function<void(void*, zmsg*)>> _poll_funcs_s;

    typedef struct
    {
        int delay;  //milliseconds
        int64_t when;
        std::function<void()> func;
    } timer;

    std::vector<timer> _poll_func_timers;
    std::vector<timer> _poll_func_tickets;

    typedef struct
    {
        std::string servicename;
        std::function<void(void*, zmsg*)> func;
    } pendingservice;

    std::vector<pendingservice> _pending_service;

    typedef struct
    {
        std::function<zmq::socket_t*()> sockcreatefunc;
        std::function<void(void*, zmsg*)> func;
    } pendingsock;

    std::vector<pendingsock> _pending_sock;

 };


inline void MQMsgPush(zmsg *msg)
{}

template<typename... Args>
inline void MQMsgPush(zmsg *msg, const string& str, Args... args)
{
    msg->push_back(str.c_str(), str.size());
    MQMsgPush(msg, std::forward<Args>(args)...);
}

template<typename... Args>
inline void MQMsgPush(zmsg *msg, const void *p, Args... args)
{
    msg->push_back(&p, sizeof(void*));
    MQMsgPush(msg, std::forward<Args>(args)...);
}

template<typename T, typename... Args>
inline void MQMsgPush(zmsg *msg, T t, Args... args)
{
    msg->push_back(&t, sizeof(T));
    MQMsgPush(msg, std::forward<Args>(args)...);
}

extern boost::thread_specific_ptr<HCMQClient> mqrsyncclient;

template<typename... Args>
inline zmsg* MQRequest(const char *servicename, int nReq, Args... args)
{
    HCMQClient client(ZMQ_REQ);

    zmsg msg;
    MQMsgPush(&msg, args...);
    msg.push_front((char*)&nReq, sizeof(nReq));

    return (zmsg*)client.cocall(servicename, &msg);
}

template<typename... Args>
inline void MQRequestNoWaitResult(const char *servicename, int nReq, Args... args)
{
    if(!mqrsyncclient.get())
        mqrsyncclient.reset(new HCMQClient(ZMQ_DEALER));


    zmsg msg;
    MQMsgPush(&msg, args...);
    msg.push_front((char*)&nReq, sizeof(nReq));

    mqrsyncclient->rsynccall(servicename, &msg);
}


inline void MQMsgParseHlp(zmsg *rspmsg)
{}

template<typename... Args>
inline void MQMsgParseHlp(zmsg *rspmsg, string &str, Args&... args)
{
    str = rspmsg->pop_front();
    MQMsgParseHlp(rspmsg, args...);
}

template<typename T, typename... Args>
inline void MQMsgParseHlp(zmsg *rspmsg, T &t, Args&... args)
{
    std::string str = rspmsg->pop_front();
    memcpy(&t, str.c_str(), str.size());
    MQMsgParseHlp(rspmsg, args...);
}

template<typename... Args>
inline void MQMsgPop(zmsg *rspmsg, Args&... args)
{
    MQMsgParseHlp(rspmsg, args...);
}
