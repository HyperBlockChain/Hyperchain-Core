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

#include "newLog.h"
#include "Singleton.h"
#include "ITask.hpp"

#include "NodeManager.h"
#include "MsgDispatcher.h"


class UdpRecvDataHandler
{
public:
    UdpRecvDataHandler() {}
    UdpRecvDataHandler(const UdpRecvDataHandler &) = delete;
    UdpRecvDataHandler & operator=(const UdpRecvDataHandler &) = delete;

    void stop()
    {
        _isstopped = true;
        _dispatcher.stop();
    }

    bool put(const char* ip, uint32_t port, const char *buf, size_t len)
    {
        if (_isstopped) {
            return true;
        }

        if (len < ProtocolHeaderLen) {
            char logmsg[128] = { 0 };
            snprintf(logmsg, 128, "Received invalid data from: %s:%d\n", ip, port);
            cout << logmsg;
            return true;
        }

        auto taskbuf = std::make_shared<std::string>(buf, len);
        return put(ip, port, taskbuf);
    }

    bool put(const char* ip, uint32_t port, TASKBUF taskbuf)
    {
        if (_isstopped) {
            return true;
        }

        size_t len = taskbuf->size();
        if (len < ProtocolHeaderLen) {
            char logmsg[128] = { 0 };
            snprintf(logmsg, 128, "Received invalid data from: %s:%d\n", ip, port);
            g_console_logger->warn(logmsg);
            return true;
        }

        if (!ITask::checkProtocolVer(taskbuf->c_str(), pro_ver.net())) {
            g_console_logger->warn("Received data with net type or version incompatibility.");
            return true;
        }


        _dispatcher.dispatch(taskbuf->c_str(), taskbuf->size(), string(ip), port);

        return true;
    }

    void registerAppTask(TASKTYPE tt, const std::string &servicename)
    {
        _dispatcher.register_app_task(tt, servicename);
    }

    void unregisterAppTask(TASKTYPE tt)
    {
        _dispatcher.unregister_app_task(tt);
    }

private:

    MsgDispatcher _dispatcher;
    bool _isstopped = false;
};
