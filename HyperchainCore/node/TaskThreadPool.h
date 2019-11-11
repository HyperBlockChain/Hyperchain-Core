/*Copyright 2016-2019 hyperchain.net (Hyperchain)

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

#include <sstream>
#include <list>
#include <thread>
#include <memory>
#include <functional>
#include <unordered_map>
using namespace std;

#include "ITask.hpp"
#include "SyncQueue.h"

class TaskThreadPool {

public:
    using QueueTask = shared_ptr<ITask>;

    //
    TaskThreadPool(uint32_t numthreads = thread::hardware_concurrency() < 2 ? 2 : thread::hardware_concurrency(),
                    uint32_t maxnumtasks = 5000);
    TaskThreadPool(const TaskThreadPool &) = delete;
    TaskThreadPool & operator=(const TaskThreadPool &) = delete;
    ~TaskThreadPool() { stop(); }

    bool put(QueueTask &&t);

    void stop();
    void exec_task();

    size_t getQueueSize() {
        return _taskqueue.size();
    }

    size_t getTaskThreads() {
        return _numthreads;
    }

    string getQueueDetails() {

        std::unordered_map<string, uint16> tt;
        {
            std::unique_lock<std::mutex> lck(_taskqueue.guard());
            std::list<QueueTask>& tsklist = _taskqueue.tasklist();

            for (auto it = tsklist.begin(); it != tsklist.end(); it++) {
                string t = typeid(*it->get()).name();
                if (tt.count(t) == 0) {
                    tt[t] = 1;
                }
                else {
                    tt[t] += 1;
                }
            }
        }
        ostringstream oss;
        for (auto &task : tt) {
            oss << task.first << ":" << task.second << endl;
        }
        return oss.str();
    }

private:

    uint32_t _numthreads;
    SyncQueue<QueueTask> _taskqueue;
    std::list<std::thread> _threads;

    bool _isstop;
};
