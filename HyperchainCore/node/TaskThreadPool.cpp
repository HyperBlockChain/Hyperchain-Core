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

#include "TaskThreadPool.h"
#include "newLog.h"

TaskThreadPool::TaskThreadPool(uint32_t numthreads, uint32_t maxnumtasks) :
    _numthreads(numthreads), _taskqueue(maxnumtasks), _isstop(false)
{
    std::function<void()> f = std::bind(&TaskThreadPool::exec_task, this);
    for (size_t i = 0; i < _numthreads; i++) {
        _threads.emplace_back(thread(f));
    }
}

void TaskThreadPool::stop()
{
    _taskqueue.stop();
    _isstop = true;
    for (auto& t : _threads) {
        t.join();
    }
    _threads.clear();
}

bool TaskThreadPool::put(QueueTask &&t)
{
    bool ret = _taskqueue.push(std::forward<QueueTask>(t));
    if (!ret) {
        g_daily_logger->error("TaskThreadPool::put() _taskqueue put fail , size = {}", _taskqueue.size());
    }
    return ret;
}

void TaskThreadPool::exec_task()
{
    while (!_isstop) {
        list<QueueTask> tasklist;
        _taskqueue.pop(tasklist);
        for (auto &t : tasklist) {
            if (t->isRespond()) {
                t->execRespond();
            }
            else {
                t->exec();
            }
        }
    }
}
