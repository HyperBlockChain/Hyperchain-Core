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


#ifndef _SYNCQUEUE_H
#define _SYNCQUEUE_H

#include <list>
#include <mutex>
#include <condition_variable>
using namespace std;

template<typename T>
class SyncQueue {
public:
    SyncQueue(size_t capacity) :_maxCapacity(capacity), _requeststop(false) {}

    void stop() {
        _requeststop = true;
        _not_empty_cv.notify_all();
        _not_full_cv.notify_all();
    }

    bool push(T && task) {
        return addTask(std::forward<T>(task));
    }

    void pop(T& t) {
        std::unique_lock<std::mutex> lck(_guard);
        _not_empty_cv.wait(lck, [this] { return _requeststop || !isEmpty(); });
        if (_requeststop) {
            return;
        }
        t = std::move(_tasklist.front());
        _tasklist.pop_front();
        _not_full_cv.notify_one();
    }

    void pop(std::list<T>& resultlist, size_t num = 10) {
        std::unique_lock<std::mutex> lck(_guard);
        _not_empty_cv.wait(lck, [this] { return _requeststop || !isEmpty(); });
        if (_requeststop) {
            return;
        }
        if (_tasklist.size() <= num) {
            resultlist = std::move(_tasklist);
        }
        else {
            auto end = _tasklist.begin();
            std::advance(end, num);
            resultlist.splice(resultlist.end(), _tasklist, _tasklist.begin(), end);
        }
        _not_full_cv.notify_one();
    }

    size_t size() { return _tasklist.size(); }
    std::mutex& guard() { return _guard; }
    std::list<T>& tasklist() { return _tasklist; }
private:
    bool isFull() {
        return _tasklist.size() < _maxCapacity ? false : true;
    }
    bool isEmpty() {
        return _tasklist.size() > 0 ? false : true;
    }

    bool addTask(T && task) {
        std::unique_lock<std::mutex> lck(_guard);
        std::chrono::microseconds timeout(200);
        bool isavailable = _not_full_cv.wait_for(lck, timeout, [this] { return _requeststop || !isFull(); });
        if (!isavailable || _requeststop) {
            return false;
        }
        _tasklist.push_back(task);
        _not_empty_cv.notify_one();
        return true;
    }

private:
    std::list<T> _tasklist;
    std::mutex _guard;
    std::condition_variable _not_full_cv;
    std::condition_variable _not_empty_cv;

    // maximum capacity of _tasklist
    size_t _maxCapacity;
    bool _requeststop;
};

#endif //_SYNCQUEUE_H
