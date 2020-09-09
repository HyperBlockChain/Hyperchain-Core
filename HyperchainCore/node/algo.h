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

#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <algorithm>                // std::find_if()

#include <boost/fiber/all.hpp>
#include <boost/fiber/scheduler.hpp>
#include <boost/noncopyable.hpp>

using namespace boost;
using namespace boost::fibers;
using namespace boost::fibers::detail;

class Verbose : public boost::noncopyable
{
public:
    Verbose(std::string const& d, std::string const& s = "stop") :
        desc(d),
        stop(s)
    {
        std::cout << desc << " start" << std::endl;
    }

    ~Verbose()
    {
        std::cout << desc << ' ' << stop << std::endl;
    }

private:
    std::string     desc;
    std::string     stop;
};

class priority_props : public boost::fibers::fiber_properties
{
public:
    priority_props(boost::fibers::context * ctx) :
        fiber_properties(ctx),        priority_(0)
    {
    }

    ~priority_props();

    int get_priority() const
    {
        return priority_;
    }

    void set_priority(int p)
    {
        if (p != priority_) {
            priority_ = p;
            notify();
        }
    }

    std::string name;
private:
    int priority_;
};

class priority_scheduler :
    public boost::fibers::algo::algorithm_with_properties< priority_props >
{
private:
    typedef boost::fibers::scheduler::ready_queue_type rqueue_t;

    rqueue_t                                rqueue_;
    std::mutex                  mtx_{};
    std::condition_variable     cnd_{};
    bool                        flag_{ false };
    boost::fibers::context      *main_context_ = nullptr;
    int                         nfibers_terminated_ = 0;
public:
    priority_scheduler() :
        rqueue_()
    {
    }

    virtual void awakened(boost::fibers::context * ctx, priority_props & props) noexcept;
    virtual boost::fibers::context * pick_next() noexcept;

    virtual bool has_ready_fibers() const noexcept;

    virtual void property_change(boost::fibers::context * ctx, priority_props & props) noexcept;

    void describe_ready_queue();

    virtual void suspend_until(std::chrono::steady_clock::time_point const& time_point) noexcept;

    virtual void notify() noexcept;

    void count_terminated() { nfibers_terminated_++; }
    int fibers_count();
};

template< typename Fn , typename ... Arg>
boost::fibers::fiber Newfiber(Fn && func, std::string const& name, int priority, Arg && ... arg)
{
    boost::fibers::fiber fiber(func, std::forward<Arg>(arg)...);
    priority_props & props(fiber.properties< priority_props >());
    props.name = name;
    props.set_priority(priority);
    return fiber;
}

