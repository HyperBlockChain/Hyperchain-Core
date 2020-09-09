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


#include "algo.h"

priority_props::~priority_props()
{
    auto *ctx = boost::fibers::context::active();
    if (ctx) {
        auto p = dynamic_cast<priority_scheduler*>(algo_);
        if (p) {
            p->count_terminated();
        }
    }
}

void priority_scheduler::awakened(boost::fibers::context * ctx, priority_props & props) noexcept
{
    int ctx_priority = props.get_priority();
    rqueue_t::iterator i(std::find_if(rqueue_.begin(), rqueue_.end(),
        [ctx_priority, this](boost::fibers::context & c) { return properties(&c).get_priority() < ctx_priority; }));
    rqueue_.insert(i, *ctx);
}

boost::fibers::context * priority_scheduler::pick_next() noexcept
{
    if (rqueue_.empty()) {
        return nullptr;
    }
    boost::fibers::context * ctx(&rqueue_.front());
    rqueue_.pop_front();
    if (properties(ctx).name == "dispatchMQEvent") {
        main_context_ = ctx;
    }

    return ctx;
}

bool priority_scheduler::has_ready_fibers() const noexcept
{
    return !rqueue_.empty();
}

void priority_scheduler::property_change(boost::fibers::context * ctx, priority_props & props) noexcept
{
    if (!ctx->ready_is_linked()) {
        //describe_ready_queue();
        return;
    }

    ctx->ready_unlink();

    awakened(ctx, props);
}

void priority_scheduler::describe_ready_queue()
{
    if (rqueue_.empty()) {
        std::cout << "[empty]";
    }
    else {
        const char * delim = "";
        for (boost::fibers::context & ctx : rqueue_) {
            priority_props & props(properties(&ctx));
            std::cout << delim << props.name << '(' << props.get_priority() << ')';
            delim = ", ";
        }
    }
    std::cout << std::endl;
}

void priority_scheduler::suspend_until(std::chrono::steady_clock::time_point const& time_point) noexcept
{
    if ((std::chrono::steady_clock::time_point::max)() == time_point) {
        std::unique_lock< std::mutex > lk(mtx_);
        cnd_.wait(lk, [this]() { return flag_; });
        flag_ = false;
    }
    else {
        std::unique_lock< std::mutex > lk(mtx_);
        cnd_.wait_until(lk, time_point, [this]() { return flag_; });
        flag_ = false;
    }
}

void priority_scheduler::notify() noexcept
{
    std::unique_lock< std::mutex > lk(mtx_);
    flag_ = true;
    lk.unlock();
    cnd_.notify_all();
}


int priority_scheduler::fibers_count()
{
    return nfibers_terminated_;
}

