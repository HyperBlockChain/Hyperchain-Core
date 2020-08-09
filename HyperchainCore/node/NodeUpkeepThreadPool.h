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

#include <set>
#include <thread>
#include "ITask.hpp"

using namespace std;
using std::chrono::system_clock;



class NodeUPKeepThreadPool
{
public:
    NodeUPKeepThreadPool() = default;
    ~NodeUPKeepThreadPool() { stop(); }

    void start();
    void stop();
    void AddToPingList(const CUInt128 nodeid);
    void AddToPingList(vector<CUInt128>& vecNewNode);

    void RemoveNodeFromPingList(const CUInt128 &nodeid);

    void NodePing();
    void NodeFind();

private:

    void InitPullList();
    void PreparePullList();

    std::set<CUInt128>& getPingNodeSet();
    std::set<CUInt128>& getAddNodeSet();

    void PreparePingSet();
    void DoPing();
    void EmitPingSignal(int nDelaySecond);

    std::list<CUInt128> m_lstPullNode;

    

    bool                m_pingSecSet;
    std::set<CUInt128> m_setPingNode1;
    std::set<CUInt128> m_setPingNode2;

    enum class pingstate : char {
        prepare,
        ping1,
        ping2,
        check,
    };
    pingstate m_pingstate = pingstate::prepare;
};