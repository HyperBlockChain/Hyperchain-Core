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

#include <iostream>
using namespace std;

#include "ITask.hpp"


class SearchNeighbourRspTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::SEARCH_NEIGHBOUR_RSP> {
public:
    using ITask::ITask;

    SearchNeighbourRspTask() {}
    SearchNeighbourRspTask(CUInt128&& fromNodeId, const char* requestNode) : _fromNodeId(std::move(fromNodeId)), _msg(requestNode) {}
    ~SearchNeighbourRspTask() {}

    void exec() override;
    void execRespond() override;

private:

    int getPeerList(CUInt128 nodeid, const string& targetid, string& peerlist);

private:
    CUInt128 _fromNodeId;
    string _msg;
};

class SearchNeighbourTask : public ITask, public std::integral_constant<TASKTYPE, TASKTYPE::SEARCH_NEIGHBOUR> {
public:
    using ITask::ITask;

    SearchNeighbourTask() {}
    SearchNeighbourTask(CUInt128& toNodeId) : _toNodeId(toNodeId) {}

    ~SearchNeighbourTask() {}
    void exec() override;
    void execRespond() override;
private:
    CUInt128 _toNodeId; // ∑¢ÀÕ∂‘œÛ
};


