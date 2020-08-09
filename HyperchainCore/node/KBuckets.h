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

#include "UInt128.h"
#include <mutex>
#include <set>

using namespace std;
using std::chrono::system_clock;

class CKBNode
{
public:
    CKBNode(const CUInt128& id);
    CUInt128 m_id;
    system_clock::time_point  m_lastTime;
};



class CKBuckets
{
public:
    CKBuckets() = default;
    ~CKBuckets();

    

    void InitKbuckets(CUInt128 myID);

    

    bool AddNode(CUInt128 nID, CUInt128& nRemoveID);
    void RemoveNode(CUInt128 nID);

    

    std::set<CUInt128> PickRandomNodes(int nNum = 16);
    

    vector<CUInt128> PickNeighbourNodes(CUInt128 targetID, int nNum = 10);
    

    vector<CUInt128> PickLastActiveNodes(CUInt128 targetID, int nNum = 10, int nMinutes = 10);

    std::set<CUInt128> GetAllNodes();
    int GetNodesNum();
    bool IsNodeInKBuckets(CUInt128 nID);

private:
    

    int LocateKBucket(CUInt128 nID);

    CUInt128 m_localID;			

    vector<list<CKBNode>> m_vecBuckets;
    std::set<CUInt128> m_setNodes;    

};