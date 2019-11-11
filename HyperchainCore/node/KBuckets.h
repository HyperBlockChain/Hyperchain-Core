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

#include "UInt128.h"
#include "HCNode.h"
//#include "..\headers\includeComm.h"


#include <map>
#include <mutex>
using namespace std;
using std::chrono::system_clock;
using HCNodeMap = std::map<CUInt128, std::shared_ptr<HCNode> >;



class CKBNode
{
public:
    CKBNode(CUInt128& id);
    CUInt128 m_id;
    system_clock::time_point  m_lastTime;
};

//
class CKBuckets
{
public:
    CKBuckets() { }
    ~CKBuckets();

    void InitKbuckets(CUInt128 myID); //
    //
    bool AddNode(CUInt128 nID, CUInt128& nRemoveID);

    void RemoveNode(CUInt128 nID);
    //
    int  PickNeighbourNodes(int nNum, CUInt128 targetID, vector<CUInt128>& vecResult);
    int  PickNeighbourNodes2(int nNum, CUInt128 targetID, vector<CUInt128>& vecResult);
    //
    int PickNodesRandomly(int nNum, vector<CUInt128>& vecResult);
    //
    int PickLastActiveNodes(int nMinutes, int nNum, vector<CUInt128>& vecResult);
    //
    int PickPullNodes(int nNum, vector<CUInt128>& vecResult);

    int GetAllNodes(vector<CUInt128>& vecResult);
    size_t GetNodesNum();

    bool IsNodeInKBuckets(CUInt128 nID);
private:
    int LocateKBucker(CUInt128 nID);

    vector<list<CKBNode>> m_vecBuckets;
    CUInt128 m_localID;			//

    mutex _guard;
};