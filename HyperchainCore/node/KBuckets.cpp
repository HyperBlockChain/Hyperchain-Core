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
#include "../newLog.h"
#include "NodeManager.h"
#include "../db/dbmgr.h"
#include "../wnd/common.h"
#include "KBuckets.h"

#include <cpprest/json.h>
using namespace web;

//
int KBUCKRT_NUM = 128;
int KNODE_NUM = 20;


CKBNode::CKBNode(CUInt128& id)
{
    m_id = id;
    m_lastTime = system_clock::now();
}

CKBuckets::~CKBuckets()
{
    std::lock_guard<std::mutex> lck(_guard);
    list<CKBNode>::iterator iter;
    for (int k = 0; k < KBUCKRT_NUM; k++)
    {
        for (iter = m_vecBuckets[k].begin(); iter != m_vecBuckets[k].end();)
        {
            m_vecBuckets[k].erase(iter);
        }
    }
    m_vecBuckets.clear();
}

int CKBuckets::LocateKBucker(CUInt128 nID)
{
    int k = 0;
    CUInt128 r = m_localID ^ nID;
    int kBit = r.GetNonZeroTopBit();
    int K = kBit / (128 / KBUCKRT_NUM);

    return K;
}

void CKBuckets::InitKbuckets(CUInt128 myID)
{
    m_localID = myID;
    m_vecBuckets.resize(KBUCKRT_NUM);

}
bool CKBuckets::AddNode(CUInt128 nID, CUInt128& nRemoveID)
{
    int kBK = LocateKBucker(nID);
    //
    std::lock_guard<std::mutex> lck(_guard);
    list<CKBNode>::iterator iter;
    for (iter = m_vecBuckets[kBK].begin(); iter != m_vecBuckets[kBK].end();)
    {
        if ((*iter).m_id == nID)
        {
            m_vecBuckets[kBK].erase(iter);
            break;
        }
        else
            iter++;
    }

    m_vecBuckets[kBK].push_front(CKBNode(nID));

    if (m_vecBuckets[kBK].size() > KNODE_NUM)
    {
        nRemoveID = m_vecBuckets[kBK].back().m_id;
        m_vecBuckets[kBK].pop_back();
        return false;
    }
    else
        return true;
}

void CKBuckets::RemoveNode(CUInt128 nID)
{
    int kBK = LocateKBucker(nID);
    std::lock_guard<std::mutex> lck(_guard);
    list<CKBNode>::iterator iter;
    for (iter = m_vecBuckets[kBK].begin(); iter != m_vecBuckets[kBK].end();)
    {
        if ((*iter).m_id == nID)
        {
            m_vecBuckets[kBK].erase(iter);
            break;
        }
        else
            iter++;
    }
}

//
int  CKBuckets::PickNeighbourNodes2(int nNum, CUInt128 targetID, vector<CUInt128>& vecResult)
{
    int kBK = LocateKBucker(targetID);
    std::lock_guard<std::mutex> lck(_guard);
    int nActNum = 0;
    list<CKBNode>::iterator iter;
    int k = 0;
    while (k < kBK)
    {
        for (iter = m_vecBuckets[k].begin(); iter != m_vecBuckets[k].end();)
        {
            if (nActNum < nNum)
            {
                vecResult.push_back((*iter).m_id);
                nActNum++;
                ++iter;
            }
            else
                break;
        }
        k++;
    }
    if (nActNum < nNum)
    {
        CUInt128 rs = m_localID ^ targetID;
        for (iter = m_vecBuckets[kBK].begin(); iter != m_vecBuckets[kBK].end();)
        {
            CUInt128 r = (*iter).m_id ^ targetID;
            if (r < rs)
            {
                if (nActNum < nNum)
                {
                    vecResult.push_back((*iter).m_id);
                    nActNum++;
                }
                if (nActNum >= nNum)
                    break;
            }
            ++iter;
        }
    }
    return nActNum;
}

int  CKBuckets::PickNeighbourNodes(int nNum, CUInt128 targetID, vector<CUInt128>& vecResult)
{
    CUInt128 rs = m_localID ^ targetID;
    std::lock_guard<std::mutex> lck(_guard);
    int nActNum = 0;
    list<CKBNode>::iterator iter;
    for (int k = 0; k < KBUCKRT_NUM; k++)
    {
        for (iter = m_vecBuckets[k].begin(); iter != m_vecBuckets[k].end();)
        {
            CUInt128 r = (*iter).m_id ^ targetID;
            if (r < rs)
            {
                if (nActNum < nNum)
                {
                    vecResult.push_back((*iter).m_id);
                    nActNum++;
                }
                if (nActNum >= nNum)
                    break;
            }
            ++iter;
        }
        k++;
    }
    if (nActNum <= 0)
    {
        for (int k = 0; k < KBUCKRT_NUM; k++)
        {
            for (iter = m_vecBuckets[k].begin(); iter != m_vecBuckets[k].end();)
            {
                vecResult.push_back((*iter).m_id);
                nActNum++;
                ++iter;
                if (nActNum >= nNum)
                    break;
            }
            if (nActNum >= nNum)
                break;
        }
    }
    return nActNum;
}
//
int CKBuckets::PickPullNodes(int nNum, vector<CUInt128>& vecResult)
{
    //
    string str = HCNode::generateNodeId();
    CUInt128 targetID = CUInt128(str);
    return PickNeighbourNodes(nNum, targetID, vecResult);
}
int CKBuckets::GetAllNodes(vector<CUInt128>& vecResult)
{
    std::lock_guard<std::mutex> lck(_guard);
    int nActNum = 0;
    list<CKBNode>::iterator iter;
    for (int k = 0; k < KBUCKRT_NUM; k++)
    {
        for (iter = m_vecBuckets[k].begin(); iter != m_vecBuckets[k].end(); iter++)
        {
            vecResult.push_back((*iter).m_id);
            nActNum++;
        }
        // cout << "k = " << k << "   total nodes = " << nActNum << endl;
    }
    return nActNum;
}

size_t CKBuckets::GetNodesNum()
{
    size_t nActNum = 0;
    for (int k = 0; k < KBUCKRT_NUM; k++)
        nActNum += m_vecBuckets[k].size();
    return nActNum;
}

bool CKBuckets::IsNodeInKBuckets(CUInt128 nID)
{
    int kBK = LocateKBucker(nID);
    std::lock_guard<std::mutex> lck(_guard);
    list<CKBNode>::iterator iter;
    for (iter = m_vecBuckets[kBK].begin(); iter != m_vecBuckets[kBK].end(); iter++)
    {
        if ((*iter).m_id == nID)
            return true;
    }
    return false;
}

//
int CKBuckets::PickNodesRandomly(int nNum, vector<CUInt128>& vecResult)
{
    return 0;
}

//
int CKBuckets::PickLastActiveNodes(int nMinutes, int nNum, vector<CUInt128>& vecResult)
{
    using minutes = std::chrono::duration<double, ratio<60>>;
    system_clock::time_point curr = system_clock::now();

    std::lock_guard<std::mutex> lck(_guard);
    int nActNum = 0;
    list<CKBNode>::iterator iter;
    for (int k = 0; k < KBUCKRT_NUM; k++)
    {
        for (iter = m_vecBuckets[k].begin(); iter != m_vecBuckets[k].end(); iter++)
        {
            minutes timespan = std::chrono::duration_cast<minutes>(curr - (*iter).m_lastTime);
            if (timespan.count() < nMinutes)
            {
                vecResult.push_back((*iter).m_id);
                nActNum++;
                if (nActNum >= nNum)
                    break;
            }
        }
        if (nActNum >= nNum)
            break;
    }
    return nActNum;
}
