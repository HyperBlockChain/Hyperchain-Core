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
#include "KBuckets.h"
#include "HCNode.h"
#include <random>



int KBUCKRT_NUM = 256;
int KNODE_NUM = 10;


CKBNode::CKBNode(const CUInt128& id)
{
    m_id = id;
    m_lastTime = system_clock::now();
}

CKBuckets::~CKBuckets()
{
    for (int k = 0; k < KBUCKRT_NUM; k++)
        m_vecBuckets[k].clear();
    m_vecBuckets.clear();
    m_setNodes.clear();
}


void CKBuckets::InitKbuckets(CUInt128 myID)
{
    m_localID = myID;
    m_vecBuckets.resize(KBUCKRT_NUM);
}

bool CKBuckets::AddNode(CUInt128 nID, CUInt128& nRemoveID)
{
    int kBK = LocateKBucket(nID);
    

    for (auto iter = m_vecBuckets[kBK].begin(); iter != m_vecBuckets[kBK].end(); iter++) {
        if (iter->m_id == nID) {
            m_vecBuckets[kBK].erase(iter);
            break;
        }
    }

    m_vecBuckets[kBK].push_front(CKBNode(nID));
    m_setNodes.insert(nID);

    if (m_vecBuckets[kBK].size() > KNODE_NUM) {
        nRemoveID = m_vecBuckets[kBK].back().m_id;
        m_vecBuckets[kBK].pop_back();
        m_setNodes.erase(nRemoveID);
        return false;
    }

    return true;
}

void CKBuckets::RemoveNode(CUInt128 nID)
{
    int kBK = LocateKBucket(nID);
    if (kBK >= m_vecBuckets.size()) {
        return;
    }
    for (auto iter = m_vecBuckets[kBK].begin(); iter != m_vecBuckets[kBK].end(); iter++) {
        if (iter->m_id == nID) {
            m_vecBuckets[kBK].erase(iter);
            m_setNodes.erase(nID);
            break;
        }
    }
}

std::set<CUInt128> CKBuckets::PickRandomNodes(int nNum)
{
    std::set<CUInt128> setResult;

    if (m_setNodes.size() <= nNum)
        return m_setNodes;

    std::default_random_engine e(time(0));
    std::uniform_int_distribution<int> u(0, m_setNodes.size() - 1);

    while (setResult.size() < nNum){
        auto iter = m_setNodes.begin();
        advance(iter, u(e));
        setResult.insert(*iter);
    }
    return setResult;
}

vector<CUInt128> CKBuckets::PickNeighbourNodes(CUInt128 targetID, int nNum)
{
    int kBK = LocateKBucket(targetID);
    int rk = kBK;
    int lk = kBK;
    int nActNum = 0;
    vector<CUInt128> vecResult;

    int nKBucket = m_vecBuckets.size();
    while ((rk < KBUCKRT_NUM || lk > 0) && nActNum < nNum) {
        

        if (nKBucket > rk && rk < KBUCKRT_NUM) {
            for (auto Riter = m_vecBuckets[rk].begin(); Riter != m_vecBuckets[rk].end() && nActNum < nNum; Riter++, nActNum++)
                vecResult.push_back(Riter->m_id);
        }
        rk++;

        

        if (nKBucket > lk && lk > 0) {
            lk--;
            for (auto Liter = m_vecBuckets[lk].begin(); Liter != m_vecBuckets[lk].end() && nActNum < nNum; Liter++, nActNum++)
                vecResult.push_back(Liter->m_id);
        }
        else {
            lk--;
        }
    }

    return vecResult;
}

vector<CUInt128> CKBuckets::PickLastActiveNodes(CUInt128 targetID, int nNum, int nMinutes)
{
    int kBK = LocateKBucket(targetID);
    int rk = kBK;
    int lk = kBK;
    int nActNum = 0;
    std::chrono::minutes timespan;
    system_clock::time_point curr = system_clock::now();
    vector<CUInt128> vecResult;

    int nKBucket = m_vecBuckets.size();
    while ((rk < KBUCKRT_NUM || lk > 0) && nActNum < nNum) {
        

        if (nKBucket > rk && rk < KBUCKRT_NUM) {
            for (auto Riter = m_vecBuckets[rk].begin(); Riter != m_vecBuckets[rk].end() && nActNum < nNum; Riter++) {
                timespan = std::chrono::duration_cast<std::chrono::minutes>(curr - Riter->m_lastTime);
                if (timespan.count() > nMinutes)
                    continue;

                vecResult.push_back(Riter->m_id);
                nActNum++;
            }
        }
        rk++;

        

        if (nKBucket > lk && lk > 0) {
            lk--;
            for (auto Liter = m_vecBuckets[lk].begin(); Liter != m_vecBuckets[lk].end() && nActNum < nNum; Liter++) {
                timespan = std::chrono::duration_cast<std::chrono::minutes>(curr - Liter->m_lastTime);
                if (timespan.count() > nMinutes)
                    continue;

                vecResult.push_back(Liter->m_id);
                nActNum++;
            }
        }
        else {
            lk--;
        }
    }

    return vecResult;
}

std::set<CUInt128> CKBuckets::GetAllNodes()
{
    return m_setNodes;
}

int CKBuckets::GetNodesNum()
{
    return m_setNodes.size();
}

bool CKBuckets::IsNodeInKBuckets(CUInt128 nID)
{
    return m_setNodes.count(nID);
}

int CKBuckets::LocateKBucket(CUInt128 nID)
{
    CUInt128 r = m_localID ^ nID;
    r >>= 120;
    return r.Lower64();
}