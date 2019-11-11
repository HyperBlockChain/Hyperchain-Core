/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/
#include "HyperchainDB.h"
#include "../node/Singleton.h"

T_HYPERBLOCK& HyperBlockDB::GetHyperBlock()
{
    return hyperBlock;
}

LocalChainDB& HyperBlockDB::GetMapLocalChain()
{
    return mapLocalChain;
}

int CHyperchainDB::saveHyperBlockToDB(const T_HYPERBLOCK& hyperblock)
{
    return Singleton<DBmgr>::instance()->insertHyperblock(hyperblock);
}

int CHyperchainDB::saveHyperBlocksToDB(const vector<T_HYPERBLOCK> &vHyperblock)
{
    for (auto it = vHyperblock.begin(); it != vHyperblock.end(); it++) {
        T_HYPERBLOCK d = *it;
        CHyperchainDB::saveHyperBlockToDB(d);
    }
    return 0;
}

int CHyperchainDB::cleanTmp(HyperchainDB &hyperchainDB)
{
    //
    if (hyperchainDB.size() > 0)
    {
        HyperchainDB::iterator it = hyperchainDB.begin();
        for (; it != hyperchainDB.end(); ++it)
        {
            HyperBlockDB hyperBlock = it->second;
            LocalChainDB mapLocalChain = hyperBlock.mapLocalChain;
            LocalChainDB::iterator itLocalChain = mapLocalChain.begin();
            for (; itLocalChain != mapLocalChain.end(); ++itLocalChain)
            {
                LocalBlockDB localBlock = itLocalChain->second;
                localBlock.erase(localBlock.begin(), localBlock.end());
            }
            mapLocalChain.erase(mapLocalChain.begin(), mapLocalChain.end());
        }

        hyperchainDB.erase(hyperchainDB.begin(), hyperchainDB.end());
    }
    return 0;
}

bool CHyperchainDB::getHyperBlock(T_HYPERBLOCK &h, const T_SHA256 &hhash)
{
    int ret = Singleton<DBmgr>::instance()->getHyperBlock(h, hhash);
    if (ret != 0) {
        return false;
    }
    addLocalBlocks(h);
    if (!h.verify()) {
        std::printf("Invalid hyper block: %llu in my storage\n", h.GetID());
        return false;
    }
    return true;
}

bool CHyperchainDB::getHyperBlock(T_HYPERBLOCK &h, uint64 hid)
{
    std::list<T_HYPERBLOCK> queue;
    Singleton<DBmgr>::instance()->getHyperBlocks(queue, hid, hid);
    if (queue.size() == 0) {
        return false;
    }
    h = queue.front();
    addLocalBlocks(h);

    if (!h.verify()) {
        std::printf("Invalid hyper block: %llu in my storage\n", hid);
        return false;
    }
    return true;
}

void CHyperchainDB::addLocalBlocks(T_HYPERBLOCK &h)
{
    LIST_T_LOCALBLOCK localblocklist;
    LIST_T_LOCALBLOCK childchain;
    int chainnum = -1;
    Singleton<DBmgr>::instance()->getLocalBlocks(localblocklist, h.GetID());
    for (auto & l : localblocklist) {

        if (chainnum == -1) {
            chainnum = l.GetChainNum();
        }
        if (chainnum != l.GetChainNum()) {
            //
            h.AddChildChain(std::move(childchain));
            childchain.clear();
            chainnum = l.GetChainNum();
        }
        childchain.push_back(std::move(l));
    }
    if (!childchain.empty()) {
        h.AddChildChain(std::move(childchain));
    }
}

//
uint64 CHyperchainDB::GetLatestHyperBlockNo()
{
    return Singleton<DBmgr>::instance()->getLatestHyperBlockNo();
}



