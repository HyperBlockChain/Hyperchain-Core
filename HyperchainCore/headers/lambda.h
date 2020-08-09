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
#ifndef __LAMBDA_H__

#define __LAMBDA_H__

#include "../headers/commonstruct.h"

struct Cmpare
{
    bool operator()(const T_PPEERINFO &st1, const T_PPEERINFO  &st2) const
    {
        return (st1->GetTime() < st2->GetTime());
    }
};


struct CmpareRecvLocalBuddyReq
{
    bool operator()(const T_BUDDYINFO &st1, const T_BUDDYINFO &st2) const
    {
        return (st1.GetType() < st2.GetType());
    }
};

struct CmpareOnChain
{
    bool operator()(const T_LOCALCONSENSUS &st1, const T_LOCALCONSENSUS  &st2) const
    {
        return (st1.GetLocalBlock().GetUUID() < st2.GetLocalBlock().GetUUID());
    }
};
struct CmpareOnChainLocal
{
    bool operator()(const T_LOCALBLOCK &st1, const T_LOCALBLOCK &st2) const
    {
        return (st1.GetUUID() < st2.GetUUID());
    }
};

struct CmpareGlobalBuddy
{
    bool operator()(const LIST_T_LOCALCONSENSUS &st1, const LIST_T_LOCALCONSENSUS  &st2) const
    {
        auto itr1 = st1.begin();
        auto itr2 = st2.begin();

        return ((*itr1).GetLocalBlock().GetUUID() < (*itr2).GetLocalBlock().GetUUID());
    }
};


#endif