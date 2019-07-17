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
#ifndef __HYPERCHAIN_DB_H__
#define __HYPERCHAIN_DB_H__

#pragma once

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

#ifndef _WIN32
# define __STDC_LIMIT_MACROS
# include <stdint.h>
#else
#include <cstdint>
#endif

#include "../db/dbmgr.h"
#include "../headers/inter_public.h"

using namespace std;



//HC: 单条局部块链定义
//HC: uint64:	local block id 局部块id
typedef map<uint64, T_LOCALBLOCK> LocalBlockDB;


//HC: 并行局部链定义
//HC: uint64: local chain num 局部链号

typedef map<uint64, LocalBlockDB> LocalChainDB;


//HC: 超块结构
struct HyperBlockDB
{
    T_HYPERBLOCK hyperBlock;        //HC: 超块链
    LocalChainDB mapLocalChain;     //HC: 局部链（并行)

    T_HYPERBLOCK& GetHyperBlock();
    LocalChainDB& GetMapLocalChain();

};


//HC: 超块链定义

typedef map<uint64, HyperBlockDB> HyperchainDB;

class CHyperchainDB
{
public:
    //HC: 功能函数
    static int cleanTmp(HyperchainDB &hyperchainDB);

public:
    CHyperchainDB();
    ~CHyperchainDB();
public:
    //HC: 保存一条块信息到数据库
    static int saveHyperBlockToDB(const T_HYPERBLOCK& hyperblock);

    //HC: 保存多条块信息到数据库
    static int saveHyperBlocksToDB(const vector<T_HYPERBLOCK> &vHyperblock);

    //HC: 从本地数据库读取块信息
    static bool getHyperBlock(T_HYPERBLOCK &h, uint64 hid);
    static bool getHyperBlock(T_HYPERBLOCK &h, const T_SHA256 &hhash);


    //HC: 获取最新块号
    static uint64 GetLatestHyperBlockNo();

    static int GetHyperBlockNumInfo(std::list<uint64> &HyperBlockNum);

private:
    static void addLocalBlocks(T_HYPERBLOCK &h);

};
#endif //__HYPERCHAIN_DB_H__