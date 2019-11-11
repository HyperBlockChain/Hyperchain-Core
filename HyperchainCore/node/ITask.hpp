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

#include <assert.h>
#include "IDGenerator.h"
#include "UInt128.h"
#include <string.h>

#include <memory>
using namespace std;

enum class TASKTYPE :char
{
    BASETYPE = 0,
    HYPER_CHAIN_SEARCH,
    HYPER_CHAIN_SEARCH_RSP,

    ON_CHAIN,
    ON_CHAIN_RSP,
    ON_CHAIN_CONFIRM,
    ON_CHAIN_CONFIRM_RSP,

    COPY_BLOCK,

    ON_CHAIN_REFUSE,
    ON_CHAIN_WAIT,

    GLOBAL_BUDDY_START_REQ,
    GLOBAL_BUDDY_SEND_REQ,
    GLOBAL_BUDDY_RSP,
    BOARDCAST_HYPER_BLOCK,
    GET_HYPERBLOCK_BY_NO_REQ,
    GET_HEADERHASH_BY_NO_REQ,
    GET_HEADERHASH_BY_NO_RSP,

    HYPER_CHAIN_SPACE_PULL,
    HYPER_CHAIN_SPACE_PULL_RSP,
	HYPER_CHAIN_HYPERDATA_PULL,
	HYPER_CHAIN_HYPERDATA_PULL_RSP,
    SEARCH_NEIGHBOUR,
    SEARCH_NEIGHBOUR_RSP,

	PING_PONG,
	PING_PONG_RSP,
	
    //
    LEDGE,
    LEDGE_RSP,
    LEDGE_PING_NODE,
    LEDGE_PING_NODE_RSP,

    //
    PARACOIN,
	PARACOIN_RSP,
    PARA_PING_NODE,
    PARA_PING_NODE_RSP,

    APP_CHAIN,
    APP_CHAIN_RSP,
    APP_ACTION
};

using TASKBUF = std::shared_ptr<string>;
using ProtocolVer = uint16_t;
const size_t ProtocolHeaderLen = CUInt128::value + sizeof(ProtocolVer) + sizeof(TASKTYPE);

class ITask
{
public:
    ITask() {}
    ITask(TASKBUF && recvbuf) : _isRespond(true), _recvbuf(std::move(recvbuf)) {

        uint8_t ut[CUInt128::value];
        memcpy(ut, _recvbuf->c_str(), CUInt128::value);
        _sentnodeid = CUInt128(ut);
        _ver = *(ProtocolVer*)(_recvbuf->c_str() + CUInt128::value);
        _payload = _recvbuf->c_str() + ProtocolHeaderLen;
        _payloadlen = _recvbuf->size() - ProtocolHeaderLen;
    }

    virtual ~ITask() {}
    virtual void exec() = 0;
    virtual void execRespond() = 0;

    bool isRespond() { return _isRespond; }

protected:
    bool _isRespond = false;
    const char * _payload = nullptr;
    size_t _payloadlen = 0;
    CUInt128 _sentnodeid;
    ProtocolVer _ver = 0;

private:
    TASKBUF _recvbuf;
};
