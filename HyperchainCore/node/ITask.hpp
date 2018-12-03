/*Copyright 2016-2018 hyperchain.net (Hyperchain)

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

typedef enum
{
	BASETYPE = 0,
	HYPER_CHAIN_SEARCH,
	HYPER_CHAIN_SEARCH_RSP,
	HYPER_CHAIN_UP,
	HYPER_CHAIN_UP_RSP,
	HYPER_CHAIN_SPACE_PULL,
	HYPER_CHAIN_SPACE_PULL_RSP,
	HYPER_CHAIN_HYPERDATA_PULL,
	HYPER_CHAIN_HYPERDATA_PULL_RSP,
	SEARCH_NEIGHBOUR,
	SEARCH_NEIGHBOUR_RSP,
} TASKTYPE;

using TASKBUF = shared_ptr<string>;

class ITask
{
public: 
	ITask() {}
	ITask(TASKBUF && recvbuf) : _isRespond(true), _recvbuf(std::move(recvbuf)) {

		size_t prefixlen = CUInt128::value + sizeof(TASKTYPE);

		string id(_recvbuf->c_str(), CUInt128::value);
		_sentnodeid.SetHexString(id);

		_payload = _recvbuf->c_str() + prefixlen;
		_payloadlen = _recvbuf->size() - prefixlen;
	}

	virtual ~ITask() {}
	virtual void exec() = 0;
	virtual void execRespond() = 0;
	
	bool isRespond() { return _isRespond; }
protected:
	template<typename T>
	typename std::enable_if<std::is_base_of<ITask,T>::value>::type 
		attachTaskMetaHead(string &msgbuf) 
	{
		TASKTYPE t = T::value;
		msgbuf.insert(0,(char*)&(t),sizeof(TASKTYPE));
	}

protected:
	bool _isRespond = false;

	const char * _payload = nullptr;
	size_t _payloadlen = 0;
	CUInt128 _sentnodeid;

private:

	TASKBUF _recvbuf;
};
