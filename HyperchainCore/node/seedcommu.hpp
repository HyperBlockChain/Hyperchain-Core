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

#include <thread>
using namespace std;

#include "Singleton.h"
#include "NodeManager.h"
#include "SearchNeighbourTask.h"
#include "TaskThreadPool.h"

class SeedCommunication
{
public:
	SeedCommunication() : _isExit(false)
	{}

	~SeedCommunication() {}

	void pullPeerlistFromSeedServer()
	{
		TaskThreadPool *taskpool = Singleton<TaskThreadPool>::getInstance();

		int num = 0;
		while (!_isExit) {
			taskpool->put(make_shared<SearchNeighbourTask>());

			num = 0;
			while (num < 100 && !_isExit) {
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
				++num;
			}
		}
	}

	void start()
	{
		_thread.reset(new std::thread(&SeedCommunication::pullPeerlistFromSeedServer, this));
	}

	void stop()
	{
		_isExit = true;
		if (_thread && _thread->joinable()) {
			_thread->join();
		}
	}

private:
	std::unique_ptr<std::thread> _thread;
	bool _isExit;
};

