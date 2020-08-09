/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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

#ifndef __MUTEX_OBJ_H__
#define __MUTEX_OBJ_H__

//#include "includeComm.h"
#ifdef WIN32
//#include <WinBase.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <semaphore.h>
#include <pthread.h>
#include <unistd.h>
#endif// WIN32


class CMutexObj
{
public:
	CMutexObj();
	~CMutexObj();

	void  Lock();
	void UnLock();

private:
	//windows OS
#ifdef WIN32
	CRITICAL_SECTION	m_oSection;
#else
	pthread_mutex_t m_hMutex;
#endif

};


class CAutoMutexLock
{
public:
    CAutoMutexLock(CMutexObj& aCriticalSection);
    ~CAutoMutexLock();
    void lock();
    void unlock();
private:
    CMutexObj& m_oCriticalSection;
    bool m_islocked = false;
};

class semaphore_t{
public:
	semaphore_t();
	~semaphore_t();
	int wait(bool bBlock = true);
	void signal(int nCount = 1);
	int getvalue(int * value);
private:
#ifdef _WIN32
	HANDLE	m_sem;
	int     m_value;
#else
	sem_t	m_sem;
#endif
};

#endif // __MUTEX_OBJ_H__
