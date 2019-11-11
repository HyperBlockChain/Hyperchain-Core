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
                                                
#include "MutexObj.h"


CMutexObj::CMutexObj()
{
#ifdef WIN32
	InitializeCriticalSection(&m_oSection);
#else
	//m_hMutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
	//pthread_mutex_init(&m_hMutex,NULL);
	pthread_mutexattr_t   attr;   
	pthread_mutexattr_init(&attr);   
	pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);   
	pthread_mutex_init(&m_hMutex,&attr);
#endif
}

CMutexObj::~CMutexObj()
{
#ifdef WIN32
	DeleteCriticalSection(&m_oSection);
#else
	pthread_mutex_destroy(&m_hMutex);
#endif
}

void  CMutexObj::Lock()
{
#ifdef WIN32
	EnterCriticalSection(&m_oSection);
#else
	pthread_mutex_lock(&m_hMutex);
#endif
}

void CMutexObj::UnLock()
{
#ifdef WIN32
	LeaveCriticalSection(&m_oSection);
#else
	pthread_mutex_unlock(&m_hMutex);
#endif
};

CAutoMutexLock::CAutoMutexLock(CMutexObj& aCriticalSection) :m_oCriticalSection(aCriticalSection)
{
    lock();
}

CAutoMutexLock::~CAutoMutexLock()
{
    unlock();
}

void CAutoMutexLock::lock()
{
    if (!m_islocked) {
        m_oCriticalSection.Lock();
        m_islocked = true;
    }
}

void CAutoMutexLock::unlock()
{
    if (m_islocked) {
        m_oCriticalSection.UnLock();
        m_islocked = false;
    }
}

//semaphore_t
#ifdef _WIN32
#define SAFE_CLOSE_HANDLE(h) if(h){::CloseHandle(h);h=0;}
#endif

semaphore_t::semaphore_t(){
#ifdef _WIN32
	m_sem = ::CreateSemaphore(0, 0, 0x7fffffff, 0);
	m_value = 0;
#else
	::sem_init(&m_sem, 0, 0);
#endif
}

semaphore_t::~semaphore_t(){
#ifdef _WIN32
	SAFE_CLOSE_HANDLE(m_sem);
	m_value = 0;
#else
	::sem_destroy(&m_sem);
#endif
}

int semaphore_t::wait(bool bBlock)
{
#ifndef _WIN32
	if (bBlock)
		return ::sem_wait(&m_sem);
	else
		return ::sem_trywait(&m_sem);
#else
	if (m_sem == 0)
		return -1;
	m_value--;
	return ::WaitForSingleObject(m_sem, bBlock ? INFINITE : 0);
#endif
}

void semaphore_t::signal(int nCount)
{
	if (nCount <= 0)
		return;
#ifdef _WIN32
	if (m_sem){
		long value;
		if (ReleaseSemaphore(m_sem, nCount, &value))
			m_value = value + nCount;
	}
#else
	for (int i = 0; i < nCount; i++)
		::sem_post(&m_sem);
#endif
}

int semaphore_t::getvalue(int * value)
{
#ifdef _WIN32
	if (m_sem == 0)
		return -1;
	*value = m_value;
	return 0;
#else
	return sem_getvalue(&m_sem, value);
#endif
}