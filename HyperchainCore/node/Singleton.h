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


#ifndef _SINGLETON_H
#define _SINGLETON_H

template<typename T, typename... Args>
class Singleton {
public:
    static T* instance(Args... args)
    {
        if (_instance == nullptr) {
            _instance = new T(args...);
            return _instance;
        }
        return _instance;
    }

    static T* getInstance() {
        return _instance;
    }

    static void setInstance(T* t) {
        _instance = t;
    }

    static void releaseInstance() {
        if (_instance == nullptr) {
            return;
        }
        delete _instance;
        _instance = nullptr;
    }
private:
    Singleton(void) {};
    ~Singleton(void) {};
    Singleton(const Singleton&) = delete;
    void operator=(const Singleton&) = delete;

private:
    static T* _instance;

};


template<typename T, typename... Args>
T* Singleton<T, Args...>::_instance = nullptr;
#endif //_SINGLETON_H