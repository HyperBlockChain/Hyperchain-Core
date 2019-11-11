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
#include<string>
#include<unordered_map>
#include<memory>
#include<functional>
#include <mutex>
using namespace std;

#include "Any.hpp"
#include "NonCopyable.hpp"

class objectFactory : NonCopyable
{
public:
    objectFactory(void) {}
    ~objectFactory(void) {}

    template<class T, class Derived, typename... Args>
    bool RegisterType(uint32_t ukey)
    {
        return RegisterType<T, Derived, Args...>(to_string(ukey));
    }

    template<class T, class Derived, typename... Args>
    bool RegisterType(const string& key)
    {
        std::function<T* (Args...)> function = [](Args... args) { return new Derived(std::forward<Args>(args)...); };
        return RegisterType(key, function);
    }

    template<class T, class Derived, typename... Args>
    void UnregisterType(uint32_t ukey)
    {
        UnregisterType<T, Derived, Args...>(to_string(ukey));
    }

    template<class T, class Derived, typename... Args>
    void UnregisterType(const string& key)
    {
        UnregisterType(key);
    }

    template<class T, typename... Args>
    T* Create(uint32_t ukey, Args... args)
    {
        return Create<T, Args...>(to_string(ukey), std::forward<Args>(args)...);
    }

    template<class T, typename... Args>
    T* Create(const string & key, Args... args)
    {
        if (m_creatorStringMap.find(key) == m_creatorStringMap.end())
            return nullptr;

        Any resolver = m_creatorStringMap[key];
        std::function<T* (Args...)> function = resolver.AnyCast<std::function<T* (Args...)>>();

        return function(args...);
    }

    template<class T, typename... Args>
    std::shared_ptr<T> CreateShared(uint32_t ukey, Args... args)
    {
        return CreateShared<T, Args...>(to_string(ukey), std::forward<Args>(args)...);
    }

    template<class T, typename... Args>
    std::shared_ptr<T> CreateShared(const string & key, Args... args)
    {
        T* t = Create<T>(key, args...);
        return std::shared_ptr<T>(t);
    }

private:

    bool RegisterType(const string & strKey, Any constructor)
    {
        std::unique_lock<std::mutex> lck(m_creatorGuard);
        if (m_creatorStringMap.find(strKey) != m_creatorStringMap.end())
            throw std::invalid_argument("this key has already exist!");

        m_creatorStringMap.emplace(strKey, constructor);
        return true;
    }

    void UnregisterType(const string & strKey)
    {
        std::unique_lock<std::mutex> lck(m_creatorGuard);
        if (m_creatorStringMap.count(strKey)) {
            m_creatorStringMap.erase(strKey);
        }
    }

private:
    std::mutex m_creatorGuard;
    unordered_map<string, Any> m_creatorStringMap;
};

