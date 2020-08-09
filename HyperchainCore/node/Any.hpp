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
#pragma once
#include <memory>
#include <typeindex>
#include <exception>
#include <iostream>
#include <sstream>
using namespace std;

struct Any
{
    Any(void) : m_tpIndex(std::type_index(typeid(void))) {}
    Any(const Any& that) : m_ptr(that.Clone()), m_tpIndex(that.m_tpIndex) {}
    Any(Any && that) : m_ptr(std::move(that.m_ptr)), m_tpIndex(that.m_tpIndex) {}

    template<typename U, class = typename std::enable_if<!std::is_same<typename std::decay<U>::type, Any>::value, U>::type> Any(U && value) : m_ptr(new Derived < typename std::decay<U>::type>(std::forward<U>(value))),
        m_tpIndex(std::type_index(typeid(typename std::decay<U>::type))) {}

    bool IsNull() const { return !bool(m_ptr); }

    template<class U> bool Is() const
    {
        return m_tpIndex == std::type_index(typeid(U));
    }
    template<class U> bool IsBaseOf() const
    {
        return m_tpIndex == std::type_index(typeid(U));
    }

    template<class U>
    U& AnyCast()
    {
        if (!Is<U>()) {
            cout << "can not cast " << typeid(U).name() << " to " << m_tpIndex.name() << std::endl;
            throw std::logic_error{ "bad cast" };
        }


        auto derived = dynamic_cast<Derived<U>*> (m_ptr.get());
        return derived->m_value;
    }

    Any& operator=(const Any& a)
    {
        if (m_ptr == a.m_ptr)
            return *this;

        m_ptr = a.Clone();
        m_tpIndex = a.m_tpIndex;
        return *this;
    }

private:
    struct Base;
    typedef std::unique_ptr<Base> BasePtr;

    struct Base
    {
        virtual ~Base() {}
        virtual BasePtr Clone() const = 0;
    };

    template<typename T>
    struct Derived : Base
    {
        template<typename U>
        Derived(U && value) : m_value(std::forward<U>(value)) { }

        BasePtr Clone() const
        {
            return BasePtr(new Derived<T>(m_value));
        }

        T m_value;
    };

    BasePtr Clone() const
    {
        if (m_ptr != nullptr)
            return m_ptr->Clone();

        return nullptr;
    }

    BasePtr m_ptr;
    std::type_index m_tpIndex;
};
