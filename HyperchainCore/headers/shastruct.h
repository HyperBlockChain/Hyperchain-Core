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
#ifndef __SHA_STRUCT_H__

#define __SHA_STRUCT_H__

#include "includeComm.h"

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/array.hpp>
#include <boost/serialization/version.hpp>

#include <string>
#include <array>

using namespace std;

typedef struct _tsha256
{
    array<unsigned char, DEF_SHA256_LEN> pID;

    _tsha256() {}

    _tsha256(int nNum)
    {
        pID.fill(nNum);
    }

    _tsha256(const unsigned char sha[DEF_SHA256_LEN])
    {
        for (int i = 0; i < DEF_SHA256_LEN; i++)
            pID[i] = sha[i];
    }

    _tsha256(const string sha)
    {
        for (int i = 0; i < DEF_SHA256_LEN; i++)
            pID[i] = sha[i];
    }

    _tsha256(const _tsha256&sha)
    {
        for (int i = 0; i < DEF_SHA256_LEN; i++)
            pID[i] = sha.pID[i];
    }

    _tsha256 operator = (const _tsha256& arRes)
    {
        if (this != &arRes) {
            for (int i = 0; i < DEF_SHA256_LEN; i++)
                pID[i] = arRes.pID[i];
        }
        return *this;
    }

    bool operator == (const _tsha256& arRes) const
    {
        if (this == &arRes)
            return true;

        for (int i = 0; i < DEF_SHA256_LEN; i++) {
            if (pID[i] != arRes.pID[i])
                return false;
        }
        return true;
    }

    bool operator != (const _tsha256& arRes) const
    {
        return !(*this == arRes);
    }

    bool operator < (const _tsha256& arRes) const
    {
        if (this == &arRes)
            return false;

        for (int i = 0; i < DEF_SHA256_LEN; i++) {
            if (pID[i] < arRes.pID[i]) {
                return true;
            }
            else if (pID[i] == arRes.pID[i]) {
                continue;
            }
            else
                return false;

        }
        return false;
    }

    bool operator > (const _tsha256& arRes) const
    {
        if (this == &arRes)
            return false;

        for (int i = 0; i < DEF_SHA256_LEN; i++) {
            if (pID[i] > arRes.pID[i]) {
                return true;
            }
            else if (pID[i] == arRes.pID[i]) {
                continue;
            }
            else
                return false;
        }
        return false;
    }

    void SetInit(int nNum)
    {
        pID.fill(nNum);
    }

    inline unsigned char* data() { return pID.data(); }
    inline const unsigned char* data() const { return pID.data(); }
    inline size_t size() const { return DEF_SHA256_LEN; }

    string tostring() const
    {
        return string((const char*)pID.data(), DEF_SHA256_LEN);
    }
    string toHexString() const
    {
        char ucBuf[DEF_SHA256_LEN * 2 + 1] = { 0 };

        unsigned int uiNum = 0;
        char *p = ucBuf;
        for (; uiNum < DEF_SHA256_LEN; uiNum++) {
            sprintf(p, "%02x", pID[uiNum]);
            p += 2;
        }
        return string(ucBuf);
    }
    bool isNull() {
        char test[DEF_SHA256_LEN] = { 0 };
        if (memcmp(pID.data(),test,DEF_SHA256_LEN) == 0) {
            return true;
        }
        return false;
    }
private:
    friend class boost::serialization::access;
    template <typename Archive>
    void serialize(Archive &ar, unsigned int version)
    {
        ar & boost::serialization::make_array(pID.data(), DEF_SHA256_LEN);
    }

}T_SHA256, *T_PSHA256;
BOOST_CLASS_VERSION(T_SHA256, 0)

typedef struct _tsha512
{
    array<unsigned char, DEF_SHA512_LEN> pID;

    _tsha512()
    {
    }

    _tsha512(int nNum)
    {
        pID.fill(nNum);
    }

    _tsha512 operator = (const _tsha512& arRes)
    {
        if (this != &arRes) {
            for (int i = 0; i < DEF_SHA512_LEN; i++)
                pID[i] = arRes.pID[i];
        }
        return *this;
    }

    bool operator == (const _tsha512& arRes) const
    {
        if (this == &arRes)
            return true;

        for (int i = 0; i < DEF_SHA512_LEN; i++) {
            if (pID[i] != arRes.pID[i])
                return false;
        }
        return true;
    }

    bool operator < (const _tsha512& arRes) const
    {
        if (this == &arRes)
            return false;

        for (int i = 0; i < DEF_SHA512_LEN; i++) {
            if (pID[i] < arRes.pID[i]) {
                return true;
            }
            else if (pID[i] == arRes.pID[i]) {
                continue;
            }
            else
                return false;

        }
        return false;
    }

    bool operator > (const _tsha512& arRes)
    {
        if (this == &arRes)
            return false;

        for (int i = 0; i < DEF_SHA512_LEN; i++) {
            if (pID[i] > arRes.pID[i]) {
                return true;
            }
            else if (pID[i] == arRes.pID[i]) {
                continue;
            }
            else
                return false;

        }
        return false;
    }
    void SetInit(int nNum)
    {
        pID.fill(nNum);
    }

    bool isNull() {
        char test[DEF_SHA512_LEN] = { 0 };
        if (memcmp(pID.data(),test,DEF_SHA512_LEN) == 0) {
            return true;
        }
        return false;
    }

    inline unsigned char* data() { return pID.data(); }

}T_SHA512, *T_PSHA512;

#endif