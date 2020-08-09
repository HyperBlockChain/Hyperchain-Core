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

#include <stdint.h>
#include <string>





typedef struct tagProtocolVer
{
    enum class NET : char {
        SAND_BOX = 0xD,
        INFORMAL_NET = 0xE,
        FORMAL_NET = 0xF,
    };

    union {
        struct {
            uint8_t ver_low;
            uint8_t ver_high : 4;
            uint8_t net_type : 4;
        };
        uint16_t ver = 0;
    };

    tagProtocolVer() : ver(0)
    {}

    tagProtocolVer(uint16_t v) : ver(v)
    {}

    explicit tagProtocolVer(const char *buf) : ver(*(uint16_t*)buf)
    {}

    tagProtocolVer& operator=(NET n)
    {
        net_type = static_cast<char>(n) & 0x0f;
        return *this;
    }



    //static inline void setNetType(char *buf, NET n)
    //{
    //    *buf = (*buf & 0x0f) | (static_cast<char>(n) << 4) ;
    //}



    static void setVerNetType(char *buf, NET n);

    bool checkVersion();

    static std::string getString();

    inline NET net() { return static_cast<NET>(net_type & 0x0f); }

    inline bool operator==(NET n)
    {
        return static_cast<NET>(net_type & 0x0f) == n;
    }

    friend inline bool operator<(const tagProtocolVer &a, const tagProtocolVer &b)
    {
        if (a.ver_high != b.ver_high) {
            return a.ver_high < b.ver_high;
        }

        if (a.ver_low != b.ver_low) {
            return a.ver_low < b.ver_low;
        }
        return false;
    }

    friend inline bool operator>=(const tagProtocolVer &a, const tagProtocolVer &b)
    {
        return !(a < b);
    }

} ProtocolVer;


