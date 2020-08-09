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

#include "ProtocolVer.h"

#include <assert.h>
#include "IDGenerator.h"
#include "UInt128.h"




static const ProtocolVer ProtocolVersion = 100;
static const ProtocolVer ProtocolVersionUpper = 200;
static const ProtocolVer ProtocolVersionLower = 100;

bool ProtocolVer::checkVersion()
{
    if (*this < ProtocolVersionUpper && *this >= ProtocolVersionLower)
        return true;
    return false;
}

void ProtocolVer::setVerNetType(char *buf, NET n)
{
    ProtocolVer *v = reinterpret_cast<ProtocolVer*>(buf);
    *v = ProtocolVersion;

    //Net type
    *(buf + 1) = (*(buf + 1) & 0x0f) | (static_cast<char>(n) << 4);
}

std::string ProtocolVer::getString()
{
    int v = ProtocolVersion.ver_high << 4 | ProtocolVersion.ver_low;
    int v_u = ProtocolVersionUpper.ver_high << 4 | ProtocolVersionUpper.ver_low;
    int v_l = ProtocolVersionLower.ver_high << 4 | ProtocolVersionLower.ver_low;

    char info[128] = {0};
    std::snprintf(info, 128, "%d, upper: %d  lower: %d", v, v_u, v_l);

    return info;
}
