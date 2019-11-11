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

#include <sstream>
#include <string>
using namespace std;

class CAutoBuffer
{
protected:
    stringstream ss;
    short state;
    short exceptmask;
public:
    int nType;
    int nVersion;

    CAutoBuffer(string &&buffer,int nTypeIn= SER_BUDDYCONSENSUS, int nVersionIn=VERSION) : ss(std::forward<string>(buffer))
    {
        nType = nTypeIn;
        nVersion = nVersionIn;
        state = 0;
        exceptmask = std::ios::badbit | std::ios::failbit;
    }

    ~CAutoBuffer() {}

    //
    // Stream subset
    //
    void setstate(short bits, const char* psz)
    {
        state |= bits;
        if (state & exceptmask)
            throw std::ios_base::failure(psz);
    }

    bool fail() const            { return state & (std::ios::badbit | std::ios::failbit); }
    bool good() const            { return state == 0; }
    void clear(short n = 0)      { state = n; }
    short exceptions()           { return exceptmask; }
    short exceptions(short mask) { short prev = exceptmask; exceptmask = mask; setstate(0, "CAutoBuffer"); return prev; }

    void SetType(int n)          { nType = n; }
    int GetType()                { return nType; }
    void SetVersion(int n)       { nVersion = n; }
    int GetVersion()             { return nVersion; }
    void ReadVersion()           { *this >> nVersion; }
    void WriteVersion()          { *this << nVersion; }

    CAutoBuffer& seekg(int nOffset)
    {
        ss.seekg(nOffset);
        if (!ss.good()) {
            setstate(std::ios::failbit, "CAutoBuffer::seekg : seekg failed");
        }
        return (*this);
    }

    CAutoBuffer& read(char* pch, int nSize)
    {
        ss.read(pch, nSize);
        int n = ss.gcount();
        if (n != nSize)
            setstate(std::ios::failbit, ss.eof() ? "CAutoBuffer::read : end of file" : "CAutoBuffer::read : fread failed");
        return (*this);
    }

    CAutoBuffer& write(const char* pch, int nSize)
    {
        ss.write(pch, nSize);
        if (!ss.good()) {
            setstate(std::ios::failbit, "CAutoBuffer::write : write failed");
        }
        return (*this);
    }

    template<typename T>
    unsigned int GetSerializeSize(const T& obj)
    {
        // Tells the size of the object if serialized to this stream
        return ::GetSerializeSize(obj, nType, nVersion);
    }

    template<typename T>
    CAutoBuffer& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }

    template<typename T>
    CAutoBuffer& operator>>(T& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj, nType, nVersion);
        return (*this);
    }
};
