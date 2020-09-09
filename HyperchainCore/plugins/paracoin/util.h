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
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#include "uint256.h"

#ifndef __WXMSW__
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <map>
#include <vector>
#include <string>
#include <thread>

#include <boost/thread/thread.hpp>
#include <boost/interprocess/sync/interprocess_recursive_mutex.hpp>
#include <boost/date_time/gregorian/gregorian_types.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include <openssl/sha.h>
#include <openssl/ripemd.h>


#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64  int64;
typedef unsigned __int64  uint64;
#else
typedef int64_t				int64;
typedef uint64_t			uint64;
#endif
#if defined(_MSC_VER) && _MSC_VER < 1300
#define for  if (false) ; else for
#endif
#ifndef _MSC_VER
#define __forceinline  inline
#endif

#define loop                for (;;)
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))
#define printf              OutputDebugStringF

#ifdef snprintf
#undef snprintf
#endif

#ifndef PRI64d

#if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__MSVCRT__)
#define PRI64d  "I64d"
#define PRI64u  "I64u"
#define PRI64x  "I64x"
#else

#define PRI64d  "lld"
#define PRI64u  "llu"
#define PRI64x  "llx"
#endif
#endif

// This is needed because the foreach macro can't get over the comma in pair<t1, t2>
#define PAIRTYPE(t1, t2)    pair<t1, t2>

// Align by increasing pointer, must have extra space at end of buffer
template <size_t nBytes, typename T>
T* alignup(T* p)
{
    union
    {
        T* ptr;
        size_t n;
    } u;
    u.ptr = p;
    u.n = (u.n + (nBytes-1)) & ~(nBytes-1);
    return u.ptr;
}

#ifdef __WXMSW__
#define MSG_NOSIGNAL        0
#define MSG_DONTWAIT        0
#ifndef UINT64_MAX
#define UINT64_MAX          _UI64_MAX
#define INT64_MAX           _I64_MAX
#define INT64_MIN           _I64_MIN
#endif
#ifndef S_IRUSR
#define S_IRUSR             0400
#define S_IWUSR             0200
#endif
#define unlink              _unlink
typedef int socklen_t;
#else
#define WSAGetLastError()   errno
#define WSAEINVAL           EINVAL
#define WSAEALREADY         EALREADY
#define WSAEWOULDBLOCK      EWOULDBLOCK
#define WSAEMSGSIZE         EMSGSIZE
#define WSAEINTR            EINTR
#define WSAEINPROGRESS      EINPROGRESS
#define WSAEADDRINUSE       EADDRINUSE
#define WSAENOTSOCK         EBADF
#define INVALID_SOCKET      (SOCKET)(~0)
#define SOCKET_ERROR        -1
typedef u_int SOCKET;
#define _vsnprintf(a,b,c,d) vsnprintf(a,b,c,d)
#define strlwr(psz)         to_lower(psz)
#define _strlwr(psz)        to_lower(psz)
#define MAX_PATH            1024
#define Beep(n1,n2)         (0)
inline void Sleep(int64 n)
{
    boost::thread::sleep(boost::get_system_time() + boost::posix_time::milliseconds(n));
}
#endif

inline int myclosesocket(SOCKET& hSocket)
{
    if (hSocket == INVALID_SOCKET)
        return WSAENOTSOCK;
#ifdef __WXMSW__
    int ret = closesocket(hSocket);
#else
    int ret = close(hSocket);
#endif
    hSocket = INVALID_SOCKET;
    return ret;
}
#define closesocket(s)      myclosesocket(s)

#ifndef GUI
inline const char* _(const char* psz)
{
    return psz;
}
#endif

extern std::map<std::string, std::string> mapArgs;
extern std::map<std::string, std::vector<std::string> > mapMultiArgs;
extern bool fDebug;
extern bool fPrintToConsole;
extern bool fPrintToDebugFile;

extern bool fPrintBacktracking;
extern bool fPrintBacktracking_node;
extern std::string strBacktracking_node;

extern bool fPrintToDebugger;
extern char pszSetDataDir[MAX_PATH];
extern bool fRequestShutdown;
extern bool fShutdown;
extern bool fExit;
extern bool fDaemon;
extern bool fServer;
extern bool fRPCServerRunning;
extern bool fCommandLine;
extern std::string strMiscWarning;
extern bool fTestNet;
extern bool fNoListen;
extern bool fLogTimestamps;

void RandAddSeed();
void RandAddSeedPerfmon();


int OutputDebugStringF(const char* pszFormat, ...);
std::string strprintf(const char* format, ...);

void LogBacktracking(const char* format, ...);
void LogBacktrackingFromNode(const string &fromnode, const char* format, ...);

#define __format(fmt) "(%s:%d) " fmt

void LogException(std::exception* pex, const char* pszThread);
void PrintException(std::exception* pex, const char* pszThread);
void PrintExceptionContinue(std::exception* pex, const char* pszThread);
void ParseString(const std::string& str, char c, std::vector<std::string>& v);
std::string FormatMoney(int64 n, bool fPlus=false);
bool ParseMoney(const std::string& str, int64& nRet);
bool ParseMoney(const char* pszIn, int64& nRet);
std::vector<unsigned char> ParseHex(const char* psz);
std::vector<unsigned char> ParseHex(const std::string& str);
void AppParseParameters(int argc, char* argv[]);
//const char* wxGetTranslation(const char* psz);
bool WildcardMatch(const char* psz, const char* mask);
bool WildcardMatch(const std::string& str, const std::string& mask);
int GetFilesize(FILE* file);
void GetDataDir(char* pszDirRet);
std::string GetConfigFile();

std::string GetPidFile();
void log_output_nowrap(const char* format, ...);

template<const char* C, bool R>
bool log_output(const char* format, ...)
{
    char buffer[50000];
    int limit = sizeof(buffer);
    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnprintf(buffer, limit, format, arg_ptr);
    va_end(arg_ptr);
    if (ret < 0 || ret >= limit)
    {
        ret = limit - 1;
        buffer[limit - 1] = 0;
    }
    //fprintf(stdout, "%s: %s\n", C, buffer);
    printf("%s: %s\n", C, buffer);
    return R;
}



extern char log_prefix_i[];
extern char log_prefix_e[];
extern char log_prefix_w[];

#define INFO_NOWRAP(fmt, ...) log_output_nowrap((fmt), ##__VA_ARGS__)
#define INFO_FL(fmt, ...) log_output<log_prefix_i, true>(__format(fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define WARNING_FL(fmt, ...) log_output<log_prefix_w, false>(__format(fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define ERROR_FL(fmt, ...) log_output<log_prefix_e, false>(__format(fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__)


#ifndef __WXMSW__
void CreatePidFile(std::string pidFile, pid_t pid);
#endif

void ReadConfigFile(std::map<std::string, std::string>& mapSettingsRet, std::map<std::string, std::vector<std::string> >& mapMultiSettingsRet);
#ifdef __WXMSW__
std::string MyGetSpecialFolderPath(int nFolder, bool fCreate);
#endif
std::string GetDefaultDataDir();
std::string GetDataDir();
void ShrinkDebugFile();
int GetRandInt(int nMax);
uint64 GetRand(uint64 nMax);
int64 GetTime();
int64 GetAdjustedTime();
void AddTimeData(unsigned int ip, int64 nTime);
std::string FormatFullVersion();

extern string GetHyperChainDataDir();

template<class Container>
std::string ToHexString(const Container& container)
{
    string rs;
    rs.resize(container.size() * 2);

    char* p = &rs[0];
    for (unsigned char c : container) {
        sprintf(p, "%02x", c);
        p += 2;
    }
    return  rs;
}

class CApplicationSettings{
public:
    CApplicationSettings()  {
        _configfile = GetHyperChainDataDir();
        _configfile += "/";
        _configfile += "hc.ini";
    }
private:
    CApplicationSettings(const CApplicationSettings&);
    void operator=(const CApplicationSettings&);

public:

    void WriteDefaultApp(const string& hash)
    {
        boost::property_tree::ptree pt;
        pt.put("App.coinhash", hash);
        boost::property_tree::ini_parser::write_ini(_configfile, pt);
    }

    void ReadDefaultApp(string& hash);

private:
    string _configfile;
};


// Wrapper to automatically initialize mutex
class CCriticalSection
{
protected:
    boost::interprocess::interprocess_recursive_mutex mutex;
public:
    explicit CCriticalSection() { }
    ~CCriticalSection() { }
    void Enter(const char* pszName, const char* pszFile, int nLine);
    void Leave();
    bool TryEnter(const char* pszName, const char* pszFile, int nLine);
};


class CUnCriticalBlock
{
protected:
    CCriticalSection* pcs;
    string _name;
    string _file;
    int _nLine;

public:
    CUnCriticalBlock(CCriticalSection& csIn, const char* pszName, const char* pszFile, int nLine) : _name(pszName),_file(pszFile),_nLine(nLine)
    {
        pcs = &csIn;
        pcs->Leave();
    }
    ~CUnCriticalBlock()
    {
        pcs->Enter(_name.c_str(), _file.c_str(), _nLine);
    }
};


// Automatically leave critical section when leaving block, needed for exception safety
class CCriticalBlock
{
protected:
    CCriticalSection* pcs;

public:
    CCriticalBlock(CCriticalSection& csIn, const char* pszName, const char* pszFile, int nLine)
    {
        pcs = &csIn;
        pcs->Enter(pszName, pszFile, nLine);
    }
    ~CCriticalBlock()
    {
        pcs->Leave();
    }
};

template<const char* NAME>
class CCriticalBlockT
{
public:
    CCriticalSection* _pcs;
    static string _file;
    static int _nLine;
    static std::thread::id _tid;
    bool _isLocked = false;

public:
    explicit CCriticalBlockT(CCriticalSection& csIn, const char* pszFile, int nLine) :
        _pcs(&csIn)
    {}

    ~CCriticalBlockT()
    {
        Leave();
    }

    bool Enter(const char* pszFile, int nLine)
    {
        _pcs->Enter(NAME, pszFile, nLine);
        _file = pszFile;
        _nLine = nLine;
        _tid = std::this_thread::get_id();
        _isLocked = true;
        return true;
    }

    void Leave()
    {
        if (_isLocked) {
            _isLocked = false;
            _file.clear();
            _nLine = 0;

            _pcs->Leave();
        }
    }

    bool TryEnter(const char* pszFile, int nLine)
    {
        if (_pcs->TryEnter(NAME, pszFile, nLine)) {
            _file = pszFile;
            _nLine = nLine;
            _tid = std::this_thread::get_id();
            _isLocked = true;
            return true;
        }
        return false;
    }

    static string ToString()
    {
        stringstream ss;
        ss << _tid;
        return strprintf("%s is taken by TID:%s (%s %d)", NAME, ss.str().c_str(), _file.c_str(), _nLine);
    }
};

template<const char* NAME>
class CUnCriticalBlockT
{
protected:
    CCriticalSection* _pcs;

public:
    explicit CUnCriticalBlockT(CCriticalSection& csIn, const char* pszFile, int nLine) :
        _pcs(&csIn)
    {
        csIn.Leave();
        CCriticalBlockT<NAME>::_file.clear();
        CCriticalBlockT<NAME>::_nLine = 0;
    }

    ~CUnCriticalBlockT()
    {
        CCriticalBlockT<NAME> cb(*_pcs, __FILE__, __LINE__);
		cb.Enter(__FILE__, __LINE__);
    }
};

// WARNING: This will catch continue and break!
// break is caught with an assertion, but there's no way to detect continue.
// I'd rather be careful than suffer the other more error prone syntax.
// The compiler will optimise away all this loop junk.
#define CRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by CRITICAL_BLOCK!" && !fcriticalblockonce)), fcriticalblockonce=false) \
        for (CCriticalBlock criticalblock(cs, #cs, __FILE__, __LINE__); fcriticalblockonce; fcriticalblockonce=false)

extern char pcstName[];
#define CRITICAL_BLOCK_T_MAIN(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by CRITICAL_BLOCK_T!" && !fcriticalblockonce)), fcriticalblockonce=false) \
        for (CCriticalBlockT<pcstName> criticalblock(cs, __FILE__, __LINE__); fcriticalblockonce && (fcriticalblockonce = criticalblock.Enter(__FILE__, __LINE__)); fcriticalblockonce=false)

#define UNCRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by UNCRITICAL_BLOCK!" && !fcriticalblockonce)), fcriticalblockonce=false) \
        for (CUnCriticalBlock criticalblock(cs, #cs, __FILE__, __LINE__); fcriticalblockonce; fcriticalblockonce=false)

#define UNCRITICAL_BLOCK_T_MAIN(cs)     \
    for (bool fcriticalblockonce=true;  fcriticalblockonce; assert(("break caught by UNCRITICAL_BLOCK_T!" && !fcriticalblockonce)), fcriticalblockonce=false) \
        for (CUnCriticalBlockT<pcstName> criticalblock(cs, __FILE__, __LINE__); fcriticalblockonce; fcriticalblockonce=false)


class CTryCriticalBlock
{
protected:
    CCriticalSection* pcs;

public:
    CTryCriticalBlock(CCriticalSection& csIn, const char* pszName, const char* pszFile, int nLine)
    {
        pcs = (csIn.TryEnter(pszName, pszFile, nLine) ? &csIn : NULL);
    }
    ~CTryCriticalBlock()
    {
        if (pcs)
        {
            pcs->Leave();
        }
    }
    bool Entered() { return pcs != NULL; }
};


#define TRY_CRITICAL_BLOCK(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by TRY_CRITICAL_BLOCK!" && !fcriticalblockonce)), fcriticalblockonce=false) \
        for (CTryCriticalBlock criticalblock(cs, #cs, __FILE__, __LINE__); fcriticalblockonce && (fcriticalblockonce = criticalblock.Entered()); fcriticalblockonce=false)

#define TRY_CRITICAL_BLOCK_T_MAIN(cs)     \
    for (bool fcriticalblockonce=true; fcriticalblockonce; assert(("break caught by TRY_CRITICAL_BLOCK_T!" && !fcriticalblockonce)), fcriticalblockonce=false) \
        for (CCriticalBlockT<pcstName> criticalblock(cs, __FILE__, __LINE__); fcriticalblockonce && (fcriticalblockonce = criticalblock.TryEnter(__FILE__, __LINE__)); fcriticalblockonce=false)


inline std::string i64tostr(int64 n)
{
    return strprintf("%" PRI64d "", n);
}

inline std::string itostr(int n)
{
    return strprintf("%d", n);
}

inline int64 atoi64(const char* psz)
{
#ifdef _MSC_VER
    return _atoi64(psz);
#else
    return strtoll(psz, NULL, 10);
#endif
}

int64 atoi64(const std::string& str);
//inline int64 atoi64(const std::string& str)
//{
//#ifdef _MSC_VER
//    return _atoi64(str.c_str());
//#else
//    return strtoll(str.c_str(), NULL, 10);
//#endif
//}

int atoi(const std::string& str);
//inline int atoi(const std::string& str)
//{
//    return atoi(str.c_str());
//}

inline int roundint(double d)
{
    return (int)(d > 0 ? d + 0.5 : d - 0.5);
}

inline int64 roundint64(double d)
{
    return (int64)(d > 0 ? d + 0.5 : d - 0.5);
}

inline int64 abs64(int64 n)
{
    return (n >= 0 ? n : -n);
}

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces=false)
{
    if (itbegin == itend)
        return "";
    const unsigned char* pbegin = (const unsigned char*)&itbegin[0];
    const unsigned char* pend = pbegin + (itend - itbegin) * sizeof(itbegin[0]);
    std::string str;
    str.reserve((pend-pbegin) * (fSpaces ? 3 : 2));
    for (const unsigned char* p = pbegin; p != pend; p++)
        str += strprintf((fSpaces && p != pend-1 ? "%02x " : "%02x"), *p);
    return str;
}

inline std::string HexStr(const std::vector<unsigned char>& vch, bool fSpaces=false)
{
    return HexStr(vch.begin(), vch.end(), fSpaces);
}

template<typename T>
std::string HexNumStr(const T itbegin, const T itend, bool f0x=true)
{
    if (itbegin == itend)
        return "";
    const unsigned char* pbegin = (const unsigned char*)&itbegin[0];
    const unsigned char* pend = pbegin + (itend - itbegin) * sizeof(itbegin[0]);
    std::string str = (f0x ? "0x" : "");
    str.reserve(str.size() + (pend-pbegin) * 2);
    for (const unsigned char* p = pend-1; p >= pbegin; p--)
        str += strprintf("%02x", *p);
    return str;
}

inline std::string HexNumStr(const std::vector<unsigned char>& vch, bool f0x=true)
{
    return HexNumStr(vch.begin(), vch.end(), f0x);
}

template<typename T>
void PrintHex(const T pbegin, const T pend, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(pbegin, pend, fSpaces).c_str());
}

inline void PrintHex(const std::vector<unsigned char>& vch, const char* pszFormat="%s", bool fSpaces=true)
{
    printf(pszFormat, HexStr(vch, fSpaces).c_str());
}

inline int64 GetPerformanceCounter()
{
    int64 nCounter = 0;
#ifdef __WXMSW__
    QueryPerformanceCounter((LARGE_INTEGER*)&nCounter);
#else
    timeval t;
    gettimeofday(&t, NULL);
    nCounter = t.tv_sec * 1000000 + t.tv_usec;
#endif
    return nCounter;
}

inline int64 GetTimeMillis()
{
    return (boost::posix_time::ptime(boost::posix_time::microsec_clock::universal_time()) -
            boost::posix_time::ptime(boost::gregorian::date(1970,1,1))).total_milliseconds();
}

inline std::string DateTimeStrFormat(const char* pszFormat, int64 nTime)
{
    time_t n = nTime;
    struct tm* ptmTime = gmtime(&n);
    char pszTime[200];
    strftime(pszTime, sizeof(pszTime), pszFormat, ptmTime);
    return pszTime;
}

template<typename T>
void skipspaces(T& it)
{
    while (isspace(*it))
        ++it;
}

inline bool IsSwitchChar(char c)
{
#ifdef __WXMSW__
    return c == '-' || c == '/';
#else
    return c == '-';
#endif
}

inline std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

inline int64 GetArg(const std::string& strArg, int64 nDefault)
{
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

inline bool GetBoolArg(const std::string& strArg)
{
    if (mapArgs.count(strArg))
    {
        if (mapArgs[strArg].empty())
            return true;
        return (atoi(mapArgs[strArg]) != 0);
    }
    return false;
}










inline void heapchk()
{
#ifdef __WXMSW__
    /// for debugging
    //if (_heapchk() != _HEAPOK)
    //    DebugBreak();
#endif
}

// Randomize the stack to help protect against buffer overrun exploits
#define IMPLEMENT_RANDOMIZE_STACK(ThreadFn)     \
    {                                           \
        static char nLoops;                     \
        if (nLoops <= 0)                        \
            nLoops = GetRand(20) + 1;           \
        if (nLoops-- > 1)                       \
        {                                       \
            ThreadFn;                           \
            return;                             \
        }                                       \
    }

#define CATCH_PRINT_EXCEPTION(pszFn)     \
    catch (std::exception& e) {          \
        PrintException(&e, (pszFn));     \
    } catch (...) {                      \
        PrintException(NULL, (pszFn));   \
    }










template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=VERSION)
{
    // Most of the time is spent allocating and deallocating CDataStream's
    // buffer.  If this ever needs to be optimized further, make a CStaticStream
    // class with its buffer on the stack.
    CDataStream ss(nType, nVersion);
    ss.reserve(10000);
    ss << obj;
    return Hash(ss.begin(), ss.end());
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    uint256 hash1;
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}











// Note: It turns out we might have been able to use boost::thread
// by using TerminateThread(boost::thread.native_handle(), 0);
#ifdef __WXMSW__
typedef HANDLE pthread_t;

inline pthread_t CreateThread(void(*pfn)(void*), void* parg, bool fWantHandle=false)
{
    DWORD nUnused = 0;
    HANDLE hthread =
        CreateThread(
            NULL,                        // default security
            0,                           // inherit stack size from parent
            (LPTHREAD_START_ROUTINE)pfn, // function pointer
            parg,                        // argument
            0,                           // creation option, start immediately
            &nUnused);                   // thread identifier
    if (hthread == NULL)
    {
        printf("Error: CreateThread() returned %d\n", GetLastError());
        return (pthread_t)0;
    }
    if (!fWantHandle)
    {
        CloseHandle(hthread);
        return (pthread_t)-1;
    }
    return hthread;
}

inline void SetThreadPriority(int nPriority)
{
    SetThreadPriority(GetCurrentThread(), nPriority);
}
#else
inline pthread_t CreateThread(void(*pfn)(void*), void* parg, bool fWantHandle=false)
{
    pthread_t hthread = 0;
    int ret = pthread_create(&hthread, NULL, (void*(*)(void*))pfn, parg);
    if (ret != 0)
    {
        printf("Error: pthread_create() returned %d\n", ret);
        return (pthread_t)0;
    }
    if (!fWantHandle)
    {
        pthread_detach(hthread);
        return (pthread_t)-1;
    }
    return hthread;
}

#define THREAD_PRIORITY_LOWEST          PRIO_MAX
#define THREAD_PRIORITY_BELOW_NORMAL    2
#define THREAD_PRIORITY_NORMAL          0
#define THREAD_PRIORITY_ABOVE_NORMAL    0

inline void SetThreadPriority(int nPriority)
{
    // It's unclear if it's even possible to change thread priorities on Linux,
    // but we really and truly need it for the generation threads.
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif
}

inline bool TerminateThread(pthread_t hthread, unsigned int nExitCode)
{
    return (pthread_cancel(hthread) == 0);
}

inline void ExitThread(size_t nExitCode)
{
    pthread_exit((void*)nExitCode);
}
#endif



inline bool AffinityBugWorkaround(void(*pfn)(void*))
{
#ifdef __WXMSW__
    // Sometimes after a few hours affinity gets stuck on one processor
	DWORD_PTR dwProcessAffinityMask = -1;
	DWORD_PTR dwSystemAffinityMask = -1;
    GetProcessAffinityMask(GetCurrentProcess(), &dwProcessAffinityMask, &dwSystemAffinityMask);
	DWORD_PTR dwPrev1 = SetThreadAffinityMask(GetCurrentThread(), dwProcessAffinityMask);
	DWORD_PTR dwPrev2 = SetThreadAffinityMask(GetCurrentThread(), dwProcessAffinityMask);
    if (dwPrev2 != dwProcessAffinityMask)
    {
        printf("AffinityBugWorkaround() : SetThreadAffinityMask=%d, ProcessAffinityMask=%d, restarting thread\n", dwPrev2, dwProcessAffinityMask);
        if (!CreateThread(pfn, NULL))
            printf("Error: CreateThread() failed\n");
        return true;
    }
#endif
    return false;
}

#endif
