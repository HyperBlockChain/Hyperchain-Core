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

#include "config.h"
#include "headers.h"
#include "strlcpy.h"

#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/interprocess/sync/interprocess_recursive_mutex.hpp>
#include <boost/foreach.hpp>

#include "cryptocurrency.h"

using namespace std;
using namespace boost;

map<string, string> mapArgs;
map<string, vector<string> > mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugFile = false;
bool fPrintBacktracking = false;
bool fPrintToDebugger = false;
char pszSetDataDir[MAX_PATH] = "";
bool fRequestShutdown = false;
bool fShutdown = false;
bool fDaemon = false;
bool fServer = false;
bool fRPCServerRunning = false;
bool fCommandLine = false;
string strMiscWarning;
bool fTestNet = false;
bool fNoListen = false;
bool fLogTimestamps = false;


char log_prefix_i[] = "INFO";
char log_prefix_e[] = "ERROR";
char log_prefix_w[] = "WARNING";

// Workaround for "multiple definition of `_tls_used'"
// http://svn.boost.org/trac/boost/ticket/4258
extern "C" void tss_cleanup_implemented() { }



void log_output_nowrap(const char* format, ...)
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
    fprintf(stdout, "%s", buffer);
}



// Init openssl library multithreading support
static boost::interprocess::interprocess_mutex** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line)
{
    if (mode & CRYPTO_LOCK)
        ppmutexOpenSSL[i]->lock();
    else
        ppmutexOpenSSL[i]->unlock();
}

void CApplicationSettings::ReadDefaultApp(string& hash)
{
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::ini_parser::read_ini(_configfile, pt);
        hash = pt.get<std::string>("App.coinhash");
        return;
    }
    catch (std::exception e) {
        printf(e.what());
    }
    hash = CryptoCurrency::GetHashPrefixOfSysGenesis();
}

// Init
class CInit
{
public:
    CInit()
    {
        // Init openssl library multithreading support
        ppmutexOpenSSL = (boost::interprocess::interprocess_mutex**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(boost::interprocess::interprocess_mutex*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new boost::interprocess::interprocess_mutex();
        CRYPTO_set_locking_callback(locking_callback);

#ifdef __WXMSW__
        // Seed random number generator with screen scrape and other hardware sources
        RAND_screen();
#endif

        // Seed random number generator with performance counter
        RandAddSeed();
    }
    ~CInit()
    {
        // Shutdown openssl library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
}
instance_of_cinit;








//void RandAddSeed()
//{
//    // Seed with CPU performance counter
//    int64 nCounter = GetPerformanceCounter();
//    RAND_add(&nCounter, sizeof(nCounter), 1.5);
//    memset(&nCounter, 0, sizeof(nCounter));
//}

void RandAddSeedPerfmon()
{
    RandAddSeed();

    // This can take up to 2 seconds, so only do it every 10 minutes
    static int64 nLastPerfmon;
    if (GetTime() < nLastPerfmon + 10 * 60)
        return;
    nLastPerfmon = GetTime();

#ifdef __WXMSW__
    // Don't need this on Linux, OpenSSL automatically uses /dev/urandom
    // Seed with the entire set of perfmon data
    unsigned char pdata[250000];
    memset(pdata, 0, sizeof(pdata));
    unsigned long nSize = sizeof(pdata);
    long ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", NULL, NULL, pdata, &nSize);
    RegCloseKey(HKEY_PERFORMANCE_DATA);
    if (ret == ERROR_SUCCESS)
    {
        RAND_add(pdata, nSize, nSize/100.0);
        memset(pdata, 0, nSize);
        printf("%s RandAddSeed() %d bytes\n", DateTimeStrFormat("%x %H:%M", GetTime()).c_str(), nSize);
    }
#endif
}

extern "C" BOOST_SYMBOL_EXPORT
bool TurnOnOffDebugOutput(const string& onoff, string& ret)
{
    string optiononoff=onoff;
    std::transform(onoff.begin(), onoff.end(), optiononoff.begin(),
        [](unsigned char c) { return std::tolower(c); });

    ret = "Paracoin's debug setting is ";
    if (optiononoff.empty()) {
        if (fPrintToConsole && fPrintToDebugFile) {
            ret += "'both'";
        }
        else if (!fPrintToConsole && !fPrintToDebugFile) {
            ret += "'off'";
        }
        else if (fPrintToConsole && !fPrintToDebugFile) {
            ret += "'con'";
        }
        else if (!fPrintToConsole && fPrintToDebugFile) {
            ret += "'file'";
        }

        if (fPrintBacktracking) {
            ret += " and 'backtracking'";
        }
        return true;
    }

    if (optiononoff == "both") {
        fPrintToConsole = true;
        fPrintToDebugFile = true;
    }
    else if (optiononoff == "con") {
        fPrintToConsole = true;
        fPrintToDebugFile = false;
    }
    else if (optiononoff == "file") {
        fPrintToConsole = false;
        fPrintToDebugFile = true;
    }
    else if (optiononoff == "off") {
        fPrintToConsole = false;
        fPrintToDebugFile = false;
        fPrintBacktracking = false;
    }
    else if (optiononoff == "bt") {
        fPrintBacktracking = true;
    }
    else {
        ret = "unknown debug option";
        return false;
    }
    ret = string("Paracoin's debug setting is '") + optiononoff + "'";
    return true;
}

void LogBacktracking(const char* format, ...)
{
    if (fPrintBacktracking || fPrintToConsole) {
        // print to console
        va_list arg_ptr;
        va_start(arg_ptr, format);
        vprintf(format, arg_ptr);
        va_end(arg_ptr);
    }
}

int OutputDebugStringF(const char* pszFormat, ...)
{
    int ret = 0;
    if (fPrintToConsole) {
        // print to console
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        ret = vprintf(pszFormat, arg_ptr);
        va_end(arg_ptr);
    }

    if(fPrintToDebugFile) {
        // print to debug.log
        static FILE* fileout = NULL;

        if (!fileout) {
            char pszFile[MAX_PATH+100];
            GetDataDir(pszFile);
            strlcat(pszFile, "/debug_para.log", sizeof(pszFile));
            fileout = fopen(pszFile, "a");
            if (fileout) setbuf(fileout, NULL); // unbuffered
        }
        if (fileout) {
            static bool fStartedNewLine = true;

            // Debug print useful for profiling
            if (fLogTimestamps && fStartedNewLine)
                fprintf(fileout, "%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
            if (pszFormat[strlen(pszFormat) - 1] == '\n')
                fStartedNewLine = true;
            else
                fStartedNewLine = false;

            va_list arg_ptr;
            va_start(arg_ptr, pszFormat);
            ret = vfprintf(fileout, pszFormat, arg_ptr);
            va_end(arg_ptr);
        }
    }

#ifdef __WXMSW__
    if (fPrintToDebugger) {
        static CCriticalSection cs_OutputDebugStringF;

        // accumulate a line at a time
        CRITICAL_BLOCK(cs_OutputDebugStringF)
        {
            static char pszBuffer[50000];
            static char* pend;
            if (pend == NULL)
                pend = pszBuffer;
            va_list arg_ptr;
            va_start(arg_ptr, pszFormat);
            int limit = END(pszBuffer) - pend - 2;
            int ret = _vsnprintf(pend, limit, pszFormat, arg_ptr);
            va_end(arg_ptr);
            if (ret < 0 || ret >= limit) {
                pend = END(pszBuffer) - 2;
                *pend++ = '\n';
            }
            else
                pend += ret;
            *pend = '\0';
            char* p1 = pszBuffer;
            char* p2;
            while (p2 = strchr(p1, '\n')) {
                p2++;
                char c = *p2;
                *p2 = '\0';
                OutputDebugStringA(p1);
                *p2 = c;
                p1 = p2;
            }
            if (p1 != pszBuffer)
                memmove(pszBuffer, p1, pend - p1 + 1);
            pend -= (p1 - pszBuffer);
        }
    }
#endif
    return ret;
}


string strprintf(const char* fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    int sz = std::vsnprintf(nullptr, 0, fmt, args);
    va_end(args);

    std::string buf(sz, 0);

    va_start(args, fmt);
    std::vsnprintf(&buf[0], sz + 1, fmt, args);
    va_end(args);

    return buf;
}

void ParseString(const string& str, char c, vector<string>& v)
{
    if (str.empty())
        return;
    string::size_type i1 = 0;
    string::size_type i2;
    loop
    {
        i2 = str.find(c, i1);
        if (i2 == str.npos)
        {
            v.push_back(str.substr(i1));
            return;
        }
        v.push_back(str.substr(i1, i2-i1));
        i1 = i2+1;
    }
}


string FormatMoney(int64 n, bool fPlus)
{
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    int64 n_abs = (n > 0 ? n : -n);
    int64 quotient = n_abs/COIN;
    int64 remainder = n_abs%COIN;

    string str = strprintf("%" PRI64d ".%08" PRI64d, quotient, remainder);

    // Right-trim excess 0's before the decimal point:
    int nTrim = 0;
    for (int i = str.size()-1; (str[i] == '0' && isdigit(str[i-2])); --i)
        ++nTrim;
    if (nTrim)
        str.erase(str.size()-nTrim, nTrim);

    if (n < 0)
        str.insert((unsigned int)0, 1, '-');
    else if (fPlus && n > 0)
        str.insert((unsigned int)0, 1, '+');
    return str;
}


bool ParseMoney(const string& str, int64& nRet)
{
    return ParseMoney(str.c_str(), nRet);
}

bool ParseMoney(const char* pszIn, int64& nRet)
{
    string strWhole;
    int64 nUnits = 0;
    const char* p = pszIn;
    while (isspace(*p))
        p++;
    for (; *p; p++)
    {
        if (*p == '.')
        {
            p++;
            int64 nMult = CENT*10;
            while (isdigit(*p) && (nMult > 0))
            {
                nUnits += nMult * (*p++ - '0');
                nMult /= 10;
            }
            break;
        }
        if (isspace(*p))
            break;
        if (!isdigit(*p))
            return false;
        strWhole.insert(strWhole.end(), *p);
    }
    for (; *p; p++)
        if (!isspace(*p))
            return false;
    if (strWhole.size() > 14)
        return false;
    if (nUnits < 0 || nUnits > COIN)
        return false;
    int64 nWhole = atoi64(strWhole);
    int64 nValue = nWhole*COIN + nUnits;

    nRet = nValue;
    return true;
}

//
//vector<unsigned char> ParseHex(const char* psz)
//{
//    static char phexdigit[256] =
//    { -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
//      -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
//      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };
//
//    // convert hex dump to vector
//    vector<unsigned char> vch;
//    loop
//    {
//        while (isspace(*psz))
//            psz++;
//        char c = phexdigit[(unsigned char)*psz++];
//        if (c == (char)-1)
//            break;
//        unsigned char n = (c << 4);
//        c = phexdigit[(unsigned char)*psz++];
//        if (c == (char)-1)
//            break;
//        n |= c;
//        vch.push_back(n);
//    }
//    return vch;
//}
//
//vector<unsigned char> ParseHex(const string& str)
//{
//    return ParseHex(str.c_str());
//}


void AppParseParameters(int argc, char* argv[])
{
    mapArgs.clear();
    mapMultiArgs.clear();
    for (int i = 1; i < argc; i++)
    {
        char psz[10000];
        strlcpy(psz, argv[i], sizeof(psz));
        char* pszValue = (char*)"";
        if (strchr(psz, '='))
        {
            pszValue = strchr(psz, '=');
            *pszValue++ = '\0';
        }
        #ifdef __WXMSW__
        _strlwr(psz);
        if (psz[0] == '/')
            psz[0] = '-';
        #endif
        if (psz[0] != '-')
            break;
        mapArgs[psz] = pszValue;
        mapMultiArgs[psz].push_back(pszValue);
    }
}

bool WildcardMatch(const char* psz, const char* mask)
{
    loop
    {
        switch (*mask)
        {
        case '\0':
            return (*psz == '\0');
        case '*':
            return WildcardMatch(psz, mask+1) || (*psz && WildcardMatch(psz+1, mask));
        case '?':
            if (*psz == '\0')
                return false;
            break;
        default:
            if (*psz != *mask)
                return false;
            break;
        }
        psz++;
        mask++;
    }
}

bool WildcardMatch(const string& str, const string& mask)
{
    return WildcardMatch(str.c_str(), mask.c_str());
}








void FormatException(char* pszMessage, std::exception* pex, const char* pszThread)
{
#ifdef __WXMSW__
    char pszModule[MAX_PATH];
    pszModule[0] = '\0';
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "ledger";
#endif
    if (pex)
        snprintf(pszMessage, 1000,
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        snprintf(pszMessage, 1000,
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void LogException(std::exception* pex, const char* pszThread)
{
    char pszMessage[10000];
    FormatException(pszMessage, pex, pszThread);
    printf("\n%s", pszMessage);
}

void PrintException(std::exception* pex, const char* pszThread)
{
    char pszMessage[10000];
    FormatException(pszMessage, pex, pszThread);
    printf("\n\n************************\n%s\n", pszMessage);
    fprintf(stderr, "\n\n************************\n%s\n", pszMessage);
    strMiscWarning = pszMessage;
    

    //throw;
}

void ThreadOneMessageBox(string strMessage)
{
    // Skip message boxes if one is already open
    static bool fMessageBoxOpen;
    if (fMessageBoxOpen)
        return;
    fMessageBoxOpen = true;
    ThreadSafeMessageBox(strMessage, "Hyperchain", wxOK | wxICON_EXCLAMATION);
    fMessageBoxOpen = false;
}

void PrintExceptionContinue(std::exception* pex, const char* pszThread)
{
    char pszMessage[10000];
    FormatException(pszMessage, pex, pszThread);
    printf("\n\n************************\n%s\n", pszMessage);
    fprintf(stderr, "\n\n************************\n%s\n", pszMessage);
    strMiscWarning = pszMessage;

}

#ifdef __WXMSW__
typedef WINSHELLAPI BOOL (WINAPI *PSHGETSPECIALFOLDERPATHA)(HWND hwndOwner, LPSTR lpszPath, int nFolder, BOOL fCreate);

string MyGetSpecialFolderPath(int nFolder, bool fCreate)
{
    char pszPath[MAX_PATH+100] = "";

    // SHGetSpecialFolderPath isn't always available on old Windows versions
    HMODULE hShell32 = LoadLibraryA("shell32.dll");
    if (hShell32)
    {
        PSHGETSPECIALFOLDERPATHA pSHGetSpecialFolderPath =
            (PSHGETSPECIALFOLDERPATHA)GetProcAddress(hShell32, "SHGetSpecialFolderPathA");
        if (pSHGetSpecialFolderPath)
            (*pSHGetSpecialFolderPath)(NULL, pszPath, nFolder, fCreate);
        FreeModule(hShell32);
    }

    // Backup option
    if (pszPath[0] == '\0')
    {
        if (nFolder == CSIDL_STARTUP)
        {
            strcpy(pszPath, getenv("USERPROFILE"));
            strcat(pszPath, "\\Start Menu\\Programs\\Startup");
        }
        else if (nFolder == CSIDL_APPDATA)
        {
            strcpy(pszPath, getenv("APPDATA"));
        }
    }

    return pszPath;
}
#endif

extern string GetHyperChainDataDir();
string GetDefaultDataDir()
{
    return GetHyperChainDataDir();
    // Windows: C:\Documents and Settings\username\Application Data\Hyperchain
    // Mac: ~/Library/Application Support/Hyperchain
    // Unix: ~/.hyperchain
#ifdef __WXMSW__
    // Windows
    return MyGetSpecialFolderPath(CSIDL_APPDATA, true) + "\\Hyperchain";
#else
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pszHome = (char*)"/";
    string strHome = pszHome;
    if (strHome[strHome.size()-1] != '/')
        strHome += '/';
#ifdef __WXMAC_OSX__
    // Mac
    strHome += "Library/Application Support/";
    filesystem::create_directory(strHome.c_str());
    return strHome + "Hyperchain";
#else
    // Unix
    return strHome + ".hyperchain";
#endif
#endif
}

void GetDataDir(char* pszDir)
{
    // pszDir must be at least MAX_PATH length.
    int nVariation;
    if (pszSetDataDir[0] != 0)
    {
        strlcpy(pszDir, pszSetDataDir, MAX_PATH);
        nVariation = 0;
    }
    else
    {
        // This can be called during exceptions by printf, so we cache the
        // value so we don't have to do memory allocations after that.
        static char pszCachedDir[MAX_PATH];
        if (pszCachedDir[0] == 0)
            strlcpy(pszCachedDir, GetDefaultDataDir().c_str(), sizeof(pszCachedDir));
        strlcpy(pszDir, pszCachedDir, MAX_PATH);
        nVariation = 1;
    }
    if (fTestNet)
    {
        char* p = pszDir + strlen(pszDir);
        if (p > pszDir && p[-1] != '/' && p[-1] != '\\')
            *p++ = '/';
        strcpy(p, "testnet");
        nVariation += 2;
    }
    static bool pfMkdir[4];
    if (!pfMkdir[nVariation])
    {
        pfMkdir[nVariation] = true;
        boost::filesystem::create_directory(pszDir);
    }
}

string GetDataDir()
{
    char pszDir[MAX_PATH];
    GetDataDir(pszDir);
    return pszDir;
}

string GetConfigFile()
{
    namespace fs = boost::filesystem;
    fs::path pathConfig(GetArg("-conf", "paracoin.conf"));
    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetDataDir()) / pathConfig;
    return pathConfig.string();
}

void ReadConfigFile(map<string, string>& mapSettingsRet,
                    map<string, vector<string> >& mapMultiSettingsRet)
{
    namespace fs = boost::filesystem;
    namespace pod = boost::program_options::detail;

    fs::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good())
        return;

    set<string> setOptions;
    setOptions.insert("*");

    for (pod::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
    {
        // Don't overwrite existing settings so command line settings override ledger.conf
        string strKey = string("-") + it->string_key;
        if (mapSettingsRet.count(strKey) == 0)
            mapSettingsRet[strKey] = it->value[0];
        mapMultiSettingsRet[strKey].push_back(it->value[0]);
    }
}

string GetPidFile()
{
    namespace fs = boost::filesystem;
    fs::path pathConfig(GetArg("-pid", "paracoin.pid"));
    if (!pathConfig.is_complete())
        pathConfig = fs::path(GetDataDir()) / pathConfig;
    return pathConfig.string();
}

#ifndef __WXMSW__
void CreatePidFile(string pidFile, pid_t pid)
{
    FILE* file = fopen(pidFile.c_str(), "w");
    if (file)
    {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}
#endif

int GetFilesize(FILE* file)
{
    int nSavePos = ftell(file);
    int nFilesize = -1;
    if (fseek(file, 0, SEEK_END) == 0)
        nFilesize = ftell(file);
    fseek(file, nSavePos, SEEK_SET);
    return nFilesize;
}

void ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    string strFile = GetDataDir() + "/debug.log";
    FILE* file = fopen(strFile.c_str(), "r");
    if (file && GetFilesize(file) > 10 * 1000000)
    {
        // Restart the file with some of the end
        char pch[200000];
        fseek(file, -sizeof(pch), SEEK_END);
        int nBytes = fread(pch, 1, sizeof(pch), file);
        fclose(file);

        file = fopen(strFile.c_str(), "w");
        if (file)
        {
            fwrite(pch, 1, nBytes, file);
            fclose(file);
        }
    }
}








//
// "Never go to sea with two chronometers; take one or three."
// Our three time sources are:
//  - System clock
//  - Median of other nodes's clocks
//  - The user (asking the user to fix the system clock if the first two disagree)
//
int64 GetTime()
{
    return time(NULL);
}

static int64 nTimeOffset = 0;

int64 GetAdjustedTime()
{
    return GetTime() + nTimeOffset;
}

void AddTimeData(unsigned int ip, int64 nTime)
{
    int64 nOffsetSample = nTime - GetTime();

    // Ignore duplicates
    static set<unsigned int> setKnown;
    if (!setKnown.insert(ip).second)
        return;

    // Add data
    static vector<int64> vTimeOffsets;
    if (vTimeOffsets.empty())
        vTimeOffsets.push_back(0);
    vTimeOffsets.push_back(nOffsetSample);
    printf("Added time data, samples %d, offset %+" PRI64d " (%+" PRI64d " minutes)\n", vTimeOffsets.size(), vTimeOffsets.back(), vTimeOffsets.back()/60);
    if (vTimeOffsets.size() >= 5 && vTimeOffsets.size() % 2 == 1)
    {
        sort(vTimeOffsets.begin(), vTimeOffsets.end());
        int64 nMedian = vTimeOffsets[vTimeOffsets.size()/2];
        // Only let other nodes change our time by so much
        if (abs64(nMedian) < 70 * 60)
        {
            nTimeOffset = nMedian;
        }
        else
        {
            nTimeOffset = 0;

            static bool fDone;
            if (!fDone)
            {
                // If nobody has a time different than ours but within 5 minutes of ours, give a warning
                bool fMatch = false;
                BOOST_FOREACH(int64 nOffset, vTimeOffsets)
                    if (nOffset != 0 && abs64(nOffset) < 5 * 60)
                        fMatch = true;

                if (!fMatch)
                {
                    fDone = true;
                    string strMessage = _("Warning: Please check that your computer's date and time are correct.  If your clock is wrong Hyperchain will not work properly.");
                    strMiscWarning = strMessage;
                    printf("*** %s\n", strMessage.c_str());
                    boost::thread(boost::bind(ThreadSafeMessageBox, strMessage+" ", string("Hyperchain"), wxOK | wxICON_EXCLAMATION, (wxWindow*)NULL, -1, -1));
                }
            }
        }
        BOOST_FOREACH(int64 n, vTimeOffsets)

        printf("%+" PRI64d, n);
        printf("|  nTimeOffset = %+I64d  (%+" PRI64d " minutes)\n", nTimeOffset, nTimeOffset/60);
    }
}









string FormatVersion(int nVersion)
{
    if (nVersion%100 == 0)
        return strprintf("%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100);
    else
        return strprintf("%d.%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100, nVersion%100);
}

string FormatFullVersion()
{
	return VERSION_STRING;
}


#ifdef DEBUG_LOCKORDER
//
// Early deadlock detection.
// Problem being solved:
//    Thread 1 locks  A, then B, then C
//    Thread 2 locks  D, then C, then A
//     --> may result in deadlock between the two threads, depending on when they run.
// Solution implemented here:
// Keep track of pairs of locks: (A before B), (A before C), etc.
// Complain if any thread trys to lock in a different order.
//

struct CLockLocation
{
    CLockLocation(const char* pszName, const char* pszFile, int nLine)
    {
        mutexName = pszName;
        sourceFile = pszFile;
        sourceLine = nLine;
    }

    std::string ToString() const
    {
        return mutexName+"  "+sourceFile+":"+itostr(sourceLine);
    }

private:
    std::string mutexName;
    std::string sourceFile;
    int sourceLine;
};

typedef std::vector< std::pair<CCriticalSection*, CLockLocation> > LockStack;

static boost::interprocess::interprocess_mutex dd_mutex;
static std::map<std::pair<CCriticalSection*, CCriticalSection*>, LockStack> lockorders;
static boost::thread_specific_ptr<LockStack> lockstack;


static void potential_deadlock_detected(const std::pair<CCriticalSection*, CCriticalSection*>& mismatch, const LockStack& s1, const LockStack& s2)
{
    printf("POTENTIAL DEADLOCK DETECTED\n");
    printf("Previous lock order was:\n");
    BOOST_FOREACH(const PAIRTYPE(CCriticalSection*, CLockLocation)& i, s2)
    {
        if (i.first == mismatch.first) printf(" (1)");
        if (i.first == mismatch.second) printf(" (2)");
        printf(" %s\n", i.second.ToString().c_str());
    }
    printf("Current lock order is:\n");
    BOOST_FOREACH(const PAIRTYPE(CCriticalSection*, CLockLocation)& i, s1)
    {
        if (i.first == mismatch.first) printf(" (1)");
        if (i.first == mismatch.second) printf(" (2)");
        printf(" %s\n", i.second.ToString().c_str());
    }
}

static void push_lock(CCriticalSection* c, const CLockLocation& locklocation)
{
    bool fOrderOK = true;
    if (lockstack.get() == NULL)
        lockstack.reset(new LockStack);

    if (fDebug) printf("Locking: %s\n", locklocation.ToString().c_str());
    dd_mutex.lock();

    (*lockstack).push_back(std::make_pair(c, locklocation));

    BOOST_FOREACH(const PAIRTYPE(CCriticalSection*, CLockLocation)& i, (*lockstack))
    {
        if (i.first == c) break;

        std::pair<CCriticalSection*, CCriticalSection*> p1 = std::make_pair(i.first, c);
        if (lockorders.count(p1))
            continue;
        lockorders[p1] = (*lockstack);

        std::pair<CCriticalSection*, CCriticalSection*> p2 = std::make_pair(c, i.first);
        if (lockorders.count(p2))
        {
            potential_deadlock_detected(p1, lockorders[p2], lockorders[p1]);
            break;
        }
    }
    dd_mutex.unlock();
}

static void pop_lock()
{
    if (fDebug)
    {
        const CLockLocation& locklocation = (*lockstack).rbegin()->second;
        printf("Unlocked: %s\n", locklocation.ToString().c_str());
    }
    dd_mutex.lock();
    (*lockstack).pop_back();
    dd_mutex.unlock();
}

void CCriticalSection::Enter(const char* pszName, const char* pszFile, int nLine)
{
    push_lock(this, CLockLocation(pszName, pszFile, nLine));
    mutex.lock();
}
void CCriticalSection::Leave()
{
    mutex.unlock();
    pop_lock();
}
bool CCriticalSection::TryEnter(const char* pszName, const char* pszFile, int nLine)
{
    push_lock(this, CLockLocation(pszName, pszFile, nLine));
    bool result = mutex.try_lock();
    if (!result) pop_lock();
    return result;
}

#else

void CCriticalSection::Enter(const char*, const char*, int)
{
    mutex.lock();
}

void CCriticalSection::Leave()
{
    mutex.unlock();
}

bool CCriticalSection::TryEnter(const char*, const char*, int)
{
    bool result = mutex.try_lock();
    return result;
}

char pcstName[] = "cs_main";

template<>
string CCriticalBlockT<pcstName>::_file = "";

template<>
int CCriticalBlockT<pcstName>::_nLine = 0;


#endif /* DEBUG_LOCKORDER */
