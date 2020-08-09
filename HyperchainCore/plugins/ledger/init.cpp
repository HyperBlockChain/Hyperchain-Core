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

#include "node/Singleton.h"
#include "headers/commonstruct.h"
#include "consensus/consensus_engine.h"

#include "headers.h"
#include "db.h"
#include "ledger_rpc.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "../PluginContext.h"
#include "cryptotoken.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/interprocess/sync/file_lock.hpp>

using namespace std;

extern bool HandleGenesisBlockCb(vector<T_PAYLOADADDR>& vecPA);
extern bool PutTxsChainCb();
extern bool UpdateLedgerDataCb(string& payload, string &newpaylod);
extern bool CheckChainCb(vector<T_PAYLOADADDR>& vecPA);
extern bool LedgerAcceptChainCb(map<T_APPTYPE, vector<T_PAYLOADADDR>>& , uint32_t& hidFork, uint32_t& hid, T_SHA256& thhash, bool isLatest);
extern bool ValidateLedgerDataCb(T_PAYLOADADDR& payloadaddr, map<boost::any, T_LOCALBLOCKADDRESS>& mapOutPt, boost::any& hashPrevBlock);
extern bool LedgerBlockUUIDCb(string& payload, string& uuidpayload);
extern bool GetVPath(T_LOCALBLOCKADDRESS& sAddr, T_LOCALBLOCKADDRESS& eAddr, vector<string>& vecVPath);

extern void ThreadRSyncGetBlock(void* parg);

extern void StartRPCServer();
extern void StopRPCServer();

extern void StartMQHandler();
extern void StopMQHandler();


CWallet* pwalletMain = nullptr;
bool fExit = true;

string GetHyperChainDataDir()
{
	string datapath;
	boost::filesystem::path pathDataDir;
	if (mapArgs.count("-datadir") && boost::filesystem::is_directory(boost::filesystem::system_complete(mapArgs["-datadir"])))
		pathDataDir = boost::filesystem::system_complete(mapArgs["-datadir"]);
	else
		pathDataDir = boost::filesystem::system_complete(".");

	if (mapArgs.count("-model") && mapArgs["-model"] == "informal")
		pathDataDir /= "informal";
	else
		pathDataDir /= "sandbox";

	if (!boost::filesystem::exists(pathDataDir))
		boost::filesystem::create_directories(pathDataDir);

	return pathDataDir.string();
}

string CreateChildDir(const string& childdir)
{
    string log_path = GetHyperChainDataDir();
    boost::filesystem::path logpath(log_path);
    logpath /= childdir;
    if (!boost::filesystem::exists(logpath)) {
        boost::filesystem::create_directories(logpath);
    }
    return logpath.string();
}

void ExitTimeout(void* parg)
{
#ifdef __WXMSW__
    Sleep(5000);
    ExitProcess(0);
#endif
}

string GetLockFile()
{
    return GetDataDir() + "/.lock";
}

static std::shared_ptr<boost::interprocess::file_lock> g_pLock;

void StopApplication()
{
	Shutdown(nullptr);
}

bool IsStopped()
{
    return fShutdown || fExit;
}


void ShutdownExcludeRPCServer()
{
    

    g_sys_interrupted = 1;

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::ledger, 0, 0, 0));
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::ledger,
            g_cryptoToken.GetHID(), g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID()));
    }

    if (g_pLock) {
        g_pLock->unlock();
    }

    fShutdown = true;
    nTransactionsUpdated++;
    DBFlush(false);
    StopNode(false);
    DBFlush(true);
    boost::filesystem::remove(GetPidFile());
    UnregisterWallet(pwalletMain);
    delete pwalletMain;
    pwalletMain = nullptr;
    //CreateThread(ExitTimeout, NULL);
    Sleep(50);

}

void Shutdown(void* parg)
{
    static CCriticalSection cs_Shutdown;
    static bool fTaken;
    bool fFirstThread;
    CRITICAL_BLOCK(cs_Shutdown)
    {
        fFirstThread = !fTaken;
        fTaken = true;
    }

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::ledger, 0, 0, 0));
        consensuseng->UnregisterAppCallback(T_APPTYPE(APPTYPE::ledger,
            g_cryptoToken.GetHID(), g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID()));
    }

	if (g_pLock) {
		g_pLock->unlock();
	}

    if (fFirstThread)
    {
        printf("Stopping Hyperchain Ledger...\n");
        fShutdown = true;
        StopMQHandler();
        StopRPCServer();
        nTransactionsUpdated++;
        DBFlush(false);
        StopNode();
        DBFlush(true);
        boost::filesystem::remove(GetPidFile());
        UnregisterWallet(pwalletMain);
        delete pwalletMain;
        //CreateThread(ExitTimeout, NULL);
        Sleep(50);
        fExit = true;
    }
 }

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

bool LoadCryptoToken()
{
    

    CApplicationSettings appini;
    string defaultAppHash;
    appini.ReadDefaultApp(defaultAppHash);

    string tokenhash = GetArg("-tokenhash", "");

    if (tokenhash.empty()) {
        tokenhash = defaultAppHash;
    }
    g_cryptoToken.SelectNetWorkParas();
    if (!CryptoToken::ContainToken(tokenhash)) {

        ERROR_FL("Invalid CryptoToken hash: %s", tokenhash.c_str());

		if (CryptoToken::ContainToken(defaultAppHash)) {
            ERROR_FL("Invalid Cryptotoken: %s", defaultAppHash.c_str());
            tokenhash = defaultAppHash;
        }
        else {
            

            tokenhash = g_cryptoToken.GetHashPrefixOfGenesis();
        }

    }

    if (defaultAppHash != tokenhash) {
        appini.WriteDefaultApp(tokenhash);
    }

    

    if (g_cryptoToken.GetHashPrefixOfGenesis() != tokenhash) {
        string errmsg;
        if (!g_cryptoToken.ReadTokenFile("", tokenhash, errmsg)) {
            return ERROR_FL("Not found cryptotoken: %s", tokenhash.c_str());
        }
    }
    hashGenesisBlock = g_cryptoToken.GetHashGenesisBlock();

    

    string strLedgerDir = CreateChildDir(g_cryptoToken.GetTokenConfigPath());
    strlcpy(pszSetDataDir, strLedgerDir.c_str(), sizeof(pszSetDataDir));

    return true;
}


bool StartApplication(PluginContext* context)
{
    bool fRet = false;
    fShutdown = false;
    try {
        context->SetPluginContext();
        fRet = AppInit2(context->pc_argc, context->pc_argv);
        fExit = !fRet;
    }
    catch (std::exception& e) {
        PrintException(&e, "AppInit()");
    }
    catch (...) {
        PrintException(NULL, "AppInit()");
    }
    if (!fRet) {
        printf("Failed to start Ledger");
        Shutdown(NULL);
    }

    return fRet;
}

bool AppInit2(int argc, char* argv[])
{
#ifdef _MSC_VER
    // Turn off microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, ctrl-c
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifndef __WXMSW__
    umask(077);
#endif
#ifndef __WXMSW__
    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
#endif

    AppParseParameters(argc, argv);
    ReadConfigFile(mapArgs, mapMultiArgs); // Must be done after processing datadir

    fDebug = GetBoolArg("-debug");
    fAllowDNS = GetBoolArg("-dns");

#ifndef __WXMSW__
    fDaemon = GetBoolArg("-daemon");
#else
    fDaemon = false;
#endif

    if (fDaemon)
        fServer = true;
    else
        fServer = GetBoolArg("-server");

    /* force fServer when running */
    fServer = true;

    fPrintToConsole = GetBoolArg("-printtoconsole");
    fPrintToDebugger = GetBoolArg("-printtodebugger");
    fPrintToDebugFile = GetBoolArg("-printtofile");

    fTestNet = GetBoolArg("-testnet");
    bool fTOR = (fUseProxy && addrProxy.port == htons(9050));
    fNoListen = GetBoolArg("-nolisten") || fTOR;
    fLogTimestamps = GetBoolArg("-logtimestamps");

    for (int i = 1; i < argc; i++)
        if (!IsSwitchChar(argv[i][0]))
            fCommandLine = true;

    if (fCommandLine) {
        int ret = CommandLineRPC(argc, argv);
        exit(ret);
    }

    pro_ver = ProtocolVer::NET::SAND_BOX;
    if (mapArgs.count("-model") && mapArgs["-model"] == "informal")
        pro_ver = ProtocolVer::NET::INFORMAL_NET;

    

    LoadCryptoToken();

    if (!fDebug && !pszSetDataDir[0])
        ShrinkDebugFile();
    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    printf("Hyperchain version %s\n", FormatFullVersion().c_str());

    if (GetBoolArg("-loadblockindextest")) {
        CTxDB txdb("r");
        txdb.LoadBlockIndex();
        PrintBlockTree();
        return false;
    }

    // Make sure only a single bitcoin process is using the data directory.
    string strLockFile = GetLockFile();

    FILE* file = fopen(strLockFile.c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);
    g_pLock = make_shared<boost::interprocess::file_lock>(strLockFile.c_str());

    if (!g_pLock->try_lock()) {
        wxMessageBox(strprintf(_("Cannot obtain a lock on data directory %s. Ledger is probably already running."), GetDataDir().c_str()), "Hyperchain");
        return false;
    }

    // Bind to the port early so we can tell if another instance is already running.
    string strErrors;
    //if (!fNoListen)
    //{
        //if (!BindListenPort(strErrors))
        //{
        //    wxMessageBox(strErrors, "Hyperchain");
        //    return false;
        //}
    //}

    //
    // Load data files
    //
    if (fDaemon)
        fprintf(stdout, "Ledger server starting\n");
    strErrors = "";
    int64 nStart;

    printf("Loading addresses...\n");
    nStart = GetTimeMillis();
    if (!LoadAddresses())
        strErrors += _("Error loading addr.dat      \n");
    printf(" addresses   %15" PRI64d " ms\n", GetTimeMillis() - nStart);


    printf("Loading block index...\n");
    nStart = GetTimeMillis();
    if (!LoadBlockIndex())
        strErrors += _("Error loading blkindex.dat      \n");

    printf(" block index %15" PRI64d "ms\n", GetTimeMillis() - nStart);
    printf("Loading wallet...\n");
    nStart = GetTimeMillis();
    bool fFirstRun;

    if (!pwalletMain) {
        pwalletMain = new CWallet("wallet.dat");
    }
    int nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);

    

    if (GetBoolArg("-importkey") && g_cryptoToken.IsSysToken()) {
        CKey key;
        if (ReadKeyFromFile(key)) {
            CBitcoinAddress coinaddress = CBitcoinAddress(key.GetPubKey());
            if (pwalletMain->HaveKey(coinaddress)) {
                string str = coinaddress.ToString();
                fprintf(stdout, "Ledger's genesis key already exist : %s\n", str.c_str());
            }
            else if (pwalletMain->AddKey(key)) {
                pwalletMain->SetDefaultKey(key.GetPubKey());
                pwalletMain->SetAddressBookName(coinaddress, "");

                fprintf(stdout, "Ledger's genesis key imported successfully\n");
            }
            else {
                fprintf(stderr, "Ledger's genesis key imported failed\n");
            }
        }
        else {
            fprintf(stderr, "ReadKeyFromFile failed\n");
        }
    }

    

    if (GetBoolArg("-scangenesis") || pindexBest == pindexGenesisBlock) {
        pwalletMain->ScanForWalletTransactions(pindexBest, true);
    }

    if (nLoadWalletRet != DB_LOAD_OK) {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors += _("Error loading wallet.dat: Wallet corrupted      \n");
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors += _("Error loading wallet.dat: Wallet requires newer version of Ledger      \n");
        else
            strErrors += _("Error loading wallet.dat      \n");
    }

    printf(" wallet      %15" PRI64d "ms\n", GetTimeMillis() - nStart);
    RegisterWallet(pwalletMain);

    CBlockIndex *pindexRescan = pindexBest;
    if (GetBoolArg("-rescan"))
        pindexRescan = pindexGenesisBlock;
    else {
        CWalletDB walletdb("wallet.dat");
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = locator.GetBlockIndex();
    }
    if (pindexBest != pindexRescan) {
        printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->Height() - pindexRescan->Height(), pindexRescan->Height());
        nStart = GetTimeMillis();
        pwalletMain->ScanForWalletTransactions(pindexRescan, true);

        printf(" rescan      %15" PRI64d "ms\n", GetTimeMillis() - nStart);
    }

    printf("Done loading\n");

    //// debug print
    printf("mapBlockIndex.size() = %d\n", mapBlockIndex.size());
    

    //printf("nBestHeight = %d\n", nBestHeight);
    printf("setKeyPool.size() = %d\n", pwalletMain->setKeyPool.size());
    printf("mapWallet.size() = %d\n", pwalletMain->mapWallet.size());
    printf("mapAddressBook.size() = %d\n", pwalletMain->mapAddressBook.size());

    if (!strErrors.empty()) {
        wxMessageBox(strErrors, "Ledger", wxOK | wxICON_ERROR);
        return false;
    }

    // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();

    //
    // Parameters
    //
    if (GetBoolArg("-printblockindex") || GetBoolArg("-printblocktree")) {
        PrintBlockTree();
        return false;
    }

    if (mapArgs.count("-timeout")) {
        int nNewTimeout = GetArg("-timeout", 5000);
        if (nNewTimeout > 0 && nNewTimeout < 600000)
            nConnectTimeout = nNewTimeout;
    }

    if (mapArgs.count("-printblock")) {
        string strMatch = mapArgs["-printblock"];
        int nFound = 0;
        for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi) {
            uint256 hash = (*mi).first;
            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0) {
                CBlockIndex* pindex = (*mi).second;
                CBlock block;
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                printf("\n");
                nFound++;
            }
        }
        if (nFound == 0)
            printf("No blocks matching %s were found\n", strMatch.c_str());
        return false;
    }

    fGenerateBitcoins = GetBoolArg("-gen");

    if (mapArgs.count("-proxy")) {
        fUseProxy = true;
        addrProxy = CAddress(mapArgs["-proxy"]);
        if (!addrProxy.IsValid()) {
            wxMessageBox(_("Invalid -proxy address"), "Ledger");
            return false;
        }
    }

    if (mapArgs.count("-addnode")) {
        BOOST_FOREACH(string strAddr, mapMultiArgs["-addnode"])
        {
            CAddress addr(strAddr, fAllowDNS);
            addr.nTime = 0; // so it won't relay unless successfully connected
            if (addr.IsValid())
                AddAddress(addr);
        }
    }
    

    //if (GetBoolArg("-nodnsseed"))
    //    printf("DNS seeding disabled\n");
    //else
    //    DNSAddressSeed();

    if (mapArgs.count("-paytxfee")) {
        if (!ParseMoney(mapArgs["-paytxfee"], nTransactionFee)) {
            wxMessageBox(_("Invalid amount for -paytxfee=<amount>"), "Ledger");
            return false;
        }
        if (nTransactionFee > 0.25 * COIN)
            wxMessageBox(_("Warning: -paytxfee is set very high.  This is the transaction fee you will pay if you send a transaction."), "Hyperchain", wxOK | wxICON_EXCLAMATION);
    }

    if (fHaveUPnP) {
#if USE_UPNP
        if (GetBoolArg("-noupnp"))
            fUseUPnP = false;
#else
        if (GetBoolArg("-upnp"))
            fUseUPnP = true;
#endif
    }

    if (!CheckDiskSpace())
        return false;

    RandAddSeedPerfmon();

    

    ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        CONSENSUSNOTIFY ledgerGenesisCallback =
            std::make_tuple(HandleGenesisBlockCb, nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr);

        consensuseng->RegisterAppCallback(T_APPTYPE(APPTYPE::ledger,0, 0, 0), ledgerGenesisCallback);

        CONSENSUSNOTIFY ledgerCallback =
            std::make_tuple(nullptr, PutTxsChainCb,
                nullptr,
                UpdateLedgerDataCb,
                ValidateLedgerDataCb,
                CheckChainCb,
                LedgerAcceptChainCb,
                nullptr,
                LedgerBlockUUIDCb,
                GetVPath,
                nullptr);

        consensuseng->RegisterAppCallback(
            T_APPTYPE(APPTYPE::ledger, g_cryptoToken.GetHID(), g_cryptoToken.GetChainNum(), g_cryptoToken.GetLocalID()),
            ledgerCallback);

        printf("Registered ledger callback\n");
    }

    StartMQHandler();
    if (!CreateThread(StartNode, NULL))
        printf("Error: CreateThread(StartNode) failed\n");

    if (fServer && !fRPCServerRunning) {
        StartRPCServer();
    }

    CreateThread(ThreadRSyncGetBlock, NULL);


    return true;
}

