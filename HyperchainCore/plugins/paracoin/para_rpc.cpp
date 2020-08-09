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
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifdef _WIN32
#include <WinSock2.h>
#endif

#include "headers.h"
#include "cryptopp/sha.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "cryptocurrency.h"
#include "paratask.h"
#include "db/dbmgr.h"

#undef printf
#include <boost/asio.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> SSLStream;
#endif
#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"
#define printf OutputDebugStringF
// MinGW 3.4.5 gets "fatal error: had to relocate PCH" if the json headers are
// precompiled in headers.h.  The problem might be when the pch file goes over
// a certain size around 145MB.  If we need access to json_spirit outside this
// file, we could use the compiled json_spirit option.

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace json_spirit;

void ThreadRPCServer2(void* parg);
typedef Value(*rpcfn_type)(const Array& params, bool fHelp);
extern map<string, rpcfn_type> mapCallTable;

static int64 nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

std::list<std::shared_ptr<boost::asio::io_service>> rpcServerList;

extern bool ResolveBlock(CBlock& block, const char* payload, size_t payloadlen);

Value issuecoin(const Array& params, bool fHelp);
Value gid2rid(const Array& params, bool fHelp);
Value commitcoin(const Array& params, bool fHelp);
Value querygenesisblock(const Array& params, bool fHelp);
Value getcoininfo(const Array& params, bool fHelp);
Value importcoin(const Array& params, bool fHelp);
Value startmining(const Array& params, bool fHelp);
Value stopmining(const Array& params, bool fHelp);
Value queryminingstatus(const Array& params, bool fHelp);

Object JSONRPCError(int code, const string& message)
{
    Object error;
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}


void PrintConsole(const char* format, ...)
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
    printf("%s", buffer);
    fprintf(stdout, "%s", buffer);
}


int64 AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > 21000000.0)
        throw JSONRPCError(-3, "Invalid amount");
    int64 nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(-3, "Invalid amount");
    return nAmount;
}

Value ValueFromAmount(int64 amount)
{
    return (double)amount / (double)COIN;
}

void WalletTxToJSON(const CWalletTx& wtx, Object& entry)
{
    entry.push_back(Pair("confirmations", wtx.GetDepthInMainChain()));
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(-11, "Invalid account name");
    return strAccount;
}



///
/// Note: This interface may still be subject to change.
///


Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "Paracoin help [command]\n"
            "List commands, or get help for a command.");

    string strCommand;
    if (params.size() > 0)
        strCommand = params[0].get_str();

    string strRet;
    set<rpcfn_type> setDone;
    for (map<string, rpcfn_type>::iterator mi = mapCallTable.begin(); mi != mapCallTable.end(); ++mi)
    {
        string strMethod = (*mi).first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod == "getamountreceived" ||
            strMethod == "getallreceived" ||
            (strMethod.find("label") != string::npos))
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        try
        {
            Array params;
            rpcfn_type pfn = (*mi).second;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (std::exception& e)
        {
            // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != -1)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0, strRet.size() - 1);
    return strRet;
}


Value stop(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "stop\n"
            "Stop Paracoin server.");

    // Shutdown will take long enough that the response should get back
    CreateThread(Shutdown, NULL);
    return "Server is stopping";
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}


Value getblocknumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblocknumber\n"
            "Returns the block number of the latest block in the longest block chain.");

    return nBestHeight;
}


Value getconnectioncount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getconnectioncount\n"
            "Returns the number of connections to other nodes.");

    return (int)vNodes.size();
}


double GetDifficulty()
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.

    if (pindexBest == NULL)
        return 1.0;
    int nShift = (pindexBest->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(pindexBest->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.");

    return GetDifficulty();
}


Value getgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getgenerate\n"
            "Returns true or false.");

    return (bool)fGenerateBitcoins;
}


Value setgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setgenerate <generate> [genproclimit]\n"
            "<generate> is true or false to turn generation on or off.\n"
            "Generation is limited to [genproclimit] processors, -1 is unlimited.");

    bool fGenerate = true;
    if (params.size() > 0)
        fGenerate = params[0].get_bool();

    if (params.size() > 1)
    {
        int nGenProcLimit = params[1].get_int();
        fLimitProcessors = (nGenProcLimit != -1);
        WriteSetting("fLimitProcessors", fLimitProcessors);
        if (nGenProcLimit != -1)
            WriteSetting("nLimitProcessors", nLimitProcessors = nGenProcLimit);
        if (nGenProcLimit == 0)
            fGenerate = false;
    }

    GenerateBitcoins(fGenerate, pwalletMain);
    return Value::null;
}


Value gethashespersec(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement while generating.");

    if (GetTimeMillis() - nHPSTimerStart > 8000)
        return (boost::int64_t)0;
    return (boost::int64_t)dHashesPerSec;
}


Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    Object obj;
    obj.push_back(Pair("version", (int)VERSION));
    obj.push_back(Pair("balance", ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("blocks", (int)nBestHeight));
    obj.push_back(Pair("connections", (int)vNodes.size()));
    obj.push_back(Pair("proxy", (fUseProxy ? addrProxy.ToStringIPPort() : string())));
    obj.push_back(Pair("generate", (bool)fGenerateBitcoins));
    obj.push_back(Pair("genproclimit", (int)(fLimitProcessors ? nLimitProcessors : -1)));
    obj.push_back(Pair("difficulty", (double)GetDifficulty()));
    obj.push_back(Pair("hashespersec", gethashespersec(params, false)));
    obj.push_back(Pair("testnet", fTestNet));
    obj.push_back(Pair("keypoololdest", (boost::int64_t)pwalletMain->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize", pwalletMain->GetKeyPoolSize()));
    obj.push_back(Pair("paytxfee", ValueFromAmount(nTransactionFee)));
    if (pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", (boost::int64_t)nWalletUnlockTime));
    obj.push_back(Pair("errors", GetWarnings("statusbar")));
    return obj;
}


Value getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress [account]\n"
            "Returns a new address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    std::vector<unsigned char> newKey;
    if (!pwalletMain->GetKeyFromPool(newKey, false))
        throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");
    CBitcoinAddress address(newKey);

    pwalletMain->SetAddressBookName(address, strAccount);

    return address.ToString();
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew = false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (!account.vchPubKey.empty())
    {
        CScript scriptPubKey;
        scriptPubKey.SetBitcoinAddress(account.vchPubKey);
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
            it != pwalletMain->mapWallet.end() && !account.vchPubKey.empty();
            ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (account.vchPubKey.empty() || bForceNew || bKeyUsed)
    {
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey, false))
            throw JSONRPCError(-12, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBookName(CBitcoinAddress(account.vchPubKey), strAccount);
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey);
}

Value getaccountaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress <account>\n"
            "Returns the current ledger address for receiving payments to this account.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    Object ret;
    ret.push_back(Pair(strAccount, GetAccountAddress(strAccount).ToString()));

    return ret;
}



Value setaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount <address> <account>\n"
            "Sets the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid address");


    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (pwalletMain->mapAddressBook.count(address))
    {
        string strOldAccount = pwalletMain->mapAddressBook[address];
        if (address == GetAccountAddress(strOldAccount))
            GetAccountAddress(strOldAccount, true);
    }

    pwalletMain->SetAddressBookName(address, strAccount);

    return Value::null;
}


Value getaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccount <address>\n"
            "Returns the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid address");

    string strAccount;
    map<CBitcoinAddress, string>::iterator mi = pwalletMain->mapAddressBook.find(address);
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;
    return strAccount;
}


Value getaddressesbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    Array ret;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    // Amount
    int64 nAmount = 0;
    if (params[0].get_real() != 0.0)
        nAmount = AmountFromValue(params[0]);        // rejects 0.0 amounts

    nTransactionFee = nAmount;
    return true;
}

Value sendtoaddress(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendtoaddress <ledgeraddress> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001\n"
            "requires wallet passphrase to be set with walletpassphrase first");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendtoaddress <ledgeraddress> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid address");

    // Amount
    int64 nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["to"] = params[3].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwalletMain->SendMoneyToBitcoinAddress(address, nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(-4, strError);

    Object ret;
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));

    return ret;
}


Value getreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress <ledgeraddress> [minconf=1]\n"
            "Returns the total amount received by <ledgeraddress> in transactions with at least [minconf] confirmations.");

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid address");
    scriptPubKey.SetBitcoinAddress(address);
    if (!IsMine(*pwalletMain, scriptPubKey))
        return (double)0.0;

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    int64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


void GetAccountAddresses(string strAccount, set<CBitcoinAddress>& setAddress)
{
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            setAddress.insert(address);
    }
}


Value getreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys that have the label
    string strAccount = AccountFromValue(params[0]);
    set<CBitcoinAddress> setAddress;
    GetAccountAddresses(strAccount, setAddress);

    // Tally
    int64 nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CBitcoinAddress address;
            if (ExtractAddress(txout.scriptPubKey, pwalletMain, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


int64 GetAccountBalance(CWalletDB& walletdb, const string& strAccount, int nMinDepth)
{
    int64 nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (!wtx.IsFinal())
            continue;

        int64 nGenerated, nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nGenerated, nReceived, nSent, nFee);

        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth)
            nBalance += nReceived;
        nBalance += nGenerated - nSent - nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

int64 GetAccountBalance(const string& strAccount, int nMinDepth)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth);
}


Value getbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getbalance [account] [minconf=1]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.");

    if (params.size() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    if (params[0].get_str() == "*") {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' should always return the same number.
        int64 nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsFinal())
                continue;

            int64 allGeneratedImmature, allGeneratedMature, allFee;
            allGeneratedImmature = allGeneratedMature = allFee = 0;
            string strSentAccount;
            list<pair<CBitcoinAddress, int64> > listReceived;
            list<pair<CBitcoinAddress, int64> > listSent;
            wtx.GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount);
            if (wtx.GetDepthInMainChain() >= nMinDepth)
                BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, int64)& r, listReceived)
                nBalance += r.second;
            BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, int64)& r, listSent)
                nBalance -= r.second;
            nBalance -= allFee;
            nBalance += allGeneratedMature;
        }
        return  ValueFromAmount(nBalance);
    }

    string strAccount = AccountFromValue(params[0]);

    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);

    return ValueFromAmount(nBalance);
}


Value movecmd(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    int64 nAmount = AmountFromValue(params[2]);
    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.TxnBegin();

    int64 nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    walletdb.TxnCommit();

    return true;
}


Value sendfrom(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 3 || params.size() > 6))
        throw runtime_error(
            "sendfrom <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001\n"
            "requires wallet passphrase to be set with walletpassphrase first");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() < 3 || params.size() > 6))
        throw runtime_error(
            "sendfrom <fromaccount> <toaddress> <amount> [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.00000001");

    string strAccount = AccountFromValue(params[0]);
    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(-5, "Invalid address");
    int64 nAmount = AmountFromValue(params[2]);
    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();
    if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
        wtx.mapValue["to"] = params[5].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Check funds
    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);
    if (nAmount > nBalance)
        throw JSONRPCError(-6, "Account has insufficient funds");

    // Send
    string strError = pwalletMain->SendMoneyToBitcoinAddress(address, nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(-4, strError);

    return wtx.GetHash().GetHex();
}


Value sendmany(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers\n"
            "requires wallet passphrase to be set with walletpassphrase first");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() < 2 || params.size() > 4))
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers");

    string strAccount = AccountFromValue(params[0]);
    Object sendTo = params[1].get_obj();
    int nMinDepth = 1;
    if (params.size() > 2)
        nMinDepth = params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();

    set<CBitcoinAddress> setAddress;
    vector<pair<CScript, int64> > vecSend;

    int64 totalAmount = 0;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(-5, string("Invalid address:") + s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(-8, string("Invalid parameter, duplicated address: ") + s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetBitcoinAddress(address);
        int64 nAmount = AmountFromValue(s.value_);
        totalAmount += nAmount;

        vecSend.push_back(make_pair(scriptPubKey, nAmount));
    }

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Check funds
    int64 nBalance = GetAccountBalance(strAccount, nMinDepth);
    if (totalAmount > nBalance)
        throw JSONRPCError(-6, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwalletMain);
    int64 nFeeRequired = 0;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);
    if (!fCreated)
    {
        if (totalAmount + nFeeRequired > pwalletMain->GetBalance())
            throw JSONRPCError(-6, "Insufficient funds");
        throw JSONRPCError(-4, "Transaction creation failed");
    }
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(-4, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}


struct tallyitem
{
    int64 nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = INT_MAX;
    }
};

Value ListReceived(const Array& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    // Tally
    map<CBitcoinAddress, tallyitem> mapTally;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || !wtx.IsFinal())
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CBitcoinAddress address;
            if (!ExtractAddress(txout.scriptPubKey, pwalletMain, address) || !address.IsValid())
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
        }
    }

    // Reply
    Array ret;
    map<string, tallyitem> mapAccountTally;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strAccount = item.second;
        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        int64 nAmount = 0;
        int nConf = INT_MAX;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (fByAccounts)
        {
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = min(item.nConf, nConf);
        }
        else
        {
            Object obj;
            obj.push_back(Pair("address", address.ToString()));
            obj.push_back(Pair("account", strAccount));
            obj.push_back(Pair("label", strAccount)); // deprecated
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == INT_MAX ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            int64 nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            Object obj;
            obj.push_back(Pair("account", (*it).first));
            obj.push_back(Pair("label", (*it).first)); // deprecated
            obj.push_back(Pair("amount", ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == INT_MAX ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

Value listreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, false);
}

Value listreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, true);
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret)
{
    int64 nGeneratedImmature, nGeneratedMature, nFee;
    string strSentAccount;
    list<pair<CBitcoinAddress, int64> > listReceived;
    list<pair<CBitcoinAddress, int64> > listSent;
    wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);

    bool fAllAccounts = (strAccount == string("*"));

    // Generated blocks assigned to account ""
    if ((nGeneratedMature + nGeneratedImmature) != 0 && (fAllAccounts || strAccount == ""))
    {
        Object entry;
        entry.push_back(Pair("account", string("")));
        if (nGeneratedImmature)
        {
            entry.push_back(Pair("category", wtx.GetDepthInMainChain() ? "immature" : "orphan"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedImmature)));
        }
        else
        {
            entry.push_back(Pair("category", "generate"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
        }
        if (fLong)
            WalletTxToJSON(wtx, entry);
        ret.push_back(entry);
    }

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, int64)& s, listSent)
        {
            Object entry;
            entry.push_back(Pair("account", strSentAccount));
            entry.push_back(Pair("address", s.first.ToString()));
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.second)));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
        BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, int64)& r, listReceived)
    {
        string account;
        if (pwalletMain->mapAddressBook.count(r.first))
            account = pwalletMain->mapAddressBook[r.first];
        if (fAllAccounts || (account == strAccount))
        {
            Object entry;
            entry.push_back(Pair("account", account));
            entry.push_back(Pair("address", r.first.ToString()));
            entry.push_back(Pair("category", "receive"));
            entry.push_back(Pair("amount", ValueFromAmount(r.second)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

Value listtransactions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    Array ret;
    CWalletDB walletdb(pwalletMain->strWalletFile);

    // Firs: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap:
    typedef pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef multimap<int64, TxPair > TxItems;
    TxItems txByTime;

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txByTime.insert(make_pair(wtx->GetTxTime(), TxPair(wtx, (CAccountingEntry*)0)));
    }
    list<CAccountingEntry> acentries;
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txByTime.insert(make_pair(entry.nTime, TxPair((CWalletTx*)0, &entry)));
    }

    // Now: iterate backwards until we have nCount items to return:
    TxItems::reverse_iterator it = txByTime.rbegin();
    if (txByTime.size() > nFrom) std::advance(it, nFrom);
    for (; it != txByTime.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if (ret.size() >= nCount) break;
    }
    // ret is now newest to oldest

    // Make sure we return only last nCount items (sends-to-self might give us an extra):
    if (ret.size() > nCount)
    {
        Array::iterator last = ret.begin();
        std::advance(last, nCount);
        ret.erase(last, ret.end());
    }
    std::reverse(ret.begin(), ret.end()); // oldest to newest

    return ret;
}

Value listaccounts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    typedef struct tagBalance
    {
        int64 nTotal = 0;
        int64 nGeneratedMature = 0;

        void operator +=(int64 nFee) {
            nTotal += nFee;
            nGeneratedMature += nFee;
        }
        void operator -=(int64 nFee) {
            nTotal -= nFee;
            nGeneratedMature -= nFee;
        }
        Array ToArray() const {
            Array arr;
            arr.push_back(ValueFromAmount(nTotal).get_real());
            arr.push_back(ValueFromAmount(nGeneratedMature).get_real());
            return arr;
        }
    } Balances;

    map<string, Balances> mapAccountBalances;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& entry, pwalletMain->mapAddressBook) {
        if (pwalletMain->HaveKey(entry.first)) // This address belongs to me
            mapAccountBalances[entry.second] = Balances();
    }

    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        int64 nGeneratedImmature, nGeneratedMature, nFee;
        string strSentAccount;
        list<pair<CBitcoinAddress, int64> > listReceived;
        list<pair<CBitcoinAddress, int64> > listSent;
        wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount);
        mapAccountBalances[strSentAccount] -= nFee;
        mapAccountBalances[strSentAccount].nTotal += nGeneratedImmature;
        BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, int64)& s, listSent)
            mapAccountBalances[strSentAccount] -= s.second;
        if (wtx.GetDepthInMainChain() >= nMinDepth)
        {
            mapAccountBalances[""]+= nGeneratedMature;
            BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, int64)& r, listReceived)
                if (pwalletMain->mapAddressBook.count(r.first))
                    mapAccountBalances[pwalletMain->mapAddressBook[r.first]]+= r.second;
                else
                    mapAccountBalances[""]+= r.second;
        }
    }

    list<CAccountingEntry> acentries;
    CWalletDB(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    Object ret;
    BOOST_FOREACH(const PAIRTYPE(string, Balances)& accountBalance, mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, accountBalance.second.ToArray()));
    }
    return ret;
}

Value gettransactionaddr(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransactionaddr <txid>\n"
            "Get logical address about <txid>");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    Object entry;

    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(-5, "Invalid or non-wallet transaction id");

    CTxIndex txindex;
    if (!CTxDB_Wrapper("r").ReadTxIndex(hash, txindex))
        throw JSONRPCError(-5, "Failed to read transaction");

    entry.push_back(Pair("address",txindex.pos.addr.tostring()));

    return entry;
}

Value gettransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about <txid>");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    Object entry;

    if (!pwalletMain->mapWallet.count(hash))
        throw JSONRPCError(-5, "Invalid or non-wallet transaction id");
    const CWalletTx& wtx = pwalletMain->mapWallet[hash];

    int64 nCredit = wtx.GetCredit();
    int64 nDebit = wtx.GetDebit();
    int64 nNet = nCredit - nDebit;
    int64 nFee = (wtx.IsFromMe() ? wtx.GetValueOut() - nDebit : 0);

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
    if (wtx.IsFromMe())
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(pwalletMain->mapWallet[hash], entry);

    Array details;
    ListTransactions(pwalletMain->mapWallet[hash], "*", 0, false, details);
    entry.push_back(Pair("details", details));

    return entry;
}


Value backupwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");

    string strDest = params[0].get_str();
    BackupWallet(*pwalletMain, strDest);

    Object entry;
    entry.push_back(Pair("hashprefix", g_cryptoCurrency.GetHashPrefixOfGenesis()));

    return entry;
}


Value keypoolrefill(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() > 0))
        throw runtime_error(
            "keypoolrefill\n"
            "Fills the keypool, requires wallet passphrase to be set.");
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() > 0))
        throw runtime_error(
            "keypoolrefill\n"
            "Fills the keypool.");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    pwalletMain->TopUpKeyPool();

    if (pwalletMain->GetKeyPoolSize() < GetArg("-keypool", 100))
        throw JSONRPCError(-4, "Error refreshing keypool.");

    return Value::null;
}


void ThreadTopUpKeyPool(void* parg)
{
    pwalletMain->TopUpKeyPool();
}

void ThreadCleanWalletPassphrase(void* parg)
{
    int64 nMyWakeTime = GetTime() + *((int*)parg);

    if (nWalletUnlockTime == 0)
    {
        CRITICAL_BLOCK(cs_nWalletUnlockTime)
        {
            nWalletUnlockTime = nMyWakeTime;
        }

        while (GetTime() < nWalletUnlockTime)
            Sleep(GetTime() - nWalletUnlockTime);

        CRITICAL_BLOCK(cs_nWalletUnlockTime)
        {
            nWalletUnlockTime = 0;
        }
    }
    else
    {
        CRITICAL_BLOCK(cs_nWalletUnlockTime)
        {
            if (nWalletUnlockTime < nMyWakeTime)
                nWalletUnlockTime = nMyWakeTime;
        }
        free(parg);
        return;
    }

    pwalletMain->Lock();

    delete (int*)parg;
}

Value walletpassphrase(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    if (!pwalletMain->IsLocked())
        throw JSONRPCError(-17, "Error: Wallet is already unlocked.");

    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    string strWalletPass;
    strWalletPass.reserve(100);
    mlock(&strWalletPass[0], strWalletPass.capacity());
    strWalletPass = params[0].get_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
        {
            fill(strWalletPass.begin(), strWalletPass.end(), '\0');
            munlock(&strWalletPass[0], strWalletPass.capacity());
            throw JSONRPCError(-14, "Error: The wallet passphrase entered was incorrect.");
        }
        fill(strWalletPass.begin(), strWalletPass.end(), '\0');
        munlock(&strWalletPass[0], strWalletPass.capacity());
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    CreateThread(ThreadTopUpKeyPool, NULL);
    int* pnSleepTime = new int(params[1].get_int());
    CreateThread(ThreadCleanWalletPassphrase, pnSleepTime);

    return Value::null;
}


Value walletpassphrasechange(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 2))
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    string strOldWalletPass;
    strOldWalletPass.reserve(100);
    mlock(&strOldWalletPass[0], strOldWalletPass.capacity());
    strOldWalletPass = params[0].get_str();

    string strNewWalletPass;
    strNewWalletPass.reserve(100);
    mlock(&strNewWalletPass[0], strNewWalletPass.capacity());
    strNewWalletPass = params[1].get_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
    {
        fill(strOldWalletPass.begin(), strOldWalletPass.end(), '\0');
        fill(strNewWalletPass.begin(), strNewWalletPass.end(), '\0');
        munlock(&strOldWalletPass[0], strOldWalletPass.capacity());
        munlock(&strNewWalletPass[0], strNewWalletPass.capacity());
        throw JSONRPCError(-14, "Error: The wallet passphrase entered was incorrect.");
    }
    fill(strNewWalletPass.begin(), strNewWalletPass.end(), '\0');
    fill(strOldWalletPass.begin(), strOldWalletPass.end(), '\0');
    munlock(&strOldWalletPass[0], strOldWalletPass.capacity());
    munlock(&strNewWalletPass[0], strNewWalletPass.capacity());

    return Value::null;
}


Value walletlock(const Array& params, bool fHelp)
{
    if (pwalletMain->IsCrypted() && (fHelp || params.size() != 0))
        throw runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    if (fHelp)
        return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an unencrypted wallet, but walletlock was called.");

    pwalletMain->Lock();
    CRITICAL_BLOCK(cs_nWalletUnlockTime)
    {
        nWalletUnlockTime = 0;
    }

    return Value::null;
}


Value encryptwallet(const Array& params, bool fHelp)
{
    if (!pwalletMain->IsCrypted() && (fHelp || params.size() != 1))
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    if (fHelp)
        return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(-15, "Error: running with an encrypted wallet, but encryptwallet was called.");

    string strWalletPass;
    strWalletPass.reserve(100);
    mlock(&strWalletPass[0], strWalletPass.capacity());
    strWalletPass = params[0].get_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass))
    {
        fill(strWalletPass.begin(), strWalletPass.end(), '\0');
        munlock(&strWalletPass[0], strWalletPass.capacity());
        throw JSONRPCError(-16, "Error: Failed to encrypt the wallet.");
    }
    fill(strWalletPass.begin(), strWalletPass.end(), '\0');
    munlock(&strWalletPass[0], strWalletPass.capacity());

    return Value::null;
}


Value validateaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress <ledgeraddress>\n"
            "Return information about <ledgeraddress>.");

    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        // Call Hash160ToAddress() so we always return current ADDRESSVERSION
        // version of the address:
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));
        ret.push_back(Pair("ismine", (pwalletMain->HaveKey(address) > 0)));
        if (pwalletMain->mapAddressBook.count(address))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[address]));
    }
    return ret;
}


Value getwork(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data\n"
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash\n"
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (vNodes.empty())
        throw JSONRPCError(-9, "Hyperchain is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(-10, "Hyperchain is downloading blocks...");

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static vector<CBlock*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64 nStart;
        static CBlock* pblock;
        if (pindexPrev != pindexBest.get() ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest.get())
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }
            nTransactionsUpdatedLast = nTransactionsUpdated;
            pindexPrev = pindexBest.get();
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(reservekey);
            if (!pblock)
                throw JSONRPCError(-7, "Out of memory");
            vNewBlock.push_back(pblock);
        }

        // Update nTime
        pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Prebuild hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        Object result;
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate))));
        result.push_back(Pair("data", HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("hash1", HexStr(BEGIN(phash1), END(phash1))));
        result.push_back(Pair("target", HexStr(BEGIN(hashTarget), END(hashTarget))));
        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        if (vchData.size() != 128)
            throw JSONRPCError(-8, "Invalid parameter");
        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (int i = 0; i < 128 / 4; i++)
            ((unsigned int*)pdata)[i] = CryptoPP::ByteReverse(((unsigned int*)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        return CheckWork(pblock, *pwalletMain, reservekey);
    }
}











//
// Call Table
//

pair<string, rpcfn_type> pCallTable[] =
{
    make_pair("help",                   &help),
    make_pair("stop",                   &stop),
    make_pair("getblockcount",          &getblockcount),
    make_pair("getblocknumber",         &getblocknumber),
    make_pair("getconnectioncount",     &getconnectioncount),
    make_pair("getdifficulty",          &getdifficulty),
    make_pair("getgenerate",            &getgenerate),
    make_pair("setgenerate",            &setgenerate),
    make_pair("gethashespersec",        &gethashespersec),
    make_pair("getinfo",                &getinfo),
    make_pair("getnewaddress",          &getnewaddress),
    make_pair("getaccountaddress",      &getaccountaddress),
    make_pair("setaccount",             &setaccount),
    make_pair("getaccount",             &getaccount),
    make_pair("getaddressesbyaccount",  &getaddressesbyaccount),
    make_pair("sendtoaddress",          &sendtoaddress),
    make_pair("getreceivedbyaddress",   &getreceivedbyaddress),
    make_pair("getreceivedbyaccount",   &getreceivedbyaccount),
    make_pair("listreceivedbyaddress",  &listreceivedbyaddress),
    make_pair("listreceivedbyaccount",  &listreceivedbyaccount),
    make_pair("backupwallet",           &backupwallet),
    make_pair("keypoolrefill",          &keypoolrefill),
    make_pair("walletpassphrase",       &walletpassphrase),
    make_pair("walletpassphrasechange", &walletpassphrasechange),
    make_pair("walletlock",             &walletlock),
    make_pair("encryptwallet",          &encryptwallet),
    make_pair("validateaddress",        &validateaddress),
    make_pair("getbalance",             &getbalance),
    make_pair("move",                   &movecmd),
    make_pair("sendfrom",               &sendfrom),
    make_pair("sendmany",               &sendmany),
    make_pair("gettransaction",         &gettransaction),
    make_pair("gettransactionaddr",     &gettransactionaddr),
    make_pair("listtransactions",       &listtransactions),
    make_pair("getwork",                &getwork),
    make_pair("listaccounts",           &listaccounts),
    make_pair("settxfee",               &settxfee),
    make_pair("issuecoin",              &issuecoin),
    make_pair("gid2rid",                &gid2rid),
    make_pair("commitcoin",             &commitcoin),
    make_pair("querygenesisblock",      &querygenesisblock),
    make_pair("getcoininfo",            &getcoininfo),
    make_pair("importcoin",             &importcoin),
    make_pair("startmining",            &startmining),
    make_pair("stopmining",             &stopmining),
    make_pair("queryminingstatus",      &queryminingstatus),
};

map<string, rpcfn_type> mapCallTable(pCallTable, pCallTable + sizeof(pCallTable) / sizeof(pCallTable[0]));

string pAllowInSafeMode[] =
{
    "help",
    "stop",
    "getblockcount",
    "getblocknumber",
    "getconnectioncount",
    "getdifficulty",
    "getgenerate",
    "setgenerate",
    "gethashespersec",
    "getinfo",
    "getnewaddress",
    "getaccountaddress",
    "getaccount",
    "getaddressesbyaccount",
    "backupwallet",
    "keypoolrefill",
    "walletpassphrase",
    "walletlock",
    "validateaddress",
    "getwork",
};
set<string> setAllowInSafeMode(pAllowInSafeMode, pAllowInSafeMode + sizeof(pAllowInSafeMode) / sizeof(pAllowInSafeMode[0]));




//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string, string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
        << "User-Agent: paracoin-json-rpc/" << FormatFullVersion() << "\r\n"
        << "Host: 127.0.0.1\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << strMsg.size() << "\r\n"
        << "Accept: application/json\r\n";
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want posix (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg)
{
    if (nStatus == 401)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: paracoin-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
    string strStatus;
    if (nStatus == 200) strStatus = "OK";
    else if (nStatus == 400) strStatus = "Bad Request";
    else if (nStatus == 403) strStatus = "Forbidden";
    else if (nStatus == 404) strStatus = "Not Found";
    else if (nStatus == 500) strStatus = "Internal Server Error";
    return strprintf(
        "HTTP/1.1 %d %s\r\n"
        "Date: %s\r\n"
        "Connection: close\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: application/json\r\n"
        "Server: paracoin-json-rpc/%s\r\n"
        "\r\n"
        "%s",
        nStatus,
        strStatus.c_str(),
        rfc1123Time().c_str(),
        strMsg.size(),
        FormatFullVersion().c_str(),
        strMsg.c_str());
}

int ReadHTTPStatus(std::basic_istream<char>& stream)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return 500;
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    loop
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon + 1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nStatus = ReadHTTPStatus(stream);

    // Read header
    int nLen = ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > MAX_SIZE)
        return 500;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);

       /* int nReadLeft = nLen;
        while (!stream.eof()) {
            stream.readsome(&vch[nLen-nReadLeft], nReadLeft);
            nReadLeft -= stream.gcount();
            if (nReadLeft == 0) {
                break;
            }
        }*/
        strMessageRet = string(vch.begin(), vch.end());
    }

    return nStatus;
}

string EncodeBase64_(string s)
{
    BIO *b64, *bmem;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, s.c_str(), s.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    string result(bptr->data, bptr->length);
    BIO_free_all(b64);

    return result;
}

string DecodeBase64_(string s)
{
    BIO *b64, *bmem;

    char* buffer = static_cast<char*>(calloc(s.size(), sizeof(char)));

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(const_cast<char*>(s.c_str()), s.size());
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, s.size());
    BIO_free_all(bmem);

    string result(buffer);
    free(buffer);
    return result;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0, 6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64_(strUserPass64);
    string::size_type nColon = strUserPass.find(":");
    if (nColon == string::npos)
        return false;
    string strUser = strUserPass.substr(0, nColon);
    string strPassword = strUserPass.substr(nColon + 1);
    return (strUser == mapArgs["-rpcuser"] && strPassword == mapArgs["-rpcpassword"]);
}

//
// JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return write_string(Value(reply), false) + "\n";
}

void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = 500;
    int code = find_value(objError, "code").get_int();
    if (code == -32600) nStatus = 400;
    else if (code == -32601) nStatus = 404;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply) << std::flush;
}

bool ClientAllowed(const string& strAddress)
{
    if (strAddress == asio::ip::address_v4::loopback().to_string())
        return true;
    const vector<string>& vAllow = mapMultiArgs["-rpcallowip"];
    BOOST_FOREACH(string strAllow, vAllow)
        if (WildcardMatch(strAddress, strAllow))
            return true;
    return false;
}

#ifdef USE_SSL
//
// IOStream device that speaks SSL but can also speak non-SSL
//
class SSLIOStreamDevice : public iostreams::device<iostreams::bidirectional> {
public:
    SSLIOStreamDevice(SSLStream &streamIn, bool fUseSSLIn) : stream(streamIn)
    {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(ssl::stream_base::handshake_type role)
    {
        if (!fNeedHandshake) return;
        fNeedHandshake = false;
        stream.handshake(role);
    }
    std::streamsize read(char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL) return stream.read_some(asio::buffer(s, n));
        return stream.next_layer().read_some(asio::buffer(s, n));
    }
    std::streamsize write(const char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL) return asio::write(stream, asio::buffer(s, n));
        return asio::write(stream.next_layer(), asio::buffer(s, n));
    }
    bool connect(const std::string& server, const std::string& port)
    {
        ip::tcp::resolver resolver(stream.get_io_service());
        ip::tcp::resolver::query query(server.c_str(), port.c_str());
        ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        ip::tcp::resolver::iterator end;
        boost::system::error_code error = asio::error::host_not_found;
        while (error && endpoint_iterator != end)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error)
            return false;
        return true;
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;
    SSLStream& stream;
};
#endif

void ThreadRPCServer(void* parg)
{
    

    //IMPLEMENT_RANDOMIZE_STACK(ThreadRPCServer(parg));
    fRPCServerRunning = true;
    try
    {
        vnThreadsRunning[4]++;
        ThreadRPCServer2(parg);
        vnThreadsRunning[4]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[4]--;
        PrintException(&e, "ThreadRPCServer()");
    }
    catch (...) {
        vnThreadsRunning[4]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
    fRPCServerRunning = false;

    printf("ThreadRPCServer exiting\n");
}

void HandleAccept(const system::error_code& error,
    boost::shared_ptr<asio::ip::tcp::socket> socket,
    asio::ip::tcp::acceptor& acceptor);

void StartAccept(boost::asio::ip::tcp::acceptor& acceptor)
{
    using boost::asio::ip::tcp;
    boost::shared_ptr< tcp::socket > socket(
        new tcp::socket(acceptor.get_executor()));

    // Add an accept call to the service.  This will prevent io_service::run()
    // from returning.
    acceptor.async_accept(*socket,
        boost::bind(HandleAccept,
            boost::asio::placeholders::error,
            socket,
            boost::ref(acceptor)));
}

void ThreadRPCServer2(void* parg)
{
    printf("ThreadRPCServer started\n");

    if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
    {
        string strWhatAmI = "To use Paracoin";
        if (mapArgs.count("-server"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-server\"");
        else if (mapArgs.count("-daemon"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-daemon\"");
        PrintConsole(
            _("Warning: %s, you must set rpcpassword=<password>\nin the configuration file: %s\n"
                "If the file does not exist, create it with owner-readable-only file permissions.\n"),
            strWhatAmI.c_str(),
            GetConfigFile().c_str());
        CreateThread(Shutdown, NULL);
        return;
    }

    bool fUseSSL = GetBoolArg("-rpcssl");
    asio::ip::address bindAddress = mapArgs.count("-rpcallowip") ? asio::ip::address_v4::any() : asio::ip::address_v4::loopback();

    asio::io_service& io_service = *reinterpret_cast<asio::io_service*>(parg);
    ip::tcp::endpoint endpoint(bindAddress, GetArg("-rpcparaport", 8118));
    ip::tcp::acceptor acceptor(io_service, endpoint);

    acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));

#ifdef USE_SSL
    ssl::context context(io_service, ssl::context::sslv23);
    if (fUseSSL)
    {
        context.set_options(ssl::context::no_sslv2);
        filesystem::path certfile = GetArg("-rpcsslcertificatechainfile", "server.cert");
        if (!certfile.is_complete()) certfile = filesystem::path(GetDataDir()) / certfile;
        if (filesystem::exists(certfile)) context.use_certificate_chain_file(certfile.string().c_str());
        else printf("ThreadRPCServer ERROR: missing server certificate file %s\n", certfile.string().c_str());
        filesystem::path pkfile = GetArg("-rpcsslprivatekeyfile", "server.pem");
        if (!pkfile.is_complete()) pkfile = filesystem::path(GetDataDir()) / pkfile;
        if (filesystem::exists(pkfile)) context.use_private_key_file(pkfile.string().c_str(), ssl::context::pem);
        else printf("ThreadRPCServer ERROR: missing server private key file %s\n", pkfile.string().c_str());

        string ciphers = GetArg("-rpcsslciphers",
            "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
        SSL_CTX_set_cipher_list(context.impl(), ciphers.c_str());
    }
#else
    if (fUseSSL)
        throw runtime_error("-rpcssl=1, but ledger compiled without full openssl libraries.");
#endif

    

    StartAccept(acceptor);

    

    io_service.run();
}

void HandleWrite(boost::shared_ptr<asio::ip::tcp::socket> socket,
    std::shared_ptr<boost::asio::streambuf> stream, const boost::system::error_code& error)
{
    return;
}

void HandleReadHttpBody(boost::shared_ptr<asio::ip::tcp::socket> socket,
                std::shared_ptr<boost::asio::streambuf> stream, int content_len, const boost::system::error_code& error)
{
    if (content_len == 0) {
        return;
    }

    if (!error)
    {
        std::istream stream_in(stream.get());
        std::ostream stream_out(stream.get());

        vector<char> vch(content_len);
        stream_in.read(&vch[0], content_len);

        string strRequest = string(vch.begin(), vch.end());
        Value id = Value::null;
        try
        {
            // Parse request
            Value valRequest;
            if (!read_string(strRequest, valRequest) || valRequest.type() != obj_type)
                throw JSONRPCError(-32700, "Parse error");
            const Object& request = valRequest.get_obj();

            // Parse id now so errors from here on will have the id
            id = find_value(request, "id");

            // Parse method
            Value valMethod = find_value(request, "method");
            if (valMethod.type() == null_type)
                throw JSONRPCError(-32600, "Missing method");
            if (valMethod.type() != str_type)
                throw JSONRPCError(-32600, "Method must be a string");
            string strMethod = valMethod.get_str();
            if (strMethod != "getwork")
                printf("ThreadRPCServer method=%s\n", strMethod.c_str());

            // Parse params
            Value valParams = find_value(request, "params");
            Array params;
            if (valParams.type() == array_type)
                params = valParams.get_array();
            else if (valParams.type() == null_type)
                params = Array();
            else
                throw JSONRPCError(-32600, "Params must be an array");

            // Find method
            map<string, rpcfn_type>::iterator mi = mapCallTable.find(strMethod);
            if (mi == mapCallTable.end())
                throw JSONRPCError(-32601, "Method not found");

            // Observe safe mode
            string strWarning = GetWarnings("rpc");
            if (strWarning != "" && !GetBoolArg("-disablesafemode") && !setAllowInSafeMode.count(strMethod))
                throw JSONRPCError(-2, string("Safe mode: ") + strWarning);

            try
            {
                // Execute
                Value result;
                if ((*(*mi).second) == &help ||
                    (*(*mi).second) == &queryminingstatus ||
                    (*(*mi).second) == &getblockcount ||
                    (*(*mi).second) == &getblocknumber ||
                    (*(*mi).second) == &getconnectioncount ||
                    (*(*mi).second) == &getcoininfo) {
                    //Lock is unnecessary
                    result = (*(*mi).second)(params, false);
                    string strReply = JSONRPCReply(result, Value::null, id);
                    stream_out << HTTPReply(200, strReply) << std::flush;
                }
                else {

                    int nTry = 10;
                    CCriticalBlockT<pcstName> criticalblock(cs_main, __FILE__, __LINE__);
                    while (nTry-- > 0) {
                        if (!criticalblock.TryEnter(__FILE__, __LINE__)) {
                            boost::this_thread::sleep_for(boost::chrono::milliseconds(200));
                            if (nTry == 0) {
                                //Paracoin is busying , maybe it is backtracking or chain switching
                                throw JSONRPCError(-3, "busying");
                            }
                        }
                        else {

                            CRITICAL_BLOCK(pwalletMain->cs_wallet)
                                result = (*(*mi).second)(params, false);

                            // Send reply
                            string strReply = JSONRPCReply(result, Value::null, id);
                            stream_out << HTTPReply(200, strReply) << std::flush;
                            break;
                        }
                    }
                }
            }
            catch (std::exception & e)
            {
                ErrorReply(stream_out, JSONRPCError(-1, e.what()), id);
            }
        }
        catch (Object & objError)
        {
            ErrorReply(stream_out, objError, id);
        }
        catch (std::exception & e)
        {
            ErrorReply(stream_out, JSONRPCError(-32700, e.what()), id);
        }
    }
    asio::async_write(*socket.get(), *stream.get(),
        boost::bind(HandleWrite, socket, stream, boost::asio::placeholders::error));

}

void HandleReadHttpHeader(boost::shared_ptr<asio::ip::tcp::socket> socket,
    std::shared_ptr<boost::asio::streambuf> stream, const boost::system::error_code& error)
{
    if (!error)
    {
        /* boost::asio::streambuf::const_buffers_type bufs = buffer->data();
         std::string msgstr(boost::asio::buffers_begin(bufs),
             boost::asio::buffers_begin(bufs) +
             input_buffer_.size());

         std::vector<std::string> msgVector;
         boost::split(msgVector, msgstr, boost::is_any_of(":"));*/
        bool fUseSSL = GetBoolArg("-rpcssl");

        std::istream stream_in(stream.get());
        std::ostream stream_out(stream.get());

        //socket->read_some(stream);
        //boost::asio::read(*socket.get(), stream);
        // Restrict callers by IP
        ip::tcp::endpoint peer = socket->remote_endpoint();
        if (!ClientAllowed(peer.address().to_string())) {
            // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
            if (!fUseSSL)
                stream_out << HTTPReply(403, "") << std::flush;
            return;
        }

        map<string, string> mapHeaders;
        string strRequest;

        // Read status
        int nStatus = ReadHTTPStatus(stream_in);

        // Read header
        int content_length = ReadHTTPHeader(stream_in, mapHeaders);
        if (content_length < 0 || content_length > MAX_SIZE)
            throw JSONRPCError(-32600, "content-length too big or too small");

        int nLeft = stream->in_avail();

        if (nLeft < content_length) {
            asio::async_read(*socket.get(), *stream.get(),
                boost::asio::transfer_at_least(content_length - nLeft),
                boost::bind(HandleReadHttpBody, socket, stream, content_length, boost::asio::placeholders::error));
            return;
        }
        HandleReadHttpBody(socket,stream, content_length, error);
        //boost::thread api_caller(ReadHTTP, boost::ref(stream_in), boost::ref(mapHeaders), boost::ref(strRequest));
        //if (!api_caller.timed_join(boost::posix_time::seconds(GetArg("-rpctimeout", 30)))) {   // Timed out:
        //    //acceptor.cancel();
        //    printf("ThreadRPCServer ReadHTTP timeout\n");
        //    return;
        //}

        

        // Check authorization
        //if (mapHeaders.count("authorization") == 0)
        //{
        //    stream << HTTPReply(401, "") << std::flush;
        //    break;
        //}

        //if (!HTTPAuthorized(mapHeaders))
        //{
        //    // Deter brute-forcing short passwords
        //    if (mapArgs["-rpcpassword"].size() < 15)
        //        Sleep(50);

        //    stream << HTTPReply(401, "") << std::flush;
        //    printf("ThreadRPCServer incorrect password attempt\n");
        //    break;
        //}
    }
}

void HandleAccept(const system::error_code& error,
    boost::shared_ptr< asio::ip::tcp::socket > socket,
    asio::ip::tcp::acceptor& acceptor)
{
    

    if (error) {
        printf("Error accepting connection: %s", error.message().c_str());
        return;
    }

    bool fUseSSL = GetBoolArg("-rpcssl");

    do
    {
        // Accept connection
#ifdef USE_SSL
        ssl::context context(io_service, ssl::context::sslv23);
        if (fUseSSL)
        {
            context.set_options(ssl::context::no_sslv2);
            filesystem::path certfile = GetArg("-rpcsslcertificatechainfile", "server.cert");
            if (!certfile.is_complete()) certfile = filesystem::path(GetDataDir()) / certfile;
            if (filesystem::exists(certfile)) context.use_certificate_chain_file(certfile.string().c_str());
            else printf("ThreadRPCServer ERROR: missing server certificate file %s\n", certfile.string().c_str());
            filesystem::path pkfile = GetArg("-rpcsslprivatekeyfile", "server.pem");
            if (!pkfile.is_complete()) pkfile = filesystem::path(GetDataDir()) / pkfile;
            if (filesystem::exists(pkfile)) context.use_private_key_file(pkfile.string().c_str(), ssl::context::pem);
            else printf("ThreadRPCServer ERROR: missing server private key file %s\n", pkfile.string().c_str());

            string ciphers = GetArg("-rpcsslciphers",
                "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
            SSL_CTX_set_cipher_list(context.impl(), ciphers.c_str());
        }
#else
        if (fUseSSL)
            throw runtime_error("-rpcssl=1, but ledger compiled without full openssl libraries.");
#endif

#ifdef USE_SSL
        SSLStream sslStream(io_service, context);
        SSLIOStreamDevice d(sslStream, fUseSSL);
        iostreams::stream<SSLIOStreamDevice> stream(d);
#else
        //ip::tcp::iostream stream;
        std::shared_ptr<boost::asio::streambuf> stream(new boost::asio::streambuf());

#endif

        ip::tcp::endpoint peer = socket->remote_endpoint();
//        vnThreadsRunning[4]--;
//#ifdef USE_SSL
//        acceptor.accept(sslStream.lowest_layer(), peer);
//#else
//        acceptor.accept(*stream.rdbuf(), peer);
//#endif
//
//        vnThreadsRunning[4]++;
        if (fShutdown)
            return;

        asio::async_read(*socket.get(), *stream.get(),
            boost::asio::transfer_at_least(1),
            boost::bind(HandleReadHttpHeader, socket, stream, boost::asio::placeholders::error));


    } while (false);

    

    StartAccept(acceptor);

}

void StartRPCServer()
{
    

    int n = 1;//std::thread::hardware_concurrency();
    for (int i = 0; i < n; i++) {
        std::shared_ptr<boost::asio::io_service> io(new boost::asio::io_service());
        rpcServerList.push_back(io);
        CreateThread(ThreadRPCServer, io.get());
    }
}

void StopRPCServer()
{
    for (auto& io : rpcServerList) {
        io->stop();
    }
}


Object CallRPC(const string& strMethod, const Array& params)
{
    if (mapArgs["-rpcuser"] == "" && mapArgs["-rpcpassword"] == "")
        throw runtime_error(strprintf(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
                "If the file does not exist, create it with owner-readable-only file permissions."),
            GetConfigFile().c_str()));

    // Connect to localhost
    bool fUseSSL = GetBoolArg("-rpcssl");
#ifdef USE_SSL
    asio::io_service io_service;
    ssl::context context(io_service, ssl::context::sslv23);
    context.set_options(ssl::context::no_sslv2);
    SSLStream sslStream(io_service, context);
    SSLIOStreamDevice d(sslStream, fUseSSL);
    iostreams::stream<SSLIOStreamDevice> stream(d);
    if (!d.connect(GetArg("-rpcconnect", "127.0.0.1"), GetArg("-rpcparaport", "8118")))
        throw runtime_error("couldn't connect to server");
#else
    if (fUseSSL)
        throw runtime_error("-rpcssl=1, but ledger compiled without full openssl libraries.");

    ip::tcp::iostream stream(GetArg("-rpcconnect", "127.0.0.1"), GetArg("-rpcparaport", "8118"));
    if (stream.fail())
        throw runtime_error("couldn't connect to server");
#endif


    // HTTP basic authentication
    string strUserPass64 = EncodeBase64_(mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"]);
    map<string, string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

    // Send request
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    string strPost = HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    map<string, string> mapHeaders;
    string strReply;
    int nStatus = ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == 401)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (nStatus >= 400 && nStatus != 400 && nStatus != 404 && nStatus != 500)
        throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
    else if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    Value valReply;
    if (!read_string(strReply, valReply))
        throw runtime_error("couldn't parse reply from server");
    const Object& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}




template<typename T>
void ConvertTo(Value& value)
{
    if (value.type() == str_type)
    {
        // reinterpret string as unquoted json value
        Value value2;
        if (!read_string(value.get_str(), value2))
            throw runtime_error("type mismatch");
        value = value2.get_value<T>();
    }
    else
    {
        value = value.get_value<T>();
    }
}

int CommandLineRPC(int argc, char *argv[])
{
    string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2)
            throw runtime_error("too few parameters");
        string strMethod = argv[1];

        // Parameters default to strings
        Array params;
        for (int i = 2; i < argc; i++)
            params.push_back(argv[i]);

        int n = params.size();

        //
        // Special case non-string parameter types
        //
        if (strMethod == "setgenerate"            && n > 0) ConvertTo<bool>(params[0]);
        if (strMethod == "setgenerate"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]);
        if (strMethod == "settxfee"               && n > 0) ConvertTo<double>(params[0]);
        if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "getreceivedbyaccount"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
        if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
        if (strMethod == "listreceivedbyaccount"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
        if (strMethod == "listreceivedbyaccount"  && n > 1) ConvertTo<bool>(params[1]);
        if (strMethod == "getbalance"             && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "move"                   && n > 2) ConvertTo<double>(params[2]);
        if (strMethod == "move"                   && n > 3) ConvertTo<boost::int64_t>(params[3]);
        if (strMethod == "sendfrom"               && n > 2) ConvertTo<double>(params[2]);
        if (strMethod == "sendfrom"               && n > 3) ConvertTo<boost::int64_t>(params[3]);
        if (strMethod == "listtransactions"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "listtransactions"       && n > 2) ConvertTo<boost::int64_t>(params[2]);
        if (strMethod == "listaccounts"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
        if (strMethod == "walletpassphrase"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
        if (strMethod == "sendmany"               && n > 1)
        {
            string s = params[1].get_str();
            Value v;
            if (!read_string(s, v) || v.type() != obj_type)
                throw runtime_error("type mismatch");
            params[1] = v.get_obj();
        }
        if (strMethod == "sendmany"                && n > 2) ConvertTo<boost::int64_t>(params[2]);

        // Execute
        Object reply = CallRPC(strMethod, params);

        // Parse reply
        const Value& result = find_value(reply, "result");
        const Value& error = find_value(reply, "error");

        if (error.type() != null_type)
        {
            // Error
            strPrint = "error: " + write_string(error, false);
            int code = find_value(error.get_obj(), "code").get_int();
            nRet = abs(code);
        }
        else
        {
            // Result
            if (result.type() == null_type)
                strPrint = "";
            else if (result.type() == str_type)
                strPrint = result.get_str();
            else
                strPrint = write_string(result, true);
        }
    }
    catch (std::exception& e)
    {
        strPrint = string("error: ") + e.what();
        nRet = 87;
    }
    catch (...)
    {
        PrintException(NULL, "CommandLineRPC()");
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}



Value issuecoin(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2)
        throw runtime_error(
            "issuecoin {Name} [Genesis block message] [Model] [Logo]\n");

    vector<string> key = { "name", "description", "model", "logo" };
    map<string, string> mapGenenisBlockParams;
    for (int i=0; i<params.size(); i++) {
        mapGenenisBlockParams[key[i]] = params[i].get_str();
    }

    mapGenenisBlockParams["time"] = std::to_string(GetTime());

    std::unique_ptr<CryptoCurrency> spNewCurrency(new CryptoCurrency(false));
    spNewCurrency->SetParas(mapGenenisBlockParams);

    string requestid = spNewCurrency->GetUUID();

    std::thread t(&CryptoCurrency::RsyncMiningGenesiBlock, std::move(spNewCurrency));
    t.detach();

    Object result;
    result.push_back(Pair("gid", requestid));
    return result;
}

Value gid2rid(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error("gid2rid {GID}\n");

    string requestid = CryptoCurrency::GetRequestID(params[0].get_str());

    Object result;
    result.push_back(Pair("requestid", requestid));
    return result;
}

/*
Value issuecoin(const Array& params, bool fHelp)
{
    //name,time,type,nBits,consensus,ledger,maturity,coinBase,reward,fee,version,description
    if (fHelp || params.size() < 2)
        throw runtime_error(
            "issuecoin {name} [description] [reward] [bits] [version] [time]\n");

    vector<string> key = { "name", "description", "reward", "bits", "version", "time" };
    map<string, string> mapGenenisBlockParams;
    for (int i=0; i<params.size(); i++) {
        mapGenenisBlockParams[key[i]] = params[i].get_str();
    }

    if (mapGenenisBlockParams["time"].empty()) {
        mapGenenisBlockParams["time"] = std::to_string(GetTime());
    }

    CryptoCurrency newcurrency(false);
    newcurrency.SetParas(mapGenenisBlockParams);
    if (newcurrency.ReadCoinFile()) {
        throw JSONRPCError(-1, string("The CryptoCoin already existed"));
    }

    CBlock genesis = newcurrency.MineGenesisBlock();
    if (!newcurrency.WriteCoinFile()) {
        throw JSONRPCError(-2, string("WriteCoinFile failed"));
    }

    string requestid, errmsg;
    if (!CommitGenesisToConsensus(&genesis, requestid, errmsg)) {
        throw JSONRPCError(-3, string("CommitGenesisToConsensus failed: ") + errmsg);
    }

    Object result;
    result.push_back(Pair("requestid", requestid));
    return result;
}
*/

Value commitcoin(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error("commitcoin {name}\n");

    map<string, string> mapGenenisBlockParams;
    mapGenenisBlockParams["name"] = params[0].get_str();

    CryptoCurrency newcurrency(false);
    newcurrency.SetParas(mapGenenisBlockParams);

    string coinhash = "";
    string errmsg;
    if (!newcurrency.ReadCoinFile(params[0].get_str(), coinhash, errmsg)) {
        throw JSONRPCError(-1, string("The CryptoCoin maybe not existed: ") + errmsg);
    }

    CBlock genesis = newcurrency.GetGenesisBlock();
    if (genesis.GetHash() != newcurrency.GetHashGenesisBlock()) {
        throw JSONRPCError(-2, string("CryptoCoin genesis block data error"));
    }

    string requestid;
    

    UNCRITICAL_BLOCK(pwalletMain->cs_wallet)
    {
        UNCRITICAL_BLOCK_T_MAIN(cs_main)
        {
            if (!CommitGenesisToConsensus(&genesis, requestid, errmsg)) {
                throw JSONRPCError(-3, string("CommitGenesisToConsensus failed: ") + errmsg);
            }
        }
    }

    Object result;
    result.push_back(Pair("requestid", requestid));
    return result;
}

void ReadBlockFromChainSpace(const T_LOCALBLOCKADDRESS& addr, CBlock& block)
{
    CHyperChainSpace* chainspace = Singleton<CHyperChainSpace, string>::getInstance();

    string payload;
    if (!chainspace->GetLocalBlockPayload(addr, payload)) {
        throw JSONRPCError(-1, string("The local block not existed"));
    }

    if (!ResolveBlock(block, payload.c_str(), payload.size())) {
        throw JSONRPCError(-2, string("Incorrect local block data"));
    }
}

Value getcoininfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3)
        throw runtime_error("getcoininfo {hyperblockId} {chainNumber} {localId} \n");

    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stoi(params[0].get_str()),
        std::stoi(params[1].get_str()),
        std::stoi(params[2].get_str()));

    CBlock genesisBlock;
    ReadBlockFromChainSpace(addr, genesisBlock);

    CryptoCurrency currency(false);

    if (!currency.ParseCoin(genesisBlock)) {
        throw JSONRPCError(-3, string("Failed to parse local block data,maybe not genesis block"));
    }

    Object result;
    result.push_back(Pair("name", currency.GetName()));
    result.push_back(Pair("message", currency.GetDesc()));
    result.push_back(Pair("model", currency.GetModel()));
    result.push_back(Pair("logo", currency.GetLogo()));
    return result;
}

Value querygenesisblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error("querygenesisblock {GID}\n");
    uint32_t hid;
    uint16 chainnum;
    uint16 localid;

    string uuid = params[0].get_str();
    string requestid = CryptoCurrency::GetRequestID(uuid);

    

    T_LOCALBLOCKADDRESS addr;
    if (!requestid.empty())
    {
        bool isfound = Singleton<DBmgr>::instance()->getOnChainStateFromRequestID(requestid, addr);
        if (!isfound) {
            throw JSONRPCError(-1, string("GID not exist"));
        }
    }

    Object result;
    result.push_back(Pair("hyperblockId", addr.hid));
    result.push_back(Pair("chainNum", addr.chainnum));
    result.push_back(Pair("localblockId", addr.id));
    return result;
}

Value importcoin(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3)
        throw runtime_error("importcoin {hyperblockId} {chainNumber} {localId} \n");

    T_LOCALBLOCKADDRESS addr;
    addr.set(std::stoi(params[0].get_str()),
        std::stoi(params[1].get_str()),
        std::stoi(params[2].get_str()));

    CBlock genesisBlock;
    ReadBlockFromChainSpace(addr, genesisBlock);
    if (!genesisBlock.CheckProgPow()) {
        throw JSONRPCError(-3, string("Failed to check genesis block"));
    }

    CryptoCurrency newcurrency(false);
    if (!newcurrency.ParseCoin(genesisBlock)) {
        throw JSONRPCError(-4, string("Failed to parse local block data,maybe not genesis block"));
    }

    newcurrency.SetGenesisAddr(addr.hid, addr.chainnum, addr.id);

    Object result;

    result.push_back(Pair("name", newcurrency.GetName()));
    result.push_back(Pair("message", newcurrency.GetDesc()));
    result.push_back(Pair("model", newcurrency.GetModel()));
    result.push_back(Pair("logo", newcurrency.GetLogo()));

    return result;
}

Value startmining(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error("startmining [{name} | {hyperblockId} {chainNumber} {localId}] \n");

    string coinname = "";
    string coinhash = "";
    if (params.size() == 1) {
        coinname = params[0].get_str();
    }
    else if(params.size() == 3) {
        if (!CryptoCurrency::SearchCoinByTriple(std::stoi(params[0].get_str()),
                std::stoi(params[1].get_str()),
                std::stoi(params[2].get_str()), coinname, coinhash)) {

            throw JSONRPCError(-1, string("cannot find the coin"));
        }
    }

    Object result;
    if ((g_cryptoCurrency.GetName() == coinname || g_cryptoCurrency.GetHashPrefixOfGenesis() == coinhash) ||
            coinname.empty()) {
        if (!g_cryptoCurrency.AllowMining()) {
            g_cryptoCurrency.StartMining();
            result.push_back(Pair("result", "ok, start mining " + g_cryptoCurrency.GetName()));
            return result;
        }
        throw JSONRPCError(-2, g_cryptoCurrency.GetName() + string(" is mining"));
    }

    CryptoCurrency currency(false);
    currency.SetName(coinname);
    string errmsg;
    if (!currency.ReadCoinFile(coinname, coinhash, errmsg)) {
        throw JSONRPCError(-3, string("Failed to load coin: ") + errmsg);
    }

    if (!currency.AllowMining()) {
        currency.StartMining();
    }

    

    g_cryptoCurrency.StopMining();

    std::shared_ptr<OPAPP> oppara = std::make_shared<OPAPP>(coinhash, mapArgs);

    boost::thread op_thread(OperatorApplication, oppara);
    op_thread.detach();

    result.push_back(Pair("result", string("ok, will switch to coin: ") + coinname));
    return result;
}

Value stopmining(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error("stopmining\n");

    if (!g_cryptoCurrency.AllowMining()) {
        throw JSONRPCError(-2, "Already stopped");
    }

    if (!g_cryptoCurrency.StopMining())
    {
        throw JSONRPCError(-3, "cannot stopped");
    }

    Object result;
    result.push_back(Pair("result", "ok, stopped"));
    return result;
}

extern MiningCondition g_miningCond;
Value queryminingstatus(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error("queryminingstatus\n");

    bool isAllowed;
    string strDescription = g_miningCond.GetMiningStatus(&isAllowed);

    Object result;
    result.push_back(Pair("status", isAllowed ? "mining" : "stopped"));

    result.push_back(Pair("statuscode", g_miningCond.MiningStatusCode()));

    if (g_miningCond.IsBackTracking()) {
        BackTrackingProgress progress = g_miningCond.GetBackTrackingProcess();
        result.push_back(Pair("latestheight", progress.nLatestBlockHeight));
        result.push_back(Pair("latesttripleaddr", progress.strLatestBlockTripleAddr));
        result.push_back(Pair("backtrackingheight", progress.nBackTrackingBlockHeight));
        result.push_back(Pair("backtrackinghash", progress.strBackTrackingBlockHash));
    }

    result.push_back(Pair("currentheight", (pindexBest ? pindexBest->nHeight : 0)));
    result.push_back(Pair("statusdesc", strDescription));

    return result;
}

#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
    // Turn off microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    try
    {
        if (argc >= 2 && string(argv[1]) == "-server")
        {
            printf("server ready\n");
            ThreadRPCServer(NULL);
        }
        else
        {
            return CommandLineRPC(argc, argv);
        }
    }
    catch (std::exception& e) {
        PrintException(&e, "main()");
    }
    catch (...) {
        PrintException(NULL, "main()");
    }
    return 0;
}
#endif
