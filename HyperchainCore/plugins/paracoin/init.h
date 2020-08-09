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
#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

extern CWallet* pwalletMain;

class PluginContext;

extern "C" BOOST_SYMBOL_EXPORT bool StartApplication(PluginContext* context);
extern "C" BOOST_SYMBOL_EXPORT void StopApplication();
extern "C" BOOST_SYMBOL_EXPORT bool IsStopped();
extern "C" BOOST_SYMBOL_EXPORT void AppInfo(string&);
extern "C" BOOST_SYMBOL_EXPORT void AppRunningArg(int&, string&);
extern "C" BOOST_SYMBOL_EXPORT bool ResolveHeight(int, string&);
extern "C" BOOST_SYMBOL_EXPORT bool ResolvePayload(const string&, string&);

void Shutdown(void* parg);
bool AppInit2(int argc, char* argv[]);

#endif
