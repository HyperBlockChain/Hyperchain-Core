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

#pragma once

#include <iostream>
#include <functional>
#include <vector>
#include <string>
#include <list>
#include <algorithm>
#include <iomanip>
using namespace std;

#include "newLog.h"



string GetHyperChainDataDir();
string CreateChildDir(const string& childdir);


class ConsoleCommandHandler
{

public:
    explicit ConsoleCommandHandler();
    ~ConsoleCommandHandler();

    void run();

private:

    struct cmdstruct {
    public:
        cmdstruct(const char *keystring, std::function<void(const list<string> &)> f) {
            key = keystring;
            func = f;
        }
        bool operator==(const cmdstruct &other) const {
            return (strcmp(key, other.key) == 0);
        }

        const char *key;
        std::function<void(const list<string> &)> func;
    };

    std::vector<cmdstruct> _commands;
    bool _isRunning;

private:

    void handleCommand(const string &command);

    void exit();
    void showUsages();
    void showNeighborNode();
    void showHyperChainSpace();
    void showUnconfirmedBlock();
    void showHyperChainSpaceMore(const list<string> &commlist);
    void showLocalData();
    void downloadHyperBlock(const list<string> &commlist);
    void searchLocalHyperBlock(const list<string> &commlist);
    void showInnerDataStruct();
    void resolveAppData(const list<string> &paralist);
    void debug(const list<string> &paralist);

    void setLoggerLevel(const list<string> &level);
    void setLoggerLevelHelp(std::shared_ptr<spdlog::logger> & logger, const list<string> &level);
    void setConsensusLoggerLevel(const list<string> &level);
    void startApplication(const list<string> &appli);
    void stopApplication(const list<string> &appli);
    void statusApplication(const list<string> &appli);

    void enableTest(const list<string> &onoff);

    inline void showPrompt() {
        cout << "hc $ ";
        cout.flush();
    }

};


