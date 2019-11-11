/*Copyright 2016-2019 hyperchain.net (Hyperchain)

Distributed under the MIT software license, see the accompanying
file COPYING or https://opensource.org/licenses/MIT.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/


#include "newLog.h"
#include "RestApi.h"

#include "../node/Singleton.h"
#include "../node/NodeManager.h"
#include "../HyperChain/HyperChainSpace.h"
#include "../headers/commonstruct.h"
#include "../headers/inter_public.h"
//#include "HChainP2PManager.h"
//#include "../interface/QtInterface.h"
#include "../headers/UUFile.h"
#include "../HttpUnit/HttpUnit.h"
#include "../wnd/common.h"
#include "../consensus/buddyinfo.h"
#include "../consensus/consensus_engine.h"
#include <cpprest/http_listener.h>
#include <cpprest/filestream.h>


#ifdef WIN32
#include <io.h>
#include <fcntl.h>
#include <codecvt>
#endif

#include <chrono>
#include <string>
#include <locale>
#include <sstream>
using namespace std;
using std::chrono::system_clock;

#define MAX_BUF_LEN 512
#define LOCAL_BLOCK_BASE_LEN	sizeof(T_LOCALBLOCK)

std::map<uint64, system_clock::time_point> g_mapDownLoad;
std::mutex	_guard;

http_listener_config server_config;

utility::string_t address =
#ifdef WIN32
U("http://*:8080");
#else
U("http://0.0.0.0:8080");
#endif

web::uri_builder uri1(address);
auto addr = uri1.to_uri().to_string();
CommandHandler restHandler(addr, server_config);


string tstringToUtf8(const utility::string_t& str)
{
#ifdef _UTF16_STRINGS
    //
    wstring_convert<codecvt_utf8<wchar_t> > strCnv;
    return strCnv.to_bytes(str);
#else
    //
    return str;
#endif
}

utility::string_t stringToTstring(const string& str)
{
#ifdef _UTF16_STRINGS
    //
    std::wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>> strCnv;
    return strCnv.from_bytes(str);
#else
    //
    return str;
#endif
}

bool CheckMyVersion(string& newversion)
{
    newversion = "";
    web::json::value json_return;
    try {
        web::json::value json_v;
        web::http::client::http_client client(U("https://www.hyperchain.net/"));
        client.request(web::http::methods::GET, U("/sw/ParalismLatestSWVersion.json"))
            .then([](const web::http::http_response& response) {
            return response.extract_json();
        })
            .then([&json_return](const pplx::task<web::json::value>& task) {
            try {
                json_return = task.get();
            }
            catch (const web::http::http_exception & e) {
                std::cout << "error " << e.what() << std::endl;
            }
        }).wait();
    }
    catch (web::json::json_exception & je) {
        std::cout << je.what();
        return false;
    }
    catch (std::exception & e) {
        std::cout << e.what();
        return false;
    }

    if (!json_return.has_field(U("version"))) {
        return false;
    }

    newversion = t2s(json_return[U("version")].as_string());
    return true;
}

CommandHandler::CommandHandler(utility::string_t url, http_listener_config server_config) : m_listener(url, server_config)
{
    m_listener.support(methods::GET, std::bind(&CommandHandler::handle_get, this, std::placeholders::_1));
    m_listener.support(methods::POST, std::bind(&CommandHandler::handle_post, this, std::placeholders::_1));
    m_listener.support(methods::PUT, std::bind(&CommandHandler::handle_put, this, std::placeholders::_1));
    m_listener.support(methods::DEL, std::bind(&CommandHandler::handle_del, this, std::placeholders::_1));
}



std::vector<utility::string_t> requestPath(const http_request& message) {
    auto relativePath = uri::decode(message.relative_uri().path());
    return uri::split_path(relativePath);
}

UUFile			m_uufiletest;

utility::string_t resource_type(const utility::string_t& strSuffix)
{
    std::map<utility::string_t, utility::string_t> oVals;
    oVals[U(".html")] = U("text/html");
    oVals[U(".js")] = U("application/javascript");
    oVals[U(".css")] = U("text/css");
    oVals[U(".png")] = U("application/octet-stream");
    oVals[U(".jpg")] = U("application/octet-stream");

    auto pIt = oVals.find(strSuffix);
    if (pIt != oVals.end())
        return pIt->second;
    return U("application/octet-stream");
}

#define BADPARAMETER(msg) message.reply(status_codes::OK, json::value(_XPLATSTR("Bad Parameter:"#msg)));

void CommandHandler::handle_get(http_request message)
{
    /*utility::string_t hash;

    auto uri = message.relative_uri().to_string();
    if (string::npos != uri.find(_XPLATSTR("html"))) {
        string localPath = m_uufiletest.GetAppPath();
        string confPath = localPath + "index.html";

        char *strBody = NULL;
        unsigned int uiRecvLen = 0;
        int ret = HttpDownloadF("http://192.168.0.55/hyperchain/index.html", &strBody, uiRecvLen);
        if (200 == ret) {
            message.reply(status_codes::OK, strBody, ::utility::conversions::to_utf8string("text/html; charset=utf-8"));
        }
        else {
            concurrency::streams::fstream::open_istream(stringToTstring(confPath.c_str()), std::ios::in).then([=](concurrency::streams::istream is)
            {
                message.reply(status_codes::OK, is, U("text/html"));
            });
        }

        if (strBody != NULL) {
            delete strBody;
            strBody = NULL;
        }
        return;
    }*/

    g_basic_logger->error("RestApi Method: {}, URI: {}, Query: {})", "GET", tstringToUtf8(uri::decode(message.relative_uri().path())), tstringToUtf8(uri::decode(message.relative_uri().query())));

    auto path = requestPath(message);
    if (!path.empty() && path.size() == 1) {

        std::map<utility::string_t, utility::string_t> query = uri::split_query(uri::decode(message.request_uri().query()));

        json::value vRet;

        if (path[0] == U("SubmitRegistration")) {
            auto data = query.find(U("data"));
            if (data == query.end()) {
                BADPARAMETER(data);
                return;
            }

            if (data != query.end() && !data->second.empty()) {
                string strdata = tstringToUtf8(data->second);

                RestApi api;
                vRet = api.MakeRegistration(strdata);
            }
        }

        else if (path[0] == U("GetHyperblocks")) {
            auto cntEntryId = query.find(U("start_id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(start_id);
                return;
            }
            auto cntEntryNum = query.find(U("num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(num);
                return;
            }

            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());
            uint64_t nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getHyperblocks(nHyperBlockId, nNum);
        }

        else if (path[0] == U("SyncHyperblock")) {
            auto cntEntryHId = query.find(U("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            uint64_t nHyperBlockId = std::stol(tstringToUtf8(sHId));

            if (true == Singleton<DBmgr>::instance()->isBlockExisted(nHyperBlockId)) {
                vRet = json::value::string(_XPLATSTR("success"));
                goto REPLY;
            }

            {
                std::lock_guard<std::mutex> lck(_guard);
                map<uint64, system_clock::time_point>::iterator it = g_mapDownLoad.find(nHyperBlockId);
                if (it != g_mapDownLoad.end()) {
                    using seconds = std::chrono::duration<double, ratio<1>>;
                    system_clock::time_point curr = system_clock::now();
                    seconds timespan = std::chrono::duration_cast<seconds>(curr - it->second);
                    if (timespan.count() < 30) {
                        //
                        vRet = json::value::string(_XPLATSTR("downloading"));
                        goto REPLY;
                    }
                }
            }

            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();
            int ret = HSpce->GetRemoteHyperBlockByID(nHyperBlockId);
            if (ret < 0)
                vRet = json::value::string(_XPLATSTR("nonexistent"));
            else {
                std::lock_guard<std::mutex> lck(_guard);
                g_mapDownLoad[nHyperBlockId] = system_clock::now();
                vRet = json::value::string(_XPLATSTR("downloading"));
            }
        }

        else if (path[0] == U("GetLocalBlock")) {
            auto cntEntryHId = query.find(U("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryId = query.find(U("id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(id);
                return;
            }
            auto cntEntryNum = query.find(U("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint16 nLocalBlockId = atoi(tstringToUtf8(sId).c_str());
            uint16 nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalblock(nHyperBlockId, nLocalBlockId, nNum);
        }

        else if (path[0] == U("GetLocalChain")) {
            auto cntEntryHId = query.find(U("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryNum = query.find(U("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint64_t nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalchain(nHyperBlockId, nNum);
        }

        else if (path[0] == U("GetOnchainState"))
        {
            auto id = query.find(U("requestid"));
            if (id == query.end()) {
                BADPARAMETER(requestid);
                return;
            }

            if (id != query.end() && !id->second.empty()) {
                string strid = tstringToUtf8(id->second);

                RestApi api;
                vRet = api.getOnchainState(strid);
            }
        }

        else if (path[0] == U("GetHyperBlockInfo"))
        {
            auto cntEntryId = query.find(U("key"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(key);
                return;
            }
            utility::string_t sId = cntEntryId->second;
            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());

            RestApi api;
            vRet = api.getHyperblockInfo(nHyperBlockId);
        }
        else if (path[0] == U("GetHyperBlockHead"))
        {
            auto cntEntryId = query.find(U("key"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(key);
                return;
            }
            utility::string_t sId = cntEntryId->second;
            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());

            RestApi api;
            vRet = api.getHyperblockHead(nHyperBlockId);
        }
        else if (path[0] == U("GetHyperBlockBody"))
        {
            auto cntEntryId = query.find(U("key"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(key);
                return;
            }
            utility::string_t sId = cntEntryId->second;
            uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());

            RestApi api;
            vRet = api.getHyperblockBody(nHyperBlockId);
        }

        else if (path[0] == U("GetLocalBlockHead"))
        {
            auto cntEntryHId = query.find(U("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryId = query.find(U("id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(id);
                return;
            }
            auto cntEntryNum = query.find(U("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint16 nLocalBlockId = atoi(tstringToUtf8(sId).c_str());
            uint16 nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalblockHead(nHyperBlockId, nLocalBlockId, nNum);
        }
        else if (path[0] == U("GetLocalBlockBody"))
        {
            auto cntEntryHId = query.find(U("hid"));
            if (cntEntryHId == query.end()) {
                BADPARAMETER(hid);
                return;
            }
            auto cntEntryId = query.find(U("id"));
            if (cntEntryId == query.end()) {
                BADPARAMETER(id);
                return;
            }
            auto cntEntryNum = query.find(U("chain_num"));
            if (cntEntryNum == query.end()) {
                BADPARAMETER(chain_num);
                return;
            }

            utility::string_t sHId = cntEntryHId->second;
            utility::string_t sId = cntEntryId->second;
            utility::string_t sNum = cntEntryNum->second;

            uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
            uint16 nLocalBlockId = atoi(tstringToUtf8(sId).c_str());
            uint16 nNum = atoi(tstringToUtf8(sNum).c_str());

            RestApi api;
            vRet = api.getLocalblockBody(nHyperBlockId, nLocalBlockId, nNum);
        }

        /*else if (path[0] == U("GetRegWaitingList"))
        {
            ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
            if (consensuseng == nullptr)
                return;

            LIST_T_LOCALCONSENSUS listInfo = consensuseng->GetPoeRecordList();
            ITR_LIST_T_LOCALCONSENSUS itr = listInfo.begin();
            int i = 0;
            for (itr; itr != listInfo.end(); itr++)
            {
                char strBuf[MAX_BUF_LEN] = {0};
                CCommonStruct::Hash512ToStr(strBuf, &(*itr).tLocalBlock.tPayLoad.tPayLoad.tFileHash);


                string_t oss;
                char num[8];
                memset(num, 0, sizeof(num));
                sprintf(num, "%d", i);
                oss = _XPLATSTR("readyOnChainHash[");
                oss += stringToTstring(num);
                oss += _XPLATSTR("]");
                vRet[oss] = json::value::string(stringToTstring(strBuf));

                i += 1;
            }

        }*/

        else if (path[0] == U("GetLatestHyperBlockNo")) {
            uint64 localHID = Singleton<DBmgr>::instance()->getLatestHyperBlockNo();

            CHyperChainSpace* hyperchainspace = Singleton<CHyperChainSpace, string>::getInstance();
            uint64 globalHID = hyperchainspace->GetGlobalLatestHyperBlockNo();

            if (localHID > globalHID)
                vRet[_XPLATSTR("laststHyperBlockNo")] = json::value::number(localHID);
            else
                vRet[_XPLATSTR("laststHyperBlockNo")] = json::value::number(globalHID);
        }
        else if (path[0] == U("GetNodeRuntimeEnv"))
        {
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();
            if (nodemgr == nullptr)
                return;

            HCNodeSH me = nodemgr->myself();
            string strnodeenv = me->serialize();

            vRet[_XPLATSTR("NodeEnv")] = json::value::string(s2t(strnodeenv));

        }
        else if (path[0] == U("GetStateOfCurrentConsensus"))
        {
            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
            if (consensuseng == nullptr)
                return;

            uint64_t blockNo;
            uint16 blockNum = 0;
            uint16 chainNum = 0;
            uint16 uiState = consensuseng->GetStateOfCurrentConsensus(blockNo, blockNum, chainNum);


            vRet[_XPLATSTR("curBuddyNo")] = json::value::number(blockNo);
            if (uiState == IDLE) {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("idle"));
            }
            else if (uiState == LOCAL_BUDDY) {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("localbuddy"));
            }
            else if (uiState == GLOBAL_BUDDY) {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("globalbuddy"));
            }
        }
        else if (path[0] == U("GetDataOfCurrentConsensus")) {

            ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
            if (consensuseng == nullptr)
                return;

            uint64_t blockNo;
            uint16 blockNum = 0;
            uint16 chainNum = 0;
            uint16 uiState = consensuseng->GetStateOfCurrentConsensus(blockNo, blockNum, chainNum);


            vRet[_XPLATSTR("curBuddyNo")] = json::value::number(blockNo);
            if (uiState == IDLE) {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("idle"));
            }
            else if (uiState == LOCAL_BUDDY)
            {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("localbuddy"));
                vRet[_XPLATSTR("blockNum")] = json::value::number(blockNum);
            }
            else if (uiState == GLOBAL_BUDDY)
            {
                vRet[_XPLATSTR("consensusState")] = json::value::string(_XPLATSTR("globalbuddy"));
                vRet[_XPLATSTR("chainNum")] = json::value::number(chainNum);
            }

        }
        else if (path[0] == U("GetDetailOfCurrentConsensus"))
        {
            uint64 localHID = Singleton<DBmgr>::instance()->getLatestHyperBlockNo();
            uint32 localchainBlocks = g_tP2pManagerStatus->listLocalBuddyChainInfo.size();
            uint32 requestBlocks = g_tP2pManagerStatus->listRecvLocalBuddyReq.size() + g_tP2pManagerStatus->listCurBuddyReq.size();
            uint32 respondBlocks = g_tP2pManagerStatus->listRecvLocalBuddyRsp.size() + g_tP2pManagerStatus->listCurBuddyRsp.size();

            vRet[_XPLATSTR("latestHyperBlockNo")] = json::value::number(localHID);
            vRet[_XPLATSTR("localchainBlocks")] = json::value::number(localchainBlocks);
            vRet[_XPLATSTR("requestBlocks")] = json::value::number(requestBlocks);
            vRet[_XPLATSTR("respondBlocks")] = json::value::number(respondBlocks);
        }
        else if (path[0] == U("GetRequestTaskTypeList"))
        {
            TASKTYPE type;
            CAutoMutexLock muxAuto(g_tP2pManagerStatus->MuxCycleQueueTask);

            json::value obj = json::value::array();
            int i = 0;
            while (g_tP2pManagerStatus->CycleQueueTask.pop(&type))
            {
                obj[i++] = json::value::number(static_cast<uint32>(type));
            }

            vRet[_XPLATSTR("TaskTypeList")] = obj;
        }
        else if (path[0] == U("CreatCustomerizeConsensusScript"))
        {
            auto cntEntryType = query.find(U("Type"));
            if (cntEntryType == query.end()) {
                BADPARAMETER(Type);
                return;
            }
            auto cntEntryScript = query.find(U("Script"));
            if (cntEntryScript == query.end()) {
                BADPARAMETER(Script);
                return;
            }

            if (cntEntryType != query.end() && !cntEntryType->second.empty() && cntEntryScript != query.end() && !cntEntryScript->second.empty())
            {

                utility::string_t sType = cntEntryType->second;
                utility::string_t sScript = cntEntryScript->second;

                string strType = tstringToUtf8(sType);
                if (0 != strType.compare("xml") || (sScript.length() > (1024 * 2))) {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(_XPLATSTR("type is wrong"));
                }
                else {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(_XPLATSTR("success"));
                }
            }
        }

        else if (path[0] == U("GetNeighborNodes"))
        {
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

            const HCNodeMap* nodemap = nodemgr->getNodeMap();
            json::value arr = json::value::array(nodemap->size());
            auto iter = nodemap->begin();
            for (int i = 0; iter != nodemap->end(); iter++, i++) {
                arr[i] = json::value::parse(s2t(iter->second->serialize()));
            }

            vRet[_XPLATSTR("NeighborNodes")] = arr;
            vRet[_XPLATSTR("NeighborNodesNum")] = json::value::number(nodemgr->getNodeMapSize());
        }
        else if (path[0] == U("GetNeighborInfo"))
        {
            NodeManager* nodemgr = Singleton<NodeManager>::getInstance();

            vRet[_XPLATSTR("NeighborNodesNum")] = json::value::number(nodemgr->getNodeMapSize());
            vRet[_XPLATSTR("KBucketNodesNum")] = json::value::number(nodemgr->GetKBuckets()->GetNodesNum());
        }
        else if (path[0] == U("GetHyperBlocksIDList"))
        {
            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            vector<string> LocalChainSpace;
            HSpce->GetLocalChainShow(LocalChainSpace);

            if (LocalChainSpace.size() <= 0)
            {
                vRet[_XPLATSTR("HyperBlocksNum")] = json::value::number(0);
                vRet[_XPLATSTR("HyperBlocksIDList")] = json::value::string(_XPLATSTR(""));
                return;
            }

            size_t nums = HSpce->GetLocalChainIDSize();
            string Ldata;
            for (auto& t : LocalChainSpace)
            {
                Ldata += t;
                Ldata += ";";
            }

            vRet[_XPLATSTR("HyperBlocksNum")] = json::value::number(nums);
            vRet[_XPLATSTR("HyperBlocksIDList")] = json::value::string(s2t(Ldata));
        }
        else if (path[0] == U("GetHyperChainSpace"))
        {
            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            map<string, string> HyperChainSpace;
            HSpce->GetHyperChainShow(HyperChainSpace);

            if (HyperChainSpace.size() <= 0)
            {
                vRet[_XPLATSTR("HyperChainSpace")] = json::value::string(_XPLATSTR(""));
                return;
            }

            json::value obj;
            for (auto& mdata : HyperChainSpace)
            {
                obj[s2t(mdata.first)] = json::value::string(s2t(mdata.second));
            }

            std::stringstream oss;
            obj.serialize(oss);

            vRet[_XPLATSTR("HyperChainSpace")] = json::value::string(s2t(oss.str()));
        }
        else if (path[0] == U("GetHyperBlockHealthInfo"))
        {
            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            map<uint64, uint32> HyperBlockHealthInfo;
            HSpce->GetHyperBlockHealthInfo(HyperBlockHealthInfo);

            if (HyperBlockHealthInfo.size() <= 0)
            {
                vRet[_XPLATSTR("HyperBlockHealthInfo")] = json::value::string(_XPLATSTR(""));
                return;
            }

            string Ldata;
            for (auto& mdata : HyperBlockHealthInfo)
            {
                Ldata += to_string(mdata.first);
                Ldata += ":";
                Ldata += to_string(mdata.second);
                Ldata += ";";
            }

            vRet[_XPLATSTR("HyperBlockHealthInfo")] = json::value::string(s2t(Ldata));
        }
        else if (path[0] == U("GetNodeIDList"))
        {
            auto cntEntryId = query.find(U("key"));
            if (cntEntryId == query.end())
            {
                BADPARAMETER(key);
                return;
            }

            utility::string_t sId = cntEntryId->second;
            uint64 nblocknum = std::stol(tstringToUtf8(sId));

            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();

            map<uint64, set<string>> HyperChainSpace;
            HSpce->GetHyperChainData(HyperChainSpace);

            if (HyperChainSpace.size() <= 0)
            {
                vRet[_XPLATSTR("HyperBlockID")] = json::value::number(nblocknum);
                vRet[_XPLATSTR("NodeIDList")] = json::value::string(_XPLATSTR(""));
                return;
            }

            string nodelist;
            for (auto& mdata : HyperChainSpace)
            {
                if (mdata.first != nblocknum)
                    continue;

                for (auto& sid : mdata.second)
                {
                    nodelist += sid;
                    nodelist += ";";
                }
                break;
            }

            vRet[_XPLATSTR("HyperBlockID")] = json::value::number(nblocknum);
            vRet[_XPLATSTR("NodeIDList")] = json::value::string(s2t(nodelist));
        }
        else if (path[0] == U("DownloadHyperBlock"))
        {
            auto cntEntryBlockId = query.find(U("HyperBlockID"));
            if (cntEntryBlockId == query.end())
            {
                BADPARAMETER(HyperBlockID);
                return;
            }

            auto cntEntryNodeId = query.find(U("NodeID"));
            if (cntEntryNodeId == query.end())
            {
                BADPARAMETER(NodeID);
                return;
            }

            utility::string_t sblockId = cntEntryBlockId->second;
            uint64 nblocknum = std::stol(tstringToUtf8(sblockId));
            string strnodeid = t2s(cntEntryNodeId->second);

            CHyperChainSpace* HSpce = Singleton<CHyperChainSpace, string>::getInstance();
            try {
                HSpce->PullHyperDataByHID(nblocknum, strnodeid);
            }
            catch (std::exception & e) {
                message.reply(status_codes::OK, json::value(stringToTstring(string("Bad Parameter:") + e.what())));
                return;
            }

            vRet[_XPLATSTR("returnValue")] = json::value::string(_XPLATSTR("request sent"));
        }

    REPLY:
        http_response response(status_codes::OK);
        response.set_body(vRet);
        response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
        message.reply(response);
        return;
    }
    message.reply(status_codes::OK, json::value(_XPLATSTR("unknow error")));
}


void CommandHandler::handle_post(http_request message)
{
    g_basic_logger->error("RestApi Method: {}, URI: {}, Query: {})", "POST", tstringToUtf8(uri::decode(message.relative_uri().path())), tstringToUtf8(uri::decode(message.relative_uri().query())));

    auto path = requestPath(message);
    if (!path.empty() && path.size() == 1) {
        if (path[0] == U("SubmitRegistration")) {
            Concurrency::streams::istream inStream = message.body();
            concurrency::streams::container_buffer<std::string> inStringBuffer;

            inStream.read_line(inStringBuffer).then([=](std::size_t bytesRead)
            {
                string struserdefined = inStringBuffer.collection();
                json::value vRet;

                if (!struserdefined.empty() && struserdefined.length() <= MAX_USER_DEFINED_DATA) {
                    RestApi api;
                    vRet = api.MakeRegistration(struserdefined);
                }
                else if (struserdefined.length() > MAX_USER_DEFINED_DATA) {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(stringToTstring("SubmitRegistration data length >= 16KB"));
                }
                else {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(stringToTstring("SubmitRegistration data length empty"));
                }

                http_response response(status_codes::OK);
                response.set_body(vRet);
                response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
                message.reply(response).then([](pplx::task<void> t)
                {
                    try {
                        t.get();
                    }
                    catch (...) {
                    }
                });
            }).then([=](pplx::task<void>t) {
                try {
                    t.get();
                }
                catch (...) {
                    message.reply(status_codes::InternalError, U("INTERNAL ERROR "));
                }
            });

            return;
        }
    }

    message.reply(status_codes::OK, json::value(_XPLATSTR("unknow error")));

    /*

        utility::string_t key = uri::decode(message.request_uri().query());
        json::value vRet;


        if (key == U("SubmitRegistration"))
        {

            Concurrency::streams::istream inStream = message.body();
            concurrency::streams::container_buffer<std::string> inStringBuffer;

            inStream.read_line(inStringBuffer).then([=](std::size_t bytesRead)
            {
                string struserdefined = inStringBuffer.collection();
                json::value vRet;

                if (!struserdefined.empty() && struserdefined.length() <= MAX_USER_DEFINED_DATA)
                {
                    string strfilename = "Default data";
                    string strfilehash = "Default data";
                    string strcustomInfo = "Default data";
                    string strrightowner = "Default data";

                    RestApi* api = new RestApi;
                    vRet = api->MakeRegistration(struserdefined);
                    delete api;
                    api = NULL;
                }
                else if (struserdefined.length() > MAX_USER_DEFINED_DATA)
                {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(stringToTstring("SubmitRegistration data length >= 16KB"));
                }
                else
                {
                    vRet[_XPLATSTR("returnValue")] = json::value::string(stringToTstring("SubmitRegistration data length empty"));
                }

                http_response response(status_codes::OK);
                response.set_body(vRet);
                response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
                message.reply(response).then([](pplx::task<void> t)
                {
                    try {
                        t.get();
                    }
                    catch (...) {
                    }
                });
            }).then([=](pplx::task<void>t)
            {
                try
                {
                    t.get();
                }
                catch (...)
                {
                    message.reply(status_codes::InternalError, U("INTERNAL ERROR "));
                }
            });

        }
        else
        {
            vRet[_XPLATSTR("returnValue")] = json::value::string(stringToTstring("unknow error"));
            http_response response(status_codes::OK);
            response.set_body(vRet);
            response.headers().add(U("Access-Control-Allow-Origin"), U("*"));
            message.reply(response);
        }*/
}


void CommandHandler::handle_put(http_request message)
{
    g_basic_logger->error("RestApi Method: {}, URI: {}, Query: {})", "PUT", tstringToUtf8(uri::decode(message.relative_uri().path())), tstringToUtf8(uri::decode(message.relative_uri().query())));
    message.reply(status_codes::OK, "PUT");
}

void CommandHandler::handle_del(http_request message)
{
    g_basic_logger->error("RestApi Method: {}, URI: {}, Query: {})", "DEL", tstringToUtf8(uri::decode(message.relative_uri().path())), tstringToUtf8(uri::decode(message.relative_uri().query())));
    message.reply(status_codes::OK, "DEL");
}

void RestApi::blockHeadToJsonValue(const T_LOCALBLOCK& localblock, json::value& val)
{
    val[_XPLATSTR("version")] = json::value::string(stringToTstring(localblock.GetVersion().tostring()));
    val[_XPLATSTR("id")] = json::value::number(localblock.GetID());

    val[_XPLATSTR("hid")] = json::value::number(localblock.GetHID());
    val[_XPLATSTR("chain_num")] = json::value::number(localblock.GetChainNum());

    val[_XPLATSTR("hash")] = json::value::string(stringToTstring(localblock.GetHashSelf().toHexString()));

    val[_XPLATSTR("hash_prev")] = json::value::string(stringToTstring(localblock.GetPreHash().toHexString()));
    val[_XPLATSTR("hhash")] = json::value::string(stringToTstring(localblock.GetPreHHash().toHexString()));
    val[_XPLATSTR("ctime")] = json::value::number(localblock.GetCTime());
    val[_XPLATSTR("nonce")] = json::value::number(localblock.GetNonce());

    json::value obj = json::value::array();
    uint16 i = 0;
    for (auto type : localblock.GetAppType()) {
        obj[i++] = json::value::number(type.app);
    }
    val[_XPLATSTR("app_type")] = obj;

    val[_XPLATSTR("root_block_body_hash")] = json::value::string(stringToTstring(localblock.GetRootHash().toHexString()));
    val[_XPLATSTR("script_hash")] = json::value::string(stringToTstring(localblock.GetScriptHash().toHexString()));

    //
    val[_XPLATSTR("payload_size")] = json::value::number(localblock.GetPayload().size());
    val[_XPLATSTR("block_size")] = json::value::number(localblock.GetSize());
}

void RestApi::blockBodyToJsonValue(const T_LOCALBLOCK& localblock, json::value& val)
{
    val[_XPLATSTR("script")] = json::value::string(stringToTstring(localblock.GetScript()));
    val[_XPLATSTR("auth")] = json::value::string(stringToTstring(localblock.GetAuth()));
    val[_XPLATSTR("payload")] = json::value::string(stringToTstring(localblock.GetPayload()));
}

void RestApi::blockToJsonValue(const T_LOCALBLOCK& localblock, json::value& val)
{
    blockHeadToJsonValue(localblock, val);
    blockBodyToJsonValue(localblock, val);
}

void RestApi::blockHeadToJsonValue(const T_HYPERBLOCK& hyperblock, size_t hyperBlockSize, json::value& val)
{
    val[_XPLATSTR("version")] = json::value::string(stringToTstring(hyperblock.GetVersion().tostring()));
    val[_XPLATSTR("weight")] = json::value::number(hyperblock.GetWeight());
    val[_XPLATSTR("hid")] = json::value::number(hyperblock.GetID());

    val[_XPLATSTR("hash")] = json::value::string(stringToTstring(hyperblock.GetHashSelf().toHexString()));

    val[_XPLATSTR("hash_prev")] = json::value::string(stringToTstring(hyperblock.GetPreHash().toHexString()));
    val[_XPLATSTR("hash_prev_header")] = json::value::string(stringToTstring(hyperblock.GetPreHeaderHash().toHexString()));
    val[_XPLATSTR("ctime")] = json::value::number(hyperblock.GetCTime());

    val[_XPLATSTR("merkle_hash_all")] = json::value::string(stringToTstring(hyperblock.GetMerkleHash().toHexString()));
    val[_XPLATSTR("br_root")] = json::value::string(stringToTstring(hyperblock.GetBRRoot().toHexString()));
    val[_XPLATSTR("xw_hash")] = json::value::string(stringToTstring(hyperblock.GetXWHash().toHexString()));
    val[_XPLATSTR("script_hash")] = json::value::string(stringToTstring(hyperblock.GetScriptHash().toHexString()));
    val[_XPLATSTR("br_rule")] = json::value::number(hyperblock.GetBRRule());

    json::value obj = json::value::array();
    for (uint16 i = 0; i < hyperblock.GetChildChainsCount(); i++) {
        obj[i] = json::value::number(hyperblock.GetChildChainBlockCount(i));
    }
    val[_XPLATSTR("childchain_blockscount")] = obj;     //

    obj = json::value::array();
    const list<T_SHA256>& tailhashlist = hyperblock.GetChildTailHashList();
    uint16 i = 0;
    for (auto tailhash : tailhashlist) {
        obj[i++] = json::value::string(stringToTstring(tailhash.toHexString()));
    }
    val[_XPLATSTR("tailblockshash")] = obj;       //

    //val[_XPLATSTR("hyperBlockHashVersion")] = json::value::number(1);
    val[_XPLATSTR("hyperBlockSize")] = json::value::number(hyperBlockSize);
}

void RestApi::blockBodyToJsonValue(const T_HYPERBLOCK& hyperblock, json::value& val)
{
    int j = 0;
    json::value vObj = json::value::array();
    for (auto list : hyperblock.body.localBlocksHeaderHash)
    {
        int i = 0;
        json::value lObj = json::value::array();
        for (auto hash : list)
        {
            lObj[i++] = json::value::string(stringToTstring(hash.toHexString()));
        }

        vObj[j++] = lObj;
    }
    val[_XPLATSTR("local_blocks_header_hash")] = vObj;     //

    int k = 0;
    json::value obj = json::value::array();
    for (auto addr : hyperblock.GetBRAddr()) {
        obj[k++] = json::value::string(stringToTstring(addr.toHexString()));
    }
    val[_XPLATSTR("br_addrs")] = obj;

    val[_XPLATSTR("script")] = json::value::string(stringToTstring(hyperblock.GetScript()));
    val[_XPLATSTR("auth")] = json::value::string(stringToTstring(hyperblock.GetAuth()));
}

void RestApi::blockToJsonValue(const T_HYPERBLOCK& hyperblock, size_t hyperBlockSize, json::value& val)
{
    blockHeadToJsonValue(hyperblock, hyperBlockSize, val);
    blockBodyToJsonValue(hyperblock, val);
}

json::value RestApi::getLocalblock(uint64_t hid, uint16 id, uint16 chain_num)
{
    json::value LocalBlock;
    T_LOCALBLOCK local;
    int nRet = Singleton<DBmgr>::instance()->getLocalblock(local, hid, id, chain_num);
    if (nRet == 0)
        blockToJsonValue(local, LocalBlock);

    return LocalBlock;
}

json::value RestApi::getLocalblockHead(uint64_t hid, uint16 id, uint16 chain_num)
{
    json::value LocalBlock;
    T_LOCALBLOCK local;
    int nRet = Singleton<DBmgr>::instance()->getLocalblock(local, hid, id, chain_num);
    if (nRet == 0)
        blockHeadToJsonValue(local, LocalBlock);


    return LocalBlock;
}

json::value RestApi::getLocalblockBody(uint64_t hid, uint16 id, uint16 chain_num)
{
    json::value LocalBlock;
    T_LOCALBLOCK local;
    int nRet = Singleton<DBmgr>::instance()->getLocalblock(local, hid, id, chain_num);
    if (nRet == 0)
        blockBodyToJsonValue(local, LocalBlock);

    return LocalBlock;
}

json::value RestApi::getHyperblocks(uint64_t nStartId, uint64_t nNum)
{
    json::value vHyperBlocks;
    std::list<T_HYPERBLOCK> queue;
    uint64_t nEndId = nStartId + nNum - 1;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(queue, nStartId, nEndId);
    if (nRet == 0) {
        for (auto& h : queue) {
            string_t sKey = stringToTstring(std::to_string(h.GetID()));
            size_t hyperBlockSize = sizeof(T_HYPERBLOCK);

            Singleton<DBmgr>::instance()->getLocalblocksPayloadTotalSize(h.GetID(), hyperBlockSize);
            blockToJsonValue(h, hyperBlockSize, vHyperBlocks[sKey][0]);

            int i = 1;
            std::list<T_LOCALBLOCK> listlocalblock;
            nRet = Singleton<DBmgr>::instance()->getLocalBlocks(listlocalblock, h.GetID());
            for (auto& l : listlocalblock) {
                blockToJsonValue(l, vHyperBlocks[sKey][i]);
                ++i;
            }
        }
    }

    return vHyperBlocks;
}

json::value RestApi::getHyperblockInfo(uint64_t hid)
{
    size_t hyperBlockSize = sizeof(T_HYPERBLOCK);

    json::value vHyperBlocks;

    list<T_HYPERBLOCK> listhyperblock;
    std::list<string> queue;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(listhyperblock, hid, hid);
    if (nRet != 0)
        return vHyperBlocks;

    Singleton<DBmgr>::instance()->getLocalblocksPayloadTotalSize(hid, hyperBlockSize);

    for (T_HYPERBLOCK& h : listhyperblock) {
        blockToJsonValue(h, hyperBlockSize, vHyperBlocks);
        break;
    }

    return vHyperBlocks;
}

json::value RestApi::getHyperblockHead(uint64_t hid)
{
    size_t hyperBlockSize = sizeof(T_HYPERBLOCK);
    json::value vHyperBlocks;
    list<T_HYPERBLOCK> listhyperblock;
    std::list<string> queue;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(listhyperblock, hid, hid);
    if (nRet != 0)
        return vHyperBlocks;

    Singleton<DBmgr>::instance()->getLocalblocksPayloadTotalSize(hid, hyperBlockSize);

    for (T_HYPERBLOCK& h : listhyperblock) {
        blockHeadToJsonValue(h, hyperBlockSize, vHyperBlocks);
        break;
    }

    return vHyperBlocks;
}

json::value RestApi::getHyperblockBody(uint64_t hid)
{
    json::value vHyperBlocks;
    list<T_HYPERBLOCK> listhyperblock;
    std::list<string> queue;
    int nRet = Singleton<DBmgr>::instance()->getHyperBlocks(listhyperblock, hid, hid);
    if (nRet != 0)
        return vHyperBlocks;

    for (T_HYPERBLOCK& h : listhyperblock) {
        blockBodyToJsonValue(h, vHyperBlocks);
        break;
    }

    return vHyperBlocks;
}

json::value RestApi::getLocalchain(uint64_t hid, uint64_t chain_num)
{
    int blocks = 0;
    int chain_difficulty = 0;
    json::value LocalChain;
    int nRet = Singleton<DBmgr>::instance()->getLocalchain(hid, chain_num, blocks, chain_difficulty);
    if (nRet == 0) {
        LocalChain[_XPLATSTR("chain_num")] = json::value::number(chain_num);	//
        LocalChain[_XPLATSTR("blocks")] = json::value::number(blocks);			//
        LocalChain[_XPLATSTR("block_chain")] = json::value::string(_XPLATSTR("unknown")); //
        LocalChain[_XPLATSTR("difficulty")] = json::value::number(chain_difficulty);	  //
        LocalChain[_XPLATSTR("consensus")] = json::value::string(_XPLATSTR("buddy"));	  //
    }

    return LocalChain;
}

struct HashFunc
{
    std::size_t operator()(const ONCHAINSTATUS& rhs) const {
        return std::hash<int>()(static_cast<int>(rhs));
    }
};

struct EqualKey
{
    bool operator () (const ONCHAINSTATUS& lhs, const ONCHAINSTATUS& rhs) const {
        return lhs == rhs;
    }
};

static unordered_map<ONCHAINSTATUS, string, HashFunc, EqualKey> mapstatus = {
    {ONCHAINSTATUS::queueing,"queueing"},
    {ONCHAINSTATUS::onchaining1,"onchaining1"},
    {ONCHAINSTATUS::onchaining2,"onchaining2"},
    {ONCHAINSTATUS::onchained,"onchained"},
    {ONCHAINSTATUS::matured,"matured"},
    {ONCHAINSTATUS::failed,"failed"},
    {ONCHAINSTATUS::nonexistent,"nonexistent"},
    {ONCHAINSTATUS::unknown,"unknown"},
};

json::value RestApi::getOnchainState(const string& requestID)
{
    json::value vHyperBlocks;
    T_LOCALBLOCKADDRESS addr;
    size_t queuenum;
    ONCHAINSTATUS status = ONCHAINSTATUS::unknown;

    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng) {
        status = consensuseng->GetOnChainState(requestID, queuenum);

        if (status == ONCHAINSTATUS::unknown) {
            //
            if (consensuseng->CheckSearchOnChainedPool(requestID, addr)) {
                status = ONCHAINSTATUS::failed;
                if (addr.isValid()) {
                    status = ONCHAINSTATUS::onchained;
                }
            }
            else {
                //
                bool isfound = Singleton<DBmgr>::instance()->getOnChainStateFromRequestID(requestID, addr);
                if (!isfound) {
                    status = ONCHAINSTATUS::nonexistent;
                }
                else {
                    status = ONCHAINSTATUS::matured;
                    if (!addr.isValid()) {
                        status = ONCHAINSTATUS::failed;
                    }
                }
            }
        }
    }

    vHyperBlocks[_XPLATSTR("onChainState")] = json::value::string(stringToTstring(mapstatus[status]));
    if (status == ONCHAINSTATUS::queueing) {
        vHyperBlocks[_XPLATSTR("queuenum")] = json::value::number(queuenum);
    }

    if (addr.isValid()) {
        vHyperBlocks[_XPLATSTR("hyperBlockId")] = json::value::number(addr.hid);
        vHyperBlocks[_XPLATSTR("chainNumber")] = json::value::number(addr.chainnum);
        vHyperBlocks[_XPLATSTR("localBlockId")] = json::value::number(addr.id);
    }
    return vHyperBlocks;
}

json::value RestApi::MakeRegistration(string strdata)
{
    vector<string> vcdata;
    vcdata.clear();

    json::value valQueueID;
    if (Upqueue(strdata, vcdata)) {
        valQueueID[_XPLATSTR("state")] = json::value::string(stringToTstring("queueing"));
        valQueueID[_XPLATSTR("requestid")] = json::value::string(stringToTstring(vcdata[0].c_str()));
        valQueueID[_XPLATSTR("queuenum")] = json::value::string(stringToTstring(vcdata[1].c_str()));
    }
    else {
        valQueueID[_XPLATSTR("requestid")] = json::value::string(stringToTstring(""));
        valQueueID[_XPLATSTR("state")] = json::value::string(stringToTstring("failed"));
    }

    return valQueueID;
}

bool RestApi::Upqueue(string strdata, vector<string>& out_vc)
{
    string requestid;
    ConsensusEngine* consensuseng = Singleton<ConsensusEngine>::getInstance();
    if (consensuseng == nullptr) {
        g_console_logger->error("ConsensusEngine is stopped");
        return false;
    }

    uint32 pos = consensuseng->AddNewBlockEx(T_APPTYPE(), "", strdata, requestid);
    out_vc.push_back(requestid);
    out_vc.push_back(std::to_string(pos));

    return true;
}

int RestApi::startRest()
{
    cout << "Start RestServer" << endl;
    try {
        restHandler.open().wait();
    }
    catch (std::exception & ex) {
        g_daily_logger->error("Start RestServer error");
        g_console_logger->error("Start RestServer error");
        cout << "RestServer exception:" << __FUNCTION__ << " " << ex.what() << endl;
        restHandler.close().wait();
    }

    return 0;
}

int RestApi::stopRest()
{
    try {
        restHandler.close().wait();
    }
    catch (std::exception & ex) {
        cout << "RestServer exception:" << __FUNCTION__ << " " << ex.what() << endl;
    }

    return 0;
}
