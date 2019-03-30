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
#include "../HyperChain/HyperData.h"
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


#include <string>
#include <locale>
#include <sstream>
using namespace std;

#define MAX_BUF_LEN 512
#define LOCAL_BLOCK_BASE_LEN	sizeof(T_LOCALBLOCK) - sizeof(T_FILEINFO)

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
	
	wstring_convert<codecvt_utf8<wchar_t> > strCnv;
	return strCnv.to_bytes(str);
#else
	
	return str;
#endif
}

utility::string_t stringToTstring(const string& str)
{
#ifdef _UTF16_STRINGS
	
	wstring_convert<codecvt_utf8<wchar_t> > strCnv;
	return strCnv.from_bytes(str);
#else
	
	return str;
#endif
}

CommandHandler::CommandHandler(utility::string_t url, http_listener_config server_config) : m_listener(url, server_config)
{
	m_listener.support(methods::GET, std::bind(&CommandHandler::handle_get, this, std::placeholders::_1));
	m_listener.support(methods::POST, std::bind(&CommandHandler::handle_post, this, std::placeholders::_1));
	m_listener.support(methods::PUT, std::bind(&CommandHandler::handle_put, this, std::placeholders::_1));
	m_listener.support(methods::DEL, std::bind(&CommandHandler::handle_del, this, std::placeholders::_1));
}



std::vector<utility::string_t> requestPath(const http_request & message) {
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

#define BADPARAMETER message.reply(status_codes::OK, json::value(_XPLATSTR("Bad Parameter")));

void CommandHandler::handle_get(http_request message)
{
	utility::string_t hash;

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
	}

	auto path = requestPath(message);
	if (!path.empty() && path.size() == 1) {

		std::map<utility::string_t, utility::string_t> query = uri::split_query(uri::decode(message.request_uri().query()));

		json::value vRet;

		if (path[0] == U("SubmitRegistration")) {
			auto data = query.find(U("data"));
			if (data == query.end()) {
				BADPARAMETER;
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
				BADPARAMETER;
				return;
			}
			auto cntEntryNum = query.find(U("num"));
			if (cntEntryNum == query.end()) {
				BADPARAMETER;
				return;
			}
			utility::string_t sId = cntEntryId->second;
			utility::string_t sNum = cntEntryNum->second;

			uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());
			uint64_t nNum = atoi(tstringToUtf8(sNum).c_str());

			RestApi api;
			vRet = api.getHyperblocks(nHyperBlockId, nNum);
		}

		else if (path[0] == U("GetLocalBlock")) {
			auto cntEntryHId = query.find(U("hid"));
			if (cntEntryHId == query.end()) {
				BADPARAMETER;
				return;
			}
			auto cntEntryId = query.find(U("id"));
			if (cntEntryId == query.end()) {
				BADPARAMETER;
				return;
			}
			auto cntEntryNum = query.find(U("chain_num"));
			if (cntEntryNum == query.end()) {
				BADPARAMETER;
				return;
			}

			utility::string_t sHId = cntEntryHId->second;
			utility::string_t sId = cntEntryId->second;
			utility::string_t sNum = cntEntryNum->second;

			uint64_t nHyperBlockId = atoi(tstringToUtf8(sHId).c_str());
			uint64_t nLocalBlockId = atoi(tstringToUtf8(sId).c_str());
			uint64_t nNum = atoi(tstringToUtf8(sNum).c_str());

			RestApi api;
			vRet = api.getLocalblock(nHyperBlockId, nLocalBlockId, nNum);
		}

		else if (path[0] == U("GetLocalChain")) {
			auto cntEntryHId = query.find(U("hid"));
			if (cntEntryHId == query.end()) {
				BADPARAMETER;
				return;
			}
			auto cntEntryNum = query.find(U("chain_num"));
			if (cntEntryNum == query.end()) {
				BADPARAMETER;
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
				BADPARAMETER;
				return;
			}

			if (id != query.end() && !id->second.empty()) {
				string strid = tstringToUtf8(id->second);

				RestApi api;
				vRet = api.getOnchainState(strid);
			}
		}
		else if (path[0] == U("GetHyperBlockHead"))
		{
			auto cntEntryId = query.find(U("key"));
			if (cntEntryId == query.end()) {
				BADPARAMETER;
				return;
			}
			utility::string_t sId = cntEntryId->second;
			uint64_t nHyperBlockId = atoi(tstringToUtf8(sId).c_str());

			RestApi api;
			vRet = api.getHyperblocksHead(nHyperBlockId);
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
			RestApi api;
			uint64_t num = api.getLatestHyperBlockNo();

			vRet[_XPLATSTR("laststHyperBlockNo")] = json::value::number(num);

		}
		else if (path[0] == U("GetLatestHyperBlock")) {
			RestApi api;
			uint64_t num = api.getLatestHyperBlockNo();
			vRet = api.getHyperblocks(num, 1);
		}

		else if (path[0] == U("GetNodeRuntimeEnv"))
		{
			NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
			if (nodemgr == nullptr)
				return;

			HCNodeSH me = nodemgr->myself();
			string strnodeenv = me->serialize();

			vRet[_XPLATSTR("NodeEnv")] = json::value::string(s2t(strnodeenv));

		}
		else if (path[0] == U("GetStateOfCurrentConsensus"))
		{
			ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
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

			ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
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
		else if (path[0] == U("CreatCustomerizeConsensusScript"))
		{
			auto cntEntryType = query.find(U("Type"));
			if (cntEntryType == query.end()) {
				BADPARAMETER;
				return;
			}
			auto cntEntryScript = query.find(U("Script"));
			if (cntEntryScript == query.end()) {
				BADPARAMETER;
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
			NodeManager *nodemgr = Singleton<NodeManager>::getInstance();

			vRet[_XPLATSTR("NeighborNodes")] = json::value::string(s2t(nodemgr->toString()));
			vRet[_XPLATSTR("NeighborNodesNum")] = json::value::number(nodemgr->getNodeMapSize());
		}

		else if (path[0] == U("GetHyperBlocksIDList"))
		{
			CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();

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
			for (auto t : LocalChainSpace)
			{
				Ldata += t;
				Ldata += ";";
			}

			vRet[_XPLATSTR("HyperBlocksNum")] = json::value::number(nums);
			vRet[_XPLATSTR("HyperBlocksIDList")] = json::value::string(s2t(Ldata));
		}
		else if (path[0] == U("GetHyperChainSpace"))
		{
			CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();

			map<string, string> HyperChainSpace;
			HSpce->GetHyperChainShow(HyperChainSpace);

			if (HyperChainSpace.size() <= 0)
			{
				vRet[_XPLATSTR("HyperChainSpace")] = json::value::string(_XPLATSTR(""));
				return;
			}

			json::value obj;
			for (auto mdata : HyperChainSpace)
			{
				obj[s2t(mdata.first)] = json::value::string(s2t(mdata.second));
			}

			std::stringstream oss;
			obj.serialize(oss);

			vRet[_XPLATSTR("HyperChainSpace")] = json::value::string(s2t(oss.str()));
		}

		else if (path[0] == U("GetHyperChainSpaceMore"))
		{
			auto cntEntryId = query.find(U("key"));
			if (cntEntryId == query.end())
			{
				BADPARAMETER;
				return;
			}

			utility::string_t sId = cntEntryId->second;
			uint64 nblocknum = std::stol(tstringToUtf8(sId));

			CHyperChainSpace * HSpce = Singleton<CHyperChainSpace, string>::getInstance();

			MULTI_MAP_HPSPACEDATA HyperChainSpace;
			HSpce->GetHyperChainData(HyperChainSpace);

			if (HyperChainSpace.size() <= 0)
			{
				vRet[_XPLATSTR("HyperBlockID")] = json::value::number(nblocknum);
				vRet[_XPLATSTR("NodeIDList")] = json::value::string(_XPLATSTR(""));
				return;
			}

			string nodelist;
			for (auto mdata : HyperChainSpace)
			{
				if (mdata.first != nblocknum)
					continue;

				for (auto sid : mdata.second)
				{
					nodelist += sid.first;
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
				BADPARAMETER;
				return;
			}

			auto cntEntryNodeId = query.find(U("NodeID"));
			if (cntEntryNodeId == query.end())
			{
				BADPARAMETER;
				return;
			}

			utility::string_t sblockId = cntEntryBlockId->second;
			uint64 nblocknum = std::stol(tstringToUtf8(sblockId));
			string strnodeid = t2s(cntEntryNodeId->second);

			CHyperData * hd = Singleton<CHyperData>::instance();
			hd->PullHyperDataByHID(nblocknum, strnodeid);

			vRet[_XPLATSTR("returnValue")] = json::value::string(_XPLATSTR("success"));
		}

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
	message.reply(status_codes::OK, "PUT");
}

void CommandHandler::handle_del(http_request message)
{
	message.reply(status_codes::OK, "DE_XPLATSTR(");
}

json::value RestApi::blockHeadToJsonValue(T_HYPERBLOCKDBINFO blockDBInfo, size_t hyperBlockSize)
{
	json::value valHyperBlock;

	valHyperBlock[_XPLATSTR("hyperBlockId")] = json::value::number(blockDBInfo.uiBlockId);
	valHyperBlock[_XPLATSTR("hyperBlockHash")] = json::value::string(stringToTstring(DBmgr::instance()->hash256tostring(blockDBInfo.strHashSelf).c_str()));
	valHyperBlock[_XPLATSTR("hyperCreateTime")] = json::value::number(blockDBInfo.uiBlockTimeStamp);
	valHyperBlock[_XPLATSTR("buddyScript")] = json::value::string(_XPLATSTR(""));
	valHyperBlock[_XPLATSTR("publicKey")] = json::value::string(_XPLATSTR(""));
	valHyperBlock[_XPLATSTR("perHyperBlockHash")] = json::value::string(stringToTstring(DBmgr::instance()->hash256tostring(blockDBInfo.strPreHash).c_str()));
	valHyperBlock[_XPLATSTR("hyperBlockSize")] = json::value::number(hyperBlockSize);
	valHyperBlock[_XPLATSTR("hyperBlockHashVersion")] = json::value::number(1);

	return valHyperBlock;
}

json::value RestApi::blockToJsonValue(T_HYPERBLOCKDBINFO blockDBInfo)
{
	json::value valHyperBlock;

	valHyperBlock[_XPLATSTR("id")] = json::value::number(blockDBInfo.uiBlockId);
	valHyperBlock[_XPLATSTR("hash")] = json::value::string(stringToTstring(DBmgr::instance()->hash256tostring(blockDBInfo.strHashSelf)));
	valHyperBlock[_XPLATSTR("ctime")] = json::value::number(blockDBInfo.uiBlockTimeStamp);
	valHyperBlock[_XPLATSTR("hash_prev")] = json::value::string(stringToTstring(DBmgr::instance()->hash256tostring(blockDBInfo.strPreHash)));
	valHyperBlock[_XPLATSTR("version")] = json::value::string(stringToTstring(blockDBInfo.strVersion));

	valHyperBlock[_XPLATSTR("type")] = json::value::number(blockDBInfo.ucBlockType);
	valHyperBlock[_XPLATSTR("hid")] = json::value::number(blockDBInfo.uiReferHyperBlockId);
	valHyperBlock[_XPLATSTR("hhash")] = json::value::string(stringToTstring(DBmgr::instance()->hash256tostring(blockDBInfo.strHyperBlockHash)));
	valHyperBlock[_XPLATSTR("payload")] = json::value::string(stringToTstring(blockDBInfo.strPayload));
	valHyperBlock[_XPLATSTR("chain_num")] = json::value::number(blockDBInfo.uiLocalChainId);
	valHyperBlock[_XPLATSTR("difficulty")] = json::value::number(blockDBInfo.difficulty);
	valHyperBlock[_XPLATSTR("hash_version")] = json::value::number(1);


	if (blockDBInfo.ucBlockType == 2) {
		
		size_t payload_size = blockDBInfo.strPayload.length();
		size_t block_size = LOCAL_BLOCK_BASE_LEN + payload_size;
		valHyperBlock[_XPLATSTR("payload_size")] = json::value::number(payload_size);
		valHyperBlock[_XPLATSTR("block_size")] = json::value::number(block_size);
	}

	return valHyperBlock;
}

json::value RestApi::getLocalblock(uint64_t hid, uint64_t id, uint64_t chain_num)
{
	json::value LocalBlock;
	T_HYPERBLOCKDBINFO local;
	int nRet = DBmgr::instance()->getLocalblock(local, hid, id, chain_num);
	if (nRet == 0 && local.ucBlockType == 2)
		LocalBlock = blockToJsonValue(local);

	return LocalBlock;
}

json::value RestApi::getLocalchain(uint64_t hid, uint64_t chain_num)
{
	int blocks = 0;
	int chain_difficulty = 0;
	json::value LocalChain;
	int nRet = DBmgr::instance()->getLocalchain(hid, chain_num, blocks, chain_difficulty);
	if (nRet == 0)
	{
		LocalChain[_XPLATSTR("chain_num")] = json::value::number(chain_num);	
		LocalChain[_XPLATSTR("blocks")] = json::value::number(blocks);			
		LocalChain[_XPLATSTR("block_chain")] = json::value::string(_XPLATSTR("unknown")); 
		LocalChain[_XPLATSTR("difficulty")] = json::value::number(chain_difficulty);	  
		LocalChain[_XPLATSTR("concensus")] = json::value::string(_XPLATSTR("buddy"));	  
	}

	return LocalChain;
}

json::value RestApi::getHyperblocks(uint64_t nStartId, uint64_t nNum)
{
	json::value vHyperBlocks;
	std::list<T_HYPERBLOCKDBINFO> queue;
	int nEndId = nStartId + nNum - 1;
	int nRet = DBmgr::instance()->getHyperblocks(queue, nStartId, nEndId);
	if (nRet == 0)
	{
		int i = 0;
		for (auto info : queue) {
			ostringstream_t oss;
			oss << info.uiReferHyperBlockId;
			string_t sKey = oss.str();

			if (info.ucBlockType == 1) {
				vHyperBlocks[sKey][0] = blockToJsonValue(info);
			}
			else if (info.ucBlockType == 2) {
				vHyperBlocks[sKey][i] = blockToJsonValue(info);
			}
			++i;
		}
	}

	return vHyperBlocks;
}

json::value RestApi::getHyperblocksHead(uint64_t nStartId)
{
	size_t hyperBlockSize = sizeof(T_HYPERBLOCK);
	json::value vHyperBlocks;
	T_HYPERBLOCKDBINFO HBlock;
	std::list<string> queue;
	int nRet = DBmgr::instance()->getHyperblockshead(HBlock, nStartId);
	if (nRet != 0)
		return vHyperBlocks;

	if (HBlock.ucBlockType != 1)
		return vHyperBlocks;

	nRet = DBmgr::instance()->getLocalblocksPayload(queue, nStartId);
	if (nRet != 0)
		return vHyperBlocks;

	for (auto payload : queue) {
		hyperBlockSize += (LOCAL_BLOCK_BASE_LEN + payload.length());
	}

	vHyperBlocks = blockHeadToJsonValue(HBlock, hyperBlockSize);

	return vHyperBlocks;
}

int RestApi::getLatestHyperBlockNo()
{
	return DBmgr::instance()->getLatestHyperBlockNo();
}

struct HashFunc
{
	std::size_t operator()(const ONCHAINSTATUS &rhs) const {
		return std::hash<int>()(static_cast<int>(rhs));
	}
};

struct EqualKey
{
	bool operator () (const ONCHAINSTATUS &lhs, const ONCHAINSTATUS &rhs) const {
		return lhs == rhs;
	}
};

static unordered_map<ONCHAINSTATUS, string, HashFunc, EqualKey> mapstatus = {
	{ONCHAINSTATUS::waiting,"waiting"},
	{ONCHAINSTATUS::onchaining,"onchaining"},
	{ONCHAINSTATUS::onchained,"onchained"},
	{ONCHAINSTATUS::success,"success"},
	{ONCHAINSTATUS::nonexistent,"nonexistent"},
	{ONCHAINSTATUS::unknown,"unknown"},
};

json::value RestApi::getOnchainState(const string & requestID)
{
	json::value vHyperBlocks;
	T_LOCALBLOCKADDRESS addr;
	ONCHAINSTATUS status = ONCHAINSTATUS::unknown;

	ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
	if (consensuseng) {
		status = consensuseng->GetOnChainState(requestID, addr);

		if (status == ONCHAINSTATUS::unknown) {
			if (consensuseng->CheckSearchOnChainedPool(requestID, addr)) {
				status = ONCHAINSTATUS::waiting;
				if (addr.isValid()) {
					status = ONCHAINSTATUS::onchained;
				}
			}
			else {
				
				status = ONCHAINSTATUS::success;
				addr = DBmgr::instance()->getOnChainStateFromRequestID(requestID);
				if (!addr.isValid()) {
					status = ONCHAINSTATUS::nonexistent;
				}
			}
		}
	}

	vHyperBlocks[_XPLATSTR("requestId")] = json::value::string(stringToTstring(requestID));
	vHyperBlocks[_XPLATSTR("hyperBlockId")] = json::value::number(addr.hid);
	vHyperBlocks[_XPLATSTR("chainNumber")] = json::value::number(addr.chainnum);
	vHyperBlocks[_XPLATSTR("localBlockId")] = json::value::number(addr.id);
	vHyperBlocks[_XPLATSTR("onChainState")] = json::value::string(stringToTstring(mapstatus[status]));
	return vHyperBlocks;
}


json::value RestApi::MakeRegistration(string strdata)
{
	vector<string> vcdata;
	vcdata.clear();

	json::value valQueueID;
	if (Upqueue(strdata, vcdata)) {
		valQueueID[_XPLATSTR("requestid")] = json::value::string(stringToTstring(vcdata[0].c_str()));
		valQueueID[_XPLATSTR("state")] = json::value::string(stringToTstring("waiting"));
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
	ConsensusEngine * consensuseng = Singleton<ConsensusEngine>::getInstance();
	if (consensuseng == nullptr) {
		g_console_logger->error("ConsensusEngine is stopped");
		return false;
	}

	consensuseng->AddNewBlockEx(strdata, requestid);
	out_vc.push_back(requestid);
	return true;
}

int RestApi::startRest()
{
	cout << "start Rest Server" << endl;
	try {
		restHandler.open().wait();
	}
	catch (std::exception& ex) {
		g_daily_logger->error("start Rest Server error");
		g_console_logger->error("start Rest Server error");
		cout << "RestServer exception:" << __FUNCTION__ << " "<< ex.what() << endl;
		restHandler.close().wait();
	}

	return 0;
}

int RestApi::stopRest()
{
	try {
		restHandler.close().wait();
	}
	catch (std::exception& ex) {
		cout << "RestServer exception:" << __FUNCTION__ << " "<< ex.what() << endl;
	}

	return 0;
}
