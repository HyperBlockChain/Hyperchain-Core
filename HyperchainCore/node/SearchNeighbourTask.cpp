/**
 * Project Untitled
 */
#pragma once

#include "Singleton.h"
#include "NodeManager.h"
#include "TaskThreadPool.h"
#include "SearchNeighbourTask.h"
#include "../wnd/common.h"

#include <iostream>
#include <map>
#include <ratio>
#include <chrono>
using namespace std;
using std::chrono::system_clock;

#include <cpprest/json.h>
using namespace web;

#include "ITask.hpp"
namespace SEED {

	typedef struct tagnode
	{
		string _nodeinfo;
		system_clock::time_point _tp;
	public:
		struct tagnode() {}
		struct tagnode(string nodeinfo) : _nodeinfo(nodeinfo), _tp(system_clock::now()) {}
		bool isTimeOut() {
			using minutes = std::chrono::duration<double, ratio<60>>;
			system_clock::time_point curr = system_clock::now();

			minutes timespan = std::chrono::duration_cast<minutes>(curr - _tp);
			if (timespan.count() > 30) {
				
				return true;
			}
			return false;
		}
	} NODE;

	std::map<string, NODE> g_mapNodes;
	int getPeerList(const string & nodeid,string & peerlist)
	{
		json::value obj = json::value::array();

		int i = 0;
		int maxlen = (64 - 1) * 1024;
		int len = 0;
		auto it = g_mapNodes.begin();
		for (; it != g_mapNodes.end();) {
			if (it->second.isTimeOut()) {
				g_mapNodes.erase(it++);
				continue;
			}
			if (it->first == nodeid) {
				++it;
				continue;
			}

			if (len + it->second._nodeinfo.size() > maxlen) {
				break;
			}

			len += it->second._nodeinfo.size();
			obj[i] = json::value::parse(s2t(it->second._nodeinfo));
			++i;
			++it;
		}
		std::stringstream oss;
		obj.serialize(oss);
		peerlist = std::move(oss.str());

		return i; 
	}
}

void SearchNeighbourRspTask::exec()
{
	string nodeid(_fromNodeId.ToHexString());
	SEED::g_mapNodes[nodeid] = SEED::NODE(_msg);

	string msgbuf;
	int num = SEED::getPeerList(nodeid, msgbuf);
	if (num <= 0) {
		
		return;
	}

	attachTaskMetaHead<SearchNeighbourRspTask>(msgbuf);

	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	nodemgr->sendTo(_fromNodeId, msgbuf);
}

void SearchNeighbourRspTask::execRespond()
{
	
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	nodemgr->parse(_payload);
}

void SearchNeighbourTask::exec()
{
	NodeManager *nodemgr = Singleton<NodeManager>::getInstance();
	CNode seedserver = nodemgr->seedServer();

	string msgbuf = nodemgr->myself().serialize();
	attachTaskMetaHead<SearchNeighbourTask>(msgbuf);

	nodemgr->sendTo(seedserver, msgbuf);

	cout << "SearchNeighbourTask request.";
}

void SearchNeighbourTask::execRespond()
{
	cout << "SearchNeighbourTask respond.";
	TaskThreadPool *taskpool = Singleton<TaskThreadPool>::instance();
	taskpool->put(make_shared<SearchNeighbourRspTask>(std::move(_sentnodeid), _payload));
}


