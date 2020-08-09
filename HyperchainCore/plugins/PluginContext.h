#pragma once

#include "node/Singleton.h"
#include "node/NodeManager.h"
#include "node/mdp.h"
#include "HyperChain/HyperChainSpace.h"
#include "db/dbmgr.h"
#include "consensus/consensus_engine.h"
#include "consensus/buddyinfo.h"

#ifdef WIN32
#include "newLog.h"
#endif // WIN32


struct PluginContext
{
    int pc_argc = 0;
    char** pc_argv = nullptr;
    NodeManager* nodemgr = nullptr;
    CHyperChainSpace* hyperchainspace = nullptr;
    ConsensusEngine* consensuseng = nullptr;
	DBmgr* dbmgr = nullptr;
    T_P2PMANAGERSTATUS* tP2pManagerStatus = nullptr;
    zmq::context_t* inproc_context = nullptr;

#ifdef WIN32
    std::shared_ptr<spdlog::logger> daily_logger;
    std::shared_ptr<spdlog::logger> basic_logger;
    std::shared_ptr<spdlog::logger> rotating_logger;
    std::shared_ptr<spdlog::logger> console_logger;
    std::shared_ptr<spdlog::logger> consensus_console_logger;
#endif

    

    void SetPluginContext()
    {
        Singleton<NodeManager>::setInstance(nodemgr);
        Singleton<CHyperChainSpace, string>::setInstance(hyperchainspace);
        Singleton<ConsensusEngine>::setInstance(consensuseng);
        Singleton<DBmgr>::setInstance(dbmgr);
        Singleton<T_P2PMANAGERSTATUS>::setInstance(tP2pManagerStatus);

        g_inproc_context = inproc_context;

        

        //g_tP2pManagerStatus = tP2pManagerStatus;

#ifdef WIN32
        g_daily_logger = daily_logger;
        g_basic_logger = basic_logger;
        g_rotating_logger = rotating_logger;
        g_console_logger = console_logger;
        g_consensus_console_logger = consensus_console_logger;
#endif

    }
};

