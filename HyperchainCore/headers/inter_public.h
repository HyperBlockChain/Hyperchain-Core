/*Copyright 2016-2020 hyperchain.net (Hyperchain)

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

#ifndef __INTER_PUBLIC_H__
#define __INTER_PUBLIC_H__

#include <inttypes.h>

#include<iostream>
#include<vector>
#include <cstdio>
#ifdef WIN32
#include <time.h>
#else
#include <sys/time.h>
#include <iconv.h>
#endif

#include<stdio.h>
#include<stdlib.h>
#include <string.h>
#include <stdint.h>
#include "gen_int.h"
#include "includeComm.h"
#include "shastruct.h"

using namespace std;



#define MAX_SECS_COUNTER (9999999999)
#define MAX_SECS_COUNTER (9999999999)
#define MAX_SEND_NAT_TRAVERSAL_NODE_NUM (2)
#define MAX_SEND_PEERLIST_RSP_PERIOD	(5*60)
#define MAX_SAVE_PEERLIST_PERIOD		(30*60)
#define MAX_SEND_CHAIN_STATE_RSP_PERIOD	(5*60)
#define MAX_RECV_UDP_BUF_LEN			(64*1024)
#define	MAX_NATTRAVERSAL_PERIOD					(10*60)
#define RANDTIME						(60)
#define LOCALBUDDYTIME                  (1*60)
#define GLOBALBUDDYTIME                 (2*60)
#define NEXTBUDDYTIME					(3*60-30)
#define LIST_BUDDY_RSP_NUM				(3)
#define BUDDYSCRIPT						("buddy_script")
#define AUTHKEY							("auth_key")
#define FILESIZES						(256)
#define FILESIZEL						(512)
#define BUFFERLEN						(1024)
#define PORT							(8111)
#define MAGICNUMBER						(116444736000000000)
#define SECONDLEN						(10000000)
#define TEST_SERVER1					("http://192.168.0.2/api/nodeinfo?node=")
#define TEST_SERVER2					("http://192.168.0.3/api/nodeinfo?node=")
#define ONE_SECOND						(1000)
#define ONE_MIN						    (60*ONE_SECOND)
#define INIT_TIME						(10)
#define ONE_KILO						(1024)
#define FIVE_MINI						(5*60)
#define ONE_HOUR						(60*60)
#define UNICODE_POS					    (2)
#define DIVIDEND_NUM					(2)
#define MAX_NUM_LEN						(256)
#define ONE_LOCAL_BLOCK				    (1)
#define NOT_START_BUDDY_NUM				(1)
#define LEAST_START_GLOBAL_BUDDY_NUM    (2)
#define HYPERBLOCK_SYNC_TIMES			(2)
#define REQUEST_ID_LEN					(32)
#define MATURITY_TIME					(10 * 60)

enum _ePoeReqState
{
    DEFAULT_REGISREQ_STATE = 0,
    RECV,													

    SEND,													

    STOP,													

    CONFIRMING,												

    CONFIRMED,												

    REJECTED,												

//	OTHERREFUSEME,											

//	ALLCONFIRMED,											

//	ALLOTHERREFUSEME,										

//	ALLMYREFUSEOTHER										

};

enum _eblocktype
{
    HYPER_BLOCK = 1,
    LOCAL_BLOCK
};

enum _eNodeState
{
    DEFAULT_NODE_STATE = 0,
    SYNC_DATA_STATE,		

    IDLE_STATE,				

    LOCAL_BUDDY_STATE,		

    GLOBAL_BUDDY_STATE,		

    ON_CHAIN_SUCCESS,		

    ON_CHAIN_FAILED,		

    NODE_MALICE				

};


enum _eChainState
{
    CHAIN_DEFAULT_STATE = 0,
    CHAIN_CONFIRMING,				

    CHAIN_CONFIRMED					

};
#pragma pack(push,1)





typedef struct _tLocalChain
{
    uint16	iId;							

    uint64	iAllChainNodeNum;				

    _eChainState	eState;					


    void Set(uint16 id, uint64 allChainNodeNum, _eChainState state);

    uint16 GetID()const;

    uint64 GetChainNodesNum()const;

    _eChainState GetChainState()const;

}TGETFRIENDCHAININFO, *P_TGETFRIENDCHAININFO;



typedef struct _tPoeInfo
{
    string				cFileName;			

    string				cCustomInfo;		

    string				cRightOwner;		

    string				cFileHash;			

    int16				iFileState;			

    uint64				tRegisTime;			

    uint64				iFileSize;			

    uint64				iBlocknum;			


    _tPoeInfo()
    {
        cFileName = "";
        cCustomInfo = "";
        cRightOwner = "";
        cFileHash = "";
        iFileSize = 0;
        iFileState = DEFAULT_REGISREQ_STATE;
        tRegisTime = 0;
        iBlocknum = 0;
    }

    void Set(string fileName, string customInfo, string rightOwner, string fileHash,
        int16 fileState, uint64 regisTime, uint64 fileSize, uint64 blockNum);

    string GetFileName()const;
    string GetFileHash()const;
    int16 GetFileState()const;
    string GetBlockNum()const;
    uint64 GetFileSize()const;
    string GetRightOwner()const;
    uint64 GetRegisTime()const;
    string GetCustomInfo()const;



}TEVIDENCEINFO, *P_TEVIDENCEINFO;



typedef struct _tChainQueryStru
{
    uint64		iBlockNo;								

    uint64		iJoinedNodeNum;							

    uint64		iLocalBlockNum;							

    uint16		iLocalChainNum;							

    //uint16		iLongestChain;						

    uint64		tTimeStamp;								

    _tPoeInfo tPoeRecordInfo;

    _tChainQueryStru()
    {
        iBlockNo = 0;
        iLocalChainNum = 0;
        iLocalBlockNum = 0;
        iJoinedNodeNum = 0;
        //iLongestChain = 0;
        tTimeStamp = 0;
    }

    void Set(uint64 blockNo, uint64 joinedNodeNum, uint64 localBlockNum, uint16 localChainNum, uint64 timeStamp,
        _tPoeInfo poeRecordInfo);

    uint64 GetBlockNo()const;

    uint64 GetJoinedNodeNum()const;

    uint64 GetLocalBlockNum()const;

    uint16 GetLocalChainNUm()const;

    uint64 GetTimeStamp()const;

    _tPoeInfo GetPoeRecordInfo()const;

}TBROWSERSHOWINFO, *P_TBROWSERSHOWINFO;
#pragma pack(pop)



typedef struct _tUpqueue
{
    uint64 uiID;
    string strHash;
    uint64 uiTime;
}TUPQUEUE, *P_TUPQUEUE;

typedef struct _tlocalblockaddress
{
    uint64 hid = 0;            

    uint16 chainnum = 0;
    uint16 id = 0;
    string ns;                  


    void set(uint64 uihid, uint16 chain, uint16 uiid, string nspace ="") {
        hid = uihid;
        chainnum = chain;
        id = uiid;
        ns = nspace;
    }
    bool isValid() const {
        return hid >= uint64(0) && id > (uint16)0 && chainnum > (uint16)0;
    }
    string tostring() const {
        const char *fmt = "[%lld,%d,%d]";
        int sz = std::snprintf(nullptr, 0, fmt, hid, chainnum, id);
        std::string buf(sz, 0);
        std::snprintf(&buf[0], buf.size()+1, fmt, hid, chainnum, id);
        return buf;
    }

    bool fromstring(const string& addr)
    {
        

        //return (std::sscanf(addr.c_str(),"[%lld,%d,%d]",&hid,&chainnum,&id) !=3);
        return (std::sscanf(addr.c_str(),"[%" PRId64 ",%hd,%hd]",&hid,&chainnum,&id) !=3);
    }

    bool operator <(const _tlocalblockaddress &addr) const
    {
        if (hid < addr.hid) {
            return true;
        } else if (hid > addr.hid) {
            return false;
        }

        if (chainnum < addr.chainnum) {
            return true;
        } else if (chainnum > addr.chainnum) {
            return false;
        }

        if (id < addr.id) {
            return true;
        } else if (id > addr.id) {
            return false;
        }
        return false;
    }
    bool operator >=(const _tlocalblockaddress &addr) const
    {
        if (hid > addr.hid) {
            return true;
        } else if (hid < addr.hid) {
            return false;
        }

        if (chainnum > addr.chainnum) {
            return true;
        } else if (chainnum < addr.chainnum) {
            return false;
        }

        if (id > addr.id) {
            return true;
        } else if (id < addr.id) {
            return false;
        }
        return true;
    }

    friend bool operator==(const _tlocalblockaddress& a, const _tlocalblockaddress& b)
    {
        return a.hid == b.hid && a.chainnum == b.chainnum && a.id == b.id && a.ns == b.ns;
    }

    friend bool operator!=(const _tlocalblockaddress& a, const _tlocalblockaddress& b)
    {
        return !(a == b);
    }


    friend class boost::serialization::access;
    template <typename Archive>
    void serialize(Archive &ar, const unsigned int version)
    {
        ar & hid;
        ar & chainnum;
        ar & id;
        ar & ns;
    }

}T_LOCALBLOCKADDRESS, *P_TLOCALBLOCKADDRESS;





typedef struct _tBlockInfo
{
    uint64 iBlockNo;
    uint64 iCreatTime;
    _tPoeInfo tPoeRecordInfo;

    void Set(uint64 blockNo, uint64 createTime, _tPoeInfo poeRecordInfo);

    uint64 GetBlockNo()const;

    uint64 GetCreateTime()const;

    _tPoeInfo GetPoeRecordInfo()const;

}TBLOCKINFO, *P_TBLOCKINFO;

typedef struct _tHBlockDlgInfo
{
    uint64 iBlockNo;
    uint64 iCreatTime;
    uint64 iLocalBlockNum;
    string strHHash;
    string strVersion;

    void Set(uint64 blockNo, uint64 createTime, uint64 localBlockNum, string HHash, string version);

    uint64 GetBlockNo()const;

    uint64 GetCreateTime()const;

    uint64 GetLocalBlockNum()const;

    string GetParentHash()const;

}THBLOCKDLGINFO, *P_THBLOCKDLGINFO;

typedef struct _tNodeInfo
{
    uint64 uiNodeState;
    string strNodeIp;

    _tNodeInfo() {};
    _tNodeInfo(uint64 nodeState, string nodeIp);
    void Set(uint64 nodeState, string nodeIp);

    uint64 GetNodeState()const;

    string GetNodeIp()const;

}TNODEINFO, *P_TNODEINFO;

typedef vector<P_TBLOCKINFO>					VEC_T_BLOCKINFO;
typedef VEC_T_BLOCKINFO::iterator				ITR_VEC_T_BLOCKINFO;

typedef vector<TNODEINFO>						VEC_T_NODEINFO;
typedef VEC_T_NODEINFO::iterator				ITR_VEC_T_NODEINFO;

typedef vector<TBROWSERSHOWINFO>				VEC_T_BROWSERSHOWINFO;
typedef VEC_T_BROWSERSHOWINFO::iterator			ITR_VEC_T_BROWSERSHOWINFO;

typedef vector<P_TEVIDENCEINFO>					VEC_T_EVIDENCEINFO;
typedef VEC_T_EVIDENCEINFO::iterator			ITR_VEC_T_EVIDENCEINFO;



typedef vector<P_TUPQUEUE>						VEC_T_UPQUEUEINFO;
typedef VEC_T_UPQUEUEINFO::iterator				ITR_VEC_T_UPQUEUEINFO;

typedef vector<P_THBLOCKDLGINFO>				VEC_T_HBLOCKDLGINFO;
typedef VEC_T_HBLOCKDLGINFO::iterator			ITR_VEC_T_HBLOCKDLGINFO;

#endif