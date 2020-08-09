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

#pragma once



#define MDPC_CLIENT         "MDPC01"



#define MDPW_WORKER         "MDPW01"



#define MDP_MON "MDPMON"



#define MDPW_READY          "\001"
#define MDPW_IDLE           "\002"
#define MDPW_REQUEST        "\003"
#define MDPW_REPLY          "\004"
#define MDPW_HEARTBEAT      "\005"
#define MDPW_DISCONNECT     "\006"

#define HC_BROKER "inproc:


#define CONSENSUS_SERVICE "consensus"
#define CONSENSUS_T_SERVICE "consensus_task"

#define NODE_SERVICE "node"
#define NODE_T_SERVICE "node_task"

#define HYPERCHAINSPACE_SERVICE "hyperchainspace"
#define HYPERCHAINSPACE_T_SERVICE "hyperchain_task"

#define HYPERBLOCK_PUB_SERVICE "inproc://hyperblock_pub"

extern zmq::context_t * g_inproc_context;
extern int g_sys_interrupted;



