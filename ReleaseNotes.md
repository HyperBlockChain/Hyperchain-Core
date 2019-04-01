# Release Note
## Version: LFT 0.1.5
## When: 2019-03-29
## 1 Restapi Interface Update
### new：
   GetLocalBlock：query local block data from node
   GetLocalChain：query local chain data from node
   GetHyperBlocksIDList：query hyper blocks from node local
   
### Obseleted：
   GetLocalHyperBlockNums:query hyper blocks from node local

### Parameter Upgrade:
   SubmitRegistration：submit onchain registrations.
   getOnchainState: query progress from node local after submitted onchain registration.

## 2 Optimized udp multiple thread processing and cache storage data structure
## 3 Enhanced exception handlers.
## 4 Optimized process resource consumption and recycling.
## 5 Adapted block meta data.
## 6 Optimized general concensus processing efficency and test harness.
## 8 Optimzed buddy concensus efficency.
## 9 Optimzed memory pool. 
## 10 Optimzed unexpected hard fork processing.
## 11 fix memory leaks.
