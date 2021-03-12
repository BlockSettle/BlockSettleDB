////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _ZEROCONF_UTILS_H_
#define _ZEROCONF_UTILS_H_

#include <map>
#include <set>
#include "BinaryData.h"
#include "txio.h"

class LMDBBlockDatabase;

////////////////////////////////////////////////////////////////////////////////
enum class ParsedTxStatus
{
   Uninitialized,
   Resolved,
   ResolveAgain,
   Unresolved,
   Mined,
   Invalid,
   Skip
};

////////////////////////////////////////////////////////////////////////////////
enum class InputResolution
{
   Both,
   Unconfirmed,
   Mined
};

////////////////////////////////////////////////////////////////////////////////
struct ParsedZCData
{
   std::set<BinaryData> scrAddrs_;
   std::map<BinaryData, BinaryData> invalidatedKeys_;

   void mergeTxios(const ParsedZCData& pzd)
   {
      scrAddrs_.insert(pzd.scrAddrs_.begin(), pzd.scrAddrs_.end());
   }
};

////////////////////////////////////////////////////////////////////////////////
class OutPointRef
{
private:
   BinaryData txHash_;
   unsigned txOutIndex_ = UINT16_MAX;
   BinaryData dbKey_;
   uint64_t time_ = UINT64_MAX;

public:
   void unserialize(uint8_t const * ptr, uint32_t remaining);
   void unserialize(BinaryDataRef bdr);

   void resolveDbKey(LMDBBlockDatabase*);
   const BinaryData& getDbKey(void) const { return dbKey_; }

   bool isResolved(void) const { return dbKey_.getSize() == 8; }
   bool isInitialized(void) const;

   BinaryDataRef getTxHashRef(void) const { return txHash_.getRef(); }
   unsigned getIndex(void) const { return txOutIndex_; }

   BinaryData& getDbKey(void) { return dbKey_; }
   BinaryDataRef getDbTxKeyRef(void) const;

   void reset(InputResolution);
   bool isZc(void) const;

   void setTime(uint64_t t) { time_ = t; }
   uint64_t getTime(void) const { return time_; }
};

////////////////////////////////////////////////////////////////////////////////
struct ParsedTxIn
{
   OutPointRef opRef_;
   BinaryData scrAddr_;
   uint64_t value_ = UINT64_MAX;

public:
   bool isResolved(void) const;
};

////////////////////////////////////////////////////////////////////////////////
struct ParsedTxOut
{
   BinaryData scrAddr_;
   uint64_t value_ = UINT64_MAX;

   size_t offset_;
   size_t len_;

   bool isInitialized(void) const
   {
      return scrAddr_.getSize() != 0 && value_ != UINT64_MAX; \
   }
};

////////////////////////////////////////////////////////////////////////////////
class ParsedTx
{
private:
   mutable BinaryData txHash_;
   const BinaryData zcKey_;

public:
   Tx tx_;
   std::vector<ParsedTxIn> inputs_;
   std::vector<ParsedTxOut> outputs_;
   ParsedTxStatus state_ = ParsedTxStatus::Uninitialized;
   bool isRBF_ = false;
   bool isChainedZc_ = false;

public:
   ParsedTx(BinaryData& key) :
      zcKey_(std::move(key))
   {
      //set zc index in Tx object
      BinaryRefReader brr(zcKey_.getRef());
      brr.advance(2);
      tx_.setTxIndex(brr.get_uint32_t(BE));
   }

   ParsedTxStatus status(void) const { return state_; }
   bool isResolved(void) const;
   void resetInputResolution(InputResolution);

   const BinaryData& getTxHash(void) const;
   void setTxHash(const BinaryData& hash) { txHash_ = hash; }
   BinaryDataRef getKeyRef(void) const { return zcKey_.getRef(); }
   const BinaryData& getKey(void) const { return zcKey_; }
};

////////////////////////////////////////////////////////////////////////////////
struct FilteredZeroConfData
{
   std::map<BinaryData, std::map<BinaryData, std::shared_ptr<TxIOPair>>> scrAddrTxioMap_;
   std::map<BinaryDataRef, std::map<unsigned, BinaryDataRef>> outPointsSpentByKey_;
   std::set<BinaryData> txOutsSpentByZC_;
   std::map<BinaryDataRef, std::shared_ptr<std::set<BinaryDataRef>>> keyToSpentScrAddr_;
   std::map<BinaryDataRef, std::set<BinaryDataRef>> keyToFundedScrAddr_;

   std::map<std::string, ParsedZCData> flaggedBDVs_;

   std::shared_ptr<ParsedTx> txPtr_;

   bool isEmpty(void) const { return scrAddrTxioMap_.size() == 0; }
   bool isValid(void) const;
};

////////////////////////////////////////////////////////////////////////////////
void preprocessTx(ParsedTx&, LMDBBlockDatabase*);
void preprocessZcMap(
   std::map<BinaryDataRef, std::shared_ptr<ParsedTx>>&,
   LMDBBlockDatabase*);

////////////////////////////////////////////////////////////////////////////////
class ZeroConfSharedStateSnapshot
{
private:
   /*
   blockHeight:
      uint32_t
   dupId:
      uint8_t

   txId:
      uint16_t
   outputId:
      uint16_t

   zcId:
      uint32_t

   zcTag:
      0xFFFF

   ------

   blockKey:
      [blockHeight (BE) << 8 | dupId] (4 bytes)

   txKey:
      [blockKey | txId (BE)] (6 bytes)

   zcKey:
      [zcTag | zcId (BE)] (6 bytes)

   txOutKey:
      [zcKey/txKey | outputId (BE)] (8 bytes)
   */

   std::map<BinaryDataRef, BinaryDataRef> txHashToDBKey_; //<txHash, zcKey>
   std::map<BinaryDataRef, std::shared_ptr<ParsedTx>> txMap_; //<zcKey, zcTx>
   std::set<BinaryData> txOutsSpentByZC_; //<txOutKey>

   //<scrAddr, <txOutKey>>
   std::map<BinaryData, std::set<BinaryData>> scrAddrMap_;

   //<zcKey/txKey, <outputId, txio>>
   std::map<BinaryData, std::map<uint16_t, std::shared_ptr<TxIOPair>>> txioMap_;

private:
   std::shared_ptr<ParsedTx> getTxByKey_NoConst(BinaryDataRef) const;

   std::set<BinaryData> findChildren(BinaryDataRef);
   void dropFromScrAddrMap(BinaryDataRef, BinaryDataRef);

public:
   static std::shared_ptr<ZeroConfSharedStateSnapshot> copy(
      std::shared_ptr<ZeroConfSharedStateSnapshot> obj)
   {
      auto ss = std::make_shared<ZeroConfSharedStateSnapshot>();
      if (obj != nullptr)
      {
         ss->txHashToDBKey_ = obj->txHashToDBKey_;
         ss->txMap_ = obj->txMap_;
         ss->txOutsSpentByZC_ = obj->txOutsSpentByZC_;
         ss->txioMap_ = obj->txioMap_;
         ss->scrAddrMap_ = obj->scrAddrMap_;
      }

      return ss;
   }

   const std::set<BinaryData>& getTxioKeysForScrAddr(BinaryDataRef) const;
   std::map<BinaryDataRef, std::shared_ptr<const TxIOPair>>
      getTxioMapForScrAddr(BinaryDataRef) const;
   const std::map<uint16_t, std::shared_ptr<TxIOPair>>&
      getTxioMapForKey(BinaryDataRef) const;

   std::shared_ptr<const ParsedTx> getTxByKey(BinaryDataRef) const;
   std::shared_ptr<const ParsedTx> getTxByHash(BinaryDataRef) const;
   TxOut getTxOutCopy(BinaryDataRef, uint16_t) const;
   std::shared_ptr<const TxIOPair> getTxioByKey(BinaryDataRef) const;

   BinaryDataRef getKeyForHash(BinaryDataRef) const;
   BinaryDataRef getHashForKey(BinaryDataRef) const;

   uint32_t getTopZcID(void) const;
   bool hasHash(BinaryDataRef) const;
   bool isTxOutSpentByZC(BinaryDataRef) const;
   bool empty(void) const;

   void preprocessZcMap(LMDBBlockDatabase*);
   std::map<BinaryDataRef, std::shared_ptr<ParsedTx>> dropZc(BinaryDataRef);

   void stageNewZc(std::shared_ptr<ParsedTx>, const FilteredZeroConfData&);
};

#endif