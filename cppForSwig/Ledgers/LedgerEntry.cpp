////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2015, Armory Technologies, Inc.                        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE-ATI or http://www.gnu.org/licenses/agpl.html                  //
//                                                                            //
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////
#include <algorithm>
#include <cstring>

#include "LedgerEntry.h"
#include <Utils/DBUtils.h>
#include <Utils/BtcUtils.h>
#include <BlockchainDatabase/txio.h>
#include <BlockchainDatabase/lmdb_wrapper.h>
#include <ZeroConf/Utils.h>
#include <ZeroConf/Parser.h>

using namespace Armory;

////////////////////////////////////////////////////////////////////////////////
// LedgerEntry
LedgerEntry::LedgerEntry(const std::string& ID,
   int64_t val, uint32_t blkNum, const BinaryData& txHash,
   uint32_t idx, uint32_t txtime,
   bool isCoinbase, bool isToSelf, bool isChange,
   bool isOptInRBF, bool usesWitness, bool isChainedZC) :
   ID_(ID), value_(val), blockNum_(blkNum),
   txHash_(txHash), index_(idx), txTime_(txtime),
   isCoinbase_(isCoinbase), isSentToSelf_(isToSelf), isChangeBack_(isChange),
   isOptInRBF_(isOptInRBF), usesWitness_(usesWitness), isChainedZC_(isChainedZC)
{}

////////
std::string LedgerEntry::getWalletID() const
{
   return ID_;
}

const std::set<BinaryData>& LedgerEntry::getScrAddrList() const
{
   return scrAddrSet_;
}

void LedgerEntry::setScrAddrList(std::set<BinaryData>& addrList)
{
   scrAddrSet_ = std::move(addrList);
}

int64_t LedgerEntry::getValue() const
{
   return value_;
}

uint32_t LedgerEntry::getBlockNum() const
{
   return blockNum_;
}
const BinaryData& LedgerEntry::getTxHash() const
{
   return txHash_;
}

uint32_t LedgerEntry::getIndex() const
{
   return index_;
}

uint32_t LedgerEntry::getTxTime() const
{
   return txTime_;
}

bool LedgerEntry::isCoinbase() const
{
   return isCoinbase_;
}

bool LedgerEntry::isSentToSelf() const
{
   return isSentToSelf_;
}

bool LedgerEntry::isChangeBack() const
{
   return isChangeBack_;
}

bool LedgerEntry::isOptInRBF() const
{
   return isOptInRBF_;
}

bool LedgerEntry::usesWitness() const
{
   return usesWitness_;
}

bool LedgerEntry::isChainedZC() const
{
   return isChainedZC_;
}

////////
bool LedgerEntry::operator<(const LedgerEntry& le2) const
{
   if (blockNum_ != le2.blockNum_) {
      return blockNum_ < le2.blockNum_;
   } else if (index_ != le2.index_) {
      return index_ < le2.index_;
   } else {
      return false;
   }
}

bool LedgerEntry::operator==(const LedgerEntry& le2) const
{
   return (blockNum_ == le2.blockNum_ && index_ == le2.index_);
}

bool LedgerEntry::operator>(const LedgerEntry& le2) const
{
   if (blockNum_ != le2.blockNum_) {
      return blockNum_ > le2.blockNum_;
   } else if (index_ != le2.index_) {
      return index_ > le2.index_;
   } else {
      return false;
   }
}

Armory::ScriptPrefix LedgerEntry::getScriptType() const
{
   return (Armory::ScriptPrefix)ID_[0];
}

//////////////////////////////////////////////////////////////////////////////
void LedgerEntry::pprint()
{
   std::cout << "LedgerEntry: " << std::endl;
   std::cout << "   ID      : " << getWalletID() << std::endl;
   std::cout << "   Value   : " << getValue()/1e8 << std::endl;
   std::cout << "   BlkNum  : " << getBlockNum() << std::endl;
   std::cout << "   TxHash  : " <<
      getTxHash().copySwapEndian().toHexStr() << std::endl;
   std::cout << "   TxIndex : " << getIndex() << std::endl;
   std::cout << "   Coinbase: " << (isCoinbase() ? 1 : 0) << std::endl;
   std::cout << "   sentSelf: " << (isSentToSelf() ? 1 : 0) << std::endl;
   std::cout << "   isChange: " << (isChangeBack() ? 1 : 0) << std::endl;
   std::cout << "   isOptInRBF: " << (isOptInRBF() ? 1 : 0) << std::endl;
   for (const auto& addr : scrAddrSet_) {
      std::cout << "   scrAddr: " << addr.toHexStr() << std::endl;
   }
   std::cout << std::endl;
}

void LedgerEntry::pprintOneLine() const
{
   printf("   Addr:%s Tx:%s:%02d   BTC:%0.3f   Blk:%06d\n",
      "   ",
      getTxHash().getSliceCopy(0,8).toHexStr().c_str(),
      getIndex(),
      getValue()/1e8,
      getBlockNum()
   );
}

//////////////////////////////////////////////////////////////////////////////
void LedgerEntry::purgeLedgerMapFromHeight(
   std::map<BinaryData, LedgerEntry>& leMap, uint32_t purgeFrom)
{
   //Remove all entries starting this height, included.
   BinaryData cutOffHeight(6);
   auto heightPtr = cutOffHeight.getPtr();

   uint8_t* purgeFromPtr = reinterpret_cast<uint8_t*>(&purgeFrom);
   memset(heightPtr, 0, 6);
   heightPtr[0] = purgeFromPtr[2];
   heightPtr[1] = purgeFromPtr[1];
   heightPtr[2] = purgeFromPtr[0];

   auto cutOffIterPair = leMap.equal_range(cutOffHeight);
   leMap.erase(cutOffIterPair.first, leMap.end());
}

void LedgerEntry::purgeLedgerVectorFromHeight(
  std::vector<LedgerEntry>& leVec, uint32_t purgeFrom)
{
   //Remove all entries starting this height, included.
   uint32_t i = 0;
   std::sort(leVec.begin(), leVec.end());
   for (const auto& le : leVec) {
      if (le.getBlockNum() >= purgeFrom) {
         break;
      }
      i++;
   }
   leVec.erase(leVec.begin() + i, leVec.end());
}

//////////////////////////////////////////////////////////////////////////////
std::map<BinaryData, LedgerEntry> LedgerEntry::computeLedgerMap(
   const std::map<BinaryData, TxIOPair>& txioMap,
   uint32_t startBlock, uint32_t endBlock, const std::string& ID,
   const LMDBBlockDatabase* db, const Blockchain* bc,
   const Armory::ZeroConf::ZeroConfContainer* zc)
{
   using TxDbKey = BinaryDataRef;
   using TxnQueue = std::vector<const TxIOPair*>;
   std::map<TxDbKey, TxnQueue> txnTxIOMap;

   //arrange txios by transaction
   for (const auto& txio : txioMap) {
      //txout
      auto txOutDBKey = txio.second.getTxRefOfOutput().getDBKeyRef();
      auto txOutIter = txnTxIOMap.find(txOutDBKey);
      if (txOutIter == txnTxIOMap.end()) {
         txOutIter = txnTxIOMap.emplace(txOutDBKey, TxnQueue{}).first;
      }
      txOutIter->second.emplace_back(&txio.second);

      //txin
      if (!txio.second.hasTxIn()) {
         continue;
      }
      auto txInDBKey = txio.second.getTxRefOfInput().getDBKeyRef();
      auto txInIter = txnTxIOMap.find(txInDBKey);
      if (txInIter == txnTxIOMap.end()) {
         txInIter = txnTxIOMap.emplace(txInDBKey, TxnQueue{}).first;
      }
      txInIter->second.emplace_back(&txio.second);
   }

   //convert TxIO to ledgers
   auto ss = zc->getSnapshot();

   std::map<BinaryData, LedgerEntry> leMap;
   for (const auto& txioVec : txnTxIOMap) {
      //reset ledger variables
      BinaryData txHash;

      uint32_t blockNum;
      uint32_t txTime;
      uint16_t txIndex;

      std::set<BinaryData> scrAddrSet;

      bool isRBF = false;
      bool usesWitness = false;
      bool isChained = false;

      //grab iterator
      auto txioIter = txioVec.second.cbegin();

      //get txhash, block, txIndex and txtime
      bool isZc = txioVec.first.startsWith(DBUtils::ZCPrefix);
      if (!isZc) {
         blockNum = DBUtils::hgtxToHeight(txioVec.first.getSliceRef(0, 4));
         txIndex = READ_UINT16_BE(txioVec.first.getSliceRef(4, 2));
         txTime = bc->getHeaderByHeight(blockNum, 0xFF)->getTimestamp();
         txHash = db->getTxHashForLdbKey(txioVec.first);
      } else {
         blockNum = UINT32_MAX;
         txIndex = READ_UINT32_BE(txioVec.first.getSliceRef(2, 4));
         txTime = (*txioIter)->getTxTime();
         if (ss == nullptr) {
            LOGWARN << "zc txio without a snapshot!";
         } else {
            txHash = ss->getHashForKey(txioVec.first);
         }
      }

      if (blockNum < startBlock || blockNum > endBlock) {
         continue;
      }

      bool isCoinbase=false;
      int64_t value=0;
      int64_t valIn=0, valOut=0;
      uint32_t nTxInAreOurs = 0, nTxOutAreOurs = 0;

      while (txioIter != txioVec.second.cend()) {
         const auto& txio = *(*txioIter);
         if (blockNum == UINT32_MAX) {
            if (txio.isRBF()) {
               isRBF = true;
            }
            if (txio.getTxTime() > txTime) {
               txTime = txio.getTxTime();
            }
         }

         if (txio.getDBKeyOfOutput().startsWith(txioVec.first)) {
            isCoinbase |= txio.isFromCoinbase();
            valIn += txio.getValue();
            value += txio.getValue();
            nTxOutAreOurs++;
         }

         if (txio.hasTxIn() &&
            txio.getDBKeyOfInput().startsWith(txioVec.first)) {
            valOut -= txio.getValue();
            value -= txio.getValue();
            nTxInAreOurs++;

            if (txio.isChainedZC()) {
               isChained = true;
            }
         }

         scrAddrSet.emplace(txio.getScrAddr());
         ++txioIter;
      }

      bool isSentToSelf = false;
      bool isChangeBack = false;
      std::shared_ptr<const Armory::ZeroConf::ParsedTx> ptx;
      if (nTxInAreOurs * nTxOutAreOurs > 0) {
         //if some of the txins AND some of the txouts are ours, this could be an STS
         //pull the txn and compare the txin and txout counts

         uint32_t nTxOutInTx = UINT32_MAX;
         if (!isZc) {
            nTxOutInTx = db->getStxoCountForTx(txioVec.first.getSliceRef(0, 6));
         } else if (ss != nullptr) {
            //grab zc by key
            auto ptx = ss->getTxByKey(txioVec.first);
            if (ptx != nullptr) {
               nTxOutInTx = ptx->outputs.size();
            }
         }

         if (nTxOutInTx == nTxOutAreOurs) {
            value = valIn;
            isSentToSelf = true;
         }
      } else if (nTxInAreOurs != 0 && (valIn + valOut) < 0) {
         isChangeBack = true;
      }

      LedgerEntry le(ID,
         value,
         blockNum,
         txHash,
         txIndex,
         txTime,
         isCoinbase,
         isSentToSelf,
         isChangeBack,
         isRBF,
         usesWitness,
         isChained);

      /*
      When signing a tx online, the wallet knows the txhash, therefor it can register all
      comments on outgoing addresses under the txhash.

      When the tx is signed offline, there is no guarantee that the txhash will be known
      when the offline tx is crafted. Therefor the comments for each outgoing address are
      registered under that address only.

      In order for the GUI to be able to resolve outgoing address comments, the ledger entry
      needs to carry those for pay out transactions
      */

      if (value < 0) {
         if (!isZc) {
            try {
               //grab tx by key
               auto payout_tx = db->getFullTxCopy(txioVec.first);

               //get scrAddr for each txout
               for (unsigned i=0; i < payout_tx.getNumTxOut(); i++) {
                  auto txout = payout_tx.getTxOutCopy(i);
                  scrAddrSet.emplace(txout.getScrAddressStr());
               }
            } catch (const std::exception&) {
               LOGWARN << "no tx on record for txio " << txioVec.first.toHexStr();
            }
         } else if (ss != nullptr) {
            if (ptx == nullptr) {
               //grab zc by key if we haven't got it previously
               auto ptx = ss->getTxByKey(txioVec.first);
            }
            if (ptx == nullptr) {
               LOGWARN << "failed to get zc for ledger parsing";
            } else {
               for (const auto& txout : ptx->outputs) {
                  scrAddrSet.emplace(txout.scrAddr);
               }
            }
         } else {
            LOGWARN << "we have a zc txio but no snapshot =(";
         }
      }

      le.setScrAddrList(scrAddrSet);
      leMap.emplace(txioVec.first, std::move(le));
   }
   return leMap;
}

////////////////////////////////////////////////////////////////////////////////
// comparator
bool LedgerEntry_DescendingOrder::operator()(
   const LedgerEntry& a, const LedgerEntry& b) const
{
   return a > b;
}

////////////////////////////////////////////////////////////////////////////////
// LedgerDelegate
LedgerDelegate::LedgerDelegate(
   std::function<std::vector<LedgerEntry>(uint32_t)> getHist,
   std::function<uint32_t(uint32_t)> getBlock,
   std::function<uint32_t(uint32_t)> getPageId,
   std::function<uint32_t(void)> getPageCount) :
   getHistoryPage_(getHist),
   getBlockInVicinity_(getBlock),
   getPageIdForBlockHeight_(getPageId),
   getPageCount_(getPageCount)
{}

////////
std::vector<LedgerEntry> LedgerDelegate::getHistoryPage(uint32_t id)
{
   return getHistoryPage_(id);
}

uint32_t LedgerDelegate::getBlockInVicinity(uint32_t blk)
{
   return getBlockInVicinity_(blk);
}

uint32_t LedgerDelegate::getPageIdForBlockHeight(uint32_t blk)
{
   return getPageIdForBlockHeight_(blk);
}

uint32_t LedgerDelegate::getPageCount()
{
   return getPageCount_();
}
