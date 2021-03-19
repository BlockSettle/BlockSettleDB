////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ZeroConfUtils.h"
#include "ZeroConfNotifications.h"
#include "ScrAddrFilter.h"
#include "lmdb_wrapper.h"

using namespace std;
using namespace ArmoryConfig;

///////////////////////////////////////////////////////////////////////////////
void preprocessTx(ParsedTx& tx, LMDBBlockDatabase* db)
{
   /*
   Resolves mined outpoints and sets reference fields.
   
   exhaustiveSearch affects the txhash resolution process. This argument has
   no effect in supernode.
    - false: check narrow set of hashes from known wallet's transaction
    - true: resolve hash through txhint db
   */
   auto& txHash = tx.getTxHash();
   auto&& txref = db->getTxRef(txHash);

   if (txref.isInitialized())
   {
      tx.state_ = ParsedTxStatus::Mined;
      return;
   }

   uint8_t const * txStartPtr = tx.tx_.getPtr();
   unsigned len = tx.tx_.getSize();

   auto nTxIn = tx.tx_.getNumTxIn();
   auto nTxOut = tx.tx_.getNumTxOut();

   //try to resolve as many outpoints as we can. unresolved outpoints are 
   //either invalid or (most likely) children of unconfirmed transactions
   if (nTxIn != tx.inputs_.size())
   {
      tx.inputs_.clear();
      tx.inputs_.resize(nTxIn);
   }

   if (nTxOut != tx.outputs_.size())
   {
      tx.outputs_.clear();
      tx.outputs_.resize(nTxOut);
   }

   for (uint32_t iin = 0; iin < nTxIn; iin++)
   {
      auto& txIn = tx.inputs_[iin];
      if (txIn.isResolved())
         continue;

      auto& opRef = txIn.opRef_;

      if (!opRef.isInitialized())
      {
         auto offset = tx.tx_.getTxInOffset(iin);
         if (offset > len)
            throw runtime_error("invalid txin offset");
         BinaryDataRef inputDataRef(txStartPtr + offset, len - offset);
         opRef.unserialize(inputDataRef);
      }

      if (!opRef.isResolved())
      {
         //resolve outpoint to dbkey
         txIn.opRef_.resolveDbKey(db);
         if (!opRef.isResolved())
            continue;
      }

      //grab txout
      StoredTxOut stxOut;
      if (!db->getStoredTxOut(stxOut, opRef.getDbKey()))
         continue;

      if (DBSettings::getDbType() == ARMORY_DB_SUPER)
         opRef.getDbKey() = stxOut.getDBKey(false);

      if (stxOut.isSpent())
      {
         tx.state_ = ParsedTxStatus::Invalid;
         return;
      }

      //set txin address and value
      txIn.scrAddr_ = stxOut.getScrAddress();
      txIn.value_ = stxOut.getValue();
   }

   for (uint32_t iout = 0; iout < nTxOut; iout++)
   {
      auto& txOut = tx.outputs_[iout];
      if (txOut.isInitialized())
         continue;

      auto offset = tx.tx_.getTxOutOffset(iout);
      auto len = tx.tx_.getTxOutOffset(iout + 1) - offset;

      BinaryRefReader brr(txStartPtr + offset, len);
      txOut.value_ = brr.get_uint64_t();

      auto scriptLen = brr.get_var_int();
      auto scriptRef = brr.get_BinaryDataRef(scriptLen);
      txOut.scrAddr_ = move(BtcUtils::getTxOutScrAddr(scriptRef));

      txOut.offset_ = offset;
      txOut.len_ = len;
   }

   tx.isRBF_ = tx.tx_.isRBF();


   bool txInResolved = true;
   for (auto& txin : tx.inputs_)
   {
      if (txin.isResolved())
         continue;

      txInResolved = false;
      break;
   }

   if (!txInResolved)
      tx.state_ = ParsedTxStatus::Unresolved;
   else
      tx.state_ = ParsedTxStatus::Resolved;
}

///////////////////////////////////////////////////////////////////////////////
void preprocessZcMap(
   map<BinaryDataRef, shared_ptr<ParsedTx>>& zcMap,
   LMDBBlockDatabase* db)
{
   //run threads to preprocess the zcMap
   auto counter = make_shared<atomic<unsigned>>();
   counter->store(0, memory_order_relaxed);

   vector<shared_ptr<ParsedTx>> txVec;
   txVec.reserve(zcMap.size());
   for (auto& txPair : zcMap)
      txVec.push_back(txPair.second);

   auto parserLdb = [db, &txVec, counter](void)->void
   {
      while (1)
      {
         auto id = counter->fetch_add(1, memory_order_relaxed);
         if (id >= txVec.size())
            return;

         auto txIter = txVec.begin() + id;
         preprocessTx(*(*txIter), db);
      }
   };

   vector<thread> parserThreads;
   for (unsigned i = 1; i < thread::hardware_concurrency(); i++)
      parserThreads.push_back(thread(parserLdb));
   parserLdb();

   for (auto& thr : parserThreads)
   {
      if (thr.joinable())
         thr.join();
   }
}

///////////////////////////////////////////////////////////////////////////////
void finalizeParsedTxResolution(
   shared_ptr<ParsedTx> parsedTxPtr,
   LMDBBlockDatabase* db, const set<BinaryData>& allZcHashes,
   shared_ptr<ZeroConfSharedStateSnapshot> ss)
{
   auto& parsedTx = *parsedTxPtr;
   bool isRBF = parsedTx.isRBF_;
   bool isChained = parsedTx.isChainedZc_;

   //if parsedTx has unresolved outpoint, they are most likely ZC
   for (auto& input : parsedTx.inputs_)
   {
      if (input.isResolved())
      {
         //check resolved key is valid
         if (input.opRef_.isZc())
         {
            isChained = true;
            auto chainedZC = ss->getTxByKey(input.opRef_.getDbTxKeyRef());
            if (chainedZC == nullptr)
            {
               parsedTx.state_ = ParsedTxStatus::Invalid;
               return;
            }
            else if (chainedZC->status() == ParsedTxStatus::Invalid)
            {
               throw runtime_error("invalid parent zc");
            }
         }
         else
         {
            auto&& keyRef = input.opRef_.getDbKey().getSliceRef(0, 4);
            auto height = DBUtils::hgtxToHeight(keyRef);
            auto dupId = DBUtils::hgtxToDupID(keyRef);

            if (db->getValidDupIDForHeight(height) != dupId)
            {
               parsedTx.state_ = ParsedTxStatus::Invalid;
               return;
            }
         }

         continue;
      }

      auto& opZcKey = input.opRef_.getDbKey();
      opZcKey = ss->getKeyForHash(input.opRef_.getTxHashRef());
      if (opZcKey.empty())
      {
         if (DBSettings::getDbType() == ARMORY_DB_SUPER ||
            allZcHashes.find(input.opRef_.getTxHashRef()) == allZcHashes.end())
            continue;
      }

      isChained = true;

      auto chainedZC = ss->getTxByKey(opZcKey);
      if (chainedZC == nullptr)
         continue;

      //NOTE: avoid the copy
      auto chainedTxOut = chainedZC->tx_.getTxOutCopy(input.opRef_.getIndex());

      input.value_ = chainedTxOut.getValue();
      input.scrAddr_ = chainedTxOut.getScrAddressStr();
      isRBF |= chainedZC->tx_.isRBF();
      input.opRef_.setTime(chainedZC->tx_.getTxTime());

      opZcKey.append(WRITE_UINT16_BE(input.opRef_.getIndex()));
   }

   //check & update resolution state
   if (parsedTx.state_ != ParsedTxStatus::Resolved)
   {
      bool isResolved = true;
      for (auto& input : parsedTx.inputs_)
      {
         if (!input.isResolved())
         {
            isResolved = false;
            break;
         }
      }

      if (isResolved)
         parsedTx.state_ = ParsedTxStatus::Resolved;
   }

   parsedTx.isRBF_ = isRBF;
   parsedTx.isChainedZc_ = isChained;
}

///////////////////////////////////////////////////////////////////////////////
FilteredZeroConfData filterParsedTx(
   shared_ptr<ParsedTx> parsedTxPtr,
   shared_ptr<const map<BinaryDataRef, shared_ptr<AddrAndHash>>> mainAddressMap,
   ZeroConfCallbacks* bdvCallbacks)
{
   auto& parsedTx = *parsedTxPtr;
   auto zcKey = parsedTxPtr->getKeyRef();

   FilteredZeroConfData result; 
   result.txPtr_ = parsedTxPtr;
   auto& txHash = parsedTx.getTxHash();

   auto filter = [mainAddressMap, bdvCallbacks]
      (const BinaryData& addr)->pair<bool, set<string>>
   {
      pair<bool, set<string>> flaggedBDVs;
      flaggedBDVs.first = false;

      
      //Check if this address is being watched before looking for specific BDVs
      auto addrIter = mainAddressMap->find(addr.getRef());
      if (addrIter == mainAddressMap->end())
      {
         if (DBSettings::getDbType() == ARMORY_DB_SUPER)
         {
            /*
            We got this far because no BDV is watching this address and the DB
            is running as a supernode. In supernode we track all ZC regardless 
            of watch status. Flag as true to process the ZC, but do not attach
            a bdv ID as no clients will be notified of this zc.
            */
            flaggedBDVs.first = true;
         }

         return flaggedBDVs;
      }

      flaggedBDVs.first = true;
      flaggedBDVs.second = bdvCallbacks->hasScrAddr(addr.getRef());
      return flaggedBDVs;
   };

   auto insertNewZc = [&result](const BinaryData& sa,
      BinaryData txiokey, shared_ptr<TxIOPair> txio,
      set<string> flaggedBDVs, bool consumesTxOut)->void
   {
      if (consumesTxOut)
         result.txOutsSpentByZC_.insert(txiokey);

      auto& key_txioPair = result.scrAddrTxioMap_[sa];
      key_txioPair[txiokey] = move(txio);

      for (auto& bdvId : flaggedBDVs)
         result.flaggedBDVs_[bdvId].scrAddrs_.insert(sa);
   };

   //spent txios
   unsigned iin = 0;
   for (auto& input : parsedTx.inputs_)
   {
      bool skipTxIn = false;
      auto inputId = iin++;
      if (!input.isResolved())
      {
         if (DBSettings::getDbType() == ARMORY_DB_SUPER)
         {
            parsedTx.state_ = ParsedTxStatus::Invalid;
            return result;
         }
         else
         {
            parsedTx.state_ = ParsedTxStatus::ResolveAgain;
         }

         skipTxIn = true;
      }

      //keep track of all outputs this ZC consumes
      auto& id_map = result.outPointsSpentByKey_[input.opRef_.getTxHashRef()];
      id_map.insert(make_pair(input.opRef_.getIndex(), zcKey));

      if (skipTxIn)
         continue;

      auto&& flaggedBDVs = filter(input.scrAddr_);
      if (!parsedTx.isChainedZc_ && !flaggedBDVs.first)
         continue;

      auto txio = make_shared<TxIOPair>(
         TxRef(input.opRef_.getDbTxKeyRef()), input.opRef_.getIndex(),
         TxRef(zcKey), inputId);

      txio->setTxHashOfOutput(input.opRef_.getTxHashRef());
      txio->setTxHashOfInput(txHash);
      txio->setValue(input.value_);
      auto tx_time = input.opRef_.getTime();
      if (tx_time == UINT64_MAX)
         tx_time = parsedTx.tx_.getTxTime();
      txio->setTxTime(tx_time);
      txio->setRBF(parsedTx.isRBF_);
      txio->setChained(parsedTx.isChainedZc_);

      auto&& txioKey = txio->getDBKeyOfOutput();
      insertNewZc(input.scrAddr_, move(txioKey), move(txio),
         move(flaggedBDVs.second), true);

      auto& updateSet = result.keyToSpentScrAddr_[zcKey];
      if (updateSet == nullptr)
         updateSet = make_shared<set<BinaryDataRef>>();
      updateSet->insert(input.scrAddr_.getRef());
   }

   //funded txios
   unsigned iout = 0;
   for (auto& output : parsedTx.outputs_)
   {
      auto outputId = iout++;

      auto&& flaggedBDVs = filter(output.scrAddr_);
      if (flaggedBDVs.first)
      {
         auto txio = make_shared<TxIOPair>(TxRef(zcKey), outputId);

         txio->setValue(output.value_);
         txio->setTxHashOfOutput(txHash);
         txio->setTxTime(parsedTx.tx_.getTxTime());
         txio->setUTXO(true);
         txio->setRBF(parsedTx.isRBF_);
         txio->setChained(parsedTx.isChainedZc_);

         auto& fundedScrAddr = result.keyToFundedScrAddr_[zcKey];
         fundedScrAddr.insert(output.scrAddr_.getRef());

         auto&& txioKey = txio->getDBKeyOfOutput();
         insertNewZc(output.scrAddr_, move(txioKey),
            move(txio), move(flaggedBDVs.second), false);
      }
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
//
// FilteredZeroConfData
//
////////////////////////////////////////////////////////////////////////////////
bool FilteredZeroConfData::isValid() const
{
   if (txPtr_ == nullptr)
      return false;

   switch (DBSettings::getDbType())
   {
   case ARMORY_DB_SUPER:
      return txPtr_->status() == ParsedTxStatus::Resolved && !isEmpty();

   case ARMORY_DB_FULL:
   case ARMORY_DB_BARE:
   {
      if (txPtr_->status() == ParsedTxStatus::Invalid ||
         txPtr_->status() == ParsedTxStatus::Mined ||
         txPtr_->status() == ParsedTxStatus::Unresolved)
      {
         return false;
      }

      return !isEmpty();
   }

   default:
      return false;
   }
}

////////////////////////////////////////////////////////////////////////////////
//
// OutPointRef
//
////////////////////////////////////////////////////////////////////////////////
void OutPointRef::unserialize(uint8_t const * ptr, uint32_t remaining)
{
   if (remaining < 36)
      throw runtime_error("ptr is too short to be an outpoint");

   BinaryDataRef bdr(ptr, remaining);
   BinaryRefReader brr(bdr);

   txHash_ = brr.get_BinaryDataRef(32);
   txOutIndex_ = brr.get_uint32_t();
}

////////////////////////////////////////////////////////////////////////////////
void OutPointRef::unserialize(BinaryDataRef bdr)
{
   unserialize(bdr.getPtr(), bdr.getSize());
}

////////////////////////////////////////////////////////////////////////////////
void OutPointRef::resolveDbKey(LMDBBlockDatabase *dbPtr)
{
   if (txHash_.getSize() == 0 || txOutIndex_ == UINT16_MAX)
      throw runtime_error("empty outpoint hash");

   auto key = dbPtr->getDBKeyForHash(txHash_);
   if (key.getSize() != 6)
      return;

   setDbKey(key);
}

////////////////////////////////////////////////////////////////////////////////
void OutPointRef::setDbKey(const BinaryData& key)
{
   BinaryWriter bw;
   bw.put_BinaryData(key);
   bw.put_uint16_t(txOutIndex_, BE);

   dbKey_ = bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef OutPointRef::getDbTxKeyRef() const
{
   if (!isResolved())
      throw runtime_error("unresolved outpoint key");

   return dbKey_.getSliceRef(0, 6);
}

////////////////////////////////////////////////////////////////////////////////
bool OutPointRef::isInitialized() const
{
   return txHash_.getSize() == 32 && txOutIndex_ != UINT16_MAX;
}

////////////////////////////////////////////////////////////////////////////////
void OutPointRef::reset(InputResolution mode)
{
   if (mode != InputResolution::Both)
   {
      if (isZc() && mode == InputResolution::Mined)
         return;
   }

   dbKey_.clear();
   time_ = UINT64_MAX;
}

////////////////////////////////////////////////////////////////////////////////
bool OutPointRef::isZc() const
{
   if (!isResolved())
      return false;

   return dbKey_.startsWith(DBUtils::ZeroConfHeader_);
}

////////////////////////////////////////////////////////////////////////////////
//
// ParsedTxIn
//
////////////////////////////////////////////////////////////////////////////////
bool ParsedTxIn::isResolved() const
{
   if (!opRef_.isResolved())
      return false;

   if (scrAddr_.getSize() == 0 || value_ == UINT64_MAX)
      return false;

   return true;
}

////////////////////////////////////////////////////////////////////////////////
//
// ParsedTx
//
////////////////////////////////////////////////////////////////////////////////
bool ParsedTx::isResolved() const
{
   if (state_ == ParsedTxStatus::Uninitialized)
      return false;

   if (!tx_.isInitialized())
      return false;

   if (inputs_.size() != tx_.getNumTxIn() ||
      outputs_.size() != tx_.getNumTxOut())
      return false;

   for (auto& input : inputs_)
   {
      if (!input.isResolved())
         return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
void ParsedTx::resetInputResolution(InputResolution mode)
{
   for (auto& input : inputs_)
      input.opRef_.reset(mode);

   if (mode != InputResolution::Mined)
      tx_.setChainedZC(false);

   state_ = ParsedTxStatus::Uninitialized;
   isRBF_ = false;
   isChainedZc_ = false;
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& ParsedTx::getTxHash(void) const
{
   if (txHash_.getSize() == 0)
      txHash_ = move(tx_.getThisHash());
   return txHash_;
}

///////////////////////////////////////////////////////////////////////////////
//
// ZeroConfSharedStateSnapshot
//
///////////////////////////////////////////////////////////////////////////////
void ZeroConfSharedStateSnapshot::preprocessZcMap(LMDBBlockDatabase* db)
{
   ::preprocessZcMap(txMap_, db);
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<ParsedTx> ZeroConfSharedStateSnapshot::getTxByKey_NoConst(
   BinaryDataRef key) const
{
   auto iter = txMap_.find(key);
   if (iter == txMap_.end())
      return nullptr;

   return iter->second;
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<const ParsedTx> ZeroConfSharedStateSnapshot::getTxByKey(
   BinaryDataRef key) const
{
   auto txPtr = getTxByKey_NoConst(key);
   return const_pointer_cast<const ParsedTx>(txPtr);
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<const ParsedTx> ZeroConfSharedStateSnapshot::getTxByHash(
   BinaryDataRef hash) const
{
   auto key = getKeyForHash(hash);
   if (key.empty())
      return nullptr;

   return getTxByKey(key);
}

///////////////////////////////////////////////////////////////////////////////
TxOut ZeroConfSharedStateSnapshot::getTxOutCopy(
   BinaryDataRef key, uint16_t outputId) const
{
   auto txPtr = getTxByKey(key);
   if (txPtr == nullptr)
      throw range_error("invalid zc key");

   if (outputId >= txPtr->outputs_.size())
      throw range_error("invalid output id");

   return txPtr->tx_.getTxOutCopy(outputId);
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<const TxIOPair> ZeroConfSharedStateSnapshot::getTxioByKey(
   BinaryDataRef txioKey) const
{
   //extract zcKey
   BinaryRefReader brr(txioKey);
   auto zcKey = brr.get_BinaryDataRef(6);
   auto zcIter = txioMap_.find(zcKey);
   if (zcIter == txioMap_.end())
   {
      LOGERR << "missing zc for scraddr";
      return nullptr;
   }

   //and output id
   auto outputId = brr.get_uint16_t(BE);
   auto txioIter = zcIter->second.find(outputId);
   if (txioIter == zcIter->second.end())
   {
      LOGERR << "missing txio for scraddr";
      return nullptr;
   }

   return const_pointer_cast<TxIOPair>(txioIter->second);
}

///////////////////////////////////////////////////////////////////////////////
BinaryDataRef ZeroConfSharedStateSnapshot::getKeyForHash(
   BinaryDataRef hash) const
{
   auto iter = txHashToDBKey_.find(hash);
   if (iter == txHashToDBKey_.end())
      return {};

   return iter->second;
}

///////////////////////////////////////////////////////////////////////////////
BinaryDataRef ZeroConfSharedStateSnapshot::getHashForKey(
   BinaryDataRef key) const
{
   auto iter = txMap_.find(key);
   if (iter == txMap_.end())
      return BinaryDataRef();

   return iter->second->getTxHash().getRef();
}

///////////////////////////////////////////////////////////////////////////////
uint32_t ZeroConfSharedStateSnapshot::getTopZcID(void) const
{
   uint32_t topID = 0;
   auto rIter = txMap_.rbegin();
   if (rIter != txMap_.rend())
   {
      BinaryRefReader brr(rIter->first);
      brr.advance(2);
      topID = brr.get_uint32_t(BE);
   }

   return topID;
}

///////////////////////////////////////////////////////////////////////////////
bool ZeroConfSharedStateSnapshot::hasHash(BinaryDataRef hash) const
{
   auto iter = txHashToDBKey_.find(hash);
   return iter != txHashToDBKey_.end();
}

///////////////////////////////////////////////////////////////////////////////
bool ZeroConfSharedStateSnapshot::isTxOutSpentByZC(BinaryDataRef key) const
{
   auto iter = txOutsSpentByZC_.find(key);
   return iter != txOutsSpentByZC_.end();
}

///////////////////////////////////////////////////////////////////////////////
bool ZeroConfSharedStateSnapshot::empty(void) const
{
   return txMap_.empty();
}

///////////////////////////////////////////////////////////////////////////////
const set<BinaryData>& ZeroConfSharedStateSnapshot::getTxioKeysForScrAddr(
   BinaryDataRef scrAddr) const
{
   auto keyIter = scrAddrMap_.find(scrAddr);
   if (keyIter == scrAddrMap_.end())
      throw range_error("");

   return keyIter->second;
}

///////////////////////////////////////////////////////////////////////////////
map<BinaryDataRef, shared_ptr<const TxIOPair>> 
   ZeroConfSharedStateSnapshot::getTxioMapForScrAddr(
      BinaryDataRef scrAddr) const
{
   auto keyIter = scrAddrMap_.find(scrAddr);
   if (keyIter == scrAddrMap_.end())
      return {};

   map<BinaryDataRef, shared_ptr<const TxIOPair>> result;

   for (const auto& txioKey : keyIter->second)
   {
      auto txioPtr = getTxioByKey(txioKey);
      if (txioPtr == nullptr)
         continue;

      result.emplace(txioKey.getRef(), txioPtr);
   }

   return result;
}

///////////////////////////////////////////////////////////////////////////////
const map<uint16_t, shared_ptr<TxIOPair>>& 
   ZeroConfSharedStateSnapshot::getTxioMapForKey(BinaryDataRef key) const
{
   auto iter = txioMap_.find(key);
   if (iter == txioMap_.end())
      throw range_error("");

   return iter->second;
}

///////////////////////////////////////////////////////////////////////////////
void ZeroConfSharedStateSnapshot::dropFromScrAddrMap(
   BinaryDataRef scrAddr, BinaryDataRef zcKey)
{
   //this scrAddr is funded by outputs from this zc, remove them
   auto saIter = scrAddrMap_.find(scrAddr);
   if (saIter == scrAddrMap_.end())
      return;

   //look for txio keys belonging to our zc
   auto& txioKeySet = saIter->second;
   auto keyIter = txioKeySet.lower_bound(zcKey);

   while (keyIter != txioKeySet.end())
   {
      if (!keyIter->startsWith(zcKey))
         break;

      //remove all entries that begin with our zcKey
      txioKeySet.erase(keyIter++);
   }

   //remove the scrAddr if not ZC affects it anymore
   if (txioKeySet.empty())
      scrAddrMap_.erase(saIter);
}

///////////////////////////////////////////////////////////////////////////////
set<BinaryData> ZeroConfSharedStateSnapshot::findChildren(BinaryDataRef zcKey)
{
   //find the set of outputs created by this zc
   auto txioMapIter = txioMap_.find(zcKey);
   if (txioMapIter == txioMap_.end())
      return {};

   //set zcKeys of all ZC spending from our parent
   set<BinaryData> children;

   //look for ZCs spending from these outputs
   for (const auto& txioPair : txioMapIter->second)
   {
      //skip if this txio doesn't carry a txin (txout isn't spent)
      if (!txioPair.second->hasTxIn())
         continue;

      //grab the txin's TxRef object
      auto spenderRef = txioPair.second->getTxRefOfInput();

      //save the Tx key (key of the txin's owner)
      children.emplace(spenderRef.getDBKey());
   }

   return children;
}

///////////////////////////////////////////////////////////////////////////////
map<BinaryDataRef, std::shared_ptr<ParsedTx>> 
   ZeroConfSharedStateSnapshot::dropZc(BinaryDataRef zcKey)
{
   auto txPtr = getTxByKey_NoConst(zcKey);
   if (txPtr == nullptr)
      return {};

   std::set<BinaryData> spentFromTxoutKeys;
   map<BinaryDataRef, shared_ptr<ParsedTx>> droppedZc;

   //drop from spent set
   for (auto& input : txPtr->inputs_)
   {
      if (!input.isResolved())
         continue;
      txOutsSpentByZC_.erase(input.opRef_.getDbKey());
      spentFromTxoutKeys.emplace(input.opRef_.getDbKey());

      //do not purge input keys from scrAddr map unless they're mined
      if (input.opRef_.getDbKey().startsWith(DBUtils::ZeroConfHeader_))
         continue;
      dropFromScrAddrMap(input.scrAddr_, input.opRef_.getDbKey());
   }

   /*
   Find the children and drop them. A child evicted as a consequence
   of the parent's invalidation isn't necessarely invalid too, 
   the parent may just have been mined.

   Make sure eviction is followed by reparsing. The cost to reparse
   isn't so dire as to justify the complexity of changing txin 
   resolution on the fly only for the children.

   NOTE #1: the child purging atm is recursive and exhaustive. It could
   be improved if the reason for the eviction is specified: ZCs that
   are mined do not need their entire descendancy evicted from the mempool, 
   only the direct descendants need reparsed to point to the mined output
   instead of the unconfirmed ones.

   NOTE #2: the full reparsing of children will trigger undesirable
   ZC notifications, these should be suppressed. Only final eviction
   from the mempool should be notified to the BDV objects, on all
   occasions.
   */
   auto children = findChildren(zcKey);
   for (auto& child : children)
   {
      auto droppedTx = dropZc(child);
      droppedZc.insert(droppedTx.begin(), droppedTx.end());
   }

   //drop outputs from scrAddrMap
   for (auto& output : txPtr->outputs_)
      dropFromScrAddrMap(output.scrAddr_, zcKey);

   /*
   Drop all txios this ZC created (where our tx holds the txout)
   */
   txioMap_.erase(zcKey);

   /*
   Drop all spending from other txios (where our tx holds the txin)
   */
   for (auto& spentTxoutKey : spentFromTxoutKeys)
   {
      //look the spendee by key
      BinaryRefReader brr(spentTxoutKey.getRef());
      auto spentFromZcKey = brr.get_BinaryDataRef(6);
      auto zcIter = txioMap_.find(spentFromZcKey);
      if (zcIter == txioMap_.end())
         continue;

      //and output id
      auto outputId = brr.get_uint16_t(BE);
      auto txioIter = zcIter->second.find(outputId);
      if (txioIter == zcIter->second.end())
         continue;

      //does this txio have a spender and is it our tx?
      if (!txioIter->second->hasTxIn() ||
         txioIter->second->getTxRefOfInput().getDBKeyRef() != zcKey)
         continue;

      if (!txioIter->second->hasTxOutZC())
      {
         //if the txout is mined, remove it entirely
         zcIter->second.erase(txioIter);
      }
      else
      {
         /*
         copy the txio, remove the txin and replace it in the map
         (so as to not disrupt the potential readers)
         */
         auto newTxio = make_shared<TxIOPair>(*(txioIter->second));
         newTxio->setTxIn(BinaryData());
         txioIter->second = newTxio;
      }

      //if this tx is not affected by any zc anymore, remove it
      if (zcIter->second.empty())
         txioMap_.erase(zcIter);
   }

   //drop hash
   txHashToDBKey_.erase(txPtr->getTxHash().getRef());

   //delete tx
   txMap_.erase(zcKey);

   //save this tx as dropped from the mempool and return
   droppedZc.emplace(txPtr->getKeyRef(), txPtr);
   return droppedZc;
}

///////////////////////////////////////////////////////////////////////////////
void ZeroConfSharedStateSnapshot::stageNewZc(
   shared_ptr<ParsedTx> zcPtr, const FilteredZeroConfData& filteredData)
{
   const auto& dbKey = zcPtr->getKey();
   const auto& txHash = zcPtr->getTxHash();

   //set tx and hash to key entry
   txHashToDBKey_[txHash.getRef()] = dbKey.getRef();
   txMap_[dbKey.getRef()] = zcPtr;

   //merge spent outpoints
   txOutsSpentByZC_.insert(
      filteredData.txOutsSpentByZC_.begin(),
      filteredData.txOutsSpentByZC_.end());

   //updated txio and scraddr maps
   for (auto& saTxios : filteredData.scrAddrTxioMap_)
   {
      auto& keySet = scrAddrMap_[saTxios.first];
      for (auto& txioPair : saTxios.second)
      {
         //add the txioKey to the affect scrAddr
         keySet.emplace(txioPair.first);

         //break down txioKey into txKey and outputId
         BinaryRefReader keyReader(txioPair.first);
         auto txKeyRef = keyReader.get_BinaryDataRef(6);
         auto outputId = keyReader.get_uint16_t(BE);

         //get the txio map for this txKey
         auto& txiomap = txioMap_[txKeyRef];

         //set the txio for this outputId, override existing data
         txiomap[outputId] = txioPair.second;
      }
   }
}
