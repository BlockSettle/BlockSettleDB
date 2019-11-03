////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "WalletFileInterface.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DBInterface
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
DBInterface::DBInterface(
   std::shared_ptr<LMDBEnv> dbEnv, const std::string& dbName) :
   dbEnv_(dbEnv), dbName_(dbName)
{
   auto tx = LMDBEnv::Transaction(dbEnv_.get(), LMDB::ReadWrite);
   db_.open(dbEnv_.get(), dbName_);
}

////////////////////////////////////////////////////////////////////////////////
DBInterface::~DBInterface()
{
   db_.close();
}

////////////////////////////////////////////////////////////////////////////////
void DBInterface::loadAllEntries()
{
   auto tx = LMDBEnv::Transaction(dbEnv_.get(), LMDB::ReadOnly);

   int prevDbKey = -1;
   auto iter = db_.begin();
   while (iter.isValid())
   {
      auto key_mval = iter.key();
      if (key_mval.mv_size != 4)
         throw WalletInterfaceException("invalid dbkey");

      auto val_mval = iter.value();

      BinaryDataRef key_bdr((const uint8_t*)key_mval.mv_data, key_mval.mv_size);
      BinaryDataRef val_bdr((const uint8_t*)val_mval.mv_data, val_mval.mv_size);

      //dbkeys should be consecutive integers
      int dbKeyInt = READ_UINT32_BE(key_bdr);
      if (dbKeyInt - prevDbKey != 1)
         throw WalletInterfaceException("db key gap");
      prevDbKey = dbKeyInt;

      BinaryRefReader brr(val_bdr);
      auto len = brr.get_var_int();
      auto&& dataKey = brr.get_BinaryData(len);
      len = brr.get_var_int();
      auto&& dataVal = brr.get_BinaryData(len);

      if (brr.getSizeRemaining() != 0)
         throw WalletInterfaceException("loose data entry");

      if (dataVal != BinaryData("erased"))
      {
         auto&& dataPair = make_pair(dataKey, move(dataVal));
         dataMap_.emplace(dataPair);

         auto&& keyPair = make_pair(move(dataKey), move(key_bdr.copy()));
         auto insertIter = dataKeyToDbKey_.emplace(keyPair);
         if (!insertIter.second)
            throw WalletInterfaceException("duplicated db entry");
      }

      iter.advance();
   }

   dbKeyCounter_.store(prevDbKey + 1, memory_order_relaxed);
}

////////////////////////////////////////////////////////////////////////////////
const BinaryDataRef DBInterface::getDataRef(const BinaryData& key) const
{
   auto iter = dataMap_.find(key);
   if (iter == dataMap_.end())
      return BinaryDataRef();

   return iter->second.getRef();
}

////////////////////////////////////////////////////////////////////////////////
void DBInterface::update(const std::vector<std::shared_ptr<InsertData>>& vec)
{
   for (auto& dataPtr : vec)
   {
      if (!dataPtr->write_)
      {
         dataMap_.erase(dataPtr->key_);
         continue;
      }

      auto insertIter = dataMap_.insert(make_pair(dataPtr->key_, dataPtr->value_));
      if (!insertIter.second)
         insertIter.first->second = dataPtr->value_;
   }
}

////////////////////////////////////////////////////////////////////////////////
void DBInterface::wipe(const BinaryData& key)
{
   CharacterArrayRef carKey(key.getSize(), key.getPtr());
   db_.wipe(carKey);
}

////////////////////////////////////////////////////////////////////////////////
bool DBInterface::resolveDataKey(const BinaryData& dataKey,
   BinaryData& dbKey)
{
   /*
   Return the dbKey for the data key if it exists, otherwise increment the
   dbKeyCounter and construct a key from that.
   */

   auto iter = dataKeyToDbKey_.find(dataKey);
   if (iter != dataKeyToDbKey_.end())
   {
      dbKey = iter->second;
      return true;
   }

   dbKey = getNewDbKey();
   return false;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData DBInterface::getNewDbKey()
{
   auto dbKeyInt = dbKeyCounter_.fetch_add(1, memory_order_relaxed);
   return WRITE_UINT32_BE(dbKeyInt);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// WalletDBInterface
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::setupEnv(const string& path, unsigned dbCount)
{
   if (dbEnv_ != nullptr)
      return;

   dbEnv_ = std::make_shared<LMDBEnv>(dbCount);
   dbEnv_->open(path, MDB_WRITEMAP);
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::shutdown()
{
   auto lock = unique_lock<mutex>(setupMutex_);

   dbMap_.clear();
   dbEnv_->close();
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::openDB(const string& dbName)
{
   auto lock = unique_lock<mutex>(setupMutex_);

   auto iter = dbMap_.find(dbName);
   if (iter != dbMap_.end())
      return;

   auto dbiPtr = make_shared<DBInterface>(dbEnv_, dbName);
   dbMap_.insert(make_pair(dbName, dbiPtr));

   //load all entries in db
   dbiPtr->loadAllEntries();
}

////////////////////////////////////////////////////////////////////////////////
const string& WalletDBInterface::getFilename() const
{
   if (dbEnv_ == nullptr)
      throw WalletInterfaceException("null dbEnv");

   return dbEnv_->getFilename();
}

////////////////////////////////////////////////////////////////////////////////
WalletIfaceTransaction WalletDBInterface::beginWriteTransaction(
   const string& dbName)
{
   auto iter = dbMap_.find(dbName);
   if (iter == dbMap_.end())
      throw WalletInterfaceException("invalid db name");

   return WalletIfaceTransaction(iter->second, true);
}

////////////////////////////////////////////////////////////////////////////////
WalletIfaceTransaction WalletDBInterface::beginReadTransaction(
   const string& dbName)
{
   auto iter = dbMap_.find(dbName);
   if (iter == dbMap_.end())
      throw WalletInterfaceException("invalid db name");

   return WalletIfaceTransaction(iter->second, false);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// WalletIfaceIterator
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
bool WalletIfaceIterator::isValid() const
{
   return iterator_ != dbPtr_->dataMap_.end();
}

////////////////////////////////////////////////////////////////////////////////
void WalletIfaceIterator::seek(const BinaryDataRef& key)
{
   iterator_ = dbPtr_->dataMap_.lower_bound(key);
}

////////////////////////////////////////////////////////////////////////////////
void WalletIfaceIterator::advance()
{
   ++iterator_;
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef WalletIfaceIterator::key() const
{
   return iterator_->first.getRef();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef WalletIfaceIterator::value() const
{
   return iterator_->second.getRef();
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// WalletIfaceTransaction
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
map<string, map<thread::id, WalletIfaceTransaction::ParentTx>> 
WalletIfaceTransaction::txMap_;

mutex WalletIfaceTransaction::txMutex_;

////////////////////////////////////////////////////////////////////////////////
WalletIfaceTransaction::WalletIfaceTransaction(
   shared_ptr<DBInterface> dbPtr, bool mode) :
   dbPtr_(dbPtr), commit_(mode)
{
   if (!insertTx(this))
      throw WalletInterfaceException("failed to create db tx");
}

////////////////////////////////////////////////////////////////////////////////
WalletIfaceTransaction::~WalletIfaceTransaction()
{
   if (!eraseTx(this))
      return;

   //this is the top tx, check if it has to commit
   if (!commit_)
      return;

   //need to commit all this data to the underlying db object
   auto tx = LMDBEnv::Transaction(dbPtr_->dbEnv_.get(), LMDB::ReadWrite);
   for (auto& dataPtr : insertVec_)
   {
      BinaryData dbKey;
      auto keyExists = dbPtr_->resolveDataKey(dataPtr->key_, dbKey);
      if (keyExists)
      {
         /***
            This operation abuses the no copy read feature in lmdb. Since all data is
            mmap'd, a no copy read is a pointer to the data on disk. Therefor modifying
            that data will result in a modification on disk.

            This is done under 3 conditions:
            1) The decrypted data container is locked.
            2) The calling threads owns a ReadWrite transaction on the lmdb object
            3) There are no active ReadOnly transactions on the lmdb object

            1. is a no brainer, 2. guarantees the changes are flushed to disk once the
            tx is released. RW tx are locked, therefor only one is active at any given
            time, by LMDB design.

            3. is to guarantee there are no readers when the change takes place. Needs
            some LMDB C++ wrapper modifications to be able to check from the db object.
            The condition should be enforced by the caller regardless.
         ***/

         //check db only has one RW tx
         /*if (!dbEnv_->isRWLockExclusive())
         {
            throw DecryptedDataContainerException(
               "need exclusive RW lock to delete entries");
         }*/
         //check data exists

         /*auto dataRef = dbPtr_->getDataRef(key);
         if (dataRef.getSize() == 0)
            return;

         //wipe it
         dbPtr_->wipe(key);
         */

         //wipe the key
         CharacterArrayRef carKey(dbKey.getSize(), dbKey.getPtr());
         dbPtr_->db_.wipe(carKey);

         //write in the erased place holder
         BinaryWriter bw;
         bw.put_var_int(dataPtr->key_.getSize());
         bw.put_BinaryData(dataPtr->key_);

         bw.put_var_int(6);
         bw.put_BinaryData(BinaryData("erased"));

         CharacterArrayRef carData(bw.getSize(), bw.getDataRef().getPtr());
         dbPtr_->db_.insert(carKey, carData);

         //move on to next piece of data if there is nothing to write
         if (!dataPtr->write_)
         {
            //update dataKeyToDbKey
            dbPtr_->dataKeyToDbKey_.erase(dataPtr->key_);
            continue;
         }

         //grab a fresh key
         dbKey = dbPtr_->getNewDbKey();
      }

      //sanity check
      if (!dataPtr->write_)
         throw WalletInterfaceException("key marked for deletion when it does not exist");

      //update dataKeyToDbKey
      dbPtr_->dataKeyToDbKey_[dataPtr->key_] = dbKey;

      //bundle key and val together, key by dbkey
      BinaryWriter dbVal;
      dbVal.put_var_int(dataPtr->key_.getSize());
      dbVal.put_BinaryData(dataPtr->key_);
      dbVal.put_var_int(dataPtr->value_.getSize());
      dbVal.put_BinaryData(dataPtr->value_);

      CharacterArrayRef carKey(dbKey.getSize(), dbKey.getPtr());
      CharacterArrayRef carVal(dbVal.getSize(), dbVal.getDataRef().getPtr());
      dbPtr_->db_.insert(carKey, carVal);
   }

   //update db data map
   dbPtr_->update(insertVec_);
}

////////////////////////////////////////////////////////////////////////////////
bool WalletIfaceTransaction::insertTx(WalletIfaceTransaction* txPtr)
{
   if (txPtr == nullptr)
      throw WalletInterfaceException("null tx ptr");

   auto lock = unique_lock<mutex>(txMutex_);

   auto dbIter = txMap_.find(txPtr->dbPtr_->getName());
   if (dbIter == txMap_.end())
   {
      dbIter = txMap_.insert(
         make_pair(txPtr->dbPtr_->getName(), map<thread::id, ParentTx>())
      ).first;
   }

   auto& txMap = dbIter->second;

   //save tx by thread id
   auto thrId = this_thread::get_id();
   auto iter = txMap.find(thrId);
   if (iter == txMap.end())
   {
      //this is the parent tx, create the lambdas and setup the struct
      
      ParentTx ptx;
      ptx.commit_ = txPtr->commit_;

      if (txPtr->commit_)
      {
         auto insertLbd = [thrId, txPtr](const BinaryData& key, const BinaryData& val)
         {
            if (thrId != this_thread::get_id())
               throw WalletInterfaceException("insert operation thread id mismatch");

            auto dataPtr = make_shared<InsertData>();
            dataPtr->key_ = key;
            dataPtr->value_ = val;

            unsigned vecSize = txPtr->insertVec_.size();
            txPtr->insertVec_.emplace_back(dataPtr);

            /*
            Insert the index for this data object in the key map.
            Replace the index if it's already there as we want to track
            the final effect for each key.
            */
            auto insertPair = txPtr->keyToDataMap_.insert(make_pair(key, vecSize));
            if (!insertPair.second)
               insertPair.first->second = vecSize;
         };

         auto eraseLbd = [thrId, txPtr](const BinaryData& key, bool wipe)
         {
            if (thrId != this_thread::get_id())
               throw WalletInterfaceException("insert operation thread id mismatch");

            auto dataPtr = make_shared<InsertData>();
            dataPtr->key_ = key;
            dataPtr->write_ = false; //set to false to signal deletion
            dataPtr->wipe_ = wipe;

            unsigned vecSize = txPtr->insertVec_.size();
            txPtr->insertVec_.emplace_back(dataPtr);

            auto insertPair = txPtr->keyToDataMap_.insert(make_pair(key, vecSize));
            if (!insertPair.second)
               insertPair.first->second = vecSize;
         };

         auto getDataLbd = [thrId, txPtr](const BinaryData& key)->
            const shared_ptr<InsertData>&
         {
            auto iter = txPtr->keyToDataMap_.find(key);
            if (iter == txPtr->keyToDataMap_.end())
               throw NoDataInDB();

            return txPtr->insertVec_[iter->second];
         };

         txPtr->insertLbd_ = insertLbd;
         txPtr->eraseLbd_ = eraseLbd;
         txPtr->getDataLbd_ = getDataLbd;

         ptx.insertLbd_ = insertLbd;
         ptx.eraseLbd_ = eraseLbd;
         ptx.getDataLbd_ = getDataLbd;
      }

      txMap.insert(make_pair(thrId, ptx));
      return true;
   }
   
   /*we already have a tx for this thread, we will nest the new one within it*/
   
   //make sure the commit type between parent and nested tx match
   if (iter->second.commit_ != txPtr->commit_)
      return false;

   //set lambdas
   txPtr->insertLbd_ = iter->second.insertLbd_;
   txPtr->eraseLbd_ = iter->second.eraseLbd_;
   txPtr->getDataLbd_ = iter->second.getDataLbd_;

   //increment counter
   ++iter->second.counter_;
   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool WalletIfaceTransaction::eraseTx(WalletIfaceTransaction* txPtr)
{
   if (txPtr == nullptr)
      throw WalletInterfaceException("null tx ptr");

   auto lock = unique_lock<mutex>(txMutex_);
   
   //we have to have this db name in the tx map
   auto dbIter = txMap_.find(txPtr->dbPtr_->getName());
   if (dbIter == txMap_.end())
      throw WalletInterfaceException("missing db name in tx map");

   auto& txMap = dbIter->second;

   //thread id has to be present too
   auto thrId = this_thread::get_id();
   auto iter = txMap.find(thrId);
   if (iter == txMap.end())
      throw WalletInterfaceException("missing thread id in tx map");

   if (iter->second.counter_ > 1)
   {
      //this is a nested tx, decrement and return false
      --iter->second.counter_;
      return false;
   }

   //counter is 1, this is the parent tx, clean up the entry and return true
   txMap.erase(iter);
   return true;
}

////////////////////////////////////////////////////////////////////////////////
void WalletIfaceTransaction::insert(const BinaryData& key, const BinaryData& val)
{
   if (!insertLbd_)
      throw WalletInterfaceException("insert lambda is not set");

   insertLbd_(key, val);
}

////////////////////////////////////////////////////////////////////////////////
void WalletIfaceTransaction::erase(const BinaryData& key)
{
   if (!eraseLbd_)
      throw WalletInterfaceException("erase lambda is not set");

   eraseLbd_(key, false);
}

////////////////////////////////////////////////////////////////////////////////
void WalletIfaceTransaction::wipe(const BinaryData& key)
{
   if (!eraseLbd_)
      throw WalletInterfaceException("erase lambda is not set");

   eraseLbd_(key, true);
}

////////////////////////////////////////////////////////////////////////////////
WalletIfaceIterator WalletIfaceTransaction::getIterator() const
{
   if (commit_)
      throw WalletInterfaceException("cannot iterate over a write transaction");

   return WalletIfaceIterator(dbPtr_);
}

////////////////////////////////////////////////////////////////////////////////
const BinaryDataRef WalletIfaceTransaction::getDataRef(
   const BinaryData& key) const
{
   if (commit_)
   {
      /*
      A write transaction may carry data that overwrites the db object data map.
      Check the modification map first.
      */

      try
      {
         auto& dataPtr = getInsertDataForKey(key);
         if (!dataPtr->write_)
            return BinaryDataRef();

         return dataPtr->value_.getRef();
      }
      catch (NoDataInDB&)
      {
         /*
         Will throw if there's no data in the write tx.
         Look for it in the db instead.
         */
      }
   }

   return dbPtr_->getDataRef(key);
}

////////////////////////////////////////////////////////////////////////////////
const std::shared_ptr<InsertData>& WalletIfaceTransaction::getInsertDataForKey(
   const BinaryData& key) const
{
   if (!getDataLbd_)
      throw WalletInterfaceException("tx is missing get lbd");

   return getDataLbd_(key);
}