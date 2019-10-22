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

   auto iter = db_.begin();
   while (iter.isValid())
   {
      auto key_mval = iter.key();
      auto val_mval = iter.value();

      BinaryDataRef key_bdr((const uint8_t*)key_mval.mv_data, key_mval.mv_size);
      BinaryDataRef val_bdr((const uint8_t*)val_mval.mv_data, val_mval.mv_size);

      BinaryData key_bd(key_bdr);
      BinaryData val_bd(val_bdr);

      auto&& keyval = make_pair(move(key_bd), move(val_bd));
      dataMap_.emplace(keyval);

      iter.advance();
   }
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
WalletIfaceIterator WalletDBInterface::getIterator(const string& dbName) const
{
   auto iter = dbMap_.find(dbName);
   if (iter == dbMap_.end())
      throw WalletInterfaceException("invalid db name");

   return WalletIfaceIterator(iter->second);
}

////////////////////////////////////////////////////////////////////////////////
const string& WalletDBInterface::getFilename() const
{
   if (dbEnv_ == nullptr)
      throw WalletInterfaceException("null dbEnv");

   return dbEnv_->getFilename();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef WalletDBInterface::getDataRef(const string& dbName, 
   const BinaryData& key)
{
   auto iter = dbMap_.find(dbName);
   if (iter == dbMap_.end())
      throw WalletInterfaceException("invalid db name");

   return iter->second->getDataRef(key);
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
      CharacterArrayRef carKey(dataPtr->key_.getSize(), dataPtr->key_.getPtr());
      if (!dataPtr->write_)
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

         if(!dataPtr->wipe_)
            dbPtr_->db_.erase(carKey);
         else
            dbPtr_->db_.wipe(carKey);

         continue;
      }

      CharacterArrayRef carVal(dataPtr->value_.getSize(), dataPtr->value_.getPtr());
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

            txPtr->insertVec_.emplace_back(dataPtr);
         };

         auto eraseLbd = [thrId, txPtr](const BinaryData& key, bool wipe)
         {
            if (thrId != this_thread::get_id())
               throw WalletInterfaceException("insert operation thread id mismatch");

            auto dataPtr = make_shared<InsertData>();
            dataPtr->key_ = key;
            dataPtr->write_ = false; //set to false to signal deletion
            dataPtr->wipe_ = wipe;

            txPtr->insertVec_.emplace_back(dataPtr);
         };

         txPtr->insertLbd_ = insertLbd;
         txPtr->eraseLbd_ = eraseLbd;

         ptx.insertLbd_ = insertLbd;
         ptx.eraseLbd_ = eraseLbd;
      }

      txMap.insert(make_pair(thrId, ptx));
      return true;
   }
   
   /*we have already a tx for this thread, we will nest the new one within it*/
   
   //make sure the commit type between parent and nested tx match
   if (iter->second.commit_ != txPtr->commit_)
      return false;

   //set lambdas
   txPtr->insertLbd_ = iter->second.insertLbd_;
   txPtr->eraseLbd_ = iter->second.eraseLbd_;

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

