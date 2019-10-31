////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_WALLETFILEINTERFACE_
#define _H_WALLETFILEINTERFACE_

#include <memory>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <mutex>

#include "make_unique.h"
#include "lmdbpp.h"
#include "BinaryData.h"

////////////////////////////////////////////////////////////////////////////////
class NoDataInDB : std::runtime_error
{
public:
   NoDataInDB(void) :
      runtime_error("")
   {}
};

////////////////////////////////////////////////////////////////////////////////
struct InsertData
{
   BinaryData key_;
   BinaryData value_;
   bool write_ = true;
   bool wipe_ = false;
};

////////////////////////////////////////////////////////////////////////////////
class WalletInterfaceException : public std::runtime_error
{
public:
   WalletInterfaceException(const std::string& err) :
      std::runtime_error(err)
   {}
};

class WalletIfaceIterator;
class WalletIfaceTransaction;

////////////////////////////////////////////////////////////////////////////////
class DBInterface
{
   friend class WalletIfaceIterator;
   friend class WalletIfaceTransaction;

private:
   const std::string dbName_;
   std::shared_ptr<LMDBEnv> dbEnv_ = nullptr;
   LMDB db_;

   std::map<BinaryData, BinaryData> dataMap_;

private:
   void update(const std::vector<std::shared_ptr<InsertData>>&);
   void wipe(const BinaryData&);

public:
   DBInterface(std::shared_ptr<LMDBEnv>, const std::string&);
   ~DBInterface(void);

   ////
   void loadAllEntries(void);

   ////
   const BinaryDataRef getDataRef(const BinaryData&) const;

   ////
   const std::string& getName(void) const { return dbName_; }
};

////////////////////////////////////////////////////////////////////////////////
class WalletIfaceTransaction
{
private:
   struct ParentTx
   {
      unsigned counter_ = 1;
      bool commit_;

      std::function<void(const BinaryData&, const BinaryData&)> insertLbd_;
      std::function<void(const BinaryData&, bool)> eraseLbd_;
      std::function<const std::shared_ptr<InsertData>&(const BinaryData&)> 
         getDataLbd_;
   };

private:
   std::shared_ptr<DBInterface> dbPtr_;
   bool commit_ = false;

   /*
   insertVec tracks the order in which instertion and deletion take place
   keyToMapData keeps tracks of the final effect for each key

   using shared_ptr to reduce cost of copies when resizing the vector
   */
   std::vector<std::shared_ptr<InsertData>> insertVec_;
   std::map<BinaryData, unsigned> keyToDataMap_;

   //<dbName, <thread id, <counter, mode>>>
   static std::map<std::string, std::map<std::thread::id, ParentTx>> txMap_;
   static std::mutex txMutex_;

   std::function<void(const BinaryData&, const BinaryData&)> insertLbd_;
   std::function<void(const BinaryData&, bool)> eraseLbd_;
   std::function<const std::shared_ptr<InsertData>&(const BinaryData&)> 
      getDataLbd_;

private:
   static bool insertTx(WalletIfaceTransaction*);
   static bool eraseTx(WalletIfaceTransaction*);

   const std::shared_ptr<InsertData>& getInsertDataForKey(const BinaryData&) const;

public:
   WalletIfaceTransaction(std::shared_ptr<DBInterface> dbPtr, bool mode);
   ~WalletIfaceTransaction(void);

   //write routines
   void insert(const BinaryData&, const BinaryData&);
   void erase(const BinaryData&);
   void wipe(const BinaryData&);

   //get routines
   const BinaryDataRef getDataRef(const BinaryData&) const;
   WalletIfaceIterator getIterator() const;
};

////////////////////////////////////////////////////////////////////////////////
class WalletIfaceIterator
{
private:
   const std::shared_ptr<DBInterface> dbPtr_;
   std::map<BinaryData, BinaryData>::const_iterator iterator_;

public:
   WalletIfaceIterator(const std::shared_ptr<DBInterface>& dbPtr) :
      dbPtr_(dbPtr)
   {
      if (dbPtr_ == nullptr)
         throw WalletInterfaceException("null db ptr");

      iterator_ = dbPtr_->dataMap_.begin();
   }

   bool isValid(void) const;
   void seek(const BinaryDataRef&);
   void advance(void);

   BinaryDataRef key(void) const;
   BinaryDataRef value(void) const;
};

////////////////////////////////////////////////////////////////////////////////
class WalletDBInterface
{
private:
   std::mutex setupMutex_;

   std::shared_ptr<LMDBEnv> dbEnv_ = nullptr;
   std::map<std::string, std::shared_ptr<DBInterface>> dbMap_;

public:
   //tors
   WalletDBInterface(void) {}
   ~WalletDBInterface(void) { shutdown(); }

   //setup
   void setupEnv(const std::string& path, unsigned dbCount);
   void shutdown(void);
   void openDB(const std::string& dbName);

   const std::string& getFilename(void) const;

   //transactions
   WalletIfaceTransaction beginWriteTransaction(const std::string&);
   WalletIfaceTransaction beginReadTransaction(const std::string&);
};

#endif