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
#include <functional>

#include "make_unique.h"
#include "lmdbpp.h"
#include "BinaryData.h"
#include "SecureBinaryData.h"
#include "ReentrantLock.h"

#define CONTROL_DB_NAME "control_db"
#define ERASURE_PLACE_HOLDER "erased"
#define KEY_CYCLE_FLAG "cycle"

////////////////////////////////////////////////////////////////////////////////
typedef std::function<SecureBinaryData(const std::set<BinaryData>&)> 
   PassphraseLambda;

////////////////////////////////////////////////////////////////////////////////
class NoDataInDB : std::runtime_error
{
public:
   NoDataInDB(void) :
      runtime_error("")
   {}
};

////
class NoEntryInWalletException
{};

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

////////////////////////////////////////////////////////////////////////////////
class DBIfaceIterator;
class WalletIfaceIterator;
class WalletIfaceTransaction;

////////////////////////////////////////////////////////////////////////////////
class DBInterface
{
   friend class WalletIfaceIterator;
   friend class WalletIfaceTransaction;

private:
   const std::string dbName_;
   LMDBEnv* dbEnv_ = nullptr;
   LMDB db_;

   std::map<BinaryData, BinaryData> dataMap_;
   std::map<BinaryData, BinaryData> dataKeyToDbKey_;
   std::atomic<unsigned> dbKeyCounter_ = { 0 };

   const SecureBinaryData controlSalt_;
   SecureBinaryData encrPubKey_;
   SecureBinaryData macKey_;

   static const BinaryData erasurePlaceHolder_;
   static const BinaryData keyCycleFlag_;

private:
   void update(const std::vector<std::shared_ptr<InsertData>>&);
   void wipe(const BinaryData&);
   bool resolveDataKey(const BinaryData&, BinaryData&);
   BinaryData getNewDbKey(void);

   //serialization methods
   static BinaryData createDataPacket(const BinaryData& dbKey,
      const BinaryData& dataKey, const BinaryData& dataVal,
      const SecureBinaryData&, const SecureBinaryData&);
   static std::pair<BinaryData, BinaryData> readDataPacket(
      const BinaryData& dbKey, const BinaryData& dataPacket,
      const SecureBinaryData&, const SecureBinaryData&);

public:
   DBInterface(LMDBEnv*, 
      const std::string&, const SecureBinaryData&);
   ~DBInterface(void);

   ////
   void loadAllEntries(const SecureBinaryData&);
   void reset(LMDBEnv*);
   void close(void) { db_.close(); }

   ////
   const BinaryDataRef getDataRef(const BinaryData&) const;
   const std::string& getName(void) const { return dbName_; }
   unsigned getEntryCount(void) const { return dataMap_.size(); }
};

////////////////////////////////////////////////////////////////////////////////
class DBIfaceTransaction
{
protected:
   struct ParentTx
   {
      unsigned counter_ = 1;
      bool commit_;

      std::function<void(const BinaryData&, const BinaryData&)> insertLbd_;
      std::function<void(const BinaryData&, bool)> eraseLbd_;
      std::function<const std::shared_ptr<InsertData>&(const BinaryData&)> 
         getDataLbd_;
   };

protected:
   //<dbName, <thread id, <counter, mode>>>
   static std::map<std::string, std::map<std::thread::id, ParentTx>> txMap_;
   static std::mutex txMutex_;

public:
   DBIfaceTransaction(void) {}
   virtual ~DBIfaceTransaction(void) = 0;

   virtual void insert(const BinaryData&, const BinaryData&) = 0;
   virtual void erase(const BinaryData&) = 0;
   virtual void wipe(const BinaryData&) = 0;

   virtual const BinaryDataRef getDataRef(const BinaryData&) const = 0;
   virtual std::shared_ptr<DBIfaceIterator> getIterator() const = 0;

   static bool hasTx(void);
};

////////////////////////////////////////////////////////////////////////////////
class WalletIfaceTransaction : public DBIfaceTransaction
{
private:
   DBInterface* dbPtr_;
   bool commit_ = false;

   /*
   insertVec tracks the order in which insertion and deletion take place
   keyToMapData keeps tracks of the final effect for each key

   using shared_ptr to reduce cost of copies when resizing the vector
   */
   std::vector<std::shared_ptr<InsertData>> insertVec_;
   std::map<BinaryData, unsigned> keyToDataMap_;

   std::function<void(const BinaryData&, const BinaryData&)> insertLbd_;
   std::function<void(const BinaryData&, bool)> eraseLbd_;
   std::function<const std::shared_ptr<InsertData>&(const BinaryData&)> 
      getDataLbd_;

private:
   static bool insertTx(WalletIfaceTransaction*);
   static bool eraseTx(WalletIfaceTransaction*);

   const std::shared_ptr<InsertData>& getInsertDataForKey(const BinaryData&) const;

public:
   WalletIfaceTransaction(DBInterface* dbPtr, bool mode);
   ~WalletIfaceTransaction(void);

   //write routines
   void insert(const BinaryData&, const BinaryData&) override;
   void erase(const BinaryData&) override;
   void wipe(const BinaryData&) override;

   //get routines
   const BinaryDataRef getDataRef(const BinaryData&) const override;
   std::shared_ptr<DBIfaceIterator> getIterator() const override;
};

////////////////////////////////////////////////////////////////////////////////
class RawIfaceTransaction : public DBIfaceTransaction
{
private:
   LMDB* dbPtr_;
   std::unique_ptr<LMDBEnv::Transaction> txPtr_;

public:
   RawIfaceTransaction(LMDBEnv* dbEnv, 
      LMDB* dbPtr, bool write) :
      DBIfaceTransaction(), dbPtr_(dbPtr)
   {
      auto type = LMDB::ReadOnly;
      if (write)
         type = LMDB::ReadWrite;

      txPtr_ = make_unique<LMDBEnv::Transaction>(dbEnv, type);
   }

   ~RawIfaceTransaction(void)
   {
      txPtr_.reset();
   }

   //write routines
   void insert(const BinaryData&, const BinaryData&) override;
   void erase(const BinaryData&) override;
   void wipe(const BinaryData&) override;

   //get routines
   const BinaryDataRef getDataRef(const BinaryData&) const override;
   std::shared_ptr<DBIfaceIterator> getIterator() const override;
};

////////////////////////////////////////////////////////////////////////////////
class DBIfaceIterator
{
public:
   DBIfaceIterator(void) {}
   virtual ~DBIfaceIterator(void) = 0;

   virtual bool isValid(void) const = 0;
   virtual void seek(const BinaryDataRef&) = 0;
   virtual void advance(void) = 0;

   virtual BinaryDataRef key(void) const = 0;
   virtual BinaryDataRef value(void) const = 0;
};

////////////////////////////////////////////////////////////////////////////////
class WalletIfaceIterator : public DBIfaceIterator
{
private:
   const DBInterface* dbPtr_;
   std::map<BinaryData, BinaryData>::const_iterator iterator_;

public:
   WalletIfaceIterator(const DBInterface* dbPtr) :
      dbPtr_(dbPtr)
   {
      if (dbPtr_ == nullptr)
         throw WalletInterfaceException("null db ptr");

      iterator_ = dbPtr_->dataMap_.begin();
   }

   bool isValid(void) const override;
   void seek(const BinaryDataRef&) override;
   void advance(void) override;

   BinaryDataRef key(void) const override;
   BinaryDataRef value(void) const override;
};

////////////////////////////////////////////////////////////////////////////////
class RawIfaceIterator : public DBIfaceIterator
{
private:
   LMDB* dbPtr_;
   LMDB::Iterator iterator_;

public:
   RawIfaceIterator(LMDB* dbPtr) :
      dbPtr_(dbPtr)
   {
      if (dbPtr_ == nullptr)
         throw WalletInterfaceException("null db ptr");

      iterator_ = dbPtr_->begin();
   }

   bool isValid(void) const override;
   void seek(const BinaryDataRef&) override;
   void advance(void) override;

   BinaryDataRef key(void) const override;
   BinaryDataRef value(void) const override;
};

struct WalletHeader;
struct WalletHeader_Control;
class DecryptedDataContainer;
class EncryptedSeed;

////////////////////////////////////////////////////////////////////////////////
struct MasterKeyStruct;

////
class WalletDBInterface
{
private:
   mutable std::mutex setupMutex_;

   std::unique_ptr<LMDBEnv> dbEnv_ = nullptr;
   std::map<std::string, std::unique_ptr<DBInterface>> dbMap_;

   //encryption objects
   std::unique_ptr<LMDB> controlDb_;

   //wallet structure
   std::map<BinaryData, std::shared_ptr<WalletHeader>> headerMap_;

   std::string path_;
   unsigned dbCount_ = 0;

   std::unique_ptr<DecryptedDataContainer> decryptedData_;
   std::unique_ptr<ReentrantLock> controlLock_;
   std::unique_ptr<EncryptedSeed> controlSeed_;

private:
   //control objects loading
   std::shared_ptr<WalletHeader> loadControlHeader();
   void loadDataContainer(std::shared_ptr<WalletHeader>);
   void loadSeed(std::shared_ptr<WalletHeader>);
   void loadHeaders(void);

   //utils
   BinaryDataRef getDataRefForKey(
      std::shared_ptr<DBIfaceTransaction> tx, const BinaryData& key);
   void setDbCount(unsigned, bool);
   void openDB(std::shared_ptr<WalletHeader>, const SecureBinaryData&);

   //header methods
   void openControlDb(void);
   std::shared_ptr<WalletHeader_Control> setupControlDB(
      const PassphraseLambda&);
   void putHeader(std::shared_ptr<WalletHeader>);

public:
   //tors
   WalletDBInterface(void) {}
   ~WalletDBInterface(void) { shutdown(); }

   //setup
   void setupEnv(const std::string& path, const PassphraseLambda&);
   void shutdown(void);

   const std::string& getFilename(void) const;

   //headers
   static MasterKeyStruct initWalletHeaderObject(
      std::shared_ptr<WalletHeader>, const SecureBinaryData&);
   void addHeader(std::shared_ptr<WalletHeader>);
   std::shared_ptr<WalletHeader> getWalletHeader(
      const std::string&) const;
   const std::map<BinaryData, std::shared_ptr<WalletHeader>>& 
      getHeaderMap(void) const;

   //db count
   unsigned getDbCount(void) const;
   unsigned getFreeDbCount(void) const;
   void setDbCount(unsigned);

   //transactions
   std::shared_ptr<DBIfaceTransaction> beginWriteTransaction(const std::string&);
   std::shared_ptr<DBIfaceTransaction> beginReadTransaction(const std::string&);

   //utils
   void lockControlContainer(const PassphraseLambda&);
   void unlockControlContainer(void);
};

#endif