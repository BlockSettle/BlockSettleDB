////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "WalletFileInterface.h"
#include "BtcUtils.h"
#include "DBUtils.h"
#include "WalletHeader.h"
#include "DecryptedDataContainer.h"
#include "Assets.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DBInterface
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
DBInterface::DBInterface(
   std::shared_ptr<LMDBEnv> dbEnv, const std::string& dbName, 
   const SecureBinaryData& macKey) :
   dbEnv_(dbEnv), dbName_(dbName), macKey_(macKey)
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
void DBInterface::reset(shared_ptr<LMDBEnv> envPtr)
{
   if (db_.isOpen())
      db_.close();

   dbEnv_ = envPtr;
   auto tx = LMDBEnv::Transaction(dbEnv_.get(), LMDB::ReadWrite);
   db_.open(dbEnv_.get(), dbName_);
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

      auto dataPair = readDataPacket(key_bdr, val_bdr, macKey_);

      if (dataPair.second != BinaryData("erased"))
      {
         auto&& keyPair = make_pair(dataPair.first, move(key_bdr.copy()));
         auto insertIter = dataKeyToDbKey_.emplace(keyPair);
         if (!insertIter.second)
            throw WalletInterfaceException("duplicated db entry");

         dataMap_.emplace(dataPair);
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
BinaryData DBInterface::createDataPacket(const BinaryData& dbKey,
   const BinaryData& dataKey, const BinaryData& dataVal,
   const BinaryData& macKey)
{
   //concatenate dataKey and dataVal
   BinaryWriter bw;
   bw.put_var_int(dataKey.getSize());
   bw.put_BinaryData(dataKey);
   bw.put_var_int(dataVal.getSize());
   bw.put_BinaryData(dataVal);

   //save the writer state for later
   auto bwData = bw.getData();

   //concatenate the dbKey
   bw.put_BinaryData(dbKey);

   //hmac it
   auto&& hmac = BtcUtils::getHMAC256(macKey, bw.getData());

   //append the hmac to the concatenated data
   bwData.append(hmac);

   //padding

   return bwData;
}

////////////////////////////////////////////////////////////////////////////////
pair<BinaryData, BinaryData> DBInterface::readDataPacket(
   const BinaryData& dbKey, const BinaryData& dataPacket,
   const BinaryData& macKey)
{
   BinaryRefReader brr(dataPacket.getRef());

   //grab data key
   auto len = brr.get_var_int();
   auto dataKey = brr.get_BinaryData(len);

   //grab data val
   len = brr.get_var_int();
   auto dataVal = brr.get_BinaryData(len);

   //mark the position
   auto pos = brr.getPosition();

   //grab hmac
   auto hmac = brr.get_BinaryData(32);

   //sanity check
   if (brr.getSizeRemaining() != 0)
      throw WalletInterfaceException("loose data entry");

   //reset reader & grab data packet
   brr.resetPosition();
   auto data = brr.get_BinaryData(pos);

   //append db key
   data.append(dbKey);

   //compute hmac
   auto computedHmac = BtcUtils::getHMAC256(macKey, data);

   //check hmac
   if (computedHmac != hmac)
      throw WalletInterfaceException("mac mismatch");

   return make_pair(dataKey, dataVal);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// WalletDBInterface
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::setupEnv(const string& path)
{
   auto lock = unique_lock<mutex>(setupMutex_);
   if (dbEnv_ != nullptr)
      return;

   path_ = path;

   //open env for control and meta dbs
   dbEnv_ = std::make_shared<LMDBEnv>(2);
   dbEnv_->open(path, MDB_WRITEMAP);

   //open control db
   openControlDb();

   bool isNew = false;
   shared_ptr<WalletHeader_Control> controlHeader;
   try
   {
      //get control header
      controlHeader = dynamic_pointer_cast<WalletHeader_Control>(
         loadControlHeader());
      if (controlHeader == nullptr)
         throw WalletException("invalid control header");
   }
   catch (NoEntryInWalletException&)
   {
      //no control header, this is a fresh wallet, set it up
      controlHeader = setupControlDB(SecureBinaryData());
      isNew = true;
   }

   //get control decrypted data container
   auto decrData = loadDataContainer(controlHeader);

   //get control seed
   auto seed = loadSeed(controlHeader);

   //decrypt control seed
   {
      auto lock = ReentrantLock(decrData.get());
      macKey_ = decrData->getDecryptedPrivateData(seed);
   }

   //load wallet header db
   {
      openDB(WALLETHEADER_DBNAME);
      auto dbPtr = dbMap_.find(WALLETHEADER_DBNAME)->second;
   }

   //load wallet header objects
   unsigned dbCount;
   if (!isNew)
   {
      loadHeaders();
      dbCount = headerMap_.size() + 2;
   }
   else
   {
      dbCount = 3;
   }

   //set new db count;
   setDbCount(dbCount, false);

   //open all dbs listed in header map
   for (auto& headerPtr : headerMap_)
      openDB(headerPtr.second->dbName_);
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef WalletDBInterface::getDataRefForKey(
   shared_ptr<DBIfaceTransaction> tx, const BinaryData& key)
{
   /** The reference lifetime is tied to the db tx lifetime. The caller has to
   maintain the tx for as long as the data ref needs to be valid **/

   auto ref = tx->getDataRef(key);

   if (ref.getSize() == 0)
      throw NoEntryInWalletException();

   return DBUtils::getDataRefForPacket(ref);
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::loadHeaders()
{
   openDB(WALLETHEADER_DBNAME);

   auto&& tx = beginReadTransaction(WALLETHEADER_DBNAME);

   {
      //masterID
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MASTERID_KEY);

      try
      {
         masterID_ = getDataRefForKey(tx, bwKey.getData());
      }
      catch (NoEntryInWalletException&)
      {
         throw WalletInterfaceException("missing masterID entry");
      }
   }

   {
      //mainWalletID
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAINWALLET_KEY);

      try
      {
         mainWalletID_ = getDataRefForKey(tx, bwKey.getData());
      }
      catch (NoEntryInWalletException&)
      {
         throw WalletInterfaceException("missing main wallet entry");
      }
   }

   //meta map
   auto dbIter = tx->getIterator();

   BinaryWriter bwKey;
   bwKey.put_uint8_t(WALLETHEADER_PREFIX);
   dbIter->seek(bwKey.getDataRef());

   while (dbIter->isValid())
   {
      auto iterkey = dbIter->key();
      auto itervalue = dbIter->value();

      //check value's advertized size is packet size and strip it
      BinaryRefReader brrVal(itervalue);
      auto valsize = brrVal.get_var_int();
      if (valsize != brrVal.getSizeRemaining())
         throw WalletInterfaceException("entry val size mismatch");

      try
      {
         auto headerPtr = WalletHeader::deserialize(
            iterkey, brrVal.get_BinaryDataRef(brrVal.getSizeRemaining()));
         headerPtr->masterID_ = masterID_;

         if (headerPtr->shouldLoad())
            headerMap_.insert(make_pair(headerPtr->getWalletID(), headerPtr));
      }
      catch (exception& e)
      {
         LOGERR << e.what();
         break;
      }

      dbIter->advance();
   }
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::openControlDb(void)
{
   if (controlDb_ != nullptr)
      throw WalletInterfaceException("controlDb is not null");

   controlDb_ = make_shared<LMDB>();
   auto tx = LMDBEnv::Transaction(dbEnv_.get(), LMDB::ReadWrite);
   controlDb_->open(dbEnv_.get(), CONTROL_DB_NAME);
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::shutdown()
{
   auto lock = unique_lock<mutex>(setupMutex_);
   if (controlDb_ != nullptr)
   {
      controlDb_->close();
      controlDb_.reset();
   }

   dbMap_.clear();
   dbEnv_->close();
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::openDB(const string& dbName)
{
   auto iter = dbMap_.find(dbName);
   if (iter != dbMap_.end())
      return;

   auto dbiPtr = make_shared<DBInterface>(dbEnv_, dbName, macKey_);
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
shared_ptr<DBIfaceTransaction> WalletDBInterface::beginWriteTransaction(
   const string& dbName)
{
   auto iter = dbMap_.find(dbName);
   if (iter == dbMap_.end())
   {
      if (dbName == CONTROL_DB_NAME)
         return make_shared<RawIfaceTransaction>(dbEnv_, controlDb_, true);

      throw WalletInterfaceException("invalid db name");
   }

   return make_shared<WalletIfaceTransaction>(iter->second, true);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<DBIfaceTransaction> WalletDBInterface::beginReadTransaction(
   const string& dbName)
{
   auto iter = dbMap_.find(dbName);
   if (iter == dbMap_.end())
   {
      if (dbName == CONTROL_DB_NAME)
         return make_shared<RawIfaceTransaction>(dbEnv_, controlDb_, false);

      throw WalletInterfaceException("invalid db name");
   }

   return make_shared<WalletIfaceTransaction>(iter->second, false);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WalletHeader> WalletDBInterface::loadControlHeader()
{
   //grab meta object
   BinaryWriter bw;
   bw.put_uint8_t(WALLETHEADER_PREFIX);
   bw.put_BinaryData(BinaryData(CONTROL_DB_NAME));
   auto& headerKey = bw.getData();

   auto&& tx = beginReadTransaction(CONTROL_DB_NAME);
   auto headerVal = getDataRefForKey(tx, headerKey);
   if (headerVal.getSize() == 0)
      throw WalletInterfaceException("missing control db entry");

   return WalletHeader::deserialize(headerKey, headerVal);
}

////////////////////////////////////////////////////////////////////////////////
void MockDeleteWalletDBInterface(WalletDBInterface* wdbi)
{
   /*
   To create the DecryptedDataContainer for the control header, we need to pass 
   it a shared_ptr of -this-. This dcc is tied to the setupEnv scope, and we do
   not want it to delete -this- when it is destroyed and takes the wdbi 
   shared_ptr with it. Therefor we create a shared_ptr from -this-, passing it
   a deleter that does in effect nothing.
   */
   return;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<DecryptedDataContainer> WalletDBInterface::loadDataContainer(
   shared_ptr<WalletHeader> headerPtr)
{
   //grab decrypted data object
   shared_ptr<WalletDBInterface> ifacePtr(this, MockDeleteWalletDBInterface);
   auto decryptedData = make_shared<DecryptedDataContainer>(
      ifacePtr, headerPtr->dbName_,
      headerPtr->getDefaultEncryptionKey(),
      headerPtr->getDefaultEncryptionKeyId(),
      headerPtr->defaultKdfId_, headerPtr->masterEncryptionKeyId_);
   decryptedData->readFromDisk();
   return decryptedData;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<EncryptedSeed> WalletDBInterface::loadSeed(
   shared_ptr<WalletHeader> headerPtr)
{
   auto&& tx = beginReadTransaction(headerPtr->dbName_);

   BinaryWriter bwKey;
   bwKey.put_uint32_t(WALLET_SEED_KEY);
   auto rootAssetRef = getDataRefForKey(tx, bwKey.getData());

   auto seedPtr = Asset_EncryptedData::deserialize(
      rootAssetRef.getSize(), rootAssetRef);
   auto seedObj = dynamic_pointer_cast<EncryptedSeed>(seedPtr);
   if (seedObj == nullptr)
      throw WalletException("failed to deser wallet seed");

   return seedObj;
}

////////////////////////////////////////////////////////////////////////////////
MasterKeyStruct WalletDBInterface::initWalletHeaderObject(
   shared_ptr<WalletHeader> headerPtr, const SecureBinaryData& passphrase)
{
   /*
   Setup master and top encryption key.

   - The master encryption key encrypts entries in the wallet.

   - The top encryption key encrypts the master encryption key.
     If a user passphrase is provided, it is used to generate the top encryption
     key. Otherwise the default encryption key is used.

   - The default encryption key is 32 byte RNG value written in clear text on
     disk. Its purpose is to prevent divergence in implemenation between
     encrypted and unencrypted wallets.
   */

   if (headerPtr->dbName_.size() == 0)
   {
      string walletIDStr(headerPtr->getWalletIDStr());
      headerPtr->dbName_ = walletIDStr;
   }

   MasterKeyStruct mks;

   /*
   generate master encryption key, derive id
   */
   mks.kdf_ = make_shared<KeyDerivationFunction_Romix>();
   auto&& masterKeySBD = CryptoPRNG::generateRandom(32);
   mks.decryptedMasterKey_ = make_shared<DecryptedEncryptionKey>(masterKeySBD);
   mks.decryptedMasterKey_->deriveKey(mks.kdf_);
   auto&& masterEncryptionKeyId = mks.decryptedMasterKey_->getId(mks.kdf_->getId());

   /*
   create cipher, tie it to master encryption key
   */
   mks.cipher_ = make_unique<Cipher_AES>(mks.kdf_->getId(),
      masterEncryptionKeyId);

   /*
   setup default encryption key, only ever used if no user passphrase is
   provided
   */
   headerPtr->defaultEncryptionKey_ = move(CryptoPRNG::generateRandom(32));
   auto defaultKey = headerPtr->getDefaultEncryptionKey();
   auto defaultEncryptionKeyPtr = make_unique<DecryptedEncryptionKey>(defaultKey);
   defaultEncryptionKeyPtr->deriveKey(mks.kdf_);
   headerPtr->defaultEncryptionKeyId_ =
      defaultEncryptionKeyPtr->getId(mks.kdf_->getId());

   /*
   encrypt master encryption key with passphrase if present, otherwise use
   default key
   */
   unique_ptr<DecryptedEncryptionKey> topEncryptionKey;
   if (passphrase.getSize() > 0)
   {
      //copy passphrase
      auto&& passphraseCopy = passphrase.copy();
      topEncryptionKey = make_unique<DecryptedEncryptionKey>(passphraseCopy);
   }
   else
   {
      LOGWARN << "Wallet created without password, using default encryption key";
      topEncryptionKey = move(defaultEncryptionKeyPtr);
   }

   /*
   derive encryption key id
   */
   topEncryptionKey->deriveKey(mks.kdf_);
   auto&& topEncryptionKeyId = topEncryptionKey->getId(mks.kdf_->getId());

   /*
   create cipher for top encryption key
   */
   auto&& masterKeyCipher = mks.cipher_->getCopy(topEncryptionKeyId);

   /*
   encrypt the master encryption key with the top encryption key
   */
   auto&& encrMasterKey = masterKeyCipher->encrypt(
      topEncryptionKey.get(), mks.kdf_->getId(), 
      mks.decryptedMasterKey_.get());

   /*
   create encryption key object
   */
   mks.masterKey_ = make_shared<Asset_EncryptionKey>(masterEncryptionKeyId,
      encrMasterKey, move(masterKeyCipher));

   /*
   set master encryption key relevant ids in the WalletMeta object
   */
   headerPtr->masterEncryptionKeyId_ = mks.masterKey_->getId();
   headerPtr->defaultKdfId_ = mks.kdf_->getId();

   return move(mks);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WalletHeader_Control> WalletDBInterface::setupControlDB(
   const SecureBinaryData& passphrase)
{
   //create control meta object
   auto headerPtr = make_shared<WalletHeader_Control>();
   headerPtr->walletID_ = BinaryData(CONTROL_DB_NAME);
   auto keyStruct = initWalletHeaderObject(headerPtr, passphrase);

   //setup controlDB decrypted data container
   shared_ptr<WalletDBInterface> ifacePtr(this, MockDeleteWalletDBInterface);
   auto decryptedData = make_shared<DecryptedDataContainer>(
      ifacePtr, CONTROL_DB_NAME,
      headerPtr->defaultEncryptionKey_,
      headerPtr->defaultEncryptionKeyId_,
      headerPtr->defaultKdfId_,
      headerPtr->masterEncryptionKeyId_);
   decryptedData->addEncryptionKey(keyStruct.masterKey_);
   decryptedData->addKdf(keyStruct.kdf_);

   //if custom passphrase, set prompt lambda prior to encryption
   if (passphrase.getSize() > 0)
   {
      auto passphraseLambda =
         [&passphrase](const set<BinaryData>&)->SecureBinaryData
      {
         return passphrase;
      };

      decryptedData->setPassphrasePromptLambda(passphraseLambda);
   }

   {
      //create encrypted seed object
      auto&& seed = CryptoPRNG::generateRandom(32);
      auto&& lock = ReentrantLock(decryptedData.get());

      auto cipherCopy = keyStruct.cipher_->getCopy();
      auto&& cipherText = decryptedData->encryptData(
         cipherCopy.get(), seed);
      auto encrSeed = make_shared<EncryptedSeed>(cipherText, move(cipherCopy));

      //write seed to disk
      auto&& tx = beginWriteTransaction(CONTROL_DB_NAME);

      BinaryWriter seedKey;
      seedKey.put_uint32_t(WALLET_SEED_KEY);
      auto&& seedVal = encrSeed->serialize();
      tx->insert(seedKey.getData(), seedVal);

      //write meta ptr to disk
      auto&& metaKey = headerPtr->getDbKey();
      auto&& metaVal = headerPtr->serialize();
      tx->insert(metaKey, metaVal);

      //write decrypted data container to disk
      decryptedData->updateOnDisk();
   }

   return headerPtr;
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::putHeader(shared_ptr<WalletHeader> headerPtr)
{
   //masterID
   if(headerPtr->masterID_.getSize() == 0)
      throw WalletException("header has no master id");

   BinaryWriter bwKey;
   bwKey.put_uint32_t(MASTERID_KEY);

   auto&& tx = beginWriteTransaction(WALLETHEADER_DBNAME);
   auto idVal = tx->getDataRef(bwKey.getData());
   if (idVal.getSize() == 0)
   {
      BinaryWriter bwData;
      bwData.put_var_int(headerPtr->masterID_.getSize());
      bwData.put_BinaryDataRef(headerPtr->masterID_);
      tx->insert(bwKey.getData(), bwData.getData());
   }
   else if(idVal != headerPtr->masterID_)
   {
      //the master key is already set, this is an existing wallet, abort
      throw WalletException("trying to init an already existing wallet");
   }

   //header data
   auto&& key = headerPtr->getDbKey();
   auto&& val = headerPtr->serialize();
   tx->insert(key, val);
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::setMainWallet(const BinaryData& walletID)
{
   BinaryWriter bwKey;
   bwKey.put_uint32_t(MAINWALLET_KEY);

   BinaryWriter bwData;
   bwData.put_var_int(walletID.getSize());
   bwData.put_BinaryData(walletID);

   auto&& tx = beginWriteTransaction(WALLETHEADER_DBNAME);
   tx->insert(bwKey.getData(), bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::addHeader(std::shared_ptr<WalletHeader> headerPtr)
{
   auto lock = unique_lock<mutex>(setupMutex_);
   auto iter = headerMap_.insert(make_pair(headerPtr->walletID_, headerPtr));
   if (!iter.second)
      throw WalletInterfaceException("header already in map");
   putHeader(headerPtr);

   auto& dbName = headerPtr->dbName_;
   if (dbName.size() == 0)
      throw WalletInterfaceException("empty dbname");

   auto dbIter = dbMap_.find(dbName);
   if (dbIter != dbMap_.end())
      return;

   auto dbiPtr = make_shared<DBInterface>(dbEnv_, dbName, macKey_);
   dbMap_.insert(make_pair(dbName, dbiPtr));
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WalletHeader> WalletDBInterface::getMainWalletHeader()
{
   auto iter = headerMap_.find(mainWalletID_);
   if (iter == headerMap_.end())
      throw WalletException("missing main wallet header");
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
const map<BinaryData, shared_ptr<WalletHeader>>& 
WalletDBInterface::getHeaderMap() const
{
   return headerMap_;
}

////////////////////////////////////////////////////////////////////////////////
unsigned WalletDBInterface::getDbCount() const
{
   return headerMap_.size();
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::setDbCount(unsigned count)
{
   //add 2 for the control and headers db
   setDbCount(count + 2, true);
}

////////////////////////////////////////////////////////////////////////////////
void WalletDBInterface::setDbCount(unsigned count, bool doLock)
{
   if (count == dbCount_)
      return;

   auto lock = unique_lock<mutex>(setupMutex_, defer_lock);
   if (doLock)
      lock.lock();

   //close env
   if (controlDb_ != nullptr)
   {
      controlDb_->close();
      controlDb_.reset();
   }

   for (auto& dbPtr : dbMap_)
      dbPtr.second->close();

   dbEnv_->close();
   dbEnv_.reset();

   //reopen with new dbCount
   dbEnv_ = std::make_shared<LMDBEnv>(count);
   dbEnv_->open(path_, MDB_WRITEMAP);

   for (auto& dbPtr : dbMap_)
   {
      auto&& tx = beginWriteTransaction(dbPtr.first);
      dbPtr.second->reset(dbEnv_);
   }

   dbCount_ = count;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DBIfaceIterator
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
DBIfaceIterator::~DBIfaceIterator()
{}

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
//// RawIfaceIterator
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
bool RawIfaceIterator::isValid() const
{
   return iterator_.isValid();
}

////////////////////////////////////////////////////////////////////////////////
void RawIfaceIterator::seek(const BinaryDataRef& key)
{
   CharacterArrayRef carKey(key.getSize(), key.getPtr());
   iterator_.seek(carKey, LMDB::Iterator::SeekBy::Seek_GE);
}

////////////////////////////////////////////////////////////////////////////////
void RawIfaceIterator::advance()
{
   ++iterator_;
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef RawIfaceIterator::key() const
{
   auto val = iterator_.key();
   return BinaryDataRef((const uint8_t*)val.mv_data, val.mv_size);
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef RawIfaceIterator::value() const
{
   auto val = iterator_.value();
   return BinaryDataRef((const uint8_t*)val.mv_data, val.mv_size);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DBIfaceTransaction
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
DBIfaceTransaction::~DBIfaceTransaction()
{}

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
   DBIfaceTransaction(), dbPtr_(dbPtr), commit_(mode)
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

         //wipe the key
         CharacterArrayRef carKey(dbKey.getSize(), dbKey.getPtr());
         dbPtr_->db_.wipe(carKey);

         //write in the erased place holder
         auto&& dbVal = DBInterface::createDataPacket(
            dbKey, dataPtr->key_, BinaryData("erased"), dbPtr_->macKey_);
         CharacterArrayRef carData(dbVal.getSize(), dbVal.getPtr());
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
      auto&& dbVal = DBInterface::createDataPacket(
         dbKey, dataPtr->key_, dataPtr->value_, dbPtr_->macKey_);
      CharacterArrayRef carKey(dbKey.getSize(), dbKey.getPtr());
      CharacterArrayRef carVal(dbVal.getSize(), dbVal.getPtr());

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
std::shared_ptr<DBIfaceIterator> WalletIfaceTransaction::getIterator() const
{
   if (commit_)
      throw WalletInterfaceException("cannot iterate over a write transaction");

   return make_shared<WalletIfaceIterator>(dbPtr_);
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

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// RawIfaceTransaction
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void RawIfaceTransaction::insert(const BinaryData& key, const BinaryData& val)
{
   CharacterArrayRef carKey(key.getSize(), key.getPtr());
   CharacterArrayRef carVal(val.getSize(), val.getPtr());
   dbPtr_->insert(carKey, carVal);
}

////////////////////////////////////////////////////////////////////////////////
void RawIfaceTransaction::erase(const BinaryData& key)
{
   CharacterArrayRef carKey(key.getSize(), key.getPtr());
   dbPtr_->erase(carKey);
}

////////////////////////////////////////////////////////////////////////////////
void RawIfaceTransaction::wipe(const BinaryData& key)
{
   CharacterArrayRef carKey(key.getSize(), key.getPtr());
   dbPtr_->wipe(carKey);
}

////////////////////////////////////////////////////////////////////////////////
const BinaryDataRef RawIfaceTransaction::getDataRef(const BinaryData& key) const
{
   CharacterArrayRef carKey(key.getSize(), key.getPtr());
   auto&& carVal = dbPtr_->get_NoCopy(carKey);

   if (carVal.len == 0)
      return BinaryDataRef();

   BinaryDataRef result((const uint8_t*)carVal.data, carVal.len);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<DBIfaceIterator> RawIfaceTransaction::getIterator() const
{
   return make_shared<RawIfaceIterator>(dbPtr_);
}
