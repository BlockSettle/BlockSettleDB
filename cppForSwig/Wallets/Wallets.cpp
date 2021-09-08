////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2019, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ArmoryConfig.h"
#include "Wallets.h"
#include "WalletFileInterface.h"

using namespace std;
using namespace ArmorySigner;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetWallet::AssetWallet(
   shared_ptr<WalletDBInterface> iface,
   shared_ptr<WalletHeader> headerPtr, 
   const string& masterID) :
   iface_(iface), 
   dbName_(headerPtr->getDbName()),
   walletID_(headerPtr->walletID_)
{
   auto ifaceCopy = iface_;
   auto getWriteTx = [ifaceCopy](const string& name)->
      unique_ptr<DBIfaceTransaction>
   {
      return ifaceCopy->beginWriteTransaction(name);
   };
   
   decryptedData_ = make_shared<DecryptedDataContainer>(
      getWriteTx, dbName_,
      headerPtr->getDefaultEncryptionKey(),
      headerPtr->getDefaultEncryptionKeyId(),
      headerPtr->defaultKdfId_, headerPtr->masterEncryptionKeyId_);
   checkMasterID(masterID);
}

////////////////////////////////////////////////////////////////////////////////
AssetWallet::~AssetWallet()
{
   accounts_.clear();
   iface_.reset();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WalletDBInterface> AssetWallet::getIfaceFromFile(
    const string& path, const PassphraseLambda& passLbd)
{
   /*
   This passphrase lambda is used to prompt the user for the wallet file's
   passphrase. Private keys use a different passphrase, with its own prompt.
   */

   auto iface = make_shared<WalletDBInterface>();
   iface->setupEnv(path, passLbd);

   return iface;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<WalletDBInterface> AssetWallet::getIface() const
{
   return iface_;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressAccount> AssetWallet::createAccount(
   shared_ptr<AccountType> accountType)
{
   auto cipher = make_unique<Cipher_AES>(
      decryptedData_->getDefaultKdfId(),
      decryptedData_->getMasterEncryptionKeyId());

   //instantiate AddressAccount object from AccountType
   auto ifaceCopy = iface_;
   auto getWriteTx = [ifaceCopy](const string& name)->
      unique_ptr<DBIfaceTransaction>
   {
      return ifaceCopy->beginWriteTransaction(name);
   };
   auto account_ptr = make_shared<AddressAccount>(dbName_, getWriteTx);

   account_ptr->make_new(accountType, decryptedData_, move(cipher));
   auto accID = account_ptr->getID();
   if (accounts_.find(accID) != accounts_.end())
      throw WalletException("already have an address account with this path");

   //commit to disk
   account_ptr->commit(iface_);

   if (accountType->isMain())
   {
      mainAccount_ = account_ptr->getID();

      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

      BinaryWriter bwData;
      bwData.put_var_int(mainAccount_.getSize());
      bwData.put_BinaryData(mainAccount_);

      auto&& tx = iface_->beginWriteTransaction(dbName_);
      tx->insert(bwKey.getData(), bwData.getData());
   }

   accounts_.insert(make_pair(accID, account_ptr));
   return account_ptr;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::setMainWallet(
   shared_ptr<WalletDBInterface> iface, const string& walletID)
{
   BinaryWriter bwKey;
   bwKey.put_uint32_t(MAINWALLET_KEY);

   BinaryWriter bwData;
   bwData.put_var_int(walletID.size());
   bwData.put_String(walletID);

   auto&& tx = iface->beginWriteTransaction(WALLETHEADER_DBNAME);
   tx->insert(bwKey.getData(), bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet::getMainWalletID(shared_ptr<WalletDBInterface> iface)
{
   BinaryWriter bwKey;
   bwKey.put_uint32_t(MAINWALLET_KEY);

   try
   {
      auto&& tx = iface->beginWriteTransaction(WALLETHEADER_DBNAME);   
      auto dataRef = getDataRefForKey(tx.get(), bwKey.getData());
      
      string idStr(dataRef.toCharPtr(), dataRef.getSize());
      return idStr;
   }
   catch (NoEntryInWalletException&)
   {
      LOGERR << "main wallet ID is not set!";
      throw WalletException("main wallet ID is not set!");
   }
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet::getMasterID(shared_ptr<WalletDBInterface> iface)
{
   BinaryWriter bwKey;
   bwKey.put_uint32_t(MASTERID_KEY);

   auto tx = iface->beginReadTransaction(WALLETHEADER_DBNAME);
   auto dataRef = getDataRefForKey(tx.get(), bwKey.getData());

   string masterID(dataRef.toCharPtr(), dataRef.getSize());
   return masterID;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::checkMasterID(const string& masterID)
{
   try
   {
      /*
      Grab ID from disk, check it matches arg.
      */

      auto fromDisk = getMasterID(iface_);

      //sanity check
      if (fromDisk.size() == 0)
      {
         LOGERR << "empty master ID";
         throw WalletException("empty master ID");
      }

      //only compare disk value with arg if the arg isn't empty
      if (masterID.size() != 0 && masterID != fromDisk)
      {
         LOGERR << "masterID mismatch, aborting";
         throw WalletException("masterID mismatch, aborting");
      }

      //set masterID_ from disk value
      masterID_ = fromDisk;
      return;
   }
   catch(NoEntryInWalletException&)
   {}
      
   /*
   This wallet has no masterID entry if we got this far, let's set it.
   */

   //sanity check
   if (masterID.size() == 0)
   {
      LOGERR << "cannot set empty master ID";
      throw WalletException("cannot set empty master ID");
   }

   BinaryWriter bwKey;
   bwKey.put_uint32_t(MASTERID_KEY);

   BinaryWriter bwVal;
   bwVal.put_var_int(masterID.size());
   bwVal.put_String(masterID);

   auto tx = iface_->beginWriteTransaction(WALLETHEADER_DBNAME);
   tx->insert(bwKey.getData(), bwVal.getData());

   masterID_ = masterID;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::readFromFile()
{
   //sanity check
   if (iface_ == nullptr)
      throw WalletException("uninitialized wallet object");

   auto uniqueTx = iface_->beginReadTransaction(dbName_);
   shared_ptr<DBIfaceTransaction> sharedTx(move(uniqueTx));

   {
      //main account
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

      try
      {
         auto account_id = getDataRefForKey(sharedTx.get(), bwKey.getData());

         mainAccount_ = account_id;
      }
      catch (NoEntryInWalletException&)
      { }
   }

   {
      //root asset
      root_ = nullptr;

      try
      {
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);
         auto rootAssetRef = getDataRefForKey(sharedTx.get(), bwKey.getData());

         auto asset_root = AssetEntry::deserDBValue(-1, BinaryData(), rootAssetRef);
         root_ = dynamic_pointer_cast<AssetEntry_Single>(asset_root);
      }
      catch(NoEntryInWalletException&)
      {}
   }

   {
      //seed
      seed_ = nullptr;

      try
      {
         BinaryWriter bwKey;
         bwKey.put_uint32_t(WALLET_SEED_KEY);
         auto rootAssetRef = getDataRefForKey(sharedTx.get(), bwKey.getData());

         auto seedUPtr = Asset_EncryptedData::deserialize(
            rootAssetRef.getSize(), rootAssetRef);
         shared_ptr<Asset_EncryptedData> seedSPtr(move(seedUPtr));
         auto seedObj = dynamic_pointer_cast<EncryptedSeed>(seedSPtr);
         if (seedObj == nullptr)
            throw WalletException("failed to deser wallet seed");

         seed_ = seedObj;
      }
      catch(NoEntryInWalletException&)
      {}
   }

   {
      //label
      BinaryWriter bwKey;
      bwKey.put_uint32_t(WALLET_LABEL_KEY);
      try
      {
         auto labelRef = getDataRefForKey(sharedTx.get(), bwKey.getData());
         label_ = string(labelRef.toCharPtr(), labelRef.getSize());
      }
      catch(NoEntryInWalletException& )
      {}
   }

   {
      //description
      BinaryWriter bwKey;
      bwKey.put_uint32_t(WALLET_DESCR_KEY);
      try
      {
         auto labelRef = getDataRefForKey(sharedTx.get(), bwKey.getData());
         description_ = string(labelRef.toCharPtr(), labelRef.getSize());
      }
      catch(NoEntryInWalletException& )
      {}
   }

   //encryption keys and kdfs
   decryptedData_->readFromDisk(sharedTx);

   {
      //accounts
      BinaryWriter bwPrefix;
      bwPrefix.put_uint8_t(ADDRESS_ACCOUNT_PREFIX);
      auto dbIter = sharedTx->getIterator();
      dbIter->seek(bwPrefix.getDataRef());

      while (dbIter->isValid())
      {
         //iterate through account keys
         auto&& key = dbIter->key();

         try
         {
            //instantiate account object and read data on disk
            auto ifaceCopy = iface_;
            auto getWriteTx = [ifaceCopy](const string& name)->
               unique_ptr<DBIfaceTransaction>
            {
               return ifaceCopy->beginWriteTransaction(name);
            };

            auto addressAccount = make_shared<AddressAccount>(dbName_, getWriteTx);
            addressAccount->readFromDisk(iface_, key);

            //insert
            accounts_.insert(make_pair(addressAccount->getID(), addressAccount));
         }
         catch (exception&)
         {
            //in case of exception, the value for this key is not for an
            //account. Assume we ran out of accounts and break out.
            break;
         }

         dbIter->advance();
      }

      loadMetaAccounts();
   }
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewAddress(
   AddressEntryType aeType)
{
   /***
   The wallet will always try to deliver an address with the requested type if 
   any of its accounts supports it. It will prioritize the main account, then
   try through all accounts in binary order.
   ***/

   //lock
   ReentrantLock lock(this);

   if (mainAccount_.getSize() == 0)
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->getNewAddress(aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->getNewAddress(aeType);
   }

   throw WalletException("unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewChangeAddress(
   AddressEntryType aeType)
{
   ReentrantLock lock(this);

   if (mainAccount_.getSize() == 0)
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->getNewChangeAddress(aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->getNewChangeAddress(aeType);
   }

   throw WalletException("unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::peekNextChangeAddress(
   AddressEntryType aeType)
{
   ReentrantLock lock(this);

   if (mainAccount_.getSize() == 0)
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->peekNextChangeAddress(aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->peekNextChangeAddress(aeType);
   }

   throw WalletException("unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::updateAddressEntryType(
   const BinaryData& assetID, AddressEntryType aeType)
{
   ReentrantLock lock(this);

   auto accPtr = getAccountForID(assetID);
   accPtr->updateInstantiatedAddressType(assetID, aeType);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewAddress(
   const BinaryData& accountID, AddressEntryType aeType)
{
   ReentrantLock lock(this);

   auto account = getAccountForID(accountID);
   auto newAddress = account->getNewAddress(aeType);

   return newAddress;
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet::hasAddrStr(const string& addrStr) const
{
   try
   {
      getAssetIDForAddrStr(addrStr);
   }
   catch (runtime_error&)
   {
      return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet::hasScrAddr(const BinaryData& scrAddr) const
{
   try
   {
      getAssetIDForScrAddr(scrAddr);
   }
   catch (runtime_error&)
   {
      return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
const pair<BinaryData, AddressEntryType>& 
   AssetWallet::getAssetIDForAddrStr(const string& addrStr) const
{
   //this takes b58 or bech32 addresses

   ReentrantLock lock(this);
   
   BinaryData scrAddr;

   try
   {
      scrAddr = move(BtcUtils::base58toScrAddr(addrStr));
   }
   catch(runtime_error&)
   {
      scrAddr = move(BtcUtils::segWitAddressToScrAddr(addrStr));
   }

   return getAssetIDForScrAddr(scrAddr);
}

////////////////////////////////////////////////////////////////////////////////
const pair<BinaryData, AddressEntryType>&
   AssetWallet::getAssetIDForScrAddr(const BinaryData& scrAddr) const
{
   //this takes prefixed hashes

   ReentrantLock lock(this);

   for (auto acc : accounts_)
   {
      try
      {
         return acc.second->getAssetIDPairForAddr(scrAddr);
      }
      catch (runtime_error&)
      {
         continue;
      }
   }

   throw runtime_error("unknown scrAddr");
}


////////////////////////////////////////////////////////////////////////////////
AddressEntryType AssetWallet::getAddrTypeForID(const BinaryData& ID)
{
   ReentrantLock lock(this);
   
   auto addrPtr = getAddressEntryForID(ID);
   return addrPtr->getType();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressAccount> AssetWallet::getAccountForID(
   const BinaryData& ID) const
{
   if (ID.getSize() < 4)
      throw WalletException("invalid account id");

   ReentrantLock lock(this);

   auto idRef = ID.getSliceRef(0, 4);
   auto iter = accounts_.find(idRef);
   if (iter == accounts_.end())
      throw WalletException("unknown account ID");

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
const string& AssetWallet::getDbFilename(void) const
{ 
   if (iface_ == nullptr)
      throw WalletException("uninitialized db environment");
   return iface_->getFilename(); 
}

////////////////////////////////////////////////////////////////////////////////
const string& AssetWallet::getDbName(void) const
{ 
   return dbName_;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::shutdown()
{
   if (iface_ == nullptr)
      return;

   iface_.reset();
}

////////////////////////////////////////////////////////////////////////////////
AddressEntryType AssetWallet::getAddrTypeForAccount(const BinaryData& ID)
{
   auto acc = getAccountForID(ID);
   return acc->getAddressType();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getAddressEntryForID(
   const BinaryData& ID) const
{
   ReentrantLock lock(this);

   if (ID.getSize() != 12)
      throw WalletException("invalid asset id");

   auto accPtr = getAccountForID(ID);
   return accPtr->getAddressEntryForID(ID.getRef());
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::updateHashMap()
{
   ReentrantLock lock(this);

   for (auto account : accounts_)
      account.second->updateAddressHashMap();
}

////////////////////////////////////////////////////////////////////////////////
set<BinaryData> AssetWallet::getAddrHashSet()
{
   ReentrantLock lock(this);

   set<BinaryData> addrHashSet;
   for (auto account : accounts_)
   {
      auto& hashes = account.second->getAddressHashMap();

      for (auto& hashPair : hashes)
         addrHashSet.insert(hashPair.first);
   }

   return addrHashSet;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetWallet::getAssetForID(const BinaryData& ID) const
{
   if (ID.getSize() < 8)
      throw WalletException("invalid asset ID");

   ReentrantLock lock(this);

   auto acc = getAccountForID(ID);
   return acc->getAssetForID(ID.getSliceRef(4, ID.getSize() - 4));
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet::getID(void) const
{
   return walletID_;
}

////////////////////////////////////////////////////////////////////////////////
ReentrantLock AssetWallet::lockDecryptedContainer(void)
{
   return move(ReentrantLock(decryptedData_.get()));
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet::isDecryptedContainerLocked() const
{
   try
   {
      auto lock = SingleLock(decryptedData_.get());
      return false;
   }
   catch (AlreadyLocked&)
   {}

   return true;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPublicChain(unsigned count)
{
   for (auto& account : accounts_)
   {
      account.second->extendPublicChain(count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPrivateChain(unsigned count)
{
   for (auto& account : accounts_)
   {
      account.second->extendPrivateChain(decryptedData_, count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPublicChainToIndex(
   const BinaryData& account_id, unsigned count)
{
   auto account = getAccountForID(account_id);
   account->extendPublicChainToIndex(
      account->getOuterAccount()->getID(), count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPrivateChainToIndex(
   const BinaryData& account_id, unsigned count)
{
   auto account = getAccountForID(account_id);
   account->extendPrivateChainToIndex(
      decryptedData_,
      account->getOuterAccount()->getID(), count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::addSubDB(
   const std::string& dbName, const PassphraseLambda& passLbd)
{
   if (iface_->getFreeDbCount() == 0)
      iface_->setDbCount(iface_->getDbCount() + 1);

   auto headerPtr = make_shared<WalletHeader_Custom>();
   headerPtr->walletID_ = dbName;

   try
   {   
      iface_->lockControlContainer(passLbd);
      iface_->addHeader(headerPtr);
      iface_->unlockControlContainer();
   }
   catch (...)
   {
      iface_->unlockControlContainer();
      rethrow_exception(current_exception());
   }
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<DBIfaceTransaction> AssetWallet::beginSubDBTransaction(
   const string& dbName, bool write)
{
   if (!write)
      return iface_->beginReadTransaction(dbName);
   else
      return iface_->beginWriteTransaction(dbName);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet> AssetWallet::loadMainWalletFromFile(
   const string& path, const PassphraseLambda& passLbd)
{
   auto iface = getIfaceFromFile(path.c_str(), passLbd);
   auto mainWalletID = getMainWalletID(iface);
   auto headerPtr = iface->getWalletHeader(mainWalletID);

   shared_ptr<AssetWallet> wltPtr;

   switch (headerPtr->type_)
   {
   case WalletHeaderType_Single:
   {
      auto wltSingle = make_shared<AssetWallet_Single>(
         iface, headerPtr, string());
      wltSingle->readFromFile();

      wltPtr = wltSingle;
      break;
   }

   case WalletHeaderType_Multisig:
   {
      auto wltMS = make_shared<AssetWallet_Multisig>(
         iface, headerPtr, string());
      wltMS->readFromFile();

      wltPtr = wltMS;
      break;
   }

   default:
      throw WalletException("unexpected main wallet type");
   }

   return wltPtr;
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef AssetWallet::getDataRefForKey(
   DBIfaceTransaction* tx, const BinaryData& key)
{
   /** The reference lifetime is tied to the db tx lifetime. The caller has to
   maintain the tx for as long as the data ref needs to be valid **/

   auto ref = tx->getDataRef(key);

   if (ref.getSize() == 0)
      throw NoEntryInWalletException();

   return DBUtils::getDataRefForPacket(ref);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::addMetaAccount(MetaAccountType type)
{
   auto account_ptr = make_shared<MetaDataAccount>(dbName_);
   account_ptr->make_new(type);

   //do not overwrite existing account of the same type
   if (metaDataAccounts_.find(type) != metaDataAccounts_.end())
      return;

   auto tx = iface_->beginWriteTransaction(dbName_);
   account_ptr->commit(move(tx));
   metaDataAccounts_.insert(make_pair(type, account_ptr));
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::loadMetaAccounts()
{
   auto&& tx = iface_->beginReadTransaction(dbName_);

   //accounts
   BinaryWriter bwPrefix;
   bwPrefix.put_uint8_t(META_ACCOUNT_PREFIX);
   auto dbIter = tx->getIterator();
   dbIter->seek(bwPrefix.getDataRef());

   while (dbIter->isValid())
   {
      //iterate through account keys
      auto&& key = dbIter->key();

      try
      {
         //instantiate account object and read data on disk
         auto metaAccount = make_shared<MetaDataAccount>(dbName_);
         metaAccount->readFromDisk(iface_, key);

         //insert
         metaDataAccounts_.insert(
            make_pair(metaAccount->getType(), metaAccount));
      }
      catch (exception&)
      {
         //in case of exception, the value for this key is not for an
         //account. Assume we ran out of accounts and break out.
         break;
      }

      dbIter->advance();
   }
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaDataAccount> AssetWallet::getMetaAccount(
   MetaAccountType type) const
{
   auto iter = metaDataAccounts_.find(type);

   if (iter == metaDataAccounts_.end())
      throw WalletException("no meta account for this type");
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet::forkWatchingOnly(
   const string& filename, const PassphraseLambda& passLbd)
{
   //strip '_wallet' extention
   auto underscoreIndex = filename.find_last_of("_");
   auto newname = filename.substr(0, underscoreIndex);

   //set WO suffix
   newname.append("_WatchingOnly.lmdb");

   //check file does not exist
   if (DBUtils::fileExists(newname, 0))
      throw WalletException("WO wallet filename already exists");

   //open original wallet db & new 
   auto originIface = getIfaceFromFile(filename, passLbd);
   auto masterID = getMasterID(originIface);

   auto woIface = getIfaceFromFile(newname, passLbd);
   woIface->setDbCount(originIface->getDbCount());
   woIface->lockControlContainer(passLbd);

   //cycle through wallet metas, copy wallet structure and assets
   for (auto& metaPtr : originIface->getHeaderMap())
   {
      switch (metaPtr.second->type_)
      {
      case WalletHeaderType_Single:
      {
         woIface->addHeader(metaPtr.second);

         //load wallet
         auto wltSingle = make_shared<AssetWallet_Single>(
            originIface, metaPtr.second, masterID);
         wltSingle->readFromFile();

         //copy content
         AssetWallet_Single::copyPublicData(wltSingle, woIface);

         //close the wallet
         wltSingle.reset();
         break;
      }

      default:
         LOGWARN << "wallet contains header types that " <<
            "aren't covered by WO forking";
      }
   }

   //set main wallet id
   setMainWallet(woIface, getMainWalletID(originIface));

   //close dbs
   originIface.reset();
   woIface->unlockControlContainer();
   woIface.reset();

   //return the file name of the wo wallet
   return newname;
}

////////////////////////////////////////////////////////////////////////////////
set<BinaryData> AssetWallet::getAccountIDs(void) const
{
   set<BinaryData> result;
   for (auto& accPtr : accounts_)
      result.insert(accPtr.second->getID());

   return result;
}

////////////////////////////////////////////////////////////////////////////////
map<BinaryData, shared_ptr<AddressEntry>> AssetWallet::getUsedAddressMap() const
{
   /***
   This is an expensive call, do not spam it.
   ***/

   map<BinaryData, shared_ptr<AddressEntry>> result;
   for (auto& account : accounts_)
   {
      auto&& addrMap = account.second->getUsedAddressMap();
      result.insert(addrMap.begin(), addrMap.end());
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::changeControlPassphrase(
   const function<SecureBinaryData(void)>& newPassLbd, 
   const PassphraseLambda& passLbd)
{
   iface_->changeControlPassphrase(newPassLbd, passLbd);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::eraseControlPassphrase(const PassphraseLambda& passLbd)
{
   iface_->eraseControlPassphrase(passLbd);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::setComment(const BinaryData& key, const string& comment)
{
   auto accPtr = getMetaAccount(MetaAccountType::MetaAccount_Comments);
   auto uniqueTx = iface_->beginWriteTransaction(dbName_);
   shared_ptr<DBIfaceTransaction> sharedTx(move(uniqueTx));
   CommentAssetConversion::setAsset(accPtr.get(), key, comment, sharedTx);
}

////////////////////////////////////////////////////////////////////////////////
const string& AssetWallet::getComment(const BinaryData& key) const
{
   auto accPtr = getMetaAccount(MetaAccountType::MetaAccount_Comments);
   auto assetPtr = CommentAssetConversion::getByKey(accPtr.get(), key);

   if (assetPtr == nullptr)
      throw WalletException("no comment for key");

   return assetPtr->getValue();
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::deleteComment(const BinaryData& key)
{
   auto accPtr = getMetaAccount(MetaAccountType::MetaAccount_Comments);
   auto uniqueTx = iface_->beginWriteTransaction(dbName_);
   shared_ptr<DBIfaceTransaction> sharedTx(move(uniqueTx));
   CommentAssetConversion::deleteAsset(accPtr.get(), key, sharedTx);
}

////////////////////////////////////////////////////////////////////////////////
map<BinaryData, string> AssetWallet::getCommentMap() const
{
   auto accPtr = getMetaAccount(MetaAccountType::MetaAccount_Comments);
   return CommentAssetConversion::getCommentMap(accPtr.get());
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::setLabel(const string& str)
{
   label_ = str;
   
   BinaryWriter bwKey;
   bwKey.put_uint32_t(WALLET_LABEL_KEY);
   BinaryWriter bwData;
   bwData.put_var_int(str.size());
   bwData.put_String(str);

   auto tx = iface_->beginWriteTransaction(dbName_);
   tx->insert(bwKey.getDataRef(), bwData.getDataRef());
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::setDescription(const string& str)
{
   description_ = str;
   
   BinaryWriter bwKey;
   bwKey.put_uint32_t(WALLET_DESCR_KEY);
   BinaryWriter bwData;
   bwData.put_var_int(str.size());
   bwData.put_String(str);

   auto tx = iface_->beginWriteTransaction(dbName_);
   tx->insert(bwKey.getDataRef(), bwData.getDataRef());
}

////////////////////////////////////////////////////////////////////////////////
const string& AssetWallet::getLabel() const
{
   return label_;
}

////////////////////////////////////////////////////////////////////////////////
const string& AssetWallet::getDescription() const
{
   return description_;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::eraseFromDisk(AssetWallet* wltPtr)
{
   if (wltPtr == nullptr)
      throw runtime_error("null wltPtr");

   auto ifaceCopy = move(wltPtr->iface_);
   ifaceCopy->eraseFromDisk();
   ifaceCopy.reset();
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet_Single
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetWallet_Single::createBIP32Account(
   std::shared_ptr<AccountType_BIP32> accTypePtr)
{
   //passes wallet's root as parent
   auto root = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);
   return createBIP32Account_WithParent(root, accTypePtr);
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetWallet_Single::createBIP32Account_WithParent(
   std::shared_ptr<AssetEntry_BIP32Root> root,
   std::shared_ptr<AccountType_BIP32> accTypePtr)
{
   if (root == nullptr)
      throw AccountException("no valid root to create BIP32 account from");

   bool isDerived = false;
   if (root->getPrivKey() != nullptr)
   {
      //try to decrypt the root's private key to get full derivation
      try
      {
         //lock for decryption
         auto lock = lockDecryptedContainer();

         //decrypt root
         auto privKey = decryptedData_->getDecryptedPrivateData(
            root->getPrivKey());
         auto chaincode = root->getChaincode();

         //derive account root
         BIP32_Node bip32Node;
         bip32Node.initFromPrivateKey(
            root->getDepth(), root->getLeafID(), root->getParentFingerprint(),
            privKey, chaincode);
         for (auto& path : accTypePtr->getDerivationPath())
            bip32Node.derivePrivate(path);

         auto derivedKey = bip32Node.movePrivateKey();
         auto derivedCode = bip32Node.moveChaincode();
         auto pubkey = CryptoECDSA().ComputePublicKey(derivedKey, true);

         accTypePtr->setChaincode(derivedCode);
         accTypePtr->setPrivateKey(derivedKey);
         accTypePtr->setPublicKey(pubkey);
         accTypePtr->setFingerprint(bip32Node.getParentFingerprint());

         accTypePtr->setDepth(bip32Node.getDepth());
         accTypePtr->setLeafId(bip32Node.getLeafID());
         
         isDerived = true;
      }
      catch (exception&)
      {
         isDerived = false;
      }
   }

   if (!isDerived)
   {
      //can't get the private key, if we can derive this only from 
      //the pubkey then do it, otherwise it will throw

      auto pubkey = root->getPubKey()->getCompressedKey();
      auto chaincode = root->getChaincode();

      BIP32_Node bip32Node;
      bip32Node.initFromPublicKey(
         root->getDepth(), root->getLeafID(), root->getParentFingerprint(),
         pubkey, chaincode);
      for (auto& path : accTypePtr->getDerivationPath())
         bip32Node.derivePublic(path);

      auto derivedKey = bip32Node.movePublicKey();
      auto derivedCode = bip32Node.moveChaincode();

      accTypePtr->setChaincode(derivedCode);
      accTypePtr->setPublicKey(derivedKey);
      accTypePtr->setFingerprint(bip32Node.getParentFingerprint());

      accTypePtr->setDepth(bip32Node.getDepth());
      accTypePtr->setLeafId(bip32Node.getLeafID());
   }

   //update the derivation path, it should be root's + account's
   vector<unsigned> derivationPath = root->getDerivationPath();
   for (auto& path : accTypePtr->getDerivationPath())
      derivationPath.push_back(path);
   accTypePtr->setDerivationPath(derivationPath);

   //set the account seed fingerprint
   accTypePtr->setSeedFingerprint(root->getSeedFingerprint(false));

   auto accountPtr = createAccount(accTypePtr);
   if (!accTypePtr->isWatchingOnly())
   {
      accountPtr->extendPrivateChain(
         decryptedData_, accTypePtr->getAddressLookup());
   }
   else
   {
      accountPtr->extendPublicChain(accTypePtr->getAddressLookup());
   }

   return accountPtr->getID();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::
   createFromPrivateRoot_Armory135(
   const string& folder,
   const SecureBinaryData& privateRoot,
   SecureBinaryData chaincode,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   unsigned lookup)
{
   /*
   Pass the chaincode as it may be non deterministic for older Armory wallets.
   To generate the chaincode from the private root, leave it empty.
   */

   if (privateRoot.getSize() != 32)
      throw WalletException("invalid root size");
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privateRoot);

   //compute wallet ID
   BinaryWriter masterIdPreimage;
   masterIdPreimage.put_BinaryData(pubkey);
   if (!chaincode.empty())
      masterIdPreimage.put_BinaryData(chaincode);
   
   //compute master ID as hmac256(root pubkey + chaincode, "MetaEntry")
   auto hmacMasterMsg = SecureBinaryData::fromString("MetaEntry");
   auto&& masterID_long = BtcUtils::getHMAC256(
      masterIdPreimage.getData(), hmacMasterMsg);
   auto&& masterID = BtcUtils::computeID(masterID_long);

   /*
   Create control passphrase lambda. It gets wiped after the wallet is setup
   */
   auto controlPassLbd = 
      [&controlPassphrase](const set<BinaryData>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterID << "_wallet.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), controlPassLbd);

   string walletID;
   {
      //generate chaincode if it's not provided
      if (chaincode.empty())
         chaincode = BtcUtils::computeChainCode_Armory135(privateRoot);
      
      auto chaincodeCopy = chaincode;
      auto derScheme = make_shared<DerivationScheme_ArmoryLegacy>(
         chaincodeCopy);

      auto asset_single = make_shared<AssetEntry_Single>(
         ROOT_ASSETENTRY_ID, BinaryData(), 
         pubkey, nullptr);

      walletID = move(computeWalletID(derScheme, asset_single));
   }
   
   //for account creation
   SecureBinaryData dummyPubKey;
   auto&& privateRootCopy = privateRoot.copy();

   //create empty wallet
   auto walletPtr = initWalletDb(
      iface,
      masterID, walletID,
      passphrase, 
      controlPassphrase,
      privateRoot, 
      chaincode, 
      0); //pass 0 for the fingerprint to signal legacy wallet

   //set as main
   setMainWallet(iface, walletID);

   //add account
   auto account135 = make_shared<AccountType_ArmoryLegacy>(
      privateRootCopy, dummyPubKey, chaincode);
   account135->setMain(true);

   if (passphrase.getSize() > 0)
   {
      //custom passphrase, set prompt lambda for the chain extention
      auto passphraseLambda =
         [&passphrase](const set<BinaryData>&)->SecureBinaryData
      {
         return passphrase;
      };

      walletPtr->decryptedData_->setPassphrasePromptLambda(passphraseLambda);
   }

   auto accountPtr = walletPtr->createAccount(account135);
   accountPtr->extendPrivateChain(
      walletPtr->decryptedData_, lookup - 1);

   walletPtr->resetPassphrasePromptLambda();
   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::
createFromPublicRoot_Armory135(
   const string& folder,
   SecureBinaryData& pubRoot,
   SecureBinaryData& chainCode,
   const SecureBinaryData& controlPassphrase,
   unsigned lookup)
{
   //compute master ID as hmac256(root pubkey, "MetaEntry")
   auto hmacMasterMsg = SecureBinaryData::fromString("MetaEntry");
   auto&& masterID_long = BtcUtils::getHMAC256(pubRoot, hmacMasterMsg);
   auto&& masterID = BtcUtils::computeID(masterID_long);

   /*
   Create control passphrase lambda. It gets wiped after the wallet is setup
   */
   auto controlPassLbd = 
      [&controlPassphrase](const set<BinaryData>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterID << "_WatchingOnly.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), controlPassLbd);

   string walletID;
   {
      //walletID
      auto chainCode_copy = chainCode;
      auto derScheme = make_shared<DerivationScheme_ArmoryLegacy>(
         chainCode_copy);

      auto asset_single = make_shared<AssetEntry_Single>(
         ROOT_ASSETENTRY_ID, BinaryData(),
         pubRoot, nullptr);

      walletID = move(computeWalletID(derScheme, asset_single));
   }

   //needed for account creation
   SecureBinaryData dummy;
   auto&& pubRootCopy = pubRoot.copy();
   auto&& chainCodeCopy = chainCode.copy();

   //create wallet
   auto walletPtr = initWalletDbFromPubRoot(
      iface, 
      controlPassphrase,
      masterID, walletID,
      pubRoot);

   //set as main
   setMainWallet(iface, walletID);

   //add account
   auto account135 = make_shared<AccountType_ArmoryLegacy>(
      dummy, pubRootCopy, chainCodeCopy);
   account135->setMain(true);

   auto accountPtr = walletPtr->createAccount(account135);
   accountPtr->extendPublicChain(lookup - 1);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromSeed_BIP32(
   const string& folder,
   const SecureBinaryData& seed,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   unsigned lookup)
{
   if (seed.getSize() == 0)
      throw WalletException("empty seed");

   BIP32_Node rootNode;
   rootNode.initFromSeed(seed);

   auto coinType = ArmoryConfig::BitcoinSettings::getCoinType();
   
   //address accounts
   set<shared_ptr<AccountType_BIP32>> accountTypes;

   {
      //legacy account: 44
      vector<unsigned> path = { 0x8000002C, coinType, 0x80000000 };
      auto legacyAcc = make_shared<AccountType_BIP32>(path);

      //nodes
      legacyAcc->setNodes({
         BIP32_OUTER_ACCOUNT_DERIVATIONID, 
         BIP32_INNER_ACCOUNT_DERIVATIONID});
      legacyAcc->setOuterAccountID(
         WRITE_UINT32_BE(BIP32_OUTER_ACCOUNT_DERIVATIONID));
      legacyAcc->setInnerAccountID(
         WRITE_UINT32_BE(BIP32_INNER_ACCOUNT_DERIVATIONID));

      //lookup
      legacyAcc->setAddressLookup(lookup);

      //address types
      legacyAcc->addAddressType(AddressEntryType(
         AddressEntryType_P2PKH | AddressEntryType_Uncompressed));
      legacyAcc->addAddressType(AddressEntryType_P2PKH);
      legacyAcc->setDefaultAddressType(AddressEntryType_P2PKH);

      legacyAcc->setMain(true);
      accountTypes.insert(legacyAcc);
   }
   
   {
      //nested sw account: 49
      vector<unsigned> path = { 0x80000031, coinType, 0x80000000 };
      auto nestedAcc = make_shared<AccountType_BIP32>(path);
         
      //nodes
      nestedAcc->setNodes({
         BIP32_OUTER_ACCOUNT_DERIVATIONID, 
         BIP32_INNER_ACCOUNT_DERIVATIONID});
      nestedAcc->setOuterAccountID(
         WRITE_UINT32_BE(BIP32_OUTER_ACCOUNT_DERIVATIONID));
      nestedAcc->setInnerAccountID(
         WRITE_UINT32_BE(BIP32_INNER_ACCOUNT_DERIVATIONID));

      //lookup
      nestedAcc->setAddressLookup(lookup);

      //address types
      nestedAcc->addAddressType(
         AddressEntryType(AddressEntryType_P2SH | AddressEntryType_P2WPKH));
      nestedAcc->setDefaultAddressType(
         AddressEntryType(AddressEntryType_P2SH | AddressEntryType_P2WPKH));

      accountTypes.insert(nestedAcc);
   }

   {
      //sw account: 84
      vector<unsigned> path = { 0x80000054, coinType, 0x80000000 };
      auto segwitAcc = make_shared<AccountType_BIP32>(path);
         
      //nodes
      segwitAcc->setNodes({
         BIP32_OUTER_ACCOUNT_DERIVATIONID, 
         BIP32_INNER_ACCOUNT_DERIVATIONID});
      segwitAcc->setOuterAccountID(
         WRITE_UINT32_BE(BIP32_OUTER_ACCOUNT_DERIVATIONID));
      segwitAcc->setInnerAccountID(
         WRITE_UINT32_BE(BIP32_INNER_ACCOUNT_DERIVATIONID));

      //lookup
      segwitAcc->setAddressLookup(lookup);

      //address types
      segwitAcc->addAddressType(AddressEntryType_P2WPKH);
      segwitAcc->setDefaultAddressType(AddressEntryType_P2WPKH);

      accountTypes.insert(segwitAcc);
   }


   auto walletPtr = createFromBIP32Node(
      rootNode, 
      accountTypes, 
      passphrase, 
      controlPassphrase,
      folder);

   //save the seed
   walletPtr->setSeed(seed, passphrase);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromSeed_BIP32_Blank(
   const string& folder,
   const SecureBinaryData& seed,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase)
{
   BIP32_Node rootNode;
   if (seed.getSize() == 0)
      throw WalletException("empty seed");
   rootNode.initFromSeed(seed);

   //address accounts
   set<shared_ptr<AccountType_BIP32>> accountTypes;

   /*
   no accounts are setup for a blank wallet
   */

   auto walletPtr = createFromBIP32Node(
      rootNode,
      accountTypes,
      passphrase,
      controlPassphrase,      
      folder);

   //save the seed
   walletPtr->setSeed(seed, passphrase);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromBIP32Node(
   const BIP32_Node& node,
   set<shared_ptr<AccountType_BIP32>> accountTypes,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   const string& folder)
{
   bool isPublic = false;
   if (node.isPublic())
      isPublic = true;

   //compute wallet ID
   auto pubkey = node.getPublicKey();

   //compute master ID as hmac256(root pubkey, "MetaEntry")
   auto hmacMasterMsg = SecureBinaryData::fromString("MetaEntry");
   auto&& masterID_long = BtcUtils::getHMAC256(pubkey, hmacMasterMsg);
   auto&& masterID = BtcUtils::computeID(masterID_long);

   /*
   Create control passphrase lambda. It gets wiped after the wallet is setup
   */
   auto controlPassLbd = 
      [&controlPassphrase](const set<BinaryData>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   if (!isPublic)
      pathSS << folder << "/armory_" << masterID << "_wallet.lmdb";
   else
      pathSS << folder << "/armory_" << masterID << "_WatchingOnly.lmdb";

   auto iface = getIfaceFromFile(pathSS.str(), controlPassLbd);

   string walletID;
   {
      //walletID
      auto chaincode_copy = node.getChaincode();
      auto derScheme =
         make_shared<DerivationScheme_ArmoryLegacy>(chaincode_copy);

      auto asset_single = make_shared<AssetEntry_Single>(
         ROOT_ASSETENTRY_ID, BinaryData(),
         pubkey, nullptr);

      walletID = move(computeWalletID(derScheme, asset_single));
   }

   //create wallet
   shared_ptr<AssetWallet_Single> walletPtr = nullptr;

   if (!isPublic)
   {
      walletPtr = initWalletDb(
         iface,
         masterID, walletID,
         passphrase,
         controlPassphrase,
         node.getPrivateKey(),
         node.getChaincode(),
         node.getThisFingerprint());
   }
   else
   {
      throw runtime_error("invalid for bip32 wallets");
   }

   //set as main
   setMainWallet(iface, walletID);

   //add accounts
   auto passLbd = 
      [&passphrase](const set<BinaryData>&)->SecureBinaryData
   {
      return passphrase;
   };
   walletPtr->setPassphrasePromptLambda(passLbd);

   for (auto accountPtr : accountTypes)
      walletPtr->createBIP32Account(accountPtr);

   walletPtr->resetPassphrasePromptLambda();
   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createSeedless_WatchingOnly(
   const string& folder, const string& walletID,
   const SecureBinaryData& controlPassphrase)
{
   auto&& masterID = walletID;

   /*
   Create control passphrase lambda. It gets wiped after the wallet is setup
   */
   auto controlPassLbd = 
      [&controlPassphrase](const set<BinaryData>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterID << "_WatchingOnly.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), controlPassLbd);

   //address accounts
   shared_ptr<AssetWallet_Single> walletPtr = nullptr;

   //ctors move the arguments in, gotta create copies first
   SecureBinaryData pubRoot;
   walletPtr = initWalletDbFromPubRoot(
      iface,
      controlPassphrase,
      masterID, walletID,
      pubRoot);

   //set as main
   setMainWallet(iface, walletID);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet_Single::computeWalletID(
   shared_ptr<DerivationScheme> derScheme,
   shared_ptr<AssetEntry> rootEntry)
{
   auto&& addrVec = derScheme->extendPublicChain(rootEntry, 1, 1);
   if (addrVec.size() != 1)
      throw WalletException("unexpected chain derivation output");

   auto firstEntry = dynamic_pointer_cast<AssetEntry_Single>(addrVec[0]);
   if (firstEntry == nullptr)
      throw WalletException("unexpected asset entry type");

   return BtcUtils::computeID(firstEntry->getPubKey()->getUncompressedKey());
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::initWalletDb(
   shared_ptr<WalletDBInterface> iface,
   const string& masterID, const string& walletID,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   const SecureBinaryData& privateRoot,
   const SecureBinaryData& chaincode, 
   uint32_t seedFingerprint)
{
   auto headerPtr = make_shared<WalletHeader_Single>();
   headerPtr->walletID_ = walletID;

   //init headerPtr object
   auto&& masterKeyStruct = 
      WalletDBInterface::initWalletHeaderObject(headerPtr, passphrase);

   //get a cipher for the master encryption key
   auto cipher = masterKeyStruct.cipher_->getCopy(
      headerPtr->masterEncryptionKeyId_);

   //copy cipher to cycle the IV then encrypt the private root
   auto rootCipher = cipher->getCopy();
   auto&& encryptedRoot = rootCipher->encrypt(
      masterKeyStruct.decryptedMasterKey_.get(), cipher->getKdfId(), privateRoot);

   //compute public root
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privateRoot);

   //create encrypted object
   auto rootAsset = make_shared<Asset_PrivateKey>(
      WRITE_UINT32_BE(UINT32_MAX), encryptedRoot, move(rootCipher));

   unique_ptr<AssetEntry> rootAssetEntry;
   if (seedFingerprint != 0)
   {
      //bip32 root
      rootAssetEntry = make_unique<AssetEntry_BIP32Root>(
         -1, BinaryData(),
         pubkey, rootAsset,
         chaincode, 0, 0, 0, seedFingerprint, vector<uint32_t>());
   }
   else
   {
      //legacy armory root
      rootAssetEntry = make_unique<AssetEntry_ArmoryLegacyRoot>(
         -1, BinaryData(),
         pubkey, rootAsset, chaincode);
   }

   //create wallet
   auto walletPtr = make_shared<AssetWallet_Single>(iface, headerPtr, masterID);

   //add kdf & master key
   walletPtr->decryptedData_->addKdf(masterKeyStruct.kdf_);
   walletPtr->decryptedData_->addEncryptionKey(masterKeyStruct.masterKey_);

   auto controlPassLbd = 
      [&controlPassphrase](const set<BinaryData>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //put wallet db name in meta db
   iface->lockControlContainer(controlPassLbd);
   iface->addHeader(headerPtr);
   iface->unlockControlContainer();

   //insert the original entries
   {
      auto&& tx = iface->beginWriteTransaction(walletPtr->dbName_);

      {
         //decrypted data container
         walletPtr->decryptedData_->updateOnDisk();
      }

      {
         //root asset
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);

         auto&& data = rootAssetEntry->serialize();
         tx->insert(bwKey.getData(), data);
      }

      {
         //comment account
         walletPtr->addMetaAccount(
            MetaAccountType::MetaAccount_Comments);
      }
   }

   //init walletptr from file
   walletPtr->readFromFile();
   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::initWalletDbFromPubRoot(
   shared_ptr<WalletDBInterface> iface,
   const SecureBinaryData& controlPassphrase,
   const string& masterID, const string& walletID,
   SecureBinaryData& pubRoot)
{
   //create root AssetEntry
   shared_ptr<AssetEntry_Single> rootAssetEntry = nullptr;
   if (pubRoot.getSize() != 0)
   {
      rootAssetEntry = make_shared<AssetEntry_Single>(
         -1, BinaryData(), pubRoot, nullptr);
   }

   auto headerPtr = make_shared<WalletHeader_Single>();
   headerPtr->walletID_ = walletID;
   headerPtr->controlSalt_ = CryptoPRNG::generateRandom(32);

   auto walletPtr = make_shared<AssetWallet_Single>(iface, headerPtr, masterID);

   auto controlPassLbd = 
      [&controlPassphrase](const set<BinaryData>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   iface->lockControlContainer(controlPassLbd);
   iface->addHeader(headerPtr);
   iface->unlockControlContainer();

   /**insert the original entries**/
   {
      auto&& tx = iface->beginWriteTransaction(walletPtr->dbName_);

      if (rootAssetEntry != nullptr)
      {
         //root asset
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);

         auto&& data = rootAssetEntry->serialize();

         tx->insert(bwKey.getData(), data);
      }

      {
         //comment account
         walletPtr->addMetaAccount(
            MetaAccountType::MetaAccount_Comments);
      }
   }

   //init walletptr from file
   walletPtr->readFromFile();
   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getDecryptedValue(
   shared_ptr<Asset_EncryptedData> assetPtr)
{
   //have to lock the decryptedData object before calling this method
   return decryptedData_->getDecryptedPrivateData(assetPtr);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getDecryptedPrivateKeyForAsset(
   std::shared_ptr<AssetEntry_Single> assetPtr)
{
   auto assetPrivKey = assetPtr->getPrivKey();

   if (assetPrivKey == nullptr)
   {      
      auto account = getAccountForID(assetPtr->getAccountID());
      assetPrivKey = account->fillPrivateKey(
         decryptedData_, assetPtr->getID());
   }
   
   return getDecryptedValue(assetPrivKey);
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetWallet_Single::derivePrivKeyFromPath(
   const BIP32_AssetPath& path)
{
   auto derPath = path.getDerivationPathFromSeed();

   //grab wallet root
   auto rootBip32 = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);
   if (rootBip32 == nullptr)
      throw runtime_error("missing root");

   //check fingerprint
   auto rootFingerprint = rootBip32->getThisFingerprint();
   if (path.getSeedFingerprint() != rootFingerprint)
      throw runtime_error("root mismatch");

   //decrypt root
   auto privKey = decryptedData_->getDecryptedPrivateData(rootBip32->getPrivKey());
   auto chaincode = rootBip32->getChaincode();

   //derive
   auto hdNode = 
      BIP32_Node::getHDNodeFromPrivateKey(0, 0, 0, privKey, chaincode);

   for (unsigned i=0; i<derPath.size(); i++)
   {
      if (!btc_hdnode_private_ckd(&hdNode, derPath[i]))
         throw std::runtime_error("failed to derive bip32 private key");
   }

   //add to decrypted data container and return id
   return decryptedData_->insertDecryptedPrivateData(
      hdNode.private_key, BTC_ECKEY_PKEY_LENGTH);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getDecrypedPrivateKeyForId(
   const BinaryData& id) const
{
   return decryptedData_->getDecryptedPrivateData(id);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::changePrivateKeyPassphrase(
   const std::function<SecureBinaryData(void)>& newPassLbd)
{
   auto&& masterKeyId = decryptedData_->getMasterEncryptionKeyId();
   auto&& kdfId = decryptedData_->getDefaultKdfId();

   decryptedData_->encryptEncryptionKey(
      masterKeyId, kdfId, newPassLbd, true);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::addPrivateKeyPassphrase(
   const function<SecureBinaryData(void)>& newPassLbd)
{
   if (root_ == nullptr || !root_->hasPrivateKey())
      throw WalletException("wallet has no private root");

   auto&& masterKeyId = root_->getPrivateEncryptionKeyId();
   auto&& masterKdfId = root_->getKdfId();

   decryptedData_->encryptEncryptionKey(
      masterKeyId, masterKdfId, newPassLbd, false);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::erasePrivateKeyPassphrase()
{
   if (root_ == nullptr || !root_->hasPrivateKey())
      throw WalletException("wallet has no private root");

   auto&& masterKeyId = root_->getPrivateEncryptionKeyId();
   auto&& masterKdfId = root_->getKdfId();

   decryptedData_->eraseEncryptionKey(masterKeyId, masterKdfId);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getPublicRoot() const
{
   if (root_ == nullptr)
      throw WalletException("null root");

   auto pubkey = root_->getPubKey();
   if (pubkey == nullptr)
      throw WalletException("null pubkey");

   return pubkey->getUncompressedKey();
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getArmory135Chaincode() const
{
   BinaryWriter bw;
   bw.put_uint32_t(ARMORY_LEGACY_ACCOUNTID, BE);

   auto account = getAccountForID(bw.getData());
   auto assetAccount = account->getOuterAccount();
   return assetAccount->getChaincode();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> 
   AssetWallet_Single::getMainAccountAssetForIndex(unsigned id) const
{
   auto account = getAccountForID(mainAccount_);
   if (account == nullptr)
      throw WalletException("failed to grab main account");

   return account->getOutterAssetForIndex(id);
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetWallet_Single::getMainAccountAssetCount(void) const
{
   auto account = getAccountForID(mainAccount_);
   if (account == nullptr)
      throw WalletException("failed to grab main account");

   auto asset_account = account->getOuterAccount();
   return asset_account->getAssetCount();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetWallet_Single::getAccountRoot(
   const BinaryData& id) const
{
   auto account = getAccountForID(id);
   if (account == nullptr)
      throw WalletException("failed to grab main account");

   return account->getOutterAssetRoot();
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::copyPublicData(
   shared_ptr<AssetWallet_Single> wlt,
   std::shared_ptr<WalletDBInterface> iface)
{
   {
      //open the relevant db name
      auto&& tx = iface->beginWriteTransaction(wlt->dbName_);

      if (wlt->root_ != nullptr)
      {
         //copy root
         auto rootCopy = wlt->root_->getPublicCopy();

         //commit root
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);

         auto&& data = rootCopy->serialize();

         tx->insert(bwKey.getData(), data);
      }

      {
         //address accounts
         for (auto& addrAccPtr : wlt->accounts_)
         {
            auto woAcc = addrAccPtr.second->getWatchingOnlyCopy(wlt->dbName_);
            woAcc->commit(iface);
         }
      }

      {
         //meta accounts
         for (auto& metaAccPtr : wlt->metaDataAccounts_)
         {
            auto accCopy = metaAccPtr.second->copy(wlt->dbName_);
            auto tx = iface->beginWriteTransaction(wlt->dbName_);
            accCopy->commit(move(tx));
         }
      }
   }

   //header data
   {
      auto headerPtr = make_shared<WalletHeader_Single>();
      headerPtr->walletID_ = wlt->walletID_;
      AssetWallet_Single wltWO(iface, headerPtr, wlt->masterID_);

      auto tx = wltWO.iface_->beginWriteTransaction(wltWO.dbName_);

      if (wlt->mainAccount_.getSize() > 0)
      {
         //main account
         BinaryWriter bwKey;
         bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

         BinaryWriter bwData;
         bwData.put_var_int(wlt->mainAccount_.getSize());
         bwData.put_BinaryData(wlt->mainAccount_);
         tx->insert(bwKey.getData(), bwData.getData());
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::exportPublicData(shared_ptr<AssetWallet_Single> wlt)
{
/*   struct WalletPublicData
   {
      BIP32_Node pubRoot_;
   };

   WalletPublicData wpd;

   //root
   if (wlt->root_ != nullptr)
      wpd.pubRoot_ = wlt->root_->getPublicCopy();

   //address accounts
   for (auto& addrAccPtr : wlt->accounts_)
   {
      auto woAcc = addrAccPtr.second->getWatchingOnlyCopy(iface, wlt->dbName_);
      woAcc->commit();
   }

   //meta accounts
   for (auto& metaAccPtr : wlt->metaDataAccounts_)
   {
      auto accCopy = metaAccPtr.second->copy(iface, wlt->dbName_);
      accCopy->commit();
   }

   //header data
   {
      auto headerPtr = make_shared<WalletHeader_Single>();
      headerPtr->walletID_ = wlt->walletID_;
      AssetWallet_Single wltWO(iface, headerPtr, wlt->masterID_);

      auto&& tx = wltWO.iface_->beginWriteTransaction(wltWO.dbName_);

      if (wlt->mainAccount_.getSize() > 0)
      {
         //main account
         BinaryWriter bwKey;
         bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

         BinaryWriter bwData;
         bwData.put_var_int(wlt->mainAccount_.getSize());
         bwData.put_BinaryData(wlt->mainAccount_);
         tx->insert(bwKey.getData(), bwData.getData());
      }
   }*/
}


////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::setSeed(
   const SecureBinaryData& seed,
   const SecureBinaryData& passphrase)
{
   //copy root node cipher
   auto rootPtr = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);
   if (rootPtr == nullptr)
      throw WalletException("expected BIP32 root object");
   auto cipherCopy = 
      rootPtr->getPrivKey()->getCipherDataPtr()->cipher_->getCopy();

   //if custom passphrase, set prompt lambda prior to encryption
   if (passphrase.getSize() > 0)
   {
      auto passphraseLambda =
         [&passphrase](const set<BinaryData>&)->SecureBinaryData
      {
         return passphrase;
      };

      decryptedData_->setPassphrasePromptLambda(passphraseLambda);
   }

   //create encrypted seed object
   {
      auto lock = lockDecryptedContainer();

      auto&& cipherText = decryptedData_->encryptData(cipherCopy.get(), seed);
      seed_ = make_shared<EncryptedSeed>(cipherText, move(cipherCopy));
   }

   //write to disk
   {
      auto&& tx = iface_->beginWriteTransaction(dbName_);

      BinaryWriter bwKey;
      bwKey.put_uint32_t(WALLET_SEED_KEY);
      auto&& serData = seed_->serialize();

      tx->insert(bwKey.getData(), serData);
   }

   //reset prompt lambda
   resetPassphrasePromptLambda();
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet_Single::isWatchingOnly() const
{
   if (root_ == nullptr)
      return true;

   return !root_->hasPrivateKey();
}

////////////////////////////////////////////////////////////////////////////////
BIP32_AssetPath AssetWallet_Single::getBip32PathForAssetID(
   const BinaryData& id) const
{
   auto asset = getAssetForID(id);
   return getBip32PathForAsset(asset);
}

////////////////////////////////////////////////////////////////////////////////
BIP32_AssetPath AssetWallet_Single::getBip32PathForAsset(
   shared_ptr<AssetEntry> asset) const
{
   const auto& id = asset->getID();
   if (id.getSize() != 12)
      throw WalletException("invalid asset id length");

   auto assetSingle = dynamic_pointer_cast<AssetEntry_Single>(asset);
   if (assetSingle == nullptr)
      throw WalletException("unexpected asset type");
   
   auto pubKeyPtr = assetSingle->getPubKey();
   if (pubKeyPtr == nullptr)
      throw WalletException("asset is missing public key");

   const auto& pubkey = pubKeyPtr->getCompressedKey();
   
   auto account = getAccountForID(id);
   auto accountRoot = account->getBip32RootForAssetId(id);
   auto accountPath = accountRoot->getDerivationPath();

   //asset step
   BinaryRefReader brr(id.getRef());
   brr.advance(8);
   auto assetStep = brr.get_uint32_t(BE);

   //get root
   auto rootBip32 = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);
   if (rootBip32 == nullptr)
   {
      /* 
      Wallet has no root, we have to use the account's root instead. It should
      carry the path from its seed as well as the seed's fingerprint
      */

      auto rootObj = make_shared<BIP32_PublicDerivedRoot>(
         accountRoot->getXPub(), 
         accountPath, 
         accountRoot->getSeedFingerprint(true));

      return BIP32_AssetPath(
         pubkey,
         { assetStep }, 
         accountRoot->getThisFingerprint(), 
         rootObj);
   }
   else
   {
      //wallet has a root, build path from that
      auto rootPath = accountRoot->getDerivationPath();
      rootPath.push_back(assetStep);

      return BIP32_AssetPath(
         pubkey,
         rootPath,
         rootBip32->getThisFingerprint(),
         nullptr);
   }
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet_Single::getXpubForAssetID(const BinaryData& id) const
{
   if (id.getSize() != 12)
      throw WalletException("unexpected asset id length");

   BinaryRefReader brrId(id.getRef());
   brrId.advance(4);
   auto accountID = brrId.get_BinaryData(4);
   auto assetID = brrId.get_uint32_t(BE);

   //grab account
   auto addrAccount = getAccountForID(id);
   auto accountPtr = addrAccount->getAccountForID(accountID);

   //setup bip32 node from root pubkey
   auto root = dynamic_pointer_cast<AssetEntry_BIP32Root>(
      accountPtr->getRoot());
   if (root == nullptr)
      throw WalletException("unexpected type for account root");

   BIP32_Node node;
   node.initFromPublicKey(
      root->getDepth(), root->getLeafID(), root->getParentFingerprint(),
      root->getPubKey()->getCompressedKey(), root->getChaincode());

   //derive with asset's step
   node.derivePublic(assetID);

   auto b58sbd = node.getBase58();
   return string(b58sbd.getCharPtr(), b58sbd.getSize());
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet_Multisig
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Multisig::readFromFile()
{
   //sanity check
   if (iface_ == nullptr)
      throw WalletException("uninitialized wallet object");

   {
      auto&& tx = iface_->beginReadTransaction(dbName_);

      {
         //walletId
         BinaryWriter bwKey;
         bwKey.put_uint32_t(WALLETID_KEY);
         auto walletIdRef = getDataRefForKey(tx.get(), bwKey.getData());

         walletID_ = string(walletIdRef.toCharPtr(), walletIdRef.getSize());
      }

      {
         //lookup
         {
            BinaryWriter bwKey;
            bwKey.put_uint8_t(ASSETENTRY_PREFIX);
            auto lookupRef = getDataRefForKey(tx.get(), bwKey.getData());

            BinaryRefReader brr(lookupRef);
            chainLength_ = brr.get_uint32_t();
         }
      }
   }

   {
      unsigned n = 0;

      map<string, shared_ptr<AssetWallet_Single>> walletPtrs;
      for (unsigned i = 0; i < n; i++)
      {
         stringstream ss;
         ss << "Subwallet-" << i;

         auto subWltMeta = make_shared<WalletHeader_Subwallet>();
         subWltMeta->walletID_ = ss.str();

         auto subwalletPtr = make_shared<AssetWallet_Single>(
            iface_, subWltMeta, masterID_);
         subwalletPtr->readFromFile();
         walletPtrs[subwalletPtr->getID()] = subwalletPtr;

      }

      loadMetaAccounts();
   }
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Multisig::getDecryptedValue(
   shared_ptr<Asset_EncryptedData> assetPtr)
{
   return decryptedData_->getDecryptedPrivateData(assetPtr);
}