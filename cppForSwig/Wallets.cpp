////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2019, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Wallets.h"
#include "BlockDataManagerConfig.h"

using namespace std;
using namespace ArmorySigner;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetWallet::~AssetWallet()
{
   accounts_.clear();
   iface_.reset();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressAccount> AssetWallet::createAccount(
   shared_ptr<AccountType> accountType)
{
   auto cipher = make_unique<Cipher_AES>(
      decryptedData_->getDefaultKdfId(),
      decryptedData_->getMasterEncryptionKeyId());

   //instantiate AddressAccount object from AccountType
   auto account_ptr = make_shared<AddressAccount>(iface_, dbName_);
   account_ptr->make_new(accountType, decryptedData_, move(cipher));
   auto accID = account_ptr->getID();
   if (accounts_.find(accID) != accounts_.end())
      throw WalletException("already have an address account with this path");

   //commit to disk
   account_ptr->commit();

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

   auto&& tx = iface_->beginReadTransaction(dbName_);

   {
      //main account
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

      try
      {
         auto account_id = getDataRefForKey(tx.get(), bwKey.getData());

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
         auto rootAssetRef = getDataRefForKey(tx.get(), bwKey.getData());

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
         auto rootAssetRef = getDataRefForKey(tx.get(), bwKey.getData());

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
         auto labelRef = getDataRefForKey(tx.get(), bwKey.getData());
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
         auto labelRef = getDataRefForKey(tx.get(), bwKey.getData());
         description_ = string(labelRef.toCharPtr(), labelRef.getSize());
      }
      catch(NoEntryInWalletException& )
      {}
   }

   //encryption keys and kdfs
   decryptedData_->readFromDisk();

   {
      //accounts
      BinaryWriter bwPrefix;
      bwPrefix.put_uint8_t(ADDRESS_ACCOUNT_PREFIX);
      auto dbIter = tx->getIterator();
      dbIter->seek(bwPrefix.getDataRef());

      while (dbIter->isValid())
      {
         //iterate through account keys
         auto&& key = dbIter->key();

         try
         {
            //instantiate account object and read data on disk
            auto addressAccount = make_shared<AddressAccount>(iface_, dbName_);
            addressAccount->readFromDisk(key);

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
   auto account_ptr = make_shared<MetaDataAccount>(iface_, dbName_);
   account_ptr->make_new(type);

   //do not overwrite existing account of the same type
   if (metaDataAccounts_.find(type) != metaDataAccounts_.end())
      return;

   account_ptr->commit();
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
         auto metaAccount = make_shared<MetaDataAccount>(iface_, dbName_);
         metaAccount->readFromDisk(key);

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
         LOGWARN << "wallet contains header types that \
            aren't covered by WO forking";
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
   CommentAssetConversion::setAsset(accPtr.get(), key, comment);
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
   CommentAssetConversion::deleteAsset(accPtr.get(), key);
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
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet_Single
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetWallet_Single::createBIP32Account(
   shared_ptr<AssetEntry_BIP32Root> parentNode, 
   vector<unsigned> derPath, bool isSegWit, bool isMain)
{
   shared_ptr<AssetEntry_BIP32Root> root = parentNode;
   if (parentNode == nullptr)
      root = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);

   if (root == nullptr)
      throw AccountException("no valid root to create BIP32 account from");

   auto seedFingerprint = root->getSeedFingerprint();

   shared_ptr<AccountType_BIP32> accountTypePtr = nullptr;
   if(root->getPrivKey() != nullptr)
   {
      //try to decrypt the root's private key to get full derivation
      try
      {
         //lock for decryption
         auto lock = lockDecryptedContainer();

         //decrypt root
         auto privKey = decryptedData_->getDecryptedPrivateData(root->getPrivKey());
         auto chaincode = root->getChaincode();

         SecureBinaryData dummy;
         if (!isSegWit)
         {
            accountTypePtr = make_shared<AccountType_BIP32_Legacy>(
               privKey, dummy, chaincode, derPath,
               root->getDepth(), root->getLeafID(), 
               root->getParentFingerprint(), seedFingerprint);
         }
         else
         {
            accountTypePtr = make_shared<AccountType_BIP32_SegWit>(
               privKey, dummy, chaincode, derPath,
               root->getDepth(), root->getLeafID(), 
               root->getParentFingerprint(), seedFingerprint);
         }
      }
      catch(exception&)
      {}
   }

   if (accountTypePtr == nullptr)
   {
      //can't get the private key, if we can derive this only from 
      //the pubkey then do it, otherwise throw
      auto pubkey = root->getPubKey()->getCompressedKey();
      auto chaincode = root->getChaincode();

      SecureBinaryData dummy1;
      if (!isSegWit)
      {
         accountTypePtr = make_shared<AccountType_BIP32_Legacy>(
            dummy1, pubkey, chaincode, derPath,
            root->getDepth(), root->getLeafID(), 
            root->getParentFingerprint(), seedFingerprint);
      }
      else
      {
         accountTypePtr = make_shared<AccountType_BIP32_SegWit>(
            dummy1, pubkey, chaincode, derPath,
            root->getDepth(), root->getLeafID(), 
            root->getParentFingerprint(), seedFingerprint);
      }
   }

   if (isMain || accounts_.size() == 0)
      accountTypePtr->setMain(true);

   auto&& tx = iface_->beginWriteTransaction(dbName_);
   auto accountPtr = createAccount(accountTypePtr);
   accountPtr->extendPrivateChain(decryptedData_, DERIVATION_LOOKUP);
   return accountPtr->getID();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetWallet_Single::createCustomBIP32Account(
   std::shared_ptr<AssetEntry_BIP32Root> parentNode,
   std::shared_ptr<AccountType_BIP32_Custom> accTypePtr)
{
   shared_ptr<AssetEntry_BIP32Root> root = parentNode;
   if (parentNode == nullptr)
      root = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);

   if (root == nullptr)
      throw AccountException("no valid root to create BIP32 account from");

   bool isDerived = false;
   if (root->getPrivKey() != nullptr)
   {
      //try to decrypt the root's private to get full derivation
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
      //the pubkey then do it, otherwise throw

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
   }

   //update the derivation path, it should be root's + account's
   vector<unsigned> derivationPath = root->getDerivationPath();
   for (auto& path : accTypePtr->getDerivationPath())
      derivationPath.push_back(path);
   accTypePtr->setDerivationPath(derivationPath);

   //if we provided a root, set the account seed fingerprint to
   //that carried by the root
   if (parentNode != nullptr)
      accTypePtr->setSeedFingerprint(root->getSeedFingerprint());

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
      throw WalletException("empty root");

   //compute wallet ID
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privateRoot);
   
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
   pathSS << folder << "/armory_" << masterID << "_wallet.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), controlPassLbd);

   string walletID;
   {
      //generate chaincode if it's not provided
      if (chaincode.getSize() == 0)
         chaincode = BtcUtils::computeChainCode_Armory135(privateRoot);
      
      auto chaincodeCopy = chaincode;
      auto derScheme = make_shared<DerivationScheme_ArmoryLegacy>(
         chaincodeCopy);

      auto asset_single = make_shared<AssetEntry_Single>(
         ROOT_ASSETENTRY_ID, BinaryData(), 
         pubkey, nullptr);

      walletID = move(computeWalletID(derScheme, asset_single));
   }
   
   SecureBinaryData dummyPubKey;
   auto&& privateRootCopy = privateRoot.copy();

   //address accounts
   set<shared_ptr<AccountType>> accountTypes;
   accountTypes.insert(
      make_shared<AccountType_ArmoryLegacy>(
      privateRootCopy, 
      dummyPubKey, chaincode));
   (*accountTypes.begin())->setMain(true);
   
   SecureBinaryData dummy;
   auto walletPtr = initWalletDb(
      iface,
      masterID, walletID,
      passphrase, 
      controlPassphrase,
      privateRoot, 
      dummy,
      move(accountTypes),
      lookup - 1);

   //set as main
   setMainWallet(iface, walletID);

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

   //address accounts
   SecureBinaryData dummy;
   auto&& pubRootCopy = pubRoot.copy();
   auto&& chainCodeCopy = chainCode.copy();

   set<shared_ptr<AccountType>> accountTypes;
   accountTypes.insert(
      make_shared<AccountType_ArmoryLegacy>(
      dummy, pubRootCopy, chainCodeCopy));
   (*accountTypes.begin())->setMain(true);

   auto walletPtr = initWalletDbFromPubRoot(
      iface, 
      controlPassphrase,
      masterID, walletID,
      pubRoot, 
      accountTypes,
      lookup - 1);

   //set as main
   setMainWallet(iface, walletID);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromSeed_BIP32(
   const string& folder,
   const SecureBinaryData& seed,
   const vector<unsigned>& derivationPath,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   unsigned lookup)
{
   if (seed.getSize() == 0)
      throw WalletException("empty seed");

   BIP32_Node rootNode;
   rootNode.initFromSeed(seed);

   //address accounts
   set<shared_ptr<AccountType>> accountTypes;

   /*
   Derive 2 hardcoded paths on top of the main derivatrionPath for
   this wallet, to support the default address chains for Armory operations
   */

   SecureBinaryData dummy1, dummy2;
   auto privateRootCopy_1 = rootNode.getPrivateKey();
   auto privateRootCopy_2 = rootNode.getPrivateKey();
   auto chaincode1 = rootNode.getChaincode();
   auto chaincode2 = rootNode.getChaincode();

   accountTypes.insert(
      make_shared<AccountType_BIP32_Legacy>(
         privateRootCopy_1,
         dummy1, chaincode1,
         derivationPath, 
         0, 0, 
         0, rootNode.getThisFingerprint()));
   (*accountTypes.begin())->setMain(true);

   accountTypes.insert(
      make_shared<AccountType_BIP32_SegWit>(
         privateRootCopy_2,
         dummy2, chaincode2,
         derivationPath, 
         0, 0, 
         0, rootNode.getThisFingerprint()));

   auto walletPtr = createFromBIP32Node(
      rootNode, 
      accountTypes, 
      passphrase, 
      controlPassphrase,
      folder, 
      lookup);

   //save the seed
   walletPtr->setSeed(seed, passphrase);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromBase58_BIP32(
   const string& folder,
   const SecureBinaryData& base58,
   const vector<unsigned>& derivationPath,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   unsigned lookup)
{
   //setup node
   BIP32_Node node;
   node.initFromBase58(base58);

   bool isPublic = false;
   if (node.isPublic())
      isPublic = true;

   //address accounts
   set<shared_ptr<AccountType>> accountTypes;

   /*
   Unlike wallets setup from seeds, we do not make any assumption with those setup from
   a xpriv/xpub and only use what's provided in derivationPath. It is the caller's
   responsibility to run sanity checks.
   */

   if (!isPublic)
   {
      auto privateRootCopy = node.getPrivateKey();
      SecureBinaryData dummy;
      auto chainCodeCopy = node.getChaincode();

      accountTypes.insert(make_shared<AccountType_BIP32_Custom>(
         privateRootCopy, dummy, chainCodeCopy, derivationPath,
         node.getDepth(), node.getLeafID(), 
         node.getParentFingerprint(), node.getThisFingerprint()));
      (*accountTypes.begin())->setMain(true);
   }
   else
   {
      //ctors move the arguments in, gotta create copies first
      auto pubkey_copy = node.getPublicKey();
      auto chaincode_copy = node.getChaincode();
      SecureBinaryData dummy1;

      accountTypes.insert(make_shared<AccountType_BIP32_Custom>(
         dummy1, pubkey_copy, chaincode_copy, derivationPath,
         node.getDepth(), node.getLeafID(), 
         node.getParentFingerprint(), node.getThisFingerprint()));
      (*accountTypes.begin())->setMain(true);
   }

   auto walletPtr = createFromBIP32Node(
      node,
      accountTypes,
      passphrase,
      controlPassphrase,      
      folder, 
      lookup);

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
   set<shared_ptr<AccountType>> accountTypes;

   /*
   no accounts are setup for a blank wallet
   */

   auto walletPtr = createFromBIP32Node(
      rootNode,
      accountTypes,
      passphrase,
      controlPassphrase,      
      folder,
      0);

   //save the seed
   walletPtr->setSeed(seed, passphrase);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromBIP32Node(
   const BIP32_Node& node,
   set<shared_ptr<AccountType>> accountTypes,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   const string& folder,
   unsigned lookup)
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

   //address accounts
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
         move(accountTypes),
         lookup);
   }
   else
   {
      //ctors move the arguments in, gotta create copies first
      auto pubkey_copy = node.getPublicKey();
      walletPtr = initWalletDbFromPubRoot(
         iface,
         controlPassphrase,
         masterID, walletID,
         pubkey_copy,
         move(accountTypes),
         lookup);
   }

   //set as main
   setMainWallet(iface, walletID);

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
      pubRoot, {}, 0);

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
   set<shared_ptr<AccountType>> accountTypes,
   unsigned lookup)
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

   bool isBip32 = false;
   unsigned armory135AccCount = 0;
   for (auto& account : accountTypes)
   {
      switch (account->type())
      {
      case AccountTypeEnum_ArmoryLegacy:
      {
         ++armory135AccCount;
         break;
      }

      default:
         continue;
      }
   }

   //default to bip32 root if there are no account types specified
   if (armory135AccCount == 0)
      isBip32 = true;

   shared_ptr<AssetEntry_Single> rootAssetEntry;
   if (isBip32)
   {
      if (chaincode.getSize() == 0)
         throw WalletException("emtpy chaincode for bip32 root");

      rootAssetEntry = make_shared<AssetEntry_BIP32Root>(
         -1, BinaryData(),
         pubkey, rootAsset,
         chaincode, 0, 0, 0, 0, vector<uint32_t>());
   }
   else
   {
      rootAssetEntry = make_shared<AssetEntry_Single>(
         -1, BinaryData(),
         pubkey, rootAsset);
   }

   auto walletPtr = make_shared<AssetWallet_Single>(iface, headerPtr, masterID);

   //add kdf & master key
   walletPtr->decryptedData_->addKdf(masterKeyStruct.kdf_);
   walletPtr->decryptedData_->addEncryptionKey(masterKeyStruct.masterKey_);

   //set passphrase lambda if necessary
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
         //accounts
         for (auto& accountType : accountTypes)
         {
            //instantiate AddressAccount object from AccountType
            auto account_ptr = make_shared<AddressAccount>(
               iface, walletPtr->dbName_);

            auto&& cipher_copy = cipher->getCopy();
            account_ptr->make_new(accountType,
               walletPtr->decryptedData_,
               move(cipher_copy));

            //commit to disk
            account_ptr->commit();

            if (accountType->isMain())
               walletPtr->mainAccount_ = account_ptr->getID();
         }

         //comment account
         walletPtr->addMetaAccount(MetaAccountType::MetaAccount_Comments);

         //main account
         if (walletPtr->mainAccount_.getSize() > 0)
         {
            BinaryWriter bwKey;
            bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

            BinaryWriter bwData;
            bwData.put_var_int(walletPtr->mainAccount_.getSize());
            bwData.put_BinaryData(walletPtr->mainAccount_);
            tx->insert(bwKey.getData(), bwData.getData());
         }
      }
   }

   //init walletptr from file
   walletPtr->readFromFile();

   {
      //asset lookup
      if (lookup == UINT32_MAX)
         lookup = DERIVATION_LOOKUP;

      if (lookup != 0)
         walletPtr->extendPrivateChain(lookup);
   }

   walletPtr->decryptedData_->resetPassphraseLambda();
   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::initWalletDbFromPubRoot(
   shared_ptr<WalletDBInterface> iface,
   const SecureBinaryData& controlPassphrase,
   const string& masterID, const string& walletID,
   SecureBinaryData& pubRoot,
   set<shared_ptr<AccountType>> accountTypes,
   unsigned lookup)
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
         //accounts
         for (auto& accountType : accountTypes)
         {
            //instantiate AddressAccount object from AccountType
            auto account_ptr = make_shared<AddressAccount>(
               iface, walletPtr->dbName_);
            account_ptr->make_new(accountType, nullptr, nullptr);

            //commit to disk
            account_ptr->commit();

            if (accountType->isMain())
               walletPtr->mainAccount_ = account_ptr->getID();
         }

         //comment account
         walletPtr->addMetaAccount(MetaAccountType::MetaAccount_Comments);

         //main account
         if (walletPtr->mainAccount_.getSize() > 0)
         {
            BinaryWriter bwKey;
            bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

            BinaryWriter bwData;
            bwData.put_var_int(walletPtr->mainAccount_.getSize());
            bwData.put_BinaryData(walletPtr->mainAccount_);
            tx->insert(bwKey.getData(), bwData.getData());
         }
      }
   }

   //init walletptr from file
   walletPtr->readFromFile();

   {
      //asset lookup
      if (lookup == UINT32_MAX)
         lookup = DERIVATION_LOOKUP;

      if (lookup > 0)
         walletPtr->extendPublicChain(lookup);
   }

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
            auto woAcc = addrAccPtr.second->getWatchingOnlyCopy(iface, wlt->dbName_);
            woAcc->commit();
         }
      }

      {
         //meta accounts
         for (auto& metaAccPtr : wlt->metaDataAccounts_)
         {
            auto accCopy = metaAccPtr.second->copy(iface, wlt->dbName_);
            accCopy->commit();
         }
      }
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
   }
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
      throw runtime_error("invalid asset id length");

   auto assetSingle = dynamic_pointer_cast<AssetEntry_Single>(asset);
   if (assetSingle == nullptr)
      throw runtime_error("unexpected asset type");
   
   auto pubKeyPtr = assetSingle->getPubKey();
   if (pubKeyPtr == nullptr)
      throw runtime_error("asset is missing public key");

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
         accountRoot->getSeedFingerprint());

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

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// ResolverFeed_AssetWalletSingle
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void ResolverFeed_AssetWalletSingle::addToMap(shared_ptr<AddressEntry> addrPtr)
{
   try
   {
      BinaryDataRef hash(addrPtr->getHash());
      BinaryDataRef preimage(addrPtr->getPreimage());

      hash_to_preimage_.insert(make_pair(hash, preimage));
   }
   catch (const exception&)
   {}

   auto addr_nested = dynamic_pointer_cast<AddressEntry_Nested>(addrPtr);
   if (addr_nested != nullptr)
   {
      addToMap(addr_nested->getPredecessor());
      return;
   }

   auto addr_with_asset = dynamic_pointer_cast<AddressEntry_WithAsset>(addrPtr);
   if (addr_with_asset != nullptr)
   {
      BinaryDataRef preimage(addrPtr->getPreimage());
      auto& asset = addr_with_asset->getAsset();

      auto asset_single = dynamic_pointer_cast<AssetEntry_Single>(asset);
      if (asset_single == nullptr)
         throw WalletException("multisig asset in asset_single resolver");

      pubkey_to_asset_.insert(make_pair(preimage, asset_single));
   }
}

////////////////////////////////////////////////////////////////////////////////
pair<shared_ptr<AssetEntry>, AddressEntryType> 
   ResolverFeed_AssetWalletSingle::getAssetPairForKey(const BinaryData& key) const
{
   //run through accounts
   auto& accounts = wltPtr_->accounts_;
   for (auto& accPair : accounts)
   {
      /*
      Accounts store script hashes with their relevant prefix, resolver
      uses unprefixed hashes as found in the actual outputs. Hence,
      all possible script prefixes will be prepended to the key to
      look for the relevant asset ID
      */

      auto accPtr = accPair.second;

      auto prefixSet = accPtr->getAddressTypeSet();
      auto& hashMap = accPtr->getAddressHashMap();
      set<uint8_t> usedPrefixes;

      for (auto& addrType : prefixSet)
      {
         BinaryWriter prefixedKey;
         try
         {
            auto prefix = AddressEntry::getPrefixByte(addrType);

            //skip prefixes already used
            auto insertIter = usedPrefixes.insert(prefix);
            if (!insertIter.second)
               continue;

            prefixedKey.put_uint8_t(prefix);
         }
         catch (const AddressException&)
         {}

         prefixedKey.put_BinaryData(key);

         auto iter = hashMap.find(prefixedKey.getData());
         if (iter == hashMap.end())
            continue;

         /*
         We have a hit for this prefix, return the asset and its
         address type. 
            
         Note that we can't use addrType, as it may use a prefix 
         shared across several address types (i.e. P2SH-P2PK and 
         P2SH-P2WPKH).

         Therefor, we return the address type attached to hash 
         rather the one used to roll the prefix.
         */

         auto asset =
            accPtr->getAssetForID(iter->second.first.getSliceRef(4, 8));
         return make_pair(asset, iter->second.second);
      }
   }

   return make_pair(nullptr, AddressEntryType_Default);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ResolverFeed_AssetWalletSingle::getByVal(const BinaryData& key)
{
   //check cached hits first
   auto iter = hash_to_preimage_.find(key);
   if (iter != hash_to_preimage_.end())
      return iter->second;

   //short of that, try to get the asset for this key
   auto assetPair = getAssetPairForKey(key);
   if (assetPair.first == nullptr || 
      assetPair.second == AddressEntryType_Default)
   {
      throw runtime_error("could not resolve key");
   }

   auto addrPtr = AddressEntry::instantiate(
      assetPair.first, assetPair.second);

   /*
   We cache all hits at this stage to speed up further resolution.

   In the case of nested addresses, we have to cache the predessors
   anyways as they are most likely going to be requested later, yet
   there is no guarantee the account address hashmap which our
   resolution is based on carries the predecessor hashes. addToMap
   takes care of this for us.
   */

   addToMap(addrPtr);
   return addrPtr->getPreimage();
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& ResolverFeed_AssetWalletSingle::getPrivKeyForPubkey(
   const BinaryData& pubkey)
{
   //check cache first
   {
      auto pubkeyref = pubkey.getRef();
      auto cacheIter = pubkey_to_asset_.find(pubkeyref);
      if (cacheIter != pubkey_to_asset_.end())
      {
         return wltPtr_->getDecryptedPrivateKeyForAsset(
            cacheIter->second);
      }
   }

   //if we have a bip32 path hint for this pubkey, use that
   {
      auto pathIter = bip32Paths_.find(pubkey);
      if (pathIter != bip32Paths_.end())
      {
         if (pathIter->second.second.empty())
         {
            pathIter->second.second = 
               wltPtr_->derivePrivKeyFromPath(pathIter->second.first);
         }

         return wltPtr_->getDecrypedPrivateKeyForId(pathIter->second.second);
      }
   }

   /*
   Lacking a cache hit, we need to get the asset for this pubkey. All
   pubkeys are carried as assets, and all assets are expressed as all
   possible script hash variations within an account's hash map.

   Therefor, converting this pubkey to one of the eligible script hash
   variation should yield a hit from the key to asset resolution logic.

   From that asset object, we can then get the private key.

   Conveniently, the only hash ever used on public keys is
   BtcUtils::getHash160
   */

   auto&& hash = BtcUtils::getHash160(pubkey);
   auto assetPair = getAssetPairForKey(hash);
   if (assetPair.first == nullptr)
      throw NoAssetException("invalid pubkey");

   auto assetSingle =
      dynamic_pointer_cast<AssetEntry_Single>(assetPair.first);
   if (assetSingle == nullptr)
      throw logic_error("invalid asset type");

   return wltPtr_->getDecryptedPrivateKeyForAsset(assetSingle);

   /*
   In case of NoAssetException failure, it is still possible this public key 
   is used in an exotic script (multisig or other).
   Use ResolverFeed_AssetWalletSingle_Exotic for a wallet carrying
   that kind of scripts.

   logic_error means the asset was found but it does not carry the private 
   key.

   DecryptedDataContainerException means the wallet failed to decrypt the 
   encrypted pubkey (bad passphrase or unlocked wallet most likely).
   */
}

////////////////////////////////////////////////////////////////////////////////
BIP32_AssetPath ResolverFeed_AssetWalletSingle::resolveBip32PathForPubkey(
   const BinaryData& pubkey)
{
   //check cache first
   {
      auto pubkeyref = pubkey.getRef();
      auto cacheIter = pubkey_to_asset_.find(pubkeyref);
      if (cacheIter != pubkey_to_asset_.end())
         return wltPtr_->getBip32PathForAsset(cacheIter->second);
   }

   auto&& hash = BtcUtils::getHash160(pubkey);
   auto assetPair = getAssetPairForKey(hash);
   if (assetPair.first == nullptr)
      throw NoAssetException("invalid pubkey");

   return wltPtr_->getBip32PathForAsset(assetPair.first);
}

////////////////////////////////////////////////////////////////////////////////
void ResolverFeed_AssetWalletSingle::seedFromAddressEntry(
   shared_ptr<AddressEntry> addrPtr)
{
   try
   {
      //add hash to preimage pair
      auto& hash = addrPtr->getHash();
      auto& preimage = addrPtr->getPreimage();
      hash_to_preimage_.insert(make_pair(hash, preimage));
   }
   catch (AddressException&)
   {
      return;
   }

   //is this address nested?
   auto addrNested =
      dynamic_pointer_cast<AddressEntry_Nested>(addrPtr);
   if (addrNested == nullptr)
      return; //return if not

   //seed the predecessor too
   seedFromAddressEntry(addrNested->getPredecessor());
}

////////////////////////////////////////////////////////////////////////////////
void ResolverFeed_AssetWalletSingle::setBip32PathForPubkey(
   const BinaryData& pubkey, const BIP32_AssetPath& path)
{
   bip32Paths_.emplace(pubkey, make_pair(path, BinaryData()));
}
