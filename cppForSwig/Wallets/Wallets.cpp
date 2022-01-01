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
using namespace Armory::Signer;
using namespace Armory::Assets;
using namespace Armory::Accounts;
using namespace Armory::Wallets;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetWallet::AssetWallet(
   shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<IO::WalletHeader> headerPtr, 
   const string& masterID) :
   iface_(iface), 
   dbName_(headerPtr->getDbName()),
   walletID_(headerPtr->walletID_)
{
   auto ifaceCopy = iface_;
   auto getWriteTx = [ifaceCopy](const string& name)->
      unique_ptr<IO::DBIfaceTransaction>
   {
      return ifaceCopy->beginWriteTransaction(name);
   };

   decryptedData_ = make_shared<Encryption::DecryptedDataContainer>(
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
shared_ptr<IO::WalletDBInterface> AssetWallet::getIfaceFromFile(
    const string& path, bool fileExists, const PassphraseLambda& passLbd)
{
   /*
   This passphrase lambda is used to prompt the user for the wallet file's
   passphrase. Private keys use a different passphrase, with its own prompt.
   */

   auto iface = make_shared<IO::WalletDBInterface>();
   iface->setupEnv(path, fileExists, passLbd);

   return iface;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<IO::WalletDBInterface> AssetWallet::getIface() const
{
   return iface_;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressAccount> AssetWallet::createAccount(
   shared_ptr<AccountType> accountType)
{
   auto cipher = make_unique<Encryption::Cipher_AES>(
      decryptedData_->getDefaultKdfId(),
      decryptedData_->getMasterEncryptionKeyId());

   //instantiate AddressAccount object from AccountType
   auto ifaceCopy = iface_;
   auto getRootLbd = [this]()->shared_ptr<AssetEntry>
   {
      return this->getRoot();
   };

   auto account_ptr = AddressAccount::make_new(
      dbName_, accountType, decryptedData_, move(cipher), getRootLbd);

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
      mainAccount_.serializeValue(bwData);

      auto&& tx = iface_->beginWriteTransaction(dbName_);
      tx->insert(bwKey.getData(), bwData.getData());
   }

   shared_ptr<AddressAccount> sharedAcc(move(account_ptr));
   accounts_.insert(make_pair(accID, sharedAcc));
   return sharedAcc;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::setMainWallet(
   shared_ptr<IO::WalletDBInterface> iface, const string& walletID)
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
string AssetWallet::getMainWalletID(shared_ptr<IO::WalletDBInterface> iface)
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
   catch (IO::NoEntryInWalletException&)
   {
      LOGERR << "main wallet ID is not set!";
      throw WalletException("main wallet ID is not set!");
   }
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet::getMasterID(shared_ptr<IO::WalletDBInterface> iface)
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
   catch(IO::NoEntryInWalletException&)
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
   shared_ptr<IO::DBIfaceTransaction> sharedTx(move(uniqueTx));
   auto walletTx = dynamic_pointer_cast<IO::WalletIfaceTransaction>(sharedTx);

   {
      //main account
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

      try
      {
         auto account_id = sharedTx->getDataRef(bwKey.getData());
         mainAccount_ = AddressAccountId::deserializeValue(account_id);
      }
      catch (const IdException&)
      {}
   }

   {
      //root asset
      root_ = nullptr;

      try
      {
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);
         auto rootAssetRef = getDataRefForKey(sharedTx.get(), bwKey.getData());

         auto asset_root = AssetEntry::deserDBValue(
            AssetId::getRootAssetId(), rootAssetRef);
         root_ = dynamic_pointer_cast<AssetEntry_Single>(asset_root);
      }
      catch(const IO::NoEntryInWalletException&)
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

         auto seedUPtr = EncryptedSeed::deserialize(rootAssetRef);
         seed_ = shared_ptr<EncryptedSeed>(move(seedUPtr));
         if (seed_ == nullptr)
            throw WalletException("failed to deser wallet seed");
      }
      catch(IO::NoEntryInWalletException&)
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
      catch(IO::NoEntryInWalletException& )
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
      catch(IO::NoEntryInWalletException& )
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
            auto addrAccId = AddressAccountId::deserializeKey(
               key, ADDRESS_ACCOUNT_PREFIX);

            //instantiate account object and read data on disk
            auto addressAccount = AddressAccount::readFromDisk(
               walletTx, addrAccId);
            shared_ptr<AddressAccount> accPtr(move(addressAccount));

            //insert
            accounts_.insert(make_pair(accPtr->getID(), accPtr));
         }
         catch (const IdException&)
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

   if (!mainAccount_.isValid())
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->getNewAddress(iface_, aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->getNewAddress(iface_, aeType);
   }

   throw WalletException("[getNewAddress] unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewChangeAddress(
   AddressEntryType aeType)
{
   ReentrantLock lock(this);

   if (!mainAccount_.isValid())
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->getNewChangeAddress(iface_, aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->getNewChangeAddress(iface_, aeType);
   }

   throw WalletException("[getNewChangeAddress] unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::peekNextChangeAddress(
   AddressEntryType aeType)
{
   ReentrantLock lock(this);

   if (!mainAccount_.isValid())
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->peekNextChangeAddress(iface_, aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->peekNextChangeAddress(iface_, aeType);
   }

   throw WalletException("[peekNextChangeAddress] unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::updateAddressEntryType(
   const AssetId& assetID, AddressEntryType aeType)
{
   ReentrantLock lock(this);

   auto accPtr = getAccountForID(assetID.getAddressAccountId());
   accPtr->updateInstantiatedAddressType(iface_, assetID, aeType);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewAddress(
   const AddressAccountId& accountID, AddressEntryType aeType)
{
   ReentrantLock lock(this);

   auto account = getAccountForID(accountID);
   return account->getNewAddress(iface_, aeType);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewAddress(
   const AssetAccountId& accountID, AddressEntryType aeType)
{
   ReentrantLock lock(this);

   auto account = getAccountForID(accountID.getAddressAccountId());
   return account->getNewAddress(iface_, accountID, aeType);
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
const pair<AssetId, AddressEntryType>& 
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
      scrAddr = move(BtcUtils::segWitAddressToScrAddr(addrStr).first);
   }

   return getAssetIDForScrAddr(scrAddr);
}

////////////////////////////////////////////////////////////////////////////////
const pair<AssetId, AddressEntryType>&
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
AddressEntryType AssetWallet::getAddrTypeForID(const AssetId& id) const
{
   ReentrantLock lock(this);
   
   auto addrPtr = getAddressEntryForID(id);
   return addrPtr->getType();
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet::isAssetUsed(const AssetId& id) const
{
   try
   {
      auto acc = getAccountForID(id.getAddressAccountId());
      if (acc == nullptr)
         return false;

      return acc->isAssetUsed(id);
   }
   catch (const exception&)
   {
      return false;
   }
}

////////////////////////////////////////////////////////////////////////////////
const Armory::Wallets::AddressAccountId& AssetWallet::getMainAccountID() const
{
   if (!mainAccount_.isValid())
      throw WalletException("[getMainAccountID] invalid account id");

   return mainAccount_;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressAccount> AssetWallet::getAccountForID(
   const AddressAccountId& id) const
{
   if (!id.isValid())
      throw WalletException("[getAccountForID] invalid account id");

   ReentrantLock lock(this);

   auto iter = accounts_.find(id);
   if (iter == accounts_.end())
      throw WalletException("[getAccountForID] unknown account ID");

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
AddressEntryType AssetWallet::getAddrTypeForAccount(const AssetId& id) const
{
   auto acc = getAccountForID(id.getAddressAccountId());
   return acc->getDefaultAddressType();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getAddressEntryForID(
   const AssetId& id) const
{
   ReentrantLock lock(this);

   if (!id.isValid())
      throw WalletException("invalid asset id");

   auto accPtr = getAccountForID(id.getAddressAccountId());
   return accPtr->getAddressEntryForID(id);
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
shared_ptr<AssetEntry> AssetWallet::getAssetForID(const AssetId& id) const
{
   if (!id.isValid())
      throw WalletException("invalid asset ID");

   ReentrantLock lock(this);

   auto acc = getAccountForID(id.getAddressAccountId());
   return acc->getAssetForID(id);
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
      account.second->extendPublicChain(iface_, count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPrivateChain(unsigned count)
{
   for (auto& account : accounts_)
   {
      account.second->extendPrivateChain(iface_, decryptedData_, count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPublicChainToIndex(
   const AddressAccountId& account_id, unsigned count,
   const std::function<void(int)>& progressCallback)
{
   auto account = getAccountForID(account_id);
   account->extendPublicChainToIndex(iface_,
      account->getOuterAccount()->getID(), count, progressCallback);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPrivateChainToIndex(
   const AddressAccountId& account_id, unsigned count)
{
   auto account = getAccountForID(account_id);
   account->extendPrivateChainToIndex(
      iface_, decryptedData_,
      account->getOuterAccount()->getID(), count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::addSubDB(
   const std::string& dbName, const PassphraseLambda& passLbd)
{
   if (iface_->getFreeDbCount() == 0)
      iface_->setDbCount(iface_->getDbCount() + 1);

   auto headerPtr = make_shared<IO::WalletHeader_Custom>();
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
shared_ptr<IO::WalletIfaceTransaction> AssetWallet::beginSubDBTransaction(
   const string& dbName, bool write)
{
   shared_ptr<IO::DBIfaceTransaction> tx;
   if (!write)
      tx = iface_->beginReadTransaction(dbName);
   else
      tx = iface_->beginWriteTransaction(dbName);

   auto wltTx = dynamic_pointer_cast<IO::WalletIfaceTransaction>(tx);
   if (wltTx == nullptr)
      throw WalletException("[beginSubDBTransaction] invalid dbtx type");
   return wltTx;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet> AssetWallet::loadMainWalletFromFile(
   const string& path, const PassphraseLambda& passLbd)
{
   auto iface = getIfaceFromFile(path.c_str(), true, passLbd);
   auto mainWalletID = getMainWalletID(iface);
   auto headerPtr = iface->getWalletHeader(mainWalletID);

   shared_ptr<AssetWallet> wltPtr;

   switch (headerPtr->type_)
   {
   case IO::WalletHeaderType_Single:
   {
      auto wltSingle = make_shared<AssetWallet_Single>(
         iface, headerPtr, string());
      wltSingle->readFromFile();

      wltPtr = wltSingle;
      break;
   }

   case IO::WalletHeaderType_Multisig:
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
   IO::DBIfaceTransaction* tx, const BinaryData& key)
{
   /** The reference lifetime is tied to the db tx lifetime. The caller has to
   maintain the tx for as long as the data ref needs to be valid **/

   auto ref = tx->getDataRef(key);

   if (ref.getSize() == 0)
      throw IO::NoEntryInWalletException();

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
   auto originIface = getIfaceFromFile(filename, true, passLbd);
   auto masterID = getMasterID(originIface);

   auto woIface = getIfaceFromFile(newname, false, passLbd);
   woIface->setDbCount(originIface->getDbCount());
   woIface->lockControlContainer(passLbd);

   //cycle through wallet metas, copy wallet structure and assets
   for (auto& metaPtr : originIface->getHeaderMap())
   {
      switch (metaPtr.second->type_)
      {
      case IO::WalletHeaderType_Single:
      {
         woIface->addHeader(metaPtr.second);

         //load wallet
         auto wltSingle = make_shared<AssetWallet_Single>(
            originIface, metaPtr.second, masterID);
         wltSingle->readFromFile();

         //copy content
         auto wpd = AssetWallet_Single::exportPublicData(wltSingle);
         AssetWallet_Single::importPublicData(wpd, woIface);

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
set<AddressAccountId> AssetWallet::getAccountIDs(void) const
{
   set<AddressAccountId> result;
   for (auto& accPtr : accounts_)
      result.insert(accPtr.second->getID());

   return result;
}

////////////////////////////////////////////////////////////////////////////////
map<AssetId, shared_ptr<AddressEntry>> AssetWallet::getUsedAddressMap() const
{
   /***
   This is an expensive call, do not spam it.
   ***/

   map<AssetId, shared_ptr<AddressEntry>> result;
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
   shared_ptr<IO::DBIfaceTransaction> sharedTx(move(uniqueTx));
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
   shared_ptr<IO::DBIfaceTransaction> sharedTx(move(uniqueTx));
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
AssetWallet_Single::AssetWallet_Single(shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<IO::WalletHeader> metaPtr, const string& masterID) :
   AssetWallet(iface, metaPtr, masterID)
{
   if (metaPtr == nullptr ||
      metaPtr->magicBytes_ != Armory::Config::BitcoinSettings::getMagicBytes())
   {
      throw WalletException(
         "[AssetWallet_Single] network magic bytes mismatch");
   }
}

////////////////////////////////////////////////////////////////////////////////
const AddressAccountId& AssetWallet_Single::createBIP32Account(
   std::shared_ptr<AccountType_BIP32> accTypePtr)
{
   auto accountPtr = createAccount(accTypePtr);
   if (!isWatchingOnly())
   {
      accountPtr->extendPrivateChain(iface_,
         decryptedData_, accTypePtr->getAddressLookup());
   }
   else
   {
      accountPtr->extendPublicChain(iface_, accTypePtr->getAddressLookup());
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
      [&controlPassphrase](const set<EncryptionKeyId>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterID << "_wallet.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), false, controlPassLbd);

   string walletID;
   {
      //generate chaincode if it's not provided
      if (chaincode.empty())
         chaincode = BtcUtils::computeChainCode_Armory135(privateRoot);
      
      auto chaincodeCopy = chaincode;
      auto derScheme = make_shared<DerivationScheme_ArmoryLegacy>(
         chaincodeCopy);

      auto asset_single = make_shared<AssetEntry_Single>(
         AssetId::getRootAssetId(),
         pubkey, nullptr);

      walletID = move(computeWalletID(derScheme, asset_single));
   }

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

   //create account
   auto account135 = make_shared<AccountType_ArmoryLegacy>();
   account135->setMain(true);

   if (passphrase.getSize() > 0)
   {
      //custom passphrase, set prompt lambda for the chain extention
      auto passphraseLambda =
         [&passphrase](const set<EncryptionKeyId>&)->SecureBinaryData
      {
         return passphrase;
      };

      walletPtr->decryptedData_->setPassphrasePromptLambda(passphraseLambda);
   }

   auto accountPtr = walletPtr->createAccount(account135);
   accountPtr->extendPrivateChain(
      iface, walletPtr->decryptedData_, lookup - 1);

   walletPtr->resetPassphrasePromptLambda();
   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single>
   AssetWallet_Single::createFromPublicRoot_Armory135(
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
      [&controlPassphrase](const set<EncryptionKeyId>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterID << "_WatchingOnly.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), false, controlPassLbd);

   string walletID;
   shared_ptr<AssetEntry_Single> rootPtr;
   {
      //walletID
      auto chainCode_copy = chainCode;
      auto derScheme = make_shared<DerivationScheme_ArmoryLegacy>(
         chainCode_copy);

      rootPtr = make_shared<AssetEntry_ArmoryLegacyRoot>(
         AssetId::getRootAssetId(),
         pubRoot, nullptr, chainCode);

      walletID = move(computeWalletID(derScheme, rootPtr));
   }

   //create wallet
   auto walletPtr = initWalletDbWithPubRoot(
      iface,
      controlPassphrase,
      masterID, walletID,
      rootPtr);

   //set as main
   setMainWallet(iface, walletID);

   //add account
   auto account135 = make_shared<AccountType_ArmoryLegacy>();
   account135->setMain(true);

   auto accountPtr = walletPtr->createAccount(account135);
   accountPtr->extendPublicChain(iface, lookup - 1);

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
   if (seed.empty())
      throw WalletException("[createFromSeed_BIP32] empty seed");

   BIP32_Node rootNode;
   rootNode.initFromSeed(seed);

   auto coinType = Armory::Config::BitcoinSettings::getCoinType();

   //address accounts
   set<shared_ptr<AccountType_BIP32>> accountTypes;

   {
      //legacy account: 44
      vector<unsigned> path = { 0x8000002C, coinType, 0x80000000 };
      auto legacyAcc = AccountType_BIP32::makeFromDerPaths(
         rootNode.getThisFingerprint(), {path});

      //nodes
      legacyAcc->setNodes({
         BIP32_OUTER_ACCOUNT_DERIVATIONID,
         BIP32_INNER_ACCOUNT_DERIVATIONID});
      legacyAcc->setOuterAccountID(
         BIP32_OUTER_ACCOUNT_DERIVATIONID);
      legacyAcc->setInnerAccountID(
         BIP32_INNER_ACCOUNT_DERIVATIONID);

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
      auto nestedAcc = AccountType_BIP32::makeFromDerPaths(
         rootNode.getThisFingerprint(), {path});
         
      //nodes
      nestedAcc->setNodes({
         BIP32_OUTER_ACCOUNT_DERIVATIONID,
         BIP32_INNER_ACCOUNT_DERIVATIONID});
      nestedAcc->setOuterAccountID(
         BIP32_OUTER_ACCOUNT_DERIVATIONID);
      nestedAcc->setInnerAccountID(
         BIP32_INNER_ACCOUNT_DERIVATIONID);

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
      auto segwitAcc = AccountType_BIP32::makeFromDerPaths(
         rootNode.getThisFingerprint(), {path});

      //nodes
      segwitAcc->setNodes({
         BIP32_OUTER_ACCOUNT_DERIVATIONID,
         BIP32_INNER_ACCOUNT_DERIVATIONID});
      segwitAcc->setOuterAccountID(
         BIP32_OUTER_ACCOUNT_DERIVATIONID);
      segwitAcc->setInnerAccountID(
         BIP32_INNER_ACCOUNT_DERIVATIONID);

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
      [&controlPassphrase](const set<EncryptionKeyId>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   if (!isPublic)
      pathSS << folder << "/armory_" << masterID << "_wallet.lmdb";
   else
      pathSS << folder << "/armory_" << masterID << "_WatchingOnly.lmdb";

   auto iface = getIfaceFromFile(pathSS.str(), false, controlPassLbd);

   string walletID;
   {
      //walletID
      auto chaincode_copy = node.getChaincode();
      auto derScheme =
         make_shared<DerivationScheme_ArmoryLegacy>(chaincode_copy);

      auto asset_single = make_shared<AssetEntry_Single>(
         AssetId::getRootAssetId(),
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
      [&passphrase](const set<EncryptionKeyId>&)->SecureBinaryData
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
shared_ptr<AssetWallet_Single> AssetWallet_Single::createBlank(
   const string& folder, const string& walletID,
   const SecureBinaryData& controlPassphrase)
{
   auto&& masterID = walletID;

   /*
   Create control passphrase lambda. It gets wiped after the wallet is setup
   */
   auto controlPassLbd = 
      [&controlPassphrase](const set<EncryptionKeyId>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterID << "_WatchingOnly.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), false, controlPassLbd);

   //address accounts
   shared_ptr<AssetWallet_Single> walletPtr = nullptr;

   //ctors move the arguments in, gotta create copies first
   walletPtr = initWalletDbWithPubRoot(
      iface,
      controlPassphrase,
      masterID, walletID,
      nullptr);

   //set as main
   setMainWallet(iface, walletID);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet_Single::computeWalletID(
   shared_ptr<DerivationScheme> derScheme,
   shared_ptr<AssetEntry> rootEntry)
{
   auto&& addrVec = derScheme->extendPublicChain(rootEntry, 1, 1, nullptr);
   if (addrVec.size() != 1)
      throw WalletException("unexpected chain derivation output");

   auto firstEntry = dynamic_pointer_cast<AssetEntry_Single>(addrVec[0]);
   if (firstEntry == nullptr)
      throw WalletException("unexpected asset entry type");

   return BtcUtils::computeID(firstEntry->getPubKey()->getUncompressedKey());
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::initWalletDb(
   shared_ptr<IO::WalletDBInterface> iface,
   const string& masterID, const string& walletID,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& controlPassphrase,
   const SecureBinaryData& privateRoot,
   const SecureBinaryData& chaincode,
   uint32_t seedFingerprint)
{
   auto headerPtr = make_shared<IO::WalletHeader_Single>(
      Armory::Config::BitcoinSettings::getMagicBytes());
   headerPtr->walletID_ = walletID;

   //init headerPtr object
   auto masterKeyStruct = IO::WalletDBInterface::initWalletHeaderObject(
      headerPtr, passphrase);

   //copy cipher to cycle the IV then encrypt the private root
   auto rootCipher = masterKeyStruct.cipher_->getCopy(
      headerPtr->masterEncryptionKeyId_);
   auto encryptedRoot = rootCipher->encrypt(
      masterKeyStruct.decryptedMasterKey_.get(), rootCipher->getKdfId(), privateRoot);

   //compute public root
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privateRoot);

   //create encrypted object
   AssetId rootAssetId = AssetId::getRootAssetId();
   auto cipherData = make_unique<Encryption::CipherData>(
      encryptedRoot, move(rootCipher));
   auto rootAsset = make_shared<Asset_PrivateKey>(
      rootAssetId, move(cipherData));

   unique_ptr<AssetEntry> rootAssetEntry;
   if (seedFingerprint != 0)
   {
      //bip32 root
      rootAssetEntry = make_unique<AssetEntry_BIP32Root>(
         rootAssetId,
         pubkey, rootAsset,
         chaincode, 0, 0, 0, seedFingerprint, vector<uint32_t>());
   }
   else
   {
      //legacy armory root
      rootAssetEntry = make_unique<AssetEntry_ArmoryLegacyRoot>(
         rootAssetId,
         pubkey, rootAsset, chaincode);
   }

   //create wallet
   auto walletPtr = make_shared<AssetWallet_Single>(iface, headerPtr, masterID);

   //add kdf & master key
   walletPtr->decryptedData_->addKdf(masterKeyStruct.kdf_);
   walletPtr->decryptedData_->addEncryptionKey(masterKeyStruct.masterKey_);

   auto controlPassLbd = 
      [&controlPassphrase](const set<EncryptionKeyId>&)->SecureBinaryData
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
shared_ptr<AssetWallet_Single> AssetWallet_Single::initWalletDbWithPubRoot(
   shared_ptr<IO::WalletDBInterface> iface,
   const SecureBinaryData& controlPassphrase,
   const string& masterID, const string& walletID,
   shared_ptr<AssetEntry_Single> pubRoot)
{
   if (pubRoot != nullptr)
   {
      if (pubRoot->hasPrivateKey())
         throw WalletException("[initWalletDbWithPubRoot] root has priv key");
   }

   auto headerPtr = make_shared<IO::WalletHeader_Single>(
      Armory::Config::BitcoinSettings::getMagicBytes());
   headerPtr->walletID_ = walletID;
   IO::WalletDBInterface::initWalletHeaderObject(headerPtr, {});
   auto walletPtr = make_shared<AssetWallet_Single>(iface, headerPtr, masterID);

   auto controlPassLbd = 
      [&controlPassphrase](const set<EncryptionKeyId>&)->SecureBinaryData
   {
      return controlPassphrase;
   };

   iface->lockControlContainer(controlPassLbd);
   iface->addHeader(headerPtr);
   iface->unlockControlContainer();

   /**insert the original entries**/
   {
      auto&& tx = iface->beginWriteTransaction(walletPtr->dbName_);

      if (pubRoot != nullptr)
      {
         //root asset
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);

         auto&& data = pubRoot->serialize();

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
   shared_ptr<Encryption::EncryptedAssetData> assetPtr)
{
   //have to lock the decryptedData object before calling this method
   return decryptedData_->getClearTextAssetData(assetPtr);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getDecryptedPrivateKeyForAsset(
   std::shared_ptr<AssetEntry_Single> assetPtr)
{
   auto assetPrivKey = assetPtr->getPrivKey();

   if (assetPrivKey == nullptr)
   {
      auto account = getAccountForID(assetPtr->getID().getAddressAccountId());
      assetPrivKey = account->fillPrivateKey(iface_,
         decryptedData_, assetPtr->getID());
   }
   
   return getDecryptedValue(assetPrivKey);
}

////////////////////////////////////////////////////////////////////////////////
const AssetId& AssetWallet_Single::derivePrivKeyFromPath(
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
   auto privKey = decryptedData_->getClearTextAssetData(
      rootBip32->getPrivKey());
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
   return decryptedData_->insertClearTextAssetData(
      hdNode.private_key, BTC_ECKEY_PKEY_LENGTH);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getDecrypedPrivateKeyForId(
   const AssetId& id) const
{
   return decryptedData_->getClearTextAssetData(id);
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
   if (root_ == nullptr)
      throw WalletException("[getArmory135Chaincode] null root");

   auto root135 = dynamic_pointer_cast<AssetEntry_ArmoryLegacyRoot>(root_);
   if (root135 == nullptr)
      throw WalletException("[getArmory135Chaincode] unexpected root type");

   return root135->getChaincode();
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::importPublicData(
   const WalletPublicData& wpd, std::shared_ptr<IO::WalletDBInterface> iface)
{
   //TODO: merging from exported data

   //open the relevant db name
   auto&& tx = iface->beginWriteTransaction(wpd.dbName_);

   //open the wallet
   auto headerPtr = make_shared<IO::WalletHeader_Single>(
      Armory::Config::BitcoinSettings::getMagicBytes());
   headerPtr->walletID_ = wpd.walletID_;
   auto wltWO = make_unique<AssetWallet_Single>(iface, headerPtr, wpd.masterID_);

   if (wpd.mainAccountID_.isValid())
   {
      //main account
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

      BinaryWriter bwData;
      wpd.mainAccountID_.serializeValue(bwData);
      tx->insert(bwKey.getData(), bwData.getData());
   }

   if (wpd.pubRoot_ != nullptr && wltWO->getRoot() == nullptr)
   {
      //wallet is missing a root, commit
      BinaryWriter bwKey;
      bwKey.put_uint32_t(ROOTASSET_KEY);

      auto&& data = wpd.pubRoot_->serialize();
      tx->insert(bwKey.getData(), data);

      //and set it
      wltWO->root_ = wpd.pubRoot_;
   }

   //address accounts
   for (auto& accPair : wpd.accounts_)
   {
      const auto& accData = accPair.second;

      //guess address account type
      auto outerAccIter = accData.accountDataMap_.find(accData.outerAccountId_);
      if (outerAccIter == accData.accountDataMap_.end())
      {
         throw WalletException("[importPublicData] "
            "Address account data missing outer account");
      }

      //reconstruct derivation scheme object
      auto derData = DBUtils::getDataRefForPacket(
         outerAccIter->second.derivationData_);
      auto derScheme = DerivationScheme::deserialize(derData);

      //instantiate account type object
      shared_ptr<AccountType> accTypePtr;
      switch (derScheme->getType())
      {
      case DerivationSchemeType::ArmoryLegacy:
      {
         if (accData.accountDataMap_.size() != 1)
         {
            throw WalletException("[importPublicData]"
               " invalid account data map size");
         }

         accTypePtr = make_shared<AccountType_ArmoryLegacy>();
         break;
      }

      case DerivationSchemeType::BIP32:
      case DerivationSchemeType::BIP32_Salted:
      {
         //create derTree
         auto rootBip32 = dynamic_pointer_cast<AssetEntry_BIP32Root>(
            wpd.pubRoot_);
         if (rootBip32 == nullptr)
            throw WalletException("[importPublicData] invalid root");

         //grab the path for each asset account
         vector<PathAndRoot> pathsAndRoots;
         for (const auto& acc : accData.accountDataMap_)
         {
            //deser the root
            auto accRootData = DBUtils::getDataRefForPacket(acc.second.rootData_);
            auto accRoot = AssetEntry::deserDBValue(
               AssetId::getRootAssetId(), accRootData);
            auto accRootBip32 = dynamic_pointer_cast<AssetEntry_BIP32Root>(
               accRoot);
            if (accRootBip32 == nullptr)
            {
               throw WalletException("[importPublicData] "
                  "unexpected account root type");
            }

            //get der path from the root
            pathsAndRoots.emplace_back(
               accRootBip32->getDerivationPath(), accRootBip32->getXPub());
         }

         //create account type object from paths
         vector<vector<uint32_t>> paths;
         for (auto& pathAndRootIt : pathsAndRoots)
            paths.emplace_back(pathAndRootIt.getPath());

         shared_ptr<AccountType_BIP32> accTypeBip32;
         if (derScheme->getType() == DerivationSchemeType::BIP32)
         {
            accTypeBip32 = AccountType_BIP32::makeFromDerPaths(
               rootBip32->getSeedFingerprint(true), paths);
         }
         else if (derScheme->getType() == DerivationSchemeType::BIP32_Salted)
         {
            auto derSchemeSalted = 
               dynamic_pointer_cast<DerivationScheme_BIP32_Salted>(derScheme);
            if (derSchemeSalted == nullptr)
            {
               throw WalletException("[importPublicData]"
                  " unexpected der scheme");
            }

            accTypeBip32 = AccountType_BIP32_Salted::makeFromDerPaths(
               rootBip32->getSeedFingerprint(true), paths,
               derSchemeSalted->getSalt());
         }

         //set the roots
         accTypeBip32->setRoots(pathsAndRoots);

         //address types
         for (auto& addrType : accData.addressTypes_)
            accTypeBip32->addAddressType(addrType);
         accTypeBip32->setDefaultAddressType(accData.defaultAddressEntryType_);

         //account ids
         accTypeBip32->setOuterAccountID(
            accData.outerAccountId_.getAssetAccountKey());
         accTypeBip32->setInnerAccountID(
            accData.innerAccountId_.getAssetAccountKey());

         accTypePtr = accTypeBip32;
         break;
      }

      case DerivationSchemeType::ECDH:
      {
         if (accData.accountDataMap_.size() != 1)
         {
            throw WalletException("[importPublicData]"
               " invalid account data map size");
         }

         const auto& adm = accData.accountDataMap_.begin()->second;
         auto accRootData = DBUtils::getDataRefForPacket(adm.rootData_);
         auto accRoot = AssetEntry::deserDBValue(
            AssetId::getRootAssetId(), accRootData);
         auto accRootEcdh = dynamic_pointer_cast<AssetEntry_Single>(accRoot);
         if (accRootEcdh == nullptr)
         {
            throw WalletException("[importPublicData] "
               "unexpected account root type");
         }

         auto accEcdh = make_shared<AccountType_ECDH>(
            SecureBinaryData(), accRootEcdh->getPubKey()->getCompressedKey());

         //address types
         for (auto& addrType : accData.addressTypes_)
            accEcdh->addAddressType(addrType);
         accEcdh->setDefaultAddressType(accData.defaultAddressEntryType_);

         accTypePtr = accEcdh;
         break;
      }

      default:
         break;
      }

      if (accTypePtr == nullptr)
      {
         throw WalletException("[importPublicData] "
            "Failed to resolve address account type");
      }

      //address account main flag
      if (accData.ID_ == wpd.mainAccountID_)
         accTypePtr->setMain(true);

      //create the account
      auto newAcc = wltWO->createAccount(accTypePtr);

      //check the created account matches the public data we're importing from
      if (newAcc->addressTypes_ != accData.addressTypes_ ||
         newAcc->defaultAddressEntryType_ != accData.defaultAddressEntryType_)
      {
         throw WalletException("[importPublicData] Address type mismtach");
      }

      if (newAcc->accountDataMap_.size() != accData.accountDataMap_.size())
         throw WalletException("[importPublicData] Account map mismatch");

      auto newAccDataIter = newAcc->accountDataMap_.begin();
      auto accDataIter = accData.accountDataMap_.begin();
      while (newAccDataIter != newAcc->accountDataMap_.end())
      {
         if (newAccDataIter->first != accDataIter->first)
            throw WalletException("[importPublicData] Account map mismatch");

         ++newAccDataIter;
         ++accDataIter;
      }

      if (newAcc->outerAccountId_ != accData.outerAccountId_ ||
         newAcc->innerAccountId_ != accData.innerAccountId_)
      {
         throw WalletException("[importPublicData] "
            "Mismtach in outer/inner accounts");
      }

      //synchronize the account
      newAcc->importPublicData(accData);

      //commit to disk
      newAcc->commit(iface);
   }

   //meta accounts
   for (auto& metaAccPtr : wpd.metaAccounts_)
   {
      auto accCopy = metaAccPtr.second->copy(wpd.dbName_);
      auto metaTx = iface->beginWriteTransaction(wpd.dbName_);
      accCopy->commit(move(metaTx));
   }
}

////////////////////////////////////////////////////////////////////////////////
WalletPublicData AssetWallet_Single::exportPublicData(
   shared_ptr<AssetWallet_Single> wlt)
{
   WalletPublicData wpd{
      wlt->dbName_,
      wlt->masterID_,
      wlt->walletID_,
      wlt->mainAccount_
   };

   //root
   if (wlt->root_ != nullptr)
      wpd.pubRoot_ = wlt->root_->getPublicCopy();

   //address accounts
   for (auto& addrAccPtr : wlt->accounts_)
   {
      auto accData = addrAccPtr.second->exportPublicData();
      wpd.accounts_.emplace(accData.ID_, accData);
   }

   //meta accounts
   for (auto& metaAccPtr : wlt->metaDataAccounts_)
   {
      auto accCopy = metaAccPtr.second->copy(wlt->dbName_);
      wpd.metaAccounts_.emplace(accCopy->getType(), accCopy);
   }

   return wpd;
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
         [&passphrase](const set<EncryptionKeyId>&)->SecureBinaryData
      {
         return passphrase;
      };

      decryptedData_->setPassphrasePromptLambda(passphraseLambda);
   }

   //create encrypted seed object
   {
      auto lock = lockDecryptedContainer();

      auto cipherText = decryptedData_->encryptData(cipherCopy.get(), seed);
      auto cipherData = make_unique<Encryption::CipherData>(
         cipherText, move(cipherCopy));
      seed_ = make_shared<EncryptedSeed>(move(cipherData));
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
   const AssetId& id) const
{
   auto asset = getAssetForID(id);
   return getBip32PathForAsset(asset);
}

////////////////////////////////////////////////////////////////////////////////
BIP32_AssetPath AssetWallet_Single::getBip32PathForAsset(
   shared_ptr<AssetEntry> asset) const
{
   const auto& id = asset->getID();
   if (!id.isValid())
      throw WalletException("invalid asset id");

   auto assetSingle = dynamic_pointer_cast<AssetEntry_Single>(asset);
   if (assetSingle == nullptr)
      throw WalletException("unexpected asset type");
   
   auto pubKeyPtr = assetSingle->getPubKey();
   if (pubKeyPtr == nullptr)
      throw WalletException("asset is missing public key");

   const auto& pubkey = pubKeyPtr->getCompressedKey();
   
   auto account = getAccountForID(id.getAddressAccountId());
   auto accountRoot = account->getBip32RootForAssetId(id);
   auto accountPath = accountRoot->getDerivationPath();

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
         { (uint32_t)id.getAssetKey() },
         accountRoot->getThisFingerprint(),
         rootObj);
   }
   else
   {
      //wallet has a root, build path from that
      auto rootPath = accountRoot->getDerivationPath();
      rootPath.push_back(id.getAssetKey());

      return BIP32_AssetPath(
         pubkey,
         rootPath,
         rootBip32->getThisFingerprint(),
         nullptr);
   }
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet_Single::getXpubForAssetID(const AssetId& id) const
{
   if (!id.isValid())
      throw WalletException("invalid asset id");

   //grab account
   auto addrAccount = getAccountForID(id.getAddressAccountId());
   auto accountPtr = addrAccount->getAccountForID(id);

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
   node.derivePublic(id.getAssetKey());

   auto b58sbd = node.getBase58();
   return string(b58sbd.getCharPtr(), b58sbd.getSize());
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AccountType_BIP32> AssetWallet_Single::makeNewBip32AccTypeObject(
   const std::vector<uint32_t>& derPath) const
{
   auto rootBip32 = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);
   if (rootBip32 == nullptr)
      throw WalletException("[makeNewBip32AccTypeObject] unexpected root ptr");

   auto seedFingerprint = rootBip32->getSeedFingerprint(true);
   return AccountType_BIP32::makeFromDerPaths(seedFingerprint, {derPath});
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet_Multisig
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetWallet_Multisig::AssetWallet_Multisig(shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<IO::WalletHeader> metaPtr, const string& masterID) :
   AssetWallet(iface, metaPtr, masterID)
{
   if (metaPtr == nullptr ||
      metaPtr->magicBytes_ != Armory::Config::BitcoinSettings::getMagicBytes())
   {
      throw WalletException(
         "[AssetWallet_Multisig] network magic bytes mismatch");
   }
}

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

         auto subWltMeta = make_shared<IO::WalletHeader_Subwallet>();
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
   shared_ptr<Encryption::EncryptedAssetData> assetPtr)
{
   return decryptedData_->getClearTextAssetData(assetPtr);
}