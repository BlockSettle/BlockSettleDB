////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Utils/DBUtils.h"
#include "AccountTypes.h"
#include "AssetAccounts.h"
#include "../EncryptedDB.h"
#include "../DerivationScheme.h"
#include "../WalletFileInterface.h"

using namespace Armory::Assets;
using namespace Armory::Accounts;
using namespace Armory::Wallets;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccountData
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetAccountData::AssetAccountData(
   const AssetAccountType type,
   const Wallets::AssetAccountId& id,
   std::shared_ptr<Assets::AssetEntry> root,
   std::shared_ptr<Assets::DerivationScheme> scheme,
   const std::string& dbName) :
   type_(type), id_(id),
   root_(root), derScheme_(scheme),
   dbName_(dbName)
{}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetAccountData> AssetAccountData::copy(
   const std::string& dbName) const
{
   auto accDataCopy = std::make_shared<AssetAccountData>(type_,
      id_, root_, derScheme_, dbName);

   //shared_ptr of asset entries are not copied
   accDataCopy->assets_ = assets_;
   accDataCopy->lastUsedIndex_ = lastUsedIndex_;
   accDataCopy->lastHashedAsset_ = lastHashedAsset_;
   return accDataCopy;
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountExtendedData::~AssetAccountExtendedData() {}
AssetAccountSaltMap::~AssetAccountSaltMap() {}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccount
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetAccount::AssetAccount(std::shared_ptr<AssetAccountData> data) :
   data_(data)
{
   if (data == nullptr) {
      throw std::runtime_error("null account data ptr");
   }
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountType AssetAccount::type() const
{
   return AssetAccountType::Plain;
}

////////////////////////////////////////////////////////////////////////////////
const AssetAccountId& AssetAccount::getID(void) const
{
   return data_->id_;
}

////////////////////////////////////////////////////////////////////////////////
size_t AssetAccount::writeAssetEntry(std::shared_ptr<AssetEntry> entryPtr,
   std::shared_ptr<IO::WalletDBInterface> iface)
{
   if (!entryPtr->needsCommit()) {
      return SIZE_MAX;
   }
   if (iface == nullptr) {
      throw AccountException("writeAssetEntry: null iface");
   }

   auto tx = iface->beginWriteTransaction(data_->dbName_);
   auto serializedEntry = entryPtr->serialize();
   auto dbKey = entryPtr->getDbKey();
   tx->insert(dbKey, serializedEntry);

   entryPtr->doNotCommit();
   return serializedEntry.getSize();
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateOnDiskAssets(
   std::shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr) {
      throw AccountException("updateOnDiskAssets: null iface");
   }

   auto tx = iface->beginWriteTransaction(data_->dbName_);
   for (auto& entryPtr : data_->assets_) {
      writeAssetEntry(entryPtr.second, iface);
   }
   updateAssetCount(iface);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateAssetCount(
   std::shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr) {
      throw AccountException("updateAssetCount: null iface");
   }
   //asset count key
   const auto& id = getID();
   auto idKey = id.getSerializedKey(ASSET_COUNT_PREFIX);

   //asset count
   BinaryWriter bwData;
   bwData.put_var_int(data_->assets_.size());

   auto tx = iface->beginWriteTransaction(data_->dbName_);
   tx->insert(idKey, bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::commit(std::shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr) {
      throw AccountException("commit: null iface");
   }
   //id as key
   const auto& id = getID();
   auto idKey = id.getSerializedKey(ASSET_ACCOUNT_PREFIX);

   //data
   BinaryWriter bwData;

   //type
   bwData.put_uint8_t((uint8_t)type());

   //place holder for former parent key size var_int
   bwData.put_var_int(0);

   //der scheme
   if (data_->derScheme_ != nullptr) {
      auto derSchemeSerData = data_->derScheme_->serialize();
      bwData.put_var_int(derSchemeSerData.getSize());
      bwData.put_BinaryData(derSchemeSerData);
   } else {
      //no derivation scheme, set a 0 size
      bwData.put_var_int(0);
   }

   //commit root asset if there is one
   if (data_->root_ != nullptr) {
      writeAssetEntry(data_->root_, iface);
   }

   //commit assets
   for (auto asset : data_->assets_) {
      writeAssetEntry(asset.second, iface);
   }

   //commit serialized account data
   auto tx = iface->beginWriteTransaction(data_->dbName_);
   tx->insert(idKey, bwData.getData());

   updateAssetCount(iface);
   updateHighestUsedIndex(iface);
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetAccountData> AssetAccount::loadFromDisk(
   const BinaryData& key, std::shared_ptr<IO::WalletIfaceTransaction> tx)
{
   //sanity checks
   if (tx == nullptr) {
      throw AccountException("[loadFromDisk] invalid db tx");
   }
   auto account_id = AssetAccountId::deserializeKey(key, ASSET_ACCOUNT_PREFIX);
   auto diskDataRef = tx->getDataRef(key);
   BinaryRefReader brr(diskDataRef);

   //type
   auto type = AssetAccountType(brr.get_uint8_t());

   //skip parent_id len, irrelevant now
   brr.get_var_int();

   //der scheme
   std::shared_ptr<DerivationScheme> derScheme = nullptr;
   auto len = brr.get_var_int();
   if (len > 0) {
      auto derSchemeBDR = DBUtils::getDataRefForPacket(brr.get_BinaryDataRef(len));
      derScheme = DerivationScheme::deserialize(derSchemeBDR);
      if (derScheme->getType() == DerivationSchemeType::ECDH) {
         auto derECDH = std::dynamic_pointer_cast<DerivationScheme_ECDH>(derScheme);
         if (derECDH == nullptr) {
            throw AccountException("[loadFromDisk] ecdh der scheme snafu");
         }
         derECDH->getAllSalts(tx);
      }
   }

   //asset count
   size_t assetCount = 0;
   {
      BinaryWriter bwKey_assetcount;
      bwKey_assetcount.put_uint8_t(ASSET_COUNT_PREFIX);
      bwKey_assetcount.put_BinaryDataRef(key.getSliceRef(1, key.getSize() - 1));

      auto assetcount = tx->getDataRef(bwKey_assetcount.getData());
      if (assetcount.empty()) {
         throw AccountException("[loadFromDisk] missing asset count entry");
      }
      BinaryRefReader brr_assetcount(assetcount);
      assetCount = brr_assetcount.get_var_int();
   }

   //last used index
   int32_t lastUsedIndex = 0;
   {
      BinaryWriter bwKey_lastusedindex;
      bwKey_lastusedindex.put_uint8_t(ASSET_TOP_INDEX_PREFIX_V2);
      bwKey_lastusedindex.put_BinaryDataRef(key.getSliceRef(
         1, key.getSize() - 1));

      auto lastusedindex = tx->getDataRef(
         bwKey_lastusedindex.getData());
      if (lastusedindex.empty()) {
         /*
         Can't find the last used index entry keying by the V2 prefix.
         Let's look for the V1 style just in case.
         */
         BinaryWriter bwKey_lastusedindex;
         bwKey_lastusedindex.put_uint8_t(ASSET_TOP_INDEX_PREFIX_V1);
         bwKey_lastusedindex.put_BinaryDataRef(key.getSliceRef(
            1, key.getSize() - 1));

         auto&& lastusedindex = tx->getDataRef(
            bwKey_lastusedindex.getData());
         if (lastusedindex.empty()) {
            throw AccountException("[loadFromDisk] missing last used entry");
         } else {
            LOGWARN << "[loadFromDisk] This wallet uses an older format" <<
               ", you should refresh it";
         }

         BinaryRefReader brr_lastusedindex(lastusedindex);
         uint64_t lui_varint = brr_lastusedindex.get_var_int();
         lastUsedIndex = (int32_t)lui_varint;
      } else {
         //V2 key
         BinaryRefReader brr_lastusedindex(lastusedindex);
         lastUsedIndex = brr_lastusedindex.get_int32_t();
      }
   }

   //asset entry prefix key
   BinaryWriter bwAssetKey;
   bwAssetKey.put_uint8_t(ASSETENTRY_PREFIX);
   bwAssetKey.put_BinaryDataRef(key.getSliceRef(1, key.getSize() - 1));

   //asset key
   std::shared_ptr<AssetEntry> rootEntry = nullptr;
   std::map<AssetKeyType, std::shared_ptr<AssetEntry>> assetMap;

   //get all assets
   {
      auto& assetDbKey = bwAssetKey.getData();
      auto dbIter = tx->getIterator();
      dbIter->seek(assetDbKey);

      while (dbIter->isValid()) {
         auto key_bdr = dbIter->key();
         auto value_bdr = dbIter->value();

         //check key isnt prefix
         if (key_bdr == assetDbKey) {
            continue;
         }

         //check key starts with prefix
         if (!key_bdr.startsWith(assetDbKey)) {
            break;
         }

         //instantiate and insert asset
         auto assetPtr = AssetEntry::deserialize(
            key_bdr,
            DBUtils::getDataRefForPacket(value_bdr));

         if (assetPtr->getIndex() != AssetId::getRootKey()) {
            assetMap.insert(make_pair(assetPtr->getIndex(), assetPtr));
         } else {
            rootEntry = assetPtr;
         }
         dbIter->advance();
      }
   }

   //sanity check
   if (assetCount != assetMap.size()) {
      throw AccountException("[loadFromDisk] unexpected account asset count");
   }

   //instantiate & return the object
   auto accDataPtr = std::make_shared<AssetAccountData>(type,
      account_id, rootEntry, derScheme, tx->getDbName());
   accDataPtr->lastUsedIndex_ = lastUsedIndex;
   accDataPtr->assets_ = move(assetMap);
   return accDataPtr;
}

////////////////////////////////////////////////////////////////////////////////
int AssetAccount::getLastComputedIndex() const
{
   if (data_ == nullptr) {
      throw AssetException("[getLastComputedIndex] empty asset account data");
   }

   ReentrantLock lock(this);
   if (data_->assets_.empty()) {
      return -1;
   }
   return data_->assets_.rbegin()->first;
}

////////////////////////////////////////////////////////////////////////////////
int AssetAccount::getHighestUsedIndex() const
{
   return data_->lastUsedIndex_;
}

////////////////////////////////////////////////////////////////////////////////
bool AssetAccount::isAssetInUse(const AssetId& id) const
{
   return id.getAssetKey() <= getHighestUsedIndex();
}

////////////////////////////////////////////////////////////////////////////////
size_t AssetAccount::getAssetCount() const
{
   ReentrantLock lock(this);
   return data_->assets_.size();
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChain(
   std::shared_ptr<IO::WalletDBInterface> iface, int32_t count,
   const std::function<void(int)>& progressCallback)
{
   if (count <= 0) {
      return;
   }
   ReentrantLock lock(this);

   //add *count* entries to address chain
   std::shared_ptr<AssetEntry> assetPtr = nullptr;
   if (!data_->assets_.empty()) {
      assetPtr = data_->assets_.rbegin()->second;
   } else {
      assetPtr = data_->root_;
   }
   extendPublicChain(iface, assetPtr, count, progressCallback);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChainToIndex(
   std::shared_ptr<IO::WalletDBInterface> iface, int32_t index,
   const std::function<void(int)>& progressCallback)
{
   ReentrantLock lock(this);

   //make address chain at least *count* long
   auto lastComputedIndex = getLastComputedIndex();
   if (lastComputedIndex >= index) {
      return;
   }
   int32_t toCompute = index - lastComputedIndex;
   if (toCompute < 0) {
      throw AccountException("extendPublicChainToIndex: invalid index");
   }
   extendPublicChain(iface, toCompute, progressCallback);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChain(
   std::shared_ptr<IO::WalletDBInterface> iface,
   std::shared_ptr<AssetEntry> assetPtr, int32_t count,
   const std::function<void(int)>& progressCallback)
{
   if (count <= 0) {
      return;
   }
   ReentrantLock lock(this);

   auto assetVec = extendPublicChain(assetPtr,
      assetPtr->getIndex(),
      assetPtr->getIndex() + count,
      progressCallback);

   for (auto& asset : assetVec) {
      auto id = asset->getIndex();
      auto iter = data_->assets_.find(id);
      if (iter != data_->assets_.end()) {
         continue;
      }
      data_->assets_.emplace(id, asset);
   }

   if (iface != nullptr) {
      updateOnDiskAssets(iface);
   }
}

////////////////////////////////////////////////////////////////////////////////
std::vector<std::shared_ptr<AssetEntry>> AssetAccount::extendPublicChain(
   std::shared_ptr<AssetEntry> assetPtr, int32_t start, int32_t end,
   const std::function<void(int)>& progressCallback)
{
   std::vector<std::shared_ptr<AssetEntry>> result;

   switch (data_->derScheme_->getType())
   {
      case DerivationSchemeType::ArmoryLegacy:
      {
         //Armory legacy derivation operates from the last valid asset
         result = std::move(data_->derScheme_->extendPublicChain(
            assetPtr, start, end, progressCallback));
         break;
      }

      case DerivationSchemeType::BIP32:
      case DerivationSchemeType::BIP32_Salted:
      case DerivationSchemeType::ECDH:
      {
         //BIP32 operates from the node's root asset
         result = std::move(data_->derScheme_->extendPublicChain(
            data_->root_, start, end, progressCallback));
         break;
      }

      default:
         throw AccountException("unexpected derscheme type");
   }
   return result;
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChain(
   std::shared_ptr<IO::WalletDBInterface> iface,
   std::shared_ptr<Encryption::DecryptedDataContainer> ddc,
   int32_t count)
{
   ReentrantLock lock(this);
   std::shared_ptr<AssetEntry> topAsset = nullptr;

   try {
      topAsset = getLastAssetWithPrivateKey();
   } catch (const std::runtime_error&) {}
   extendPrivateChain(iface, ddc, topAsset, count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChainToIndex(
   std::shared_ptr<IO::WalletDBInterface> iface,
   std::shared_ptr<Encryption::DecryptedDataContainer> ddc,
   int32_t id)
{
   ReentrantLock lock(this);
   std::shared_ptr<AssetEntry> topAsset = nullptr;
   int topIndex = 0;

   try {
      topAsset = getLastAssetWithPrivateKey();
      topIndex = topAsset->getIndex();
   } catch (const std::runtime_error&) {}

   if (id > topIndex) {
      int32_t count = id - topIndex;
      extendPrivateChain(iface, ddc, topAsset, count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChain(
   std::shared_ptr<IO::WalletDBInterface> iface,
   std::shared_ptr<Encryption::DecryptedDataContainer> ddc,
   std::shared_ptr<AssetEntry> assetPtr, int32_t count)
{
   if (count <= 0) {
      return;
   }

   ReentrantLock lock(this);
   int32_t assetIndex = -1;
   if (assetPtr != nullptr) {
      assetIndex = assetPtr->getIndex();
   }
   auto assetVec = extendPrivateChain(ddc, assetPtr,
      assetIndex, assetIndex + count);

   for (auto& asset : assetVec) {
      auto id = asset->getIndex();
      auto iter = data_->assets_.find(id);
      if (iter != data_->assets_.end()) {
         if (iter->second->hasPrivateKey()) {
            //do not overwrite an existing asset that already has a privkey
            continue;
         } else {
            iter->second = asset;
            continue;
         }
      }
      data_->assets_.emplace(id, asset);
   }

   if (iface != nullptr) {
      updateOnDiskAssets(iface);
   }
}

////////////////////////////////////////////////////////////////////////////////
std::vector<std::shared_ptr<AssetEntry>> AssetAccount::extendPrivateChain(
   std::shared_ptr<Encryption::DecryptedDataContainer> ddc,
   std::shared_ptr<AssetEntry> assetPtr,
   int32_t start, int32_t end)
{
   std::vector<std::shared_ptr<AssetEntry>> result;
   switch (data_->derScheme_->getType())
   {
      case DerivationSchemeType::ArmoryLegacy:
      {
         //Armory legacy derivation operates from the last valid asset
         result = std::move(data_->derScheme_->extendPrivateChain(
            ddc, assetPtr, start, end));
         break;
      }

      case DerivationSchemeType::BIP32:
      case DerivationSchemeType::BIP32_Salted:
      case DerivationSchemeType::ECDH:
      {
         //BIP32 operates from the node's root asset
         result = std::move(data_->derScheme_->extendPrivateChain(
            ddc, data_->root_, start, end));
         break;
      }

      default:
         throw AccountException("unexpected derscheme type");
   }
   return result;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetEntry> AssetAccount::getLastAssetWithPrivateKey() const
{
   ReentrantLock lock(this);
   auto assetIter = data_->assets_.rbegin();
   while (assetIter != data_->assets_.rend()) {
      if (assetIter->second->hasPrivateKey()) {
         return assetIter->second;
      }
      ++assetIter;
   }

   throw std::runtime_error("no asset with private keys");
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateHighestUsedIndex(
   std::shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr) {
      throw AccountException("updateHighestUsedIndex: null iface");
   }
   ReentrantLock lock(this);

   const auto& id = getID();
   auto idKey = id.getSerializedKey(ASSET_TOP_INDEX_PREFIX_V2);

   BinaryWriter bwData;
   bwData.put_int32_t(data_->lastUsedIndex_);

   auto tx = iface->beginWriteTransaction(data_->dbName_);
   tx->insert(idKey, bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetAccount::getAndBumpHighestUsedIndex(
   std::shared_ptr<IO::WalletDBInterface> iface)
{
   ReentrantLock lock(this);

   ++data_->lastUsedIndex_;
   updateHighestUsedIndex(iface);
   return data_->lastUsedIndex_;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetEntry> AssetAccount::getOrSetAssetAtIndex(
   std::shared_ptr<IO::WalletDBInterface> iface, unsigned index,
   const ProgressFunc& progFunc)
{
   ReentrantLock lock(this);

   auto entryIter = data_->assets_.find(index);
   if (entryIter == data_->assets_.end()) {
      extendPublicChain(iface, getLookup(), progFunc);
      entryIter = data_->assets_.find(index);
      if (entryIter == data_->assets_.end()) {
         throw AccountException("requested index overflows max lookup");
      }
   }
   return entryIter->second;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetEntry> AssetAccount::getNewAsset(
   std::shared_ptr<IO::WalletDBInterface> iface,
   const ProgressFunc& progFunc)
{
   auto index = getAndBumpHighestUsedIndex(iface);
   return getOrSetAssetAtIndex(iface, index, progFunc);
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetEntry> AssetAccount::peekNextAsset(
   std::shared_ptr<IO::WalletDBInterface> iface,
   const ProgressFunc& progFunc)
{
   auto index = data_->lastUsedIndex_ + 1;
   return getOrSetAssetAtIndex(iface, index, progFunc);
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetEntry> AssetAccount::getAssetForID(const AssetId& ID) const
{
   if (!ID.isValid()) {
      throw std::runtime_error("invalid asset ID");
   }

   auto iter = data_->assets_.find(ID.getAssetKey());
   if (iter == data_->assets_.end()) {
      throw AccountException("unknown asset index");
   }
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetEntry> AssetAccount::getAssetForKey(
   const AssetKeyType& key) const
{
   AssetId id(data_->id_, key);
   return getAssetForID(id);
}

////////////////////////////////////////////////////////////////////////////////
bool AssetAccount::isAssetIDValid(const AssetId& id) const
{
   auto assetIt = data_->assets_.find(id.getAssetKey());
   return assetIt != data_->assets_.end();
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateAddressHashMap(
   const std::set<AddressEntryType>& typeSet)
{
   ReentrantLock lock(this);

   auto assetIter = data_->assets_.find(data_->lastHashedAsset_);
   if (assetIter == data_->assets_.end()) {
      assetIter = data_->assets_.begin();
   } else {
      ++assetIter;
      if (assetIter == data_->assets_.end()) {
         return;
      }
   }

   while (assetIter != data_->assets_.end()) {
      auto hashMapiter = data_->addrHashMap_.find(assetIter->second->getID());
      if (hashMapiter == data_->addrHashMap_.end()) {
         hashMapiter = data_->addrHashMap_.emplace(
            assetIter->second->getID(),
            std::map<AddressEntryType, BinaryData>{}
         ).first;
      }

      for (auto ae_type : typeSet) {
         if (hashMapiter->second.find(ae_type) != hashMapiter->second.end()) {
            continue;
         }
         auto addrPtr = AddressEntry::instantiate(assetIter->second, ae_type);
         auto& addrHash = addrPtr->getPrefixedHash();
         data_->addrHashMap_[assetIter->second->getID()].emplace(ae_type, addrHash);
      }

      data_->lastHashedAsset_ = assetIter->first;
      ++assetIter;
   }
}

/////////
void AssetAccount::updateAddressHashMap(
   const std::map<Wallets::AssetId, AddressEntryType>&)
{
   throw AccountException("invalid for AssetAccount");
}

////////////////////////////////////////////////////////////////////////////////
const AssetAccountData::AddrHashMapType& AssetAccount::getAddressHashMap() const
{
   return data_->addrHashMap_;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetAccount::getChaincode() const
{
   if (data_->derScheme_ == nullptr) {
      throw AccountException("null derivation scheme");
   }
   return data_->derScheme_->getChaincode();
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Asset_PrivateKey> AssetAccount::fillPrivateKey(
   std::shared_ptr<IO::WalletDBInterface> iface,
   std::shared_ptr<Encryption::DecryptedDataContainer> ddc,
   const AssetId& id)
{
   if (!id.isValid()) {
      throw AccountException("unexpected asset id length");
   }
   auto assetKey = id.getAssetKey();

   //get the asset
   auto iter = data_->assets_.find(assetKey);
   if (iter == data_->assets_.end()) {
      throw AccountException("invalid asset id");
   }
   auto thisAsset = std::dynamic_pointer_cast<AssetEntry_Single>(iter->second);
   if (thisAsset == nullptr) {
      throw AccountException("unexpected asset type in map");
   }

   //sanity check
   if (thisAsset->hasPrivateKey()) {
      return thisAsset->getPrivKey();
   }

   //reverse iter through the map, find closest previous asset with priv key
   //this is only necessary for armory 1.35 derivation
   std::shared_ptr<AssetEntry> prevAssetWithKey = nullptr;
   std::map<AssetKeyType, std::shared_ptr<AssetEntry>>::reverse_iterator rIter(iter);
   while (rIter != data_->assets_.rend()) {
      if (rIter->second->hasPrivateKey()) {
         prevAssetWithKey = rIter->second;
         break;
      }
      ++rIter;
   }

   //if no asset in map had a private key, use the account root instead
   if (prevAssetWithKey == nullptr) {
      prevAssetWithKey = data_->root_;
   }

   //figure out the asset count
   unsigned count = assetKey - prevAssetWithKey->getIndex();

   //extend the private chain
   extendPrivateChain(iface, ddc, prevAssetWithKey, count);

   //grab the fresh asset, return its private key
   auto privKeyIter = data_->assets_.find(assetKey);
   if (privKeyIter == data_->assets_.end()) {
      throw AccountException("invalid asset id");
   }
   if (!privKeyIter->second->hasPrivateKey()) {
      throw AccountException("fillPrivateKey failed");
   }

   auto assetSingle = std::dynamic_pointer_cast<AssetEntry_Single>(
      privKeyIter->second);
   if (assetSingle == nullptr) {
      throw AccountException("fillPrivateKey failed");
   }
   return assetSingle->getPrivKey();
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetAccount::getLookup(void) const
{
   return DERIVATION_LOOKUP;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AssetEntry> AssetAccount::getRoot() const
{
   return data_->root_;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccount_ECDH
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetAccount_ECDH::AssetAccount_ECDH(std::shared_ptr<AssetAccountData> data) :
   AssetAccount(data)
{}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetAccount_ECDH::getLookup() const
{
   return 1;
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountType AssetAccount_ECDH::type() const
{
   return AssetAccountType::ECDH;
}

////////////////////////////////////////////////////////////////////////////////
AssetKeyType AssetAccount_ECDH::addSalt(
   std::shared_ptr<IO::WalletIfaceTransaction> tx,
   const SecureBinaryData& salt)
{
   auto derScheme = std::dynamic_pointer_cast<DerivationScheme_ECDH>(
      data_->derScheme_);

   if (derScheme == nullptr) {
      throw AccountException("unexpected derivation scheme type");
   }
   return derScheme->addSalt(salt, tx);
}

////////////////////////////////////////////////////////////////////////////////
AssetKeyType AssetAccount_ECDH::getSaltIndex(const SecureBinaryData& salt) const
{
   auto derScheme = std::dynamic_pointer_cast<DerivationScheme_ECDH>(
      data_->derScheme_);

   if (derScheme == nullptr) {
      throw AccountException("unexpected derivation scheme type");
   }
   return derScheme->getIdForSalt(salt);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount_ECDH::commit(std::shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr) {
      throw AccountException("commit: null iface");
   }

   auto schemeECDH = std::dynamic_pointer_cast<DerivationScheme_ECDH>(
      data_->derScheme_);
   if (schemeECDH == nullptr) {
      throw AccountException("expected ECDH derScheme");
   }

   auto uniqueTx = iface->beginWriteTransaction(data_->dbName_);
   AssetAccount::commit(iface);

   std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
   schemeECDH->putAllSalts(sharedTx);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccount_Imports
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetAccount_Imports::AssetAccount_Imports(std::shared_ptr<AssetAccountData> data) :
   AssetAccount(data)
{}

////
unsigned AssetAccount_Imports::getLookup() const
{
   return UINT32_MAX;
}

////
AssetAccountType AssetAccount_Imports::type() const
{
   return AssetAccountType::Imports;
}

////
AssetId AssetAccount_Imports::importPrivateKey(
   std::shared_ptr<IO::WalletIfaceTransaction>,
   std::shared_ptr<Encryption::DecryptedDataContainer>,
   const SecureBinaryData&)
{
   throw std::runtime_error("[importPrivateKey] implement me!");
}

////////
void AssetAccount_Imports::updateAddressHashMap(
   const std::set<AddressEntryType>&)
{
   throw AccountException("invalid for AssetAccount_Imports");
}

////
void AssetAccount_Imports::updateAddressHashMap(
   const std::map<Wallets::AssetId, AddressEntryType>&)
{
   throw std::runtime_error("[updateAddressHashMap] implement me");
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccount_ImportsWO
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetAccount_ImportsWO::AssetAccount_ImportsWO(
   std::shared_ptr<AssetAccountData> data) :
   AssetAccount(data)
{}

////
unsigned AssetAccount_ImportsWO::getLookup() const
{
   return UINT32_MAX;
}

////
AssetAccountType AssetAccount_ImportsWO::type() const
{
   return AssetAccountType::ImportsWO;
}

////
AssetId AssetAccount_ImportsWO::importPublicKey(
   std::shared_ptr<IO::WalletDBInterface> iface,
   SecureBinaryData& pubKey)
{
   //get last key
   AssetKeyType keyId = 0;
   auto lastEntry = data_->assets_.rbegin();
   if (lastEntry != data_->assets_.rend()) {
      keyId = lastEntry->first+1;
   }

   AssetId assetId{data_->id_, keyId};
   auto assetPtr = std::make_shared<AssetEntry_Single>(
      assetId, pubKey, nullptr);
   data_->assets_.emplace(keyId, assetPtr);
   ++data_->lastUsedIndex_;

   commit(iface);
   return assetId;
}

/////////
void AssetAccount_ImportsWO::updateAddressHashMap(
   const std::set<AddressEntryType>&)
{
   throw AccountException("invalid for AssetAccount_ImportsWO");
}

////
void AssetAccount_ImportsWO::updateAddressHashMap(
   const std::map<Wallets::AssetId, AddressEntryType>& addrTypeMap)
{
   ReentrantLock lock(this);

   //set iterator to last hashed asset
   auto assetIter = data_->assets_.find(data_->lastHashedAsset_);
   if (assetIter == data_->assets_.end()) {
      assetIter = data_->assets_.begin();
   } else {
      ++assetIter;
      if (assetIter == data_->assets_.end()) {
         return;
      }
   }

   while (assetIter != data_->assets_.end()) {
      //does this asset have an entry in the type map?
      AssetId assetId{data_->id_, assetIter->first};
      auto typeIter = addrTypeMap.find(assetId);
      if (typeIter == addrTypeMap.end()) {
         continue;
      }

      //find the entry for this asset
      auto hashMapiter = data_->addrHashMap_.find(assetId);
      if (hashMapiter == data_->addrHashMap_.end()) {
         hashMapiter = data_->addrHashMap_.emplace(
            assetId,
            std::map<AddressEntryType, BinaryData>{}
         ).first;
      }

      //skip if we already have a hash for this address type
      if (hashMapiter->second.find(typeIter->second) !=
         hashMapiter->second.end()) {
         continue;
      }

      auto addrPtr = AddressEntry::instantiate(
         assetIter->second, typeIter->second);
      auto& addrHash = addrPtr->getPrefixedHash();
      data_->addrHashMap_[assetIter->second->getID()].emplace(
         typeIter->second, addrHash);
      data_->lastHashedAsset_ = assetIter->first;
      ++assetIter;
   }
}
