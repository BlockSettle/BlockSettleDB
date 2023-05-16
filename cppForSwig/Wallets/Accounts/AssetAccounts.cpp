////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "../../DBUtils.h"
#include "AccountTypes.h"
#include "AssetAccounts.h"
#include "../EncryptedDB.h"
#include "../DerivationScheme.h"
#include "../WalletFileInterface.h"

using namespace std;
using namespace Armory::Assets;
using namespace Armory::Accounts;
using namespace Armory::Wallets;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccountData
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetAccountData> AssetAccountData::copy(
   const string& dbName) const
{
   auto accDataCopy = make_shared<AssetAccountData>(type_,
      id_, root_, derScheme_, dbName);

   //shared_ptr of asset entries are not copied
   accDataCopy->assets_ = assets_;
   accDataCopy->lastUsedIndex_ = lastUsedIndex_;
   accDataCopy->lastHashedAsset_ = lastHashedAsset_;

   return accDataCopy;
}

AssetAccountExtendedData::~AssetAccountExtendedData() {}
AssetAccountSaltMap::~AssetAccountSaltMap() {}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccount
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
const AssetAccountId& AssetAccount::getID(void) const
{
   return data_->id_;
}

////////////////////////////////////////////////////////////////////////////////
size_t AssetAccount::writeAssetEntry(shared_ptr<AssetEntry> entryPtr,
   shared_ptr<IO::WalletDBInterface> iface)
{
   if (!entryPtr->needsCommit())
      return SIZE_MAX;

   if (iface == nullptr)
      throw AccountException("writeAssetEntry: null iface");

   auto&& tx = iface->beginWriteTransaction(data_->dbName_);

   auto&& serializedEntry = entryPtr->serialize();
   auto&& dbKey = entryPtr->getDbKey();

   tx->insert(dbKey, serializedEntry);

   entryPtr->doNotCommit();
   return serializedEntry.getSize();
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateOnDiskAssets(shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr)
      throw AccountException("updateOnDiskAssets: null iface");

   auto&& tx = iface->beginWriteTransaction(data_->dbName_);
   for (auto& entryPtr : data_->assets_)
      writeAssetEntry(entryPtr.second, iface);

   updateAssetCount(iface);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateAssetCount(shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr)
      throw AccountException("updateAssetCount: null iface");

   //asset count key
   const auto& id = getID();
   auto idKey = id.getSerializedKey(ASSET_COUNT_PREFIX);

   //asset count
   BinaryWriter bwData;
   bwData.put_var_int(data_->assets_.size());

   auto&& tx = iface->beginWriteTransaction(data_->dbName_);
   tx->insert(idKey, bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::commit(shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr)
      throw AccountException("commit: null iface");

   //id as key
   const auto& id = getID();
   auto idKey = id.getSerializedKey(ASSET_ACCOUNT_PREFIX);

   //data
   BinaryWriter bwData;

   //type
   bwData.put_uint8_t(type());

   //place holder for former parent key size var_int
   bwData.put_var_int(0);

   //der scheme
   auto derSchemeSerData = data_->derScheme_->serialize();
   bwData.put_var_int(derSchemeSerData.getSize());
   bwData.put_BinaryData(derSchemeSerData);

   //commit root asset if there is one
   if (data_->root_ != nullptr)
      writeAssetEntry(data_->root_, iface);

   //commit assets
   for (auto asset : data_->assets_)
      writeAssetEntry(asset.second, iface);

   //commit serialized account data
   auto&& tx = iface->beginWriteTransaction(data_->dbName_);
   tx->insert(idKey, bwData.getData());

   updateAssetCount(iface);
   updateHighestUsedIndex(iface);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetAccountData> AssetAccount::loadFromDisk(const BinaryData& key,
   shared_ptr<IO::WalletIfaceTransaction> tx)
{
   //sanity checks
   if (tx == nullptr)
      throw AccountException("[loadFromDisk] invalid db tx");

   auto account_id = AssetAccountId::deserializeKey(key, ASSET_ACCOUNT_PREFIX);
   auto&& diskDataRef = tx->getDataRef(key);
   BinaryRefReader brr(diskDataRef);

   //type
   auto type = AssetAccountTypeEnum(brr.get_uint8_t());

   //skip parent_id len, irrelevant now
   brr.get_var_int();

   //der scheme
   auto len = brr.get_var_int();
   auto derSchemeBDR = DBUtils::getDataRefForPacket(brr.get_BinaryDataRef(len));
   auto derScheme = DerivationScheme::deserialize(derSchemeBDR);
   if (derScheme->getType() == DerivationSchemeType::ECDH)
   {
      auto derECDH = dynamic_pointer_cast<DerivationScheme_ECDH>(derScheme);
      if (derECDH == nullptr)
         throw AccountException("[loadFromDisk] ecdh der scheme snafu");
      derECDH->getAllSalts(tx);
   }

   //asset count
   size_t assetCount = 0;
   {
      BinaryWriter bwKey_assetcount;
      bwKey_assetcount.put_uint8_t(ASSET_COUNT_PREFIX);
      bwKey_assetcount.put_BinaryDataRef(key.getSliceRef(
         1, key.getSize() - 1));

      auto&& assetcount = tx->getDataRef(bwKey_assetcount.getData());
      if (assetcount.getSize() == 0)
         throw AccountException("[loadFromDisk] missing asset count entry");

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

      auto&& lastusedindex = tx->getDataRef(
         bwKey_lastusedindex.getData());

      if (lastusedindex.empty())
      {
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
         if (lastusedindex.empty())
         {
            throw AccountException("[loadFromDisk] missing last used entry");
         }
         else
         {
            LOGWARN << "[loadFromDisk] This wallet uses an older format" <<
               ", you should refresh it";
         }

         BinaryRefReader brr_lastusedindex(lastusedindex);
         uint64_t lui_varint = brr_lastusedindex.get_var_int();
         lastUsedIndex = (int32_t)lui_varint;
      }
      else
      {
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
   shared_ptr<AssetEntry> rootEntry = nullptr;
   map<AssetKeyType, shared_ptr<AssetEntry>> assetMap;
   
   //get all assets
   {
      auto& assetDbKey = bwAssetKey.getData();
      auto dbIter = tx->getIterator();
      dbIter->seek(assetDbKey);

      while (dbIter->isValid())
      {
         auto&& key_bdr = dbIter->key();
         auto&& value_bdr = dbIter->value();

         //check key isnt prefix
         if (key_bdr == assetDbKey)
            continue;

         //check key starts with prefix
         if (!key_bdr.startsWith(assetDbKey))
            break;

         //instantiate and insert asset
         auto assetPtr = AssetEntry::deserialize(
            key_bdr,
            DBUtils::getDataRefForPacket(value_bdr));

         if (assetPtr->getIndex() != AssetId::getRootKey())
            assetMap.insert(make_pair(assetPtr->getIndex(), assetPtr));
         else
            rootEntry = assetPtr;

         dbIter->advance();
      } 
   }

   //sanity check
   if (assetCount != assetMap.size())
      throw AccountException("[loadFromDisk] unexpected account asset count");

   //instantiate object
   auto accDataPtr = make_shared<AssetAccountData>(type,
      account_id, rootEntry, derScheme, tx->getDbName());

   accDataPtr->lastUsedIndex_ = lastUsedIndex;
   accDataPtr->assets_ = move(assetMap);

   return accDataPtr;
}

////////////////////////////////////////////////////////////////////////////////
int AssetAccount::getLastComputedIndex() const
{
   if (data_ == nullptr)
      throw AssetException("[getLastComputedIndex] empty asset account data");

   ReentrantLock lock(this);
   if (data_->assets_.empty())
      return -1;

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
void AssetAccount::extendPublicChain(shared_ptr<IO::WalletDBInterface> iface,
   unsigned count, const function<void(int)>& progressCallback)
{
   if (count == 0)
      return;

   ReentrantLock lock(this);

   //add *count* entries to address chain
   shared_ptr<AssetEntry> assetPtr = nullptr;
   if (!data_->assets_.empty())
      assetPtr = data_->assets_.rbegin()->second;
   else
      assetPtr = data_->root_;

   extendPublicChain(iface, assetPtr, count, progressCallback);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChainToIndex(
   shared_ptr<IO::WalletDBInterface> iface, unsigned index,
   const std::function<void(int)>& progressCallback)
{
   ReentrantLock lock(this);

   //make address chain at least *count* long
   auto lastComputedIndex = getLastComputedIndex();
   if (lastComputedIndex >= (int)index)
      return;

   int toCompute = int(index) - lastComputedIndex;
   if (toCompute < 0)
      throw AccountException("extendPublicChainToIndex: invalid index");

   extendPublicChain(iface, (unsigned)toCompute, progressCallback);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChain(shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<AssetEntry> assetPtr, unsigned count,
   const function<void(int)>& progressCallback)
{
   if (count == 0)
      return;

   ReentrantLock lock(this);

   auto assetVec = extendPublicChain(assetPtr,
      assetPtr->getIndex() + 1,
      assetPtr->getIndex() + count,
      progressCallback);

   for (auto& asset : assetVec)
   {
      auto id = asset->getIndex();
      auto iter = data_->assets_.find(id);
      if (iter != data_->assets_.end())
         continue;

      data_->assets_.insert(make_pair(id, asset));
   }

   if (iface != nullptr)
      updateOnDiskAssets(iface);
}

////////////////////////////////////////////////////////////////////////////////
vector<shared_ptr<AssetEntry>> AssetAccount::extendPublicChain(
   shared_ptr<AssetEntry> assetPtr, unsigned start, unsigned end,
   const function<void(int)>& progressCallback)
{
   vector<shared_ptr<AssetEntry>> result;

   switch (data_->derScheme_->getType())
   {
   case DerivationSchemeType::ArmoryLegacy:
   {
      //Armory legacy derivation operates from the last valid asset
      result = move(data_->derScheme_->extendPublicChain(
         assetPtr, start, end, progressCallback));
      break;
   }

   case DerivationSchemeType::BIP32:
   case DerivationSchemeType::BIP32_Salted:
   case DerivationSchemeType::ECDH:
   {
      //BIP32 operates from the node's root asset
      result = move(data_->derScheme_->extendPublicChain(
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
   shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<Encryption::DecryptedDataContainer> ddc,
   unsigned count)
{
   ReentrantLock lock(this);
   shared_ptr<AssetEntry> topAsset = nullptr;
   
   try
   {
      topAsset = getLastAssetWithPrivateKey();
   }
   catch(runtime_error&)
   {}

   extendPrivateChain(iface, ddc, topAsset, count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChainToIndex(
   shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<Encryption::DecryptedDataContainer> ddc,
   unsigned id)
{
   ReentrantLock lock(this);

   shared_ptr<AssetEntry> topAsset = nullptr;
   int topIndex = 0;

   try
   {
      topAsset = getLastAssetWithPrivateKey();
      topIndex = topAsset->getIndex();
   }
   catch(runtime_error&)
   {}

   if ((int)id > topIndex)
   {
      auto count = id - topIndex;
      extendPrivateChain(iface, ddc, topAsset, count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChain(shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<Encryption::DecryptedDataContainer> ddc,
   shared_ptr<AssetEntry> assetPtr, unsigned count)
{
   if (count == 0)
      return;

   ReentrantLock lock(this);
   unsigned assetIndex = UINT32_MAX;
   if (assetPtr != nullptr)
      assetIndex = assetPtr->getIndex();

   auto&& assetVec = extendPrivateChain(ddc, assetPtr, 
      assetIndex + 1, assetIndex + count);

   {
      for (auto& asset : assetVec)
      {
         auto id = asset->getIndex();
         auto iter = data_->assets_.find(id);
         if (iter != data_->assets_.end())
         {
            if (iter->second->hasPrivateKey())
            {
               //do not overwrite an existing asset that already has a privkey
               continue;
            }
            else
            {
               iter->second = asset;
               continue;
            }
         }

         data_->assets_.insert(make_pair(
            id, asset));
      }
   }

   if (iface != nullptr)
      updateOnDiskAssets(iface);
}

////////////////////////////////////////////////////////////////////////////////
vector<shared_ptr<AssetEntry>> AssetAccount::extendPrivateChain(
   shared_ptr<Encryption::DecryptedDataContainer> ddc,
   shared_ptr<AssetEntry> assetPtr,
   unsigned start, unsigned end)
{
   vector<shared_ptr<AssetEntry>> result;

   switch (data_->derScheme_->getType())
   {
   case DerivationSchemeType::ArmoryLegacy:
   {
      //Armory legacy derivation operates from the last valid asset
      result = move(data_->derScheme_->extendPrivateChain(
         ddc, assetPtr, start, end));
      break;
   }

   case DerivationSchemeType::BIP32:
   case DerivationSchemeType::BIP32_Salted:
   case DerivationSchemeType::ECDH:
   {
      //BIP32 operates from the node's root asset
      result = move(data_->derScheme_->extendPrivateChain(
         ddc, data_->root_, start, end));
      break;
   }

   default:
      throw AccountException("unexpected derscheme type");
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getLastAssetWithPrivateKey() const
{
   ReentrantLock lock(this);

   auto assetIter = data_->assets_.rbegin();
   while (assetIter != data_->assets_.rend())
   {
      if (assetIter->second->hasPrivateKey())
         return assetIter->second;

      ++assetIter;
   }

   throw runtime_error("no asset with private keys");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateHighestUsedIndex(shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr)
      throw AccountException("updateHighestUsedIndex: null iface");

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
   shared_ptr<IO::WalletDBInterface> iface)
{
   ReentrantLock lock(this);

   ++data_->lastUsedIndex_;
   updateHighestUsedIndex(iface);
   return data_->lastUsedIndex_;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getOrSetAssetAtIndex(
   shared_ptr<IO::WalletDBInterface> iface, unsigned index)
{
   ReentrantLock lock(this);

   auto entryIter = data_->assets_.find(index);
   if (entryIter == data_->assets_.end())
   {
      extendPublicChain(iface, getLookup());
      entryIter = data_->assets_.find(index);
      if (entryIter == data_->assets_.end())
         throw AccountException("requested index overflows max lookup");
   }

   return entryIter->second;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getNewAsset(
   shared_ptr<IO::WalletDBInterface> iface)
{
   auto index = getAndBumpHighestUsedIndex(iface);
   return getOrSetAssetAtIndex(iface, index);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::peekNextAsset(
   shared_ptr<IO::WalletDBInterface> iface)
{
   auto index = data_->lastUsedIndex_ + 1;
   return getOrSetAssetAtIndex(iface, index);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getAssetForID(const AssetId& ID) const
{
   if (!ID.isValid())
      throw runtime_error("invalid asset ID");

   auto iter = data_->assets_.find(ID.getAssetKey());
   if (iter == data_->assets_.end())
      throw AccountException("unknown asset index");

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getAssetForKey(
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
   const set<AddressEntryType>& typeSet)
{
   auto assetIter = data_->assets_.find(data_->lastHashedAsset_);
   if (assetIter == data_->assets_.end())
   {
      assetIter = data_->assets_.begin();
   }
   else
   {
      ++assetIter;
      if (assetIter == data_->assets_.end())
         return;
   }

   ReentrantLock lock(this);

   while (assetIter != data_->assets_.end())
   {
      auto hashMapiter = data_->addrHashMap_.find(assetIter->second->getID());
      if (hashMapiter == data_->addrHashMap_.end())
      {
         hashMapiter = data_->addrHashMap_.insert(make_pair(
            assetIter->second->getID(),
            map<AddressEntryType, BinaryData>())).first;
      }

      for (auto ae_type : typeSet)
      {
         if (hashMapiter->second.find(ae_type) != hashMapiter->second.end())
            continue;

         auto addrPtr = AddressEntry::instantiate(assetIter->second, ae_type);
         auto& addrHash = addrPtr->getPrefixedHash();
         data_->addrHashMap_[assetIter->second->getID()].insert(
            make_pair(ae_type, addrHash));
      }

      data_->lastHashedAsset_ = assetIter->first;
      ++assetIter;
   }
}

////////////////////////////////////////////////////////////////////////////////
const AssetAccountData::AddrHashMapType& AssetAccount::getAddressHashMap(
   const set<AddressEntryType>& typeSet)
{
   updateAddressHashMap(typeSet);

   return data_->addrHashMap_;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetAccount::getChaincode() const
{
   if (data_->derScheme_ == nullptr)
      throw AccountException("null derivation scheme");

   return data_->derScheme_->getChaincode();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<Asset_PrivateKey> AssetAccount::fillPrivateKey(
   shared_ptr<IO::WalletDBInterface> iface,
   shared_ptr<Encryption::DecryptedDataContainer> ddc,
   const AssetId& id)
{
   if (!id.isValid())
      throw AccountException("unexpected asset id length");

   auto assetKey = id.getAssetKey();

   //get the asset
   auto iter = data_->assets_.find(assetKey);
   if (iter == data_->assets_.end())
      throw AccountException("invalid asset id");

   auto thisAsset = dynamic_pointer_cast<AssetEntry_Single>(iter->second);
   if (thisAsset == nullptr)
      throw AccountException("unexpected asset type in map");

   //sanity check
   if (thisAsset->hasPrivateKey())
      return thisAsset->getPrivKey();

   //reverse iter through the map, find closest previous asset with priv key
   //this is only necessary for armory 1.35 derivation
   shared_ptr<AssetEntry> prevAssetWithKey = nullptr;
   map<AssetKeyType, shared_ptr<AssetEntry>>::reverse_iterator rIter(iter);
   while (rIter != data_->assets_.rend())
   {
      if (rIter->second->hasPrivateKey())
      {
         prevAssetWithKey = rIter->second;
         break;
      }

      ++rIter;
   }
   
   //if no asset in map had a private key, use the account root instead
   if (prevAssetWithKey == nullptr)
      prevAssetWithKey = data_->root_;

   //figure out the asset count
   unsigned count = assetKey - prevAssetWithKey->getIndex();

   //extend the private chain
   extendPrivateChain(iface, ddc, prevAssetWithKey, count);

   //grab the fresh asset, return its private key
   auto privKeyIter = data_->assets_.find(assetKey);
   if (privKeyIter == data_->assets_.end())
      throw AccountException("invalid asset id");

   if (!privKeyIter->second->hasPrivateKey())
      throw AccountException("fillPrivateKey failed");

   auto assetSingle =
      dynamic_pointer_cast<AssetEntry_Single>(privKeyIter->second);
   if(assetSingle == nullptr)
      throw AccountException("fillPrivateKey failed");

   return assetSingle->getPrivKey();
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetAccount::getLookup(void) const 
{
   return DERIVATION_LOOKUP; 
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getRoot() const
{
   return data_->root_;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccount_ECDH
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetKeyType AssetAccount_ECDH::addSalt(
   shared_ptr<IO::WalletIfaceTransaction> tx,
   const SecureBinaryData& salt)
{
   auto derScheme =
      dynamic_pointer_cast<DerivationScheme_ECDH>(data_->derScheme_);

   if (derScheme == nullptr)
      throw AccountException("unexpected derivation scheme type");

   return derScheme->addSalt(salt, tx);
}

////////////////////////////////////////////////////////////////////////////////
AssetKeyType AssetAccount_ECDH::getSaltIndex(const SecureBinaryData& salt) const
{
   auto derScheme =
      dynamic_pointer_cast<DerivationScheme_ECDH>(data_->derScheme_);

   if (derScheme == nullptr)
      throw AccountException("unexpected derivation scheme type");

   return derScheme->getIdForSalt(salt);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount_ECDH::commit(shared_ptr<IO::WalletDBInterface> iface)
{
   if (iface == nullptr)
      throw AccountException("commit: null iface");

   auto schemeECDH =
      dynamic_pointer_cast<DerivationScheme_ECDH>(data_->derScheme_);
   if (schemeECDH == nullptr)
      throw AccountException("expected ECDH derScheme");

   auto uniqueTx = iface->beginWriteTransaction(data_->dbName_);
   AssetAccount::commit(iface);

   shared_ptr<IO::DBIfaceTransaction> sharedTx(move(uniqueTx));
   schemeECDH->putAllSalts(sharedTx);
}