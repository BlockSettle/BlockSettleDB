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

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetAccount
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetAccount::getID(void) const
{
   return data_->id_;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AssetAccount::getFullID(void) const
{
   return data_->parentId_ + data_->id_;
}

////////////////////////////////////////////////////////////////////////////////
size_t AssetAccount::writeAssetEntry(shared_ptr<AssetEntry> entryPtr)
{
   if (!entryPtr->needsCommit())
      return SIZE_MAX;

   auto&& tx = getWriteTx_(data_->dbName_);

   auto&& serializedEntry = entryPtr->serialize();
   auto&& dbKey = entryPtr->getDbKey();

   tx->insert(dbKey, serializedEntry);

   entryPtr->doNotCommit();
   return serializedEntry.getSize();
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateOnDiskAssets()
{
   auto&& tx = getWriteTx_(data_->dbName_);
   for (auto& entryPtr : data_->assets_)
      writeAssetEntry(entryPtr.second);

   updateAssetCount();
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::updateAssetCount()
{
   //asset count key
   BinaryWriter bwKey;
   bwKey.put_uint8_t(ASSET_COUNT_PREFIX);
   bwKey.put_BinaryData(getFullID());

   //asset count
   BinaryWriter bwData;
   bwData.put_var_int(data_->assets_.size());

   auto&& tx = getWriteTx_(data_->dbName_);
   tx->insert(bwKey.getData(), bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::commit()
{
   //id as key
   BinaryWriter bwKey;
   bwKey.put_uint8_t(ASSET_ACCOUNT_PREFIX);
   bwKey.put_BinaryData(getFullID());

   //data
   BinaryWriter bwData;

   //type
   bwData.put_uint8_t(type());

   //parent key size
   bwData.put_var_int(data_->parentId_.getSize());

   //der scheme
   auto&& derSchemeSerData = data_->derScheme_->serialize();
   bwData.put_var_int(derSchemeSerData.getSize());
   bwData.put_BinaryData(derSchemeSerData);
     
   //commit root asset if there is one
   if (data_->root_ != nullptr)
      writeAssetEntry(data_->root_);

   //commit assets
   for (auto asset : data_->assets_)
      writeAssetEntry(asset.second);

   //commit serialized account data
   auto&& tx = getWriteTx_(data_->dbName_);
   tx->insert(bwKey.getData(), bwData.getData());

   updateAssetCount();
   updateHighestUsedIndex();
}

////////////////////////////////////////////////////////////////////////////////
AccountDataStruct AssetAccount::loadFromDisk(const BinaryData& key, 
   shared_ptr<WalletDBInterface> iface, const string& dbName)
{
   //sanity checks
   if (iface == nullptr || dbName.size() == 0)
      throw AccountException("invalid db pointers");

   auto uniqueTx = iface->beginReadTransaction(dbName);
   shared_ptr<DBIfaceTransaction> sharedTx(move(uniqueTx));

   if (key.getSize() == 0)
      throw AccountException("invalid key size");

   if (key.getPtr()[0] != ASSET_ACCOUNT_PREFIX)
      throw AccountException("unexpected prefix for AssetAccount key");

   auto&& diskDataRef = sharedTx->getDataRef(key);
   BinaryRefReader brr(diskDataRef);

   //type
   auto type = AssetAccountTypeEnum(brr.get_uint8_t());

   //ids
   auto parent_id_len = brr.get_var_int();

   auto&& parent_id = key.getSliceCopy(1, parent_id_len);
   auto&& account_id = key.getSliceCopy(
      1 + parent_id_len, key.getSize() - 1 - parent_id_len);

   //der scheme
   auto len = brr.get_var_int();
   auto derSchemeBDR = DBUtils::getDataRefForPacket(brr.get_BinaryDataRef(len));
   auto derScheme = DerivationScheme::deserialize(derSchemeBDR, sharedTx);

   //asset count
   size_t assetCount = 0;
   {
      BinaryWriter bwKey_assetcount;
      bwKey_assetcount.put_uint8_t(ASSET_COUNT_PREFIX);
      bwKey_assetcount.put_BinaryDataRef(key.getSliceRef(
         1, key.getSize() - 1));

      auto&& assetcount = sharedTx->getDataRef(bwKey_assetcount.getData());
      if (assetcount.getSize() == 0)
         throw AccountException("missing asset count entry");

      BinaryRefReader brr_assetcount(assetcount);
      assetCount = brr_assetcount.get_var_int();
   }

   //last used index
   size_t lastUsedIndex = 0;
   {
      BinaryWriter bwKey_lastusedindex;
      bwKey_lastusedindex.put_uint8_t(ASSET_TOP_INDEX_PREFIX);
      bwKey_lastusedindex.put_BinaryDataRef(key.getSliceRef(
         1, key.getSize() - 1));

      auto&& lastusedindex = sharedTx->getDataRef(
         bwKey_lastusedindex.getData());
      if (lastusedindex.getSize() == 0)
         throw AccountException("missing last used entry");

      BinaryRefReader brr_lastusedindex(lastusedindex);
      lastUsedIndex = brr_lastusedindex.get_var_int();
   }

   //asset entry prefix key
   BinaryWriter bwAssetKey;
   bwAssetKey.put_uint8_t(ASSETENTRY_PREFIX);
   bwAssetKey.put_BinaryDataRef(key.getSliceRef(1, key.getSize() - 1));
   
   //asset key
   shared_ptr<AssetEntry> rootEntry = nullptr;
   map<unsigned, shared_ptr<AssetEntry>> assetMap;
   
   //get all assets
   {
      auto& assetDbKey = bwAssetKey.getData();
      auto dbIter = sharedTx->getIterator();
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

         if (assetPtr->getIndex() != ROOT_ASSETENTRY_ID)
            assetMap.insert(make_pair(assetPtr->getIndex(), assetPtr));
         else
            rootEntry = assetPtr;

         dbIter->advance();
      } 
   }

   //sanity check
   if (assetCount != assetMap.size())
      throw AccountException("unexpected account asset count");

   //instantiate object
   auto accDataPtr = make_shared<AssetAccountData>(
      account_id, parent_id, rootEntry, derScheme, dbName);

   accDataPtr->lastUsedIndex_ = lastUsedIndex;
   accDataPtr->assets_ = move(assetMap);

   AccountDataStruct ads;
   ads.accountData_ = accDataPtr;
   ads.type_ = type;

   return ads;
}

////////////////////////////////////////////////////////////////////////////////
int AssetAccount::getLastComputedIndex(void) const
{
   ReentrantLock lock(this);

   if (data_->assets_.empty())
      return -1;

   auto iter = data_->assets_.rbegin();
   return iter->first;
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetAccount::getHighestUsedIndex() const
{
   return data_->lastUsedIndex_;
}

////////////////////////////////////////////////////////////////////////////////
size_t AssetAccount::getAssetCount() const
{
   ReentrantLock lock(this);
   return data_->assets_.size();
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChain(unsigned count)
{
   ReentrantLock lock(this);

   //add *count* entries to address chain
   shared_ptr<AssetEntry> assetPtr = nullptr;
   if (!data_->assets_.empty())
      assetPtr = data_->assets_.rbegin()->second;
   else
      assetPtr = data_->root_;

   if (count == 0)
      return;

   extendPublicChain(assetPtr, count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChainToIndex(unsigned count)
{
   ReentrantLock lock(this);

   //make address chain at least *count* long
   auto lastComputedIndex = max(getLastComputedIndex(), 0);
   if (lastComputedIndex > count)
      return;

   auto toCompute = count - lastComputedIndex;
   extendPublicChain(toCompute);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPublicChain(
   shared_ptr<AssetEntry> assetPtr, unsigned count)
{
   if (count == 0)
      return;

   ReentrantLock lock(this);

   auto&& assetVec = extendPublicChain(assetPtr,
      assetPtr->getIndex() + 1, 
      assetPtr->getIndex() + count);

   {
      for (auto& asset : assetVec)
      {
         auto id = asset->getIndex();
         auto iter = data_->assets_.find(id);
         if (iter != data_->assets_.end())
            continue;

         data_->assets_.insert(make_pair(
            id, asset));
      }
   }

   updateOnDiskAssets();
}

////////////////////////////////////////////////////////////////////////////////
vector<shared_ptr<AssetEntry>> AssetAccount::extendPublicChain(
   shared_ptr<AssetEntry> assetPtr, 
   unsigned start, unsigned end)
{
   vector<shared_ptr<AssetEntry>> result;

   switch (data_->derScheme_->getType())
   {
   case DerSchemeType_ArmoryLegacy:
   {
      //Armory legacy derivation operates from the last valid asset
      result = move(data_->derScheme_->extendPublicChain(
         assetPtr, start, end));
      break;
   }

   case DerSchemeType_BIP32:
   case DerSchemeType_ECDH:
   {
      //BIP32 operates from the node's root asset
      result = move(data_->derScheme_->extendPublicChain(
         data_->root_, start, end));
      break;
   }

   default:
      throw AccountException("unexpected derscheme type");
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChain(
   shared_ptr<DecryptedDataContainer> ddc,
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

   extendPrivateChain(ddc, topAsset, count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChainToIndex(
   shared_ptr<DecryptedDataContainer> ddc,
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

   if (id > topIndex)
   {
      auto count = id - topIndex;
      extendPrivateChain(ddc, topAsset, count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount::extendPrivateChain(
   shared_ptr<DecryptedDataContainer> ddc,
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

   updateOnDiskAssets();
}

////////////////////////////////////////////////////////////////////////////////
vector<shared_ptr<AssetEntry>> AssetAccount::extendPrivateChain(
   shared_ptr<DecryptedDataContainer> ddc,
   shared_ptr<AssetEntry> assetPtr,
   unsigned start, unsigned end)
{
   vector<shared_ptr<AssetEntry>> result;

   switch (data_->derScheme_->getType())
   {
   case DerSchemeType_ArmoryLegacy:
   {
      //Armory legacy derivation operates from the last valid asset
      result = move(data_->derScheme_->extendPrivateChain(
         ddc, assetPtr, start, end));
      break;
   }

   case DerSchemeType_BIP32:
   case DerSchemeType_ECDH:
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
void AssetAccount::updateHighestUsedIndex()
{
   ReentrantLock lock(this);

   BinaryWriter bwKey;
   bwKey.put_uint8_t(ASSET_TOP_INDEX_PREFIX);
   bwKey.put_BinaryData(getFullID());

   BinaryWriter bwData;
   bwData.put_var_int(data_->lastUsedIndex_);

   auto tx = getWriteTx_(data_->dbName_);
   tx->insert(bwKey.getData(), bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetAccount::getAndBumpHighestUsedIndex()
{
   ReentrantLock lock(this);

   ++data_->lastUsedIndex_;
   updateHighestUsedIndex();
   return data_->lastUsedIndex_;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getNewAsset()
{
   ReentrantLock lock(this);

   auto index = getAndBumpHighestUsedIndex();
   auto entryIter = data_->assets_.find(index);
   if (entryIter == data_->assets_.end())
   {
      extendPublicChain(getLookup());
      entryIter = data_->assets_.find(index);
      if (entryIter == data_->assets_.end())
         throw AccountException("requested index overflows max lookup");
   }

   return entryIter->second;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::peekNextAsset()
{
   ReentrantLock lock(this);

   auto index = data_->lastUsedIndex_ + 1;
   auto entryIter = data_->assets_.find(index);
   if (entryIter == data_->assets_.end())
   {
      extendPublicChain(getLookup());
      entryIter = data_->assets_.find(index);
      if (entryIter == data_->assets_.end())
         throw AccountException("requested index overflows max lookup");
   }

   return entryIter->second;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getAssetForID(const BinaryData& ID) const
{
   if (ID.getSize() < 4)
      throw runtime_error("invalid asset ID");

   auto id_int = READ_UINT32_BE(ID.getPtr());
   return getAssetForIndex(id_int);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetAccount::getAssetForIndex(unsigned id) const
{
   auto iter = data_->assets_.find(id);
   if (iter == data_->assets_.end())
      throw AccountException("unknown asset index");

   return iter->second;
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
const map<BinaryData, map<AddressEntryType, BinaryData>>& 
   AssetAccount::getAddressHashMap(const set<AddressEntryType>& typeSet)
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
   shared_ptr<DecryptedDataContainer> ddc,
   const BinaryData& id)
{
   if (id.getSize() != 12)
      throw AccountException("unexpected asset id length");

   //get the asset
   auto assetID_bdr = id.getSliceRef(8, 4);
   auto assetID = READ_UINT32_BE(assetID_bdr);

   auto iter = data_->assets_.find(assetID);
   if (iter == data_->assets_.end())
      throw AccountException("invalid asset id");

   auto thisAsset = std::dynamic_pointer_cast<AssetEntry_Single>(iter->second);
   if (thisAsset == nullptr)
      throw AccountException("unexpected asset type in map");

   //sanity check
   if (thisAsset->hasPrivateKey())
      return thisAsset->getPrivKey();

   //reverse iter through the map, find closest previous asset with priv key
   //this is only necessary for armory 1.35 derivation
   shared_ptr<AssetEntry> prevAssetWithKey = nullptr;
   map<unsigned, shared_ptr<AssetEntry>>::reverse_iterator rIter(iter);
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
   unsigned count = assetID - (unsigned)prevAssetWithKey->getIndex();

   //extend the private chain
   extendPrivateChain(ddc, prevAssetWithKey, count);

   //grab the fresh asset, return its private key
   auto privKeyIter = data_->assets_.find(assetID);
   if (privKeyIter == data_->assets_.end())
      throw AccountException("invalid asset id");

   if (!privKeyIter->second->hasPrivateKey())
      throw AccountException("fillPrivateKey failed");

   auto assetSingle = 
      std::dynamic_pointer_cast<AssetEntry_Single>(privKeyIter->second);
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
unsigned AssetAccount_ECDH::addSalt(const SecureBinaryData& salt)
{
   auto derScheme = 
      dynamic_pointer_cast<DerivationScheme_ECDH>(data_->derScheme_);

   if (derScheme == nullptr)
      throw AccountException("unexpected derivation scheme type");

   auto uniqueTx = getWriteTx_(data_->dbName_);
   shared_ptr<DBIfaceTransaction> sharedTx(move(uniqueTx));
   return derScheme->addSalt(salt, sharedTx);
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetAccount_ECDH::getSaltIndex(const SecureBinaryData& salt) const
{
   auto derScheme = 
      dynamic_pointer_cast<DerivationScheme_ECDH>(data_->derScheme_);

   if (derScheme == nullptr)
      throw AccountException("unexpected derivation scheme type");

   return derScheme->getSaltIndex(salt);
}

////////////////////////////////////////////////////////////////////////////////
void AssetAccount_ECDH::commit()
{
   auto schemeECDH =
      dynamic_pointer_cast<DerivationScheme_ECDH>(data_->derScheme_);
   if (schemeECDH == nullptr)
      throw AccountException("expected ECDH derScheme");

   auto uniqueTx = getWriteTx_(data_->dbName_);
   AssetAccount::commit();

   shared_ptr<DBIfaceTransaction> sharedTx(move(uniqueTx));
   schemeECDH->putAllSalts(sharedTx);
}