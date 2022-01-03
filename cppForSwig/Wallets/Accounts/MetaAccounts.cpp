////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "MetaAccounts.h"
#include "../Assets.h"
#include "../EncryptedDB.h"
#include "../WalletFileInterface.h"

using namespace std;
using namespace Armory::Assets;
using namespace Armory::Accounts;
using namespace Armory::Wallets;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// MetaDataAccount
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void MetaDataAccount::make_new(MetaAccountType type)
{
   type_ = type;

   switch (type_)
   {
   case MetaAccount_Comments:
   {
      ID_ = WRITE_UINT32_BE(META_ACCOUNT_COMMENTS);
      break;
   }

   case MetaAccount_AuthPeers:
   {
      ID_ = WRITE_UINT32_BE(META_ACCOUNT_AUTHPEER);
      break;
   }

   default:
      throw AccountException("unexpected meta account type");
   }
}

////////////////////////////////////////////////////////////////////////////////
void MetaDataAccount::commit(unique_ptr<IO::DBIfaceTransaction> txPtr) const
{
   ReentrantLock lock(this);

   BinaryWriter bwKey;
   bwKey.put_uint8_t(META_ACCOUNT_PREFIX);
   bwKey.put_BinaryData(ID_);

   BinaryWriter bwData;
   bwData.put_var_int(4);
   bwData.put_uint32_t((uint32_t)type_);

   //commit assets
   shared_ptr<IO::DBIfaceTransaction> sharedTx(move(txPtr));
   for (auto& asset : assets_)
      writeAssetToDisk(sharedTx, asset.second);

   //commit serialized account data
   sharedTx->insert(bwKey.getData(), bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
bool MetaDataAccount::writeAssetToDisk(
   shared_ptr<IO::DBIfaceTransaction> txPtr,
   shared_ptr<MetaData> assetPtr) const
{
   if (!assetPtr->needsCommit())
      return true;
   
   assetPtr->needsCommit_ = false;

   auto&& key = assetPtr->getDbKey();
   auto&& data = assetPtr->serialize();

   if (data.getSize() != 0)
   {
      txPtr->insert(key, data);
      return true;
   }
   else
   {
      txPtr->erase(key);
      return false;
   }
}

////////////////////////////////////////////////////////////////////////////////
void MetaDataAccount::updateOnDisk(shared_ptr<IO::DBIfaceTransaction> txPtr)
{
   ReentrantLock lock(this);

   bool needsCommit = false;
   for (auto& asset : assets_)
      needsCommit |= asset.second->needsCommit();

   if (!needsCommit)
      return;

   auto iter = assets_.begin();
   while (iter != assets_.end())
   {
      if (writeAssetToDisk(txPtr, iter->second))
      {
         ++iter;
         continue;
      }

      assets_.erase(iter++);
   }
}

////////////////////////////////////////////////////////////////////////////////
void MetaDataAccount::reset()
{
   type_ = MetaAccount_Unset;
   ID_.clear();
   assets_.clear();
}

////////////////////////////////////////////////////////////////////////////////
void MetaDataAccount::readFromDisk(
   shared_ptr<IO::WalletDBInterface> iface, const BinaryData& key)
{
   //sanity checks
   if (iface == nullptr || dbName_.size() == 0)
      throw AccountException("invalid db pointers");

   if (key.getSize() != 5)
      throw AccountException("invalid key size");

   if (key.getPtr()[0] != META_ACCOUNT_PREFIX)
      throw AccountException("unexpected prefix for AssetAccount key");

   auto&& tx = iface->beginReadTransaction(dbName_);

   CharacterArrayRef carKey(key.getSize(), key.getCharPtr());

   auto diskDataRef = tx->getDataRef(key);
   BinaryRefReader brr(diskDataRef);

   //wipe object prior to loading from disk
   reset();

   //set ID
   ID_ = key.getSliceCopy(1, 4);

   //getType
   brr.get_var_int();
   type_ = (MetaAccountType)brr.get_uint32_t();

   uint8_t prefix;
   switch (type_)
   {
   case MetaAccount_Comments:
   {
      prefix = METADATA_COMMENTS_PREFIX;
      break;
   }

   case MetaAccount_AuthPeers:
   {
      prefix = METADATA_AUTHPEER_PREFIX;
      break;
   }

   default:
      throw AccountException("unexpected meta account type");
   }

   //get assets
   BinaryWriter bwAssetKey;
   bwAssetKey.put_uint8_t(prefix);
   bwAssetKey.put_BinaryData(ID_);
   auto& assetDbKey = bwAssetKey.getData();

   auto dbIter = tx->getIterator();
   dbIter->seek(assetDbKey);

   while (dbIter->isValid())
   {
      auto&& key = dbIter->key();
      auto&& data = dbIter->value();

      //check key isnt prefix
      if (key == assetDbKey)
         continue;

      //check key starts with prefix
      if (!key.startsWith(assetDbKey))
         break;

      //deser asset
      try
      {
         auto assetPtr = MetaData::deserialize(key, data);
         assets_.insert(make_pair(
            assetPtr->index_, assetPtr));
      }
      catch (exception&)
      {}

      dbIter->advance();
   }
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaData> MetaDataAccount::getMetaDataByIndex(unsigned id) const
{
   auto iter = assets_.find(id);
   if (iter == assets_.end())
      throw AccountException("invalid asset index");

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
void MetaDataAccount::eraseMetaDataByIndex(unsigned id)
{
   auto iter = assets_.find(id);
   if (iter == assets_.end())
      return;

   iter->second->clear();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaDataAccount> MetaDataAccount::copy(const string& dbName) const
{
   auto copyPtr = make_shared<MetaDataAccount>(dbName);
   
   copyPtr->type_ = type_;
   copyPtr->ID_ = ID_;

   for (auto& assetPair : assets_)
   {
      auto assetCopy = assetPair.second->copy();
      assetCopy->flagForCommit();
      copyPtr->assets_.insert(make_pair(assetPair.first, assetCopy));
   }

   return copyPtr;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AuthPeerAssetConversion
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AuthPeerAssetMap AuthPeerAssetConversion::getAssetMap(
   const MetaDataAccount* account)
{
   if (account == nullptr || account->type_ != MetaAccount_AuthPeers)
      throw AccountException("invalid metadata account ptr");
   ReentrantLock lock(account);

   AuthPeerAssetMap result;

   for (auto& asset : account->assets_)
   {
      switch (asset.second->type())
      {
      case MetaType_AuthorizedPeer:
      {
         auto assetPeer = dynamic_pointer_cast<PeerPublicData>(asset.second);
         if (assetPeer == nullptr)
            continue;

         auto& names = assetPeer->getNames();
         auto& pubKey = assetPeer->getPublicKey();

         for (auto& name : names)
            result.nameKeyPair_.emplace(make_pair(name, &pubKey));

         break;
      }

      case MetaType_PeerRootKey:
      {
         auto assetRoot = dynamic_pointer_cast<PeerRootKey>(asset.second);
         if (assetRoot == nullptr)
            continue;

         auto descPair = make_pair(assetRoot->getDescription(), asset.first);
         result.peerRootKeys_.emplace(make_pair(assetRoot->getKey(), descPair));
         
         break;
      }

      case MetaType_PeerRootSig:
      {
         auto assetSig = dynamic_pointer_cast<PeerRootSignature>(asset.second);
         if (assetSig == nullptr)
            continue;

         result.rootSignature_ = make_pair(assetSig->getKey(), assetSig->getSig());
      }

      default:
         continue;
      }
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
map<SecureBinaryData, set<unsigned>> 
   AuthPeerAssetConversion::getKeyIndexMap(const MetaDataAccount* account)
{
   if (account == nullptr || account->type_ != MetaAccount_AuthPeers)
      throw AccountException("invalid metadata account ptr");
   ReentrantLock lock(account);

   map<SecureBinaryData, set<unsigned>> result;

   for (auto& asset : account->assets_)
   {
      auto assetPeer = dynamic_pointer_cast<PeerPublicData>(asset.second);
      if (assetPeer == nullptr)
         throw AccountException("invalid asset type");

      auto& pubKey = assetPeer->getPublicKey();

      auto iter = result.find(pubKey);
      if (iter == result.end())
      {
         auto insertIter = result.insert(make_pair(
            pubKey, set<unsigned>()));
         iter = insertIter.first;
      }

      iter->second.insert(asset.first);
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
int AuthPeerAssetConversion::addAsset(
   MetaDataAccount* account, const SecureBinaryData& pubkey,
   const std::vector<std::string>& names,
   shared_ptr<IO::DBIfaceTransaction> txPtr)
{
   ReentrantLock lock(account);

   if (account == nullptr || account->type_ != MetaAccount_AuthPeers)
      throw AccountException("invalid metadata account ptr");

   auto& accountID = account->ID_;
   unsigned index = account->assets_.size();

   auto metaObject = make_shared<PeerPublicData>(accountID, index);
   metaObject->setPublicKey(pubkey);
   for (auto& name : names)
      metaObject->addName(name);

   metaObject->flagForCommit();
   account->assets_.emplace(make_pair(index, metaObject));
   account->updateOnDisk(txPtr);

   return index;
}

////////////////////////////////////////////////////////////////////////////////
void AuthPeerAssetConversion::addRootSignature(MetaDataAccount* account,
   const SecureBinaryData& key, const SecureBinaryData& sig,
   shared_ptr<IO::DBIfaceTransaction> txPtr)
{
   ReentrantLock lock(account);

   if (account == nullptr || account->type_ != MetaAccount_AuthPeers)
      throw AccountException("invalid metadata account ptr");

   auto& accountID = account->ID_;
   unsigned index = account->assets_.size();

   auto metaObject = make_shared<PeerRootSignature>(accountID, index);
   metaObject->set(key, sig);
   
   metaObject->flagForCommit();
   account->assets_.emplace(make_pair(index, metaObject));
   account->updateOnDisk(txPtr);
}
////////////////////////////////////////////////////////////////////////////////
unsigned AuthPeerAssetConversion::addRootPeer(MetaDataAccount* account,
   const SecureBinaryData& key, const std::string& desc, 
   shared_ptr<IO::DBIfaceTransaction> txPtr)
{
   ReentrantLock lock(account);

   if (account == nullptr || account->type_ != MetaAccount_AuthPeers)
      throw AccountException("invalid metadata account ptr");

   auto& accountID = account->ID_;
   unsigned index = account->assets_.size();

   auto metaObject = make_shared<PeerRootKey>(accountID, index);
   metaObject->set(desc, key);

   metaObject->flagForCommit();
   account->assets_.emplace(make_pair(index, metaObject));
   account->updateOnDisk(txPtr);

   return index;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// CommentAssetConversion
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
shared_ptr<CommentData> CommentAssetConversion::getByKey(
   MetaDataAccount* account, const BinaryData& key)
{
   ReentrantLock lock(account);

   if (account == nullptr || account->type_ != MetaAccount_Comments)
      throw AccountException("invalid metadata account ptr");

   for (auto& asset : account->assets_)
   {
      auto objPtr = dynamic_pointer_cast<CommentData>(asset.second);
      if (objPtr == nullptr)
         continue;

      if (objPtr->getKey() == key)
         return objPtr;
   }

   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
int CommentAssetConversion::setAsset(MetaDataAccount* account,
   const BinaryData& key, const std::string& comment,
   shared_ptr<IO::DBIfaceTransaction> txPtr)
{
   if (comment.size() == 0)
      return INT32_MIN;

   ReentrantLock lock(account);

   if (account == nullptr || account->type_ != MetaAccount_Comments)
      throw AccountException("invalid metadata account ptr");

   auto metaObject = getByKey(account, key);

   if (metaObject == nullptr)
   {
      auto& accountID = account->ID_;
      auto index = (uint32_t)account->assets_.size();
      metaObject = make_shared<CommentData>(accountID, index);
      metaObject->setKey(key);

      account->assets_.emplace(make_pair(index, metaObject));
   }

   metaObject->setValue(comment);

   metaObject->flagForCommit();
   account->updateOnDisk(txPtr);

   return metaObject->getIndex();
}

////////////////////////////////////////////////////////////////////////////////
int CommentAssetConversion::deleteAsset(
   MetaDataAccount* account, const BinaryData& key,
   shared_ptr<IO::DBIfaceTransaction> txPtr)
{
   auto metaObject = getByKey(account, key);
   if (metaObject == nullptr)
      return -1;

   metaObject->clear();
   account->updateOnDisk(txPtr);

   return metaObject->getIndex();
}

////////////////////////////////////////////////////////////////////////////////
map<BinaryData, string> CommentAssetConversion::getCommentMap(
   MetaDataAccount* account)
{
   ReentrantLock lock(account);

   if (account == nullptr || account->type_ != MetaAccount_Comments)
      throw AccountException("invalid metadata account ptr");

   map<BinaryData, string> result;
   for (auto& asset : account->assets_)
   {
      auto objPtr = dynamic_pointer_cast<CommentData>(asset.second);
      if (objPtr == nullptr)
         continue;

      result.emplace(objPtr->getKey(), objPtr->getValue());
   }

   return result;
}