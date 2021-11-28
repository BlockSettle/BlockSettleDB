////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2019, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Assets.h"
#include "BtcUtils.h"
#include "DBUtils.h"
#include "ScriptRecipient.h"
#include "BIP32_Node.h"

#define ASSET_VERSION                  0x00000001
#define CIPHER_DATA_VERSION            0x00000001

#define ASSETENTRY_SINGLE_VERSION      0x00000001
#define ASSETENTRY_BIP32ROOT_VERSION   0x00000002
#define ASSETENTRY_LEGACYROOT_VERSION  0x00000001

#define ENCRYPTED_SEED_VERSION         0x00000001
#define ENCRYPTION_KEY_VERSION         0x00000001

#define PRIVKEY_VERSION                0x00000001
#define PUBKEY_COMPRESSED_VERSION      0x00000001
#define PUBKEY_UNCOMPRESSED_VERSION    0x00000001

#define PEER_PUBLICDATA_VERSION        0x00000001
#define PEER_ROOTKEY_VERSION           0x00000001
#define PEER_ROOTSIG_VERSION           0x00000001

#define COMMENT_DATA_VERSION           0x00000001

using namespace std;
using namespace Armory::Assets;
using namespace Armory::Wallets;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DecryptedData
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void ClearTextEncryptionKey::deriveKey(shared_ptr<KeyDerivationFunction> kdf)
{
   if (derivedKeys_.find(kdf->getId()) != derivedKeys_.end())
      return;

   auto&& derivedkey = kdf->deriveKey(rawKey_);
   auto&& keypair = make_pair(kdf->getId(), move(derivedkey));
   derivedKeys_.insert(move(keypair));
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<ClearTextEncryptionKey> ClearTextEncryptionKey::copy() const
{
   auto key_copy = rawKey_;
   auto copy_ptr = make_unique<ClearTextEncryptionKey>(key_copy);

   copy_ptr->derivedKeys_ = derivedKeys_;

   return copy_ptr;
}

////////////////////////////////////////////////////////////////////////////////
EncryptionKeyId ClearTextEncryptionKey::getId(
   const BinaryData& kdfId) const
{
   const auto keyIter = derivedKeys_.find(kdfId);
   if (keyIter == derivedKeys_.end())
      throw runtime_error("couldn't find derivation for kdfid");

   return computeId(keyIter->second);
}

////////////////////////////////////////////////////////////////////////////////
EncryptionKeyId ClearTextEncryptionKey::computeId(
   const SecureBinaryData& key) const
{
   //treat value as scalar, get pubkey for it
   auto&& hashedKey = BtcUtils::hash256(key);
   auto&& pubkey = CryptoECDSA().ComputePublicKey(hashedKey);

   //HMAC the pubkey, get last 16 bytes as ID
   return EncryptionKeyId(
      BtcUtils::computeDataId(pubkey, HMAC_KEY_ENCRYPTIONKEYS));
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& ClearTextEncryptionKey::getDerivedKey(
   const BinaryData& id) const
{
   auto iter = derivedKeys_.find(id);
   if (iter == derivedKeys_.end())
      throw runtime_error("invalid key");

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// CipherData
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
bool CipherData::isSame(CipherData* const rhs) const
{
   return cipherText_ == rhs->cipherText_ &&
      cipher_->isSame(rhs->cipher_.get());
}

////////////////////////////////////////////////////////////////////////////////
BinaryData CipherData::serialize(void) const
{
   BinaryWriter bw;
   bw.put_uint32_t(CIPHER_DATA_VERSION);

   bw.put_var_int(cipherText_.getSize());
   bw.put_BinaryData(cipherText_);

   auto&& data = cipher_->serialize();
   bw.put_var_int(data.getSize());
   bw.put_BinaryData(data);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<CipherData> CipherData::deserialize(BinaryRefReader& brr)
{
   unique_ptr<CipherData> cipherDataPtr = nullptr;

   auto version = brr.get_uint32_t();
   switch (version)
   {
   case 0x00000001:
   {
      auto len = brr.get_var_int();
      if (len > brr.getSizeRemaining())
         throw AssetException("invalid ciphertext length");

      auto&& cipherText = brr.get_SecureBinaryData(len);

      len = brr.get_var_int();
      if (len > brr.getSizeRemaining())
         throw AssetException("invalid cipher length");

      auto&& cipher = Cipher::deserialize(brr);
      cipherDataPtr = make_unique<CipherData>(cipherText, move(cipher));

      break;
   }

   default:
      throw AssetException("unsupported cipher data version");
   }

   if (cipherDataPtr == nullptr)
      throw AssetException("failed to deser cipher data");
   return cipherDataPtr;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetEntry
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetEntry::~AssetEntry(void)
{}

////////////////////////////////////////////////////////////////////////////////
AssetKeyType AssetEntry::getIndex(void) const
{
   return ID_.getAssetKey();
}

////////////////////////////////////////////////////////////////////////////////
const AssetAccountId AssetEntry::getAccountID(void) const
{
   return ID_.getAssetAccountId();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AssetEntry::getDbKey() const
{
   return ID_.getSerializedKey(ASSETENTRY_PREFIX);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetEntry::deserialize(
   BinaryDataRef key, BinaryDataRef value)
{
   BinaryRefReader brrKey(key);
   auto assetId = AssetId::deserializeKey(key, ASSETENTRY_PREFIX);
   auto assetPtr = deserDBValue(assetId, value);
   assetPtr->doNotCommit();
   return assetPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetEntry::deserDBValue(
   const AssetId& assetId, BinaryDataRef value)
{
   BinaryRefReader brrVal(value);

   auto version = brrVal.get_uint32_t();
   auto val = brrVal.get_uint8_t();
   auto entryType = AssetEntryType(val & 0x0F);

   auto getKeyData = [&assetId](BinaryRefReader& brr,
      shared_ptr<Asset_PrivateKey>& privKeyPtr,
      SecureBinaryData& pubKeyCompressed,
      SecureBinaryData& pubKeyUncompressed
   )->void
   {
      vector<BinaryDataRef> dataVec;

      while (brr.getSizeRemaining() > 0)
      {
         auto len = brr.get_var_int();
         auto valref = brr.get_BinaryDataRef(len);
         dataVec.push_back(valref);
      }

      for (auto& dataRef : dataVec)
      {
         BinaryRefReader brrData(dataRef);
         auto version = brrData.get_uint32_t();
         auto keybyte = brrData.get_uint8_t();

         switch (keybyte)
         {
         case PUBKEY_UNCOMPRESSED_BYTE:
         {
            switch (version)
            {
            case 0x00000001:
            {
               if (dataRef.getSize() != 70)
                  throw AssetException("invalid size for uncompressed pub key");

               if (!pubKeyUncompressed.empty())
                  throw AssetException("multiple pub keys for entry");

               pubKeyUncompressed = move(SecureBinaryData(
                  brrData.get_BinaryDataRef(brrData.getSizeRemaining())));

               break;
            }

            default:
               throw AssetException("unsupported pubkey version");
            }

            break;
         }

         case PUBKEY_COMPRESSED_BYTE:
         {
            switch (version)
            {
            case 0x00000001:
            {
               if (dataRef.getSize() != 38)
                  throw AssetException("invalid size for compressed pub key");

               if (!pubKeyCompressed.empty())
                  throw AssetException("multiple pub keys for entry");

               pubKeyCompressed = move(SecureBinaryData(
                  brrData.get_BinaryDataRef(brrData.getSizeRemaining())));

               break;
            }

            default:
               throw AssetException("unsupported pubkey version");
            }

            break;
         }

         case PRIVKEY_BYTE:
         {
            switch (version)
            {
            case 0x00000001:
            {
               if (privKeyPtr != nullptr)
                  throw AssetException("multiple priv keys for entry");

               unique_ptr<EncryptedAssetData> keyUPtr;
               try
               {
                  keyUPtr = EncryptedAssetData::deserialize(dataRef);
               }
               catch (const IdException&)
               {
                  //potentially an old id format, let's try that instead
                  keyUPtr = EncryptedAssetData::deserializeOld(
                     assetId, dataRef);
               }

               if (keyUPtr->getAssetId() != assetId)
                  throw AssetException("priv key asset mismatch");
               shared_ptr<EncryptedAssetData> keySPtr(move(keyUPtr));

               privKeyPtr = dynamic_pointer_cast<Asset_PrivateKey>(keySPtr);
               if (privKeyPtr == nullptr)
                  throw AssetException("deserialized to unexpected type");
               break;
            }

            default:
               throw AssetException("unsupported privkey version");
            }

            break;
         }

         default:
            throw AssetException("unsupported key type byte");
         }
      }
   };

   switch (entryType)
   {
   case AssetEntryType_Single:
   {
      switch (version)
      {
      case 0x00000001:
      {
         shared_ptr<Asset_PrivateKey> privKeyPtr;
         SecureBinaryData pubKeyCompressed;
         SecureBinaryData pubKeyUncompressed;

         getKeyData(brrVal, privKeyPtr, pubKeyCompressed, pubKeyUncompressed);

         auto addrEntry = make_shared<AssetEntry_Single>(
            assetId,
            pubKeyUncompressed, pubKeyCompressed, privKeyPtr);

         addrEntry->doNotCommit();
         return addrEntry;
      }

      default:
         throw AssetException("unsupported asset single version");
      }

      break;
   }

   case AssetEntryType_BIP32Root:
   {
      switch (version)
      {
      case 0x00000001:
      case 0x00000002:
      {
         auto depth = brrVal.get_uint8_t();
         auto leafid = brrVal.get_uint32_t();
         auto fingerprint = brrVal.get_uint32_t();
         auto cclen = brrVal.get_var_int();
         auto&& chaincode = brrVal.get_BinaryData(cclen);
         unsigned seedFingerprint = UINT32_MAX;

         vector<uint32_t> derPath;
         if (version >= 0x00000002)
         {
            seedFingerprint = brrVal.get_uint32_t();
            auto count = brrVal.get_var_int();
            for (unsigned i=0; i<count; i++)
               derPath.push_back(brrVal.get_uint32_t());
         }

         shared_ptr<Asset_PrivateKey> privKeyPtr;
         SecureBinaryData pubKeyCompressed;
         SecureBinaryData pubKeyUncompressed;

         getKeyData(brrVal, privKeyPtr, pubKeyCompressed, pubKeyUncompressed);

         shared_ptr<AssetEntry_BIP32Root> rootEntry;
         if (!pubKeyCompressed.empty())
         {
            rootEntry = make_shared<AssetEntry_BIP32Root>(
               assetId,
               pubKeyCompressed, privKeyPtr,
               chaincode, depth, leafid, fingerprint, seedFingerprint,
               derPath);
         }
         else
         {
            rootEntry = make_shared<AssetEntry_BIP32Root>(
               assetId,
               pubKeyUncompressed, privKeyPtr,
               chaincode, depth, leafid, fingerprint, seedFingerprint,
               derPath);
         }

         rootEntry->doNotCommit();
         return rootEntry;
      }

      default:
         throw AssetException("unsupported bip32 root version");
      }

      break;
   }

   case AssetEntryType_ArmoryLegacyRoot:
   {
      switch (version)
      {
      case 0x00000001:
      {
         auto cclen = brrVal.get_var_int();
         auto&& chaincode = brrVal.get_BinaryData(cclen);

         shared_ptr<Asset_PrivateKey> privKeyPtr;
         SecureBinaryData pubKeyCompressed;
         SecureBinaryData pubKeyUncompressed;

         getKeyData(brrVal, privKeyPtr, pubKeyCompressed, pubKeyUncompressed);

         auto rootEntry = make_shared<AssetEntry_ArmoryLegacyRoot>(
            assetId,
            pubKeyCompressed, privKeyPtr,
            chaincode);

         rootEntry->doNotCommit();
         return rootEntry;
      }

      default:
         throw AssetException("unsupported legacy root version");
      }
   }

   default:
      throw AssetException("invalid asset entry type");
   }

   throw AssetException("invalid asset entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AssetEntry_Single::serialize() const
{
   BinaryWriter bw;

   bw.put_uint32_t(ASSETENTRY_SINGLE_VERSION);

   auto entryType = getType();
   bw.put_uint8_t(entryType);

   bw.put_BinaryData(pubkey_->serialize());
   if (privkey_ != nullptr && privkey_->hasData())
      bw.put_BinaryData(privkey_->serialize());

   BinaryWriter finalBw;

   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryData(bw.getData());

   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AssetEntry_BIP32Root::serialize() const
{
   BinaryWriter bw;

   bw.put_uint32_t(ASSETENTRY_BIP32ROOT_VERSION);

   auto entryType = getType();
   bw.put_uint8_t(entryType);

   bw.put_uint8_t(depth_);
   bw.put_uint32_t(leafID_);
   bw.put_uint32_t(parentFingerprint_);
   
   bw.put_var_int(chaincode_.getSize());
   bw.put_BinaryData(chaincode_);

   auto pubkey = getPubKey();
   auto privkey = getPrivKey();

   bw.put_uint32_t(seedFingerprint_);
   bw.put_var_int(derivationPath_.size());
   for (auto& step : derivationPath_)
      bw.put_uint32_t(step);

   bw.put_BinaryData(pubkey->serialize());
   if (privkey != nullptr && privkey->hasData())
      bw.put_BinaryData(privkey->serialize());

   BinaryWriter finalBw;

   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryData(bw.getData());

   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool AssetEntry_Single::hasPrivateKey() const
{
   if (privkey_ != nullptr)
      return privkey_->hasData();

   return false;
}

////////////////////////////////////////////////////////////////////////////////
const EncryptionKeyId& AssetEntry_Single::getPrivateEncryptionKeyId() const
{
   if (!hasPrivateKey())
      throw runtime_error("no private key in this asset");

   return privkey_->getEncryptionKeyId();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetEntry_Single::getKdfId() const
{
   if (!hasPrivateKey())
      throw runtime_error("no private key in this asset");

   return privkey_->getKdfId();
}

////////////////////////////////////////////////////////////////////////////////
bool AssetEntry_Multisig::hasPrivateKey() const
{
   for (auto& asset_pair : assetMap_)
   {
      auto asset_single =
         dynamic_pointer_cast<AssetEntry_Single>(asset_pair.second);
      if (asset_single == nullptr)
         throw runtime_error("unexpected asset entry type");

      if (!asset_single->hasPrivateKey())
         return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
const EncryptionKeyId& AssetEntry_Multisig::getPrivateEncryptionKeyId() const
{
   if (assetMap_.size() != n_)
      throw runtime_error("missing asset entries");

   if (!hasPrivateKey())
      throw runtime_error("no private key in this asset");

   set<EncryptionKeyId> idSet;

   for (auto& asset_pair : assetMap_)
   {
      auto asset_single =
         dynamic_pointer_cast<AssetEntry_Single>(asset_pair.second);
      if (asset_single == nullptr)
         throw runtime_error("unexpected asset entry type");

      idSet.insert(asset_pair.second->getPrivateEncryptionKeyId());
   }

   if (idSet.size() != 1)
      throw runtime_error("wallets use different encryption keys");

   return *idSet.begin();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry_Single> AssetEntry_Single::getPublicCopy()
{
   return make_shared<AssetEntry_Single>(getID(), pubkey_, nullptr);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetEntry_BIP32Root
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetEntry_BIP32Root::AssetEntry_BIP32Root(const AssetId& id,
   SecureBinaryData& pubkey, shared_ptr<Asset_PrivateKey> privkey,
   const SecureBinaryData& chaincode,
   uint8_t depth, uint32_t leafID,
   uint32_t fingerPrint, uint32_t seedFingerprint,
   const vector<uint32_t>& derPath) :
   AssetEntry_Single(id, pubkey, privkey),
   chaincode_(chaincode),
   depth_(depth), leafID_(leafID),
   parentFingerprint_(fingerPrint), seedFingerprint_(seedFingerprint),
   derivationPath_(derPath)
{
   checkSeedFingerprint(false);
}

////////////////////////////////////////////////////////////////////////////////
AssetEntry_BIP32Root::AssetEntry_BIP32Root(const AssetId& id,
   shared_ptr<Asset_PublicKey> pubkey, shared_ptr<Asset_PrivateKey> privkey,
   const SecureBinaryData& chaincode,
   uint8_t depth, uint32_t leafID,
   uint32_t fingerPrint, uint32_t seedFingerprint,
   const vector<uint32_t>& derPath) :
   AssetEntry_Single(id, pubkey, privkey),
   chaincode_(chaincode),
   depth_(depth), leafID_(leafID),
   parentFingerprint_(fingerPrint), seedFingerprint_(seedFingerprint),
   derivationPath_(derPath)
{
   checkSeedFingerprint(false);
}

////////////////////////////////////////////////////////////////////////////////
void AssetEntry_BIP32Root::checkSeedFingerprint(bool strongCheck) const
{
   if (seedFingerprint_ != 0)
      return;

   stringstream ss;
   ss << "BIP32 root " << getThisFingerprint() << 
      " is missing seed fingerprint. You should regenerate this wallet!";
   cout << ss.str() << endl;

   if (strongCheck)
      throw runtime_error(ss.str());
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry_Single> AssetEntry_BIP32Root::getPublicCopy()
{
   auto pubkey = getPubKey();
   auto woCopy = make_shared<AssetEntry_BIP32Root>(
      getID(), pubkey, nullptr,
      chaincode_, depth_, leafID_, parentFingerprint_, seedFingerprint_,
      derivationPath_);

   return woCopy;
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetEntry_BIP32Root::getThisFingerprint() const
{
   if (thisFingerprint_ == UINT32_MAX)
   {
      auto pubkey = getPubKey();
      if (pubkey == nullptr)
         throw AssetException("null pubkey");

      const auto& compressed = pubkey->getCompressedKey();
      if (compressed.empty())
         throw AssetException("missing pubkey data");

      auto hash = BtcUtils::getHash160(compressed);
      thisFingerprint_ = *(uint32_t*)hash.getPtr();
   }

   return thisFingerprint_;
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetEntry_BIP32Root::getSeedFingerprint(bool strongCheck) const
{
   checkSeedFingerprint(strongCheck);

   //if we have an explicit seed fingerpint, return it
   if (seedFingerprint_ != UINT32_MAX)
      return seedFingerprint_;

   if (parentFingerprint_ == 0)
   {
      //otherwise, if it this root is from the seed (parent is 0), return
      //this fingerprint
      return getThisFingerprint();
   }

   throw runtime_error("missing seed fingerprint");
}

////////////////////////////////////////////////////////////////////////////////
string AssetEntry_BIP32Root::getXPub(void) const
{
   auto pubkey = getPubKey();
   BIP32_Node node;
   node.initFromPublicKey(
      depth_, leafID_, parentFingerprint_,
      pubkey->getCompressedKey(), chaincode_);
   
   auto base58 = node.getBase58();
   string b58str(base58.toCharPtr(), base58.getSize());
   return b58str;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetEntry_ArmoryLegacyRoot
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BinaryData AssetEntry_ArmoryLegacyRoot::serialize() const
{
   BinaryWriter bw;

   bw.put_uint32_t(ASSETENTRY_LEGACYROOT_VERSION);

   auto entryType = getType();
   bw.put_uint8_t(entryType);

   bw.put_var_int(chaincode_.getSize());
   bw.put_BinaryData(chaincode_);

   auto pubkey = getPubKey();
   auto privkey = getPrivKey();

   bw.put_BinaryData(pubkey->serialize());
   if (privkey != nullptr && privkey->hasData())
      bw.put_BinaryData(privkey->serialize());

   BinaryWriter finalBw;

   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryData(bw.getData());

   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry_Single> AssetEntry_ArmoryLegacyRoot::getPublicCopy()
{
   auto pubkey = getPubKey()->getUncompressedKey();
   if (pubkey.empty())
      throw AssetException("Armory legacy root missing uncompressed pubkey");

   auto woCopy = make_shared<AssetEntry_ArmoryLegacyRoot>(
      getID(), pubkey, nullptr, chaincode_);

   return woCopy;
}

////////////////////////////////////////////////////////////////////////////////
//
//// EncryptionKey
//
////////////////////////////////////////////////////////////////////////////////
EncryptionKey::EncryptionKey(EncryptionKeyId& id,
   SecureBinaryData& cipherText,
   unique_ptr<Cipher> cipher) :
   id_(move(id))
{
   auto cipherData = make_unique<CipherData>(cipherText, move(cipher));
   cipherDataMap_.emplace(
      cipherData->cipher_->getEncryptionKeyId(), move(cipherData));
}

////////////////////////////////////////////////////////////////////////////////
EncryptionKey::EncryptionKey(EncryptionKeyId& id,
   map<EncryptionKeyId, unique_ptr<CipherData>> cipherDataMap) :
   id_(move(id)),
   cipherDataMap_(move(cipherDataMap))
{}

////////////////////////////////////////////////////////////////////////////////
bool EncryptionKey::isSame(EncryptionKey* const keyPtr) const
{
   if (keyPtr == nullptr)
      return false;

   if (id_ != keyPtr->id_)
      return false;

   if (cipherDataMap_.size() != keyPtr->cipherDataMap_.size())
      return false;

   for (auto& cipherData : cipherDataMap_)
   {
      auto cdIter = keyPtr->cipherDataMap_.find(cipherData.first);
      if (cdIter == keyPtr->cipherDataMap_.end())
         return false;

      if (!cipherData.second->isSame(cdIter->second.get()))
         return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
Cipher* EncryptionKey::getCipherPtrForId(const EncryptionKeyId& id) const
{
   auto iter = cipherDataMap_.find(id);
   if (iter == cipherDataMap_.end())
      return nullptr;

   return iter->second->cipher_.get();
}

////////////////////////////////////////////////////////////////////////////////
bool EncryptionKey::removeCipherData(const EncryptionKeyId& id)
{
   return cipherDataMap_.erase(id) == 1;
}

////////////////////////////////////////////////////////////////////////////////
bool EncryptionKey::addCipherData(std::unique_ptr<CipherData> dataPtr)
{
   auto insertIter = cipherDataMap_.insert(make_pair(
      dataPtr->cipher_->getEncryptionKeyId(), move(dataPtr)));

   return insertIter.second;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData EncryptionKey::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(ENCRYPTION_KEY_VERSION);
   bw.put_uint8_t(ENCRYPTIONKEY_BYTE);
   id_.serializeValue(bw);

   bw.put_var_int(cipherDataMap_.size());

   for (auto& dataPair : cipherDataMap_)
   {
      auto&& cipherData = dataPair.second->serialize();
      bw.put_var_int(cipherData.getSize());
      bw.put_BinaryData(cipherData);
   }

   BinaryWriter finalBw;
   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryDataRef(bw.getDataRef());
   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<EncryptionKey> EncryptionKey::deserialize(const BinaryDataRef& data)
{
   BinaryRefReader brr(DBUtils::getDataRefForPacket(data));
   unique_ptr<EncryptionKey> keyPtr;

   //version
   auto version = brr.get_uint32_t();

   //prefix
   auto prefix = brr.get_uint8_t();

   switch (prefix)
   {
   case ENCRYPTIONKEY_BYTE:
   {
      switch (version)
      {
      case 0x00000001:
      {
         //id
         auto id = EncryptionKeyId::deserializeValue(brr);

         //cipher data
         map<EncryptionKeyId, unique_ptr<CipherData>> cipherMap;
         auto count = brr.get_var_int();
         for (unsigned i = 0; i < count; i++)
         {
            auto len = brr.get_var_int();
            if (len > brr.getSizeRemaining())
               throw AssetException("invalid serialized encrypted data len");

            auto cipherBdr = brr.get_BinaryDataRef(len);
            BinaryRefReader cipherBrr(cipherBdr);

            auto cipherData = CipherData::deserialize(cipherBrr);
            cipherMap.insert(make_pair(
               cipherData->cipher_->getEncryptionKeyId(), std::move(cipherData)));
         }

         //ptr
         keyPtr = make_unique<EncryptionKey>(id, move(cipherMap));
         break;
      }

      default:
         throw AssetException("unsupported encryption key version");
      }

      break;
   }

   default:
      throw AssetException("unexpected encrypted key prefix");
   }

   if (keyPtr == nullptr)
      throw AssetException("failed to deserialize encrypted asset");

   return keyPtr;
}

////////////////////////////////////////////////////////////////////////////////
//
//// Asset
//
////////////////////////////////////////////////////////////////////////////////
Asset::~Asset()
{}

////////////////////////////////////////////////////////////////////////////////
BinaryData Asset_PublicKey::serialize() const
{
   BinaryWriter bw;

   if (uncompressed_.getSize() == 65)
   {
      bw.put_var_int(uncompressed_.getSize() + 5);
      bw.put_uint32_t(PUBKEY_UNCOMPRESSED_VERSION);
      bw.put_uint8_t(PUBKEY_UNCOMPRESSED_BYTE);
      bw.put_BinaryData(uncompressed_);
   }

   if (compressed_.getSize() == 33)
   {
      bw.put_var_int(compressed_.getSize() + 5);
      bw.put_uint32_t(PUBKEY_COMPRESSED_VERSION);
      bw.put_uint8_t(PUBKEY_COMPRESSED_BYTE);
      bw.put_BinaryData(compressed_);
   }

   if (bw.getSize() == 0)
      throw AssetException("empty pubkey");

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Asset_PrivateKey::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(PRIVKEY_VERSION);
   bw.put_uint8_t(PRIVKEY_BYTE);
   id_.serializeValue(bw);

   auto&& cipherData = getCipherDataPtr()->serialize();
   bw.put_var_int(cipherData.getSize());
   bw.put_BinaryData(cipherData);

   BinaryWriter finalBw;
   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryDataRef(bw.getDataRef());
   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
//
//// EncryptedAssetData
//
////////////////////////////////////////////////////////////////////////////////
EncryptedAssetData::~EncryptedAssetData()
{}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<ClearTextAssetData> EncryptedAssetData::decrypt(
   const SecureBinaryData& key) const
{
   auto cipherDataPtr = getCipherDataPtr();
   auto&& decryptedData = cipherDataPtr->cipher_->decrypt(
      key, cipherDataPtr->cipherText_);
   auto decrPtr = make_unique<ClearTextAssetData>(getAssetId(), decryptedData);
   return decrPtr;
}

bool EncryptedAssetData::isSame(EncryptedAssetData* const asset) const
{
   if (asset == nullptr)
      return false;

   return cipherData_->isSame(asset->cipherData_.get());
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<EncryptedAssetData> EncryptedAssetData::deserializeOld(
   const Armory::Wallets::AssetId& id, const BinaryDataRef& data)
{
   BinaryRefReader brr(data);

   //return ptr
   unique_ptr<EncryptedAssetData> assetPtr = nullptr;

   //version
   auto version = brr.get_uint32_t();

   //prefix
   auto prefix = brr.get_uint8_t();

   switch (prefix)
   {
   case PRIVKEY_BYTE:
   {
      switch(version)
      {
      case 0x00000001:
      {
         //id
         auto len = brr.get_var_int();
         auto onDiskId = brr.get_BinaryData(len);

         if (onDiskId.getSize() != 4)
         {
            throw AssetException("[EncryptedAssetData::deserialize]"
               " invalid id size");
         }

         BinaryRefReader keyRefReader(onDiskId);
         AssetKeyType assetKey = keyRefReader.get_int32_t();
         if (id.getAssetKey() != assetKey)
         {
            throw AssetException("[EncryptedAssetData::deserialize]"
               " privkey id mismatch");
         }

         //cipher data
         len = brr.get_var_int();
         if (len > brr.getSizeRemaining())
         {
            throw AssetException("[EncryptedAssetData::deserialize]"
               " invalid serialized encrypted data len");
         }

         auto cipherBdr = brr.get_BinaryDataRef(len);
         BinaryRefReader cipherBrr(cipherBdr);
         auto cipherData = CipherData::deserialize(cipherBrr);

         //ptr
         assetPtr = make_unique<Asset_PrivateKey>(id, move(cipherData));

         break;
      }

      default:
         throw AssetException("[EncryptedAssetData::deserialize]"
            "unsupported privkey version");
      }

      break;
   }

   default:
      throw AssetException("unexpected encrypted data prefix");
   }

   if (assetPtr == nullptr)
   {
      throw AssetException("[EncryptedAssetData::deserialize]"
         " failed to deserialize encrypted asset");
   }

   return assetPtr;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<EncryptedAssetData> EncryptedAssetData::deserialize(
   const BinaryDataRef& data)
{
   BinaryRefReader brr(data);

   //return ptr
   unique_ptr<EncryptedAssetData> assetPtr = nullptr;

   //version
   auto version = brr.get_uint32_t();

   //prefix
   auto prefix = brr.get_uint8_t();

   switch (prefix)
   {
   case PRIVKEY_BYTE:
   {
      switch(version)
      {
      case 0x00000001:
      {
         //id
         auto assetId = AssetId::deserializeValue(brr);

         //cipher data
         auto len = brr.get_var_int();
         if (len > brr.getSizeRemaining())
            throw AssetException("invalid serialized encrypted data len");

         auto cipherBdr = brr.get_BinaryDataRef(len);
         BinaryRefReader cipherBrr(cipherBdr);
         auto cipherData = CipherData::deserialize(cipherBrr);

         //ptr
         assetPtr = make_unique<Asset_PrivateKey>(assetId, move(cipherData));

         break;
      }

      default:
         throw AssetException("unsupported privkey version");
      }

      break;
   }

   case WALLET_SEED_BYTE:
   {
      switch (version)
      {
      case 0x00000001:
      {
         auto len = brr.get_var_int();
         if (len > brr.getSizeRemaining())
            throw AssetException("invalid serialized encrypted data len");

         auto cipherBdr = brr.get_BinaryDataRef(len);
         BinaryRefReader cipherBrr(cipherBdr);
         auto cipherData = CipherData::deserialize(cipherBrr);

         //ptr
         assetPtr = make_unique<EncryptedSeed>(move(cipherData));
         break;
      }

      default:
         throw AssetException("unsupported seed version");
      }

      break;
   }

   default:
      throw AssetException("unexpected encrypted data prefix");
   }

   if (assetPtr == nullptr)
      throw AssetException("failed to deserialize encrypted asset");

   return assetPtr;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& EncryptedAssetData::getCipherText() const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipherText_;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& EncryptedAssetData::getIV() const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getIV();
}

////////////////////////////////////////////////////////////////////////////////
const EncryptionKeyId& EncryptedAssetData::getEncryptionKeyId() const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getEncryptionKeyId();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& EncryptedAssetData::getKdfId() const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getKdfId();
}

////////////////////////////////////////////////////////////////////////////////
//
//// Asset_PrivateKey
//
////////////////////////////////////////////////////////////////////////////////
bool Asset_PrivateKey::isSame(EncryptedAssetData* const asset) const
{
   auto asset_ed = dynamic_cast<Asset_PrivateKey*>(asset);
   if (asset_ed == nullptr)
      return false;

   if (id_ != asset_ed->id_)
      return false;

   return EncryptedAssetData::isSame(asset);
}

////////////////////////////////////////////////////////////////////////////////
const AssetId& Asset_PrivateKey::getAssetId() const
{
   return id_;
}

////////////////////////////////////////////////////////////////////////////////
//
//// EncryptedSeed
//
////////////////////////////////////////////////////////////////////////////////
const AssetId EncryptedSeed::seedAssetId_(0x5EED, 0xDEE5, 0x5EED);

////////////////////////////////////////////////////////////////////////////////
BinaryData EncryptedSeed::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(ENCRYPTED_SEED_VERSION);
   bw.put_uint8_t(WALLET_SEED_BYTE);

   auto&& cipherData = getCipherDataPtr()->serialize();
   bw.put_var_int(cipherData.getSize());
   bw.put_BinaryData(cipherData);

   BinaryWriter finalBw;
   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryDataRef(bw.getDataRef());
   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool EncryptedSeed::isSame(EncryptedAssetData* const seed) const
{
   auto asset_ed = dynamic_cast<EncryptedSeed*>(seed);
   if (asset_ed == nullptr)
      return false;

   return EncryptedAssetData::isSame(seed);
}

////////////////////////////////////////////////////////////////////////////////
const AssetId& EncryptedSeed::getAssetId() const
{
   return seedAssetId_;
}

////////////////////////////////////////////////////////////////////////////////
//
//// MetaData
//
////////////////////////////////////////////////////////////////////////////////
MetaData::~MetaData()
{}

shared_ptr<MetaData> MetaData::deserialize(
   const BinaryDataRef& key, const BinaryDataRef& data)
{
   if (key.getSize() != 9)
      throw AssetException("invalid metadata key size");

   //deser key
   BinaryRefReader brrKey(key);
   auto keyPrefix = brrKey.get_uint8_t();
   auto&& accountID = brrKey.get_BinaryData(4);
   auto index = brrKey.get_uint32_t(BE);

   //construct object and deser data
   shared_ptr<MetaData> resultPtr;
   switch (keyPrefix)
   {
   case METADATA_COMMENTS_PREFIX:
   {
      resultPtr = make_shared<CommentData>(accountID, index);
      resultPtr->deserializeDBValue(data);
      break;
   }

   case METADATA_AUTHPEER_PREFIX:
   {
      resultPtr = make_shared<PeerPublicData>(accountID, index);
      resultPtr->deserializeDBValue(data);
      break;
   }

   case METADATA_PEERROOT_PREFIX:
   {
      resultPtr = make_shared<PeerRootKey>(accountID, index);
      resultPtr->deserializeDBValue(data);
      break;
   }

   case METADATA_ROOTSIG_PREFIX:
   {
      resultPtr = make_shared<PeerRootSignature>(accountID, index);
      resultPtr->deserializeDBValue(data);
      break;
   }

   default:
      throw AssetException("unexpected metadata prefix");
   }

   return resultPtr;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// PeerPublicData
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BinaryData PeerPublicData::getDbKey() const
{
   if (accountID_.getSize() != 4)
      throw AssetException("invalid accountID");

   BinaryWriter bw;
   bw.put_uint8_t(METADATA_AUTHPEER_PREFIX);
   bw.put_BinaryData(accountID_);
   bw.put_uint32_t(index_, BE);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData PeerPublicData::serialize() const
{
   //returning an empty serialized string will cause the key to be deleted
   if (names_.size() == 0)
      return BinaryData();

   BinaryWriter bw;

   bw.put_uint32_t(PEER_PUBLICDATA_VERSION);
   bw.put_var_int(publicKey_.getSize());
   bw.put_BinaryData(publicKey_);

   bw.put_var_int(names_.size());
   for (auto& name : names_)
   {
      bw.put_var_int(name.size());

      BinaryDataRef bdrName;
      bdrName.setRef(name);
      bw.put_BinaryDataRef(bdrName);
   }

   BinaryWriter bwWithSize;
   bwWithSize.put_var_int(bw.getSize());
   bwWithSize.put_BinaryDataRef(bw.getDataRef());

   return bwWithSize.getData();
}

////////////////////////////////////////////////////////////////////////////////
void PeerPublicData::deserializeDBValue(const BinaryDataRef& data)
{
   BinaryRefReader brrData(data);

   auto len = brrData.get_var_int();
   if (len != brrData.getSizeRemaining())
      throw AssetException("size mismatch in metadata entry");

   auto version = brrData.get_uint32_t();

   switch (version)
   {
   case 0x00000001:
   {
      auto keyLen = brrData.get_var_int();
      publicKey_ = brrData.get_BinaryData(keyLen);
      
      //check pubkey is valid
      if(!CryptoECDSA().VerifyPublicKeyValid(publicKey_))
         throw AssetException("invalid pubkey in peer metadata");

      auto count = brrData.get_var_int();
      for (unsigned i = 0; i < count; i++)
      {
         auto nameLen = brrData.get_var_int();
         auto bdrName = brrData.get_BinaryDataRef(nameLen);

         string name((char*)bdrName.getPtr(), nameLen);
         names_.emplace(name);
      }

      break;
   }

   default:
      throw AssetException("unsupported peer data version");
   }
}

////////////////////////////////////////////////////////////////////////////////
void PeerPublicData::setPublicKey(const SecureBinaryData& key)
{
   publicKey_ = key;
   flagForCommit();
}

////////////////////////////////////////////////////////////////////////////////
void PeerPublicData::addName(const string& name)
{
   names_.insert(name);
   flagForCommit();
}

////////////////////////////////////////////////////////////////////////////////
bool PeerPublicData::eraseName(const string& name)
{
   auto iter = names_.find(name);
   if (iter == names_.end())
      return false;

   names_.erase(iter);
   flagForCommit();
   return true;
}

////////////////////////////////////////////////////////////////////////////////
void PeerPublicData::clear()
{
   names_.clear();
   flagForCommit();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaData> PeerPublicData::copy() const
{
   auto copyPtr = make_shared<PeerPublicData>(getAccountID(), getIndex());
   copyPtr->names_ = names_;
   copyPtr->publicKey_ = publicKey_;

   return copyPtr;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// PeerRootKey
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BinaryData PeerRootKey::getDbKey() const
{
   if (accountID_.getSize() != 4)
      throw AssetException("invalid accountID");

   BinaryWriter bw;
   bw.put_uint8_t(METADATA_PEERROOT_PREFIX);
   bw.put_BinaryData(accountID_);
   bw.put_uint32_t(index_, BE);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData PeerRootKey::serialize() const
{
   //returning an empty serialized string will cause the key to be deleted
   if (publicKey_.getSize() == 0)
      return BinaryData();

   BinaryWriter bw;
   bw.put_uint32_t(PEER_ROOTKEY_VERSION);
   bw.put_var_int(publicKey_.getSize());
   bw.put_BinaryData(publicKey_);

   bw.put_var_int(description_.size());
   if (description_.size() > 0)
   {
      BinaryDataRef descBdr;
      descBdr.setRef(description_);
      bw.put_BinaryDataRef(descBdr);
   }

   BinaryWriter bwWithSize;
   bwWithSize.put_var_int(bw.getSize());
   bwWithSize.put_BinaryDataRef(bw.getDataRef());

   return bwWithSize.getData();
}

////////////////////////////////////////////////////////////////////////////////
void PeerRootKey::deserializeDBValue(const BinaryDataRef& data)
{
   BinaryRefReader brrData(data);
   auto len = brrData.get_var_int();
   if (len != brrData.getSizeRemaining())
      throw AssetException("size mismatch in metadata entry");

   auto version = brrData.get_uint32_t();

   switch (version)
   {
   case 0x00000001:
   {
      auto keyLen = brrData.get_var_int();
      publicKey_ = brrData.get_BinaryData(keyLen);

      //check pubkey is valid
      if (!CryptoECDSA().VerifyPublicKeyValid(publicKey_))
         throw AssetException("invalid pubkey in peer metadata");

      auto descLen = brrData.get_var_int();
      if (descLen == 0)
         return;

      auto descBdr = brrData.get_BinaryDataRef(descLen);
      description_ = string(descBdr.toCharPtr(), descBdr.getSize());

      break;
   }

   default:
      throw AssetException("unsupported peer rootkey version");
   }
}

////////////////////////////////////////////////////////////////////////////////
void PeerRootKey::clear()
{
   publicKey_.clear();
   description_.clear();
   flagForCommit();
}

////////////////////////////////////////////////////////////////////////////////
void PeerRootKey::set(const string& desc, const SecureBinaryData& key)
{
   if (publicKey_.getSize() != 0)
      throw AssetException("peer root key already set");

   if (!CryptoECDSA().VerifyPublicKeyValid(key))
      throw AssetException("invalid pubkey for peer root");

   publicKey_ = key;
   description_ = desc;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaData> PeerRootKey::copy() const
{
   auto copyPtr = make_shared<PeerRootKey>(getAccountID(), getIndex());
   copyPtr->publicKey_ = publicKey_;
   copyPtr->description_ = description_;

   return copyPtr;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// PeerRootSignature
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BinaryData PeerRootSignature::getDbKey() const
{
   if (accountID_.getSize() != 4)
      throw AssetException("invalid accountID");

   BinaryWriter bw;
   bw.put_uint8_t(METADATA_ROOTSIG_PREFIX);
   bw.put_BinaryData(accountID_);
   bw.put_uint32_t(index_, BE);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData PeerRootSignature::serialize() const
{
   //returning an empty serialized string will cause the key to be deleted
   if (publicKey_.getSize() == 0)
      return BinaryData();

   BinaryWriter bw;
   bw.put_uint32_t(PEER_ROOTSIG_VERSION);
   bw.put_var_int(publicKey_.getSize());
   bw.put_BinaryData(publicKey_);

   bw.put_var_int(signature_.getSize());
   bw.put_BinaryData(signature_);

   BinaryWriter bwWithSize;
   bwWithSize.put_var_int(bw.getSize());
   bwWithSize.put_BinaryDataRef(bw.getDataRef());

   return bwWithSize.getData();
}

////////////////////////////////////////////////////////////////////////////////
void PeerRootSignature::deserializeDBValue(const BinaryDataRef& data)
{
   BinaryRefReader brrData(data);
   auto len = brrData.get_var_int();
   if (len != brrData.getSizeRemaining())
      throw AssetException("size mismatch in metadata entry");

   auto version = brrData.get_uint32_t();

   switch (version)
   {
   case 0x00000001:
   {
      auto keyLen = brrData.get_var_int();
      publicKey_ = brrData.get_BinaryData(keyLen);

      //check pubkey is valid
      if (!CryptoECDSA().VerifyPublicKeyValid(publicKey_))
         throw AssetException("invalid pubkey in peer metadata");

      len = brrData.get_var_int();
      signature_ = brrData.get_BinaryDataRef(len);

      break;
   }

   default:
      throw AssetException("unsupported peer rootsig version");
   }

   //cannot check sig is valid until full peer account is loaded
}

////////////////////////////////////////////////////////////////////////////////
void PeerRootSignature::clear()
{
   publicKey_.clear();
   signature_.clear();
   flagForCommit();
}

////////////////////////////////////////////////////////////////////////////////
void PeerRootSignature::set(
   const SecureBinaryData& key, const SecureBinaryData& sig)
{
   if (publicKey_.getSize() != 0)
      throw AssetException("peer root key already set");

   //check pubkey and sig prior to calling this

   publicKey_ = key;
   signature_ = sig;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaData> PeerRootSignature::copy() const
{
   auto copyPtr = make_shared<PeerRootSignature>(getAccountID(), getIndex());
   copyPtr->publicKey_ = publicKey_;
   copyPtr->signature_ = signature_;

   return copyPtr;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// CommentData
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BinaryData CommentData::getDbKey() const
{
   if (accountID_.getSize() != 4)
      throw AssetException("invalid accountID");

   BinaryWriter bw;
   bw.put_uint8_t(METADATA_COMMENTS_PREFIX);
   bw.put_BinaryData(accountID_);
   bw.put_uint32_t(index_, BE);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData CommentData::serialize() const
{
   //returning an empty serialized string will cause the key to be deleted
   if (commentStr_.size() == 0)
      return BinaryData();

   BinaryWriter bw;
   bw.put_uint32_t(COMMENT_DATA_VERSION);
   bw.put_var_int(key_.getSize());
   bw.put_BinaryData(key_);

   bw.put_var_int(commentStr_.size());
   bw.put_String(commentStr_);

   BinaryWriter bwWithSize;
   bwWithSize.put_var_int(bw.getSize());
   bwWithSize.put_BinaryDataRef(bw.getDataRef());

   return bwWithSize.getData();
}

////////////////////////////////////////////////////////////////////////////////
void CommentData::deserializeDBValue(const BinaryDataRef& data)
{
   BinaryRefReader brrData(data);
   auto len = brrData.get_var_int();
   if (len != brrData.getSizeRemaining())
      throw AssetException("size mismatch in metadata entry");

   auto version = brrData.get_uint32_t();

   switch (version)
   {
   case 0x00000001:
   {
      len = brrData.get_var_int();
      key_ = brrData.get_BinaryData(len);

      len = brrData.get_var_int();
      commentStr_ = brrData.get_String(len);

      break;
   }

   default:
      throw AssetException("unsupported comment version");
   }
}

////////////////////////////////////////////////////////////////////////////////
void CommentData::clear()
{
   commentStr_.clear();
   flagForCommit();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaData> CommentData::copy() const
{
   auto copyPtr = make_shared<CommentData>(getAccountID(), getIndex());
   copyPtr->commentStr_ = commentStr_;
   copyPtr->key_ = key_;

   return copyPtr;
}