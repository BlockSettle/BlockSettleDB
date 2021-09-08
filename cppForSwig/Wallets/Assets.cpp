////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2019, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Assets.h"
#include "BtcUtils.h"
#include "ScriptRecipient.h"
#include "make_unique.h"
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

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DecryptedData
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void DecryptedEncryptionKey::deriveKey(
   shared_ptr<KeyDerivationFunction> kdf)
{
   if (derivedKeys_.find(kdf->getId()) != derivedKeys_.end())
      return;

   auto&& derivedkey = kdf->deriveKey(rawKey_);
   auto&& keypair = make_pair(kdf->getId(), move(derivedkey));
   derivedKeys_.insert(move(keypair));
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<DecryptedEncryptionKey>
DecryptedEncryptionKey::copy() const
{
   auto key_copy = rawKey_;
   auto copy_ptr = make_unique<DecryptedEncryptionKey>(key_copy);

   copy_ptr->derivedKeys_ = derivedKeys_;

   return move(copy_ptr);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData DecryptedEncryptionKey::getId(
   const BinaryData& kdfId) const
{
   const auto keyIter = derivedKeys_.find(kdfId);
   if (keyIter == derivedKeys_.end())
      throw runtime_error("couldn't find derivation for kdfid");

   return move(computeId(keyIter->second));
}

////////////////////////////////////////////////////////////////////////////////
BinaryData DecryptedEncryptionKey::computeId(
   const SecureBinaryData& key) const
{
   //treat value as scalar, get pubkey for it
   auto&& hashedKey = BtcUtils::hash256(key);
   auto&& pubkey = CryptoECDSA().ComputePublicKey(hashedKey);

   //HMAC the pubkey, get last 16 bytes as ID
   return BtcUtils::computeDataId(pubkey, HMAC_KEY_ENCRYPTIONKEYS);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& DecryptedEncryptionKey::getDerivedKey(
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
BinaryData AssetEntry::getDbKey() const
{
   BinaryWriter bw;
   bw.put_uint8_t(ASSETENTRY_PREFIX);
   bw.put_BinaryData(ID_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetEntry::deserialize(
   BinaryDataRef key, BinaryDataRef value)
{
   //sanity check
   if (key.getSize() < 5)
      throw AssetException("invalid AssetEntry db key");

   BinaryRefReader brrKey(key);

   auto prefix = brrKey.get_uint8_t();
   if (prefix != ASSETENTRY_PREFIX)
      throw AssetException("unexpected asset entry prefix");

   auto accountID = brrKey.get_BinaryData(brrKey.getSizeRemaining() - 4);
   auto index = brrKey.get_int32_t(BE);

   if (brrKey.getSizeRemaining() != 0)
      throw AssetException("invalid AssetEntry db key");

   auto assetPtr = deserDBValue(index, accountID, value);
   assetPtr->doNotCommit();
   return assetPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetEntry::deserDBValue(
   int index, const BinaryData& account_id,
   BinaryDataRef value)
{
   BinaryRefReader brrVal(value);

   auto version = brrVal.get_uint32_t();
   auto val = brrVal.get_uint8_t();
   auto entryType = AssetEntryType(val & 0x0F);

   auto getKeyData = [](BinaryRefReader& brr,
      shared_ptr<Asset_PrivateKey>& privKeyPtr,
      SecureBinaryData& pubKeyCompressed,
      SecureBinaryData& pubKeyUncompressed
   )->void
   {
      vector<pair<size_t, BinaryDataRef>> dataVec;

      while (brr.getSizeRemaining() > 0)
      {
         auto len = brr.get_var_int();
         auto valref = brr.get_BinaryDataRef(len);

         dataVec.push_back(make_pair(len, valref));
      }

      for (auto& datapair : dataVec)
      {
         BinaryRefReader brrData(datapair.second);
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
               if (datapair.first != 70)
                  throw AssetException("invalid size for uncompressed pub key");

               if (pubKeyUncompressed.getSize() != 0)
                  throw AssetException("multiple pub keys for entry");

               pubKeyUncompressed = move(SecureBinaryData(
                  brrData.get_BinaryDataRef(
                     brrData.getSizeRemaining())));

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
               if (datapair.first != 38)
                  throw AssetException("invalid size for compressed pub key");

               if (pubKeyCompressed.getSize() != 0)
                  throw AssetException("multiple pub keys for entry");

               pubKeyCompressed = move(SecureBinaryData(
                  brrData.get_BinaryDataRef(
                     brrData.getSizeRemaining())));

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

               auto keyUPtr = Asset_EncryptedData::deserialize(
                  datapair.first, datapair.second);
               shared_ptr<Asset_EncryptedData> keySPtr(move(keyUPtr));

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
            index, account_id,
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
            index, account_id,
            pubKeyCompressed, privKeyPtr,
            chaincode, depth, leafid, fingerprint, seedFingerprint,
            derPath);
         }
         else
         {
            rootEntry = make_shared<AssetEntry_BIP32Root>(
            index, account_id,
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
            index, account_id,
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
const BinaryData& AssetEntry_Single::getPrivateEncryptionKeyId() const
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
const BinaryData& AssetEntry_Multisig::getPrivateEncryptionKeyId(void) const
{
   if (assetMap_.size() != n_)
      throw runtime_error("missing asset entries");

   if (!hasPrivateKey())
      throw runtime_error("no private key in this asset");

   set<BinaryDataRef> idSet;

   for (auto& asset_pair : assetMap_)
   {
      auto asset_single =
         dynamic_pointer_cast<AssetEntry_Single>(asset_pair.second);
      if (asset_single == nullptr)
         throw runtime_error("unexpected asset entry type");

      idSet.insert(asset_pair.second->getPrivateEncryptionKeyId().getRef());
   }

   if (idSet.size() != 1)
      throw runtime_error("wallets use different encryption keys");

   return assetMap_.begin()->second->getPrivateEncryptionKeyId();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry_Single> AssetEntry_Single::getPublicCopy()
{
   auto woCopy = make_shared<AssetEntry_Single>(
      index_, getAccountID(), pubkey_, nullptr);

   return woCopy;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetEntry_BIP32Root
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetEntry_BIP32Root::AssetEntry_BIP32Root(int id, const BinaryData& accountID,
   SecureBinaryData& pubkey, shared_ptr<Asset_PrivateKey> privkey,
   const SecureBinaryData& chaincode,
   uint8_t depth, unsigned leafID, 
   unsigned fingerPrint, unsigned seedFingerprint,
   const vector<uint32_t>& derPath) :
   AssetEntry_Single(id, accountID, pubkey, privkey),
   chaincode_(chaincode),
   depth_(depth), leafID_(leafID), 
   parentFingerprint_(fingerPrint), seedFingerprint_(seedFingerprint),
   derivationPath_(derPath)
{
   checkSeedFingerprint(false);
}

////////////////////////////////////////////////////////////////////////////////
AssetEntry_BIP32Root::AssetEntry_BIP32Root(int id, const BinaryData& accountID,
   shared_ptr<Asset_PublicKey> pubkey, shared_ptr<Asset_PrivateKey> privkey,
   const SecureBinaryData& chaincode,
   uint8_t depth, unsigned leafID, 
   unsigned fingerPrint, unsigned seedFingerprint,
   const vector<uint32_t>& derPath) :
   AssetEntry_Single(id, accountID, pubkey, privkey),
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
      index_, getAccountID(), pubkey, nullptr,
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
//// Asset
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
////////////////////////////////////////////////////////////////////////////////
//// Asset
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
Asset::~Asset()
{}

Asset_EncryptedData::~Asset_EncryptedData()
{}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<DecryptedData> Asset_EncryptedData::decrypt(
   const SecureBinaryData& key) const
{
   auto cipherDataPtr = getCipherDataPtr();
   auto&& decryptedData = cipherDataPtr->cipher_->decrypt(
      key, cipherDataPtr->cipherText_);
   auto decrPtr = make_unique<DecryptedData>(getId(), decryptedData);
   return move(decrPtr);
}

bool Asset_EncryptedData::isSame(Asset_EncryptedData* const asset) const
{
   if (asset == nullptr || 
      cipherData_.size() != asset->cipherData_.size())
      return false;

   for (auto& dataPair : cipherData_)
   {
      auto iter = asset->cipherData_.find(dataPair.first);
      if (iter == asset->cipherData_.end())
         return false;

      if (!dataPair.second->isSame(iter->second.get()))
         return false;
   }

   return true;
}

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
   bw.put_var_int(id_.getSize());
   bw.put_BinaryData(id_);

   if (cipherData_.size() != 1)
      throw AssetException("invalid cipherData size");

   auto&& cipherData = getCipherDataPtr()->serialize();
   bw.put_var_int(cipherData.getSize());
   bw.put_BinaryData(cipherData);

   BinaryWriter finalBw;
   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryDataRef(bw.getDataRef());
   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Asset_EncryptionKey::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(ENCRYPTION_KEY_VERSION);
   bw.put_uint8_t(ENCRYPTIONKEY_BYTE);
   bw.put_var_int(id_.getSize());
   bw.put_BinaryData(id_);

   bw.put_var_int(cipherData_.size());

   for (auto& dataPair : cipherData_)
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
bool Asset_PrivateKey::isSame(Asset_EncryptedData* const asset) const
{
   auto asset_ed = dynamic_cast<Asset_PrivateKey*>(asset);
   if (asset_ed == nullptr)
      return false;

   if (id_ != asset_ed->id_)
      return false;

   return Asset_EncryptedData::isSame(asset);
}

////////////////////////////////////////////////////////////////////////////////
bool Asset_EncryptionKey::isSame(Asset_EncryptedData* const asset) const
{
   auto asset_ed = dynamic_cast<Asset_EncryptionKey*>(asset);
   if (asset_ed == nullptr)
      return false;

   if (id_ != asset_ed->id_)
      return false;

   return Asset_EncryptedData::isSame(asset);
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Asset_EncryptedData> Asset_EncryptedData::deserialize(
   const BinaryDataRef& data)
{
   BinaryRefReader brr(data);

   //grab size
   auto totalLen = brr.get_var_int();
   return deserialize(totalLen, brr.get_BinaryDataRef(brr.getSizeRemaining()));
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Asset_EncryptedData> Asset_EncryptedData::deserialize(
   size_t totalLen, const BinaryDataRef& data)
{
   BinaryRefReader brr(data);

   //check size
   if (totalLen != brr.getSizeRemaining())
      throw AssetException("invalid serialized encrypted data len");

   //return ptr
   unique_ptr<Asset_EncryptedData> assetPtr = nullptr;

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
         auto&& id = brr.get_BinaryData(len);

         //cipher data
         len = brr.get_var_int();
         if (len > brr.getSizeRemaining())
            throw AssetException("invalid serialized encrypted data len");

         auto cipherBdr = brr.get_BinaryDataRef(len);
         BinaryRefReader cipherBrr(cipherBdr);
         auto cipherData = CipherData::deserialize(cipherBrr);

         //ptr
         assetPtr = make_unique<Asset_PrivateKey>(id, move(cipherData));

         break;
      }

      default: 
         throw AssetException("unsupported privkey version");
      }

      break;
   }

   case ENCRYPTIONKEY_BYTE:
   {
      switch (version)
      {
      case 0x00000001:
      {
         //id
         auto len = brr.get_var_int();
         auto&& id = brr.get_BinaryData(len);

         //cipher data
         map<BinaryData, unique_ptr<CipherData>> cipherMap;
         auto count = brr.get_var_int();
         for (unsigned i = 0; i < count; i++)
         {
            len = brr.get_var_int();
            if (len > brr.getSizeRemaining())
               throw AssetException("invalid serialized encrypted data len");

            auto cipherBdr = brr.get_BinaryDataRef(len);
            BinaryRefReader cipherBrr(cipherBdr);

            auto cipherData = CipherData::deserialize(cipherBrr);
            cipherMap.insert(make_pair(
               cipherData->cipher_->getEncryptionKeyId(), std::move(cipherData)));
         }

         //ptr
         assetPtr = make_unique<Asset_EncryptionKey>(id, move(cipherMap));
         break;
      }

      default:
         throw AssetException("unsupported encryption key version");
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

   return move(assetPtr);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData EncryptedSeed::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(ENCRYPTED_SEED_VERSION);
   bw.put_uint8_t(WALLET_SEED_BYTE);

   if (cipherData_.size() != 1)
      throw AssetException("invalid cipherData size");

   auto&& cipherData = getCipherDataPtr()->serialize();
   bw.put_var_int(cipherData.getSize());
   bw.put_BinaryData(cipherData);

   BinaryWriter finalBw;
   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryDataRef(bw.getDataRef());
   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool EncryptedSeed::isSame(Asset_EncryptedData* const seed) const
{
   auto asset_ed = dynamic_cast<EncryptedSeed*>(seed);
   if (asset_ed == nullptr)
      return false;

   return Asset_EncryptedData::isSame(seed);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& Asset_EncryptionKey::getCipherText(void) const
{
   throw AssetException("illegal for encryption keys");
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& Asset_EncryptionKey::getIV(void) const
{
   throw AssetException("illegal for encryption keys");
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& Asset_EncryptionKey::getEncryptionKeyId(void) const
{
   throw AssetException("illegal for encryption keys");
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& Asset_EncryptionKey::getKdfId(void) const
{
   throw AssetException("illegal for encryption keys");
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<DecryptedData> Asset_EncryptionKey::decrypt(
   const SecureBinaryData&) const
{
   throw std::runtime_error("illegal for encryption keys");
}

////////////////////////////////////////////////////////////////////////////////
CipherData* Asset_EncryptionKey::getCipherDataPtr(void) const
{
   throw std::runtime_error("illegal for encryption keys");
}

////////////////////////////////////////////////////////////////////////////////
Cipher* Asset_EncryptionKey::getCipherPtrForId(const BinaryData& id) const
{
   auto iter = cipherData_.find(id);
   if (iter == cipherData_.end())
      return nullptr;

   return iter->second->cipher_.get();
}

////////////////////////////////////////////////////////////////////////////////
bool Asset_EncryptionKey::removeCipherData(const BinaryData& id)
{
   return cipherData_.erase(id) == 1;
}

////////////////////////////////////////////////////////////////////////////////
bool Asset_EncryptionKey::addCipherData(std::unique_ptr<CipherData> dataPtr)
{
   auto insertIter = cipherData_.insert(make_pair(
      dataPtr->cipher_->getEncryptionKeyId(), move(dataPtr)));

   return insertIter.second;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& Asset_PrivateKey::getCipherText(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipherText_;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& Asset_PrivateKey::getIV(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getIV();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& Asset_PrivateKey::getEncryptionKeyId(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getEncryptionKeyId();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& Asset_PrivateKey::getKdfId(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getKdfId();
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& EncryptedSeed::getCipherText(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipherText_;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& EncryptedSeed::getIV(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getIV();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& EncryptedSeed::getEncryptionKeyId(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getEncryptionKeyId();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& EncryptedSeed::getKdfId(void) const
{
   auto ptr = getCipherDataPtr();
   return ptr->cipher_->getKdfId();
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// MetaData
////////////////////////////////////////////////////////////////////////////////
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