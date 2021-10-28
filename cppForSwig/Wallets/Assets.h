////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2019, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_ASSETS
#define _H_ASSETS

#include <vector>
#include <set>
#include <string>
#include <memory>

#include "make_unique.h"
#include "BinaryData.h"
#include "EncryptionUtils.h"
#include "WalletIdTypes.h"
#include "AssetEncryption.h"

class AssetException : public std::runtime_error
{
public:
   AssetException(const std::string& err) : std::runtime_error(err)
   {}
};

#define HMAC_KEY_ENCRYPTIONKEYS "EncyrptionKey"
#define HMAC_KEY_PRIVATEKEYS "PrivateKey"

#define ASSETENTRY_PREFIX        0x8A
#define PUBKEY_UNCOMPRESSED_BYTE 0x80
#define PUBKEY_COMPRESSED_BYTE   0x81
#define PRIVKEY_BYTE             0x82
#define ENCRYPTIONKEY_BYTE       0x83
#define WALLET_SEED_BYTE         0x84
#define ECDH_SALT_PREFIX         0x85

#define METADATA_COMMENTS_PREFIX 0x90
#define METADATA_AUTHPEER_PREFIX 0x91
#define METADATA_PEERROOT_PREFIX 0x92
#define METADATA_ROOTSIG_PREFIX  0x93

////////////////////////////////////////////////////////////////////////////////
enum class AssetType : int
{
   EncryptedData,
   PublicKey,
   PrivateKey,
};

enum MetaType
{
   MetaType_Comment,
   MetaType_AuthorizedPeer,
   MetaType_PeerRootKey,
   MetaType_PeerRootSig
};

////
enum AssetEntryType
{
   AssetEntryType_Single = 0x01,
   AssetEntryType_Multisig,
   AssetEntryType_BIP32Root,
   AssetEntryType_ArmoryLegacyRoot
};

enum ScriptHashType
{
   ScriptHash_P2PKH_Uncompressed,
   ScriptHash_P2PKH_Compressed,
   ScriptHash_P2WPKH,
   ScriptHash_Nested_P2PK
};

////////////////////////////////////////////////////////////////////////////////
struct ClearTextEncryptionKey
{
   friend class DecryptedDataContainer;
   friend class Cipher_AES;
   friend class AssetWallet_Single;
   friend class AssetWallet;

private:
   const SecureBinaryData rawKey_;
   std::map<BinaryData, SecureBinaryData> derivedKeys_;

private:
   Armory::Wallets::EncryptionKeyId computeId(
      const SecureBinaryData& key) const;
   const SecureBinaryData& getData(void) const { return rawKey_; }
   const SecureBinaryData& getDerivedKey(const BinaryData& id) const;

public:
   ClearTextEncryptionKey(SecureBinaryData& key) :
      rawKey_(std::move(key))
   {}

   void deriveKey(std::shared_ptr<KeyDerivationFunction> kdf);
   Armory::Wallets::EncryptionKeyId getId(const BinaryData& kdfid) const;

   std::unique_ptr<ClearTextEncryptionKey> copy(void) const;
   bool hasData(void) const { return !rawKey_.empty(); }
};

////////////////////////////////////////////////////////////////////////////////
class ClearTextAssetData
{
private:
   const Armory::Wallets::AssetId id_;
   const SecureBinaryData clearText_;

public:
   ClearTextAssetData(const Armory::Wallets::AssetId& id,
      SecureBinaryData& clearText) :
      id_(id), clearText_(std::move(clearText))
   {}

   bool hasData(void) const { return !clearText_.empty(); }
   const Armory::Wallets::AssetId& getId(void) const { return id_; }
   const SecureBinaryData& getData(void) const { return clearText_; }
};

////////////////////////////////////////////////////////////////////////////////
struct Asset
{
   const AssetType type_;

   Asset(AssetType type) :
      type_(type)
   {}

   /*TODO: create a mlocked binarywriter class*/

   virtual ~Asset(void) = 0;
   virtual BinaryData serialize(void) const = 0;
};

////////////////////////////////////////////////////////////////////////////////
struct Asset_PublicKey : public Asset
{
public:
   SecureBinaryData uncompressed_;
   SecureBinaryData compressed_;

public:
   Asset_PublicKey(SecureBinaryData& pubkey) :
      Asset(AssetType::PublicKey)
   {
      switch (pubkey.getSize())
      {
      case 33:
      {
         uncompressed_ = CryptoECDSA().UncompressPoint(pubkey);
         compressed_ = std::move(pubkey);
         break;
      }

      case 65:
      {
         uncompressed_ = std::move(pubkey);
         compressed_ = CryptoECDSA().CompressPoint(pubkey);
         break;
      }

      default:
         throw AssetException("cannot compress/decompress pubkey of that size");
      }
   }

   Asset_PublicKey(SecureBinaryData& uncompressedKey,
      SecureBinaryData& compressedKey) :
      Asset(AssetType::PublicKey),
      uncompressed_(std::move(uncompressedKey)),
      compressed_(std::move(compressedKey))
   {
      if (uncompressed_.getSize() != 65 ||
         compressed_.getSize() != 33)
         throw AssetException("invalid pubkey size");
   }

   const SecureBinaryData& getUncompressedKey(void) const { return uncompressed_; }
   const SecureBinaryData& getCompressedKey(void) const { return compressed_; }

   BinaryData serialize(void) const override;
};

////////////////////////////////////////////////////////////////////////////////
struct CipherData
{
   /*
   Cipher text and its relevant cipher object
   */

   const SecureBinaryData cipherText_;
   std::unique_ptr<Cipher> cipher_;

   CipherData(SecureBinaryData& cipherText, std::unique_ptr<Cipher> cipher) :
      cipherText_(std::move(cipherText)), cipher_(std::move(cipher))
   {
      if (cipherText_.getSize() == 0)
         throw AssetException("empty cipher text");

      if (cipher_ == nullptr)
         throw AssetException("null cipher for privkey");
   }

   BinaryData serialize(void) const;
   bool isSame(CipherData* const) const;

   static std::unique_ptr<CipherData> deserialize(BinaryRefReader&);
};

////////////////////////////////////////////////////////////////////////////////
class DecryptedDataContainer;

class EncryptionKey
{
   /*
   May have multiple cipher data objects
   */

   friend class DecryptedDataContainer;

protected:
   const Armory::Wallets::EncryptionKeyId id_;
   std::map<Armory::Wallets::EncryptionKeyId,
      std::unique_ptr<CipherData>> cipherDataMap_;

private:
   Cipher* getCipherPtrForId(const Armory::Wallets::EncryptionKeyId&) const;
   bool removeCipherData(const Armory::Wallets::EncryptionKeyId&);
   bool addCipherData(std::unique_ptr<CipherData>);

public:
   EncryptionKey(Armory::Wallets::EncryptionKeyId&,
      SecureBinaryData&,
      std::unique_ptr<Cipher>);

   EncryptionKey(Armory::Wallets::EncryptionKeyId&,
      std::map<Armory::Wallets::EncryptionKeyId,
         std::unique_ptr<CipherData>>);

   ////
   bool isSame(EncryptionKey* const) const;
   const Armory::Wallets::EncryptionKeyId& getId(void) const { return id_; }
   BinaryData serialize(void) const;
   static std::unique_ptr<EncryptionKey> deserialize(const BinaryDataRef&);

   /*
   TODO:
      - dedicated decrypt per sub class instead of virtual (
        otherwise the return type is always ClearTextAssetData)
      - dedicated encryption key id
   */

   std::unique_ptr<ClearTextAssetData> decrypt(
      const SecureBinaryData& key) const;
   CipherData* getCipherDataPtr(void) const;
};

////////////////////////////////////////////////////////////////////////////////
class EncryptedAssetData
{
   /***
   This class holds the cipher data for an encrypted key. It can yield the
   clear text secret, provided the kdf'ed encryption key. It cannot generate
   the cipher text.

   Use Cipher::encrypt to generate the cipher text first. Pass that cipher data
   at construction time.
   ***/

   friend class DecryptedDataContainer;

protected:
   const Armory::Wallets::EncryptionKeyId& encryptionKeyId_;
   const std::unique_ptr<CipherData> cipherData_;

public:
   EncryptedAssetData(std::unique_ptr<CipherData> cipherData) :
      encryptionKeyId_(cipherData->cipher_->getEncryptionKeyId()),
      cipherData_(std::move(cipherData))
   {
      if (cipherData_ == nullptr)
         throw std::runtime_error("nullptr cipher data");
   }

   //virtual
   virtual ~EncryptedAssetData(void) = 0;

   virtual bool isSame(EncryptedAssetData* const) const;
   virtual BinaryData serialize(void) const = 0;
   virtual const Armory::Wallets::AssetId& getAssetId(void) const = 0;

   virtual std::unique_ptr<ClearTextAssetData> decrypt(
      const SecureBinaryData& key) const;

   //local
   const SecureBinaryData& getCipherText(void) const;
   const SecureBinaryData& getIV(void) const;
   const Armory::Wallets::EncryptionKeyId& getEncryptionKeyId(void) const;
   const BinaryData& getKdfId(void) const;

   bool hasData(void) const
   {
      return cipherData_ != nullptr;
   }

   const CipherData* getCipherDataPtr() const
   {
      return cipherData_.get();
   }

   //static
   static std::unique_ptr<EncryptedAssetData> deserialize(
      const BinaryDataRef&);
   static std::unique_ptr<EncryptedAssetData> deserializeOld(
      const Armory::Wallets::AssetId&, const BinaryDataRef&);
};

////////////////////////////////////////////////////////////////////////////////
struct Asset_PrivateKey : public EncryptedAssetData, public Asset
{
public:
   const Armory::Wallets::AssetId id_;

public:
   Asset_PrivateKey(const Armory::Wallets::AssetId& id,
      std::unique_ptr<CipherData> cipherData) :
      EncryptedAssetData(std::move(cipherData)),
      Asset(AssetType::PrivateKey), id_(id)
   {}

   ////
   bool isSame(EncryptedAssetData* const) const override;
   BinaryData serialize(void) const override;
   const Armory::Wallets::AssetId& getAssetId(void) const override;
};

////////////////////////////////////////////////////////////////////////////////
class EncryptedSeed : public EncryptedAssetData
{
public:
   static const Armory::Wallets::AssetId seedAssetId_;

public:
   //tors
   EncryptedSeed(
      std::unique_ptr<CipherData> cipher) :
      EncryptedAssetData(move(cipher))
   {}

   //virtual
   bool isSame(EncryptedAssetData* const) const override;
   BinaryData serialize(void) const override;
   const Armory::Wallets::AssetId& getAssetId(void) const override;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
class AssetEntry
{
protected:
   AssetEntryType type_;
   const Armory::Wallets::AssetId ID_;

   bool needsCommit_ = true;

public:
   //tors
   AssetEntry(AssetEntryType type, Armory::Wallets::AssetId id) :
      type_(type), ID_(id)
   {}

   virtual ~AssetEntry(void) = 0;

   //local
   Armory::Wallets::AssetKeyType getIndex(void) const;
   const Armory::Wallets::AssetAccountId getAccountID(void) const;
   const Armory::Wallets::AssetId& getID(void) const { return ID_; }

   virtual const AssetEntryType getType(void) const { return type_; }
   bool needsCommit(void) const { return needsCommit_; }
   void doNotCommit(void) { needsCommit_ = false; }
   void flagForCommit(void) { needsCommit_ = true; }
   BinaryData getDbKey(void) const;

   //virtual
   virtual BinaryData serialize(void) const = 0;
   virtual bool hasPrivateKey(void) const = 0;
   virtual const Armory::Wallets::EncryptionKeyId&
      getPrivateEncryptionKeyId(void) const = 0;

   //static
   static std::shared_ptr<AssetEntry> deserialize(
      BinaryDataRef key, BinaryDataRef value);
   static std::shared_ptr<AssetEntry> deserDBValue(
      const Armory::Wallets::AssetId&, BinaryDataRef);
};

////////////////////////////////////////////////////////////////////////////////
class AssetEntry_Single : public AssetEntry
{
private:
   std::shared_ptr<Asset_PublicKey> pubkey_;
   std::shared_ptr<Asset_PrivateKey> privkey_;

public:
   //tors
   AssetEntry_Single(Armory::Wallets::AssetId id,
      SecureBinaryData& pubkey,
      std::shared_ptr<Asset_PrivateKey> privkey) :
      AssetEntry(AssetEntryType_Single, id),
      privkey_(privkey)
   {
      pubkey_ = std::make_shared<Asset_PublicKey>(pubkey);
   }

   AssetEntry_Single(Armory::Wallets::AssetId id,
      SecureBinaryData& pubkeyUncompressed,
      SecureBinaryData& pubkeyCompressed,
      std::shared_ptr<Asset_PrivateKey> privkey) :
      AssetEntry(AssetEntryType_Single, id),
      privkey_(privkey)
   {
      pubkey_ = std::make_shared<Asset_PublicKey>(
         pubkeyUncompressed, pubkeyCompressed);
   }

   AssetEntry_Single(Armory::Wallets::AssetId id,
      std::shared_ptr<Asset_PublicKey> pubkey,
      std::shared_ptr<Asset_PrivateKey> privkey) :
      AssetEntry(AssetEntryType_Single, id),
      pubkey_(pubkey), privkey_(privkey)
   {}

   //local
   std::shared_ptr<Asset_PublicKey> getPubKey(void) const { return pubkey_; }
   std::shared_ptr<Asset_PrivateKey> getPrivKey(void) const { return privkey_; }

   //virtual
   virtual BinaryData serialize(void) const override;
   bool hasPrivateKey(void) const;
   const Armory::Wallets::EncryptionKeyId&
      getPrivateEncryptionKeyId(void) const override;
   const BinaryData& getKdfId(void) const;

   virtual std::shared_ptr<AssetEntry_Single> getPublicCopy(void);
};

////////////////////////////////////////////////////////////////////////////////
class AssetEntry_ArmoryLegacyRoot : public AssetEntry_Single
{
private:
   const SecureBinaryData chaincode_;

public:
   //tors
   AssetEntry_ArmoryLegacyRoot(
      Armory::Wallets::AssetId id,
      SecureBinaryData& pubkey,
      std::shared_ptr<Asset_PrivateKey> privkey,
      const SecureBinaryData& chaincode):
      AssetEntry_Single(id, pubkey, privkey),
      chaincode_(chaincode)
   {}

   BinaryData serialize(void) const override;
   const AssetEntryType getType(void) const override 
   { return AssetEntryType_ArmoryLegacyRoot; }

   const SecureBinaryData& getChaincode(void) const
   { return chaincode_; }

   std::shared_ptr<AssetEntry_Single> getPublicCopy(void) override;
};

////////////////////////////////////////////////////////////////////////////////
class AssetEntry_BIP32Root : public AssetEntry_Single
{
private:
   const SecureBinaryData chaincode_;
   const uint8_t depth_;
   const unsigned leafID_;

   /*
   Fingerprint of the parent (see BIP32 specs), 0 for roots derived from
   a seed (there is no parent)
   */
   const uint32_t parentFingerprint_;

   /*
   Fingerprint of the node generated from a seed (no derivation), equal 
   to thisFingerprint when parentFingerprint is 0
   */
   uint32_t seedFingerprint_ = UINT32_MAX;

   /*
   Own fingerprint, 4 first bytes of hash256 of the root's public key
   */
   mutable uint32_t thisFingerprint_ = UINT32_MAX;

   const std::vector<uint32_t> derivationPath_ = {};

public:
   //tors
   AssetEntry_BIP32Root(
      const Armory::Wallets::AssetId&,
      SecureBinaryData&, //pubkey
      std::shared_ptr<Asset_PrivateKey>, //privkey
      const SecureBinaryData&, //chaincode
      uint8_t, uint32_t, //depth, leafID
      uint32_t, uint32_t, //fingerprint, seed fingerprint
      const std::vector<uint32_t>&); //der path

   AssetEntry_BIP32Root(
      const Armory::Wallets::AssetId&,
      std::shared_ptr<Asset_PublicKey>,
      std::shared_ptr<Asset_PrivateKey>,
      const SecureBinaryData&,
      uint8_t, uint32_t,
      uint32_t, uint32_t,
      const std::vector<uint32_t>&);

   //local
   uint8_t getDepth(void) const { return depth_; }
   unsigned getLeafID(void) const { return leafID_; }
   unsigned getParentFingerprint(void) const { return parentFingerprint_; }
   unsigned getThisFingerprint(void) const;
   unsigned getSeedFingerprint(bool) const;
   std::string getXPub(void) const;
   const SecureBinaryData& getChaincode(void) const { return chaincode_; }
   const std::vector<uint32_t>& getDerivationPath(void) const 
   { return derivationPath_; }

   //sanity check
   void checkSeedFingerprint(bool) const;

   //virtual
   BinaryData serialize(void) const override;
   const AssetEntryType getType(void) const override 
   { return AssetEntryType_BIP32Root; }

   std::shared_ptr<AssetEntry_Single> getPublicCopy(void) override;
};

////////////////////////////////////////////////////////////////////////////////
class AssetEntry_Multisig : public AssetEntry
{
   friend class AddressEntry_Multisig;

private:
   //map<AssetWalletID, AssetEntryPtr>
   //ordering by wallet ids guarantees the ms script hash can be 
   //reconstructed deterministically
   const std::map<BinaryData, std::shared_ptr<AssetEntry>> assetMap_;

   const unsigned m_;
   const unsigned n_;

private:
   const std::map<BinaryData, std::shared_ptr<AssetEntry>> getAssetMap(void) const
   {
      return assetMap_;
   }

public:
   //tors
   AssetEntry_Multisig(Armory::Wallets::AssetId id,
      const std::map<BinaryData, std::shared_ptr<AssetEntry>>& assetMap,
      unsigned m, unsigned n) :
      AssetEntry(AssetEntryType_Multisig, id),
      assetMap_(assetMap), m_(m), n_(n)
   {
      if (assetMap.size() != n)
         throw AssetException("asset count mismatch in multisig entry");

      if (m > n || m == 0)
         throw AssetException("invalid m");
   }

   //local
   unsigned getM(void) const { return m_; }
   unsigned getN(void) const { return n_; }

   //virtual
   BinaryData serialize(void) const override
   {
      throw AssetException("no serialization for MS assets");
   }

   bool hasPrivateKey(void) const;
   const Armory::Wallets::EncryptionKeyId&
      getPrivateEncryptionKeyId(void) const override;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
struct MetaData
{
   friend class MetaDataAccount;

private:
   bool needsCommit_ = false;

protected:
   const MetaType type_;
   const BinaryData accountID_;
   const unsigned index_;

public:
   MetaData(MetaType type, const BinaryData& accountID, unsigned index) :
      type_(type), accountID_(accountID), index_(index)
   {}

   //virtuals
   virtual ~MetaData(void) = 0;
   virtual BinaryData serialize(void) const = 0;
   virtual BinaryData getDbKey(void) const = 0;
   virtual void deserializeDBValue(const BinaryDataRef&) = 0;
   virtual void clear(void) = 0;
   virtual std::shared_ptr<MetaData> copy(void) const = 0;

   //locals
   bool needsCommit(void) { return needsCommit_; }
   void flagForCommit(void) { needsCommit_ = true; }
   MetaType type(void) const { return type_; }

   const BinaryData& getAccountID(void) const { return accountID_; }
   unsigned getIndex(void) const { return index_; }

   //static
   static std::shared_ptr<MetaData> deserialize(
      const BinaryDataRef& key, const BinaryDataRef& data);
};

////////////////////////////////////////////////////////////////////////////////
class PeerPublicData : public MetaData
{
private:
   std::set<std::string> names_; //IPs, domain names
   SecureBinaryData publicKey_;

public:
   PeerPublicData(const BinaryData& accountID, unsigned index) :
      MetaData(MetaType_AuthorizedPeer, accountID, index)
   {}

   //virtuals
   BinaryData serialize(void) const override;
   BinaryData getDbKey(void) const;
   void deserializeDBValue(const BinaryDataRef&);
   void clear(void);
   std::shared_ptr<MetaData> copy(void) const;

   //locals
   void addName(const std::string&);
   bool eraseName(const std::string&);
   void setPublicKey(const SecureBinaryData&);

   //
   const std::set<std::string> getNames(void) const { return names_; }
   const SecureBinaryData& getPublicKey(void) const { return publicKey_; }
};

////////////////////////////////////////////////////////////////////////////////
class PeerRootKey : public MetaData
{
   //carries the root key of authorized peers' parent public key
   //used to check signatures of child peer keys, typically a server with a
   //key pair cycling schedule

private:
   SecureBinaryData publicKey_;
   std::string description_;

public:
   PeerRootKey(const BinaryData& accountID, unsigned index) :
      MetaData(MetaType_PeerRootKey, accountID, index)
   {}

   //virtuals
   BinaryData serialize(void) const override;
   BinaryData getDbKey(void) const;
   void deserializeDBValue(const BinaryDataRef&);
   void clear(void);
   std::shared_ptr<MetaData> copy(void) const;

   //locals
   void set(const std::string&, const SecureBinaryData&);
   const SecureBinaryData& getKey(void) const { return publicKey_; }
   const std::string& getDescription(void) const { return description_; }

};

////////////////////////////////////////////////////////////////////////////////
class PeerRootSignature : public MetaData
{
   // carries the peer wallet's key pair signature from a 'parent' wallet
   // typically only one per peer wallet

private:
   SecureBinaryData publicKey_;
   SecureBinaryData signature_;

public:
   PeerRootSignature(const BinaryData& accountID, unsigned index) :
      MetaData(MetaType_PeerRootSig, accountID, index)
   {}

   //virtuals
   BinaryData serialize(void) const override;
   BinaryData getDbKey(void) const;
   void deserializeDBValue(const BinaryDataRef&);
   void clear(void);
   std::shared_ptr<MetaData> copy(void) const;

   //locals
   void set(const SecureBinaryData& key, const SecureBinaryData& sig);
   const SecureBinaryData& getKey(void) const { return publicKey_; }
   const SecureBinaryData& getSig(void) const { return signature_; }
};

////////////////////////////////////////////////////////////////////////////////
class CommentData : public MetaData
{
private:
   std::string commentStr_;
   BinaryData key_;

public:
   CommentData(const BinaryData& accountID, unsigned index) :
      MetaData(MetaType_AuthorizedPeer, accountID, index)
   {}

   //virtuals
   BinaryData serialize(void) const override;
   BinaryData getDbKey(void) const;
   void deserializeDBValue(const BinaryDataRef&);
   void clear(void);
   std::shared_ptr<MetaData> copy(void) const;

   //locals
   const std::string& getValue(void) const { return commentStr_; }
   void setValue(const std::string& val) { commentStr_ = val; }
   
   const BinaryData& getKey(void) const { return key_; }
   void setKey(const BinaryData& val) { key_ = val; }
};

#endif
