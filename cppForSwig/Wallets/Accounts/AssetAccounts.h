////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_ASSET_ACCOUNT
#define _H_ASSET_ACCOUNT

#include <memory>
#include <functional>
#include <string>

#include "../WalletIdTypes.h"
#include "../../ReentrantLock.h"

#define ASSET_ACCOUNT_PREFIX        0xE1
#define ASSET_COUNT_PREFIX          0xE2
#define ASSET_TOP_INDEX_PREFIX_V1   0xE3
#define ASSET_TOP_INDEX_PREFIX_V2   0xE4

////////////////////////////////////////////////////////////////////////////////
class WalletIfaceTransaction;
class WalletDBInterface;
class DerivationScheme;
enum class DerivationSchemeType : int;

////////////////////////////////////////////////////////////////////////////////
struct AssetAccountData
{
public:
   const AssetAccountTypeEnum type_;
   Armory::Wallets::AssetAccountId id_;

   std::shared_ptr<AssetEntry> root_;
   std::shared_ptr<DerivationScheme> derScheme_;

   const std::string dbName_;

   std::map<Armory::Wallets::AssetKeyType, std::shared_ptr<AssetEntry>> assets_;
   Armory::Wallets::AssetKeyType lastUsedIndex_ = -1;

   //<assetID, <address type, prefixed address hash>>
   using AddrHashMapType = std::map<Armory::Wallets::AssetId,
      std::map<AddressEntryType, BinaryData>>;
   AddrHashMapType addrHashMap_;
   Armory::Wallets::AssetKeyType lastHashedAsset_ = -1;

public:
   AssetAccountData(
      const AssetAccountTypeEnum type,
      const Armory::Wallets::AssetAccountId& id,
      std::shared_ptr<AssetEntry> root,
      std::shared_ptr<DerivationScheme> scheme,
      const std::string& dbName) :
      type_(type), id_(id),
      root_(root), derScheme_(scheme),
      dbName_(dbName)
   {}

   std::shared_ptr<AssetAccountData> copy(const std::string&) const;
};

////////////////////////////////////////////////////////////////////////////////
struct AssetAccountPublicData
{
   const Armory::Wallets::AssetAccountId id_;

   const SecureBinaryData rootData_;
   const SecureBinaryData derivationData_;

   const Armory::Wallets::AssetKeyType lastUsedIndex_;
   const Armory::Wallets::AssetKeyType lastComputedIndex_;
};

////////////////////////////////////////////////////////////////////////////////
class AssetAccount : protected Lockable
{
   friend class AssetAccount_ECDH;
   friend class AddressAccount;

private:
   std::shared_ptr<AssetAccountData> data_;

private:
   size_t writeAssetEntry(std::shared_ptr<AssetEntry>,
      std::shared_ptr<WalletDBInterface>);
   void updateOnDiskAssets(std::shared_ptr<WalletDBInterface>);

   void updateHighestUsedIndex(std::shared_ptr<WalletDBInterface>);
   unsigned getAndBumpHighestUsedIndex(std::shared_ptr<WalletDBInterface>);

   virtual void commit(std::shared_ptr<WalletDBInterface>);
   void updateAssetCount(std::shared_ptr<WalletDBInterface>);

   void extendPublicChainToIndex(std::shared_ptr<WalletDBInterface>
      , unsigned);
   void extendPublicChain(std::shared_ptr<WalletDBInterface>
      , std::shared_ptr<AssetEntry>, unsigned);
   std::vector<std::shared_ptr<AssetEntry>> extendPublicChain(
      std::shared_ptr<AssetEntry>, unsigned, unsigned);

   void extendPrivateChain(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<DecryptedDataContainer>,
      unsigned);
   void extendPrivateChainToIndex(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<DecryptedDataContainer>,
      unsigned);
   void extendPrivateChain(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<DecryptedDataContainer>,
      std::shared_ptr<AssetEntry>, unsigned);
   std::vector<std::shared_ptr<AssetEntry>> extendPrivateChain(
      std::shared_ptr<DecryptedDataContainer>,
      std::shared_ptr<AssetEntry>,
      unsigned, unsigned);

   std::shared_ptr<AssetEntry> getOrSetAssetAtIndex(
      std::shared_ptr<WalletDBInterface>, unsigned);
   std::shared_ptr<AssetEntry> getNewAsset(
      std::shared_ptr<WalletDBInterface>);
   std::shared_ptr<AssetEntry> peekNextAsset(
      std::shared_ptr<WalletDBInterface>);

   std::shared_ptr<Asset_PrivateKey> fillPrivateKey(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<DecryptedDataContainer>,
      const Armory::Wallets::AssetId&);

   virtual unsigned getLookup(void) const;
   virtual AssetAccountTypeEnum type(void) const
   { return AssetAccountTypeEnum_Plain; }

public:
   AssetAccount(
      std::shared_ptr<AssetAccountData> data) :
      data_(data)
   {
      if (data == nullptr)
         throw std::runtime_error("null account data ptr");
   }

   size_t getAssetCount(void) const;
   int32_t getLastComputedIndex(void) const;
   int32_t getHighestUsedIndex(void) const;
   bool isAssetInUse(const Armory::Wallets::AssetId&) const;
   std::shared_ptr<AssetEntry> getLastAssetWithPrivateKey(void) const;

   std::shared_ptr<AssetEntry> getAssetForID(
      const Armory::Wallets::AssetId&) const;
   std::shared_ptr<AssetEntry> getAssetForKey(
      const Armory::Wallets::AssetKeyType&) const;
   bool isAssetIDValid(const Armory::Wallets::AssetId&) const;

   void updateAddressHashMap(const std::set<AddressEntryType>&);
   const AssetAccountData::AddrHashMapType&
      getAddressHashMap(const std::set<AddressEntryType>&);

   const Armory::Wallets::AssetAccountId& getID(void) const;
   const SecureBinaryData& getChaincode(void) const;
   std::shared_ptr<AssetEntry> getRoot(void) const;

   void extendPublicChain(std::shared_ptr<WalletDBInterface>, unsigned);

   //static
   static std::shared_ptr<AssetAccountData> loadFromDisk(
      const BinaryData& key, std::shared_ptr<WalletIfaceTransaction>);

   //Lockable virtuals
   void initAfterLock(void) {}
   void cleanUpBeforeUnlock(void) {}
};

////////////////////////////////////////////////////////////////////////////////
class AssetAccount_ECDH : public AssetAccount
{
private:
   unsigned getLookup(void) const override { return 1; }
   AssetAccountTypeEnum type(void) const override
   { return AssetAccountTypeEnum_ECDH; }

   void commit(std::shared_ptr<WalletDBInterface>) override;

public:
   AssetAccount_ECDH(
      std::shared_ptr<AssetAccountData> data) :
      AssetAccount(data)
   {}

   Armory::Wallets::AssetKeyType addSalt(
      std::shared_ptr<WalletIfaceTransaction>, const SecureBinaryData&);
   Armory::Wallets::AssetKeyType getSaltIndex(const SecureBinaryData&) const;
};

#endif