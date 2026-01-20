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
namespace Armory
{
   namespace Assets
   {
      enum class DerivationSchemeType : int;
      class DerivationScheme;
   };

   namespace Wallets
   {
      namespace IO
      {
         class WalletIfaceTransaction;
         class WalletDBInterface;
      };

      namespace Encryption
      {
         class DecryptedDataContainer;
      };
   };

   namespace Accounts
   {
      struct AssetAccountData
      {
      public:
         const AssetAccountTypeEnum type_;
         Wallets::AssetAccountId id_;

         std::shared_ptr<Assets::AssetEntry> root_;
         std::shared_ptr<Assets::DerivationScheme> derScheme_;

         const std::string dbName_;

         std::map<Wallets::AssetKeyType,
            std::shared_ptr<Assets::AssetEntry>> assets_;
         Wallets::AssetKeyType lastUsedIndex_ = -1;

         //<assetID, <address type, prefixed address hash>>
         using AddrHashMapType = std::map<Wallets::AssetId,
            std::map<AddressEntryType, BinaryData>>;
         AddrHashMapType addrHashMap_;
         Wallets::AssetKeyType lastHashedAsset_ = -1;

      public:
         AssetAccountData(
            const AssetAccountTypeEnum type,
            const Wallets::AssetAccountId& id,
            std::shared_ptr<Assets::AssetEntry> root,
            std::shared_ptr<Assets::DerivationScheme> scheme,
            const std::string& dbName) :
            type_(type), id_(id),
            root_(root), derScheme_(scheme),
            dbName_(dbName)
         {}

         std::shared_ptr<AssetAccountData> copy(const std::string&) const;
      };

      //////////////////////////////////////////////////////////////////////////
      struct AssetAccountExtendedData
      {
         virtual ~AssetAccountExtendedData(void) = 0;
      };

      struct AssetAccountSaltMap : public AssetAccountExtendedData
      {
         std::map<Wallets::AssetKeyType, SecureBinaryData> salts_;
         ~AssetAccountSaltMap(void) override;
      };

      ////
      struct AssetAccountPublicData
      {
         const Wallets::AssetAccountId id_;

         const SecureBinaryData rootData_;
         const SecureBinaryData derivationData_;

         const Wallets::AssetKeyType lastUsedIndex_;
         const Wallets::AssetKeyType lastComputedIndex_;

         std::shared_ptr<AssetAccountExtendedData> extendedData;
      };

      //////////////////////////////////////////////////////////////////////////
      class AssetAccount : protected Lockable
      {
         friend class AssetAccount_ECDH;
         friend class AddressAccount;

      private:
         std::shared_ptr<AssetAccountData> data_;

      private:
         size_t writeAssetEntry(std::shared_ptr<Assets::AssetEntry>,
            std::shared_ptr<Wallets::IO::WalletDBInterface>);
         void updateOnDiskAssets(
            std::shared_ptr<Wallets::IO::WalletDBInterface>);

         void updateHighestUsedIndex(
            std::shared_ptr<Wallets::IO::WalletDBInterface>);
         unsigned getAndBumpHighestUsedIndex(
            std::shared_ptr<Wallets::IO::WalletDBInterface>);

         virtual void commit(
            std::shared_ptr<Wallets::IO::WalletDBInterface>);
         void updateAssetCount(
            std::shared_ptr<Wallets::IO::WalletDBInterface>);

         void extendPublicChainToIndex(
            std::shared_ptr<Wallets::IO::WalletDBInterface>, unsigned,
            const std::function<void(int)>&);
         void extendPublicChain(
            std::shared_ptr<Wallets::IO::WalletDBInterface>,
            std::shared_ptr<Assets::AssetEntry>, unsigned,
            const std::function<void(int)>&);
         std::vector<std::shared_ptr<Assets::AssetEntry>> extendPublicChain(
            std::shared_ptr<Assets::AssetEntry>, unsigned, unsigned,
            const std::function<void(int)>&);

         void extendPrivateChain(
            std::shared_ptr<Wallets::IO::WalletDBInterface>,
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            unsigned);
         void extendPrivateChainToIndex(
            std::shared_ptr<Wallets::IO::WalletDBInterface>,
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            unsigned);
         void extendPrivateChain(
            std::shared_ptr<Wallets::IO::WalletDBInterface>,
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            std::shared_ptr<Assets::AssetEntry>, unsigned);
         std::vector<std::shared_ptr<Assets::AssetEntry>> extendPrivateChain(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            std::shared_ptr<Assets::AssetEntry>,
            unsigned, unsigned);

         std::shared_ptr<Assets::AssetEntry> getOrSetAssetAtIndex(
            std::shared_ptr<Wallets::IO::WalletDBInterface>, unsigned);
         std::shared_ptr<Assets::AssetEntry> getNewAsset(
            std::shared_ptr<Wallets::IO::WalletDBInterface>);
         std::shared_ptr<Assets::AssetEntry> peekNextAsset(
            std::shared_ptr<Wallets::IO::WalletDBInterface>);

         std::shared_ptr<Assets::Asset_PrivateKey> fillPrivateKey(
            std::shared_ptr<Wallets::IO::WalletDBInterface>,
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            const Wallets::AssetId&);

         virtual unsigned getLookup(void) const;
         virtual AssetAccountTypeEnum type(void) const
         { return AssetAccountTypeEnum_Plain; }

      public:
         AssetAccount(std::shared_ptr<AssetAccountData> data) :
            data_(data)
         {
            if (data == nullptr)
               throw std::runtime_error("null account data ptr");
         }

         size_t getAssetCount(void) const;
         int32_t getLastComputedIndex(void) const;
         int32_t getHighestUsedIndex(void) const;
         bool isAssetInUse(const Wallets::AssetId&) const;
         std::shared_ptr<Assets::AssetEntry> getLastAssetWithPrivateKey(void) const;

         std::shared_ptr<Assets::AssetEntry> getAssetForID(
            const Wallets::AssetId&) const;
         std::shared_ptr<Assets::AssetEntry> getAssetForKey(
            const Wallets::AssetKeyType&) const;
         bool isAssetIDValid(const Wallets::AssetId&) const;

         void updateAddressHashMap(const std::set<AddressEntryType>&);
         const AssetAccountData::AddrHashMapType&
            getAddressHashMap(const std::set<AddressEntryType>&);

         const Wallets::AssetAccountId& getID(void) const;
         const SecureBinaryData& getChaincode(void) const;
         std::shared_ptr<Assets::AssetEntry> getRoot(void) const;

         void extendPublicChain(
            std::shared_ptr<Wallets::IO::WalletDBInterface>, unsigned,
            const std::function<void(int)>& = nullptr);

         //static
         static std::shared_ptr<AssetAccountData> loadFromDisk(
            const BinaryData& key,
            std::shared_ptr<Wallets::IO::WalletIfaceTransaction>);

         //Lockable virtuals
         void initAfterLock(void) {}
         void cleanUpBeforeUnlock(void) {}
      };

      //////////////////////////////////////////////////////////////////////////
      class AssetAccount_ECDH : public AssetAccount
      {
      private:
         unsigned getLookup(void) const override { return 1; }
         AssetAccountTypeEnum type(void) const override
         { return AssetAccountTypeEnum_ECDH; }

         void commit(std::shared_ptr<Wallets::IO::WalletDBInterface>) override;

      public:
         AssetAccount_ECDH(
            std::shared_ptr<AssetAccountData> data) :
            AssetAccount(data)
         {}

         Wallets::AssetKeyType addSalt(
            std::shared_ptr<Wallets::IO::WalletIfaceTransaction>,
            const SecureBinaryData&);
         Wallets::AssetKeyType getSaltIndex(
            const SecureBinaryData&) const;
      };
   }; //namespace Accounts
}; //namespace Armory
#endif