////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <memory>
#include <string>
#include <map>
#include <filesystem>

#include "Utils/ReentrantLock.h"
#include "Loader.h"
#include "Container.h"

namespace Armory
{
   namespace Seeds
   {
      class WalletBackup;
   };

   namespace Accounts
   {
      class AddressAccount;
   }

   namespace Wallets
   {
      class WalletId;
      class AddressAccountId;
      class AssetWallet;
      class EncryptionKeyId;

      namespace IO
      {
         struct CreateWalletParams;
         struct ReadOnlyFileParams;
      }
   };

   ////////
   namespace Bridge
   {
      class Callback;

      class WalletManager : public Lockable
      {
      private:
         const std::filesystem::path path_;
         std::map<std::string, std::shared_ptr<WalletFileInfo>> walletFiles_;

         std::map<Wallets::WalletId, std::map<
            Wallets::AddressAccountId,
            std::shared_ptr<WalletContainer>>> wallets_;
         std::map<std::string, std::shared_ptr<WalletContainer>> walletsByDbId_;

         std::shared_ptr<Callback> callbackPtr_;
         std::shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;

      private:
         void initAfterLock(void) override {}
         void cleanUpBeforeUnlock(void) override {}
         std::shared_ptr<WalletContainer> addAccount(
            std::shared_ptr<Wallets::AssetWallet>,
            const Wallets::AddressAccountId&);
         void addAllAccounts(std::shared_ptr<Wallets::AssetWallet>);
         void loadAFile(const std::filesystem::path&);

      public:
         WalletManager(const std::filesystem::path&);

         /* pre wallets loading calls */
         std::map<std::string, std::shared_ptr<WalletFileInfo>> listWallets(void);
         void unlockControlHeader(const std::string&, const Passphrase::UnlockFunc&);
         const Wallets::WalletId& migrateWallet(const std::filesystem::path&,
            const Passphrase::UnlockFunc&,
            const Wallets::IO::CreateWalletParams&
         );
         bool stageWallet(const Wallets::WalletId&, bool);
         void loadWallets(void);
         std::shared_ptr<WalletFileInfo> importFile(const std::filesystem::path&);

         /* db setup */
         void registerWallets(void);
         void registerWallet(const Wallets::WalletId&,
            const Wallets::AddressAccountId&, bool);
         void setupBdvCallback(
            const std::function<void(BinaryData&)>&);
         std::shared_ptr<Callback> getBdvCallback(void) const;
         void setBdvPtr(std::shared_ptr<AsyncClient::BlockDataViewer>);

         /* utils */
         const std::filesystem::path& getWalletDir(void) const;
         void updateStateFromDB(const std::function<void(void)>&);

         /* loaded wallet getters */
         bool hasWallet(const Wallets::WalletId&);
         std::shared_ptr<WalletContainer> getWalletContainer(
            const Wallets::WalletId&) const;
         std::shared_ptr<WalletContainer> getWalletContainer(
            const Wallets::WalletId&, const Wallets::AddressAccountId&) const;
         std::map<Wallets::WalletId, std::set<Wallets::AddressAccountId>>
            getAccountIdMap(void) const;

         /* wallet add/create/delete */
         void loadWallet(const Wallets::IO::ReadOnlyFileParams&);
         std::shared_ptr<WalletContainer> createNewWallet(
            const SecureBinaryData&, //extra entropy
            const Wallets::IO::CreateWalletParams&);

         std::filesystem::path unloadWallet(const Wallets::WalletId&);
         void deleteWallet(const Wallets::WalletId&);

         /* address creation */
         void extendAddressChain(const Wallets::WalletId&,
            const Wallets::AddressAccountId&,
            unsigned, bool,
            std::function<void(int)>
         );
         std::shared_ptr<AddressEntry> getNewAddress(
            const Wallets::WalletId&,
            const Wallets::AddressAccountId&,
            uint32_t, uint32_t);
      };
   } //namespace Bridge
} //namespace Armory
