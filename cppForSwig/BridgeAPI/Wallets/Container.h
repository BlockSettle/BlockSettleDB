////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <map>
#include <Wallets/WalletIdTypes.h>
#include <Wallets/GetPassphrase.h>

namespace AsyncClient
{
   class BtcWallet;
   class BlockDataViewer;
   struct CombinedBalances;
}

template<class U> class ReturnMessage;
class AddressEntry;
class AddressBookEntry;
struct UTXO;

namespace Armory
{
   namespace Accounts
   {
      class AddressAccount;
   }

   namespace Wallets
   {
      class AssetWallet;
   }

   namespace Seeds
   {
      class WalletBackup;
   }

   namespace Bridge
   {
      struct OfflineException
      {};

      class WalletContainer
      {
         friend class WalletManager;

      private:
         const Wallets::WalletId wltId_;
         const Wallets::AddressAccountId accountId_;
         std::string dbId_;
         std::shared_ptr<Wallets::AssetWallet> wallet_;

         std::shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;
         std::shared_ptr<AsyncClient::BtcWallet> asyncWlt_;

         std::map<BinaryData, std::vector<uint64_t>> balanceMap_;
         std::map<BinaryData, uint64_t> countMap_;

         uint64_t totalBalance_ = 0;
         uint64_t spendableBalance_ = 0;
         uint64_t unconfirmedBalance_ = 0;
         uint64_t txioCount_ = 0;

         std::map<Wallets::AssetAccountId, Wallets::AssetKeyType>
            highestUsedIndex_;
         std::mutex stateMutex_;

         std::map<BinaryData, std::shared_ptr<AddressEntry>> updatedAddressMap_;

      private:
         WalletContainer(
            const Wallets::WalletId&,
            const Wallets::AddressAccountId&);

         void resetCache(void);
         void setBdvPtr(std::shared_ptr<AsyncClient::BlockDataViewer>);
         void setWalletPtr(std::shared_ptr<Wallets::AssetWallet>,
            const Wallets::AddressAccountId&);
         void eraseFromDisk(void);

      public:
         void registerWithBDV(bool isNew);
         void unregisterFromBDV(void);
         const std::string& getDbId(void) const;

         virtual std::shared_ptr<Wallets::AssetWallet>
            getWalletPtr(void) const;
         std::shared_ptr<Accounts::AddressAccount>
            getAddressAccount(void) const;
         const Wallets::AddressAccountId& getAccountId(void) const;

         void updateBalancesAndCount(uint32_t);
         void updateWalletBalanceState(const AsyncClient::CombinedBalances&);
         void updateAddressCountState(const AsyncClient::CombinedBalances&);

         void extendAddressChain(unsigned, const std::function<void(int)>&);
         void extendAddressChainToIndex(unsigned);
         bool hasAddress(const BinaryData&);
         bool hasAddress(const std::string&);

         void createAddressBook(
            const std::function<void(ReturnMessage<std::vector<AddressBookEntry>>)>&);

         void getUTXOs(uint64_t, bool, bool,
            const std::function<void(ReturnMessage<std::vector<UTXO>>)>& lbd);

         uint64_t getFullBalance(void) const;
         uint64_t getSpendableBalance(void) const;
         uint64_t getUnconfirmedBalance(void) const;
         uint64_t getTxIOCount(void) const;

         std::map<BinaryData, std::vector<uint64_t>> getAddrBalanceMap(void) const;
         Wallets::AssetKeyType getHighestUsedIndex(void) const;
         std::map<BinaryData, std::shared_ptr<AddressEntry>> getUpdatedAddressMap();

         std::unique_ptr<Seeds::WalletBackup> getBackupStrings(
            bool, const Passphrase::UnlockFunc&) const;
         void changePassphrase(const Passphrase::UnlockFunc&,
            Passphrase::SetNew&, bool);

         void setComment(const std::string&, const std::string&);
         void setLabels(const std::string&, const std::string&);

         const Wallets::EncryptionKeyId& getDefaultEncryptionKeyId() const;
         std::filesystem::path forkWatchingOnly(const Passphrase::SetNew&);
      };
   } //namespace Bridge
} //namespace Armory
