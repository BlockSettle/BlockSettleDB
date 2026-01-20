////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Container.h"
#include "Utils/BtcUtils.h"
#include "Utils/Cryptography.h"

#include "Wallets/Wallets.h"
#include "Wallets/Addresses.h"
#include "Wallets/Accounts/AddressAccounts.h"
#include "Wallets/Seeds/Backups.h"
#include "AsyncClient.h"

using namespace Armory;
using namespace Armory::Bridge;

////////////////////////////////////////////////////////////////////////////////
////
//// WalletContainer
////
////////////////////////////////////////////////////////////////////////////////
WalletContainer::WalletContainer(const Wallets::WalletId& wltId,
   const Armory::Wallets::AddressAccountId& accId) :
   wltId_(wltId), accountId_(accId)
{
   dbId_ = Cryptography::PRNG::fortuna.generateRandom(6).toHexStr();
}

////////////////////////////////////////////////////////////////////////////////
const std::string& WalletContainer::getDbId() const
{
   return dbId_;
}

////////////////////////////////////////////////////////////////////////////////
const Armory::Wallets::AddressAccountId& WalletContainer::getAccountId() const
{
   return accountId_;
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::setWalletPtr(std::shared_ptr<Wallets::AssetWallet> wltPtr,
   const Wallets::AddressAccountId& accId)
{
   wallet_ = wltPtr;
   auto acc = wallet_->getAccountForID(accId);
   auto assetAccountIds = acc->getAccountIdSet();

   for (const auto& aaId : assetAccountIds) {
      auto accPtr = acc->getAccountForID(aaId);
      if (accPtr == nullptr) {
         throw std::runtime_error("[setWalletPtr] missing asset account id");
      }
      highestUsedIndex_.emplace(aaId, accPtr->getHighestUsedIndex());
   }
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::setBdvPtr(std::shared_ptr<AsyncClient::BlockDataViewer> bdv)
{
   std::unique_lock<std::mutex> lock(stateMutex_);
   bdvPtr_ = bdv;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Wallets::AssetWallet> WalletContainer::getWalletPtr() const
{
   return wallet_;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Accounts::AddressAccount>
WalletContainer::getAddressAccount() const
{
   auto accPtr = wallet_->getAccountForID(accountId_);
   return accPtr;
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::resetCache()
{
   std::unique_lock<std::mutex> lock(stateMutex_);

   totalBalance_ = 0;
   spendableBalance_ = 0;
   unconfirmedBalance_ = 0;
   balanceMap_.clear();
   countMap_.clear();
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::registerWithBDV(bool isNew)
{
   if (bdvPtr_ == nullptr) {
      throw OfflineException();
   }
   resetCache();

   auto accPtr = wallet_->getAccountForID(accountId_);
   const auto& addrMap = accPtr->getAddressHashMap();

   std::set<BinaryData> addrSet;
   for (const auto& addrIt : addrMap) {
      addrSet.emplace(addrIt.first);
   }

   //convert set to vector
   std::vector<BinaryData> addrVec;
   addrVec.insert(addrVec.end(), addrSet.begin(), addrSet.end());

   asyncWlt_ = std::make_shared<AsyncClient::BtcWallet>(
      bdvPtr_->getWalletObj(dbId_));
   asyncWlt_->registerAddresses(addrVec, isNew);
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::unregisterFromBDV()
{
   if (bdvPtr_ == nullptr) {
      throw OfflineException();
   }
   if (asyncWlt_ == nullptr) {
      throw OfflineException();
   }
   asyncWlt_->unregister();
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::updateWalletBalanceState(
   const AsyncClient::CombinedBalances& bal)
{
   std::unique_lock<std::mutex> lock(stateMutex_);

   totalBalance_        = bal.walletBalanceAndCount[0];
   spendableBalance_    = bal.walletBalanceAndCount[1];
   unconfirmedBalance_  = bal.walletBalanceAndCount[2];
   txioCount_           = bal.walletBalanceAndCount[3];

   for (const auto& addrPair : bal.addressBalances) {
      balanceMap_[addrPair.first] = addrPair.second;
   }
}

uint64_t WalletContainer::getFullBalance() const
{
   return totalBalance_;
}

uint64_t WalletContainer::getSpendableBalance() const
{
   return spendableBalance_;
}

uint64_t WalletContainer::getUnconfirmedBalance() const
{
   return unconfirmedBalance_;
}

uint64_t WalletContainer::getTxIOCount() const
{
   return txioCount_;
}

////////////////////////////////////////////////////////////////////////////////
Wallets::AssetKeyType WalletContainer::getHighestUsedIndex(void) const
{
   auto accPtr = wallet_->getAccountForID(accountId_);
   if (accPtr == nullptr) {
      throw std::runtime_error("[getHighestUsedIndex] invalid acc id");
   }

   auto outerAccId = accPtr->getOuterAccountID();
   if (!outerAccId.isValid()) {
      throw std::runtime_error("[getHighestUsedIndex] invalid outer acc id");
   }

   auto indexIter = highestUsedIndex_.find(outerAccId);
   if (indexIter == highestUsedIndex_.end()) {
      throw std::runtime_error("[getHighestUsedIndex] missing index for id");
   }

   return indexIter->second;
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::updateAddressCountState(
   const AsyncClient::CombinedBalances& cnt)
{
   std::unique_lock<std::mutex> lock(stateMutex_);

   std::map<Wallets::AssetAccountId, Wallets::AssetKeyType> topIndexMap;
   std::shared_ptr<Wallets::IO::WalletIfaceTransaction> dbtx;
   std::map<BinaryData, std::shared_ptr<AddressEntry>> updatedAddressMap;
   std::map<Wallets::AssetId, AddressEntryType> addrAndTypeMap;

   for (const auto& addrPair : cnt.addressBalances) {
      auto iter = countMap_.find(addrPair.first);
      if (iter != countMap_.end()) {
         //already tracking count for this address, just update the value
         iter->second = addrPair.second[3];
         continue;
      }

      const auto& ID = wallet_->getAssetIDForScrAddr(addrPair.first);
      auto topIdIter = topIndexMap.find(ID.first.getAssetAccountId());
      if (topIdIter == topIndexMap.end()) {
         topIdIter = topIndexMap.emplace(ID.first.getAssetAccountId(), -1).first;
      }

      //track top used index
      auto idKey = ID.first.getAssetKey();
      if (idKey > topIdIter->second) {
         topIdIter->second = idKey;
      }

      //mark newly seen addresses for further processing
      addrAndTypeMap.emplace(ID);

      //add count to map
      countMap_.emplace(addrPair.first, addrPair.second[3]);
   }

   std::map<Wallets::AssetId, AddressEntryType> unpulledAddresses;
   for (const auto& idPair : addrAndTypeMap) {
      //check scrAddr with on chain data matches scrAddr for
      //address entry in wallet
      if (!wallet_->isAssetUsed(idPair.first)) {
         //db has history for an address that hasn't been pulled
         //from the wallet yet, save it for further processing
         unpulledAddresses.insert(idPair);
         continue;
      }

      auto addrType = wallet_->getAddrTypeForID(idPair.first);
      if (addrType == idPair.second) {
         continue;
      }

      //if we don't have a db tx yet, get one, as we're about to update
      //the address type on disk
      if (dbtx == nullptr) {
         dbtx = wallet_->beginSubDBTransaction(wallet_->getID(), true);
      }

      //address type mismatches, update it
      wallet_->updateAddressEntryType(idPair.first, idPair.second);

      auto addrPtr = wallet_->getAddressEntryForID(idPair.first);
      updatedAddressMap.emplace(addrPtr->getPrefixedHash(), addrPtr);
   }

   //split unpulled addresses by their accounts
   std::map<Wallets::AssetAccountId,
      std::map<Wallets::AssetId, AddressEntryType>> accIDMap;
   for (const auto& idPair : unpulledAddresses) {
      auto accID = idPair.first.getAssetAccountId();
      auto iter = accIDMap.find(accID);
      if (iter == accIDMap.end()) {
         iter = accIDMap.emplace(accID,
            std::map<Wallets::AssetId, AddressEntryType>()).first;
      }
      iter->second.insert(idPair);
   }

   if (dbtx == nullptr) {
      dbtx = wallet_->beginSubDBTransaction(wallet_->getID(), true);
   }

   //run through each account, pulling addresses accordingly
   for (const auto& accData : accIDMap) {
      auto addrAccount = wallet_->getAccountForID(
         accData.first.getAddressAccountId());
      auto assAccount = addrAccount->getAccountForID(accData.first);

      auto currentTop = assAccount->getHighestUsedIndex();
      for (auto& idPair : accData.second) {
         const auto& assetKey = idPair.first.getAssetKey();
         while (assetKey > currentTop + 1) {
            auto addrEntry = wallet_->getNewAddress(
               accData.first, AddressEntryType::Default);
            updatedAddressMap.emplace(
               addrEntry->getPrefixedHash(), addrEntry);

            ++currentTop;
         }

         auto addrEntry = wallet_->getNewAddress(
            accData.first, idPair.second);
         updatedAddressMap.emplace(
            addrEntry->getPrefixedHash(), addrEntry);
         ++currentTop;
      }
   }

   for (const auto& topIndexIt : topIndexMap) {
      auto usedIndexIter = highestUsedIndex_.find(topIndexIt.first);
      if (usedIndexIter == highestUsedIndex_.end()) {
         LOGWARN << "[updateAddressCountState]" <<
            " missing asset account, skipping";
         continue;
      }

      usedIndexIter->second = std::max(
         topIndexIt.second,
         usedIndexIter->second);
   }

   for (const auto& addrPair : updatedAddressMap) {
      auto insertIter = updatedAddressMap_.insert(addrPair);
      if (!insertIter.second) {
         insertIter.first->second = addrPair.second;
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
std::map<BinaryData, std::vector<uint64_t>>
WalletContainer::getAddrBalanceMap() const
{
   std::map<BinaryData, std::vector<uint64_t>> result;
   for (const auto& dataPair : countMap_) {
      std::vector<uint64_t> balVec;
      auto iter = balanceMap_.find(dataPair.first);
      if (iter == balanceMap_.end()) {
         balVec = {0, 0, 0};
      } else {
         balVec = iter->second;
      }

      balVec.emplace_back(dataPair.second);
      result.emplace(dataPair.first, balVec);
   }
   return result;
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::createAddressBook(const std::function<
   void(ReturnMessage<std::vector<AddressBookEntry>>)>& lbd)
{
   if (asyncWlt_ == nullptr) {
      throw std::runtime_error("empty asyncWlt");
   }
   asyncWlt_->createAddressBook(lbd);
}

////////////////////////////////////////////////////////////////////////////////
std::map<BinaryData, std::shared_ptr<AddressEntry>>
WalletContainer::getUpdatedAddressMap()
{
   auto mapMove = std::move(updatedAddressMap_);
   updatedAddressMap_.clear();
   return mapMove;
}

////////////////////////////////////////////////////////////////////////////////
std::unique_ptr<Seeds::WalletBackup> WalletContainer::getBackupStrings(
   bool isPriv, const Passphrase::UnlockFunc& passLbd) const
{
   auto wltSingle = std::dynamic_pointer_cast<Wallets::AssetWallet_Single>(wallet_);
   if (wltSingle == nullptr) {
      LOGERR << "WalletContainer::getBackupStrings: unexpected wallet type";
      throw std::runtime_error(
         "WalletContainer::getBackupStrings: unexpected wallet type");
   }

   wltSingle->setPassphrasePromptLambda(passLbd);
   auto backupStrings = Seeds::Helpers::getWalletBackup(wltSingle, isPriv);
   wltSingle->resetPassphrasePromptLambda();

   return backupStrings;
}

void WalletContainer::changePassphrase(const Passphrase::UnlockFunc& unlockLbd,
   Passphrase::SetNew& setLbd, bool isPriv)
{
   auto wltSingle = std::dynamic_pointer_cast<Wallets::AssetWallet_Single>(wallet_);
   if (wltSingle == nullptr) {
      LOGERR << "WalletContainer::changePassphrase: unexpected wallet type";
      throw std::runtime_error(
         "WalletContainer::changePassphrase: unexpected wallet type");
   }

   if (isPriv) {
      wltSingle->setPassphrasePromptLambda(unlockLbd);
      wltSingle->changePrivateKeyPassphrase(setLbd);
      wltSingle->resetPassphrasePromptLambda();
   } else {
      wltSingle->changeControlPassphrase(setLbd, unlockLbd);
   }
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::eraseFromDisk()
{
   auto wltPtr = move(wallet_);
   Wallets::AssetWallet::eraseFromDisk(wltPtr.get());
   wltPtr.reset();
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::setComment(const std::string& key, const std::string& val)
{
   auto keyBd = BinaryData::fromString(key);
   wallet_->setComment(keyBd, val);
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::setLabels(const std::string& title, const std::string& desc)
{
   wallet_->setLabel(title);
   wallet_->setDescription(desc);
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::updateBalancesAndCount(uint32_t topBlockHeight)
{
   auto lbd = [this](ReturnMessage<std::vector<uint64_t>> vec)
   {
      std::unique_lock<std::mutex> lock(stateMutex_);
      auto balVec = std::move(vec.get());
      totalBalance_ = balVec[0];
      spendableBalance_ = balVec[1];
      unconfirmedBalance_ = balVec[2];
   };
   asyncWlt_->getBalancesAndCount(topBlockHeight, lbd);
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::extendAddressChain(unsigned count,
   const std::function<void(int)>& progFunc)
{
   wallet_->extendPublicChain(accountId_, count, progFunc);
}

////
void WalletContainer::extendAddressChainToIndex(unsigned count)
{
   wallet_->extendPublicChainToIndex(accountId_, count);
}

////////////////////////////////////////////////////////////////////////////////
bool WalletContainer::hasAddress(const BinaryData& addr)
{
   return wallet_->hasScrAddr(addr);
}

////////////////////////////////////////////////////////////////////////////////
bool WalletContainer::hasAddress(const std::string& addr)
{
   return wallet_->hasAddrStr(addr);
}

////////////////////////////////////////////////////////////////////////////////
void WalletContainer::getUTXOs(uint64_t val, bool zc, bool rbf,
   const std::function<void(ReturnMessage<std::vector<UTXO>>)>& lbd)
{
   asyncWlt_->getUTXOs(val, zc, rbf, lbd);
}

////////////////////////////////////////////////////////////////////////////////
const Wallets::EncryptionKeyId& WalletContainer::getDefaultEncryptionKeyId() const
{
   return wallet_->getDefaultEncryptionKeyId();
}

////////////////////////////////////////////////////////////////////////////////
std::filesystem::path WalletContainer::forkWatchingOnly(
   const Passphrase::SetNew& ctrlPass)
{
   auto wltSingle = std::dynamic_pointer_cast<Wallets::AssetWallet_Single>(wallet_);
   if (wltSingle == nullptr) {
      throw std::runtime_error("unexpected wallet type");
   }
   auto wpd = Wallets::AssetWallet_Single::exportPublicData(wltSingle);
   return Wallets::AssetWallet_Single::forkWatchingOnly(wpd, ctrlPass);
}
