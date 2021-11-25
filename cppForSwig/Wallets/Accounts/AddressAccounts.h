////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_ADDRESS_ACCOUNTS
#define _H_ADDRESS_ACCOUNTS

#include <set>
#include <map>
#include <memory>


#include "../../ReentrantLock.h"
#include "../../BinaryData.h"
#include "../WalletIdTypes.h"
#include "../../EncryptionUtils.h"
#include "../Assets.h"
#include "../Addresses.h"
#include "../DerivationScheme.h"

#include "AssetAccounts.h"

#define BIP32_OUTER_ACCOUNT_DERIVATIONID 0x00000000
#define BIP32_INNER_ACCOUNT_DERIVATIONID 0x00000001

#define ADDRESS_ACCOUNT_PREFIX   0xD0

////////////////////////////////////////////////////////////////////////////////
struct UnrequestedAddressException
{};

////////////////////////////////////////////////////////////////////////////////
struct AddressAccountPublicData
{
   const Armory::Wallets::AddressAccountId ID_;

   const Armory::Wallets::AssetAccountId outerAccountId_;
   const Armory::Wallets::AssetAccountId innerAccountId_;

   AddressEntryType defaultAddressEntryType_ = AddressEntryType_P2PKH;
   std::set<AddressEntryType> addressTypes_;

   std::map<Armory::Wallets::AssetId,
      AddressEntryType> instantiatedAddressTypes_;

   //<accountID, <account data>
   std::map<Armory::Wallets::AssetAccountId,
      AssetAccountPublicData> accountDataMap_;

   AddressAccountPublicData(const Armory::Wallets::AddressAccountId&,
      const Armory::Wallets::AssetAccountId&,
      const Armory::Wallets::AssetAccountId&);
};

////
class WalletDBInterface;
class WalletIfaceTransaction;

////////////////////////////////////////////////////////////////////////////////
class AddressAccount : public Lockable
{
   friend class AssetWallet;
   friend class AssetWallet_Single;

private:
   const std::string dbName_;
   const Armory::Wallets::AddressAccountId ID_;

   std::map<Armory::Wallets::AssetAccountId,
      std::shared_ptr<AssetAccountData>> accountDataMap_;
   std::map<Armory::Wallets::AssetId,
      AddressEntryType> instantiatedAddressTypes_;

   Armory::Wallets::AssetAccountId outerAccountId_;
   Armory::Wallets::AssetAccountId innerAccountId_;

   AddressEntryType defaultAddressEntryType_ = AddressEntryType_P2PKH;
   std::set<AddressEntryType> addressTypes_;

   //<prefixed address hash, <assetID, address type>>
   std::map<BinaryData,
      std::pair<Armory::Wallets::AssetId, AddressEntryType>> addressHashes_;

   std::map<Armory::Wallets::AssetAccountId,
      Armory::Wallets::AssetId> topHashedAssetId_;

   //temp placeholder for fetching comments
   std::function<const std::string&(const BinaryData&)> getComment_ = nullptr;

private:
   AddressAccount(const std::string&,
      const Armory::Wallets::AddressAccountId&);

   //used for initial commit to disk
   void commit(std::shared_ptr<WalletDBInterface>);

   void addAccount(std::shared_ptr<AssetAccount>);
   void addAccount(std::shared_ptr<AssetAccountData>);

   void updateInstantiatedAddressType(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<AddressEntry>);
   void updateInstantiatedAddressType(
      std::shared_ptr<WalletDBInterface>,
      const Armory::Wallets::AssetId&, AddressEntryType);
   void eraseInstantiatedAddressType(
      std::shared_ptr<WalletDBInterface>,
      const Armory::Wallets::AssetId&);

   void writeAddressType(std::shared_ptr<WalletDBInterface>,
      const Armory::Wallets::AssetId&, AddressEntryType);
   void writeAddressType(std::shared_ptr<DBIfaceTransaction>,
      const Armory::Wallets::AssetId&, AddressEntryType);

   std::shared_ptr<Asset_PrivateKey> fillPrivateKey(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<DecryptedDataContainer> ddc,
      const Armory::Wallets::AssetId& id);

   std::shared_ptr<AssetEntry_BIP32Root> getBip32RootForAssetId(
      const Armory::Wallets::AssetId&) const;

   const std::shared_ptr<AssetAccountData>& getAccountDataForID(
      const Armory::Wallets::AssetAccountId&) const;

   bool isLegacy(void) const;

public:
   const Armory::Wallets::AddressAccountId& getID(void) const { return ID_; }

   static std::unique_ptr<AddressAccount> make_new(
      const std::string&,
      std::shared_ptr<AccountType>,
      std::shared_ptr<DecryptedDataContainer>,
      std::unique_ptr<Cipher>,
      const std::function<std::shared_ptr<AssetEntry>(void)>&);

   static std::unique_ptr<AddressAccount> readFromDisk(
      std::shared_ptr<WalletIfaceTransaction>,
      const Armory::Wallets::AddressAccountId&);

   void extendPublicChain(std::shared_ptr<WalletDBInterface>, unsigned);
   void extendPublicChain(std::shared_ptr<WalletDBInterface>,
      const Armory::Wallets::AssetAccountId&, unsigned);
   void extendPublicChainToIndex(std::shared_ptr<WalletDBInterface>,
      const Armory::Wallets::AssetAccountId&, unsigned);

   void extendPrivateChain(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<DecryptedDataContainer>,
      unsigned);
   void extendPrivateChainToIndex(
      std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<DecryptedDataContainer>,
      const Armory::Wallets::AssetAccountId&, unsigned);

   std::shared_ptr<AddressEntry> getNewAddress(
      std::shared_ptr<WalletDBInterface>,
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewAddress(
      std::shared_ptr<WalletDBInterface>,
      const Armory::Wallets::AssetAccountId&, AddressEntryType);
   std::shared_ptr<AddressEntry> getNewChangeAddress(
      std::shared_ptr<WalletDBInterface>,
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> peekNextChangeAddress(
      std::shared_ptr<WalletDBInterface>,
      AddressEntryType aeType = AddressEntryType_Default);
   bool isAssetChange(const Armory::Wallets::AssetId&) const;
   bool isAssetInUse(const Armory::Wallets::AssetId&) const;

   std::shared_ptr<AssetEntry> getOuterAssetRoot(void) const;


   AddressEntryType getDefaultAddressType(void) const
      { return defaultAddressEntryType_; }
   const std::set<AddressEntryType>& getAddressTypeSet(void) const
      { return addressTypes_; }
   bool hasAddressType(AddressEntryType);

   std::shared_ptr<AssetEntry> getAssetForID(
      const Armory::Wallets::AssetId&) const;

   const std::pair<Armory::Wallets::AssetId, AddressEntryType>&
      getAssetIDPairForAddr(const BinaryData&);
   const std::pair<Armory::Wallets::AssetId, AddressEntryType>&
      getAssetIDPairForAddrUnprefixed(const BinaryData&);

   void updateAddressHashMap(void);
   const std::map<BinaryData,
      std::pair<Armory::Wallets::AssetId, AddressEntryType>>&
         getAddressHashMap(void);

   std::set<Armory::Wallets::AssetAccountId> getAccountIdSet(void) const;
   std::unique_ptr<AssetAccount> getAccountForID(
      const Armory::Wallets::AssetId&) const;
   std::unique_ptr<AssetAccount> getAccountForID(
      const Armory::Wallets::AssetAccountId&) const;
   std::unique_ptr<AssetAccount> getOuterAccount(void) const;

   const Armory::Wallets::AssetAccountId& getOuterAccountID(void) const
   { return outerAccountId_; }
   const Armory::Wallets::AssetAccountId& getInnerAccountID(void) const
   { return innerAccountId_; }

   AddressAccountPublicData exportPublicData() const;
   void importPublicData(const AddressAccountPublicData&);

   std::shared_ptr<AddressEntry> getAddressEntryForID(
      const Armory::Wallets::AssetId&) const;
   std::map<Armory::Wallets::AssetId, std::shared_ptr<AddressEntry>>
      getUsedAddressMap(void) const;

   //Lockable virtuals
   void initAfterLock(void) {}
   void cleanUpBeforeUnlock(void) {}

   bool hasBip32Path(const ArmorySigner::BIP32_AssetPath&) const;
};

#endif