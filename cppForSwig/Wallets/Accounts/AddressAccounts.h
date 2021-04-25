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

////
class WalletDBInterface;
class DBIfaceTransaction;
using WriteTxFuncType = 
   std::function<std::unique_ptr<DBIfaceTransaction>(const std::string&)>;

////////////////////////////////////////////////////////////////////////////////
class AddressAccount : public Lockable
{
   friend class AssetWallet;
   friend class AssetWallet_Single;

private:
   std::map<BinaryData, AccountDataStruct> accountDataMap_;
   std::map<BinaryData, AddressEntryType> addresses_;

private:
   BinaryData outerAccount_;
   BinaryData innerAccount_;

   AddressEntryType defaultAddressEntryType_ = AddressEntryType_P2PKH;
   std::set<AddressEntryType> addressTypes_;

   //<prefixed address hash, <assetID, address type>>
   std::map<BinaryData, std::pair<BinaryData, AddressEntryType>> addressHashes_;

   //account id, asset id
   std::map<BinaryData, BinaryData> topHashedAssetId_;

   BinaryData ID_;

   const WriteTxFuncType getWriteTx_;
   const std::string dbName_;

private:
   //used for initial commit to disk
   void commit(std::shared_ptr<WalletDBInterface>);
   void reset(void);

   void addAccount(std::shared_ptr<AssetAccount>);
   void addAccount(AccountDataStruct&);

   void updateInstantiatedAddressType(
      std::shared_ptr<AddressEntry>);
   void updateInstantiatedAddressType(
      const BinaryData&, AddressEntryType);
   void eraseInstantiatedAddressType(
      const BinaryData&);

   void writeAddressType(
      const BinaryData&, AddressEntryType);
   void writeAddressType(std::shared_ptr<DBIfaceTransaction>,
      const BinaryData&, AddressEntryType);

   std::shared_ptr<Asset_PrivateKey> fillPrivateKey(
      std::shared_ptr<DecryptedDataContainer> ddc,
      const BinaryData& id);

   std::shared_ptr<AssetEntry_BIP32Root> getBip32RootForAssetId(
      const BinaryData&) const;

   const AccountDataStruct& getAccountDataForID(
      const BinaryData&) const;

public:
   AddressAccount(
      const std::string& dbName,
      const WriteTxFuncType& getWriteTx) :
      dbName_(dbName), getWriteTx_(getWriteTx)
   {}

   const BinaryData& getID(void) const { return ID_; }

   void make_new(
      std::shared_ptr<AccountType>,
      std::shared_ptr<DecryptedDataContainer>,
      std::unique_ptr<Cipher>);

   void readFromDisk(
      std::shared_ptr<WalletDBInterface>, 
      const BinaryData& key);

   void extendPublicChain(unsigned);
   void extendPublicChainToIndex(const BinaryData&, unsigned);

   void extendPrivateChain(
      std::shared_ptr<DecryptedDataContainer>,
      unsigned);
   void extendPrivateChainToIndex(
      std::shared_ptr<DecryptedDataContainer>,
      const BinaryData&, unsigned);

   std::shared_ptr<AddressEntry> getNewAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewChangeAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> peekNextChangeAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewAddress(
      const BinaryData& account, AddressEntryType aeType);
   std::shared_ptr<AssetEntry> getOutterAssetForIndex(unsigned) const;
   std::shared_ptr<AssetEntry> getOutterAssetRoot(void) const;


   AddressEntryType getAddressType(void) const
      { return defaultAddressEntryType_; }
   std::set<AddressEntryType> getAddressTypeSet(void) const
      { return addressTypes_; }
   bool hasAddressType(AddressEntryType);

   //get asset by binary string ID
   std::shared_ptr<AssetEntry> getAssetForID(const BinaryData&) const;

   //get asset by integer ID; bool arg defines whether it comes from the
   //outer account (true) or the inner account (false)
   std::shared_ptr<AssetEntry> getAssetForID(unsigned, bool) const;

   const std::pair<BinaryData, AddressEntryType>& 
      getAssetIDPairForAddr(const BinaryData&);
   const std::pair<BinaryData, AddressEntryType>& 
      getAssetIDPairForAddrUnprefixed(const BinaryData&);

   void updateAddressHashMap(void);
   const std::map<BinaryData, std::pair<BinaryData, AddressEntryType>>& 
      getAddressHashMap(void);

   std::set<BinaryData> getAccountIdSet(void) const;
   std::unique_ptr<AssetAccount> getAccountForID(const BinaryData&) const;
   std::unique_ptr<AssetAccount> getOuterAccount(void) const;
   const BinaryData& getOuterAccountID(void) const { return outerAccount_; }
   const BinaryData& getInnerAccountID(void) const { return innerAccount_; }

   std::shared_ptr<AddressAccount> getWatchingOnlyCopy(
      const std::string&) const;

   std::shared_ptr<AddressEntry> getAddressEntryForID(
      const BinaryDataRef&) const;
   std::map<BinaryData, std::shared_ptr<AddressEntry>> 
      getUsedAddressMap(void) const;

   //Lockable virtuals
   void initAfterLock(void) {}
   void cleanUpBeforeUnlock(void) {}

   bool hasBip32Path(const ArmorySigner::BIP32_AssetPath&) const;
};

#endif