////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2019, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _WALLETS_H
#define _WALLETS_H

#include <atomic>
#include <thread>
#include <memory>
#include <set>
#include <map>
#include <string>

#include "ReentrantLock.h"
#include "BinaryData.h"
#include "EncryptionUtils.h"
#include "Script.h"
#include "Signer.h"

#include "DecryptedDataContainer.h"
#include "BIP32_Node.h"
#include "ResolverFeed.h"

#include "WalletHeader.h"
#include "Accounts/AccountTypes.h"
#include "Accounts/AddressAccounts.h"
#include "Accounts/MetaAccounts.h"


////////////////////////////////////////////////////////////////////////////////
struct WalletPublicData
{
   std::shared_ptr<AssetEntry_Single> pubRoot_;
   std::map<BinaryData, AddressAccountPublicData> accounts_;
   std::map<MetaAccountType, std::shared_ptr<MetaDataAccount>> metaAccounts_;

   std::string dbName_;
   std::string walletID_;
   std::string masterID_;

   BinaryData mainAccountID_;
};

////
class WalletDBInterface;

////////////////////////////////////////////////////////////////////////////////
class AssetWallet : protected Lockable
{
   friend class ResolverFeed_AssetWalletSingle;
   friend class ResolverFeed_AssetWalletSingle_ForMultisig;

private:
   virtual void initAfterLock(void) {}
   virtual void cleanUpBeforeUnlock(void) {}
   
   static std::string getMasterID(std::shared_ptr<WalletDBInterface>);
   void checkMasterID(const std::string& masterID);

protected:
   std::shared_ptr<WalletDBInterface> iface_;
   const std::string dbName_;

   std::shared_ptr<DecryptedDataContainer> decryptedData_;
   std::map<BinaryData, std::shared_ptr<AddressAccount>> accounts_;
   std::map<MetaAccountType, std::shared_ptr<MetaDataAccount>> metaDataAccounts_;
   BinaryData mainAccount_;

   ////
   std::string walletID_;
   std::string masterID_;

   ////
   std::string label_;
   std::string description_;
   
protected:
   //tors
   AssetWallet(std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<WalletHeader>, 
      const std::string&);

   static std::shared_ptr<WalletDBInterface> getIfaceFromFile(
      const std::string&, const PassphraseLambda&);

   //locals

   //address type methods
   AddressEntryType getAddrTypeForAccount(const BinaryData& ID);

   void loadMetaAccounts(void);

   //virtual
   virtual void updateHashMap(void);
   virtual void readFromFile(void) = 0;

   //static
   static BinaryDataRef getDataRefForKey(
      DBIfaceTransaction*, const BinaryData& key);

public:
   //tors
   virtual ~AssetWallet() = 0;

   //local
   std::shared_ptr<AddressEntry> getNewAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewAddress(const BinaryData& accountID,
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewChangeAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> peekNextChangeAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   void updateAddressEntryType(const BinaryData&, AddressEntryType);

   std::string getID(void) const;
   virtual ReentrantLock lockDecryptedContainer(void);
   bool isDecryptedContainerLocked(void) const;
   
   std::shared_ptr<AssetEntry> getAssetForID(const BinaryData&) const;
   
   void extendPublicChain(unsigned);
   void extendPublicChainToIndex(const BinaryData&, unsigned);
   
   void extendPrivateChain(unsigned);
   void extendPrivateChainToIndex(const BinaryData&, unsigned);

   bool hasScrAddr(const BinaryData& scrAddr) const;
   bool hasAddrStr(const std::string& scrAddr) const;

   const std::pair<BinaryData, AddressEntryType>& 
      getAssetIDForAddrStr(const std::string& scrAddr) const;
   const std::pair<BinaryData, AddressEntryType>&
      getAssetIDForScrAddr(const BinaryData& scrAddr) const;

   AddressEntryType getAddrTypeForID(const BinaryData& ID);
   std::shared_ptr<AddressEntry> 
      getAddressEntryForID(const BinaryData&) const;
   void shutdown(void);

   void setPassphrasePromptLambda(
      std::function<SecureBinaryData(const std::set<BinaryData>&)> lambda)
   {
      decryptedData_->setPassphrasePromptLambda(lambda);
   }
   
   void resetPassphrasePromptLambda(void)
   {
      decryptedData_->resetPassphraseLambda();
   }

   void addMetaAccount(MetaAccountType);
   std::shared_ptr<MetaDataAccount> getMetaAccount(MetaAccountType) const;
   std::shared_ptr<AddressAccount> getAccountForID(const BinaryData& ID) const;
   
   const std::string& getDbFilename(void) const;
   const std::string& getDbName(void) const;

   std::set<BinaryData> getAccountIDs(void) const;
   std::map<BinaryData, std::shared_ptr<AddressEntry>> 
      getUsedAddressMap(void) const;

   std::shared_ptr<AddressAccount> 
      createAccount(std::shared_ptr<AccountType>);

   void addSubDB(const std::string& dbName, const PassphraseLambda&);
   std::shared_ptr<DBIfaceTransaction> beginSubDBTransaction(
      const std::string&, bool);

   void changeControlPassphrase(
      const std::function<SecureBinaryData(void)>&,
      const PassphraseLambda&);
   void eraseControlPassphrase(const PassphraseLambda&);

   void setComment(const BinaryData&, const std::string&);
   const std::string& getComment(const BinaryData&) const;
   std::map<BinaryData, std::string> getCommentMap(void) const;
   void deleteComment(const BinaryData&);

   const BinaryData& getMainAccountID(void) const { return mainAccount_; }

   void setLabel(const std::string&);
   void setDescription(const std::string&);

   const std::string& getLabel(void) const;
   const std::string& getDescription(void) const;

   std::shared_ptr<WalletDBInterface> getIface(void) const;

   //virtual
   virtual std::set<BinaryData> getAddrHashSet();
   virtual const SecureBinaryData& getDecryptedValue(
      std::shared_ptr<Asset_EncryptedData>) = 0;

   //static
   static void setMainWallet(
      std::shared_ptr<WalletDBInterface>, const std::string&);
   static std::string getMainWalletID(std::shared_ptr<WalletDBInterface>);
  
   static std::string forkWatchingOnly(
      const std::string&, const PassphraseLambda& = nullptr);
   static std::shared_ptr<AssetWallet> loadMainWalletFromFile(
      const std::string& path, const PassphraseLambda&);

   static void eraseFromDisk(AssetWallet*);
};

////////////////////////////////////////////////////////////////////////////////
class AssetWallet_Single : public AssetWallet
{
   friend class AssetWallet;
   friend class AssetWallet_Multisig;

protected:
   std::shared_ptr<AssetEntry_Single> root_ = nullptr;
   std::shared_ptr<EncryptedSeed> seed_ = nullptr;

protected:
   //virtual
   void readFromFile(void);

   //static
   static std::shared_ptr<AssetWallet_Single> initWalletDb(
      std::shared_ptr<WalletDBInterface> iface,
      const std::string& masterID, const std::string& walletID,
      const SecureBinaryData& passphrase,
      const SecureBinaryData& controlPassphrase,
      const SecureBinaryData& privateRoot,
      const SecureBinaryData& chaincode,
      uint32_t seedFingerprint);

   static std::shared_ptr<AssetWallet_Single> initWalletDbFromPubRoot(
      std::shared_ptr<WalletDBInterface> iface,
      const SecureBinaryData& controlPassphrase,
      const std::string& masterID, const std::string& walletID,
      SecureBinaryData& pubRoot);

private:
   static void copyPublicData(
      std::shared_ptr<AssetWallet_Single>, std::shared_ptr<WalletDBInterface>);
   static WalletPublicData exportPublicData(
      std::shared_ptr<AssetWallet_Single>);

   void setSeed(const SecureBinaryData&, const SecureBinaryData&);

public:
   //tors
   AssetWallet_Single(std::shared_ptr<WalletDBInterface> iface,
      std::shared_ptr<WalletHeader> metaPtr, const std::string& masterID) :
      AssetWallet(iface, metaPtr, masterID)
   {}

   //locals
   void addPrivateKeyPassphrase(const std::function<SecureBinaryData(void)>&);
   void changePrivateKeyPassphrase(const std::function<SecureBinaryData(void)>&);
   void erasePrivateKeyPassphrase(void);

   std::shared_ptr<AssetEntry_Single> getRoot(void) const { return root_; }
   const SecureBinaryData& getPublicRoot(void) const;
   std::shared_ptr<AssetEntry> getAccountRoot(const BinaryData& accountID) const;
   const SecureBinaryData& getArmory135Chaincode(void) const;
   
   const BinaryData& createBIP32Account(
      std::shared_ptr<AccountType_BIP32>);
   const BinaryData& createBIP32Account_WithParent(
      std::shared_ptr<AssetEntry_BIP32Root> parentNode,
      std::shared_ptr<AccountType_BIP32>);

   bool isWatchingOnly(void) const;

   std::shared_ptr<AssetEntry> getMainAccountAssetForIndex(unsigned) const;
   unsigned getMainAccountAssetCount(void) const;

   const SecureBinaryData& getDecryptedPrivateKeyForAsset(
      std::shared_ptr<AssetEntry_Single>);
   const BinaryData& derivePrivKeyFromPath(const ArmorySigner::BIP32_AssetPath&);
   const SecureBinaryData& getDecrypedPrivateKeyForId(const BinaryData&) const;

   std::shared_ptr<EncryptedSeed> getEncryptedSeed(void) const { return seed_; }

   ArmorySigner::BIP32_AssetPath getBip32PathForAsset(std::shared_ptr<AssetEntry>) const;
   ArmorySigner::BIP32_AssetPath getBip32PathForAssetID(const BinaryData&) const;

   std::string getXpubForAssetID(const BinaryData&) const;

   //virtual
   const SecureBinaryData& getDecryptedValue(
      std::shared_ptr<Asset_EncryptedData>);

   //static
   static std::shared_ptr<AssetWallet_Single> createFromBIP32Node(
      const BIP32_Node& node,
      std::set<std::shared_ptr<AccountType_BIP32>> accountTypes,
      const SecureBinaryData& passphrase,
      const SecureBinaryData& controlPassphrase,
      const std::string& folder);

   static std::shared_ptr<AssetWallet_Single> createFromPrivateRoot_Armory135(
      const std::string& folder,
      const SecureBinaryData& privateRoot,
      SecureBinaryData chaincode, 
      const SecureBinaryData& passphrase,
      const SecureBinaryData& controlPassphrase,
      unsigned lookup);

   static std::shared_ptr<AssetWallet_Single> createFromPublicRoot_Armory135(
      const std::string& folder,
      SecureBinaryData& privateRoot,
      SecureBinaryData& chainCode,
      const SecureBinaryData& controlPassphrase,
      unsigned lookup);

   static std::shared_ptr<AssetWallet_Single> createFromSeed_BIP32(
      const std::string& folder,
      const SecureBinaryData& seed,
      const SecureBinaryData& passphrase,
      const SecureBinaryData& controlPassphrase,
      unsigned lookup);

   static std::shared_ptr<AssetWallet_Single> createFromSeed_BIP32_Blank(
      const std::string& folder,
      const SecureBinaryData& seed,
      const SecureBinaryData& passphrase,
      const SecureBinaryData& controlPassphrase);

   static std::shared_ptr<AssetWallet_Single> createSeedless_WatchingOnly(
      const std::string& folder,
      const std::string& walletID,
      const SecureBinaryData& controlPassphrase);

   static std::string computeWalletID(
      std::shared_ptr<DerivationScheme>,
      std::shared_ptr<AssetEntry>);
};

////////////////////////////////////////////////////////////////////////////////
class AssetWallet_Multisig : public AssetWallet
{
   friend class AssetWallet;

private:
   std::atomic<unsigned> chainLength_;

protected:

   //virtual
   void readFromFile(void);
   const SecureBinaryData& getDecryptedValue(
      std::shared_ptr<Asset_EncryptedData>);

public:
   //tors
   AssetWallet_Multisig(std::shared_ptr<WalletDBInterface> iface,
      std::shared_ptr<WalletHeader> metaPtr, const std::string& masterID) :
      AssetWallet(iface, metaPtr, masterID)
   {}

   //virtual
   bool setImport(int importID, const SecureBinaryData& pubkey);

   static std::shared_ptr<AssetWallet> createFromWallets(
      std::vector<std::shared_ptr<AssetWallet>> wallets,
      unsigned M,
      unsigned lookup = UINT32_MAX);

   //local
};

#endif
