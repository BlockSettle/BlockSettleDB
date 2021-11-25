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
#include "WalletIdTypes.h"
#include "Script.h"
#include "Signer.h"

#include "DecryptedDataContainer.h"
#include "BIP32_Node.h"
#include "ResolverFeed.h"

#include "WalletHeader.h"
#include "Accounts/AccountTypes.h"
#include "Accounts/AddressAccounts.h"
#include "Accounts/MetaAccounts.h"


namespace Armory
{
   namespace Signer
   {
      class BIP32_AssetPath;
   };
};

////////////////////////////////////////////////////////////////////////////////
struct WalletPublicData
{
   const std::string dbName_;
   const std::string masterID_;
   const std::string walletID_;
   const Armory::Wallets::AddressAccountId mainAccountID_;

   std::shared_ptr<AssetEntry_Single> pubRoot_;
   std::map<Armory::Wallets::AddressAccountId,
      AddressAccountPublicData> accounts_;
   std::map<MetaAccountType, std::shared_ptr<MetaDataAccount>> metaAccounts_;
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
   std::map<Armory::Wallets::AddressAccountId,
      std::shared_ptr<AddressAccount>> accounts_;
   std::map<MetaAccountType,
      std::shared_ptr<MetaDataAccount>> metaDataAccounts_;

   Armory::Wallets::AddressAccountId mainAccount_;

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
      const std::string&, bool, const PassphraseLambda&);

   //locals

   //address type methods
   AddressEntryType getAddrTypeForAccount(
      const Armory::Wallets::AssetId&) const;

   void loadMetaAccounts(void);

   //virtual
   virtual void readFromFile(void) = 0;

   //static
   static BinaryDataRef getDataRefForKey(
      DBIfaceTransaction*, const BinaryData& key);

public:
   //tors
   virtual ~AssetWallet() = 0;
   void shutdown(void);

   //local
   std::shared_ptr<AddressEntry> getNewAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewAddress(
      const Armory::Wallets::AddressAccountId&,
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewAddress(
      const Armory::Wallets::AssetAccountId&,
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> getNewChangeAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   std::shared_ptr<AddressEntry> peekNextChangeAddress(
      AddressEntryType aeType = AddressEntryType_Default);
   void updateAddressEntryType(const Armory::Wallets::AssetId&,
      AddressEntryType);

   std::string getID(void) const;
   virtual ReentrantLock lockDecryptedContainer(void);
   bool isDecryptedContainerLocked(void) const;
   
   std::shared_ptr<AssetEntry> getAssetForID(
      const Armory::Wallets::AssetId&) const;
   
   void extendPublicChain(unsigned);
   void extendPublicChainToIndex(
      const Armory::Wallets::AddressAccountId&, unsigned);
   
   void extendPrivateChain(unsigned);
   void extendPrivateChainToIndex(
      const Armory::Wallets::AddressAccountId&, unsigned);

   bool hasScrAddr(const BinaryData& scrAddr) const;
   bool hasAddrStr(const std::string& scrAddr) const;

   const std::pair<Armory::Wallets::AssetId, AddressEntryType>&
      getAssetIDForAddrStr(const std::string& scrAddr) const;
   const std::pair<Armory::Wallets::AssetId, AddressEntryType>&
      getAssetIDForScrAddr(const BinaryData& scrAddr) const;

   AddressEntryType getAddrTypeForID(
      const Armory::Wallets::AssetId&) const;
   std::shared_ptr<AddressEntry> getAddressEntryForID(
      const Armory::Wallets::AssetId&) const;

   void setPassphrasePromptLambda(PassphraseLambda lambda)
   {
      decryptedData_->setPassphrasePromptLambda(lambda);
   }
   
   void resetPassphrasePromptLambda(void)
   {
      decryptedData_->resetPassphraseLambda();
   }

   void addMetaAccount(MetaAccountType);
   std::shared_ptr<MetaDataAccount> getMetaAccount(MetaAccountType) const;
   std::shared_ptr<AddressAccount> getAccountForID(
      const Armory::Wallets::AddressAccountId& ID) const;
   
   const std::string& getDbFilename(void) const;
   const std::string& getDbName(void) const;

   std::set<Armory::Wallets::AddressAccountId> getAccountIDs(void) const;
   std::map<Armory::Wallets::AssetId, std::shared_ptr<AddressEntry>> 
      getUsedAddressMap(void) const;

   std::shared_ptr<AddressAccount> createAccount(
      std::shared_ptr<AccountType>);

   void addSubDB(const std::string& dbName, const PassphraseLambda&);
   std::shared_ptr<WalletIfaceTransaction> beginSubDBTransaction(
      const std::string&, bool);

   void changeControlPassphrase(
      const std::function<SecureBinaryData(void)>&,
      const PassphraseLambda&);
   void eraseControlPassphrase(const PassphraseLambda&);

   void setComment(const BinaryData&, const std::string&);
   const std::string& getComment(const BinaryData&) const;
   std::map<BinaryData, std::string> getCommentMap(void) const;
   void deleteComment(const BinaryData&);

   const Armory::Wallets::AddressAccountId& getMainAccountID(void) const;

   void setLabel(const std::string&);
   void setDescription(const std::string&);

   const std::string& getLabel(void) const;
   const std::string& getDescription(void) const;

   std::shared_ptr<WalletDBInterface> getIface(void) const;

   //virtual
   virtual std::set<BinaryData> getAddrHashSet();
   virtual const SecureBinaryData& getDecryptedValue(
      std::shared_ptr<EncryptedAssetData>) = 0;
   virtual std::shared_ptr<AssetEntry> getRoot(void) const = 0;

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

   static std::shared_ptr<AssetWallet_Single> initWalletDbWithPubRoot(
      std::shared_ptr<WalletDBInterface> iface,
      const SecureBinaryData& controlPassphrase,
      const std::string& masterID, const std::string& walletID,
      std::shared_ptr<AssetEntry_Single> pubRoot);

private:
   static WalletPublicData exportPublicData(
      std::shared_ptr<AssetWallet_Single>);
   static void importPublicData(const WalletPublicData&,
      std::shared_ptr<WalletDBInterface>);

   void setSeed(const SecureBinaryData&, const SecureBinaryData&);

public:
   //tors
   AssetWallet_Single(std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<WalletHeader>, const std::string&);

   //locals
   void addPrivateKeyPassphrase(const std::function<SecureBinaryData(void)>&);
   void changePrivateKeyPassphrase(const std::function<SecureBinaryData(void)>&);
   void erasePrivateKeyPassphrase(void);

   std::shared_ptr<AssetEntry> getRoot(void) const override { return root_; }
   const SecureBinaryData& getPublicRoot(void) const;
   const SecureBinaryData& getArmory135Chaincode(void) const;
   
   const Armory::Wallets::AddressAccountId& createBIP32Account(
      std::shared_ptr<AccountType_BIP32>);

   bool isWatchingOnly(void) const;

   const SecureBinaryData& getDecryptedPrivateKeyForAsset(
      std::shared_ptr<AssetEntry_Single>);
   const Armory::Wallets::AssetId& derivePrivKeyFromPath(
      const Armory::Signer::BIP32_AssetPath&);
   const SecureBinaryData& getDecrypedPrivateKeyForId(
      const Armory::Wallets::AssetId&) const;

   std::shared_ptr<EncryptedSeed> getEncryptedSeed(void) const
   { return seed_; }

   Armory::Signer::BIP32_AssetPath getBip32PathForAsset(
      std::shared_ptr<AssetEntry>) const;
   Armory::Signer::BIP32_AssetPath getBip32PathForAssetID(
      const Armory::Wallets::AssetId&) const;

   std::string getXpubForAssetID(const Armory::Wallets::AssetId&) const;
   std::shared_ptr<AccountType_BIP32> makeNewBip32AccTypeObject(
      const std::vector<uint32_t>&) const;

   //virtual
   const SecureBinaryData& getDecryptedValue(
      std::shared_ptr<EncryptedAssetData>);

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

   static std::shared_ptr<AssetWallet_Single> createBlank(
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
      std::shared_ptr<EncryptedAssetData>);

public:
   //tors
   AssetWallet_Multisig(std::shared_ptr<WalletDBInterface>,
      std::shared_ptr<WalletHeader>, const std::string&);

   //virtual
   bool setImport(int importID, const SecureBinaryData& pubkey);
   std::shared_ptr<AssetEntry> getRoot(void) const override {return nullptr;}

   static std::shared_ptr<AssetWallet> createFromWallets(
      std::vector<std::shared_ptr<AssetWallet>> wallets,
      unsigned M,
      unsigned lookup = UINT32_MAX);

   //local
};

#endif
