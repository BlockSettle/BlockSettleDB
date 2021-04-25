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

#include "../../ReentrantLock.h"

#define ASSET_ACCOUNT_PREFIX     0xE1
#define ASSET_COUNT_PREFIX       0xE2
#define ASSET_TOP_INDEX_PREFIX   0xE3

////////////////////////////////////////////////////////////////////////////////
class DBIfaceTransaction;
class WalletDBInterface;
using WriteTxFuncType = 
   std::function<std::unique_ptr<DBIfaceTransaction>(const std::string&)>;

class DerivationScheme;

////////////////////////////////////////////////////////////////////////////////
struct AssetAccountData
{
public:
   BinaryData id_;
   BinaryData parentId_;

   std::shared_ptr<AssetEntry> root_;
   std::shared_ptr<DerivationScheme> derScheme_;

   const std::string dbName_;

   std::map<unsigned, std::shared_ptr<AssetEntry>> assets_;
   unsigned lastUsedIndex_ = UINT32_MAX;

   //<assetID, <address type, prefixed address hash>>
   std::map<BinaryData, std::map<AddressEntryType, BinaryData>> addrHashMap_;
   unsigned lastHashedAsset_ = UINT32_MAX;

public:
   AssetAccountData(
      const BinaryData& id,
      const BinaryData& parentId,
      std::shared_ptr<AssetEntry> root,
      std::shared_ptr<DerivationScheme> scheme,
      const std::string& dbName) :
      id_(id), parentId_(parentId), 
      root_(root), derScheme_(scheme),
      dbName_(dbName)
   {}
};

////
struct AccountDataStruct
{
   AssetAccountTypeEnum type_;
   std::shared_ptr<AssetAccountData> accountData_;
};

////////////////////////////////////////////////////////////////////////////////
class AssetAccount : protected Lockable
{
   friend class AssetAccount_ECDH;
   friend class AddressAccount;

private:
   std::shared_ptr<AssetAccountData> data_;
   const WriteTxFuncType getWriteTx_;

private:
   size_t writeAssetEntry(std::shared_ptr<AssetEntry>);
   void updateOnDiskAssets(void);

   void updateHighestUsedIndex(void);
   unsigned getAndBumpHighestUsedIndex(void);

   virtual void commit(void);
   void updateAssetCount(void);

   void extendPublicChainToIndex(unsigned);
   void extendPublicChain(std::shared_ptr<AssetEntry>, unsigned);
   std::vector<std::shared_ptr<AssetEntry>> extendPublicChain(
      std::shared_ptr<AssetEntry>, unsigned, unsigned);

   void extendPrivateChain(
      std::shared_ptr<DecryptedDataContainer>,
      unsigned);
   void extendPrivateChainToIndex(
      std::shared_ptr<DecryptedDataContainer>,
      unsigned);
   void extendPrivateChain(
      std::shared_ptr<DecryptedDataContainer>,
      std::shared_ptr<AssetEntry>, unsigned);
   std::vector<std::shared_ptr<AssetEntry>> extendPrivateChain(
      std::shared_ptr<DecryptedDataContainer>,
      std::shared_ptr<AssetEntry>,
      unsigned, unsigned);

   std::shared_ptr<AssetEntry> getNewAsset(void);
   std::shared_ptr<AssetEntry> peekNextAsset(void);
   std::shared_ptr<Asset_PrivateKey> fillPrivateKey(
      std::shared_ptr<DecryptedDataContainer> ddc,
      const BinaryData& id);

   virtual unsigned getLookup(void) const;
   virtual AssetAccountTypeEnum type(void) const { return AssetAccountTypeEnum_Plain; }

public:
   AssetAccount(
      std::shared_ptr<AssetAccountData> data,
      const WriteTxFuncType& txFunc) :
      data_(data), getWriteTx_(txFunc)
   {
      if (data == nullptr)
         throw std::runtime_error("null account data ptr");
   }

   size_t getAssetCount(void) const;
   int getLastComputedIndex(void) const;
   unsigned getHighestUsedIndex(void) const;
   std::shared_ptr<AssetEntry> getLastAssetWithPrivateKey(void) const;

   std::shared_ptr<AssetEntry> getAssetForID(const BinaryData&) const;
   std::shared_ptr<AssetEntry> getAssetForIndex(unsigned id) const;

   void updateAddressHashMap(const std::set<AddressEntryType>&);
   const std::map<BinaryData, std::map<AddressEntryType, BinaryData>>&
      getAddressHashMap(const std::set<AddressEntryType>&);

   const BinaryData& getID(void) const;
   BinaryData getFullID(void) const;

   const SecureBinaryData& getChaincode(void) const;
   std::shared_ptr<AssetEntry> getRoot(void) const;

   void extendPublicChain(unsigned);

   //static
   static AccountDataStruct loadFromDisk(const BinaryData& key,
      std::shared_ptr<WalletDBInterface>, const std::string&);

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

   void commit(void) override;

public:
   AssetAccount_ECDH(
      std::shared_ptr<AssetAccountData> data,
      const WriteTxFuncType& txFunc) :
      AssetAccount(data, txFunc)
   {}

   unsigned addSalt(const SecureBinaryData&);
   unsigned getSaltIndex(const SecureBinaryData&) const;
};

#endif