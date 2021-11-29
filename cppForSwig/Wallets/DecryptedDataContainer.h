////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_DECRYPTED_DATA_CONTAINER
#define _H_DECRYPTED_DATA_CONTAINER

#include <functional>

#include "Assets.h"
#include "ReentrantLock.h"
#include "BinaryData.h"
#include "PassphraseLambda.h"

#define ENCRYPTIONKEY_PREFIX        0xC0
#define ENCRYPTIONKEY_PREFIX_TEMP   0xCC

////////////////////////////////////////////////////////////////////////////////
class AssetUnavailableException
{};

class DecryptedDataContainerException : public std::runtime_error
{
public:
   DecryptedDataContainerException(const std::string& msg) :
      std::runtime_error(msg)
   {}
};

class EncryptedDataMissing : public std::runtime_error
{
public:
   EncryptedDataMissing() : std::runtime_error("")
   {}
};

////////////////////////////////////////////////////////////////////////////////
namespace Armory
{
   namespace Wallets
   {
      namespace IO
      {
         class DBIfaceTransaction;
      };
   };
};

using WriteTxFuncType = std::function<std::unique_ptr<
   Armory::Wallets::IO::DBIfaceTransaction>(const std::string&)>;

////
class DecryptedDataContainer : public Lockable
{
private:
   struct DecryptedDataMaps
   {
      std::map<Armory::Wallets::EncryptionKeyId,
         std::unique_ptr<Armory::Assets::ClearTextEncryptionKey>> encryptionKeys_;

      std::map<Armory::Wallets::AssetId,
         std::unique_ptr<Armory::Assets::ClearTextAssetData>> assetData_;
   };

private:
   std::map<BinaryData,
      std::shared_ptr<Armory::Assets::KeyDerivationFunction>> kdfMap_ = {};
   std::unique_ptr<DecryptedDataMaps> lockedDecryptedData_ = nullptr;

   struct OtherLockedContainer
   {
      std::shared_ptr<DecryptedDataContainer> container_;
      std::shared_ptr<ReentrantLock> lock_;

      OtherLockedContainer(std::shared_ptr<DecryptedDataContainer> obj)
      {
         if (obj == nullptr)
            throw std::runtime_error("emtpy DecryptedDataContainer ptr");

         lock_ = make_unique<ReentrantLock>(obj.get());
      }
   };

   std::vector<OtherLockedContainer> otherLocks_ = {};

public:
   const WriteTxFuncType getWriteTx_;
   const std::string dbName_;

private:
   /*
   The default encryption key is used to encrypt the master encryption in
   case no passphrase was provided at wallet creation. This is to prevent
   for the master key being written in plain text on disk. It is encryption
   but does not effectively result in the wallet being protected by encryption,
   since the default encryption key is written on disk in plain text.

   This is mostly to allow for all private keys to be encrypted without 
   implementing large caveats to handle unencrypted use cases.
   */
   const SecureBinaryData defaultEncryptionKey_;
   const Armory::Wallets::EncryptionKeyId defaultEncryptionKeyId_;
   
   const SecureBinaryData defaultKdfId_;
   const Armory::Wallets::EncryptionKeyId masterEncryptionKeyId_;


protected:
   std::map<Armory::Wallets::EncryptionKeyId,
      std::shared_ptr<Armory::Assets::EncryptionKey>> encryptedKeys_;

private:
   PassphraseLambda getPassphraseLambda_;

private:
   std::unique_ptr<Armory::Assets::ClearTextEncryptionKey> deriveEncryptionKey(
      std::unique_ptr<Armory::Assets::ClearTextEncryptionKey>,
      const BinaryData& kdfid) const;

   std::unique_ptr<Armory::Assets::ClearTextEncryptionKey> promptPassphrase(
      const std::map<Armory::Wallets::EncryptionKeyId, BinaryData>&) const;

   void initAfterLock(void);
   void cleanUpBeforeUnlock(void);

   const Armory::Wallets::EncryptionKeyId& getDefaultEncryptionKeyId(void) const
   {
      return defaultEncryptionKeyId_;
   }

public:
   DecryptedDataContainer(
      const WriteTxFuncType& getWriteTx,
      const std::string dbName,
      const SecureBinaryData& defaultEncryptionKey,
      const Armory::Wallets::EncryptionKeyId& defaultEncryptionKeyId,
      const SecureBinaryData& defaultKdfId,
      const Armory::Wallets::EncryptionKeyId& masterKeyId);

   const SecureBinaryData& getClearTextAssetData(
      const std::shared_ptr<Armory::Assets::EncryptedAssetData>& data);
   const SecureBinaryData& getClearTextAssetData(
      const Armory::Assets::EncryptedAssetData* data);
   const SecureBinaryData& getClearTextAssetData(
      const Armory::Wallets::AssetId&) const;
   const Armory::Wallets::AssetId& insertClearTextAssetData(
      const uint8_t*, size_t);

   SecureBinaryData encryptData(
      Armory::Assets::Cipher* const cipher, const SecureBinaryData& data);

   Armory::Wallets::EncryptionKeyId populateEncryptionKey(
      const std::map<Armory::Wallets::EncryptionKeyId, BinaryData>&);

   void addKdf(std::shared_ptr<Armory::Assets::KeyDerivationFunction> kdfPtr)
   {
      kdfMap_.insert(std::make_pair(kdfPtr->getId(), kdfPtr));
   }

   void addEncryptionKey(std::shared_ptr<Armory::Assets::EncryptionKey> keyPtr)
   {
      encryptedKeys_.insert(std::make_pair(keyPtr->getId(), keyPtr));
   }

   void updateOnDisk(void);
   void updateOnDisk(std::unique_ptr<Armory::Wallets::IO::DBIfaceTransaction>);
   void readFromDisk(std::shared_ptr<Armory::Wallets::IO::DBIfaceTransaction>);

   void updateOnDiskRaw(std::shared_ptr<Armory::Wallets::IO::DBIfaceTransaction>,
      const BinaryData&, std::shared_ptr<Armory::Assets::EncryptionKey>);
   void updateOnDisk(std::shared_ptr<Armory::Wallets::IO::DBIfaceTransaction>,
      const Armory::Wallets::EncryptionKeyId&,
      std::shared_ptr<Armory::Assets::EncryptionKey>);
   void deleteFromDisk(std::shared_ptr<Armory::Wallets::IO::DBIfaceTransaction>, const BinaryData&);

   void setPassphrasePromptLambda(const PassphraseLambda& lambda)
   {
      getPassphraseLambda_ = lambda;
   }

   void resetPassphraseLambda(void) { getPassphraseLambda_ = nullptr; }

   void encryptEncryptionKey(
      const Armory::Wallets::EncryptionKeyId& keyID, const BinaryData& kdfID,
      const std::function<SecureBinaryData(void)>&, bool replace = true);
   void eraseEncryptionKey(
      const Armory::Wallets::EncryptionKeyId& keyID, const BinaryData& kdfID);

   void lockOther(std::shared_ptr<DecryptedDataContainer> other);

   const SecureBinaryData& getDefaultKdfId(void) const { return defaultKdfId_; }
   const Armory::Wallets::EncryptionKeyId& getMasterEncryptionKeyId(void) const
   {
      return masterEncryptionKeyId_;
   }
};

#endif
