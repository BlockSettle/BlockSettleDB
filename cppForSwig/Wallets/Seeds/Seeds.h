////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2023, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once
#include "../AssetEncryption.h"

class BIP32_Node;
namespace Armory
{
   namespace Wallets
   {
      namespace Encryption
      {
         class DecryptedDataContainer;
      }
   }

   /*** Wallet creation diagram ***
                         Raw Entropy
                              |
                              v
      WalletBackup <---> ClearTextSeed <--------
                              |                 |
                              |                 |
                              v                 |
                           AssetWallet --> EncryptedSeed
   ***/

   namespace Seeds
   {
      //////////////////////////////////////////////////////////////////////////
      enum class SeedType : int
      {
         /*
         Armory135:
            For wallets using the legacy Armory derivation scheme.
         */
         Armory135         = 0,

         /*
         BIP32_Structured:
            For wallets carrying BIP44/49/84 accounts. Restores to a bip32 wallet
            with all these accounts.
         */
         BIP32_Structured  = 1,

         /*
         BIP32_Virgin:
            No info is provided about the wallet's structure, restores to an empty
            bip32 wallet.
         */
         BIP32_Virgin      = 15,

         /*
         BIP32_base58Root
            From a base58 of the wallet root. No info about the wallet structure.
            Cannot be extract as easy16. Mostly used to import HW roots.
         */
         BIP32_base58Root  = 16,

         /*
         BIP39:
            BIP39 seed. Can be outputed as either Easy16 or BIP39 english
            dictionnary mnemonic. Backup string is always converted into the
            BIP39 mnemonic then passed through PBKDF2 to generate the seed.
            Yield a wallet with BIP44, 49 and 84 accounts.
         */
         BIP39             = 8,

         /*
         Raw:
            Raw entropy. Used for wallet public data encryption and v1 seeds
         */
         Raw               = INT32_MAX - 1,
      };
      enum class BackupType;

      //////////////////////////////////////////////////////////////////////////
      class ClearTextSeed
      {
      private:
         const SeedType type_;
         mutable std::string walletId_;
         mutable std::string masterId_;

      protected:
         enum class Prefix : int
         {
            Root        = 0x11,
            Chaincode   = 0x22,
            PublicKey   = 0x33,
            RawEntropy  = 0x44,
            Dictionnary = 0x55,
            LegacyType  = 0x66,
            Base58Root  = 0x77
         };

         virtual std::string computeWalletId(void) const = 0;
         virtual std::string computeMasterId(void) const = 0;

      public:
         ClearTextSeed(SeedType);
         virtual ~ClearTextSeed(void) = 0;

         SeedType type(void) const;
         virtual bool isBackupTypeEligible(BackupType) const = 0;
         virtual BackupType getPreferedBackupType(void) const = 0;

         const std::string& getWalletId(void) const;
         const std::string& getMasterId(void) const;

         virtual void serialize(BinaryWriter&) const = 0;
         static std::unique_ptr<ClearTextSeed> deserialize(
            const SecureBinaryData&);
      };

      ////////
      class ClearTextSeed_Armory135 : public ClearTextSeed
      {
      public:
         enum class LegacyType : int
         {
            /*
            Legacy type defines what kinda of backup can be created from this
            seed. By default, legacy wallets would be created with a Armory200a
            backup type, which would set the hash index to 3.

            A wallet restored from an older backup would then yield backups that
            differ from the old paper. To avoid this, we track which legacy type
            this seed is from.

            - seed type of LegacyType::Armory135 will generate
              BackupType::Armory135 backups
            - seed type of LegacyType::Armory200 will generate
              BackupType::Armory200a backups
            */
            Armory135 = 12,
            Armory200 = 34
         };

      private:
         const SecureBinaryData root_;
         const SecureBinaryData chaincode_;
         const LegacyType legacyType_;

      protected:
         std::string computeWalletId(void) const override;
         std::string computeMasterId(void) const override;

      public:
         //will generate random root
         ClearTextSeed_Armory135(LegacyType lType = LegacyType::Armory200);

         //root
         ClearTextSeed_Armory135(const SecureBinaryData&,
            LegacyType lType = LegacyType::Armory200);

         //root + chaincode
         ClearTextSeed_Armory135(const SecureBinaryData&, const SecureBinaryData&,
            LegacyType lType = LegacyType::Armory135);

         //overrides
         ~ClearTextSeed_Armory135(void) override;
         void serialize(BinaryWriter&) const override;
         bool isBackupTypeEligible(BackupType) const override;
         BackupType getPreferedBackupType(void) const override;

         //local
         const SecureBinaryData& getRoot(void) const;
         const SecureBinaryData& getChaincode(void) const;
      };

      ////////
      class ClearTextSeed_BIP32 : public ClearTextSeed
      {
      protected:
         const SecureBinaryData rawEntropy_;
         mutable std::shared_ptr<BIP32_Node> rootNode_;

      protected:
         std::string computeWalletId(void) const override;
         std::string computeMasterId(void) const override;

      public:
         //seed
         ClearTextSeed_BIP32(SeedType);
         ClearTextSeed_BIP32(const SecureBinaryData&, SeedType);
         BackupType getPreferedBackupType(void) const override;
         static std::unique_ptr<ClearTextSeed_BIP32> fromBase58(
            const BinaryDataRef&);

         //overrides
         ~ClearTextSeed_BIP32(void) override;
         virtual void serialize(BinaryWriter&) const override;
         virtual bool isBackupTypeEligible(BackupType) const override;

         //locals
         virtual std::shared_ptr<BIP32_Node> getRootNode(void) const;
         const SecureBinaryData& getRawEntropy(void) const;
      };

      ////////
      class ClearTextSeed_BIP39 : public ClearTextSeed_BIP32
      {
      public:
         enum class Dictionnary : int
         {
            English_Trezor = 1,
         };

      private:
         const Dictionnary dictionnary_;

      private:
         void setupRootNode(void) const;

      public:
         ClearTextSeed_BIP39(const SecureBinaryData&, Dictionnary);
         ClearTextSeed_BIP39(Dictionnary);
         ~ClearTextSeed_BIP39(void) override;

         void serialize(BinaryWriter&) const override;
         bool isBackupTypeEligible(BackupType) const override;
         BackupType getPreferedBackupType(void) const override;

         std::shared_ptr<BIP32_Node> getRootNode(void) const override;
         Dictionnary getDictionnaryId(void) const;
      };

      //////////////////////////////////////////////////////////////////////////
      class EncryptedSeed : public Wallets::Encryption::EncryptedAssetData
      {
         /*
         Carries the encrypted ClearTextSeed used to generate the wallet.
         This class cannot be used to yield wallet seeds on its own, its
         main purpose is disk IO.

         Convert to ClearTextSeed for seed/backup manipulations.
         To convert, feed the decrypted the cipher text
         to ClearTextSeed::deserialize
         */
      private:
         const SeedType type_;

      public:
         using CipherText = std::unique_ptr<Wallets::Encryption::CipherData>;
         static const Wallets::AssetId seedAssetId_;

      public:
         //tors
         EncryptedSeed(CipherText, SeedType);
         ~EncryptedSeed(void) override;

         //utils
         SeedType type(void) const;
         bool isSame(Wallets::Encryption::EncryptedAssetData* const)
            const override;
         const Wallets::AssetId& getAssetId(void) const override;

         //for disk IO
         BinaryData serialize(void) const override;
         static std::unique_ptr<EncryptedSeed> deserialize(
            const BinaryDataRef&);

         //used at wallet creation
         static std::unique_ptr<EncryptedSeed> fromClearTextSeed(
            std::unique_ptr<ClearTextSeed>,
            std::unique_ptr<Wallets::Encryption::Cipher>,
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>);
      };
   }
} //namespace Armory