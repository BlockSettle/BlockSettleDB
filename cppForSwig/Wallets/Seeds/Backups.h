////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020 - 2023, goatpig                                        //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _SECURE_PRINT_H
#define _SECURE_PRINT_H

#include <vector>
#include <string>
#include "SecureBinaryData.h"
#include "EncryptionUtils.h"

#include "Wallets.h"

#define EASY16_INVALID_CHECKSUM_INDEX UINT8_MAX

namespace Armory
{
   namespace Seeds
   {
      ////
      class RestoreUserException : public std::runtime_error
      {
      public:
         RestoreUserException(const std::string& errMsg) :
            std::runtime_error(errMsg)
         {}
      };

      class Easy16RepairError : public std::runtime_error
      {
      public:
         Easy16RepairError(const std::string& errMsg) :
            std::runtime_error(errMsg)
         {}
      };

      ////
      enum BackupType
      {
         /*
         Armory135:
            For wallets using the Armory specific derivation scheme.
         */
         Armory135               = 0,

         /*
         BIP32_Seed_Structured:
            For wallets carrying BIP44/49/84 accounts. Restores to a bip32 wallet
            with all these accounts.
         */
         BIP32_Seed_Structured   = 1,

         /*
         BIP32_Root:
            For bip32 wallets that do not carry their own seed. Support for this is
            not implemented at the moment. This type of backup would have to carry
            the root privkey and chaincode generated through the seed's hmac.

            May implement support in the future.
         */
         BIP32_Root              = 2,

         /*
         BIP32_Seed_Virgin:
            No info is provided about the wallet's structure, restores to an empt
            bip32 wallet.
         */
         BIP32_Seed_Virgin       = 15,

         /*
         Default marker value.
         */
         Invalid = UINT32_MAX
      };

      ////
      struct WalletRootData
      {
         SecureBinaryData root_;
         SecureBinaryData secondaryData_;

         BackupType type_;
         std::string wltId_;
      };

      ////
      struct BackupEasy16DecodeResult
      {
         std::vector<int> checksumIndexes_;
         std::vector<int> repairedIndexes_;
         std::vector<BinaryData> checksums_;
         SecureBinaryData data_;
      };

      ////
      struct BackupEasy16
      {
      public:
         /***
         Checksum indexes are an byte appended to the 16 byte line that is passed
         through the hash256 function to generate the checksum. That byte value
         designates the type of wallet this backup was generated from.

         For index 0 (Armory 1.35 wallets), the byte is not appended.
         The indexes for each line in a multiple line easy16 code need to match
         one another.
         ***/

         static const std::set<uint8_t> eligibleIndexes_;

      private:
         static BinaryData getHash(const BinaryDataRef&, uint8_t);
         static uint8_t verifyChecksum(const BinaryDataRef&, const BinaryDataRef&);

      public:
         const static std::vector<char> e16chars_;

         static std::vector<std::string> encode(const BinaryDataRef, uint8_t);
         static BackupEasy16DecodeResult decode(const std::vector<std::string>&);
         static BackupEasy16DecodeResult decode(const std::vector<BinaryDataRef>&);
         static bool repair(BackupEasy16DecodeResult&);
      };

      ////
      class SecurePrint
      {
      private:
         const static std::string digits_pi_;
         const static std::string digits_e_;
         const static uint32_t kdfBytes_;

         BinaryData iv16_;
         BinaryData salt_;
         mutable KdfRomix kdf_;

         SecureBinaryData passphrase_;

      public:
         SecurePrint(void);

         std::pair<SecureBinaryData, SecureBinaryData> encrypt(
            const SecureBinaryData&, const SecureBinaryData&);
         SecureBinaryData decrypt(
            const SecureBinaryData&, const BinaryDataRef) const;

         const SecureBinaryData& getPassphrase(void) const { return passphrase_; }
      };

      ////
      struct WalletBackup
      {
         std::vector<std::string> rootClear_;
         std::vector<std::string> chaincodeClear_;

         std::vector<std::string> rootEncr_;
         std::vector<std::string> chaincodeEncr_;

         SecureBinaryData spPass_;
         std::string wltId_;
      };

      ////
      enum RestorePromptType
      {
         //invalid backup format
         FormatError = 1,

         //failed to decode backup string
         Failure = 2,

         ChecksumError = 3,

         //failed to decrypt secure print string
         DecryptError = 4,

         //requesting wallet's new passphrase
         Passphrase = 5,

         //requesting wallet's new control passphrase
         Control = 6,

         //present restored wallet's id
         Id = 7,

         //unknown wallet type
         TypeError = 8,
      };

      ////
      struct Helpers
      {
         using UserPrompt = std::function<bool(
            RestorePromptType,
            const std::vector<int>&,
            SecureBinaryData&)>;

         //getting root data from wallets
         static WalletRootData getRootData(
            std::shared_ptr<Wallets::AssetWallet_Single>);
         static WalletRootData getRootData_Multisig(
            std::shared_ptr<Wallets::AssetWallet_Multisig>);

         //backup methods
         static WalletBackup getWalletBackup(
            std::shared_ptr<Wallets::AssetWallet_Single>, 
            BackupType bType = BackupType::Invalid);

         static WalletBackup getWalletBackup(
            WalletRootData&,
            BackupType bType = BackupType::Invalid);

         //restore methods
         static std::shared_ptr<Wallets::AssetWallet> restoreFromBackup(
            const std::vector<std::string>&, const BinaryDataRef,
            const std::string&, const UserPrompt&);

         static std::shared_ptr<Wallets::AssetWallet> restoreFromBackup(
            const std::vector<BinaryDataRef>&, const BinaryDataRef,
            const std::string&, const UserPrompt&);
      };
   }; //namespace Backups
}; //namespace Armory
#endif
