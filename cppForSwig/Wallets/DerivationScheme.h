////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_DERIVATION_SCHEME
#define _H_DERIVATION_SCHEME

#include <vector>
#include <set>
#include <memory>

#include "BinaryData.h"
#include "EncryptionUtils.h"
#include "Assets.h"

#define DERIVATIONSCHEME_LEGACY        0xA0
#define DERIVATIONSCHEME_BIP32         0xA1
#define DERIVATIONSCHEME_BIP32_SALTED  0xA2
#define DERIVATIONSCHEME_BIP32_ECDH    0xA3

#define DERIVATIONSCHEME_KEY  0x00000004

#define DERIVATION_LOOKUP        100


namespace Armory
{
   namespace Wallets
   {
      class AssetWallet_Single;

      namespace IO
      {
         class DBIfaceTransaction;
      };

      namespace Encryption
      {
         class Cipher;
         class DecryptedDataContainer;
      };
   };

   namespace Assets
   {
      enum class DerivationSchemeType: int
      {
         Unknown      = -1,
         ArmoryLegacy = 0,
         BIP32        = 1,
         ECDH         = 2,
         BIP32_Salted = 3,
      };

      //////////////////////////////////////////////////////////////////////////
      class DerivationSchemeException : public std::runtime_error
      {
      public:
         DerivationSchemeException(const std::string& msg) :
            std::runtime_error(msg)
         {}
      };

      //////////////////////////////////////////////////////////////////////////
      class DerivationScheme
      {
         /*in extend methods, the end argument is inclusive for all schemes*/

      private:
         const DerivationSchemeType type_;

      public:
         //tors
         DerivationScheme(DerivationSchemeType type) :
            type_(type)
         {}

         virtual ~DerivationScheme(void) = 0;

         //local
         DerivationSchemeType getType(void) const { return type_; }

         //virtual
         virtual std::vector<std::shared_ptr<Assets::AssetEntry>>
         extendPublicChain(std::shared_ptr<Assets::AssetEntry>,
            uint32_t start, uint32_t end,
            const std::function<void(int)>&) = 0;
         virtual std::vector<std::shared_ptr<Assets::AssetEntry>>
         extendPrivateChain(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            std::shared_ptr<Assets::AssetEntry>,
            uint32_t start, uint32_t end) = 0;
         virtual BinaryData serialize(void) const = 0;

         virtual const SecureBinaryData& getChaincode(void) const = 0;

         //static
         static std::shared_ptr<DerivationScheme> deserialize(BinaryDataRef);
      };

      //////////////////////////////////////////////////////////////////////////
      class DerivationScheme_ArmoryLegacy : public DerivationScheme
      {
         friend class Wallets::AssetWallet_Single;

      private:
         SecureBinaryData chainCode_;

      public:
         //tors
         DerivationScheme_ArmoryLegacy(SecureBinaryData& chainCode) :
            DerivationScheme(DerivationSchemeType::ArmoryLegacy),
            chainCode_(std::move(chainCode))
         {}

         //locals
         std::shared_ptr<AssetEntry_Single> computeNextPrivateEntry(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            const SecureBinaryData&,
            std::unique_ptr<Wallets::Encryption::Cipher>,
            Wallets::AssetId);

         std::shared_ptr<AssetEntry_Single> computeNextPublicEntry(
            const SecureBinaryData& pubKey, Wallets::AssetId);

         //virtuals
         std::vector<std::shared_ptr<AssetEntry>> extendPublicChain(
            std::shared_ptr<AssetEntry>, uint32_t start, uint32_t end,
            const std::function<void(int)>&) override;
         std::vector<std::shared_ptr<AssetEntry>> extendPrivateChain(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            std::shared_ptr<AssetEntry>, uint32_t start, uint32_t end) override;

         BinaryData serialize(void) const;

         const SecureBinaryData& getChaincode(void) const { return chainCode_; }
      };

      ////////////////////////////////////////////////////////////////////////////////
      class DerivationScheme_BIP32 : public DerivationScheme
      {
         friend class Wallets::AssetWallet_Single;
         friend class DerivationScheme_BIP32_Salted;

      private:
         SecureBinaryData chainCode_;
         const unsigned depth_;
         const unsigned leafId_;

      private:
         DerivationScheme_BIP32(DerivationSchemeType type,
            SecureBinaryData& chainCode,
            unsigned depth, unsigned leafId) :
            DerivationScheme(type),
            chainCode_(std::move(chainCode)),
            depth_(depth), leafId_(leafId)
         {}

      public:
         //tors
         DerivationScheme_BIP32(SecureBinaryData& chainCode,
            unsigned depth, unsigned leafId) :
            DerivationScheme(DerivationSchemeType::BIP32),
            chainCode_(std::move(chainCode)),
            depth_(depth), leafId_(leafId)
         {}

         //locals
         virtual std::shared_ptr<AssetEntry_Single> computeNextPrivateEntry(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            const SecureBinaryData&,
            std::unique_ptr<Wallets::Encryption::Cipher>,
            Wallets::AssetId);

         virtual std::shared_ptr<AssetEntry_Single> computeNextPublicEntry(
            const SecureBinaryData&,
            Wallets::AssetId);

         //virtuals
         std::vector<std::shared_ptr<AssetEntry>> extendPublicChain(
            std::shared_ptr<AssetEntry>, uint32_t start, uint32_t end,
            const std::function<void(int)>&) override;
         std::vector<std::shared_ptr<AssetEntry>> extendPrivateChain(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            std::shared_ptr<AssetEntry>, uint32_t start, uint32_t end) override;

         virtual BinaryData serialize(void) const;

         const SecureBinaryData& getChaincode(void) const
         { return chainCode_; }

         unsigned getDepth(void) const { return depth_; }
         unsigned getLeafId(void) const { return leafId_; }
      };

      ////////////////////////////////////////////////////////////////////////////////
      class DerivationScheme_BIP32_Salted : public DerivationScheme_BIP32
      {
      private:
         const SecureBinaryData salt_;

      public:
         DerivationScheme_BIP32_Salted(
            SecureBinaryData& salt,
            SecureBinaryData& chainCode,
            unsigned depth, unsigned leafId) :
            DerivationScheme_BIP32(DerivationSchemeType::BIP32_Salted,
               chainCode, depth, leafId), salt_(std::move(salt))
         {}

         //virtuals
         std::shared_ptr<AssetEntry_Single> computeNextPrivateEntry(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            const SecureBinaryData&,
            std::unique_ptr<Wallets::Encryption::Cipher>,
            Wallets::AssetId) override;

         std::shared_ptr<AssetEntry_Single> computeNextPublicEntry(
            const SecureBinaryData& pubKey,
            Wallets::AssetId) override;

         BinaryData serialize(void) const override;
         const SecureBinaryData& getSalt(void) const { return salt_; }
      };

      ////////////////////////////////////////////////////////////////////////////////
      class DerivationScheme_ECDH : public DerivationScheme
      {
      private:
         const BinaryData id_;
         std::map<SecureBinaryData, Wallets::AssetKeyType> saltMap_;
         Wallets::AssetKeyType topSaltIndex_ = -1;
         std::mutex saltMutex_;

      private:
         std::shared_ptr<AssetEntry_Single> computeNextPublicEntry(
            const SecureBinaryData& pubKey,
            Wallets::AssetId);

         std::shared_ptr<AssetEntry_Single> computeNextPrivateEntry(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            const SecureBinaryData&,
            std::unique_ptr<Wallets::Encryption::Cipher>,
            Wallets::AssetId);

         void putSalt(Wallets::AssetKeyType, const SecureBinaryData&,
            std::shared_ptr<Wallets::IO::DBIfaceTransaction>);

      public:
         DerivationScheme_ECDH(void) :
            DerivationScheme(DerivationSchemeType::ECDH),
            id_(CryptoPRNG::generateRandom(8))
         {}

         DerivationScheme_ECDH(const BinaryData& id);

         //virtuals
         std::vector<std::shared_ptr<AssetEntry>> extendPublicChain(
            std::shared_ptr<AssetEntry>, uint32_t start, uint32_t end,
            const std::function<void(int)>&) override;
         std::vector<std::shared_ptr<AssetEntry>> extendPrivateChain(
            std::shared_ptr<Wallets::Encryption::DecryptedDataContainer>,
            std::shared_ptr<AssetEntry>, uint32_t start, uint32_t end) override;
         BinaryData serialize(void) const override;

         const SecureBinaryData& getChaincode(void) const override;

         //locals
         Wallets::AssetKeyType addSalt(const SecureBinaryData&,
            std::shared_ptr<Wallets::IO::DBIfaceTransaction>);
         void putAllSalts(std::shared_ptr<Wallets::IO::DBIfaceTransaction>);
         void getAllSalts(std::shared_ptr<Wallets::IO::DBIfaceTransaction>);
         Wallets::AssetKeyType getIdForSalt(const SecureBinaryData&);
         const std::map<SecureBinaryData, Wallets::AssetKeyType>&
            getSaltMap(void) const;
      };
   }; //namespace Assets
}; //namespace Armory

#endif