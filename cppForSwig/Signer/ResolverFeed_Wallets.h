////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <memory>
#include <map>

#include "ResolverFeed.h"

class BinaryData;
class BinaryDataRef;
class AddressEntry;

namespace Armory
{
   namespace Assets
   {
      class AssetEntry;
      class AssetEntry_Single;
   };

   namespace Wallets
   {
      class AssetWallet;
      class AssetWallet_Single;
      class AssetId;
   };

   namespace Signing
   {
      class ResolverFeed_AssetWalletSingle : public ResolverFeed
      {
      private:
         std::shared_ptr<Wallets::AssetWallet_Single> wltPtr_;

      protected:
         std::map<BinaryData, BinaryData> hashToPreimage_;
         std::map<BinaryData,
            std::shared_ptr<Assets::AssetEntry_Single>> pubkeyToAsset_;
         std::map<BinaryData,
            std::pair<BIP32_AssetPath, Wallets::AssetId>> bip32Paths_;

      private:
         void addToMap(std::shared_ptr<AddressEntry>);

      public:
         ResolverFeed_AssetWalletSingle(
            std::shared_ptr<Wallets::AssetWallet_Single>);

         BinaryData getByVal(const BinaryData&) override;
         virtual const SecureBinaryData& getPrivKeyForPubkey(
            const BinaryData&) override;
         BIP32_AssetPath resolveBip32PathForPubkey(
            const BinaryData&) override;

         //local
         void seedFromAddressEntry(std::shared_ptr<AddressEntry>);
         void setBip32PathForPubkey(
            const BinaryData&, const BIP32_AssetPath&) override;
      };

      //////////////////////////////////////////////////////////////////////////
      class ResolverFeed_AssetWalletSingle_Exotic :
         public ResolverFeed_AssetWalletSingle
      {
      public:
         ResolverFeed_AssetWalletSingle_Exotic(
            std::shared_ptr<Wallets::AssetWallet_Single>);

         const SecureBinaryData& getPrivKeyForPubkey(const BinaryData&) override;
      };

      //////////////////////////////////////////////////////////////////////////
      class ResolverFeed_AssetWalletSingle_ForMultisig : public ResolverFeed
      {
      private:
         std::shared_ptr<Wallets::AssetWallet> wltPtr_;

      protected:
         std::map<BinaryDataRef,
            std::shared_ptr<Assets::AssetEntry_Single>> pubkeyToAsset_;

      private:
         void addToMap(std::shared_ptr<Assets::AssetEntry>);

      public:
         ResolverFeed_AssetWalletSingle_ForMultisig(
            std::shared_ptr<Wallets::AssetWallet_Single>);

         BinaryData getByVal(const BinaryData&) override;
         virtual const SecureBinaryData& getPrivKeyForPubkey(
            const BinaryData&) override;
         BIP32_AssetPath resolveBip32PathForPubkey(const BinaryData&) override;
         void setBip32PathForPubkey(
            const BinaryData&, const BIP32_AssetPath&) override;
      };
   } //namespace Signing
} //namespace Armory
