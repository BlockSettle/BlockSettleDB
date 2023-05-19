////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2023, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once
#include "../AssetEncryption.h"

namespace Armory
{
   namespace Seed
   {
      //////////////////////////////////////////////////////////////////////////
      class EncryptedSeed : public Wallets::Encryption::EncryptedAssetData
      {
      public:
         static const Wallets::AssetId seedAssetId_;

      public:
         //tors
         EncryptedSeed(
            std::unique_ptr<Wallets::Encryption::CipherData> cipher) :
            Wallets::Encryption::EncryptedAssetData(move(cipher))
         {}

         //overrides
         bool isSame(Wallets::Encryption::EncryptedAssetData* const)
            const override;
         BinaryData serialize(void) const override;
         const Wallets::AssetId& getAssetId(void) const override;

         //static
         static std::unique_ptr<EncryptedSeed> deserialize(
            const BinaryDataRef&);
      };
   }
} //namespace Armory