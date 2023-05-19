////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2023, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Seeds.h"
#include "../AssetEncryption.h"
#include "../WalletIdTypes.h"

using namespace std;
using namespace Armory;
using namespace Armory::Seed;
using namespace Armory::Wallets;

#define ENCRYPTED_SEED_VERSION 0x00000001

////////////////////////////////////////////////////////////////////////////////
//
//// EncryptedSeed
//
////////////////////////////////////////////////////////////////////////////////
const Wallets::AssetId EncryptedSeed::seedAssetId_(0x5EED, 0xDEE5, 0x5EED);

////////////////////////////////////////////////////////////////////////////////
BinaryData EncryptedSeed::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(ENCRYPTED_SEED_VERSION);
   bw.put_uint8_t(WALLET_SEED_BYTE);

   auto&& cipherData = getCipherDataPtr()->serialize();
   bw.put_var_int(cipherData.getSize());
   bw.put_BinaryData(cipherData);

   BinaryWriter finalBw;
   finalBw.put_var_int(bw.getSize());
   finalBw.put_BinaryDataRef(bw.getDataRef());
   return finalBw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool EncryptedSeed::isSame(Encryption::EncryptedAssetData* const seed) const
{
   auto asset_ed = dynamic_cast<EncryptedSeed*>(seed);
   if (asset_ed == nullptr)
      return false;

   return Encryption::EncryptedAssetData::isSame(seed);
}

////////////////////////////////////////////////////////////////////////////////
const AssetId& EncryptedSeed::getAssetId() const
{
   return seedAssetId_;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<EncryptedSeed> EncryptedSeed::deserialize(
   const BinaryDataRef& data)
{
   BinaryRefReader brr(data);

   //return ptr
   unique_ptr<EncryptedSeed> assetPtr = nullptr;

   //version
   auto version = brr.get_uint32_t();

   //prefix
   auto prefix = brr.get_uint8_t();

   switch (prefix)
   {
   case WALLET_SEED_BYTE:
   {
      switch (version)
      {
      case 0x00000001:
      {
         auto len = brr.get_var_int();
         if (len > brr.getSizeRemaining())
            throw runtime_error("invalid serialized encrypted data len");

         auto cipherBdr = brr.get_BinaryDataRef(len);
         BinaryRefReader cipherBrr(cipherBdr);
         auto cipherData = Encryption::CipherData::deserialize(cipherBrr);

         //ptr
         assetPtr = make_unique<EncryptedSeed>(move(cipherData));
         break;
      }

      default:
         throw runtime_error("unsupported seed version");
      }

      break;
   }

   default:
      throw runtime_error("unexpected encrypted data prefix");
   }

   if (assetPtr == nullptr)
      throw runtime_error("failed to deserialize encrypted asset");

   return assetPtr;
}
