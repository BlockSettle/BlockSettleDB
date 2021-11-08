////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2021-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_WALLET_ID_TYPES
#define _H_WALLET_ID_TYPES

#include <string>
#include <stdexcept>
#include "../BinaryData.h"
#include "../BtcUtils.h"

namespace Armory
{
   namespace Wallets
   {
      ////////////////////////////////////////////////////////////////////////
      using AssetKeyType = int32_t;
      using AccountKeyType = int32_t;

      static const AccountKeyType rootAccountId = -1;
      static const AssetKeyType rootAssetId = -1;
      static const AccountKeyType dummyAccountId = -2;

      static const size_t EncryptionKeyIdLength = 16;

      ////
      struct IdException : public std::runtime_error
      {
         IdException(const std::string& err) :
            std::runtime_error(err)
         {}
      };

      ////////////////////////////////////////////////////////////////////////
      class AddressAccountId
      {
         friend class AssetAccountId;
         friend class AssetId;

      private:
         BinaryData data_;

      private:
         AddressAccountId(const BinaryData&);

      public:
         AddressAccountId(void);
         AddressAccountId(AccountKeyType);

         AddressAccountId& operator=(const AddressAccountId&);
         bool operator<(const AddressAccountId&) const;
         bool operator==(const AddressAccountId&) const;
         bool operator!=(const AddressAccountId&) const;

         bool isValid(void) const;
         const AccountKeyType getAddressAccountKey(void) const;
         std::string toHexStr(void) const;
         static AddressAccountId fromHex(const std::string&);

         void serializeValue(BinaryWriter&) const;
         BinaryData getSerializedKey(uint8_t) const;

         static AddressAccountId deserializeValue(BinaryRefReader&);
         static AddressAccountId deserializeValue(const BinaryData&);
         static AddressAccountId deserializeKey(const BinaryData&, uint8_t);
         static AccountKeyType getRootKey(void) { return rootAccountId; }
      };

      ////////////////////////////////////////////////////////////////////////
      class AssetAccountId
      {
         friend class AssetId;

      private:
         BinaryData data_;

      public:
         AssetAccountId(void);
         AssetAccountId(const BinaryData&);
         AssetAccountId(AccountKeyType, AccountKeyType);
         AssetAccountId(const AddressAccountId&, AccountKeyType);
         AssetAccountId(const AssetAccountId&);

         AssetAccountId& operator=(const AssetAccountId&);
         bool operator<(const AssetAccountId&) const;
         bool operator==(const AssetAccountId&) const;
         bool operator!=(const AssetAccountId&) const;

         bool isValid(void) const;
         const AddressAccountId getAddressAccountId(void) const;
         const AccountKeyType getAddressAccountKey(void) const;
         const AccountKeyType getAssetAccountKey(void) const;
         std::string toHexStr(void) const;

         void serializeValue(BinaryWriter&) const;
         BinaryData getSerializedKey(uint8_t) const;

         static AssetAccountId deserializeValue(BinaryRefReader&);
         static AssetAccountId deserializeValueOld(
            const AddressAccountId&, BinaryRefReader&);
         static AssetAccountId deserializeKey(const BinaryData&, uint8_t);
         static AccountKeyType getRootKey(void) { return rootAccountId; }
      };

      ////////////////////////////////////////////////////////////////////////
      class AssetId
      {
      private:
         static AssetKeyType dummyId_;
         BinaryData data_;

      public:
         AssetId(void);
         AssetId(const BinaryData&);
         AssetId(AccountKeyType, AccountKeyType, AssetKeyType);
         AssetId(const AssetAccountId&, AssetKeyType);
         AssetId(const AddressAccountId&, AccountKeyType, AssetKeyType);

         AssetId& operator=(const AssetId&);
         bool operator<(const AssetId&) const;
         bool operator==(const AssetId&) const;
         bool operator!=(const AssetId&) const;
         bool belongsTo(const AssetAccountId&) const;

         bool isValid(void) const;
         const AssetKeyType getAssetKey(void) const;
         const AccountKeyType getAddressAccountKey(void) const;
         const AddressAccountId getAddressAccountId(void) const;
         const AssetAccountId getAssetAccountId(void) const;

         void serializeValue(BinaryWriter&) const;
         BinaryData getSerializedKey(uint8_t) const;

         static AssetId deserializeValue(BinaryRefReader&);
         static AssetId deserializeKey(const BinaryData&, uint8_t);
         static AssetKeyType getRootKey(void) { return rootAssetId; }
         static AssetId getRootAssetId(void);
         static AssetId getNextDummyId(void);
      };

      ////////////////////////////////////////////////////////////////////////
      class EncryptionKeyId
      {
      private:
         BinaryData data_;

      public:
         EncryptionKeyId(void);
         EncryptionKeyId(const BinaryData&);

         EncryptionKeyId& operator=(const EncryptionKeyId&);
         bool operator<(const EncryptionKeyId&) const;
         bool operator==(const EncryptionKeyId&) const;
         bool operator!=(const EncryptionKeyId&) const;

         bool isValid(void) const;
         std::string toHexStr(void) const;

         void serializeValue(BinaryWriter&) const;
         BinaryData getSerializedKey(uint8_t) const;
         static EncryptionKeyId deserializeValue(BinaryRefReader&);
      };
   };
};
#endif