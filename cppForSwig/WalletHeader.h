////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _WALLET_HEADER_H
#define _WALLET_HEADER_H

#include <string>
#include <memory>

#include "BinaryData.h"
#include "SecureBinaryData.h"


#define WALLETTYPE_KEY        0x00000001
#define PARENTID_KEY          0x00000002
#define WALLETID_KEY          0x00000003
#define ROOTASSET_KEY         0x00000007
#define MAIN_ACCOUNT_KEY      0x00000008
#define WALLET_SEED_KEY       0x00000009

#define MASTERID_KEY          0x000000A0
#define MAINWALLET_KEY        0x000000A1

#define WALLETHEADER_PREFIX   0xB0

#define WALLETHEADER_DBNAME "WalletHeader"

#define VERSION_MAJOR      3
#define VERSION_MINOR      0
#define VERSION_REVISION   0
#define ENCRYPTION_TOPLAYER_VERSION 1

////////////////////////////////////////////////////////////////////////////////
class WalletException : public std::runtime_error
{
public:
   WalletException(const std::string& msg) : std::runtime_error(msg)
   {}
};

////////////////////////////////////////////////////////////////////////////////
enum WalletHeaderType
{
   WalletHeaderType_Single,
   WalletHeaderType_Multisig,
   WalletHeaderType_Subwallet,
   WalletHeaderType_Control,
   WalletHeaderType_Custom
};

////
struct WalletHeader
{
   WalletHeaderType type_;
   std::string walletID_;

   SecureBinaryData defaultEncryptionKey_;
   SecureBinaryData defaultEncryptionKeyId_;

   SecureBinaryData defaultKdfId_;
   SecureBinaryData masterEncryptionKeyId_;

   SecureBinaryData controlSalt_;

   //tors
   WalletHeader(WalletHeaderType type) :
      type_(type)
   {}

   virtual ~WalletHeader(void) = 0;

   //local
   BinaryData getDbKey(void);
   const std::string& getWalletID(void) const { return walletID_; }
   std::string getDbName(void) const { return walletID_; }

   //serialization
   BinaryData serializeEncryptionKey(void) const;
   void unserializeEncryptionKey(BinaryRefReader&);

   BinaryData serializeControlSalt(void) const;
   void unserializeControlSalt(BinaryRefReader&);

   //encryption keys
   const SecureBinaryData& getDefaultEncryptionKey(void) const
   {
      return defaultEncryptionKey_;
   }
   const BinaryData& getDefaultEncryptionKeyId(void) const
   {
      return defaultEncryptionKeyId_;
   }

   //virtual
   virtual BinaryData serialize(void) const = 0;
   virtual bool shouldLoad(void) const = 0;

   //static
   static std::shared_ptr<WalletHeader> deserialize(
      BinaryDataRef key, BinaryDataRef val);
};

////
struct WalletHeader_Single : public WalletHeader
{
   //tors
   WalletHeader_Single() :
      WalletHeader(WalletHeaderType_Single)
   {}

   //virtual
   BinaryData serialize(void) const;
   bool shouldLoad(void) const;
};

////
struct WalletHeader_Multisig : public WalletHeader
{
   //tors
   WalletHeader_Multisig() :
      WalletHeader(WalletHeaderType_Multisig)
   {}

   //virtual
   BinaryData serialize(void) const;
   bool shouldLoad(void) const;
};

////
struct WalletHeader_Subwallet : public WalletHeader
{
   //tors
   WalletHeader_Subwallet() :
      WalletHeader(WalletHeaderType_Subwallet)
   {}

   //virtual
   BinaryData serialize(void) const;
   bool shouldLoad(void) const;
};

////
struct WalletHeader_Control : public WalletHeader
{
   friend struct WalletHeader;
public:
   uint8_t versionMajor_ = 0;
   uint16_t versionMinor_ = 0;
   uint16_t revision_ = 0;
   unsigned encryptionVersion_ = 0;

private:
   BinaryData serializeVersion(void) const;
   void unseralizeVersion(BinaryRefReader&);

public:
   //tors
   WalletHeader_Control() :
      WalletHeader(WalletHeaderType_Control)
   {
      versionMajor_ = VERSION_MAJOR;
      versionMinor_ = VERSION_MINOR;
      revision_ = VERSION_REVISION;
      encryptionVersion_ = ENCRYPTION_TOPLAYER_VERSION;
   }

   //virtual
   BinaryData serialize(void) const;
   bool shouldLoad(void) const;
};

////
struct WalletHeader_Custom : public WalletHeader
{
   //tors
   WalletHeader_Custom() :
      WalletHeader(WalletHeaderType_Custom)
   {}

   //virtual
   BinaryData serialize(void) const;
   bool shouldLoad(void) const;
};

////////////////////////////////////////////////////////////////////////////////
struct Asset_EncryptionKey;
struct DecryptedEncryptionKey;
struct KeyDerivationFunction;
class Cipher;
class DecryptedDataContainer;

struct MasterKeyStruct
{
   std::shared_ptr<Asset_EncryptionKey> masterKey_;
   std::shared_ptr<DecryptedEncryptionKey> decryptedMasterKey_;
   std::shared_ptr<KeyDerivationFunction> kdf_;
   std::unique_ptr<Cipher> cipher_;
};

////
struct ControlStruct
{
   std::shared_ptr<WalletHeader_Control> metaPtr_;
   std::shared_ptr<DecryptedDataContainer> decryptedData_;
};


#endif