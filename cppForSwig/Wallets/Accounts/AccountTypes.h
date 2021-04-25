////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_ACCOUNT_TYPES
#define _H_ACCOUNT_TYPES

#include "../Addresses.h"

#define ARMORY_LEGACY_ACCOUNTID        0xF6E10000
#define IMPORTS_ACCOUNTID              0x00000000
#define ARMORY_LEGACY_ASSET_ACCOUNTID  0x00000001
#define ECDH_ASSET_ACCOUNTID           0x20000000

class AccountException : public std::runtime_error
{
public:
   AccountException(const std::string& err) : std::runtime_error(err)
   {}
};

enum AssetAccountTypeEnum
{
   AssetAccountTypeEnum_Plain = 0,
   AssetAccountTypeEnum_ECDH
};

enum AccountTypeEnum
{
   /*
   armory derivation scheme 
   outer and inner account are the same
   uncompressed P2PKH, compresed P2SH-P2PK, P2SH-P2WPKH
   */
   AccountTypeEnum_ArmoryLegacy = 0,

   /*
   BIP32 derivation scheme, derPath is used as is.
   no address type is assumed, this has to be provided at creation
   */
   AccountTypeEnum_BIP32,

   /*
   Derives from BIP32_Custom, ECDH all keys pairs with salt, 
   carried by derScheme object.
   */
   AccountTypeEnum_BIP32_Salted,

   /*
   Stealth address account. Has a single key pair, ECDH it with custom
   salts per asset.
   */
   AccountTypeEnum_ECDH,

   AccountTypeEnum_Custom
};

enum MetaAccountType
{
   MetaAccount_Unset = 0,
   MetaAccount_Comments,
   MetaAccount_AuthPeers
};

namespace ArmorySigner
{
   class BIP32_AssetPath;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
struct AccountType
{
protected:
   std::set<AddressEntryType> addressTypes_;
   AddressEntryType defaultAddressEntryType_;
   bool isMain_ = false;

public:
   //tors
   AccountType()
   {}

   virtual ~AccountType() = 0;

   //locals
   void setMain(bool ismain) { isMain_ = ismain; }
   const bool isMain(void) const { return isMain_; }

   const std::set<AddressEntryType>& getAddressTypes(void) const 
   { return addressTypes_; }

   AddressEntryType getDefaultAddressEntryType(void) const 
   { return defaultAddressEntryType_; }

   void setAddressTypes(const std::set<AddressEntryType>&);
   void setDefaultAddressType(AddressEntryType);

   //virtuals
   virtual AccountTypeEnum type(void) const = 0;
   virtual BinaryData getAccountID(void) const = 0;
   virtual BinaryData getOuterAccountID(void) const = 0;
   virtual BinaryData getInnerAccountID(void) const = 0;
   virtual bool isWatchingOnly(void) const = 0;
};

////////////////////
struct AccountType_WithRoot : public AccountType
{
protected:
   SecureBinaryData privateRoot_;
   SecureBinaryData publicRoot_;
   mutable SecureBinaryData chainCode_;

protected:
   AccountType_WithRoot()
   {}

public:
   AccountType_WithRoot(
      SecureBinaryData& privateRoot,
      SecureBinaryData& publicRoot,
      SecureBinaryData& chainCode) : 
      privateRoot_(std::move(privateRoot)),
      publicRoot_(std::move(publicRoot)),
      chainCode_(std::move(chainCode))
   {
      if (privateRoot_.getSize() == 0 && publicRoot_.getSize() == 0)
         throw AccountException("need at least one valid root");

      if (privateRoot_.getSize() > 0 && publicRoot_.getSize() > 0)
         throw AccountException("root types are mutualy exclusive");

      if (publicRoot_.getSize() > 0 && chainCode_.getSize() == 0)
         throw AccountException("need chaincode for public account");
   }

   //virtuals
   virtual ~AccountType_WithRoot(void) = 0;
   virtual const SecureBinaryData& getChaincode(void) const = 0;
   virtual const SecureBinaryData& getPrivateRoot(void) const = 0;
   virtual const SecureBinaryData& getPublicRoot(void) const = 0;
   
   bool isWatchingOnly(void) const override
   {
      return privateRoot_.empty() &&
         !publicRoot_.empty() && !chainCode_.empty();
   }
};

////////////////////
struct AccountType_ArmoryLegacy : public AccountType_WithRoot
{
public:
   AccountType_ArmoryLegacy(
      SecureBinaryData& privateRoot,
      SecureBinaryData& publicRoot,
      SecureBinaryData& chainCode) :
      AccountType_WithRoot(
      privateRoot, publicRoot, chainCode)
   {
      //uncompressed p2pkh
      addressTypes_.insert(AddressEntryType(
         AddressEntryType_P2PKH | AddressEntryType_Uncompressed));

      //nested compressed p2pk
      addressTypes_.insert(AddressEntryType(
         AddressEntryType_P2PK | AddressEntryType_P2SH));

      //nested p2wpkh
      addressTypes_.insert(AddressEntryType(
         AddressEntryType_P2WPKH | AddressEntryType_P2SH));

      //native p2wpkh
      addressTypes_.insert(AddressEntryType_P2WPKH);

      //default type
      defaultAddressEntryType_ = AddressEntryType(
         AddressEntryType_P2PKH | AddressEntryType_Uncompressed);
   }

   AccountTypeEnum type(void) const
   { return AccountTypeEnum_ArmoryLegacy; }

   const SecureBinaryData& getChaincode(void) const;
   const SecureBinaryData& getPrivateRoot(void) const { return privateRoot_; }
   const SecureBinaryData& getPublicRoot(void) const { return publicRoot_; }
   BinaryData getAccountID(void) const { return WRITE_UINT32_BE(ARMORY_LEGACY_ACCOUNTID); }
   BinaryData getOuterAccountID(void) const;
   BinaryData getInnerAccountID(void) const;
};

////////////////////
struct AccountType_BIP32 : public AccountType_WithRoot
{   
   friend struct AccountType_BIP32_Custom;
   friend class AssetWallet_Single;

private:
   std::vector<uint32_t> derivationPath_;
   unsigned depth_ = 0;
   unsigned leafId_ = 0;

   std::set<unsigned> nodes_;   
   BinaryData outerAccount_;
   BinaryData innerAccount_;

protected:
   unsigned fingerPrint_ = 0;
   unsigned seedFingerprint_ = UINT32_MAX;
   unsigned addressLookup_ = UINT32_MAX;

protected:
   void setPrivateKey(const SecureBinaryData&);
   void setPublicKey(const SecureBinaryData&);
   void setChaincode(const SecureBinaryData&);
   void setDerivationPath(std::vector<unsigned> derPath)
   {
      derivationPath_ = derPath;
   }

   void setSeedFingerprint(unsigned fingerprint) 
   { 
      seedFingerprint_ = fingerprint; 
   }

   void setFingerprint(unsigned fingerprint)
   {
      fingerPrint_ = fingerprint;
   }

   void setDepth(unsigned depth)
   {
      depth_ = depth;
   }

   void setLeafId(unsigned leafid)
   {
      leafId_ = leafid;
   }

public:
   AccountType_BIP32(const std::vector<unsigned>& derivationPath) :
      AccountType_WithRoot(), derivationPath_(derivationPath)
   {}

   //bip32 virtuals
   AccountType_BIP32(void) {}
   virtual std::set<unsigned> getNodes(void) const
   {
      return nodes_;
   }

   //AccountType virtuals
   const SecureBinaryData& getChaincode(void) const override
   {
      return chainCode_;
   }

   const SecureBinaryData& getPrivateRoot(void) const override
   {
      return privateRoot_;
   }

   const SecureBinaryData& getPublicRoot(void) const override
   {
      return publicRoot_;
   }

   BinaryData getAccountID(void) const override;

   //bip32 locals
   unsigned getDepth(void) const { return depth_; }
   unsigned getLeafID(void) const { return leafId_; }
   unsigned getFingerPrint(void) const { return fingerPrint_; }
   std::vector<uint32_t> getDerivationPath(void) const 
   { return derivationPath_; }

   unsigned getSeedFingerprint(void) const { return seedFingerprint_; }

   unsigned getAddressLookup(void) const;
   void setAddressLookup(unsigned count) 
   { 
      addressLookup_ = count; 
   }

   void setNodes(const std::set<unsigned>& nodes);
   void setOuterAccountID(const BinaryData&);
   void setInnerAccountID(const BinaryData&);

   virtual AccountTypeEnum type(void) const override
   { return AccountTypeEnum_BIP32; }

   BinaryData getOuterAccountID(void) const override;
   BinaryData getInnerAccountID(void) const override;

   void addAddressType(AddressEntryType);
   void setDefaultAddressType(AddressEntryType);
};

////////////////////////////////////////////////////////////////////////////////
struct AccountType_BIP32_Salted : public AccountType_BIP32
{
private:
   const SecureBinaryData salt_;

public:
   AccountType_BIP32_Salted(
      const std::vector<unsigned>& derivationPath,
      const SecureBinaryData& salt) :
      AccountType_BIP32(derivationPath), salt_(salt)
   {}

   AccountTypeEnum type(void) const 
   { return AccountTypeEnum_BIP32_Salted; }

   const SecureBinaryData& getSalt(void) const 
   { return salt_; }
};

////////////////////////////////////////////////////////////////////////////////
class AccountType_ECDH : public AccountType
{
private:
   const SecureBinaryData privateKey_;
   const SecureBinaryData publicKey_;

   //ECDH accounts are always single
   const BinaryData accountID_;

public:
   //tor
   AccountType_ECDH(
      const SecureBinaryData& privKey,
      const SecureBinaryData& pubKey) :
      privateKey_(privKey), publicKey_(pubKey),
      accountID_(WRITE_UINT32_BE(ECDH_ASSET_ACCOUNTID))
   {
      //run checks
      if (privateKey_.getSize() == 0 && publicKey_.getSize() == 0)
         throw AccountException("invalid key length");
   }

   //local
   const SecureBinaryData& getPrivKey(void) const { return privateKey_; }
   const SecureBinaryData& getPubKey(void) const { return publicKey_; }

   //virtual
   AccountTypeEnum type(void) const override { return AccountTypeEnum_ECDH; }
   BinaryData getAccountID(void) const override;
   BinaryData getOuterAccountID(void) const override { return accountID_; }
   BinaryData getInnerAccountID(void) const override { return accountID_; }
   virtual bool isWatchingOnly(void) const override;
};

#endif