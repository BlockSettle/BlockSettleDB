////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "AccountTypes.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AccountType::~AccountType()
{}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_WithRoot
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AccountType_WithRoot::~AccountType_WithRoot()
{}

////////////////////////////////////////////////////////////////////////////////
void AccountType::setAddressTypes(
   const std::set<AddressEntryType>& addrTypeSet)
{
   addressTypes_ = addrTypeSet;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType::setDefaultAddressType(AddressEntryType addrType)
{
   defaultAddressEntryType_ = addrType;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_ArmoryLegacy
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AccountType_ArmoryLegacy::getChaincode() const
{
   if (chainCode_.getSize() == 0)
   {
      auto& root = getPrivateRoot();
      if (root.getSize() == 0)
         throw AssetException("cannot derive chaincode from empty root");

      chainCode_ = move(BtcUtils::computeChainCode_Armory135(root));
   }

   return chainCode_;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AccountType_ArmoryLegacy::getOuterAccountID(void) const
{
   return WRITE_UINT32_BE(ARMORY_LEGACY_ASSET_ACCOUNTID);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AccountType_ArmoryLegacy::getInnerAccountID(void) const
{
   return WRITE_UINT32_BE(ARMORY_LEGACY_ASSET_ACCOUNTID);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_BIP32
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BinaryData AccountType_BIP32::getAccountID() const
{
   //this ensures address accounts of different types based on the same
   //bip32 root do not end up with the same id

   BinaryWriter bw;
   bw.put_BinaryData(getPublicRoot());
   if (bw.getSize() == 0)
      throw AccountException("empty public root");

   //add in unique data identifying this account

   //account soft derivation paths
   for (auto& node : nodes_)
      bw.put_uint32_t(node, BE);
   
   //accounts structure
   if (!outerAccount_.empty())
      bw.put_BinaryData(outerAccount_);
   
   if (!innerAccount_.empty())
      bw.put_BinaryData(innerAccount_);

   //address types
   for (auto& addressType : addressTypes_)
      bw.put_uint32_t(addressType, BE);
   
   //default address
   bw.put_uint32_t(defaultAddressEntryType_);

   //main flag
   bw.put_uint8_t(isMain_);

   //hash, use first 4 bytes
   auto&& pub_hash160 = BtcUtils::getHash160(bw.getData());
   auto accountID = move(pub_hash160.getSliceCopy(0, 4));

   if (accountID == WRITE_UINT32_BE(ARMORY_LEGACY_ACCOUNTID) ||
       accountID == WRITE_UINT32_BE(IMPORTS_ACCOUNTID))
      throw AccountException("BIP32 account ID collision");

   return accountID;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::addAddressType(AddressEntryType addrType)
{
   addressTypes_.insert(addrType);
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setDefaultAddressType(AddressEntryType addrType)
{
   defaultAddressEntryType_ = addrType;
}

void AccountType_BIP32::setNodes(const std::set<unsigned>& nodes)
{
   nodes_ = nodes;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AccountType_BIP32::getOuterAccountID(void) const
{
   if (outerAccount_.getSize() > 0)
      return outerAccount_;

   return WRITE_UINT32_BE(UINT32_MAX);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AccountType_BIP32::getInnerAccountID(void) const
{
   if (innerAccount_.getSize() > 0)
      return innerAccount_;

   return WRITE_UINT32_BE(UINT32_MAX);
}

////////////////////////////////////////////////////////////////////////////////
unsigned AccountType_BIP32::getAddressLookup() const
{
   if (addressLookup_ == UINT32_MAX)
      throw AccountException("uninitialized address lookup");
   return addressLookup_;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setOuterAccountID(const BinaryData& outerAccount)
{
   outerAccount_ = outerAccount;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setInnerAccountID(const BinaryData& innerAccount)
{
   innerAccount_ = innerAccount;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setPrivateKey(const SecureBinaryData& key)
{
   privateRoot_ = key;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setPublicKey(const SecureBinaryData& key)
{
   publicRoot_ = key;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setChaincode(const SecureBinaryData& key)
{
   chainCode_ = key;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_ECDH
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
bool AccountType_ECDH::isWatchingOnly(void) const
{
   return privateKey_.empty();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AccountType_ECDH::getAccountID() const
{
   BinaryData accountID;
   if (isWatchingOnly())
   {
      //this ensures address accounts of different types based on the same
      //bip32 root do not end up with the same id
      auto rootCopy = publicKey_;
      rootCopy.getPtr()[0] ^= (uint8_t)type();

      auto&& pub_hash160 = BtcUtils::getHash160(rootCopy);
      accountID = move(pub_hash160.getSliceCopy(0, 4));
   }
   else
   {
      auto&& root_pub = CryptoECDSA().ComputePublicKey(privateKey_);
      root_pub.getPtr()[0] ^= (uint8_t)type();

      auto&& pub_hash160 = BtcUtils::getHash160(root_pub);
      accountID = move(pub_hash160.getSliceCopy(0, 4));
   }

   if (accountID == WRITE_UINT32_BE(ARMORY_LEGACY_ACCOUNTID) ||
      accountID == WRITE_UINT32_BE(IMPORTS_ACCOUNTID))
      throw AccountException("BIP32 account ID collision");

   return accountID;
}