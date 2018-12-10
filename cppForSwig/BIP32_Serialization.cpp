////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BIP32_Serialization.h"
#include "NetworkConfig.h"

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::init()
{
   if (privkey_.getSize() > 0)
      privkey_.clear();
   privkey_.resize(BTC_ECKEY_PKEY_LENGTH);
   memset(privkey_.getPtr(), 0, BTC_ECKEY_PKEY_LENGTH);

   if (pubkey_.getSize() > 0)
      pubkey_.clear();
   pubkey_.resize(BTC_ECKEY_COMPRESSED_LENGTH);
   memset(pubkey_.getPtr(), 0, BTC_ECKEY_COMPRESSED_LENGTH);

   if (chaincode_.getSize() > 0)
      chaincode_.clear();
   chaincode_.resize(BTC_BIP32_CHAINCODE_SIZE);
   memset(chaincode_.getPtr(), 0, BTC_BIP32_CHAINCODE_SIZE);

   node_.depth = 0;
   node_.child_num = 0;
   node_.fingerprint = 0;

   assign();
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::assign()
{
   node_.chain_code = chaincode_.getPtr();
   node_.private_key = privkey_.getPtr();
   node_.public_key = pubkey_.getPtr();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData BIP32_Node::computeFingerprint(const SecureBinaryData& key)
{
   auto compute_fingerprint = [](const SecureBinaryData& key)->BinaryData
   {
      return BtcUtils::hash160(key).getSliceCopy(0, 4);
   };

   bool ispriv = false;

   if (key.getSize() == 32)
   {
      ispriv = true;
   }
   else if (key.getSize() == 33)
   {
      if (key.getPtr()[0] == 0)
         ispriv = true;
   }

   if (ispriv)
   {
      BinaryDataRef privkey = key.getRef();
      if (privkey.getSize() == 33)
         privkey = key.getSliceRef(1, 32);

      auto&& pubkey = CryptoECDSA().ComputePublicKey(privkey);
      auto&& compressed_pub = CryptoECDSA().CompressPoint(pubkey);

      return compute_fingerprint(compressed_pub);
   }
   else
   {
      if (key.getSize() != 33)
      {
         auto&& compressed_pub = CryptoECDSA().CompressPoint(key);
         return compute_fingerprint(compressed_pub);
      }
      else
      {
         return compute_fingerprint(key);
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
std::string BIP32_Node::encodeBase58() const
{
   if (chaincode_.getSize() != BTC_BIP32_CHAINCODE_SIZE)
      throw std::runtime_error("invalid chaincode for BIP32 ser");

   size_t result_len = 200;
   char* result_char = new char[result_len];
   memset(result_char, 0, result_len);

   if (privkey_.getSize() == BTC_ECKEY_PKEY_LENGTH)
   {
      btc_hdnode_serialize_private(
         &node_, NetworkConfig::get_chain_params(), result_char, result_len);
   }
   else if (pubkey_.getSize() == BTC_ECKEY_COMPRESSED_LENGTH)
   {
      btc_hdnode_serialize_public(
         &node_, NetworkConfig::get_chain_params(), result_char, result_len);
   }
   else
   {
      delete[] result_char;
      throw std::runtime_error("uninitialized BIP32 object, cannot encode");
   }

   if (strlen(result_char) == 0)
   throw std::runtime_error("failed to serialized bip32 string");

   std::string result = result_char;
   delete[] result_char;
   return result;
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::decodeBase58(const std::string& str)
{
   //b58 decode 
   if(!btc_hdnode_deserialize(
      str.c_str(), NetworkConfig::get_chain_params(), &node_))
      throw std::runtime_error("invalid bip32 serialized string");
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromSeed(const SecureBinaryData& seed)
{
   init();
   if (!btc_hdnode_from_seed(seed.getPtr(), seed.getSize(), &node_))
      throw std::runtime_error("failed to setup seed");
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromBase58(const std::string& str)
{
   init();
   decodeBase58(str);
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromPrivateKey(uint8_t depth, unsigned leaf_id,
   const SecureBinaryData& privKey, const SecureBinaryData& chaincode)
{
   if (privKey.getSize() != BTC_ECKEY_PKEY_LENGTH)
      throw std::runtime_error("unexpected private key size");

   if (chaincode.getSize() != BTC_BIP32_CHAINCODE_SIZE)
      throw std::runtime_error("unexpected chaincode size");

   init();
   memcpy(privkey_.getPtr(), privKey.getPtr(), BTC_ECKEY_PKEY_LENGTH);
   memcpy(chaincode_.getPtr(), chaincode.getPtr(), BTC_BIP32_CHAINCODE_SIZE);

   node_.depth = depth;
   node_.child_num = leaf_id;
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromPublicKey(uint8_t depth, unsigned leaf_id,
   const SecureBinaryData& pubKey, const SecureBinaryData& chaincode)
{
   if (pubKey.getSize() != BTC_ECKEY_COMPRESSED_LENGTH)
      throw std::runtime_error("unexpected private key size");

   if (chaincode.getSize() != BTC_BIP32_CHAINCODE_SIZE)
      throw std::runtime_error("unexpected chaincode size");

   init();
   memcpy(pubkey_.getPtr(), pubKey.getPtr(), BTC_ECKEY_COMPRESSED_LENGTH);
   memcpy(chaincode_.getPtr(), chaincode.getPtr(), BTC_BIP32_CHAINCODE_SIZE);

   node_.depth = depth;
   node_.child_num = leaf_id;
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::derivePrivate(unsigned id)
{
   if (!btc_hdnode_private_ckd(&node_, id))
      throw std::runtime_error("failed to derive bip32 private key");
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::derivePublic(unsigned id)
{
   if (!btc_hdnode_public_ckd(&node_, id))
      throw std::runtime_error("failed to derive bip32 public key");
}

////////////////////////////////////////////////////////////////////////////////
BIP32_Node BIP32_Node::getPublicCopy() const
{
   BIP32_Node copy;
   copy.initFromPublicKey(
      getDepth(), getLeafID(), getPublicKey(), getChaincode());

   copy.node_ = node_;
   copy.privkey_.clear();
   copy.assign();

   return copy;
}