////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BIP32_Node.h"
#include <Utils/BtcUtils.h>
#include <Utils/BitcoinSettings.h>

using namespace Armory;

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::init()
{
   if (!privkey_.empty()) {
      privkey_.clear();
   }
   privkey_.resize(BTC_ECKEY_PKEY_LENGTH);
   memset(privkey_.getPtr(), 0, BTC_ECKEY_PKEY_LENGTH);

   if (!pubkey_.empty()) {
      pubkey_.clear();
   }
   pubkey_.resize(BTC_ECKEY_COMPRESSED_LENGTH);
   memset(pubkey_.getPtr(), 0, BTC_ECKEY_COMPRESSED_LENGTH);

   if (!chaincode_.empty()) {
      chaincode_.clear();
   }
   chaincode_.resize(BTC_BIP32_CHAINCODE_SIZE);
   memset(chaincode_.getPtr(), 0, BTC_BIP32_CHAINCODE_SIZE);
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::setupNode(btc_hdnode* node) const
{
   if (!chaincode_.empty()) {
      memcpy(node->chain_code, chaincode_.getPtr(), BTC_BIP32_CHAINCODE_SIZE);
   }
   if (!privkey_.empty()) {
      memcpy(node->private_key, privkey_.getPtr(), BTC_ECKEY_PKEY_LENGTH);
   }
   if (!pubkey_.empty()) {
      memcpy(node->public_key, pubkey_.getPtr(), BTC_ECKEY_COMPRESSED_LENGTH);
   }
   node->depth = depth_;
   node->child_num = child_num_;
   node->fingerprint = parentFingerprint_;
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::setupFromNode(const btc_hdnode* node)
{
   init();
   memcpy(chaincode_.getPtr(), node->chain_code, BTC_BIP32_CHAINCODE_SIZE);
   memcpy(privkey_.getPtr(), node->private_key, BTC_ECKEY_PKEY_LENGTH);
   memcpy(pubkey_.getPtr(), node->public_key, BTC_ECKEY_COMPRESSED_LENGTH);

   depth_ = node->depth;
   child_num_ = node->child_num;
   parentFingerprint_ = node->fingerprint;
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData BIP32_Node::encodeBase58() const
{
   if (chaincode_.getSize() != BTC_BIP32_CHAINCODE_SIZE) {
      throw std::runtime_error("invalid chaincode for BIP32 ser");
   }

   size_t result_len = 200;
   SecureBinaryData result(result_len);
   btc_hdnode node;
   setupNode(&node);

   if (!isPublic()) {
      btc_hdnode_serialize_private(
         &node,
         Armory::Config::BitcoinSettings::getChainParams(),
         (char*)result.getPtr(), result_len);
   } else if (pubkey_.getSize() == BTC_ECKEY_COMPRESSED_LENGTH) {
      btc_hdnode_serialize_public(
         &node,
         Armory::Config::BitcoinSettings::getChainParams(),
         (char*)result.getPtr(), result_len);
   } else {
      throw std::runtime_error("uninitialized BIP32 object, cannot encode");
   }

   auto finalLen = strnlen(result.getCharPtr(), result_len);
   if (finalLen == 0 || finalLen == result_len) {
      throw std::runtime_error("failed to serialized bip32 string");
   }
   result.resize(finalLen);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::decodeBase58(const char* str)
{
   btc_hdnode node;

   //b58 decode
   if (!btc_hdnode_deserialize(
      str, Armory::Config::BitcoinSettings::getChainParams(), &node)) {
      throw std::runtime_error("invalid bip32 serialized string");
   }
   setupFromNode(&node);
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromSeed(const SecureBinaryData& seed)
{
   btc_hdnode node;
   if (!btc_hdnode_from_seed(seed.getPtr(), seed.getSize(), &node)) {
      throw std::runtime_error("failed to setup seed");
   }
   setupFromNode(&node);
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromBase58(BinaryDataRef b58)
{
   //sbd doesnt 0 terminate strings as it is not specialized for char strings,
   //have to set it manually since libbtc b58 code derives string length from
   //strlen
   SecureBinaryData b58_copy(b58.getSize() + 1);
   memcpy(b58_copy.getPtr(), b58.getPtr(), b58.getSize());
   b58_copy.getPtr()[b58.getSize()] = 0;
   decodeBase58(b58_copy.getCharPtr());
}

////////////////////////////////////////////////////////////////////////////////
btc_hdnode BIP32_Node::getHDNodeFromPrivateKey(
   uint8_t depth, unsigned leaf_id, unsigned fingerPrint,
   const SecureBinaryData& privKey, const SecureBinaryData& chaincode)
{
   if (privKey.getSize() != BTC_ECKEY_PKEY_LENGTH) {
      throw std::runtime_error("unexpected private key size");
   }
   if (chaincode.getSize() != BTC_BIP32_CHAINCODE_SIZE) {
      throw std::runtime_error("unexpected chaincode size");
   }

   btc_hdnode node;
   memcpy(node.chain_code, chaincode.getPtr(), BTC_BIP32_CHAINCODE_SIZE);
   memcpy(node.private_key, privKey.getPtr(), BTC_ECKEY_PKEY_LENGTH);

   node.depth = depth;
   node.child_num = leaf_id;
   node.fingerprint = fingerPrint;

   btc_hdnode_fill_public_key(&node);
   return node;
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromPrivateKey(
   uint8_t depth, unsigned leaf_id, unsigned fingerPrint,
   const SecureBinaryData& privKey, const SecureBinaryData& chaincode)
{
   auto node = getHDNodeFromPrivateKey(
      depth, leaf_id, fingerPrint,
      privKey, chaincode);
   setupFromNode(&node);
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::initFromPublicKey(
   uint8_t depth, unsigned leaf_id, unsigned fingerPrint,
   const SecureBinaryData& pubKey, const SecureBinaryData& chaincode)
{
   if (pubKey.getSize() != BTC_ECKEY_COMPRESSED_LENGTH) {
      throw std::runtime_error("unexpected private key size");
   }
   if (chaincode.getSize() != BTC_BIP32_CHAINCODE_SIZE) {
      throw std::runtime_error("unexpected chaincode size");
   }

   init();
   memcpy(pubkey_.getPtr(), pubKey.getPtr(), BTC_ECKEY_COMPRESSED_LENGTH);
   memcpy(chaincode_.getPtr(), chaincode.getPtr(), BTC_BIP32_CHAINCODE_SIZE);

   depth_ = depth;
   child_num_ = leaf_id;
   parentFingerprint_ = fingerPrint;
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData BIP32_Node::getBase58() const
{
   return encodeBase58();
}

////
uint8_t BIP32_Node::getDepth() const
{
   return depth_;
}

////
uint32_t BIP32_Node::getParentFingerprint() const
{
   return parentFingerprint_;
}

////
unsigned BIP32_Node::getLeafID() const
{
   return child_num_;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& BIP32_Node::getChaincode() const
{
   return chaincode_;
}

////
const SecureBinaryData& BIP32_Node::getPrivateKey() const
{
   return privkey_;
}

////
const SecureBinaryData& BIP32_Node::getPublicKey() const
{
   return pubkey_;
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::derivePrivate(unsigned id)
{
   btc_hdnode node;
   setupNode(&node);
   if (!btc_hdnode_private_ckd(&node, id)) {
      throw std::runtime_error("failed to derive bip32 private key");
   }
   setupFromNode(&node);
}

////////////////////////////////////////////////////////////////////////////////
void BIP32_Node::derivePublic(unsigned id)
{
   btc_hdnode node;
   setupNode(&node);
   if (!btc_hdnode_public_ckd(&node, id)) {
      throw std::runtime_error("failed to derive bip32 public key");
   }
   setupFromNode(&node);
}

////////////////////////////////////////////////////////////////////////////////
BIP32_Node BIP32_Node::getPublicCopy() const
{
   BIP32_Node copy;
   copy.initFromPublicKey(
      getDepth(), getLeafID(), getParentFingerprint(),
      getPublicKey(), getChaincode());
   return copy;
}

////////////////////////////////////////////////////////////////////////////////
bool BIP32_Node::isPublic() const
{
   if (privkey_.empty() || privkey_ == BtcUtils::EmptyHash) {
      return true;
   }
   return false;
}

////////////////////////////////////////////////////////////////////////////////
uint32_t BIP32_Node::getThisFingerprint() const
{
   if (pubkey_.empty()) {
      throw std::runtime_error("missing public key");
   }
   auto hash = BtcUtils::getHash160(pubkey_);
   auto fingerprint = (uint32_t*)hash.getPtr();
   return *fingerprint;
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData&& BIP32_Node::moveChaincode()
{
   return std::move(chaincode_);
}

////
SecureBinaryData&& BIP32_Node::movePrivateKey()
{
   return std::move(privkey_);
}

////
SecureBinaryData&& BIP32_Node::movePublicKey()
{
   return std::move(pubkey_);
}
