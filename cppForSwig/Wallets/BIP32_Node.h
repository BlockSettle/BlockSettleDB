////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _BIP32_SERIALIZATION_H
#define _BIP32_SERIALIZATION_H

#include "BtcUtils.h"
#include "EncryptionUtils.h"
#include "btc/bip32.h"

class BIP32_Node
{
private:
   SecureBinaryData chaincode_;
   SecureBinaryData privkey_;
   SecureBinaryData pubkey_;

   uint32_t depth_ = 0;
   uint32_t parentFingerprint_ = 0;
   uint32_t child_num_ = 0;

private:
   SecureBinaryData encodeBase58(void) const;
   void decodeBase58(const char*);
   void init(void);

   void setupNode(btc_hdnode*) const;
   void setupFromNode(const btc_hdnode*);

public:
   BIP32_Node(void)
   {}

   //init
   void initFromSeed(const SecureBinaryData&);
   void initFromBase58(BinaryDataRef);
   void initFromPrivateKey(uint8_t depth, unsigned leaf_id, unsigned fingerprint,
      const SecureBinaryData& privKey, const SecureBinaryData& chaincode);
   void initFromPublicKey(uint8_t depth, unsigned leaf_id, unsigned fingerprint,
      const SecureBinaryData& pubKey, const SecureBinaryData& chaincode);

   //gets
   SecureBinaryData getBase58(void) const { return encodeBase58(); }
   uint8_t getDepth(void) const { return depth_; }
   uint32_t getParentFingerprint(void) const { return parentFingerprint_; }
   uint32_t getThisFingerprint(void) const;
   unsigned getLeafID(void) const { return child_num_; }
   BIP32_Node getPublicCopy(void) const;

   const SecureBinaryData& getChaincode(void) const { return chaincode_; }
   const SecureBinaryData& getPrivateKey(void) const { return privkey_; }
   const SecureBinaryData& getPublicKey(void) const { return pubkey_; }
   
   bool isPublic(void) const;

   //moves
   SecureBinaryData&& moveChaincode(void) { return std::move(chaincode_); }
   SecureBinaryData&& movePrivateKey(void) { return std::move(privkey_); }
   SecureBinaryData&& movePublicKey(void) { return std::move(pubkey_); }

   //derivation
   void derivePrivate(unsigned);
   void derivePublic(unsigned);

   //static
   static btc_hdnode getHDNodeFromPrivateKey(
      uint8_t depth, unsigned leaf_id, unsigned fingerprint,
      const SecureBinaryData& privKey, const SecureBinaryData& chaincode);
};

#endif