////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _BIP32_SERIALIZATION_H
#define _BIP32_SERIALIZATION_H

#include "btc/bip32.h"
#include "Utils/SecureBinaryData.h"

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
   SecureBinaryData getBase58(void) const;
   uint8_t getDepth(void) const;
   uint32_t getParentFingerprint(void) const;
   uint32_t getThisFingerprint(void) const;
   unsigned getLeafID(void) const;
   BIP32_Node getPublicCopy(void) const;

   const SecureBinaryData& getChaincode(void) const;
   const SecureBinaryData& getPrivateKey(void) const;
   const SecureBinaryData& getPublicKey(void) const;

   bool isPublic(void) const;

   //moves
   SecureBinaryData&& moveChaincode(void);
   SecureBinaryData&& movePrivateKey(void);
   SecureBinaryData&& movePublicKey(void);

   //derivation
   void derivePrivate(unsigned);
   void derivePublic(unsigned);

   //static
   static btc_hdnode getHDNodeFromPrivateKey(
      uint8_t depth, unsigned leaf_id, unsigned fingerprint,
      const SecureBinaryData& privKey, const SecureBinaryData& chaincode);
};

#endif