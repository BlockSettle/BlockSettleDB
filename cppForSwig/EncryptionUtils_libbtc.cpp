////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////
#ifdef LIBBTC_ONLY
#include "EncryptionUtils.h"
#include "log.h"
#include "btc/ecc.h"
#include "btc/sha2.h"
#include "btc/ripemd160.h"
#include "btc/ctaes.h"

using namespace std;

#define CRYPTO_DEBUG false

/////////////////////////////////////////////////////////////////////////////
//// CryptoPRNG
/////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoPRNG::generateRandom(uint32_t numBytes,
   const SecureBinaryData& extraEntropy)
{
   SecureBinaryData sbd(numBytes);
   btc_random_init();
   if (!btc_random_bytes(sbd.getPtr(), numBytes, 0))
      throw runtime_error("failed to generate random value");

   if (extraEntropy.getSize() != 0)
      sbd.XOR(extraEntropy);

   return sbd;
}

/////////////////////////////////////////////////////////////////////////////
//// PRNG_Fortuna
/////////////////////////////////////////////////////////////////////////////
PRNG_Fortuna::PRNG_Fortuna()
{
   reseed();
}

/////////////////////////////////////////////////////////////////////////////
void PRNG_Fortuna::reseed() const
{
   nBytes_.store(0, memory_order_relaxed);
   auto rng = CryptoPRNG::generateRandom(32);

   auto newKey = make_shared<SecureBinaryData>(32);
   unsigned char digest[32];
   sha256_Raw(rng.getPtr(), rng.getSize(), digest);
   sha256_Raw(digest, 32, newKey->getPtr());

   atomic_store_explicit(&key_, newKey, memory_order_relaxed);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData PRNG_Fortuna::generateRandom(uint32_t numBytes,
   const SecureBinaryData& extraEntropy) const
{
   size_t blockCount = numBytes / AES_BLOCK_SIZE;
   size_t spill = numBytes % AES_BLOCK_SIZE;
   SecureBinaryData result(numBytes);

   unsigned char plainText[AES_BLOCK_SIZE];
   memset(&plainText, 0, AES_BLOCK_SIZE);

   //setup AES object, seed with key_
   auto keyPtr = atomic_load_explicit(&key_, memory_order_relaxed);
   AES256_ctx aes_ctx;
   AES256_init(&aes_ctx, keyPtr->getPtr());

   //main body
   for (unsigned i=0; i<blockCount; i++)
   {
      //set counters in plain text block
      for (unsigned y=0; y<4; y++)
      {
         auto ptr = (uint32_t*)plainText;
         *ptr = counter_.fetch_add(1, memory_order_relaxed);
      }

      //encrypt counters with key
      auto resultPtr = result.getPtr() + (i * AES_BLOCK_SIZE);
      AES256_encrypt(&aes_ctx, 1, resultPtr, plainText);

      //xor with extra entropy if available
      if (extraEntropy.getSize() >= (i + 1) * AES_BLOCK_SIZE)
      {
         auto entropyPtr = extraEntropy.getPtr() + (i * AES_BLOCK_SIZE);
         for (unsigned z=0; z<AES_BLOCK_SIZE; z++)
            resultPtr[z] ^= entropyPtr[z];
      }
   }

   //return if we have no spill
   if (spill > 0)
   {
      //deal with spill block
      for (unsigned y=0; y<4; y++)
      {
         auto ptr = (uint32_t*)plainText;
         *ptr = counter_.fetch_add(1, memory_order_relaxed);
      }

      unsigned char lastBlock[AES_BLOCK_SIZE];
      AES256_encrypt(&aes_ctx, 1, lastBlock, plainText); 
      
      if (extraEntropy.getSize() >= numBytes)
      {
         auto entropyPtr = 
            extraEntropy.getPtr() + blockCount * AES_BLOCK_SIZE;

         for (unsigned z=0; z<spill; z++)
            lastBlock[z] ^= entropyPtr[z];
      }

      memcpy(result.getPtr() + blockCount * AES_BLOCK_SIZE,
         lastBlock, spill);
   }

   //update size counter
   nBytes_.fetch_add(numBytes, memory_order_relaxed);

   //reseed after 1MB
   if (nBytes_.load(memory_order_relaxed) >= 1048576)
      reseed();

   return result;
}

/////////////////////////////////////////////////////////////////////////////
//// CryptoAES
/////////////////////////////////////////////////////////////////////////////
// Implement AES encryption using AES mode, CFB
SecureBinaryData CryptoAES::EncryptCFB(const SecureBinaryData & data, 
                                       const SecureBinaryData & key,
                                       const SecureBinaryData & iv)
{
   if(data.getSize() == 0)
      return SecureBinaryData(0);

   size_t packet_count = data.getSize() / AES_BLOCK_SIZE + 1;

   SecureBinaryData encrData(packet_count * AES_BLOCK_SIZE);

   //sanity check
   if(iv.getSize() != AES_BLOCK_SIZE)
      throw std::runtime_error("invalid IV size!");

   //set to cbc until i implement cbf in libbtc
   auto result = aes256_cbc_encrypt(
      key.getPtr(), iv.getPtr(),
      data.getPtr(), data.getSize(),
      1, //pad with 0s if the data is not aligned with 16 bytes blocks
      encrData.getPtr());
      
   if (result == 0)
   {
      LOGERR << "AES CBC encryption failed!";
      throw std::runtime_error("AES CBC encryption failed!");
   }
   else if (result != encrData.getSize())
   {
      LOGERR << "Encrypted data size mismatch!";
      throw std::runtime_error("Encrypted data size mismatch!");
   }

   return encrData;
}

/////////////////////////////////////////////////////////////////////////////
// Implement AES decryption using AES mode, CFB
SecureBinaryData CryptoAES::DecryptCFB(const SecureBinaryData & data, 
                                       const SecureBinaryData & key,
                                       const SecureBinaryData & iv  )
{
   if(data.getSize() == 0)
      return SecureBinaryData(0);

   SecureBinaryData unencrData(data.getSize());

   //set to cbc until i implement cbf in libbtc
   aes256_cbc_decrypt(
      key.getPtr(), iv.getPtr(), 
      data.getPtr(), data.getSize(), 
      1, //data is padded to 16 bytes blocks
      unencrData.getPtr());

   return unencrData;
}

/////////////////////////////////////////////////////////////////////////////
// Same as above, but only changing the AES mode of operation (CBC, not CFB)
SecureBinaryData CryptoAES::EncryptCBC(const SecureBinaryData & data, 
                                       const SecureBinaryData & key,
                                       const SecureBinaryData & iv)
{
   if(data.getSize() == 0)
      return SecureBinaryData(0);

   size_t packet_count = data.getSize() / AES_BLOCK_SIZE + 1;

   SecureBinaryData encrData(packet_count * AES_BLOCK_SIZE);

   //sanity check
   if (iv.getSize() != AES_BLOCK_SIZE)
      throw std::runtime_error("invalid IV size!");

   auto result = aes256_cbc_encrypt(
      key.getPtr(), iv.getPtr(),
      data.getPtr(), data.getSize(),
      1, //pad with 0s if the data is not aligned with 16 bytes blocks
      encrData.getPtr());
      
   if (result == 0)
   {
      LOGERR << "AES CBC encryption failed!";
      throw std::runtime_error("AES CBC encryption failed!");
   }
   else if (result != encrData.getSize())
   {
      LOGERR << "Encrypted data size mismatch!";
      throw std::runtime_error("Encrypted data size mismatch!");
   }

   return encrData;
}

/////////////////////////////////////////////////////////////////////////////
// Same as above, but only changing the AES mode of operation (CBC, not CFB)
SecureBinaryData CryptoAES::DecryptCBC(const SecureBinaryData & data, 
                                       const SecureBinaryData & key,
                                       const SecureBinaryData & iv  )
{
   if(data.getSize() == 0)
      return SecureBinaryData(0);

   SecureBinaryData unencrData(data.getSize());

   auto size = aes256_cbc_decrypt(
      key.getPtr(), iv.getPtr(),
      data.getPtr(), data.getSize(),
      1, //data is padded to 16 bytes blocks
      unencrData.getPtr());

   if (size == 0)
      throw runtime_error("failed to decrypt packet");

   if (size < unencrData.getSize())
      unencrData.resize(size);

   return unencrData;
}

/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::checkPrivKeyIsValid(const SecureBinaryData& privKey)
{
   if (privKey.getSize() != 32)
      return false;

   btc_key pkey;
   btc_privkey_init(&pkey);
   memcpy(pkey.privkey, privKey.getPtr(), 32);
   return btc_privkey_is_valid(&pkey);
}

/////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::ComputePublicKey(
   SecureBinaryData const & cppPrivKey, bool compressed) const
{
   if (cppPrivKey.getSize() != 32)
      throw runtime_error("invalid priv key size");

   btc_key pkey;
   btc_privkey_init(&pkey);
   memcpy(pkey.privkey, cppPrivKey.getPtr(), 32);
   if (!btc_privkey_is_valid(&pkey))
      throw runtime_error("invalid private key");

   btc_pubkey pubkey;
   btc_pubkey_init(&pubkey);

   SecureBinaryData result;
   size_t len;

   if (!compressed)
   {
      len = BTC_ECKEY_UNCOMPRESSED_LENGTH;
      btc_pubkey_from_key_uncompressed(&pkey, &pubkey);
   }
   else
   {
      len = BTC_ECKEY_COMPRESSED_LENGTH;
      btc_pubkey_from_key(&pkey, &pubkey);
   }

   result.resize(len);
   memcpy(result.getPtr(), pubkey.pubkey, len);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::VerifyPublicKeyValid(SecureBinaryData const & pubKey)
{
   if(CRYPTO_DEBUG)
   {
      cout << "BinPub: " << pubKey.toHexStr() << endl;
   }

   btc_pubkey key;
   btc_pubkey_init(&key);
   memcpy(key.pubkey, pubKey.getPtr(), pubKey.getSize());
   key.compressed = pubKey.getSize() == 33 ? true : false;
   return btc_pubkey_is_valid(&key);
}

/////////////////////////////////////////////////////////////////////////////
//// CryptoECDSA
/////////////////////////////////////////////////////////////////////////////
// Use the secp256k1 curve to sign data of an arbitrary length.
// Input:  Data to sign  (const SecureBinaryData&)
//         The private key used to sign the data  (const BTC_PRIVKEY&)
//         A flag indicating if deterministic signing is used  (const bool&)
// Output: None
// Return: The signature of the data  (SecureBinaryData)
SecureBinaryData CryptoECDSA::SignData(SecureBinaryData const & binToSign, 
   SecureBinaryData const & cppPrivKey, const bool&)
{
   // We trick the Crypto++ ECDSA module by passing it a single-hashed
   // message, it will do the second hash before it signs it.  This is 
   // exactly what we need.

   //hash message
   SecureBinaryData digest1(32), digest2(32);
   sha256_Raw(binToSign.getPtr(), binToSign.getSize(), digest1.getPtr());
   sha256_Raw(digest1.getPtr(), 32, digest2.getPtr());

   // Only use RFC 6979
   SecureBinaryData sig(74);
   size_t outlen = 74;

   btc_key pkey;
   btc_privkey_init(&pkey);
   memcpy(pkey.privkey, cppPrivKey.getPtr(), 32);

   btc_key_sign_hash(&pkey, digest2.getPtr(), sig.getPtr(), &outlen);
   if(outlen != 74)
      sig.resize(outlen);

   return sig;
}

/////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::VerifyData(BinaryData const & binMessage,
   const BinaryData& sig,
   BinaryData const & cppPubKey) const
{
   /***
   This is the faster sig verification, with less sanity checks and copies.
   Meant for chain verifiation, use the SecureBinaryData versions for regular
   verifications.
   ***/

   //pub keys are already validated by the script parser

   // We execute the first SHA256 op, here.  Next one is done by Verifier
   BinaryData digest1(32), digest2(32);
   sha256_Raw(binMessage.getPtr(), binMessage.getSize(), digest1.getPtr());
   sha256_Raw(digest1.getPtr(), 32, digest2.getPtr());

   //setup pubkey
   btc_pubkey key;
   btc_pubkey_init(&key);
   memcpy(key.pubkey, cppPubKey.getPtr(), cppPubKey.getSize());
   key.compressed = cppPubKey.getSize() == 33 ? true : false;

   // Verifying message 
   return btc_pubkey_verify_sig(
      &key, digest2.getPtr(),
      (unsigned char*)sig.getCharPtr(), sig.getSize());
}

/////////////////////////////////////////////////////////////////////////////
// Deterministically generate new private key using a chaincode
// Changed:  added using the hash of the public key to the mix
//           b/c multiplying by the chaincode alone is too "linear"
//           (there's no reason to believe it's insecure, but it doesn't
//           hurt to add some extra entropy/non-linearity to the chain
//           generation process)
SecureBinaryData CryptoECDSA::ComputeChainedPrivateKey(
                                 SecureBinaryData const & binPrivKey,
                                 SecureBinaryData const & chainCode,
                                 SecureBinaryData* multiplierOut)
{
   auto&& binPubKey = ComputePublicKey(binPrivKey);

   if( binPrivKey.getSize() != 32 || chainCode.getSize() != 32)
   {
      LOGERR << "***ERROR:  Invalid private key or chaincode (both must be 32B)";
      LOGERR << "BinPrivKey: " << binPrivKey.getSize();
      LOGERR << "BinPrivKey: (not logged for security)";
      LOGERR << "BinChain  : " << chainCode.getSize();
      LOGERR << "BinChain  : " << chainCode.toHexStr();
   }

   // Adding extra entropy to chaincode by xor'ing with hash256 of pubkey
   BinaryData chainMod  = binPubKey.getHash256();
   BinaryData chainOrig = chainCode.getRawCopy();
   BinaryData chainXor(32);
      
   for(uint8_t i=0; i<8; i++)
   {
      uint8_t offset = 4*i;
      *(uint32_t*)(chainXor.getPtr()+offset) =
                           *(uint32_t*)( chainMod.getPtr()+offset) ^ 
                           *(uint32_t*)(chainOrig.getPtr()+offset);
   }

   SecureBinaryData newPrivData(binPrivKey);
   if (!btc_ecc_private_key_tweak_mul((uint8_t*)newPrivData.getPtr(), chainXor.getPtr()))
      throw runtime_error("failed to multiply priv key");

   if(multiplierOut != NULL)
      (*multiplierOut) = SecureBinaryData(chainXor);

   return newPrivData;
}
                            
/////////////////////////////////////////////////////////////////////////////
// Deterministically generate new public key using a chaincode
SecureBinaryData CryptoECDSA::ComputeChainedPublicKey(
                                SecureBinaryData const & binPubKey,
                                SecureBinaryData const & chainCode,
                                SecureBinaryData* multiplierOut)
{
   if(CRYPTO_DEBUG)
   {
      cout << "ComputeChainedPUBLICKey:" << endl;
      cout << "   BinPub: " << binPubKey.toHexStr() << endl;
      cout << "   BinChn: " << chainCode.toHexStr() << endl;
   }

   // Added extra entropy to chaincode by xor'ing with hash256 of pubkey
   BinaryData chainMod  = binPubKey.getHash256();
   BinaryData chainOrig = chainCode.getRawCopy();
   BinaryData chainXor(32);
      
   for(uint8_t i=0; i<8; i++)
   {
      uint8_t offset = 4*i;
      *(uint32_t*)(chainXor.getPtr()+offset) =
                           *(uint32_t*)( chainMod.getPtr()+offset) ^ 
                           *(uint32_t*)(chainOrig.getPtr()+offset);
   }

   SecureBinaryData pubKeyResult(binPubKey);
   if (!btc_ecc_public_key_tweak_mul((uint8_t*)pubKeyResult.getPtr(), chainXor.getPtr()))
      throw runtime_error("failed to multiply pubkey");

   if(multiplierOut != NULL)
      (*multiplierOut) = SecureBinaryData(chainXor);

   return pubKeyResult;
}

////////////////////////////////////////////////////////////////////////////////
bool CryptoECDSA::ECVerifyPoint(BinaryData const & x,
                                BinaryData const & y)
{
   BinaryWriter bw;
   bw.put_uint8_t(4);
   bw.put_BinaryData(x);
   bw.put_BinaryData(y);
   auto ptr = bw.getDataRef().getPtr();

   return btc_ecc_verify_pubkey(ptr, false);
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::CompressPoint(SecureBinaryData const & pubKey65)
{
   SecureBinaryData ptCompressed(33);
   if (!btc_ecc_public_key_compress(
      (uint8_t*)pubKey65.getPtr(), ptCompressed.getPtr()))
   {
      ptCompressed = pubKey65;
   }

   return ptCompressed; 
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::UncompressPoint(SecureBinaryData const & pubKey33)
{
   SecureBinaryData ptUncompressed(65);
   if(!btc_ecc_public_key_uncompress((uint8_t*)pubKey33.getPtr(), ptUncompressed.getPtr()))
      ptUncompressed = pubKey33;

   return ptUncompressed; 
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::PrivKeyScalarMultiply(
   const SecureBinaryData& privKey,
   const SecureBinaryData& scalar)
{
   SecureBinaryData newPrivData(privKey);
   if (!btc_ecc_private_key_tweak_mul(
      (uint8_t*)newPrivData.getPtr(), scalar.getPtr()))
      throw runtime_error("failed to multiply priv key");

   return newPrivData;
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData CryptoECDSA::PubKeyScalarMultiply(
   const SecureBinaryData& pubKey,
   const SecureBinaryData& scalar)
{
   SecureBinaryData newPubData;
   if (pubKey.getSize() == 33)
   {
      newPubData.resize(65);
      if (!btc_ecc_public_key_uncompress(
         (uint8_t*)pubKey.getPtr(), (uint8_t*)newPubData.getPtr()))
         throw runtime_error("failed to uncompress point");
   }
   else
   {
      newPubData = pubKey;
   }
   
   if (!btc_ecc_public_key_tweak_mul(
      (uint8_t*)newPubData.getPtr(), scalar.getPtr()))
      throw runtime_error("failed to multiply pub key");

   if (pubKey.getSize() == 65)
      return newPubData;

   SecureBinaryData result(33);
   if (!btc_ecc_public_key_compress(newPubData.getPtr(), (uint8_t*)result.getPtr()))
      throw runtime_error("failed to compress point");

   return result;
}

/////////////////////////////////////////////////////////////////////////////
//// CryptoSHA2
////////////////////////////////////////////////////////////////////////////////
void CryptoSHA2::getHash256(BinaryDataRef bdr, uint8_t* digest)
{
   sha256_Raw(bdr.getPtr(), bdr.getSize(), digest);
   sha256_Raw(digest, 32, digest);
}

////////////////////////////////////////////////////////////////////////////////
void CryptoSHA2::getSha256(BinaryDataRef bdr, uint8_t* digest)
{
   sha256_Raw(bdr.getPtr(), bdr.getSize(), digest);
}

////////////////////////////////////////////////////////////////////////////////
void CryptoSHA2::getHMAC256(BinaryDataRef data, BinaryDataRef msg, 
   uint8_t* digest)
{
   hmac_sha256(data.getPtr(), data.getSize(), msg.getPtr(), msg.getSize(), 
      digest);
}

////////////////////////////////////////////////////////////////////////////////
void CryptoSHA2::getSha512(BinaryDataRef bdr, uint8_t* digest)
{
   sha512_Raw(bdr.getPtr(), bdr.getSize(), digest);
}

////////////////////////////////////////////////////////////////////////////////
void CryptoSHA2::getHMAC512(BinaryDataRef data, BinaryDataRef msg,
   uint8_t* digest)
{
   hmac_sha512(data.getPtr(), data.getSize(), msg.getPtr(), msg.getSize(),
      digest);
}

/////////////////////////////////////////////////////////////////////////////
//// CryptoHASH160
////////////////////////////////////////////////////////////////////////////////
void CryptoHASH160::getHash160(BinaryDataRef bdr, uint8_t* digest)
{
   btc_ripemd160(bdr.getPtr(), bdr.getSize(), digest);
}

#endif