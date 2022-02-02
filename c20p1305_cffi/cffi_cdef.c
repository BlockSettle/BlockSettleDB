////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2021, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <string.h>

#include "cffi_cdecl.h"
#include "../cppForSwig/chacha20poly1305/poly1305.h"
#include "../cppForSwig/chacha20poly1305/chachapoly_aead.h"
#include <src/secp256k1/include/secp256k1.h>
#include <include/btc/ecc.h>
#include <include/btc/random.h>
#include <include/btc/hash.h>
#include <include/btc/hmac.h>
#include "../cppForSwig/hkdf/hkdf.h"

//so that assert isn't a no-op in release builds
#undef NDEBUG
#include <assert.h>

#define BIP151PUBKEYSIZE 33
#define BIP151PRVKEYSIZE 32
#define DERSIG_SIZE 72

#define CIPHERSUITE_CHACHA20POLY1305_OPENSSH 0
#define AAD_LEN 4

secp256k1_context* cffi_secp256k1_context;

typedef struct chachapolyaead_ctx chachapolyaead_ctx;

bool bip151_channel_generate_secret_chacha20poly1305_openssh(
   bip151_channel*, const uint8_t*, size_t);
void calc_chacha20poly1305_keys(bip151_channel*);
void calc_sessionid(bip151_channel*);
////////////////////////////////////////////////////////////////////////////////
//
// Utils
//
////////////////////////////////////////////////////////////////////////////////
uint8_t* generate_random(size_t len)
{
   uint8_t* randomBytes = (uint8_t*)malloc(len);
   if (!btc_random_bytes(randomBytes, len, 0))
   {
      free(randomBytes);
      return 0;
   }

   return randomBytes;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* compute_pubkey(const uint8_t* privkey)
{
   secp256k1_pubkey btcPubKey;
   size_t pubKeySize = BIP151PUBKEYSIZE;
   uint8_t* pubKeyBin = (uint8_t*)malloc(pubKeySize);

   secp256k1_ec_pubkey_create(
      cffi_secp256k1_context,
      &btcPubKey, privkey);

   secp256k1_ec_pubkey_serialize(
      cffi_secp256k1_context,
      pubKeyBin, &pubKeySize,
      &btcPubKey, SECP256K1_EC_COMPRESSED);

   if (pubKeySize != BIP151PUBKEYSIZE)
      return NULL;

   return pubKeyBin;
}

////////////////////////////////////////////////////////////////////////////////
bool isNull(const void* ptr)
{
   return ptr == NULL;
}

////////////////////////////////////////////////////////////////////////////////
void freeBuffer(void* buffer)
{
   if (buffer == NULL)
      return;

   free(buffer);
}

////////////////////////////////////////////////////////////////////////////////
//
// bip151 channel setup
//
////////////////////////////////////////////////////////////////////////////////
size_t bip15x_init_lib()
{
   //call this once before using any other calls
   uint8_t seed[32];

   btc_ecc_start();
   cffi_secp256k1_context = secp256k1_context_create(
      SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

   assert(btc_random_bytes(seed, 32, 0));
   assert(secp256k1_context_randomize(cffi_secp256k1_context, seed));

   return POLY1305_TAGLEN;
}

////////////////////////////////////////////////////////////////////////////////
bip151_channel* bip151_channel_makenew()
{
   bip151_channel* channel = (bip151_channel*)malloc(sizeof(bip151_channel));

   channel->ctx_ = (chachapolyaead_ctx*)malloc(sizeof(chachapolyaead_ctx));
   chacha20poly1305_init(channel->ctx_, 0, 0);

   channel->privkey_ = (btc_key*)malloc(sizeof(btc_key));
   btc_privkey_init(channel->privkey_);
   btc_privkey_gen(channel->privkey_);

   channel->seqNum_ = 0;

   return channel;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip151_channel_getencinit(bip151_channel* channel)
{
   secp256k1_pubkey ourPubKey;
   size_t encinit_len = BIP151PUBKEYSIZE;
   uint8_t* encinit = (uint8_t*)malloc(encinit_len + 1);

   if (!secp256k1_ec_pubkey_create(
      cffi_secp256k1_context,
      &ourPubKey, channel->privkey_->privkey))
   {
      free(encinit);
      return NULL;
   }

   secp256k1_ec_pubkey_serialize(
      cffi_secp256k1_context,
      encinit, &encinit_len,
      &ourPubKey, SECP256K1_EC_COMPRESSED);

   if (encinit_len != BIP151PUBKEYSIZE)
      return NULL;

   //append cipher suite flag to the pubkey
   channel->cipherSuite_ = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;
   encinit[33] = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;

   return encinit;
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_channel_processencinit(
   bip151_channel* channel, const uint8_t* payload, size_t len)
{
   uint8_t cipherSuite;

   if (payload == NULL || len < 1)
      return false;

   //check cipher suite flag
   cipherSuite = payload[len - 1];
   switch (cipherSuite)
   {
   case CIPHERSUITE_CHACHA20POLY1305_OPENSSH:
   {
      channel->cipherSuite_ = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;
      if (!bip151_channel_generate_secret_chacha20poly1305_openssh(
         channel, payload, len - 1))
      {
         return false;
      }

      calc_chacha20poly1305_keys(channel);
      calc_sessionid(channel);
      return true;
   }

   default:
      break;
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip151_channel_getencack(bip151_channel* channel)
{
   secp256k1_pubkey ourPubKey;
   size_t eninit_len = BIP151PUBKEYSIZE;
   uint8_t* encinit = (uint8_t*)malloc(eninit_len);

   switch (channel->cipherSuite_)
   {
   case CIPHERSUITE_CHACHA20POLY1305_OPENSSH:
   {
      if (!secp256k1_ec_pubkey_create(
         cffi_secp256k1_context,
         &ourPubKey, channel->privkey_->privkey))
      {
         break;
      }

      secp256k1_ec_pubkey_serialize(
         cffi_secp256k1_context,
         encinit, &eninit_len,
         &ourPubKey, SECP256K1_EC_COMPRESSED);

      //grabbing encack wipes the private key
      btc_privkey_cleanse(channel->privkey_);

      return encinit;
   }

   default:
      break;
   }

   free(encinit);
   return NULL;
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_channel_processencack(
   bip151_channel* channel, const uint8_t* payload, size_t len)
{
   switch (channel->cipherSuite_)
   {
   case CIPHERSUITE_CHACHA20POLY1305_OPENSSH:
   {
      if (!bip151_channel_generate_secret_chacha20poly1305_openssh(
         channel, payload, len))
      {
         return false;
      }

      calc_chacha20poly1305_keys(channel);
      calc_sessionid(channel);
      return true;
   }

   default:
      break;
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_channel_generate_secret_chacha20poly1305_openssh(
   bip151_channel* channel, const uint8_t* pubkey, size_t len)
{
   secp256k1_pubkey peerECDHPK;
   uint8_t parseECDHMulRes[BIP151PUBKEYSIZE];
   size_t parseECDHMulResSize = BIP151PUBKEYSIZE;

   //sanity checks
   if (len != BIP151PUBKEYSIZE)
      return false;

   if (channel == 0 || pubkey == 0)
      return false;

   //check provided pubkey
   if(secp256k1_ec_pubkey_parse(
      cffi_secp256k1_context, &peerECDHPK, pubkey, BIP151PUBKEYSIZE) != 1)
   {
      return false;
   }

   //ecdh with channel priv key
   if(secp256k1_ec_pubkey_tweak_mul(
      cffi_secp256k1_context, &peerECDHPK, channel->privkey_->privkey) != 1)
   {
      return false;
   }

   secp256k1_ec_pubkey_serialize(
      cffi_secp256k1_context, parseECDHMulRes,
      &parseECDHMulResSize, &peerECDHPK,
      SECP256K1_EC_COMPRESSED);

   memcpy(channel->sharedSecret_, parseECDHMulRes + 1, 32);
   return true;
}

////////////////////////////////////////////////////////////////////////////////
void calc_chacha20poly1305_keys(bip151_channel* channel)
{
   char salt[] = "bitcoinecdh";
   char info1[] = "BitcoinK1";
   char info2[] = "BitcoinK2";
   uint8_t ikm[33];

   memcpy(ikm, channel->sharedSecret_, 32);
   ikm[32] = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;

   hkdf_sha256(
      channel->hkdfSet_, BIP151PRVKEYSIZE,
      (const uint8_t*)salt, strlen(salt),
      ikm, 33,
      (const uint8_t*)info2, strlen(info2));

   hkdf_sha256(
      channel->hkdfSet_ + BIP151PRVKEYSIZE, BIP151PRVKEYSIZE,
      (const uint8_t*)salt, strlen(salt),
      ikm, 33,
      (const uint8_t*)info1, strlen(info1));

   chacha20poly1305_init(channel->ctx_, channel->hkdfSet_, 64);
}

////////////////////////////////////////////////////////////////////////////////
void calc_sessionid(bip151_channel* channel)
{
   char salt[] = "bitcoinecdh";
   char info[] = "BitcoinSessionID";
   uint8_t ikm[33];

   memcpy(ikm, channel->sharedSecret_, 32);
   ikm[32] = channel->cipherSuite_;

   hkdf_sha256(
      channel->sessionID_, BIP151PRVKEYSIZE,
      (const uint8_t*)salt, strlen(salt),
      ikm, 33,
      (const uint8_t*)info, strlen(info));
}

////////////////////////////////////////////////////////////////////////////////
void bip151_channel_rekey(bip151_channel* channel)
{
   uint8_t preimage[BIP151PRVKEYSIZE*2];
   memcpy(preimage, channel->sessionID_, BIP151PRVKEYSIZE);

   for (int i=0; i<2; i++)
   {
      uint8_t* ptr = channel->hkdfSet_ + (BIP151PRVKEYSIZE * i);
      memcpy(preimage + BIP151PRVKEYSIZE, ptr, BIP151PRVKEYSIZE);

      btc_hash(preimage, BIP151PRVKEYSIZE*2, ptr);
   }

   chacha20poly1305_init(channel->ctx_, channel->hkdfSet_, 64);
}

////////////////////////////////////////////////////////////////////////////////
void bip151_channel_initial_keying(
   bip151_channel* origin, const uint8_t* oppositeKdfKeys,
   const uint8_t* ownPubkey, const uint8_t* counterpartyPubkey)
{
   uint8_t preimage[162];
   memcpy (preimage, origin->sessionID_, BIP151PRVKEYSIZE);

   for (int i=0; i<2; i++)
   {
      size_t offset = BIP151PRVKEYSIZE;
      uint8_t* originKey = origin->hkdfSet_ + (BIP151PRVKEYSIZE * i);
      const uint8_t* oppositeKey = oppositeKdfKeys + (BIP151PRVKEYSIZE * i);

      //current symkey
      memcpy(preimage + offset, originKey, BIP151PRVKEYSIZE);
      offset += BIP151PRVKEYSIZE;

      //opposite channel symkeys
      memcpy(preimage + offset, oppositeKey, BIP151PRVKEYSIZE);
      offset += BIP151PRVKEYSIZE;

      //own pubkey
      memcpy(preimage + offset, ownPubkey, BIP151PUBKEYSIZE);
      offset += BIP151PUBKEYSIZE;

      //client pubkey
      memcpy(preimage + offset, counterpartyPubkey, BIP151PUBKEYSIZE);
      offset += BIP151PUBKEYSIZE;

      btc_hash(preimage, offset, originKey);
   }

   chacha20poly1305_init(origin->ctx_, origin->hkdfSet_, 64);
}

////////////////////////////////////////////////////////////////////////////////
void bip151_channel_initial_rekey(
   bip151_channel* inSession, bip151_channel* outSession,
   const uint8_t* ownPubkey, const uint8_t* counterpartyPubkey)
{
   uint8_t outSessionKeysCopy[64];
   memcpy(outSessionKeysCopy, outSession->hkdfSet_, 64);

   bip151_channel_initial_keying(outSession, inSession->hkdfSet_,
      ownPubkey, counterpartyPubkey);

   bip151_channel_initial_keying(inSession, outSessionKeysCopy,
      counterpartyPubkey, ownPubkey);
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_isrekeymsg(const uint8_t* rekey_message, size_t len)
{
   if (len != 33)
      return false;

   for (unsigned i=0; i<len; i++)
   {
      if (rekey_message[i] != 0)
         return false;
   }

   return true;
}


////////////////////////////////////////////////////////////////////////////////
//
// bip150 auth
//
////////////////////////////////////////////////////////////////////////////////
uint8_t* hash_authstring(const uint8_t* sessionID, const uint8_t* pubkey,
   char step)
{
   uint8_t preimage[66];
   uint8_t* result = (uint8_t*)malloc(32);

   memcpy(preimage, sessionID, BIP151PRVKEYSIZE);
   memset(preimage + BIP151PRVKEYSIZE, step, 1);
   memcpy(preimage + BIP151PRVKEYSIZE + 1, pubkey, BIP151PUBKEYSIZE);

   btc_hash(preimage, 66, result);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
bool check_authstring(const uint8_t* payload, const uint8_t* sessionID,
   const uint8_t* pubkey, char step)
{
   uint8_t* myHash = hash_authstring(sessionID, pubkey, step);
   int result = memcmp(payload, myHash, 32);
   free(myHash);

   return (result == 0);
}

////////////////////////////////////////////////////////////////////////////////
bool bip150_check_authchallenge(const uint8_t* payload, size_t len,
   const bip151_channel* channel, const uint8_t* pubkey)
{
   if (len != 32)
      return false;

   return check_authstring(payload, channel->sessionID_, pubkey, 'i');
}

////////////////////////////////////////////////////////////////////////////////
bool bip150_check_authpropose(const uint8_t* payload, size_t len,
   const bip151_channel* channel, const uint8_t* pubkey)
{
   if (len != 32)
      return false;

   return check_authstring(payload, channel->sessionID_, pubkey, 'p');
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip150_get_authreply(
   const bip151_channel* channel, const uint8_t* privkey)
{
   uint8_t* authReply = (uint8_t*)malloc(BIP151PRVKEYSIZE*2);
   size_t resSize = 0;

   if (btc_ecc_sign_compact(
      privkey, channel->sessionID_, authReply, &resSize) == false)
   {
      return NULL;
   }

   return authReply;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip150_get_authchallenge(
   const bip151_channel* channel, const uint8_t* pubkey)
{
   return hash_authstring(channel->sessionID_, pubkey, 'r');
}

////////////////////////////////////////////////////////////////////////////////
bool bip150_check_authreply(uint8_t* payload, size_t len,
   const bip151_channel* channel, const uint8_t* pubkey)
{
   uint8_t derSig[DERSIG_SIZE];
   size_t derSigSize = DERSIG_SIZE;

   if (len != 64)
      return false;

   if(btc_ecc_compact_to_der_normalized(payload, derSig, &derSigSize) == false)
   {
      return false;
   }

   return btc_ecc_verify_sig(
      pubkey, true, channel->sessionID_, derSig, derSigSize);
}

////////////////////////////////////////////////////////////////////////////////
//
// encryption routines
//
////////////////////////////////////////////////////////////////////////////////
uint32_t bip15x_get_length(bip151_channel* channel, const uint8_t* payload)
{
   //payload has to be AAD_LEN long

   unsigned decryptedLen;
   if (chacha20poly1305_get_length(
      channel->ctx_, &decryptedLen,
      channel->seqNum_,
      payload, AAD_LEN))
   {
      return 0;
   }

   return decryptedLen;
}

////////////////////////////////////////////////////////////////////////////////
int bip15x_decrypt(bip151_channel* channel,
   const uint8_t* cipherText, size_t len, uint8_t* clearText)
{
   uint32_t decryptedLen = bip15x_get_length(channel, cipherText);
   if (decryptedLen != len)
      return -10;

   return chacha20poly1305_crypt(
      channel->ctx_, channel->seqNum_++,
      clearText, cipherText, len, AAD_LEN, 0);
}

////////////////////////////////////////////////////////////////////////////////
bool bip15x_encrypt(bip151_channel* channel,
   const uint8_t* clearText, size_t len, uint8_t* cipherText)
{
   //prepend payload size
   memcpy(cipherText, &len, AAD_LEN);

   //copy clear text in
   memcpy(cipherText + AAD_LEN, clearText, len);

   //encrypt, increment sequence number
   return chacha20poly1305_crypt(
      channel->ctx_, channel->seqNum_++,
      cipherText, cipherText, len, AAD_LEN, 1) == 0;
}
