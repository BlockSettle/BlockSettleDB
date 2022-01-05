////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <assert.h>

#include "hkdf.h"
#include <btc/sha2.h>
#include <btc/hmac.h>


// HKDF (RFC 5869) code for SHA-256. Based on libbtc's HMAC SHA-256 code.
//
// IN:  resultSize - Size of the output buffer (max 8160 bytes).
//      salt - HKDF salt. Optional. Pass nullptr if not used.
//      ssize - HKDF salt size. Optional. Pass 0 if not used.
//      key - Initial HKDF key material. Mandatory.
//      ksize - Initial HKDF key material size. Mandatory.
//      info - HKDF context-specific info. Optional. Pass nullptr if not used.
//      isize - HKDF context-specific info size. Optional. Pass 0 if not used.
// OUT: result - The final HKDF keying material.
// RET: None
void hkdf_sha256(uint8_t *result, size_t resultSize,
                 const uint8_t *salt, size_t ssize,
                 const uint8_t *key, size_t ksize,
                 const uint8_t *info, size_t isize)
{
   unsigned int numSteps, totalHashBytes, hashInputSize;
   unsigned int hashInputBytes = isize + 1;

   uint8_t prk[SHA256_DIGEST_LENGTH];
   uint8_t *t, *hashInput;

   // RFC 5869 only allows for up to 8160 bytes of output data.
   assert(resultSize <= (255 * SHA256_DIGEST_LENGTH));
   assert(resultSize > 0);
   assert(ksize > 0);

   numSteps = (resultSize + SHA256_DIGEST_LENGTH - 1) / SHA256_DIGEST_LENGTH;
   totalHashBytes = numSteps * SHA256_DIGEST_LENGTH;
   hashInputSize = SHA256_DIGEST_LENGTH + hashInputBytes;

   t = (uint8_t*)malloc(totalHashBytes);
   hashInput = (uint8_t*)malloc(hashInputSize);

   // Step 1 (Sect. 2.2) - Extract a pseudorandom key from the salt & key.
   hmac_sha256(salt, ssize, key, ksize, prk);

   // Step 2 (Sec. 2.3) - Expand
   memcpy(hashInput, info, isize);
   hashInput[isize] = 0x01;
   hmac_sha256(prk, SHA256_DIGEST_LENGTH, hashInput, hashInputBytes, t);
   hashInputBytes += SHA256_DIGEST_LENGTH;

   // Loop as needed until you have enough output keying material.
   // NB: There appear to be subtle memory allocation gotchas in the HMAC code.
   // If you try to make a buffer serve double duty (output that writes over
   // input), the code crashes due to C memory deallocation errors. Circumvent
   // with dedicated buffers.
   for(unsigned int i = 1; i < numSteps; ++i)
   {
      uint8_t* tmpHashInput = (uint8_t*)malloc(hashInputBytes);

      // T[i] = HMAC(PRK, T[i-1] | info | i)
      memcpy(tmpHashInput, t + (i-1)*SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
      memcpy(tmpHashInput + SHA256_DIGEST_LENGTH, info, isize);
      tmpHashInput[hashInputBytes-1] = (uint8_t)(i+1);

      hmac_sha256(prk, SHA256_DIGEST_LENGTH,
                  tmpHashInput, hashInputBytes,
                  t + i*SHA256_DIGEST_LENGTH);

      free(tmpHashInput);
   }

   // Write the final results and exit.
   memcpy(result, t, resultSize);

   free(t);
   free(hashInput);
}
