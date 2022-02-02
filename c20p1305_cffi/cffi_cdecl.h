////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2021, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

/*
Header for the dedicated code CFFI has to pythonize. This is directly
included in the ffi.set_source source field so that the resulting C
file from the CFFI translation has the relevant declarations in its
translation unit.
*/

#ifndef CFFI_CDECL_H_
#define CFFI_CDECL_H_

#include <stdint.h>
#include <stdbool.h>
#include "btc/ecc_key.h"


struct chachapolyaead_ctx;

typedef struct bip151_channel_ {
   struct chachapolyaead_ctx* ctx_;

   btc_key* privkey_;
   uint8_t sharedSecret_[32];
   uint8_t hkdfSet_[64];
   uint8_t sessionID_[32];

   uint8_t cipherSuite_;
   uint32_t seqNum_;
} bip151_channel;

//setup
size_t bip15x_init_lib(void);
bip151_channel* bip151_channel_makenew(void);

//utils
bool isNull(const void*);
void freeBuffer(void*);
uint8_t* generate_random(size_t);
uint8_t* compute_pubkey(const uint8_t*);

//channel encryption handshake
uint8_t* bip151_channel_getencinit(bip151_channel*);
bool bip151_channel_processencinit(bip151_channel*, const uint8_t*, size_t);

uint8_t* bip151_channel_getencack(bip151_channel*);
bool bip151_channel_processencack(bip151_channel*, const uint8_t*, size_t);

//rekey
void bip151_channel_rekey(bip151_channel*);
void bip151_channel_initial_rekey(
   bip151_channel*, bip151_channel*, const uint8_t*, const uint8_t*);
bool bip151_isrekeymsg(const uint8_t*, size_t);

//auth setup
bool bip150_check_authchallenge(
   const uint8_t*, size_t, const bip151_channel*, const uint8_t*);
bool bip150_check_authpropose(
   const uint8_t*, size_t, const bip151_channel*, const uint8_t*);
bool bip150_check_authreply(
   uint8_t*, size_t, const bip151_channel*, const uint8_t*);

uint8_t* bip150_get_authreply(const bip151_channel*, const uint8_t*);
uint8_t* bip150_get_authchallenge(const bip151_channel*, const uint8_t*);

//encryption
uint32_t bip15x_get_length(bip151_channel*, const uint8_t*);
int bip15x_decrypt(bip151_channel*, const uint8_t*, size_t, uint8_t*);
bool bip15x_encrypt(bip151_channel*, const uint8_t*, size_t, uint8_t*);

#endif
