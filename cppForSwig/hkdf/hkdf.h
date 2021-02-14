////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018-2020, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// An HKDF (RFC 5869) implementation based on the code available with libbtc. For now, the
// code assumes SHA-256 is being used. This functionality is global.

#ifndef HKDF_H
#define HKDF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void hkdf_sha256(uint8_t *result, size_t resultSize,
                const uint8_t *salt, size_t ssize,
                const uint8_t *key, size_t ksize,
                const uint8_t *info, size_t isize);

#ifdef __cplusplus
}
#endif

#endif // HKDF_H
