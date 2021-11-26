////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2021, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_PASSPHRASE_LAMBDA
#define _H_PASSPHRASE_LAMBDA

#include <functional>
#include <set>

#include "../SecureBinaryData.h"
#include "WalletIdTypes.h"

////////////////////////////////////////////////////////////////////////////////
typedef std::function<SecureBinaryData(
   const std::set<Armory::Wallets::EncryptionKeyId>&)> PassphraseLambda;

#endif
