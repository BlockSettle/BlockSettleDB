////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <stdexcept>

class BinaryData;
class BinaryWriter;

namespace Armory
{
   namespace Signing
   {
      namespace PSBT
      {
         enum ENUM_GLOBAL
         {
            PSBT_GLOBAL_UNSIGNED_TX = 0,
            PSBT_GLOBAL_XPUB        = 1,
            PSBT_GLOBAL_VERSION     = 0xfb,
            PSBT_GLOBAL_PROPRIETARY = 0xfc,
            PSBT_GLOBAL_SEPARATOR   = 0xff,
            PSBT_GLOBAL_MAGICWORD   = 0x70736274
         };

         ////
         enum ENUM_INPUT
         {
            PSBT_IN_NON_WITNESS_UTXO      = 0,
            PSBT_IN_WITNESS_UTXO          = 1,
            PSBT_IN_PARTIAL_SIG           = 2,
            PSBT_IN_SIGHASH_TYPE          = 3,
            PSBT_IN_REDEEM_SCRIPT         = 4,
            PSBT_IN_WITNESS_SCRIPT        = 5,
            PSBT_IN_BIP32_DERIVATION      = 6,
            PSBT_IN_FINAL_SCRIPTSIG       = 7,
            PSBT_IN_FINAL_SCRIPTWITNESS   = 8,
            PSBT_IN_POR_COMMITMENT        = 9,
            PSBT_IN_PROPRIETARY           = 0xfc
         };

         ////
         enum ENUM_OUTPUT
         {
            PSBT_OUT_REDEEM_SCRIPT     = 0,
            PSBT_OUT_WITNESS_SCRIPT    = 1,
            PSBT_OUT_BIP32_DERIVATION  = 2,
            PSBT_OUT_PROPRIETARY       = 0xfc
         };

         //exceptions
         class DeserError : std::runtime_error
         {
         public:
            DeserError(const std::string&);
         };

         //ser
         void init(BinaryWriter&);
         void setUnsignedTx(BinaryWriter&, const BinaryData&);
         void setSeparator(BinaryWriter&);
      } //namespace PSBT
   } //namespace Signer
} //namespace Armory
