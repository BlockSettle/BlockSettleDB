////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "PSBT.h"
#include <Utils/BinaryData.h>

using namespace Armory::Signing;

////////////////////////////////////////////////////////////////////////////////
// exceptions
PSBT::DeserError::DeserError(const std::string& err) :
   std::runtime_error(err)
{}

////////////////////////////////////////////////////////////////////////////////
// PSBT
void PSBT::init(BinaryWriter& bw)
{
   bw.put_uint32_t(PSBT::ENUM_GLOBAL::PSBT_GLOBAL_MAGICWORD, BE);
   bw.put_uint8_t(PSBT::ENUM_GLOBAL::PSBT_GLOBAL_SEPARATOR);
}

////////////////////////////////////////////////////////////////////////////////
void PSBT::setUnsignedTx(BinaryWriter& bw, const BinaryData& unsignedTx)
{
   bw.put_uint8_t(1);
   bw.put_uint8_t(PSBT::ENUM_GLOBAL::PSBT_GLOBAL_UNSIGNED_TX);

   bw.put_var_int(unsignedTx.getSize());
   bw.put_BinaryData(unsignedTx);
}

////////////////////////////////////////////////////////////////////////////////
void PSBT::setSeparator(BinaryWriter& bw)
{
   bw.put_uint8_t(0);
}
