////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2015, Armory Technologies, Inc.                        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE-ATI or http://www.gnu.org/licenses/agpl.html                  //
//                                                                            //
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "varint.h"

using namespace Armory;

////////////////////////////////////////////////////////////////////////////////
// exceptions
BtcUtils::BlockDeserializingException::BlockDeserializingException(
   const std::string& what) :
   std::runtime_error(what)
{}

BtcUtils::VarIntException::VarIntException(const std::string& what) :
   BlockDeserializingException(what)
{}

////////////////////////////////////////////////////////////////////////////////
// varint
uint64_t BtcUtils::readVarInt(const uint8_t* strmPtr, size_t remaining,
   uint8_t& lenOut)
{
   if (remaining < 1) {
      throw VarIntException("invalid varint");
   }
   uint8_t firstByte = strmPtr[0];

   switch (firstByte)
   {
      case 0xfd:
      {
         if (remaining < 3) {
            throw VarIntException("invalid varint");
         }
         lenOut = 3;
         return *(uint16_t*)(strmPtr+1);
      }

      case 0xfe:
      {
         if (remaining < 5) {
            throw VarIntException("invalid varint");
         }
         lenOut = 5;
         return *(uint32_t*)(strmPtr+1);
      }

      case 0xff:
      {
         if (remaining < 9) {
            throw VarIntException("invalid varint");
         }
         lenOut = 9;
         return *(uint64_t*)(strmPtr+1);
      }

      default:
      {
         lenOut = 1;
         return firstByte;
      }
   }
}

/*std::pair<uint64_t, uint8_t> BtcUtils::readVarInt(BinaryRefReader& brr)
{
   uint64_t outVal;
   uint8_t outLen;
   outVal = readVarInt(brr.getCurrPtr(), brr.getSizeRemaining(), outLen);
   brr.advance(outLen);
   return std::make_pair(outVal, outLen);
}*/

uint8_t BtcUtils::readVarIntLength(const uint8_t* strmPtr)
{
   switch (strmPtr[0])
   {
      case 0xfd: return 3;
      case 0xfe: return 5;
      case 0xff: return 9;
      default:
         return 1;
   }
}

uint8_t BtcUtils::calcVarIntSize(const uint64_t& val)
{
   if (val < 0xfd) {
      return 1;
   } else if (val <= 0xffff) {
      return 3;
   } else if (val <= 0xffffffff) {
      return 5;
   } else {
      return 9;
   }
}
