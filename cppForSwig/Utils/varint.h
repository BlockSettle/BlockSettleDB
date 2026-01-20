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

#pragma once

#include <stdint.h>
#include <string>
#include <stdexcept>

namespace Armory
{
   namespace BtcUtils
   {
      class BlockDeserializingException : public std::runtime_error
      {
      public:
         BlockDeserializingException(const std::string& = "");
      };

      class VarIntException : public BlockDeserializingException
      {
      public:
         VarIntException(const std::string& = "");
      };

      uint64_t readVarInt(const uint8_t*, size_t, uint8_t&);
      //std::pair<uint64_t, uint8_t> readVarInt(BinaryRefReader&);
      uint8_t readVarIntLength(const uint8_t*);
      uint8_t calcVarIntSize(const uint64_t&);
   }
}
