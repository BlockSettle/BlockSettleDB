////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020-21, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _PROTOBUF_COMMAND_PARSER_H
#define _PROTOBUF_COMMAND_PARSER_H

#include "BinaryData.h"

namespace Armory
{
   namespace Bridge
   {
      class CppBridge;

      struct ProtobufCommandParser
      {
         static bool processData(CppBridge*, BinaryDataRef);
      };
   }; //namespace Bridge
}; //namespace Armory

#endif