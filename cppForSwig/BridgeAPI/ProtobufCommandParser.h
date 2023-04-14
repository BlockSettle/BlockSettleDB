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

namespace BridgeProto
{
   class BlockchainService;
   class Wallet;
   class CoinSelection;
   class Signer;
   class Utils;
   class ScriptUtils;
   class CallbackReply;
};

namespace Armory
{
   namespace Bridge
   {
      class CppBridge;

      class ProtobufCommandParser
      {
      private:
         static bool processBlockchainServiceCommands(CppBridge*, unsigned,
            const BridgeProto::BlockchainService&);
         static bool processWalletCommands(CppBridge*, unsigned,
            const BridgeProto::Wallet&);
         static bool processCoinSelectionCommands(CppBridge*, unsigned,
            const BridgeProto::CoinSelection&);
         static bool processSignerCommands(CppBridge*, unsigned,
            const BridgeProto::Signer&);
         static bool processUtilsCommands(CppBridge*, unsigned,
            const BridgeProto::Utils&);
         static bool processScriptUtilsCommands(CppBridge*, unsigned,
            const BridgeProto::ScriptUtils&);
         static bool processCallbackReply(CppBridge*,
            const BridgeProto::CallbackReply&);

      public:
         static bool processData(CppBridge*, BinaryDataRef);
      };
   }; //namespace Bridge
}; //namespace Armory

#endif