////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _BRIDGE_SOCKET_H
#define _BRDIGE_SOCKET_H

#include <memory>

#include "../SocketObject.h"

namespace ArmoryBridge
{
   class CppBridge;

   class CppBridgeSocket : public PersistentSocket
   {
   private:
      std::shared_ptr<CppBridge> bridgePtr_;

   public:
      CppBridgeSocket(
         const std::string& addr, const std::string& port,
         std::shared_ptr<CppBridge> bridgePtr) :
         PersistentSocket(addr, port), bridgePtr_(bridgePtr)
      {}

      SocketType type(void) const override { return SocketBitcoinP2P; }
      void respond(std::vector<uint8_t>& data) override;
      void pushPayload(
         std::unique_ptr<Socket_WritePayload>,
         std::shared_ptr<Socket_ReadPayload>) override;
   };
}; //namespace ArmoryBridge

#endif