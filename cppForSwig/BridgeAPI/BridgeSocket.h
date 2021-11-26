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

class BIP151Connection;
class AuthorizedPeers;

namespace google
{
   namespace protobuf
   {
      class Message;
   };
};

namespace ArmoryBridge
{
   class CppBridge;

   /////////////////////////////////////////////////////////////////////////////
   struct WritePayload_Bridge : public Socket_WritePayload
   {
      std::unique_ptr<google::protobuf::Message> message_;

      void serialize(std::vector<uint8_t>&) override;
      std::string serializeToText(void) override
      {
         throw std::runtime_error("not implemented"); 
      }

      size_t getSerializedSize(void) const override;
   };

   /////////////////////////////////////////////////////////////////////////////
   class CppBridgeSocket : public PersistentSocket
   {
   private:
      std::shared_ptr<CppBridge> bridgePtr_;
      const std::string serverName_;
      
      std::shared_ptr<BIP151Connection> bip151Connection_;
      std::shared_ptr<AuthorizedPeers> authPeers_;
      std::vector<uint8_t> leftOverData_;

      std::mutex writeMutex_;
      std::chrono::time_point<std::chrono::system_clock> outKeyTimePoint_;

   private:
      bool processAEADHandshake(BinaryDataRef);

   public:
      CppBridgeSocket(
         const std::string& addr, const std::string& port,
         std::shared_ptr<CppBridge> bridgePtr);

      SocketType type(void) const override { return SocketCppBridge; }
      void respond(std::vector<uint8_t>& data) override;
      void pushPayload(
         std::unique_ptr<Socket_WritePayload>,
         std::shared_ptr<Socket_ReadPayload>) override;
   };
}; //namespace ArmoryBridge

#endif