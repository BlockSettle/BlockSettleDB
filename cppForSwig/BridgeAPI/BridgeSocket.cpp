////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BridgeSocket.h"
#include "CppBridge.h"

using namespace std;
using namespace ArmoryBridge;

////////////////////////////////////////////////////////////////////////////////
////
////  CppBridgeSocket
////
////////////////////////////////////////////////////////////////////////////////
void CppBridgeSocket::respond(std::vector<uint8_t>& data)
{
   if (data.empty())
   {
      //shutdown condition
      shutdown();
      return;
   }

   if (!bridgePtr_->processData(move(data)))
      shutdown();
}

////////////////////////////////////////////////////////////////////////////////
void CppBridgeSocket::pushPayload(
   unique_ptr<Socket_WritePayload> write_payload,
   shared_ptr<Socket_ReadPayload>)
{
   if (write_payload == nullptr)
      return;

   vector<uint8_t> data;
   write_payload->serialize(data);
   queuePayloadForWrite(data);
}