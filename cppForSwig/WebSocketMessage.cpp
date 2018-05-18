////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "WebSocketMessage.h"
#include "libwebsockets.h"

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessage::serialize(uint64_t id, const string& msg)
{
   //TODO: fallback to raw binary messages once lws is standardized
   //TODO: less copies, more efficient serialization

   vector<BinaryData> result;

   size_t data_size =
      WEBSOCKET_MESSAGE_PACKET_SIZE - WEBSOCKET_MESSAGE_PACKET_HEADER;
   auto msg_count = msg.size() / data_size;
   if (msg_count * data_size < msg.size())
      msg_count++;

   if (msg_count > 255)
      throw LWS_Error("msg is too large");

   //for empty return (client method may still be waiting on reply to return)
   if (msg_count == 0)
      msg_count = 1;

   size_t pos = 0;
   for (unsigned i = 0; i < msg_count; i++)
   {
      BinaryWriter bw;

      //leading bytes for lws write routine
      BinaryData bd_buffer(LWS_PRE);
      bw.put_BinaryData(bd_buffer); 

      //msg id
      bw.put_uint64_t(id);

      //packet counts and id
      bw.put_uint8_t(msg_count);
      bw.put_uint8_t(i);

      //data
      auto size = min(data_size, msg.size() - pos);
      BinaryDataRef bdr((uint8_t*)msg.c_str() + pos, size);
      bw.put_BinaryDataRef(bdr);
      pos += data_size;

      result.push_back(bw.getData());
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketMessage::processPacket(BinaryData& packet)
{
   auto id = getMessageId(packet);
   
   //sanity check
   if (id == UINT64_MAX)
      throw LWS_Error("invalid msg id");

   //compare with msg id, if it's missing, init
   if (id_ == UINT64_MAX)
      id_ = id;
   else if (id_ != id)
      throw LWS_Error("msg id mismatch");

   //get count
   auto count = (uint8_t*)packet.getPtr() + 8;

   //sanity check
   if (*count == 0)
      throw LWS_Error("null packet count");

   //compare packet count
   if (count_ == UINT32_MAX)
      count_ = *count;
   else if (count_ != *count)
      throw LWS_Error("packet count mismatch");
   
   //get packet id
   auto packet_id = (uint8_t*)packet.getPtr() + 9;

   //make packet pair
   auto&& packet_pair = make_pair(*packet_id, move(packet));

   packets_.insert(move(packet_pair));
}

////////////////////////////////////////////////////////////////////////////////
bool WebSocketMessage::reconstruct(string& msg)
{
   //TODO: reduce the amount of copies

   //sanity checks
   if (id_ == UINT64_MAX || count_ == UINT32_MAX)
      return false;

   if (packets_.size() != count_)
      return false;

   msg.clear();
   //reconstruct msg from packets
   for (auto& packet : packets_)
   {
      msg.append(
         (char*)packet.second.getPtr() + WEBSOCKET_MESSAGE_PACKET_HEADER,
         packet.second.getSize() - WEBSOCKET_MESSAGE_PACKET_HEADER);
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
uint64_t WebSocketMessage::getMessageId(const BinaryData& packet)
{
   //sanity check
   if (packet.getSize() < WEBSOCKET_MESSAGE_PACKET_HEADER ||
      packet.getSize() > WEBSOCKET_MESSAGE_PACKET_SIZE)
      return UINT64_MAX;

   return *(uint64_t*)packet.getPtr();
}
