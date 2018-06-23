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
vector<BinaryData> WebSocketMessage::serialize(uint32_t id,
   const vector<uint8_t>& payload)
{
   BinaryDataRef bdr;
   if(payload.size() > 0)
      bdr.setRef(&payload[0], payload.size());
   return serialize(id, bdr);
}

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessage::serialize(uint32_t id,
   const string& payload)
{
   BinaryDataRef bdr((uint8_t*)payload.c_str(), payload.size());
   return serialize(id, bdr);
}

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessage::serialize(uint32_t id, 
   const BinaryDataRef& payload)
{
   //TODO: fallback to raw binary messages once lws is standardized
   //TODO: less copies, more efficient serialization

   vector<BinaryData> result;

   size_t data_size =
      WEBSOCKET_MESSAGE_PACKET_SIZE - WEBSOCKET_MESSAGE_PACKET_HEADER;
   auto msg_count = payload.getSize() / data_size;
   if (msg_count * data_size < payload.getSize())
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
      bw.put_uint32_t(id);

      //packet counts and id
      bw.put_uint8_t(msg_count);
      bw.put_uint8_t(i);

      //data
      if (payload.getSize() > 0)
      {
         auto size = min(data_size, payload.getSize() - pos);
         BinaryDataRef bdr(payload.getPtr() + pos, size);
         bw.put_BinaryDataRef(bdr);
         pos += size;
      }

      result.push_back(bw.getData());
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketMessage::processPacket(BinaryData& packet)
{
   auto id = getMessageId(packet);
   
   //sanity check
   if (id == UINT32_MAX)
      throw LWS_Error("invalid msg id");

   //compare with msg id, if it's missing, init
   if (id_ == UINT32_MAX)
      id_ = id;
   else if (id_ != id)
      throw LWS_Error("msg id mismatch");

   //get count
   auto count = (uint8_t*)packet.getPtr() + 4;

   //sanity check
   if (*count == 0)
      throw LWS_Error("null packet count");

   //compare packet count
   if (count_ == UINT32_MAX)
      count_ = *count;
   else if (count_ != *count)
      throw LWS_Error("packet count mismatch");
   
   //get packet id
   auto packet_id = (uint8_t*)packet.getPtr() + 5;

   //make packet pair
   auto&& packet_pair = make_pair(*packet_id, move(packet));

   packets_.insert(move(packet_pair));
}

////////////////////////////////////////////////////////////////////////////////
bool WebSocketMessage::reconstruct(BinaryDataRef& payload)
{
   //TODO: reduce the amount of copies

   //sanity checks
   if (id_ == UINT32_MAX || count_ == UINT32_MAX)
      return false;

   if (packets_.size() != count_)
      return false;

  
   if (packets_.size() == 1)
   {
      auto& packet = packets_.begin()->second;
      payload = packet.getSliceRef(
         WEBSOCKET_MESSAGE_PACKET_HEADER,
         packet.getSize() - WEBSOCKET_MESSAGE_PACKET_HEADER);
   }
   else
   {
      size_t total = 0;
      vector<pair<size_t, uint8_t*>> offsets;

      //reconstruct msg from packets
      for (auto& packet : packets_)
      {
         auto size = packet.second.getSize() - 
            WEBSOCKET_MESSAGE_PACKET_HEADER;
         auto offset = packet.second.getPtr() + WEBSOCKET_MESSAGE_PACKET_HEADER;
         
         offsets.push_back(make_pair(size, offset));
         total += size;
      }

      payload_.resize(total);
      size_t pos = 0;
      for (auto& offset : offsets)
      {
         memcpy(payload_.getPtr() + pos, offset.second, offset.first);
         pos += offset.first;
      }

      payload.setRef(payload_);
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
uint32_t WebSocketMessage::getMessageId(const BinaryData& packet)
{
   //sanity check
   if (packet.getSize() < WEBSOCKET_MESSAGE_PACKET_HEADER ||
      packet.getSize() > WEBSOCKET_MESSAGE_PACKET_SIZE)
      return UINT32_MAX;

   return *(uint32_t*)packet.getPtr();
}
