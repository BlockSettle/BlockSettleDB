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
vector<BinaryData> WebSocketMessage::serialize(uint64_t id,
   const vector<uint8_t>& payload)
{
   BinaryDataRef bdr(&payload[0], payload.size());
   return serialize(id, bdr);
}

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessage::serialize(uint64_t id,
   const string& payload)
{
   BinaryDataRef bdr((uint8_t*)payload.c_str(), payload.size());
   return serialize(id, bdr);
}

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessage::serialize(uint64_t id, 
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
      bw.put_uint64_t(id);

      //packet counts and id
      bw.put_uint8_t(msg_count);
      bw.put_uint8_t(i);

      //data
      auto size = min(data_size, payload.getSize() - pos);
      BinaryDataRef bdr(payload.getPtr() + pos, size);
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
bool WebSocketMessage::reconstruct(vector<uint8_t>& payload)
{
   //TODO: reduce the amount of copies

   //sanity checks
   if (id_ == UINT64_MAX || count_ == UINT32_MAX)
      return false;

   if (packets_.size() != count_)
      return false;

   payload.clear();
   size_t offset = 0;
   //reconstruct msg from packets
   for (auto& packet : packets_)
   {
      auto&& size = packet.second.getSize() - WEBSOCKET_MESSAGE_PACKET_HEADER;
      payload.resize(offset + size);
      
      memcpy(&payload[0] + offset,
         packet.second.getPtr() + WEBSOCKET_MESSAGE_PACKET_HEADER,
         size);

      offset += size;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool WebSocketMessage::reconstruct(string& payload)
{
   //TODO: reduce the amount of copies

   //sanity checks
   if (id_ == UINT64_MAX || count_ == UINT32_MAX)
      return false;

   if (packets_.size() != count_)
      return false;

   payload.clear();
   //reconstruct msg from packets
   for (auto& packet : packets_)
   {
      payload.append(
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
