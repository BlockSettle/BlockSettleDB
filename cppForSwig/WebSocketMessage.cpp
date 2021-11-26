////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BtcUtils.h"
#include "WebSocketMessage.h"
#include "libwebsockets.h"
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "BIP15x_Handshake.h"

using namespace std;
using namespace ::google::protobuf::io;

////////////////////////////////////////////////////////////////////////////////
//
// WebSocketMessageCodec
//
////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessageCodec::serialize(
   const vector<uint8_t>& payload, BIP151Connection* connPtr,
   ArmoryAEAD::BIP151_PayloadType type, uint32_t id)
{
   BinaryDataRef bdr;
   if(payload.size() > 0)
      bdr.setRef(&payload[0], payload.size());
   return serialize(bdr, connPtr, type, id);
}

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessageCodec::serialize(
   const string& payload, BIP151Connection* connPtr,
   ArmoryAEAD::BIP151_PayloadType type, uint32_t id)
{
   BinaryDataRef bdr((uint8_t*)payload.c_str(), payload.size());
   return serialize(bdr, connPtr, type, id);
}

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessageCodec::serializePacketWithoutId(
   const BinaryDataRef& payload, BIP151Connection* connPtr,
   ArmoryAEAD::BIP151_PayloadType type)
{
   /***
   no packet fragmentation, flat size serialization:
   uint32_t size
   uint8_t type
   nbytes payload
   ***/

   uint32_t size = payload.getSize() + 1;
   BinaryData plainText(4 + size + LWS_PRE + POLY1305MACLEN);
   if (plainText.getSize() > WEBSOCKET_MESSAGE_PACKET_SIZE)
      throw runtime_error("payload is too large to serialize");
   
   //skip LWS_PRE, copy in packet size
   memcpy(plainText.getPtr() + LWS_PRE, &size, 4);
   size += 4;

   //type
   memset(plainText.getPtr() + LWS_PRE + 4, (uint8_t)type, 1);

   //payload
   memcpy(plainText.getPtr() + LWS_PRE + 5, payload.getPtr(), payload.getSize());

   //encrypt if possible
   vector<BinaryData> result;
   if (connPtr != nullptr)
   {
      connPtr->assemblePacket(plainText.getPtr() + LWS_PRE, size,
         plainText.getPtr() + LWS_PRE, size + POLY1305MACLEN);
   }
   else
   {
      plainText.resize(size + LWS_PRE);
   }

   result.emplace_back(plainText);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
vector<BinaryData> WebSocketMessageCodec::serialize(
   const BinaryDataRef& payload, BIP151Connection* connPtr,
   ArmoryAEAD::BIP151_PayloadType type, uint32_t id)
{   
   //is this payload carrying a msgid?
   if (type > ArmoryAEAD::BIP151_PayloadType::Threshold_Begin)
      return serializePacketWithoutId(payload, connPtr, type);

   /***
   Fragmented packet seralization

   If the payload is less than (WEBSOCKET_MESSAGE_PACKET_SIZE - 9 - LWS_PRE - 
   POLY1305MACLEN), use:
    Single packet header:
     uint32_t packet size
     uint8_t type (WS_MSGTYPE_SINGLEPACKET)
     uint32_t msgid
     nbytes payload

   Otherwise, use:
    Fragmented header:
     uint32_t packet size
     uint8_t type (WS_MSGTYPE_FRAGMENTEDPACKET_HEADER)
     uint32_t msgid
     uint16_t count (>= 2)
     nbytes payload fragment

    Fragments:
     uint32_t packet size
     uint8_t type (WS_MSGTYPE_FRAGMENTEDPACKET_FRAGMENT)
     uint32_t msgid
     varint packet id (1 to 65535)
     nbytes payload fragment
   ***/
   
   //encrypt lambda
   vector<BinaryData> result;
   auto encryptAndAdd = [connPtr, &result](BinaryData& data)
   {
      size_t plainTextLen = data.getSize() - LWS_PRE - POLY1305MACLEN;
      size_t cipherTextLen = data.getSize() - LWS_PRE;

      if (connPtr != nullptr)
      {
         if (connPtr->assemblePacket(
            data.getPtr() + LWS_PRE, plainTextLen,
            data.getPtr() + LWS_PRE, cipherTextLen) != 0)
         {
            //failed to encrypt, abort
            throw runtime_error("failed to encrypt packet, aborting");
         }
      }
      else
      {
         data.resize(cipherTextLen);
      }

      result.emplace_back(data);
   };
   
   auto data_len = payload.getSize();
   static size_t payload_room = 
      WEBSOCKET_MESSAGE_PACKET_SIZE - LWS_PRE - POLY1305MACLEN - 9;
   if (data_len <= payload_room)
   {
      //single packet serialization
      uint32_t size = data_len + 5;
      BinaryData plainText(LWS_PRE + POLY1305MACLEN + 9 + data_len);

      memcpy(plainText.getPtr() + LWS_PRE, &size, 4);
      memset(plainText.getPtr() + LWS_PRE + 4,
         (uint8_t)ArmoryAEAD::BIP151_PayloadType::SinglePacket, 1);
      memcpy(plainText.getPtr() + LWS_PRE + 5, &id, 4);

      if (!payload.empty())
         memcpy(plainText.getPtr() + LWS_PRE + 9, payload.getPtr(), data_len);

      encryptAndAdd(plainText);
   }
   else
   {
      //2 extra bytes for fragment count
      uint32_t header_room = payload_room - 2;
      size_t left_over = data_len - header_room;
      
      //1 extra bytes for fragment count < 253
      size_t fragment_room = payload_room - 1; 
      uint16_t fragment_count = left_over / fragment_room + 1;
      if (fragment_count >= 253)
      {
         left_over -= 252 * fragment_room;
         
         //3 extra bytes for fragment count >= 253
         fragment_room = payload_room - 3; 
         fragment_count = 253 + left_over / fragment_room;
      }

      if (left_over % fragment_room != 0)
         ++fragment_count;

      if (fragment_count > 65535)
         throw runtime_error("payload too large for serialization");

      BinaryData header_packet(WEBSOCKET_MESSAGE_PACKET_SIZE);

      //-2 for fragment count
      size_t pos = payload_room - 2;

      //+4 to shave off payload size, +1 for type
      header_room = payload_room + 5; 

      memcpy(header_packet.getPtr() + LWS_PRE, &header_room, 4);
      memset(header_packet.getPtr() + LWS_PRE + 4,
         (uint8_t)ArmoryAEAD::BIP151_PayloadType::FragmentHeader, 1);
      memcpy(header_packet.getPtr() + LWS_PRE + 5, &id, 4);
      memcpy(header_packet.getPtr() + LWS_PRE + 9, &fragment_count, 2);
      memcpy(header_packet.getPtr() + LWS_PRE + 11, payload.getPtr(), pos);
      encryptAndAdd(header_packet);

      size_t fragment_overhead = 10 + LWS_PRE + POLY1305MACLEN;
      for (unsigned i = 1; i < fragment_count; i++)
      {
         if (i == 253)
            fragment_overhead += 2;

         //figure out data size
         size_t data_size = min(
            WEBSOCKET_MESSAGE_PACKET_SIZE - fragment_overhead, 
            data_len - pos);

         BinaryData fragment_packet(data_size + fragment_overhead);
         uint32_t packet_size = 
            data_size + fragment_overhead - LWS_PRE - POLY1305MACLEN - 4;

         memcpy(fragment_packet.getPtr() + LWS_PRE, &packet_size, 4);
         memset(fragment_packet.getPtr() + LWS_PRE + 4,
            (uint8_t)ArmoryAEAD::BIP151_PayloadType::FragmentPacket, 1);
         memcpy(fragment_packet.getPtr() + LWS_PRE + 5, &id, 4);

         size_t offset = LWS_PRE + 9;
         if (i < 253)
         {
            uint8_t frag_id = i;
            memcpy(fragment_packet.getPtr() + offset, &frag_id, 1);
            ++offset;
         }
         else
         {
            uint16_t frag_id = i;
            fragment_packet.getPtr()[offset++] = 0xFD;
            memcpy(fragment_packet.getPtr() + offset, &frag_id, 2);
            offset += 2;
         }

         memcpy(fragment_packet.getPtr() + offset, payload.getPtr() + pos, data_size);
         pos += data_size;

         encryptAndAdd(fragment_packet);
      }
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
bool WebSocketMessageCodec::reconstructFragmentedMessage(
   const map<uint16_t, BinaryDataRef>& payloadMap, 
   ::google::protobuf::Message* msg)
{
   //this method expects packets in order

   if (payloadMap.size() == 0)
      return false;

   auto count = payloadMap.size();

   //create a zero copy stream from each packet
   vector<ZeroCopyInputStream*> streams;
   streams.reserve(count);
   
   try
   {
      for (auto& data_pair : payloadMap)
      {
         auto& dataRef = data_pair.second;
         auto stream = new ArrayInputStream(
            dataRef.getPtr(), dataRef.getSize());
         streams.push_back(stream);
      }
   }
   catch (...)
   {
      for (auto& stream : streams)
         delete stream;
      return false;
   }

   //pass it all to concatenating stream
   ConcatenatingInputStream cStream(&streams[0], streams.size());

   //deser message
   auto result = msg->ParseFromZeroCopyStream(&cStream);

   //cleanup
   for (auto& stream : streams)
      delete stream;

   return result;
}

////////////////////////////////////////////////////////////////////////////////
uint32_t WebSocketMessageCodec::getMessageId(const BinaryDataRef& packet)
{
   //sanity check
   if (packet.getSize() < 7)
      return UINT32_MAX;

   return *(uint32_t*)(packet.getPtr() + 4);
}

///////////////////////////////////////////////////////////////////////////////
//
// SerializedMessage
//
///////////////////////////////////////////////////////////////////////////////
void SerializedMessage::construct(const vector<uint8_t>& data,
   BIP151Connection* connPtr, ArmoryAEAD::BIP151_PayloadType type, uint32_t id)
{
   packets_ = move(
      WebSocketMessageCodec::serialize(data, connPtr, type, id));
}

///////////////////////////////////////////////////////////////////////////////
void SerializedMessage::construct(const BinaryDataRef& data,
   BIP151Connection* connPtr, ArmoryAEAD::BIP151_PayloadType type, uint32_t id)
{
   packets_ = move(
      WebSocketMessageCodec::serialize(data, connPtr, type, id));
}

///////////////////////////////////////////////////////////////////////////////
BinaryData SerializedMessage::consumeNextPacket()
{
   auto& val = packets_[index_++];
   return move(val);
}

///////////////////////////////////////////////////////////////////////////////
//
// WebSocketMessagePartial
//
///////////////////////////////////////////////////////////////////////////////
WebSocketMessagePartial::WebSocketMessagePartial() :
   type_(ArmoryAEAD::BIP151_PayloadType::Undefined)
{}

///////////////////////////////////////////////////////////////////////////////
void WebSocketMessagePartial::reset()
{
   packets_.clear();
   id_ = UINT32_MAX;
   type_ = ArmoryAEAD::BIP151_PayloadType::Undefined;
   packetCount_ = UINT32_MAX;
}

///////////////////////////////////////////////////////////////////////////////
bool WebSocketMessagePartial::parsePacket(const BinaryDataRef& dataRef)
{
   if (dataRef.getSize() == 0)
      return false;

   BinaryRefReader brrPacket(dataRef);
   auto packetlen = brrPacket.get_uint32_t();
   if (packetlen != brrPacket.getSizeRemaining())
   {
      LOGERR << "invalid packet size";
      return false;
   }

   auto dataSlice = brrPacket.get_BinaryDataRef(packetlen);
   BinaryRefReader brrSlice(dataSlice);

   auto msgType = (ArmoryAEAD::BIP151_PayloadType)brrSlice.get_uint8_t();

   switch (msgType)
   {
   case ArmoryAEAD::BIP151_PayloadType::SinglePacket:
   {
      return parseSinglePacket(dataSlice);
   }

   case ArmoryAEAD::BIP151_PayloadType::FragmentHeader:
   {
      return parseFragmentedMessageHeader(dataSlice);
   }

   case ArmoryAEAD::BIP151_PayloadType::FragmentPacket:
   {
      return parseMessageFragment(dataSlice);
   }

   case ArmoryAEAD::BIP151_PayloadType::Start:
   case ArmoryAEAD::BIP151_PayloadType::PresentPubKey:
   case ArmoryAEAD::BIP151_PayloadType::PresentPubKeyChild:
   case ArmoryAEAD::BIP151_PayloadType::EncInit:
   case ArmoryAEAD::BIP151_PayloadType::EncAck:
   case ArmoryAEAD::BIP151_PayloadType::Rekey:
   case ArmoryAEAD::BIP151_PayloadType::Challenge:
   case ArmoryAEAD::BIP151_PayloadType::Reply:
   case ArmoryAEAD::BIP151_PayloadType::Propose:
   {
      return parseMessageWithoutId(dataSlice);
   }

   default:
      LOGERR << "invalid packet type";
   }

   return false;
}

///////////////////////////////////////////////////////////////////////////////
bool WebSocketMessagePartial::parseSinglePacket(const BinaryDataRef& bdr)
{
   /*
   uint8_t type(WS_MSGTYPE_SINGLEPACKET)
   uint32_t msgid
   nbytes payload
   */

   if (id_ != UINT32_MAX)
      return false;
   BinaryRefReader brr(bdr);

   type_ = (ArmoryAEAD::BIP151_PayloadType)brr.get_uint8_t();
   if (type_ != ArmoryAEAD::BIP151_PayloadType::SinglePacket)
      return false;

   id_ = brr.get_uint32_t();
   packets_.emplace(make_pair(
      0, brr.get_BinaryDataRef(brr.getSizeRemaining())));

   packetCount_ = 1;
   return true;
}

///////////////////////////////////////////////////////////////////////////////
bool WebSocketMessagePartial::parseFragmentedMessageHeader(
   const BinaryDataRef& bdr)
{
   /*
   uint8_t type (WS_MSGTYPE_FRAGMENTEDPACKET_HEADER)
   uint32_t msgid
   uint16_t count (>= 2)
   nbytes payload fragment
   */

   BinaryRefReader brr(bdr);

   type_ = (ArmoryAEAD::BIP151_PayloadType)brr.get_uint8_t();
   if (type_ != ArmoryAEAD::BIP151_PayloadType::FragmentHeader)
      return false;

   auto id = brr.get_uint32_t();
   if (id_ != UINT32_MAX && id_ != id)
      return false;
   id_ = id;

   packetCount_ = brr.get_uint16_t();
   packets_.emplace(make_pair(
      0, brr.get_BinaryDataRef(brr.getSizeRemaining())));

   return true;
}

///////////////////////////////////////////////////////////////////////////////
bool WebSocketMessagePartial::parseMessageFragment(const BinaryDataRef& bdr)
{
   /*
   uint8_t type (WS_MSGTYPE_FRAGMENTEDPACKET_FRAGMENT)
   uint32_t msgid
   varint packet id (1 to 65535)
   nbytes payload fragment
   */

   BinaryRefReader brr(bdr);

   auto type = (ArmoryAEAD::BIP151_PayloadType)brr.get_uint8_t();
   if (type != ArmoryAEAD::BIP151_PayloadType::FragmentPacket)
      return false;

   auto id = brr.get_uint32_t();
   if (id_ != UINT32_MAX && id_ != id)
      return false;
   id_ = id;

   auto packetId = (uint16_t)brr.get_var_int();
   packets_.emplace(make_pair(
      packetId, brr.get_BinaryDataRef(brr.getSizeRemaining())));

   return true;
}

///////////////////////////////////////////////////////////////////////////////
bool WebSocketMessagePartial::parseMessageWithoutId(const BinaryDataRef& bdr)
{
   /*   
   uint8_t type
   nbytes payload
   */

   BinaryRefReader brr(bdr);

   type_ = (ArmoryAEAD::BIP151_PayloadType)brr.get_uint8_t();
   if (type_ <= ArmoryAEAD::BIP151_PayloadType::Threshold_Begin)
      return false;

   packets_.emplace(make_pair(
      0, brr.get_BinaryDataRef(brr.getSizeRemaining())));

   packetCount_ = 1;
   return true;
}

///////////////////////////////////////////////////////////////////////////////
bool WebSocketMessagePartial::getMessage(
  ::google::protobuf::Message* msgPtr) const
{
   if (!isReady())
      return false;

   if (packets_.size() == 1)
   {
      auto& dataRef = packets_.begin()->second;
      return msgPtr->ParseFromArray(dataRef.getPtr(), dataRef.getSize());
   }
   else
   {
      return WebSocketMessageCodec::reconstructFragmentedMessage(packets_, msgPtr);
   }
}

///////////////////////////////////////////////////////////////////////////////
bool WebSocketMessagePartial::isReady() const
{
   return packets_.size() == packetCount_;
}

///////////////////////////////////////////////////////////////////////////////
BinaryDataRef WebSocketMessagePartial::getSingleBinaryMessage(void) const
{
   if (packetCount_ != 1 || !isReady())
      return BinaryDataRef();

   return packets_.begin()->second;
}

///////////////////////////////////////////////////////////////////////////////
ArmoryAEAD::BIP151_PayloadType WebSocketMessagePartial::getPacketType(
   const BinaryDataRef& bdr)
{
   if (bdr.getSize() < 5)
      throw runtime_error("packet is too small to be serialized fragment");
   return (ArmoryAEAD::BIP151_PayloadType)bdr.getPtr()[4];
}

///////////////////////////////////////////////////////////////////////////////
unsigned WebSocketMessagePartial::getMessageId(const BinaryDataRef& bdr)
{
   if (bdr.getSize() < 9)
      return UINT32_MAX;

   BinaryRefReader brr(bdr);
   brr.advance(4);

   auto type = (ArmoryAEAD::BIP151_PayloadType)brr.get_uint8_t();
   switch (type)
   {
   case ArmoryAEAD::BIP151_PayloadType::SinglePacket:
   case ArmoryAEAD::BIP151_PayloadType::FragmentHeader:
   case ArmoryAEAD::BIP151_PayloadType::FragmentPacket:
      return brr.get_uint32_t();

   default:
      return UINT32_MAX;
   }

   return UINT32_MAX;
}