////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _SOCKET_WRITE_PAYLOAD_H
#define _SOCKET_WRITE_PAYLOAD_H

#include "SocketObject.h"
#ifdef BUILD_PROTOBUF
#include <google/protobuf/message.h>
#endif

///////////////////////////////////////////////////////////////////////////////
struct WritePayload_Protobuf : public Socket_WritePayload
{
#ifdef BUILD_PROTOBUF
   std::unique_ptr<::google::protobuf::Message> message_;

   void serialize(std::vector<uint8_t>&);
   std::string serializeToText(void);
   size_t getSerializedSize(void) const {
      return message_->ByteSizeLong();
   }
#endif
};

///////////////////////////////////////////////////////////////////////////////
struct WritePayload_Raw : public Socket_WritePayload
{
   std::vector<uint8_t> data_;

   void serialize(std::vector<uint8_t>&);
   std::string serializeToText(void) {
      throw SocketError("raw payload cannot serilaize to str");
   }
   size_t getSerializedSize(void) const { return data_.size(); };
};

///////////////////////////////////////////////////////////////////////////////
struct WritePayload_String : public Socket_WritePayload
{
   std::string data_;

   void serialize(std::vector<uint8_t>&) {
      throw SocketError("string payload cannot serialize to raw binary");
   }

   std::string serializeToText(void) {
      return std::move(data_);
   }

   size_t getSerializedSize(void) const { return data_.size(); };
};

///////////////////////////////////////////////////////////////////////////////
struct WritePayload_StringPassthrough : public Socket_WritePayload
{
   std::string data_;

   void serialize(std::vector<uint8_t>& payload) {
      payload.reserve(data_.size() + 1);
      payload.insert(payload.end(), data_.begin(), data_.end());
      data_.push_back(0);
   }

   std::string serializeToText(void) {
      return move(data_);
   }

   size_t getSerializedSize(void) const { return data_.size(); };
};

#endif
