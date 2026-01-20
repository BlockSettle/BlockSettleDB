////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <thread>
#include <chrono>
#include <string.h>

#include "BitcoinP2P.h"
#include <Utils/BtcUtils.h>
#include <Utils/varint.h>
#include <Utils/Cryptography.h>
#include <Utils/BitcoinSettings.h>
#include "SocketWritePayload.h"
#include "bdmenums.h"

using namespace Armory::Threading;
using namespace Armory::Node;

using namespace std::chrono_literals;
using namespace std::string_view_literals;

//message header
#define MESSAGE_HEADER_LEN    24
#define MAGIC_WORD_OFFSET     0
#define MESSAGE_TYPE_OFFSET   4
#define MESSAGE_TYPE_LEN      12
#define PAYLOAD_LENGTH_OFFSET 16
#define CHECKSUM_OFFSET       20

//netaddr
#define NETADDR_WITHTIME   30
#define NETADDR_NOTIME     26

#define VERSION_MINLENGTH  85
#define USERAGENT_OFFSET   80

//inv
#define INV_MAX 50000
#define INV_ENTRY_LEN 36

// Node witness
#define NODE_WITNESS 1 << 3

namespace {
   auto RECONNECT_DELAY = 500ms;

   template <typename T> uint32_t put_integer_be(uint8_t* ptr, const T& integer)
   {
      uint32_t size = sizeof(T);
      auto len = size - 1;
      auto intptr = (uint8_t*)&integer;

      for (uint32_t i = 0; i < size; i++) {
         ptr[i] = intptr[len - i];
      }
      return size;
   };

   ////
   int make_varint(const uint64_t& value, std::vector<uint8_t>& varint)
   {
      if (value < 0xFD) {
         varint.push_back((uint8_t)value);
         return 1;
      } else if (value <= 0xFFFF) {
         varint.resize(3);
         auto ptr = (uint16_t*)&varint[1];
         *ptr = (uint16_t)value;
         varint[0] = 0xFD;
         return 3;
      } else if (value <= 0xFFFFFFFF) {
         varint.resize(5);
         auto ptr = (uint32_t*)&varint[1];
         *ptr = (uint32_t)value;
         varint[0] = 0xFE;
         return 5;
      }

      varint.resize(9);
      auto ptr = (uint64_t*)&varint[1];
      *ptr = (uint64_t)value;
      varint[0] = 0xFF;
      return 9;
   }

   ////
   int get_varint(uint64_t& val, const uint8_t* ptr, uint32_t size)
   {
      if (size == 0) {
         throw std::runtime_error("invalid varint size");
      }

      if (ptr[0] < 0xFD) {
         val = *(uint8_t*)(ptr);
         return 1;
      } else if (ptr[0] == 0xFD) {
         if (size < 3) {
            throw std::runtime_error("invalid varint size");
         }
         val = *(uint16_t*)(ptr + 1);
         return 3;
      } else if (ptr[0] == 0xFE) {
         if (size < 5) {
            throw std::runtime_error("invalid varint size");
         }
         val = *(uint32_t*)(ptr + 1);
         return 5;
      }

      if (size < 9) {
         throw std::runtime_error("invalid varint size");
      }
      val = *(uint64_t*)(ptr + 1);
      return 9;
   }
}

////////////////////////////////////////////////////////////////////////////////
const std::map<std::string_view, PayloadType> Armory::Node::typeToPayload{
   { "version"sv, PayloadType::Version },
   { "verack"sv, PayloadType::VerAck },
   { "inv"sv, PayloadType::Inv },
   { "ping"sv, PayloadType::Ping },
   { "pong"sv, PayloadType::Pong },
   { "getdata"sv, PayloadType::GetData },
   { "tx"sv, PayloadType::Tx },
   { "reject"sv, PayloadType::Reject }
};

////////////////////////////////////////////////////////////////////////////////
////
//// Exceptions
////
////////////////////////////////////////////////////////////////////////////////
NodeException::NodeException(const std::string& err) :
   error_(err)
{}

const std::string& NodeException::what() const
{
   return error_;
}

////
BitcoinMessageDeserError::BitcoinMessageDeserError(
   const std::string& err, size_t off) :
   NodeException(err), offset(off)
{}

////
BitcoinMessageUnknown::BitcoinMessageUnknown(const std::string& err) :
   NodeException(err)
{}

////
PayloadDeserError::PayloadDeserError(const std::string& err) :
   NodeException(err)
{}

////
GetDataException::GetDataException(const std::string& err) :
   NodeException(err)
{}

////////////////////////////////////////////////////////////////////////////////
////
//// BitcoinNetAddr
////
////////////////////////////////////////////////////////////////////////////////
void BitcoinNetAddr::setIPv4(uint64_t srvice, const sockaddr& nodeaddr)
{
   services = srvice;
   memset(ipV6, 0, 16);
   ipV6[10] = (char)255;
   ipV6[11] = (char)255;

   memcpy(ipV6 + 12, nodeaddr.sa_data + 2, 4);
   auto ptr = (uint8_t*)nodeaddr.sa_data;
   port = (unsigned)ptr[0] * 256 + (unsigned)ptr[1];
}

////
void BitcoinNetAddr::deserialize(BinaryRefReader brr)
{
   if (brr.getSize() != NETADDR_NOTIME) {
      throw PayloadDeserError("invalid netaddr size");
   }
   services = brr.get_uint64_t();
   auto ipv6bdr = brr.get_BinaryDataRef(16);
   memcpy(&ipV6, ipv6bdr.getPtr(), 16);
   port = brr.get_uint16_t();
}

////
void BitcoinNetAddr::serialize(uint8_t* ptr) const
{
   memcpy(ptr, &services, 8);
   memcpy(ptr + 8, ipV6, 16);
   put_integer_be(ptr + 24, port);
}

////////////////////////////////////////////////////////////////////////////////
////
//// Payload classes
////
////////////////////////////////////////////////////////////////////////////////
Payload::~Payload()
{}

////
std::vector<uint8_t> Payload::serialize(MagicWordType magicWord) const
{
   //serialize payload
   auto payload_size = serializeInner(nullptr);

   std::vector<uint8_t> msg;
   msg.resize(MESSAGE_HEADER_LEN + payload_size);
   if (serialize(magicWord, &msg[0], msg.size()) == SIZE_MAX) {
      throw PayloadDeserError("failed to serialize payload");
   }
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
size_t Payload::serialize(MagicWordType magicWord,
   void* ptr, size_t buffer_len) const
{
   auto payload_size = serializeInner(nullptr);
   if (buffer_len < payload_size + MESSAGE_HEADER_LEN) {
      return SIZE_MAX;
   }

   //message
   if (payload_size > 0) {
      serializeInner((uint8_t*)ptr + MESSAGE_HEADER_LEN);
   }

   //magic word
   memcpy((uint8_t*)ptr + MAGIC_WORD_OFFSET, &magicWord, sizeof(MagicWordType));

   //message type
   auto type = typeStr();
   auto msgtype = (char*)ptr + MESSAGE_TYPE_OFFSET;
   memset(msgtype, 0, MESSAGE_TYPE_LEN);
   memcpy(msgtype, type.data(), type.size());

   //length
   uint32_t msglen = payload_size;
   uint32_t* msglenptr = (uint32_t*)((uint8_t*)ptr + PAYLOAD_LENGTH_OFFSET);
   *msglenptr = msglen;

   //checksum
   uint8_t* payloadptr = nullptr;
   if (payload_size > 0) {
      payloadptr = (uint8_t*)ptr + MESSAGE_HEADER_LEN;
   }
   BinaryDataRef bdr(payloadptr, payload_size);
   auto hash = BtcUtils::getHash256(bdr);
   uint32_t* checksum = (uint32_t*)hash.getPtr();
   uint32_t* checksumptr = (uint32_t*)((uint8_t*)ptr + CHECKSUM_OFFSET);
   *checksumptr = *checksum;

   return payload_size + MESSAGE_HEADER_LEN;
}

////////////////////////////////////////////////////////////////////////////////
size_t Payload::getSerializedSize() const
{
   auto payload_size = serializeInner(nullptr);
   return MESSAGE_HEADER_LEN + payload_size;
}

////////////////////////////////////////////////////////////////////////////////
std::vector<size_t> Payload::processPacket(
   std::vector<uint8_t>& data, MagicWordType magicWord)
{
   std::vector<size_t> retvec;
   if (data.size() < MESSAGE_HEADER_LEN) {
      return retvec;
   }

   size_t offset = 0, totalsize = data.size();
   while (offset < totalsize - sizeof(MagicWordType)) {
      const uint8_t* ptr = &data[offset];

      //check magic word
      MagicWordType mw;
      memcpy(&mw, ptr + MAGIC_WORD_OFFSET, sizeof(MagicWordType));
      if (mw != magicWord) {
         //invalid magic word, search remainder of the packet for another one
         if (offset + sizeof(MagicWordType) >= totalsize) {
            //not data left to read one magic word
            offset = SIZE_MAX;
            break;
         }

         auto sizeRemaining = totalsize - offset - sizeof(MagicWordType);
         unsigned i;
         for (i = 1; i < sizeRemaining; i++) {
            memcpy(&mw, ptr + i, sizeof(MagicWordType));
            if (mw == magicWord) {
               break;
            }
         }
         offset += i;
         continue;
      }

      //get message type
      auto messagetype = ptr + MESSAGE_TYPE_OFFSET;

      //messagetype should be null terminated and no longer than 12 bytes
      int i;
      for (i = 0; i < MESSAGE_TYPE_LEN; i++) {
         if (messagetype[i] == 0) {
            break;
         }
      }

      if (i == MESSAGE_TYPE_LEN) {
         offset += 4; //skip the current mw before reentering the loop
         continue;
      }

      //get and verify length
      uint32_t length;
      memcpy(&length, ptr + PAYLOAD_LENGTH_OFFSET, 4);
      auto localOffset = offset;

      //at this point we don't want to reparse this message if the
      //deser operation fails
      offset += 4;
      if (length + MESSAGE_HEADER_LEN > totalsize - localOffset) {
         return retvec;
      }

      //grab payload
      BinaryDataRef payloadRef(ptr + MESSAGE_HEADER_LEN, length);

      //verify checksum
      auto payloadHash = BtcUtils::getHash256(payloadRef);
      if (memcmp(ptr + CHECKSUM_OFFSET, payloadHash.getPtr(), 4) == 0) {
         //checksum matches, track packet offset
         retvec.emplace_back(localOffset);
      }

      //set offset to end of current packet
      offset += MESSAGE_HEADER_LEN + length - 4;
   }
   return retvec;
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Payload::DeserializedPayloads> Payload::deserialize(
   std::vector<uint8_t>& data, MagicWordType magicWord,
   std::shared_ptr<DeserializedPayloads> prevPacket)
{
   size_t bytesConsumed = 0;
   auto parsepayloads = [&bytesConsumed]
   (const std::vector<uint8_t>& data, const std::vector<size_t>& offsetVec)
   ->std::shared_ptr<DeserializedPayloads>
   {
      auto result = std::make_shared<DeserializedPayloads>();
      auto& payloadVec = result->payloads_;

      for (const auto& offset : offsetVec) {
         bytesConsumed = offset;

         uint32_t length;
         memcpy(&length, &data[offset] + PAYLOAD_LENGTH_OFFSET, 4);
         size_t localBytesConsumed = length + MESSAGE_HEADER_LEN;
         if (localBytesConsumed + offset > data.size()) {
            break;
         }
         std::string_view messagetype{(const char*)&data[offset] + MESSAGE_TYPE_OFFSET};

         try {
            const uint8_t* payloadptr = nullptr;
            if (length > 0) {
               payloadptr = &data[offset] + MESSAGE_HEADER_LEN;
            }

            //instantiate relevant Payload child class and return it
            auto payloadIter = typeToPayload.find(messagetype);
            if (payloadIter != typeToPayload.end()) {
               switch (payloadIter->second)
               {
                  case PayloadType::Version:
                     payloadVec.emplace_back(std::make_unique<Payload_Version>(
                        payloadptr, length));
                     break;

                  case PayloadType::VerAck:
                     payloadVec.emplace_back(std::make_unique<Payload_Verack>());
                     break;

                  case PayloadType::Ping:
                     payloadVec.emplace_back(std::make_unique<Payload_Ping>(
                        payloadptr, length));
                     break;

                  case PayloadType::Pong:
                     payloadVec.emplace_back(std::make_unique<Payload_Pong>(
                        payloadptr, length));
                     break;

                  case PayloadType::Inv:
                     payloadVec.emplace_back(std::make_unique<Payload_Inv>(
                        payloadptr, length));
                     break;

                  case PayloadType::Tx:
                     payloadVec.emplace_back(std::make_unique<Payload_Tx>(
                        payloadptr, length));
                     break;

                  case PayloadType::GetData:
                     payloadVec.emplace_back(std::make_unique<Payload_GetData>(
                        payloadptr, length));
                     break;

                  case PayloadType::Reject:
                     payloadVec.emplace_back(std::make_unique<Payload_Reject>(
                        payloadptr, length));
                     break;

                  default:
                     payloadVec.emplace_back(std::make_unique<Payload_Unknown>(
                        payloadptr, length));
               }
            } else {
               payloadVec.emplace_back(std::make_unique<Payload_Unknown>(
                  payloadptr, length));
            }
            bytesConsumed += localBytesConsumed;
         } catch (const PayloadDeserError&) {
            continue;
         }
      }

      if (bytesConsumed < data.size()) {
         result->spillOffset_ = bytesConsumed;
         result->data_ = std::move(data);
      }
      return result;
   };

   auto patchspill = [&parsepayloads, &bytesConsumed](
      std::shared_ptr<DeserializedPayloads> prevpacket,
      const std::vector<uint8_t>& data,
      const std::vector<size_t>& offsets)
      ->std::shared_ptr<DeserializedPayloads>
   {
      if (prevpacket == nullptr) {
         return nullptr;
      }

      size_t spillSize = 0;
      if (offsets.empty()) {
         spillSize = data.size();
      } else {
         spillSize = offsets[0];
      }
      if (spillSize == 0) {
         return nullptr;
      }

      prevpacket->data_.insert(prevpacket->data_.end(),
         data.begin(), data.begin() + spillSize);

      std::vector<size_t> offvec;
      offvec.push_back(prevpacket->spillOffset_);

      auto spillResult = parsepayloads(prevpacket->data_, offvec);
      if (spillResult->spillOffset_ != SIZE_MAX) {
         spillResult->iterCount_ = prevpacket->iterCount_;
      } else {
         if (prevpacket->iterCount_ > 0) {
            LOGWARN << "[[[ succesfully completed spill packet after " <<
               spillResult->iterCount_ << " iterations";
         }
      }

      bytesConsumed += spillSize;
      return spillResult;
   };

   auto offsetVec = processPacket(data, magicWord);
   auto extraPacket = patchspill(prevPacket, data, offsetVec);
   auto result = parsepayloads(data, offsetVec);
   if (extraPacket != nullptr) {
      if (result->payloads_.empty() && result->spillOffset_ == SIZE_MAX) {
         return extraPacket;
      }

      std::vector<std::unique_ptr<Payload>> newvec;
      newvec.reserve(extraPacket->payloads_.size() + result->payloads_.size());
      for (auto&& packet : extraPacket->payloads_) {
         newvec.emplace_back(std::move(packet));
      }
      for (auto&& packet : result->payloads_) {
         newvec.emplace_back(std::move(packet));
      }

      result->payloads_ = std::move(newvec);
      result->iterCount_ = extraPacket->iterCount_;

      if (extraPacket->spillOffset_ != SIZE_MAX) {
         LOGWARN << "*** got valid payloads without completing spill packet";
         LOGWARN << "*** dumping " << extraPacket->data_.size() << " bytes of spill data";
      }
   }
   return result;
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Unknown
Payload_Unknown::Payload_Unknown()
{}

Payload_Unknown::Payload_Unknown(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

////
PayloadType Payload_Unknown::type() const
{
   return PayloadType::Unknown;
}

////
std::string_view Payload_Unknown::typeStr() const
{
   return "unknown"sv;
}

////////
void Payload_Unknown::deserialize(const uint8_t* data, size_t len)
{
   data_.clear();
   if (len == 0) {
      return;
   }
   data_.resize(len);
   memcpy(&data_[0], data, len);
}

////////
size_t Payload_Unknown::serializeInner(uint8_t* ptr) const
{
   if (ptr != nullptr && !data_.empty()) {
      memcpy(ptr, &data_[0], data_.size());
   }
   return data_.size();
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Version
Payload_Version::Payload_Version()
{}

Payload_Version::Payload_Version(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

////
PayloadType Payload_Version::type() const
{
   return PayloadType::Version;
}

////
std::string_view Payload_Version::typeStr() const
{
   return "version"sv;
}

////////
void Payload_Version::deserialize(const uint8_t* data, size_t len)
{
   const uint8_t* dataptr = data;

   memcpy(&vheader_.version_, dataptr, 4);
   dataptr += 4;
   memcpy(&vheader_.services_, dataptr, 8);
   dataptr += 8;
   memcpy(&vheader_.timestamp_, dataptr, 8);
   dataptr += 8;

   memcpy(&vheader_.addr_recv_.services, dataptr, 8);
   dataptr += 8;
   memcpy(vheader_.addr_recv_.ipV6, dataptr, 16);
   dataptr += 16;
   memcpy(&vheader_.addr_recv_.port, dataptr, 2);
   dataptr += 2;

   memcpy(&vheader_.addr_from_.services, dataptr, 8);
   dataptr += 8;
   memcpy(vheader_.addr_from_.ipV6, dataptr, 16);
   dataptr += 16;
   memcpy(&vheader_.addr_from_.port, dataptr, 2);
   dataptr += 2;

   memcpy(&vheader_.nonce_, dataptr, 8);
   dataptr += 8;

   size_t remaining = len - USERAGENT_OFFSET;
   uint64_t uaLen;
   auto varintlen = get_varint(uaLen, dataptr, remaining);
   dataptr += varintlen;
   auto userAgentPtr = (const char*)dataptr;
   userAgent_ = std::string(userAgentPtr, uaLen);
   dataptr += uaLen;

   memcpy(&startHeight_, dataptr, 4);
}

////////
size_t Payload_Version::serializeInner(uint8_t* dataptr) const
{
   if (dataptr == nullptr) {
      return BtcUtils::calcVarIntSize(userAgent_.size()) +
         userAgent_.size() +
         VERSION_MINLENGTH;
   }

   std::vector<uint8_t> varint;
   auto varintlen = make_varint(userAgent_.size(), varint);
   size_t serlen = varintlen + userAgent_.length() + VERSION_MINLENGTH;

   uint8_t* vhptr = dataptr;
   memcpy(vhptr, &vheader_.version_, 4);
   memcpy(vhptr +4, &vheader_.services_, 8);
   memcpy(vhptr + 12, &vheader_.timestamp_, 8);
   vhptr += 20;

   vheader_.addr_recv_.serialize(vhptr);
   vhptr += 26;

   vheader_.addr_from_.serialize(vhptr);
   vhptr += 26;

   memcpy(vhptr, &vheader_.nonce_, 8);

   uint8_t* ptr = dataptr + USERAGENT_OFFSET;
   memcpy(ptr, &varint[0], varintlen);
   ptr += varintlen;
   memcpy(ptr, userAgent_.c_str(), userAgent_.size());
   ptr += userAgent_.size();
   memcpy(ptr, &startHeight_, 4);
   ptr += 4;
   *ptr = 1;

   return serlen;
}

////////
void Payload_Version::setVersionHeaderIPv4(uint32_t version,
   uint64_t services, int64_t timestamp,
   const sockaddr& recvaddr, const sockaddr& fromaddr)
{
   vheader_.version_ = version;
   vheader_.services_ = services;
   vheader_.timestamp_ = timestamp;

   vheader_.addr_recv_.setIPv4(services, recvaddr);
   vheader_.addr_from_.setIPv4(services, fromaddr);

   auto randombytes = Cryptography::PRNG::fortuna.generateRandom(8);
   memcpy(&vheader_.nonce_, randombytes.getPtr(), 8);
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Verack
Payload_Verack::Payload_Verack()
{}

Payload_Verack::Payload_Verack(std::vector<uint8_t>*)
{}

////
PayloadType Payload_Verack::type() const
{
   return PayloadType::VerAck;
}

////
std::string_view Payload_Verack::typeStr() const
{
   return "verack"sv;
}

////////
void Payload_Verack::deserialize(const uint8_t*, size_t)
{
   throw PayloadDeserError("verack cannot be deserialized");
}

////////
size_t Payload_Verack::serializeInner(uint8_t*) const
{
   return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Ping
Payload_Ping::Payload_Ping()
{}

Payload_Ping::Payload_Ping(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

////
PayloadType Payload_Ping::type() const
{
   return PayloadType::Ping;
}

////
std::string_view Payload_Ping::typeStr() const
{
   return "ping"sv;
}

////////
void Payload_Ping::deserialize(const uint8_t* dataptr, size_t len)
{
   if (len == 0) {
      nonce_ = UINT64_MAX;
   } else if (len != 8) {
      throw PayloadDeserError("invalid ping payload len");
   } else {
      memcpy(&nonce_, dataptr, 8);
   }
}
////////////////////////////////////////////////////////////////////////////////
size_t Payload_Ping::serializeInner(uint8_t* dataptr) const
{
   if (nonce_ == UINT64_MAX) {
      return 0;
   }
   if (dataptr != nullptr) {
      memcpy(dataptr, &nonce_, 8);
   }
   return 8;
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Pong
Payload_Pong::Payload_Pong()
{}

Payload_Pong::Payload_Pong(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

////////
PayloadType Payload_Pong::type() const
{
   return PayloadType::Pong;
}

std::string_view Payload_Pong::typeStr() const
{
   return "pong"sv;
}

////////
void Payload_Pong::deserialize(const uint8_t* dataptr, size_t len)
{
   if (len != 8) {
      throw PayloadDeserError("invalid pong payload len");
   }
   memcpy(&nonce_, dataptr, 8);
}

////////
size_t Payload_Pong::serializeInner(uint8_t* dataptr) const
{
   if (nonce_ == UINT64_MAX) {
      return 0;
   }
   if (dataptr != nullptr) {
      memcpy(dataptr, &nonce_, 8);
   }
   return 8;
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Inv
Payload_Inv::Payload_Inv()
{}

Payload_Inv::Payload_Inv(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

////////
PayloadType Payload_Inv::type() const
{
   return PayloadType::Inv;
}

std::string_view Payload_Inv::typeStr() const
{
   return "inv"sv;
}

////////
void Payload_Inv::setInvVector(InvVector invvec)
{
   invVector_ = std::move(invvec);
}

////////
void Payload_Inv::deserialize(const uint8_t* dataptr, size_t len)
{
   uint64_t invCount;
   auto varintlen = get_varint(invCount, dataptr, len);

   if (invCount > INV_MAX) {
      throw PayloadDeserError("inv count > INV_MAX");
   }
   invVector_.resize(invCount);

   auto ptr = dataptr + varintlen;
   auto remaining = len - varintlen;

   for (auto& entry : invVector_) {
      if (remaining < INV_ENTRY_LEN) {
         throw PayloadDeserError("inv deser size mismatch");
      }
      auto entrytype = (uint32_t*)ptr;
      memcpy(&entry.invtype, ptr, 4);
      if (entry.invtype > Inv_Msg_Filtered_Block) {
         throw PayloadDeserError("invalid inv entry type");
      }
      memcpy(entry.hash, ptr + 4, 32);

      remaining -= INV_ENTRY_LEN;
      ptr += INV_ENTRY_LEN;
   }
}

////////
size_t Payload_Inv::serializeInner(uint8_t* dataptr) const
{
   if (dataptr == nullptr) {
      auto invcount = invVector_.size();
      auto varintlen = BtcUtils::calcVarIntSize(invcount);
      return invcount * INV_ENTRY_LEN + varintlen;
   }

   auto invcount = invVector_.size();
   std::vector<uint8_t> varint;
   auto varintlen = make_varint(invcount, varint);

   memcpy(dataptr, &varint[0], varintlen);
   dataptr += varintlen;

   for (auto& entry : invVector_) {
      auto intptr = (uint32_t*)dataptr;
      *intptr = (uint32_t)entry.invtype;
      memcpy(dataptr + 4, entry.hash, 32);
      dataptr += 36;
   }
   return varintlen + invcount * INV_ENTRY_LEN;
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Tx
Payload_Tx::Payload_Tx()
{}

Payload_Tx::Payload_Tx(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

////////
PayloadType Payload_Tx::type() const
{
   return PayloadType::Tx;
}

std::string_view Payload_Tx::typeStr() const
{
   return "tx"sv;
}

////////
const BinaryData& Payload_Tx::getHash256() const
{
   if (txHash_.empty()) {
      Tx thisTx(&rawTx_[0], rawTx_.size());
      txHash_ =  thisTx.getThisHash();
   }
   return txHash_;
}

////////
const std::vector<uint8_t>& Payload_Tx::getRawTx() const
{
   return rawTx_;
}

void Payload_Tx::moveFrom(Payload_Tx& ptx)
{
   rawTx_ = std::move(ptx.rawTx_);
}

void Payload_Tx::setRawTx(std::vector<uint8_t> rawtx)
{
   rawTx_ = std::move(rawtx);
}

size_t Payload_Tx::getSize() const
{
   return rawTx_.size();
}

bool Payload_Tx::empty() const
{
   return rawTx_.size() == 0;
}

////////
size_t Payload_Tx::serializeInner(uint8_t* dataptr) const
{
   if (dataptr != nullptr) {
      memcpy(dataptr, &rawTx_[0], rawTx_.size());
   }
   return rawTx_.size();
}

////////
void Payload_Tx::deserialize(const uint8_t* dataptr, size_t len)
{
   rawTx_.resize(len);
   memcpy(&rawTx_[0], dataptr, len);
}

////////////////////////////////////////////////////////////////////////////////
// Payload_GetData
Payload_GetData::Payload_GetData()
{}

Payload_GetData::Payload_GetData(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

Payload_GetData::Payload_GetData(const InvEntry& inventry)
{
   invVector_.emplace_back(inventry);
}

Payload_GetData::Payload_GetData(InvVector&& invVec)
{
   invVector_ = invVec;
}

////////
PayloadType Payload_GetData::type() const
{
   return PayloadType::GetData;
}

std::string_view Payload_GetData::typeStr() const
{
   return "getdata"sv;
}

////////
const InvVector& Payload_GetData::getInvVector() const
{
   return invVector_;
}

////////
void Payload_GetData::deserialize(const uint8_t* dataptr, size_t len)
{
   uint64_t invCount;
   auto varintlen = get_varint(invCount, dataptr, len);

   if (invCount > INV_MAX) {
      throw PayloadDeserError("inv count > INV_MAX");
   }
   invVector_.resize(invCount);

   auto ptr = dataptr + varintlen;
   auto remaining = len - varintlen;

   for (auto& entry : invVector_) {
      if (remaining < INV_ENTRY_LEN) {
         throw PayloadDeserError("inv deser size mismatch");
      }
      memcpy(&entry.invtype, ptr, 4);
      if ((entry.invtype & ~Inv_Witness) > Inv_Msg_Filtered_Block) {
         throw PayloadDeserError("invalid inv entry type");
      }
      memcpy(entry.hash, ptr + 4, 32);

      remaining -= INV_ENTRY_LEN;
      ptr += INV_ENTRY_LEN;
   }
}

////////////////////////////////////////////////////////////////////////////////
size_t Payload_GetData::serializeInner(uint8_t* dataptr) const
{
   if (dataptr == nullptr) {
      auto invcount = invVector_.size();
      auto varintlen = BtcUtils::calcVarIntSize(invcount);
      return invcount * INV_ENTRY_LEN + varintlen;
   }

   auto invcount = invVector_.size();
   std::vector<uint8_t> varint;
   auto varintlen = make_varint(invcount, varint);

   memcpy(dataptr, &varint[0], varintlen);
   dataptr += varintlen;

   for (auto& entry : invVector_) {
      memcpy(dataptr, &entry.invtype, 4);
      memcpy(dataptr + 4, entry.hash, 32);
      dataptr += 36;
   }
   return varintlen + invcount * INV_ENTRY_LEN;
}

////////////////////////////////////////////////////////////////////////////////
// Payload_Reject
Payload_Reject::Payload_Reject()
{}

Payload_Reject::Payload_Reject(const uint8_t* dataptr, size_t len)
{
   deserialize(dataptr, len);
}

////////
PayloadType Payload_Reject::type() const
{
   return PayloadType::Reject;
}

std::string_view Payload_Reject::typeStr() const
{
   return "reject"sv;
}

////////
PayloadType Payload_Reject::rejectType() const
{
   return rejectType_;
}

////
const std::vector<uint8_t>& Payload_Reject::getExtra() const
{
   return extra_;
}

////
const std::string& Payload_Reject::getReasonStr() const
{
   return reasonStr_;
}

////
int8_t Payload_Reject::code() const
{
   return code_;
}

////////
void Payload_Reject::deserialize(const uint8_t* dataptr, size_t len)
{
   uint64_t typeLen;

   //message field size in bytes
   auto varintlen = get_varint(typeLen, dataptr, len);
   auto ptr = dataptr + varintlen;

   //message type
   std::string_view msgtype{(const char*)ptr, typeLen};
   auto typeIter = typeToPayload.find(msgtype);
   if (typeIter == typeToPayload.end()) {
      throw PayloadDeserError("unknown reject type");
   }
   rejectType_ = typeIter->second;
   ptr += typeLen;

   //reject code as integer
   code_ = (const char)*ptr;
   ptr++;

   auto reasonOffset = typeLen + varintlen + 1;

   //reason str size
   uint64_t reasonLen;
   varintlen = get_varint(reasonLen, ptr, len);
   ptr += varintlen;

   //reason str
   reasonStr_ = std::string{(const char*)ptr, reasonLen};
   ptr += reasonLen;

   //extra data, final field. size and processing depends on reject code
   //just copy the data, handle when processing the payload
   auto remaining = len - (reasonLen + varintlen + reasonOffset);
   if (remaining == 0) {
      return;
   }
   extra_.resize(remaining);
   memcpy(&extra_[0], ptr, remaining);
}

////////
size_t Payload_Reject::serializeInner(uint8_t*) const
{
   throw std::runtime_error("invalid for reject");
}

////////////////////////////////////////////////////////////////////////////////
// GetDataStatus
GetDataStatus::GetDataStatus()
{
   prom_ = std::make_shared<std::promise<PayloadPtr>>();
   fut_ = prom_->get_future();
}

////////
std::shared_future<PayloadPtr> GetDataStatus::getFuture() const
{
   return fut_;
}

std::shared_ptr<std::promise<PayloadPtr>> GetDataStatus::getPromise() const
{
   return prom_;
}

////////
void GetDataStatus::setMessage(const std::string& message)
{
   msg_ = message;
}

const std::string& GetDataStatus::getMessage() const
{
   return msg_;
}

////////
bool GetDataStatus::status() const
{
   return received_;
}

void GetDataStatus::setStatus(bool st)
{
   received_ = st;
}

////////////////////////////////////////////////////////////////////////////////
////
//// BitcoinNodeInterface
////
////////////////////////////////////////////////////////////////////////////////
BitcoinNodeInterface::BitcoinNodeInterface(
   MagicWordType magicWord, bool watcher) :
   magicWord_(magicWord)
{
   if (!watcher) {
      invBlockStack_ = std::make_shared<BlockingQueue<InvVector>>();
   }
}

////////////////////////////////////////////////////////////////////////////////
BitcoinNodeInterface::~BitcoinNodeInterface()
{
   shutdown();
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::shutdown()
{
   //clean up remaining lambdas
   if (invBlockStack_ != nullptr) {
      invBlockStack_->terminate();
      invBlockStack_ = nullptr;
   }
}

////////
bool BitcoinNodeInterface::isSegWit() const
{
   return isSegWit_;
}

////
MagicWordType BitcoinNodeInterface::getMagicWord() const
{
   return magicWord_;
}

////
std::shared_ptr<BlockingQueue<InvVector>>
BitcoinNodeInterface::getInvBlockStack() const
{
   return invBlockStack_;
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::processInvBlock(InvVector invVec)
{
   if (invBlockStack_ != nullptr) {
      invBlockStack_->push_back(std::move(invVec));
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::registerInvTxCallback(
   const std::function<void(InvVector)>& func)
{
   invTxLambda_ = func;
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::registerNodeStatusCallback(
   const std::function<void(void)>& lbd)
{
   nodeStatusLambda_ = lbd;
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::registerGetTxCallback(
   const std::function<void(std::unique_ptr<Payload>)>& lbd)
{
   getTxDataLambda_ = lbd;
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::processInvTx(InvVector invVec)
{
   if (invTxLambda_) {
      invTxLambda_(invVec);
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::processGetTx(std::unique_ptr<Payload> payload)
{
   if (getTxDataLambda_) {
      getTxDataLambda_(std::move(payload));
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinNodeInterface::requestTx(InvVector invVec)
{
   /*
   Send getdata payload to bitcoin node to request transactions. Node
   reply will be processed in processGetTx
   */

   for (const auto& entry : invVec) {
      if (entry.invtype != Inv_Msg_Tx && entry.invtype!= Inv_Msg_Witness_Tx) {
        throw GetDataException("entry type isnt Inv_Msg_Tx");
      }
   }
   auto payload = std::make_unique<Payload_GetData>(std::move(invVec));
   sendMessage(std::move(payload));
}

////////////////////////////////////////////////////////////////////////////////
////
//// BitcoinP2P
////
////////////////////////////////////////////////////////////////////////////////
BitcoinP2P::BitcoinP2P(
   const std::string& addrV4, const std::string& port,
   uint32_t magicword, bool watcher) :
   BitcoinNodeInterface(magicword, watcher), addr_(addrV4), port_(port)
{
   init();
}

////////////////////////////////////////////////////////////////////////////////
BitcoinP2P::~BitcoinP2P()
{
   if (invBlockStack_ != nullptr) {
      invBlockStack_->terminate();
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::init()
{
   nodeConnected_.store(false, std::memory_order_relaxed);
   run_.store(true, std::memory_order_relaxed);
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::connectToNode(bool async)
{
   std::unique_lock<std::mutex> lock(connectMutex_, std::defer_lock);
   if (!lock.try_lock() || connectedPromise_ != nullptr) {
      //return if another thread is already here
      throw SocketError("another connect attempt is underway");
   }

   connectedPromise_ = std::unique_ptr<std::promise<bool>>(new std::promise<bool>());
   auto connectedFuture = connectedPromise_->get_future();

   std::thread connectthread([this]{ connectLoop(); });
   if (connectthread.joinable()) {
      connectthread.detach();
   }

   if (async) {
      return;
   }

   connectedFuture.get();
   if (process_except_ != nullptr) {
      std::rethrow_exception(process_except_);
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::connectLoop(void)
{
   auto waitBeforeReconnect = 0ms;
   std::promise<bool> shutdownPromise;
   shutdownFuture_ = shutdownPromise.get_future();

   if (!invTxLambda_) {
      throw SocketError("BitcoinP2P object is not initialized");
   }

   while (run_.load(std::memory_order_relaxed)) {
      //setup fresh connection
      dataStack_ = std::make_shared<BlockingQueue<std::vector<uint8_t>>>();
      socket_ = std::make_unique<BitcoinP2PSocket>(addr_, port_, dataStack_);
      verackPromise_ = std::make_unique<std::promise<bool>>();
      auto verackFuture = verackPromise_->get_future();

      while (run_.load(std::memory_order_relaxed)) {
         if (socket_->openSocket(false)) {
            break;
         }

         waitBeforeReconnect = std::min(
            waitBeforeReconnect + RECONNECT_DELAY, 5000ms);
         std::this_thread::sleep_for(waitBeforeReconnect);
      }
      if (!socket_->isValid()) {
         break;
      }

      auto processThread = [this](void)->void
      {
         try {
            this->processDataStackThread();
         } catch (...) {
            this->process_except_ = std::current_exception();
         }
      };
      socket_->connectToRemote();
      std::thread processThr(processThread);

      //send version payload
      auto version = std::make_unique<Payload_Version>();
      auto timestamp = getTimeStamp();

      struct sockaddr clientsocketaddr;
      try {
         //send version
         if (socket_->getSocketName(clientsocketaddr) != 0) {
            throw SocketError("failed to get client sockaddr");
         }
         if (socket_->getPeerName(node_addr_) != 0) {
            throw SocketError("failed to get peer sockaddr");
         }

         // Services, for future extensibility
         uint32_t services = NODE_WITNESS;
         version->setVersionHeaderIPv4(70012, services, timestamp,
            node_addr_, clientsocketaddr);
         version->userAgent_ = "Armory:0.96.5";
         version->startHeight_ = -1;
         sendMessage(std::move(version));

         //wait on verack
         verackFuture.get();
         verackPromise_.reset();
         LOGINFO << "Connected to Bitcoin node";
         updateNodeStatus(true);

         //signal calling thread
         connectedPromise_->set_value(true);
         waitBeforeReconnect = 0ms;

         //signal new blocks for good measure
         processInvBlock({});
      } catch (...) {
         waitBeforeReconnect += RECONNECT_DELAY;
         std::this_thread::sleep_for(waitBeforeReconnect);
      }

      //wait on threads
      if (processThr.joinable()) {
         processThr.join();
      }
      //close socket to guarantee select returns
      if (socket_->isValid()) {
         socket_->shutdown();
      }
      LOGINFO << "Disconnected from Bitcoin node";
      updateNodeStatus(false);
   }
   shutdownPromise.set_value(true);
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::processDataStackThread()
{
   try {
      std::shared_ptr<Payload::DeserializedPayloads> packetPtr;
      while (true) {
         auto prevPacket = packetPtr;
         packetPtr.reset();

         auto data = std::move(dataStack_->pop_front());
         auto processedPacket = Payload::deserialize(
            data, getMagicWord(), prevPacket);

         if (processedPacket->spillOffset_ != SIZE_MAX) {
            packetPtr = processedPacket;
         }
         processPayload(std::move(processedPacket->payloads_));
      }
   } catch (const StopBlockingLoop&) {
      LOGERR << "caught StopBlockingLoop in processDataStackThread";
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::processPayload(
   std::vector<std::unique_ptr<Payload>> payloadVec)
{
   for (auto&& payload : payloadVec) {
      switch (payload->type())
      {
         case PayloadType::Version:
         {
            checkServices(std::move(payload));
            returnVerack();
            break;
         }

         case PayloadType::VerAck:
            gotVerack();
            break;

         case PayloadType::Ping:
            replyPong(std::move(payload));
            break;

         case PayloadType::Inv:
            processInv(std::move(payload));
            break;

         case PayloadType::GetData:
            processGetData(std::move(payload));
            break;

         case PayloadType::Tx:
            processGetTx(std::move(payload));
            break;

         case PayloadType::Reject:
            processReject(std::move(payload));
            break;

         default:
            continue;
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::checkServices(std::unique_ptr<Payload> payload)
{
   auto pver = (Payload_Version*)payload.get();
   const auto& mw = Armory::Config::BitcoinSettings::getMagicBytes();
   auto magicWord = getMagicWord();

   if (memcmp(mw.getPtr(), &magicWord, 4)) {
      BinaryDataRef bdrMw;
      bdrMw.setRef((uint8_t*)&magicWord, 4);

      LOGERR << "Node magic word does not match expected magic word:";
      LOGERR << "   expected: " << mw.toHexStr();
      LOGERR << "   got: " << bdrMw.toHexStr();
      throw NodeException("magic word mismatch");
   }

   if (pver->vheader_.services_ & NODE_WITNESS) {
      isSegWit_ = true;
   } else {
      isSegWit_ = false;
   }
   topBlock_ = pver->startHeight_;
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::gotVerack()
{
   if (verackPromise_ == nullptr) {
      return;
   }
   try {
      verackPromise_->set_value(true);
   } catch (const std::future_error&) {
      //already set or no shared state, move on
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::returnVerack()
{
   sendMessage(std::make_unique<Payload_Verack>());
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::replyPong(std::unique_ptr<Payload> payload)
{
   Payload_Ping* pping = (Payload_Ping*)payload.get();
   auto ppong = std::make_unique<Payload_Pong>();

   ppong->nonce_ = pping->nonce_;
   sendMessage(std::move(ppong));
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::processInv(std::unique_ptr<Payload> payload)
{
   Payload_Inv* invptr = (Payload_Inv*)payload.get();

   //order entries by type
   std::map<InvType, InvVector> orderedEntries;
   for (auto& entry : invptr->invVector_) {
      auto& invvec = orderedEntries[entry.invtype];
      invvec.emplace_back(std::move(entry));
   }

   //process them
   for (auto& entryVec : orderedEntries) {
      switch (entryVec.first)
      {
         case Inv_Msg_Witness_Block:
         case Inv_Msg_Block:
         {
            //1 sec delay to make sure data is written on disk
            std::this_thread::sleep_for(1s);
            processInvBlock(std::move(entryVec.second));
            break;
         }

         case Inv_Msg_Witness_Tx:
         case Inv_Msg_Tx:
            processInvTx(std::move(entryVec.second));
            break;

         default:
            continue;
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::processGetData(std::unique_ptr<Payload> payload)
{
   auto payloadgetdata = (Payload_GetData*)payload.get();
   auto& invvector = payloadgetdata->getInvVector();
   auto getdatamap = getDataPayloadMap_.get();

   std::vector<std::unique_ptr<Payload>> payloadVec;
   for (auto& entry : invvector) {
      BinaryDataRef bdr(entry.hash, 32);

      auto payloadIter = getdatamap->find(bdr);
      if (payloadIter == getdatamap->end()) {
         continue;
      }
      payloadVec.emplace_back(std::move(payloadIter->second->payload_));
      getDataPayloadMap_.erase(payloadIter->first);
   }
   sendMessage(std::move(payloadVec));
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::processReject(std::unique_ptr<Payload> payload)
{
   if (payload->type() != PayloadType::Reject) {
      LOGERR << "processReject: expected payload_reject type, got " <<
         payload->typeStr() << " instead";
      return;
   }
   processGetTx(std::move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::sendMessage(std::unique_ptr<Payload> payload)
{
   auto msg = payload->serialize(getMagicWord());

   std::unique_lock<std::mutex> lock(writeMutex_);
   auto socket_payload = std::make_unique<WritePayload_Raw>(msg);
   socket_->pushPayload(std::move(socket_payload), nullptr);
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::sendMessage(std::vector<std::unique_ptr<Payload>> payloadVec)
{
   std::vector<uint8_t> msg;
   size_t totalSize = 0;
   for (auto& payload : payloadVec) {
      totalSize += payload->getSerializedSize();
   }

   msg.resize(totalSize);
   size_t offset = 0;
   for (auto& payload : payloadVec) {
      offset += payload->serialize(
         getMagicWord(), &msg[0] + offset, msg.size() - offset);
   }

   std::unique_lock<std::mutex> lock(writeMutex_);
   auto socket_payload = std::make_unique<WritePayload_Raw>(msg);
   socket_->pushPayload(std::move(socket_payload), nullptr);
}

void BitcoinP2P::callback() const
{
   if (nodeStatusLambda_) {
      nodeStatusLambda_();
   }
}

////////////////////////////////////////////////////////////////////////////////
int64_t BitcoinP2P::getTimeStamp() const
{
   return (int64_t)time(0);
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::shutdown()
{
   if (!run_.load(std::memory_order_relaxed)) {
      return;
   }
   run_.store(false, std::memory_order_relaxed);

   if (socket_ != nullptr) {
      auto start = std::chrono::system_clock::now();
      socket_->shutdown();
      shutdownFuture_.wait();
   }

   //have to call the parent class shutdown explicitly
   BitcoinNodeInterface::shutdown();
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinP2P::updateNodeStatus(bool connected)
{
   nodeConnected_.store(connected, std::memory_order_relaxed);
   callback();
}

bool BitcoinP2P::connected() const
{
   return nodeConnected_.load(std::memory_order_relaxed);
}

////////////////////////////////////////////////////////////////////////////////
//
// BitcoinP2PSocket
//
////////////////////////////////////////////////////////////////////////////////
BitcoinP2PSocket::BitcoinP2PSocket(
   const std::string& addr, const std::string& port,
   std::shared_ptr<BlockingQueue<std::vector<uint8_t>>> readStack) :
   PersistentSocket(addr, port), readDataStack_(readStack)
{}

SocketType BitcoinP2PSocket::type() const
{
   return SocketType::BitcoinP2P;
}

////////
void BitcoinP2PSocket::respond(std::vector<uint8_t>& packet)
{

   if (!packet.empty()) {
      readDataStack_->push_back(std::move(packet));
   } else {
      readDataStack_->terminate();
   }
}

////////
void BitcoinP2PSocket::pushPayload(
   std::unique_ptr<Socket_WritePayload> write_payload,
   std::shared_ptr<Socket_ReadPayload>)
{
   if (write_payload == nullptr) {
      return;
   }
   std::vector<uint8_t> data;
   write_payload->serialize(data);
   queuePayloadForWrite(data);
}
