////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BridgeSocket.h"
#include "CppBridge.h"
#include "BIP15x_Handshake.h"
#include "BIP150_151.h"

#include <google/protobuf/message.h>

using namespace std;
using namespace ArmoryBridge;

#define BRIDGE_SOCKET_MAXLEN 1024 * 1024 * 1024 //1MB

////////////////////////////////////////////////////////////////////////////////
////
////  CppBridgeSocket
////
////////////////////////////////////////////////////////////////////////////////
CppBridgeSocket::CppBridgeSocket(
   const string& addr, const string& port,
   shared_ptr<CppBridge> bridgePtr) :
   PersistentSocket(addr, port), bridgePtr_(bridgePtr),
   serverName_(addr + ":" + port)
{
   //setup auth peers db
   authPeers_ = make_shared<AuthorizedPeers>();

   //inject GUI key (GUI is the server, bridge connects to it)
   vector<string> peerNames = { serverName_ };
   authPeers_->addPeer(
      ArmoryConfig::NetworkSettings::serverPublicKey(), peerNames);
   auto lbds = AuthorizedPeers::getAuthPeersLambdas(authPeers_);

   //write own public key to cookie file
   {
      const auto& ownKey = authPeers_->getOwnPublicKey();
      fstream file;
      file.open("./client_cookie", ios::out);
      file.write((const char*)ownKey.pubkey, 33);
   }

   //init bip15x channel
   bip151Connection_ = make_shared<BIP151Connection>(lbds, false);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridgeSocket::respond(vector<uint8_t>& data)
{
   if (data.empty())
   {
      //shutdown condition
      shutdown();
      return;
   }

   //append data to leftovers from previous iteration if applicable
   if (leftOverData_.size() != 0)
   {
      leftOverData_.insert(leftOverData_.end(), data.begin(), data.end());
      data = move(leftOverData_);

      //clear the leftover data
      leftOverData_.clear();
   }

   BinaryDataRef dataRef;
   if (bip151Connection_->connectionComplete())
   {
      while (true)
      {
         //get decrypted length
         auto decrLen = bip151Connection_->decryptPacket(
            &data[0], POLY1305MACLEN + AUTHASSOCDATAFIELDLEN,
            nullptr, POLY1305MACLEN + AUTHASSOCDATAFIELDLEN);

         if (decrLen == -1 || decrLen > BRIDGE_SOCKET_MAXLEN)
         {
            //fatal error
            LOGERR << "packet exceeds BRIDGE_SOCKET_MAXLEN, aborting";
            shutdown();
            return;
         }

         if (decrLen > data.size() + POLY1305MACLEN)
         {
            //not enough data to decrypt, save it and continue
            leftOverData_ = move(data);
            return;
         }

         //decrypt the data
         auto result = bip151Connection_->decryptPacket(
            &data[0], data.size(), &data[0], data.size());

         dataRef.setRef(
            &data[0] + AUTHASSOCDATAFIELDLEN, decrLen);

         //we have decrypted data, process it
         if (data[4] < ArmoryAEAD::HandshakeSequence::Threshold_Begin)
         {
            //we can only process user data after the AEAD channel is auth'ed
            if (bip151Connection_->getBIP150State() != BIP150State::SUCCESS)
               shutdown();

            if (!bridgePtr_->processData(dataRef))
               shutdown();

            //if we have left over data, isolate it and process it
            if (data.size() > decrLen + AUTHASSOCDATAFIELDLEN + POLY1305MACLEN)
            {
               data = vector<uint8_t>(
                  data.begin() + decrLen + AUTHASSOCDATAFIELDLEN + POLY1305MACLEN,
                  data.end());
               continue;
            }

            return;
         }

         break;
      }
   }
   else
   {
      dataRef.setRef(&data[0], data.size());
   }

   //we can only get this far if the data is part of an ongoing AEAD handhsake
   if (!processAEADHandshake(dataRef))
   {
      //handshake failure
      LOGERR << "AEAD handshake failed, aborting";
      shutdown();
   }
}

////////////////////////////////////////////////////////////////////////////////
void CppBridgeSocket::pushPayload(
   unique_ptr<Socket_WritePayload> write_payload,
   shared_ptr<Socket_ReadPayload>)
{
   if (write_payload == nullptr)
      return;

   //lock write mutex
   unique_lock<mutex> lock(writeMutex_);

   //check for rekeys
   {
      bool needs_rekey = false;
      auto rightnow = chrono::system_clock::now();

      if (bip151Connection_->rekeyNeeded(write_payload->getSerializedSize()))
      {
         needs_rekey = true;
      }
      else
      {
         auto time_sec = chrono::duration_cast<chrono::seconds>(
            rightnow - outKeyTimePoint_);
         if (time_sec.count() >= AEAD_REKEY_INVERVAL_SECONDS)
         needs_rekey = true;
      }

         if (needs_rekey)
         {
            vector<uint8_t> rekeyPacket(BIP151PUBKEYSIZE + 1 + POLY1305MACLEN);
            memset(&rekeyPacket[1], 0, BIP151PUBKEYSIZE);
            rekeyPacket[0] = ArmoryAEAD::HandshakeSequence::Rekey;

            bip151Connection_->assemblePacket(
               &rekeyPacket[0], rekeyPacket.size() - POLY1305MACLEN,
               &rekeyPacket[0], rekeyPacket.size());

            queuePayloadForWrite(rekeyPacket);
            bip151Connection_->rekeyOuterSession();
            outKeyTimePoint_ = rightnow;
         }
   }

   //serialize payload
   vector<uint8_t> data;
   write_payload->serialize(data);

   //set data flag
   data[4] = 0;

   //encrypt
   bip151Connection_->assemblePacket(
      &data[0], data.size() - POLY1305MACLEN,
      &data[0], data.size());

   queuePayloadForWrite(data);
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridgeSocket::processAEADHandshake(BinaryDataRef data)
{
   //write lambda
   auto writeData = [this](
      const BinaryData& payload, uint8_t msgType, bool encrypt)
   {
      //prepend message type to payload
      size_t packetSize = 5 + payload.getSize() + POLY1305MACLEN;
      vector<uint8_t> cipherText(packetSize);

      unsigned index = 0;
      if (encrypt)
      {
         auto sizeHeader = (uint32_t*)&cipherText[0];
         *sizeHeader = payload.getSize() + 1;
         index = 4;
      }

      cipherText[index] = msgType;
      memcpy(&cipherText[index + 1], payload.getPtr(), payload.getSize());

      //encrypt if necessary
      if (encrypt)
      {
         bip151Connection_->assemblePacket(
            &cipherText[0], packetSize - POLY1305MACLEN,
            &cipherText[0], packetSize);
      }
      else
      {
         cipherText.resize(payload.getSize() + 1);
      }

      //push
      queuePayloadForWrite(cipherText);
   };

   //first byte is the AEAD sequence
   auto seqId = (ArmoryAEAD::HandshakeSequence)data[0];

   switch (seqId)
   {
   case ArmoryAEAD::HandshakeSequence::PresentPubKey:
   {
      LOGERR << "Server presented pubkey, bridge does not tolerate 1-way auth";
      return false;
   }

   default:
      break;
   }

   //common client side handshake
   BinaryDataRef msgbdr = data.getSliceRef(1, data.getSize() - 1);
   auto status = ArmoryAEAD::BIP15x_Handshake::clientSideHandshake(
      bip151Connection_.get(), serverName_,
      seqId, msgbdr,
      writeData);

   switch (status)
   {
   case ArmoryAEAD::HandshakeState::StepSuccessful:
   case ArmoryAEAD::HandshakeState::RekeySuccessful:
      return true;

   case ArmoryAEAD::HandshakeState::Completed:
   {
      outKeyTimePoint_ = chrono::system_clock::now();

      //flag connection as ready
      return true;
   }

   default:
      return false;
   }
}

////////////////////////////////////////////////////////////////////////////////
////
////  WritePayload_Bridge
////
////////////////////////////////////////////////////////////////////////////////
void WritePayload_Bridge::serialize(std::vector<uint8_t>& data)
{
   if (message_ == nullptr)
      return;

   auto msgSize = message_->ByteSize();
   data.resize(msgSize + 9 + POLY1305MACLEN);

   //set packet size
   auto sizePtr = (uint32_t*)&data[0];
   *sizePtr = msgSize + 5;

   //set id
   auto idPtr = (uint32_t*)&data[5];
   *idPtr = id_;

   //serialize protobuf message
   message_->SerializeToArray(&data[9], msgSize);
}

////////////////////////////////////////////////////////////////////////////////
size_t WritePayload_Bridge::getSerializedSize(void) const
{
   return message_->ByteSize() + 9 + POLY1305MACLEN;
}
