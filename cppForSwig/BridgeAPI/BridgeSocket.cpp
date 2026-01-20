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
using namespace Armory::Bridge;

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
   authPeers_ = make_shared<Armory::Wallets::AuthorizedPeers>();

   auto uiPubKey = Armory::Config::NetworkSettings::uiPublicKey();
   if (uiPubKey.getSize() != 33)
   {
      LOGERR << "Invalid UI pubkey!";
      LOGERR << "The UI pubkey must be 33 bytes long (66 hexits), " <<
         "passed through --uiPubKey";
      throw runtime_error("invalid UI pubkey");
   }

   //inject UI key (UI is the server, bridge connects to it)
   vector<string> peerNames = { serverName_ };
   authPeers_->addPeer(uiPubKey, peerNames);
   auto lbds = Armory::Wallets::AuthorizedPeers::getAuthPeersLambdas(
      authPeers_);

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
   if (!leftOverData_.empty())
   {
      leftOverData_.insert(leftOverData_.end(), data.begin(), data.end());
      data = move(leftOverData_);

      //leftoverData_ should be empty cause of the move operation
      assert(leftOverData_.empty());
   }

   while (!data.empty())
   {
      //for data that isn't encrypted, assume the payload is
      //a single whole packet
      bool encr = false;

      //skip size header
      BinaryDataRef dataRef(&data[0], data.size());
      auto packetSize = dataRef.getSize();

      if (bip151Connection_->connectionComplete())
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

         if (decrLen > (ssize_t)data.size() + POLY1305MACLEN)
         {
            //not enough data to decrypt, save it and continue
            leftOverData_ = move(data);
            return;
         }

         //decrypt the data
         bip151Connection_->decryptPacket(
            &data[0], data.size(), &data[0], data.size());

         //point to the head of the decrypted cleartext
         dataRef.setRef(&data[0] + AUTHASSOCDATAFIELDLEN, decrLen);

         //keep track of this packet's size
         if ((ssize_t)data.size() >
            decrLen + AUTHASSOCDATAFIELDLEN + POLY1305MACLEN)
         {
            packetSize = decrLen + AUTHASSOCDATAFIELDLEN + POLY1305MACLEN;
         }

         encr = true;
      }

      if (dataRef.empty())
      {
         //handshake failure
         LOGERR << "invalid packet size, aborting";
         shutdown();
         return;
      }

      auto dataType = (ArmoryAEAD::BIP151_PayloadType)dataRef[0];
      if (encr && dataType < ArmoryAEAD::BIP151_PayloadType::Threshold_Begin)
      {
         //we can only process user messages after the AEAD channel is auth'ed
         //and the data is encrypted
         if (bip151Connection_->getBIP150State() != BIP150State::SUCCESS)
         {
            shutdown();
            return;
         }

         if (!bridgePtr_->processData(dataRef))
         {
            shutdown();
            return;
         }
      }
      else
      {
         //we can only get here if the data is part of an ongoing AEAD
         //handhsake or an incoming channel rekey
         if (!processAEADHandshake(dataRef))
         {
            //handshake failure
            LOGERR << "AEAD handshake failed, aborting";
            shutdown();
            return;
         }
      }

      if (data.size() == packetSize)
         return;

      //payload is bigger than the packet we just processed, remove leading
      //packet from data and iterate over what's left
      data = vector<uint8_t>(data.begin() + packetSize, data.end());
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
         vector<uint8_t> rekeyPacket(BIP151PUBKEYSIZE + 5 + POLY1305MACLEN);
         memset(&rekeyPacket[5], 0, BIP151PUBKEYSIZE);
         
         uint32_t rekeyPacketLen = BIP151PUBKEYSIZE + 1;
         memcpy(&rekeyPacket[0], &rekeyPacketLen, sizeof(uint32_t));
         memset(&rekeyPacket[4],
            (uint8_t)ArmoryAEAD::BIP151_PayloadType::Rekey, 1);

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
   memset(&data[4], 0, 1);

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
      const BinaryData& payload, ArmoryAEAD::BIP151_PayloadType msgType, bool encrypt)
   {
      //prepend message type to payload
      size_t packetSize = 5 + payload.getSize() + POLY1305MACLEN;
      vector<uint8_t> cipherText(packetSize);

      unsigned index = 0;
      if (encrypt)
      {
         uint32_t sizeHeader = payload.getSize() + 1;
         memcpy(&cipherText[0], &sizeHeader, sizeof(uint32_t));
         index = 4;
      }

      memset(&cipherText[index], (uint8_t)msgType, 1);
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
   auto seqId = (ArmoryAEAD::BIP151_PayloadType)data[0];

   switch (seqId)
   {
   case ArmoryAEAD::BIP151_PayloadType::PresentPubKey:
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

   auto msgSize = message_->ByteSizeLong();
   data.resize(msgSize + 5 + POLY1305MACLEN);

   //set packet size
   uint32_t sizeVal = msgSize + 1;
   memcpy(&data[0], &sizeVal, sizeof(uint32_t));

   //serialize protobuf message
   message_->SerializeToArray(&data[5], msgSize);
}

////////////////////////////////////////////////////////////////////////////////
size_t WritePayload_Bridge::getSerializedSize(void) const
{
   return message_->ByteSizeLong() + 5 + POLY1305MACLEN;
}
