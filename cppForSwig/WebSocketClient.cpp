////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018-2021, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "WebSocketClient.h"
#include "BIP15x_Handshake.h"

using namespace std;
using namespace Armory::Wallets;

////////////////////////////////////////////////////////////////////////////////
static struct lws_protocols protocols[] =
{
   /* first protocol must always be HTTP handler */

   {
      "armory-bdm-protocol",
      WebSocketClient::callback,
      sizeof(struct per_session_data__client),
      per_session_data__client::rcv_size,
      1,
      NULL,
      0
   },

   { NULL, NULL, 0, 0, 0, NULL, 0 } /* terminator */
};

////////////////////////////////////////////////////////////////////////////////
WebSocketClient::WebSocketClient(const string& addr, const string& port,
   const string& datadir, const PassphraseLambda& passLbd, 
   const bool& ephemeralPeers, bool oneWayAuth,
   shared_ptr<RemoteCallback> cbPtr) :
   SocketPrototype(addr, port, false), 
   servName_(addr_ + ":" + port_), callbackPtr_(cbPtr)
{
   count_.store(0, std::memory_order_relaxed);
   requestID_.store(0, std::memory_order_relaxed);
   contextPtr_.store(0, memory_order_release);

   if (!ephemeralPeers)
   {
      std::string filename(CLIENT_AUTH_PEER_FILENAME);
      authPeers_ = make_shared<AuthorizedPeers>(
         datadir, filename, passLbd);
   }
   else
   {
      authPeers_ = make_shared<AuthorizedPeers>();
   }

   auto lbds = AuthorizedPeers::getAuthPeersLambdas(authPeers_);
   bip151Connection_ = make_shared<BIP151Connection>(lbds, oneWayAuth);
}


////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::pushPayload(
   unique_ptr<Socket_WritePayload> write_payload,
   shared_ptr<Socket_ReadPayload> read_payload)
{
   if (run_.load(memory_order_relaxed) == 0)
      throw LWS_Error("lws client down");

   unsigned id = requestID_.fetch_add(1, memory_order_relaxed);
   if (read_payload != nullptr)
   {
      //create response object
      auto response = make_shared<WriteAndReadPacket>(id, read_payload);

      //set response id
      readPackets_.insert(make_pair(id, move(response)));   
   }

   write_payload->id_ = id;
   writeSerializationQueue_.push_back(move(write_payload));
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::writeService()
{
   while (true)
   {
      unique_ptr<Socket_WritePayload> message;
      try
      {
         message = move(writeSerializationQueue_.pop_front());
      }
      catch (Armory::Threading::StopBlockingLoop&)
      {
         break;
      }

      vector<uint8_t> data;
      message->serialize(data);

      //push packets to write queue
      if (!bip151Connection_->connectionComplete())
         throw LWS_Error("invalid aead state");

      //check for rekey
      {
         bool needs_rekey = false;
         auto rightnow = chrono::system_clock::now();

         if (bip151Connection_->rekeyNeeded(message->getSerializedSize()))
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
            BinaryData rekeyPacket(BIP151PUBKEYSIZE);
            memset(rekeyPacket.getPtr(), 0, BIP151PUBKEYSIZE);

            SerializedMessage rekey_msg;
            rekey_msg.construct(
               rekeyPacket.getDataVector(),
               bip151Connection_.get(),
               ArmoryAEAD::BIP151_PayloadType::Rekey);

            writeQueue_->push_back(rekey_msg);
            bip151Connection_->rekeyOuterSession();
            outKeyTimePoint_ = rightnow;
            ++outerRekeyCount_;
         }
      }

      SerializedMessage ws_msg;
      ws_msg.construct(data,
         bip151Connection_.get(),
         ArmoryAEAD::BIP151_PayloadType::FragmentHeader,
         message->id_);

      writeQueue_->push_back(ws_msg);
   }
}

////////////////////////////////////////////////////////////////////////////////
struct lws_context* WebSocketClient::init()
{
   run_.store(1, memory_order_relaxed);
   currentReadMessage_.reset();

   //setup context
   struct lws_context_creation_info info;
   memset(&info, 0, sizeof info);

   info.port = CONTEXT_PORT_NO_LISTEN;
   info.protocols = protocols;
   info.gid = -1;
   info.uid = -1;

   //1 min ping/pong
   //info.ws_ping_pong_interval = 60;

   auto contextptr = lws_create_context(&info);
   if (contextptr == NULL)
      throw LWS_Error("failed to create LWS context");

   //connect to server
   struct lws_client_connect_info i;
   memset(&i, 0, sizeof(i));

   int port = stoi(port_);
   if (port == 0)
      port = WEBSOCKET_PORT;
   i.port = port;

   const char *prot, *p;
   char path[300];
   if(lws_parse_uri((char*)addr_.c_str(), &prot, &i.address, &i.port, &p) !=0)
   {
      LOGERR << "failed to parse server URI";
      throw LWS_Error("failed to parse server URI");
   }

   path[0] = '/';
   lws_strncpy(path + 1, p, sizeof(path) - 1);
   i.path = path;
   i.host = i.address;
   i.origin = i.address;
   i.ietf_version_or_minus_one = -1;

   i.context = contextptr;
   i.method = nullptr;
   i.protocol = protocols[PROTOCOL_ARMORY_CLIENT].name;
   i.userdata = this;

   struct lws* wsiptr;
   //i.pwsi = &wsiptr;
   wsiptr = lws_client_connect_via_info(&i);
   wsiPtr_.store(wsiptr, memory_order_release);

   return contextptr;
}

////////////////////////////////////////////////////////////////////////////////
bool WebSocketClient::connectToRemote()
{
   auto connectedFut = connectionReadyProm_.get_future();

   auto serviceLBD = [this](void)->void
   {
      auto readLBD = [this](void)->void
      {
         this->readService();
      };

      readThr_ = thread(readLBD);

      auto writeLBD = [this](void)->void
      {
         this->writeService();
      };

      writeThr_ = thread(writeLBD);

      auto contextPtr = init();
      contextPtr_.store(contextPtr, memory_order_release);
      writeQueue_ = make_unique<WSClientWriteQueue>(contextPtr);
      this->service(contextPtr);
   };

   serviceThr_ = thread(serviceLBD);

   if (connectedFut.wait_for(std::chrono::seconds{ 7 }) == std::future_status::ready) {
      return connectedFut.get();
   }
   else {
      shutdown();
      cleanUp();
      return false;
   }
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::service(lws_context* contextPtr)
{
   int n = 0;
   auto wsiPtr = (struct lws*)wsiPtr_.load(memory_order_acquire);

   while (run_.load(memory_order_relaxed) != 0 && n >= 0)
   {
      n = lws_service(contextPtr, 500);
      if (!currentWriteMessage_.isDone() || !writeQueue_ || !writeQueue_->empty())
         lws_callback_on_writable(wsiPtr);
   }

   lws_context_destroy(contextPtr);
   contextPtr_.store(0, memory_order_release);
   cleanUp();
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::shutdown()
{
   if (run_.load(memory_order_relaxed) == 0)
      return;

   auto context = (struct lws_context*)contextPtr_.load(memory_order_acquire);
   if (context != nullptr) {
      lws_cancel_service(context);
   }
   run_.store(0, memory_order_relaxed);
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::cleanUp()
{
   writeSerializationQueue_.terminate();
   readQueue_.terminate();
   writeQueue_.reset();

   try
   {
      if (writeThr_.joinable())
         writeThr_.join();

      if(readThr_.joinable())
         readThr_.join();
   }
   catch(system_error& e)
   {
      LOGERR << "failed to join on client threads with error:";
      LOGERR << e.what();

      throw e;
   }
   
   readPackets_.clear();

   //create error message to send to all outsanding read callbacks
   ::Codec_BDVCommand::BDV_Error errMsg;
   errMsg.set_code(-1);
   errMsg.set_errstr("LWS client disconnected");

   BinaryData errPacket(errMsg.ByteSizeLong());
   if (!errMsg.SerializeToArray(
      errPacket.getPtr(), (int)errPacket.getSize()))
   {
      throw LWS_Error("error during shutdown");
   }

   BinaryWriter msgBW;
   msgBW.put_uint32_t(5 + (uint32_t)errPacket.getSize());
   msgBW.put_uint8_t((uint8_t)ArmoryAEAD::BIP151_PayloadType::SinglePacket);
   msgBW.put_uint32_t(0);
   msgBW.put_BinaryData(errPacket, errPacket.getSize());

   WebSocketMessagePartial errObj;
   errObj.parsePacket(msgBW.getDataRef());

   //trigger callbacks for all outstanding query operations
   vector<thread> threads;
   {
      auto readMap = readPackets_.get();
      for (auto& readPair : *readMap)
      {
         auto& msgObjPtr = readPair.second;
         auto callbackPtr = dynamic_cast<CallbackReturn_WebSocket*>(
            msgObjPtr->payload_->callbackReturn_.get());
         if (callbackPtr == nullptr)
            continue;

         //run in its own thread
         auto callbackLbd = [callbackPtr, &errObj]()
         {
            callbackPtr->callback(errObj);
         };

         threads.push_back(thread(callbackLbd));
      }
   }

   //wait on callback threads
   for (auto& thr : threads)
   {
      if (thr.joinable())
         thr.join();
   }

   LOGINFO << "lws client cleaned up";
}

////////////////////////////////////////////////////////////////////////////////
int WebSocketClient::callback(struct lws *wsi, 
   enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
   auto instance = (WebSocketClient*)user;

   switch (reason)
   {

   case LWS_CALLBACK_CLIENT_ESTABLISHED:
   {
      //ws connection established with server
      if (instance != nullptr)
         instance->connected_.store(true, memory_order_release);

      break;
   }

   case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
   {
      LOGERR << "lws client connection error";
      if (len > 0)
      {
         auto errstr = (char*)in;
         LOGERR << "   error message: " << errstr;
      }
      else
      {
         LOGERR << "no error message was provided by lws";
      }

      [[fallthrough]];
   }

   case LWS_CALLBACK_CLIENT_CLOSED:
   case LWS_CALLBACK_CLOSED:
   {
      try
      {
         instance->connected_.store(false, memory_order_release);
         if (instance->callbackPtr_ != nullptr)
         {
            instance->callbackPtr_->disconnected();
            try
            {
               instance->connectionReadyProm_.set_value(false);
            }
            catch(future_error&)
            { }
         }

         instance->shutdown();
      }
      catch(LWS_Error&)
      { }

      break;
   }

   case LWS_CALLBACK_CLIENT_RECEIVE:
   {
      BinaryData bdData;
      bdData.resize(len);
      memcpy(bdData.getPtr(), in, len);

      instance->readQueue_.push_back(move(bdData));
      break;
   }

   case LWS_CALLBACK_CLIENT_WRITEABLE:
   {
      if (instance->currentWriteMessage_.isDone())
      {
         try
         {
            instance->currentWriteMessage_ =
               move(instance->writeQueue_->pop_front());
         }
         catch (Armory::Threading::IsEmpty&)
         {
            break;
         }
      }

      auto&& packet = instance->currentWriteMessage_.consumeNextPacket();
      auto body = (uint8_t*)packet.getPtr() + LWS_PRE;
      auto m = lws_write(wsi, 
         body, packet.getSize() - LWS_PRE,
         LWS_WRITE_BINARY);

      if (m != (int)packet.getSize() - (int)LWS_PRE)
      {
         LOGERR << "failed to send packet of size";
         LOGERR << "packet is " << packet.getSize() <<
            " bytes, sent " << m << " bytes";
      }

      if (instance->currentWriteMessage_.isDone())
      {
         instance->currentWriteMessage_.clear();
         instance->count_.fetch_add(1, memory_order_relaxed);
      }

      break;
   }

   default:
      break;
   }

   return 0;
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::readService()
{
   while (1)
   {
      BinaryData payload;
      try
      {
         payload = move(readQueue_.pop_front());
      }
      catch (Armory::Threading::StopBlockingLoop&)
      {
         break;
      }

      if (leftOverData_.getSize() != 0)
      {
         leftOverData_.append(payload);
         payload = move(leftOverData_);
         leftOverData_.clear();
      }

      if (bip151Connection_->connectionComplete())
      {
         //decrypt packet
         auto result = bip151Connection_->decryptPacket(
            payload.getPtr(), payload.getSize(),
            payload.getPtr(), payload.getSize());

         if (result != 0)
         {
            //see WebSocketServer::processReadQueue for the explaination
            if (result <= WEBSOCKET_MESSAGE_PACKET_SIZE && result > -1)
            {
               leftOverData_ = move(payload);
               continue;
            }

            shutdown();
            return;
         }

         payload.resize(payload.getSize() - POLY1305MACLEN);
      }

      //deser packet
      auto payloadRef = currentReadMessage_.insertDataAndGetRef(payload);
      auto result = 
         currentReadMessage_.message_.parsePacket(payloadRef);
      if (!result)
      {
         currentReadMessage_.reset();
         continue;
      }

      if (!currentReadMessage_.message_.isReady())
         continue;

      if (currentReadMessage_.message_.getType() >
         ArmoryAEAD::BIP151_PayloadType::Threshold_Begin)
      {
         if (!processAEADHandshake(currentReadMessage_.message_))
         {
            //invalid AEAD message, kill connection
            shutdown();
            return;
         }

         currentReadMessage_.reset();
         continue;
      }

      if (bip151Connection_->getBIP150State() != BIP150State::SUCCESS)
      {
         LOGWARN << "encryption layer is uninitialized, aborting connection";
         shutdown();
         return;
      }

      //figure out request id, fulfill promise
      auto& msgid = currentReadMessage_.message_.getId();
      switch (msgid)
      {
      case WEBSOCKET_CALLBACK_ID:
      {
         if (callbackPtr_ == nullptr)
         {
            currentReadMessage_.reset();
            continue;
         }

         auto msgptr = make_shared<::Codec_BDVCommand::BDVCallback>();
         if (!currentReadMessage_.message_.getMessage(msgptr.get()))
         {
            currentReadMessage_.reset();
            continue;
         }

         callbackPtr_->processNotifications(msgptr);
         currentReadMessage_.reset();

         break;
      }

      default:
         auto readMap = readPackets_.get();
         auto iter = readMap->find(msgid);
         if (iter != readMap->end())
         {
            auto& msgObjPtr = iter->second;
            auto callbackPtr = dynamic_cast<CallbackReturn_WebSocket*>(
               msgObjPtr->payload_->callbackReturn_.get());
            if (callbackPtr == nullptr)
               continue;

            callbackPtr->callback(currentReadMessage_.message_);
            readPackets_.erase(msgid);
            currentReadMessage_.reset();
         }
         else
         {
            LOGWARN << "invalid msg id";
            currentReadMessage_.reset();
         }
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
bool WebSocketClient::processAEADHandshake(const WebSocketMessagePartial& msgObj)
{
   auto writeData = [this](const BinaryData& payload,
      ArmoryAEAD::BIP151_PayloadType type, bool encrypt)
      ->void
   {
      SerializedMessage msg;
      BIP151Connection* connPtr = nullptr;
      if (encrypt)
         connPtr = bip151Connection_.get();

      msg.construct(payload.getDataVector(), connPtr, type);
      writeQueue_->push_back(msg);
   };

   if (serverPubkeyProm_ != nullptr)
   {
      //wait on server pubkey announce ACK/nACK
      auto fut = serverPubkeyProm_->get_future();
      fut.wait();
      serverPubkeyProm_.reset();
   }

   //auth type sanity checks & setup
   auto msgbdr = msgObj.getSingleBinaryMessage();
   switch (msgObj.getType())
   {
   case ArmoryAEAD::BIP151_PayloadType::PresentPubKey:
   {
      serverPubkeyAnnounce_ = true;

      /*packet is server's pubkey, do we have it?*/
      if (!bip151Connection_->isOneWayAuth())
      {
         LOGERR << "Trying to connect to 1-way server as a 2-way client." <<
            " Aborting!";
         return false;
      }
      
      if (!bip151Connection_->havePublicKey(msgbdr, servName_))
      {
         //we don't have this key, setup promise and prompt user
         serverPubkeyProm_ = make_shared<promise<bool>>();
         promptUser(msgbdr, servName_);
      }

      return true;
   }

   case ArmoryAEAD::BIP151_PayloadType::EncInit:
   {
      if (bip151Connection_->isOneWayAuth() && !serverPubkeyAnnounce_)
      {
         LOGERR << "trying to connect to 2-way server as 1-way client." <<
            " Aborting!";
         return false;
      }

      break;
   }

   default: 
      break;
   }

   //regular client side AEAD handshake processing
   auto status = ArmoryAEAD::BIP15x_Handshake::clientSideHandshake(
      bip151Connection_.get(), servName_,
      msgObj.getType(), msgbdr, writeData);

   switch (status)
   {
   case ArmoryAEAD::HandshakeState::StepSuccessful:
      return true;

   case ArmoryAEAD::HandshakeState::RekeySuccessful:
   {
      ++innerRekeyCount_;
      return true;
   }

   case ArmoryAEAD::HandshakeState::Completed:
   {
      outKeyTimePoint_ = chrono::system_clock::now();

      //flag connection as ready
      connectionReadyProm_.set_value(true);
      return true;
   }

   default:
      return false;
   }
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketClient::addPublicKey(const SecureBinaryData& pubkey)
{
   stringstream ss;
   ss << addr_ << ":" << port_;

   authPeers_->addPeer(pubkey, ss.str());
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketClient::setPubkeyPromptLambda(
   std::function<bool(const BinaryData&, const std::string&)> lbd)
{
   userPromptLambda_ = lbd;
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketClient::promptUser(
   const BinaryDataRef& keyRef, const string& name)
{
   //is prompt lambda set?
   if (!userPromptLambda_)
   {
      serverPubkeyProm_->set_value(false);
      return;
   }

   BinaryData key_copy(keyRef);

   //create lambda to handle user prompt
   auto promptLbd = [this, key_copy, name](void)->void
   {
      if (this->userPromptLambda_(key_copy, name))
      {
         //the lambda returns true, the user accepted the key, add it to peers
         std::vector<std::string> nameVec;
         nameVec.push_back(name);
         this->authPeers_->addPeer(key_copy, nameVec);
         serverPubkeyProm_->set_value(true);
      }
      else
      {
         //otherwise, we still have to set the promise so that the auth 
         //challenge leg can progress
         serverPubkeyProm_->set_value(false);
      }
   };

   //run prompt in new thread
   thread thr(promptLbd);
   if (thr.joinable())
      thr.detach();
}

///////////////////////////////////////////////////////////////////////////////
//
// WSClientWriteQueue
//
///////////////////////////////////////////////////////////////////////////////
void WSClientWriteQueue::push_back(SerializedMessage& msg)
{
   writeQueue_.push_back(move(msg));
   lws_cancel_service(contextPtr_);
}

///////////////////////////////////////////////////////////////////////////////
SerializedMessage WSClientWriteQueue::pop_front()
{
   return move(writeQueue_.pop_front());
}

///////////////////////////////////////////////////////////////////////////////
bool WSClientWriteQueue::empty() const
{
   return writeQueue_.count() == 0;
}