////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-18, goatpig.                                           //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////


#include "Server.h"
#include "BlockDataManagerConfig.h"
#include "BDM_Server.h"

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//// FCGI_Server
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
FCGI_Server::FCGI_Server(
   BlockDataManagerThread* bdmT, string port, bool listen_all) :
   ip_(listen_all ? "" : "127.0.0.1"), port_(port)
{
   clients_ = make_unique<Clients>(bdmT, getShutdownCallback());

   LOGINFO << "Listening on port " << port;
   if (listen_all)
      LOGWARN << "Listening to all incoming connections";

   liveThreads_.store(0, memory_order_relaxed);
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::init()
{
   run_.store(true, memory_order_relaxed);

   stringstream ss;
#ifdef _WIN32
   if (ip_ == "127.0.0.1" || ip_ == "localhost")
      ss << "localhost:" << port_;
   else
      ss << ip_ << ":" << port_;
#else
   ss << ip_ << ":" << port_;
#endif

   auto socketStr = ss.str();
   sockfd_ = FCGX_OpenSocket(socketStr.c_str(), 10);
   if (sockfd_ == -1)
      throw runtime_error("failed to create FCGI listen socket");

   keepAliveService_.startService();
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::checkSocket() const
{
   SimpleSocket testSock(ip_, port_);
   if (testSock.testConnection())
   {
      LOGERR << "There is already a process listening on "
         << ip_ << ":" << port_;
      LOGERR << "ArmoryDB cannot start under these conditions. Shutting down!";
      LOGERR << "Make sure to shutdown the conflicting process" <<
         "before trying again (most likely another ArmoryDB instance).";

      exit(1);
   }
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::haltFcgiLoop()
{
   /*** to exit the FCGI loop we need to shutdown the FCGI lib as a whole
   (otherwise accept will keep on blocking until a new fcgi request is
   received. Shutting down the lib calls WSACleanUp in Windows, which will
   terminate all networking capacity for the process.

   This means the node P2P connection will crash if it isn't cleaned up first.
   ***/

   //shutdown loop
   run_.store(false, memory_order_relaxed);

   //connect to own listen to trigger thread exit
   SimpleSocket sock("127.0.0.1", port_);
   if(!sock.connectToRemote())
      return;

   auto&& fcgiMsg = FcgiMessage::makePacket(vector<uint8_t>());
   auto serdata = fcgiMsg.serialize();

   Socket_WritePayload payload;
   payload.data_ = move(serdata);
   sock.pushPayload(payload, nullptr);
   sock.shutdown();
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::enterLoop()
{
   while (run_.load(memory_order_relaxed))
   {
      auto request = make_shared<FCGX_Request>();
      FCGX_InitRequest(request.get(), sockfd_, 0);
      int rc = FCGX_Accept_r(request.get());

      if (rc != 0)
      {
#ifdef _WIN32
         auto err_i = WSAGetLastError();
#else
         auto err_i = errno;
#endif
         LOGERR << "Accept failed with error number: " << err_i;
         LOGERR << "error message is: " << strerror(err_i);
         throw runtime_error("accept error");
      }

      auto processRequestLambda = [this](shared_ptr<FCGX_Request> req)->void
      {
         this->processRequest(req);
      };

      liveThreads_.fetch_add(1, memory_order_relaxed);
      thread thr(processRequestLambda, request);
      if (thr.joinable())
         thr.detach();

      //TODO: implement thread recycling
   }
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::processRequest(shared_ptr<FCGX_Request> req)
{
   //extract the string command from the fgci request
   stringstream ss;
   stringstream retStream;
   char* content = nullptr;

   //pass to clients_
   char* content_length = FCGX_GetParam("CONTENT_LENGTH", req->envp);
   if (content_length != nullptr)
   {
      auto a = atoi(content_length);
      content = new char[a + 1];
      FCGX_GetStr(content, a, req->in);
      content[a] = 0;

      string contentStr(content);

      //print HTML header
      ss << "HTTP/1.1 200 OK\r\n";
      ss << "Content-Type: text/html; charset=UTF-8\r\n";

      try
      {
         auto&& retVal = clients_->runCommand_FCGI(contentStr);
         if(retVal.hasArgs())
            retStream << retVal.serialize();

      }
      catch (exception& e)
      {
         ErrorType err(e.what());
         Arguments arg;
         arg.push_back(move(err));

         retStream << arg.serialize();
      }
      catch (DbErrorMsg &e)
      {
         ErrorType err(e.what());
         Arguments arg;
         arg.push_back(move(err));

         retStream << arg.serialize();
      }
      catch (...)
      {
         ErrorType err("unknown error");
         Arguments arg;
         arg.push_back(move(err));

         retStream << arg.serialize();
      }

      //complete HTML header
      ss << "Content-Length: " << retStream.str().size();
      ss << "\r\n\r\n";
   }
   else
   {
      LOGERR << "empty content_length";
      FCGX_Finish_r(req.get());

      liveThreads_.fetch_sub(1, memory_order_relaxed);
      return;
   }

   delete[] content;

   if (retStream.str().size() > 0)
   {
      //print serialized retVal
      ss << retStream.str();

      auto&& retStr = ss.str();
      vector<pair<size_t, size_t>> msgOffsetVec;
      auto totalsize = retStr.size();
      //8192 (one memory page) - 8 (1 fcgi header), also a multiple of 8
      size_t delim = 8184;
      size_t start = 0;

      while (totalsize > 0)
      {
         auto chunk = delim;
         if (chunk > totalsize)
            chunk = totalsize;

         msgOffsetVec.push_back(make_pair(start, chunk));
         start += chunk;
         totalsize -= chunk;
      }

      //get non const ptr of the message string since we will set temp null bytes
      //for the purpose of breaking down the string into FCGI sized packets
      char* ptr = const_cast<char*>(retStr.c_str());

      //complete FCGI request
      for (auto& offsetPair : msgOffsetVec)
         FCGX_PutStr(ptr + offsetPair.first, offsetPair.second, req->out);
   }

   FCGX_Finish_r(req.get());

   if (req->ipcFd != -1)
   {
      passToKeepAliveService(req);
   }

   liveThreads_.fetch_sub(1, memory_order_relaxed);
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::shutdown()
{
   keepAliveService_.shutdown();
   clients_->shutdown();
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::passToKeepAliveService(shared_ptr<FCGX_Request> req)
{
   auto serviceRead = [this, req](void)->void
   {
      int rc = FCGX_Accept_r(req.get());

      if (rc != 0)
      {
#ifdef _WIN32
         auto err_i = WSAGetLastError();
#else
         auto err_i = errno;
#endif
         LOGERR << "Accept failed with error number: " << err_i;
         LOGERR << "error message is: " << strerror(err_i);
         throw runtime_error("accept error");
      }

      auto processRequestLambda = [this](shared_ptr<FCGX_Request> req)->void
      {
         this->processRequest(req);
      };

      liveThreads_.fetch_add(1, memory_order_relaxed);
      thread thr(processRequestLambda, req);
      if (thr.joinable())
         thr.detach();
   };

   SocketStruct keepAliveStruct;

   keepAliveStruct.serviceRead_ = serviceRead;
   keepAliveStruct.singleUse_ = true;

   SOCKET sockfd = req->ipcFd;
#ifdef _WIN32
   sockfd = Win32GetFDForDescriptor(req->ipcFd);
#endif
   keepAliveStruct.sockfd_ = sockfd;

   keepAliveService_.addSocket(move(keepAliveStruct));
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//// WebSocketServer
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
atomic<WebSocketServer*> WebSocketServer::instance_;
mutex WebSocketServer::mu_;
promise<bool> WebSocketServer::shutdownPromise_;
shared_future<bool> WebSocketServer::shutdownFuture_;

///////////////////////////////////////////////////////////////////////////////
WebSocketServer::WebSocketServer()
{
   Arguments::serializeID(false);
   clients_ = make_unique<Clients>();
}

///////////////////////////////////////////////////////////////////////////////
static struct lws_protocols protocols[] = {
   /* first protocol must always be HTTP handler */

   {
      "http-only",		/* name */
      callback_http,		/* callback */
      sizeof(struct per_session_data__http),	/* per_session_data_size */
      0,			/* max frame size / rx buffer */
   },
   {
      "armory-bdm-protocol",
      WebSocketServer::callback,
      sizeof(struct per_session_data__bdv),
      per_session_data__bdv::rcv_size,
   },

{ NULL, NULL, 0, 0 } /* terminator */
};

///////////////////////////////////////////////////////////////////////////////
int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
   void *user, void *in, size_t len)
{
   return 0;
}

///////////////////////////////////////////////////////////////////////////////
int WebSocketServer::callback(
   struct lws *wsi, enum lws_callback_reasons reason,
   void *user, void *in, size_t len)
{
   struct per_session_data__bdv *session_data =
      (struct per_session_data__bdv *)user;

   switch (reason)
   {

   case LWS_CALLBACK_PROTOCOL_INIT:
   {
      auto instance = WebSocketServer::getInstance();
      instance->setIsReady();
      break;
   }

   case LWS_CALLBACK_ESTABLISHED:
   {
      auto&& bdid = SecureBinaryData().GenerateRandom(8);
      session_data->id_ = *(uint64_t*)bdid.getPtr();

      auto instance = WebSocketServer::getInstance();
      instance->addId(session_data->id_, wsi);
      break;
   }

   case LWS_CALLBACK_CLOSED:
   {
      auto instance = WebSocketServer::getInstance();
      BinaryDataRef bdr((uint8_t*)&session_data->id_, 8);
      instance->clients_->unregisterBDV(bdr.toHexStr());
      instance->eraseId(session_data->id_);

      break;
   }

   case LWS_CALLBACK_RECEIVE:
   {
      auto packetPtr = make_unique<BDV_packet>(session_data->id_, wsi);
      packetPtr->data_.resize(len);
      memcpy(packetPtr->data_.getPtr(), (uint8_t*)in, len);

      auto wsPtr = WebSocketServer::getInstance();
      wsPtr->packetQueue_.push_back(move(packetPtr));
      break;
   }

   case LWS_CALLBACK_SERVER_WRITEABLE:
   {
      auto wsPtr = WebSocketServer::getInstance();
      auto writeMap = wsPtr->getWriteMap();
      auto iter = writeMap->find(session_data->id_);
      if (iter == writeMap->end())
         break;

      BinaryData packet;
      try
      {
         packet = move(iter->second.stack_->pop_front());
      }
      catch (IsEmpty&)
      {
         break;
      }

      auto body = packet.getPtr() + LWS_PRE;

      auto m = lws_write(wsi, 
         body, packet.getSize() - LWS_PRE,
         LWS_WRITE_BINARY);

      if (m != packet.getSize() - LWS_PRE)
      {
         LOGERR << "failed to send packet of size";
         LOGERR << "packet is " << packet.getSize() <<
            " bytes, sent " << m << " bytes";
      }

      /***
      In case several threads are trying to write to the same socket, it's
      possible their calls to callback_on_writeable may overlap, resulting 
      in a single write entry being consumed.

      To avoid this, we trigger the callback from within itself, which will 
      break out if there are no more items in the writeable stack.
      ***/
      lws_callback_on_writable(wsi);

      break;
   }

   default:
      break;

   }

   return 0;
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::start(BlockDataManagerThread* bdmT, bool async)
{
   shutdownFuture_ = shutdownPromise_.get_future();
   auto instance = getInstance();

   //init Clients object
   auto shutdownLbd = [](void)->void
   {
      WebSocketServer::shutdown();
   };

   instance->clients_->init(bdmT, shutdownLbd);

   //start command threads
   auto commandThr = [instance](void)->void
   {
      instance->commandThread();
   };

   unsigned thrCount = 2;
   if (BlockDataManagerConfig::getDbType() == ARMORY_DB_SUPER)
      thrCount = thread::hardware_concurrency();

   for(unsigned i=0; i<thrCount; i++)
      instance->threads_.push_back(thread(commandThr));

   //run service thread
   if (async)
   {
      auto loopthr = [instance](void)->void
      {
         instance->webSocketService();
      };

      auto fut = instance->isReadyProm_.get_future();
      instance->threads_.push_back(thread(loopthr));

      fut.get();
      return;
   }

   instance->webSocketService();
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::shutdown()
{
   unique_lock<mutex> lock(mu_);

   auto ptr = instance_.load(memory_order_relaxed);
   if (ptr == nullptr)
      return;

   auto instance = getInstance();

   instance->run_.store(0, memory_order_relaxed);
   instance->packetQueue_.terminate();

   for (auto& thr : instance->threads_)
   {
      if (thr.joinable())
         thr.join();
   }

   instance->threads_.clear();
   instance->clients_->shutdown();

   instance_.store(nullptr, memory_order_relaxed);
   delete instance;
   shutdownPromise_.set_value(true);
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::setIsReady()
{
   try
   {
      isReadyProm_.set_value(true);
   }
   catch (future_error&)
   {}
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::webSocketService()
{
   struct lws_context_creation_info info;
   struct lws_vhost *vhost;
   const char *iface = nullptr;
   int uid = -1, gid = -1;
   int pp_secs = 0;
   int opts = 0;
   int n = 0;

   memset(&info, 0, sizeof info);
   info.port = WEBSOCKET_PORT;

   info.iface = iface;
   info.protocols = protocols;
   info.log_filepath = nullptr;
   info.ws_ping_pong_interval = pp_secs;
   info.gid = gid;
   info.uid = uid;
   info.max_http_header_pool = 256;
   info.options = opts | LWS_SERVER_OPTION_VALIDATE_UTF8 | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
   info.timeout_secs = 0;
   info.ip_limit_ah = 24; /* for testing */
   info.ip_limit_wsi = 105; /* for testing */

   auto context = lws_create_context(&info);
   if (context == nullptr) 
      throw LWS_Error("failed to create LWS context");

   vhost = lws_create_vhost(context, &info);
   if (vhost == nullptr)
      throw LWS_Error("failed to create vhost");

   run_.store(1, memory_order_relaxed);
   while (run_.load(memory_order_relaxed) != 0 && n >= 0)
   {
      n = lws_service(context, 50);
   }

   LOGINFO << "cleaning up lws server";
   lws_vhost_destroy(vhost);
   lws_context_destroy(context);
}

///////////////////////////////////////////////////////////////////////////////
WebSocketServer* WebSocketServer::getInstance()
{
   while (1)
   {
      auto ptr = instance_.load(memory_order_relaxed);
      if (ptr == nullptr)
      {
         unique_lock<mutex> lock(mu_);
         ptr = instance_.load(memory_order_relaxed);
         if (ptr != nullptr)
            continue;

         ptr = new WebSocketServer();
         instance_.store(ptr, memory_order_relaxed);
      }

      return ptr;
   }
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::commandThread()
{
   while (1)
   {
      unique_ptr<BDV_packet> packetPtr;
      try
      {
         packetPtr = move(packetQueue_.pop_front());
      }
      catch(StopBlockingLoop&)
      {
         //end loop condition
         return;
      }

      if (packetPtr == nullptr)
      {
         LOGWARN << "empty command packet";
         continue;
      }

      //check wsi is valid
      if (packetPtr->wsiPtr_ == nullptr)
      {
         LOGWARN << "null wsi";
         continue;
      }

      try
      {
         shared_ptr<WebSocketMessage> msgPtr = nullptr;
         
         {
            auto packet_id = WebSocketMessage::getMessageId(packetPtr->data_);
            auto read_map = readMap_.get();
            auto iter = read_map->find(packet_id);
            if (iter == read_map->end())
            {
               msgPtr = make_shared<WebSocketMessage>();
            }
            else
            {
               msgPtr = iter->second;
            }
         }

         if (msgPtr == nullptr)
         {
            LOGWARN << "null ws message!";
            continue;
         }

         msgPtr->processPacket(packetPtr->data_);
         string message;
         if (!msgPtr->reconstruct(message))
         {
            //TODO: limit partial messages, d/c client as malvolent if 
            //threshold is met

            //incomplete message, store partial data for later
            auto msg_pair = make_pair(msgPtr->id(), msgPtr);
            readMap_.insert(move(msg_pair));
            continue;
         }

         auto&& result = clients_->runCommand_WS(packetPtr->ID_, message);
         write(packetPtr->ID_, msgPtr->id(), result);

         //clean up
         readMap_.erase(msgPtr->id());

         //TODO: replace readMap with lockless container
      }
      catch (exception&)
      {
         LOGWARN << "failed to process packet";
         continue;
      }
   }
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::write(const uint64_t& id, const uint64_t& msgid,
   Arguments& arg)
{
   if (!arg.hasArgs())
      return;

   auto instance = getInstance();
   
   //serialize arg
   auto& serializedString = arg.serialize();
   auto&& serializedResult =
      WebSocketMessage::serialize(msgid, serializedString);

   //push to write map
   auto writemap = instance->writeMap_.get();

   auto wsi_iter = writemap->find(id);
   if (wsi_iter == writemap->end())
      return;

   for(auto& data : serializedResult)
      wsi_iter->second.stack_->push_back(move(data));

   //call write callback
   lws_callback_on_writable(wsi_iter->second.wsiPtr_);
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::waitOnShutdown()
{
   try
   {
      shutdownFuture_.get();
   }
   catch(future_error&)
   { }
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<map<uint64_t, WriteStack>> WebSocketServer::getWriteMap(void)
{
   return writeMap_.get();
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::addId(const uint64_t& id, struct lws* ptr)
{
   auto&& write_pair = make_pair(id, WriteStack(ptr));
   writeMap_.insert(move(write_pair));
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::eraseId(const uint64_t& id)
{
   writeMap_.erase(id);
}
