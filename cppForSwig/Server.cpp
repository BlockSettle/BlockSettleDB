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
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::checkSocket() const
{
   BinarySocket testSock(ip_, port_);
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
   run_ = 0;

   //spin lock until all requests are closed
   while (liveThreads_.load(memory_order_relaxed) != 0);

   //connect to own listen to trigger thread exit
   BinarySocket sock("127.0.0.1", port_);
   auto sockfd = sock.openSocket(false);
   if (sockfd == SOCK_MAX)
      return;

   auto&& fcgiMsg = FcgiMessage::makePacket("");
   auto serdata = fcgiMsg.serialize();
   auto serdatalength = fcgiMsg.getSerializedDataLength();

   sock.writeToSocket(sockfd, serdata, serdatalength);
   sock.closeSocket(sockfd);
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::enterLoop()
{
   while (run_)
   {
      FCGX_Request* request = new FCGX_Request;
      FCGX_InitRequest(request, sockfd_, 0);
      int rc = FCGX_Accept_r(request);

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

      auto processRequestLambda = [this](FCGX_Request* req)->void
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
void FCGI_Server::processRequest(FCGX_Request* req)
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
      FCGX_Finish_r(req);
      delete req;

      liveThreads_.fetch_sub(1, memory_order_relaxed);
      return;
   }

   delete[] content;

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

   FCGX_Finish_r(req);

   delete req;

   liveThreads_.fetch_sub(1, memory_order_relaxed);
}

///////////////////////////////////////////////////////////////////////////////
void FCGI_Server::shutdown()
{
   clients_->shutdown();
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//// WebSocketServer
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

atomic<WebSocketServer*> WebSocketServer::instance_;
mutex WebSocketServer::mu_;

///////////////////////////////////////////////////////////////////////////////
WebSocketServer::WebSocketServer()
{
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
      break;
   }

   case LWS_CALLBACK_ESTABLISHED:
   {
      session_data->id_ =
         SecureBinaryData().GenerateRandom(10).toHexStr();

      auto instance = WebSocketServer::getInstance();
      instance->addId(session_data->id_, wsi);
      break;
   }

   case LWS_CALLBACK_CLOSED:
   {
      auto instance = WebSocketServer::getInstance();
      instance->clients_->unregisterBDV(session_data->id_.toHexStr());
      instance->eraseId(session_data->id_);

      break;
   }

   case LWS_CALLBACK_RECEIVE:
   {
      auto packetPtr = make_unique<BDV_packet>(session_data->id_, wsi);
      packetPtr->data_ = move(string((char*)in, len));

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

      char response[per_session_data__bdv::rcv_size + LWS_PRE];
      auto body = packet.getPtr() + LWS_PRE;

      auto m = lws_write(wsi, 
         body, packet.getSize(),
         LWS_WRITE_BINARY);

      if (m != packet.getSize())
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

   }

   return 0;
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::start(BlockDataManagerThread* bdmT, bool async)
{
   //init Clients object
   auto shutdownLbd = [this](void)->void
   {
      this->shutdown();
   };

   clients_->init(bdmT, shutdownLbd);

   //start command threads
   auto commandThr = [this](void)->void
   {
      this->commandThread();
   };

   unsigned thrCount = 2;
   if (BlockDataManagerConfig::getDbType() == ARMORY_DB_SUPER)
      thrCount = thread::hardware_concurrency();

   for(unsigned i=0; i<thrCount; i++)
      threads_.push_back(thread(commandThr));

   //run service thread
   if (async)
   {
      auto loopthr = [this](void)->void
      {
         this->webSocketService();
      };

      threads_.push_back(thread(loopthr));
      return;
   }

   webSocketService();
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::shutdown()
{
   run_.store(0, memory_order_relaxed);
   packetQueue_.terminate();

   for (auto& thr : threads_)
   {
      if (thr.joinable())
         thr.join();
   }
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::webSocketService()
{
   struct lws_context_creation_info info;
   struct lws_vhost *vhost;
   const char *iface = NULL;
   int uid = -1, gid = -1;
   int pp_secs = 0;
   int opts = 0;
   int n = 0;

   memset(&info, 0, sizeof info);
   info.port = WEBSOCKET_PORT;

   info.iface = iface;
   info.protocols = protocols;
   info.ssl_cert_filepath = NULL;
   info.ssl_private_key_filepath = NULL;
   info.ws_ping_pong_interval = pp_secs;
   info.gid = gid;
   info.uid = uid;
   info.max_http_header_pool = 256;
   info.options = opts | LWS_SERVER_OPTION_VALIDATE_UTF8 | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
   info.extensions = NULL;
   info.timeout_secs = 5;
   info.ssl_cipher_list = NULL;
   info.ip_limit_ah = 24; /* for testing */
   info.ip_limit_wsi = 105; /* for testing */

   auto context = lws_create_context(&info);
   if (context == NULL) 
      throw LWS_Error("failed to create LWS context");

   vhost = lws_create_vhost(context, &info);
   if (!vhost)
      throw LWS_Error("failed to create vhost");

   run_.store(1, memory_order_relaxed);
   while (run_.load(memory_order_relaxed) != 0)
   {
      n = lws_service(context, 50);
   }
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
         auto&& result = clients_->runCommand_WS(packetPtr->ID_, packetPtr->data_);
         write(packetPtr->ID_, result);
      }
      catch (exception&)
      {
         LOGWARN << "failed to process packet";
         continue;
      }
   }
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::write(const BinaryData& id, Arguments& arg)
{
   if (arg.hasArgs())
   {
      //serialize arg
      auto&& serializedResult = arg.serialize_ws();

      //push to write map
      auto writemap = writeMap_.get();

      auto wsi_iter = writemap->find(id);
      if (wsi_iter == writemap->end())
         return;

      wsi_iter->second.stack_->push_back(move(serializedResult));

      //call write callback
      lws_callback_on_writable(wsi_iter->second.wsiPtr_);
   }
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<map<BinaryData, WriteStack>> WebSocketServer::getWriteMap(void)
{
   return writeMap_.get();
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::addId(const BinaryData& id, struct lws* ptr)
{
   auto&& write_pair = make_pair(id, WriteStack(ptr));
   writeMap_.insert(move(write_pair));
}

///////////////////////////////////////////////////////////////////////////////
void WebSocketServer::eraseId(const BinaryData& id)
{
   writeMap_.erase(id);
}
