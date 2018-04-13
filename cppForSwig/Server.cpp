////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-18, goatpig.                                           //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////


#include "Server.h"
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
         auto&& retVal = clients_->runCommand(contentStr);
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
