////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-18, goatpig.                                           //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _SERVER_H_
#define _SERVER_H_

#include <string>
#include <memory>
#include <atomic>
#include <vector>

using namespace std;

#include "ThreadSafeClasses.h"
#include "BDV_Notification.h"

#include "./fcgi/include/fcgiapp.h"
#include "./fcgi/include/fcgios.h"
#include "FcgiMessage.h"

class Clients;
class BlockDataManagerThread;

///////////////////////////////////////////////////////////////////////////////
class FCGI_Server
{
   /***
   Figure if it should use a socket or a named pipe.
   Force it to listen only to localhost if we use a socket
   (both in *nix and win32 code files)
   ***/

private:
   SOCKET sockfd_ = -1;
   mutex mu_;
   int run_ = true;
   atomic<uint32_t> liveThreads_;

   const string port_;
   const string ip_;

   unique_ptr<Clients> clients_;

private:
   function<void(void)> getShutdownCallback(void)
   {
      auto shutdownCallback = [this](void)->void
      {
         this->haltFcgiLoop();
      };

      return shutdownCallback;
   }

public:
   FCGI_Server(BlockDataManagerThread* bdmT, string port, bool listen_all);

   void init(void);
   void enterLoop(void);
   void processRequest(FCGX_Request* req);
   void haltFcgiLoop(void);
   void shutdown(void);
   void checkSocket(void) const;
};

///////////////////////////////////////////////////////////////////////////////
class WebSocketServer
{
private:
   const string port_;
   thread maintenanceThr_;

public:
   WebSocketServer(string port)
   {}

   static int callback();
   void setup(void);
   void maintenanceLoop(void);
};

#endif