////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-18, goatpig.                                           //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _SERVER_H_
#define _SERVER_H_

#include <string.h>
#include <string>
#include <memory>
#include <atomic>
#include <vector>

using namespace std;

#include "./fcgi/include/fcgiapp.h"
#include "./fcgi/include/fcgios.h"
#include "FcgiMessage.h"
#include "libwebsockets.h"

#include "ThreadSafeClasses.h"
#include "BDV_Notification.h"
#include "BinaryData.h"
#include "EncryptionUtils.h"
#include "DataObject.h"

#define WEBSOCKET_PORT 7681


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
struct per_session_data__http {
   lws_fop_fd_t fop_fd;
};

struct per_session_data__bdv {
   static const unsigned rcv_size = 8000;
   BinaryData id_;
};

enum demo_protocols {
   /* always first */
   PROTOCOL_HTTP = 0,

   PROTOCOL_ARMORY_BDM,

   /* always last */
   DEMO_PROTOCOL_COUNT
};

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
   void *in, size_t len);

class LWS_Error : public runtime_error
{
public:
   LWS_Error(const string& err) :
      runtime_error(err)
   {}
};

struct BDV_packet
{
   BinaryData ID_;
   string data_;
   struct lws *wsiPtr_;

   BDV_packet(const BinaryData& id, struct lws *wsi) :
      ID_(id), wsiPtr_(wsi)
   {}
};

///////////////////////////////////////////////////////////////////////////////
struct WriteStack
{
   struct lws *wsiPtr_ = nullptr;
   shared_ptr<Stack<BinaryData>> stack_;

   WriteStack(struct lws *wsi) :
      wsiPtr_(wsi)
   {
      stack_ = make_shared<Stack<BinaryData>>();
   }
};

///////////////////////////////////////////////////////////////////////////////
class WebSocketServer
{
private:
   vector<thread> threads_;
   BlockingStack<unique_ptr<BDV_packet>> packetQueue_;
   TransactionalMap<BinaryData, WriteStack> writeMap_;

   static atomic<WebSocketServer*> instance_;
   static mutex mu_;
   
   unique_ptr<Clients> clients_;
   atomic<unsigned> run_;

private:
   void webSocketService(void);
   void commandThread(void);

public:
   WebSocketServer(void);

   static int callback(
      struct lws *wsi, enum lws_callback_reasons reason, 
      void *user, void *in, size_t len);

   static WebSocketServer* getInstance(void);

   void start(BlockDataManagerThread* bdmT, bool async);
   void shutdown(void);
   
   shared_ptr<map<BinaryData, WriteStack>> getWriteMap(void);
   void addId(const BinaryData&, struct lws* ptr);
   void eraseId(const BinaryData&);
   void write(const BinaryData&, Arguments&);
};

#endif
