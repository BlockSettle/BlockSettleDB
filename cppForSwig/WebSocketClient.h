////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef WEBSOCKET_CLIENT_H
#define WEBSOCKET_CLIENT_H

#include <atomic>
#include <future>
#include <string>
#include <thread>

#include "libwebsockets.h"
#include "ThreadSafeClasses.h"
#include "BinaryData.h"
#include "DataObject.h"
#include "SocketObject.h"
#include "WebSocketMessage.h"
#include "BlockDataManagerConfig.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
struct WriteAndReadPacket
{
   uint64_t id_;
   promise<string> prom_;

   WriteAndReadPacket(void)
   {
      //create random_id
      id_ = rand();
   }

   ~WriteAndReadPacket(void)
   {
      try
      {
         prom_.set_value(string());
      }
      catch (future_error&)
      {}
   }
};

////////////////////////////////////////////////////////////////////////////////
enum client_protocols {
   PROTOCOL_ARMORY_CLIENT,

   /* always last */
   CLIENT_PROTOCOL_COUNT
};

struct per_session_data__client {
   static const unsigned rcv_size = 8000;
};

namespace SwigClient
{
   class PythonCallback;
}

////////////////////////////////////////////////////////////////////////////////
class WebSocketClient : public BinarySocket
{
private:
   atomic<void*> wsiPtr_ = nullptr;
   atomic<void*> contextPtr_ = nullptr;
   unique_ptr<promise<bool>> ctorProm_ = nullptr;

   Stack<BinaryData> writeQueue_;
   BlockingStack<BinaryData> readQueue_;
   atomic<unsigned> run_;
   thread serviceThr_, readThr_;
   TransactionalMap<uint64_t, shared_ptr<WriteAndReadPacket>> readPackets_;
   SwigClient::PythonCallback* pythonCallbackPtr_ = nullptr;
   
   static TransactionalMap<struct lws*, shared_ptr<WebSocketClient>> objectMap_; 

private:

   WebSocketClient(const string& addr, const string& port) :
      BinarySocket(addr, port, false)
   {
      init();
   }

   void init();
   void setIsReady(bool);
   void readService(void);
   void service(void);
   void connect(void);


public:
   ~WebSocketClient()
   {
      shutdown();
   }

   //locals
   void shutdown(void);   
   void setPythonCallback(SwigClient::PythonCallback*);

   //virtuals
   SocketType type(void) const { return SocketWS; }
   string writeAndRead(const string&, SOCKET sock = SOCK_MAX);

   //statics
   static shared_ptr<WebSocketClient> getNew(
      const string& addr, const string& port);

   static int callback(
      struct lws *wsi, enum lws_callback_reasons reason, 
      void *user, void *in, size_t len);

   static shared_ptr<WebSocketClient> getInstance(struct lws* ptr);
   static void eraseInstance(struct lws* ptr);
};

#endif
