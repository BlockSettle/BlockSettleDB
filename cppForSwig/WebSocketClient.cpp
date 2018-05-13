////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "WebSocketClient.h"
#include "SwigClient.h"

TransactionalMap<struct lws*, shared_ptr<WebSocketClient>> 
   WebSocketClient::objectMap_;

////////////////////////////////////////////////////////////////////////////////
static struct lws_protocols protocols[] = {
   /* first protocol must always be HTTP handler */

   {
      "armory-bdm-protocol",
      WebSocketClient::callback,
      sizeof(struct per_session_data__client),
      per_session_data__client::rcv_size,
   },

{ NULL, NULL, 0, 0 } /* terminator */
};

////////////////////////////////////////////////////////////////////////////////
string WebSocketClient::writeAndRead(const string& packet, SOCKET sock)
{
   //create response object
   auto response = make_shared<WriteAndReadPacket>();
   response->data_ = move(WebSocketMessage::serialize(response->id_, packet));
   auto fut = response->prom_.get_future();

   //push object to queue and map
   readPackets_.insert(make_pair(response->id_, response));   
   writeQueue_.push_back(move(response));

   //trigger write callback
   lws_callback_on_writable(wsiPtr_);

   //wait on future and return
   auto&& val = fut.get();
   return val;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WebSocketClient> WebSocketClient::getNew(
   const string& addr, const string& port)
{
   WebSocketClient* objPtr = new WebSocketClient(addr, port);
   shared_ptr<WebSocketClient> newObject;
   newObject.reset(objPtr);
   
   objectMap_.insert(move(make_pair(newObject->wsiPtr_, newObject)));
   return newObject;
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::init(const string& ip, const string& port,
   unique_ptr<promise<bool>> promPtr)
{
   run_.store(1, memory_order_relaxed);

   //setup context
   struct lws_context_creation_info info;
   memset(&info, 0, sizeof info);
   
   info.port = CONTEXT_PORT_NO_LISTEN;
   info.protocols = protocols;
   info.ws_ping_pong_interval = 0;
   info.gid = -1;
   info.uid = -1;

   contextPtr_ = lws_create_context(&info);
   if (contextPtr_ == NULL) 
      throw LWS_Error("failed to create LWS context");

   //connect to server
   struct lws_client_connect_info i;
   memset(&i, 0, sizeof(i));
   
   //i.address = ip.c_str();
   i.port = WEBSOCKET_PORT;
   const char *prot, *p;
   char path[300];
   lws_parse_uri((char*)ip.c_str(), &prot, &i.address, &i.port, &p);

   path[0] = '/';
   lws_strncpy(path + 1, p, sizeof(path) - 1);
   i.path = path;
   i.host = i.address;
   i.origin = i.address;

   i.context = contextPtr_;
   i.method = "HTTP";
   i.protocol = protocols[PROTOCOL_ARMORY_CLIENT].name;   
   i.pwsi = &wsiPtr_;
   wsiPtr_ = lws_client_connect_via_info(&i);   
   
   //start service threads
   auto readLBD = [this](void)->void
   {
      this->readService();
   };

   readThr_ = thread(readLBD);

   promPtr->set_value(true);
   service();
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::service()
{
   while(run_.load(memory_order_relaxed) != 0)
   {
      lws_service(contextPtr_, 100);
   }
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::shutdown()
{
   run_.store(0, memory_order_relaxed);
   if(serviceThr_.joinable())
      serviceThr_.join();

   lws_context_destroy(contextPtr_);
   contextPtr_ = nullptr;

   readQueue_.terminate();
   if(readThr_.joinable())
      readThr_.join();
}

////////////////////////////////////////////////////////////////////////////////
int WebSocketClient::callback(struct lws *wsi, 
   enum lws_callback_reasons reason, void *user, void *in, size_t len)
{
   struct per_session_data__client *session_data =
      (struct per_session_data__client *)user;

   switch (reason)
   {

   case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
   {
      printf("client connect fail");
      break;
   }

   case LWS_CALLBACK_CLOSED:
   {
      //WebSocketClient::eraseInstance(wsi);
      break;
   }

   case LWS_CALLBACK_RECEIVE:
   {
      BinaryData bdData;
      bdData.resize(len);
      memcpy(bdData.getPtr(), in, len);

      auto instance = WebSocketClient::getInstance(wsi);
      instance->readQueue_.push_back(move(bdData));
      break;
   }

   case LWS_CALLBACK_SERVER_WRITEABLE:
   {
      auto instance = WebSocketClient::getInstance(wsi);

      shared_ptr<WriteAndReadPacket> packet;
      try
      {
         packet = move(instance->writeQueue_.pop_front());
      }
      catch (IsEmpty&)
      {
         break;
      }

      auto body = packet->data_.getPtr() + LWS_PRE;
      auto m = lws_write(wsi, 
         body, packet->data_.getSize(),
         LWS_WRITE_BINARY);

      if (m != packet->data_.getSize())
      {
         LOGERR << "failed to send packet of size";
         LOGERR << "packet is " << packet->data_.getSize() <<
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

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::readService()
{
   while(1)
   {
      BinaryData packet;
      try
      {
         packet = move(readQueue_.pop_front());
      }
      catch(StopBlockingLoop&)
      {
         break;
      }
  
      //deser packet
      string message;
      auto msgid = WebSocketMessage::deserialize(packet, message);    

      //figure out request id, fulfill promise
      auto readMap = readPackets_.get();
      auto iter = readMap->find(msgid);
      if(iter != readMap->end())
      {
         iter->second->prom_.set_value(move(message));
         readPackets_.erase(msgid);
      }
      else
      {
         //or is it a callback command? process it locally
         Arguments argObj(move(message));
         if(pythonCallbackPtr_ != nullptr)
            pythonCallbackPtr_->processArguments(argObj);
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WebSocketClient> WebSocketClient::getInstance(struct lws* ptr)
{
   auto clientMap = objectMap_.get();
   auto iter = clientMap->find(ptr);
 
   if (iter == clientMap->end())
      throw LWS_Error("no client object for this lws instance");

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
void WebSocketClient::eraseInstance(struct lws* ptr)
{
   objectMap_.erase(ptr);
}
