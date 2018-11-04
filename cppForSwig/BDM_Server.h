////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _BDM_SERVER_H
#define _BDM_SERVER_H

#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <future>

#include "BitcoinP2p.h"
#include "BlockDataViewer.h"
#include "EncryptionUtils.h"
#include "LedgerEntry.h"
#include "DbHeader.h"
#include "BDV_Notification.h"
#include "BDVCodec.h"
#include "ZeroConf.h"
#include "Server.h"
#include "BtcWallet.h"

#define MAX_CONTENT_LENGTH 1024*1024*1024
#define CALLBACK_EXPIRE_COUNT 5

enum WalletType
{
   TypeWallet,
   TypeLockbox
};

class BDV_Server_Object;

namespace DBTestUtils
{
   tuple<shared_ptr<::Codec_BDVCommand::BDVCallback>, unsigned> waitOnSignal(
      Clients*, const string&, ::Codec_BDVCommand::NotificationType);
}

///////////////////////////////////////////////////////////////////////////////
struct BDV_Payload
{
   shared_ptr<BDV_packet> packet_;
   shared_ptr<BDV_Server_Object> bdvPtr_;
   uint32_t messageID_;
   size_t packetID_;
};

///////////////////////////////////////////////////////////////////////////////
struct BDV_PartialMessage
{
   vector<shared_ptr<BDV_Payload>> payloads_;
   WebSocketMessagePartial partialMessage_;

   bool parsePacket(shared_ptr<BDV_Payload>);
   bool isReady(void) const { return partialMessage_.isReady(); }
   bool getMessage(shared_ptr<::google::protobuf::Message>);
   void reset(void);
   size_t topId(void) const;
};

///////////////////////////////////////////////////////////////////////////////
class Callback
{
public:

   virtual ~Callback() = 0;

   virtual void callback(shared_ptr<::Codec_BDVCommand::BDVCallback>) = 0;
   virtual bool isValid(void) = 0;
   virtual void shutdown(void) = 0;
};

///////////////////////////////////////////////////////////////////////////////
class WS_Callback : public Callback
{
private:
   const uint64_t bdvID_;

public:
   WS_Callback(const uint64_t& bdvid) :
      bdvID_(bdvid)
   {}

   void callback(shared_ptr<::Codec_BDVCommand::BDVCallback>);
   bool isValid(void) { return true; }
   void shutdown(void) {}
};

///////////////////////////////////////////////////////////////////////////////
class UnitTest_Callback : public Callback
{
private:
   BlockingQueue<shared_ptr<::Codec_BDVCommand::BDVCallback>> notifQueue_;

public:
   void callback(shared_ptr<::Codec_BDVCommand::BDVCallback>);
   bool isValid(void) { return true; }
   void shutdown(void) {}

   shared_ptr<::Codec_BDVCommand::BDVCallback> getNotification(void);
};

///////////////////////////////////////////////////////////////////////////////
class BDV_Server_Object : public BlockDataViewer
{
   friend class Clients;
   friend tuple<shared_ptr<::Codec_BDVCommand::BDVCallback>, unsigned> 
      DBTestUtils::waitOnSignal(
      Clients*, const string&, ::Codec_BDVCommand::NotificationType);

private: 
   thread initT_;
   unique_ptr<Callback> cb_;

   string bdvID_;
   BlockDataManagerThread* bdmT_;

   map<string, LedgerDelegate> delegateMap_;

   struct walletRegStruct
   {
      shared_ptr<::Codec_BDVCommand::BDVCommand> command_;
      WalletType type_;
   };

   mutex registerWalletMutex_;
   map<string, walletRegStruct> wltRegMap_;

   shared_ptr<promise<bool>> isReadyPromise_;
   shared_future<bool> isReadyFuture_;

   function<void(unique_ptr<BDV_Notification>)> notifLambda_;
   atomic<unsigned> packetProcess_threadLock_;
   atomic<unsigned> notificationProcess_threadLock_;

   map<size_t, shared_ptr<BDV_Payload>> packetMap_;
   BDV_PartialMessage currentMessage_;
   atomic<size_t> nextPacketId_ = {0};
   shared_ptr<BDV_Payload> packetToReinject_ = nullptr;

private:
   BDV_Server_Object(BDV_Server_Object&) = delete; //no copies
      
   shared_ptr<::google::protobuf::Message> processCommand(
      shared_ptr<::Codec_BDVCommand::BDVCommand>);
   void startThreads(void);

   void registerWallet(shared_ptr<::Codec_BDVCommand::BDVCommand>);
   void registerLockbox(shared_ptr<::Codec_BDVCommand::BDVCommand>);
   void populateWallets(map<string, walletRegStruct>&);
   void setup(void);

   void flagRefresh(
      BDV_refresh refresh, const BinaryData& refreshId,
      unique_ptr<BDV_Notification_ZC> zcPtr);
   void resetCurrentMessage(void);

public:
   BDV_Server_Object(const string& id, BlockDataManagerThread *bdmT);

   ~BDV_Server_Object(void) 
   { 
      haltThreads(); 
   }

   const string& getID(void) const { return bdvID_; }
   void processNotification(shared_ptr<BDV_Notification>);
   void init(void);
   void haltThreads(void);
   bool processPayload(shared_ptr<BDV_Payload>&, 
      shared_ptr<::google::protobuf::Message>&);

   size_t getNextPacketId(void) { return nextPacketId_.fetch_add(1, memory_order_relaxed); }
};

class Clients;

///////////////////////////////////////////////////////////////////////////////
class ZeroConfCallbacks_BDV : public ZeroConfCallbacks
{
private:
   Clients * clientsPtr_;

public:
   ZeroConfCallbacks_BDV(Clients* clientsPtr) :
      clientsPtr_(clientsPtr)
   {}

   set<string> hasScrAddr(const BinaryDataRef&) const;
   void pushZcNotification(ZeroConfContainer::NotificationPacket& packet);
   void errorCallback(
      const string& bdvId, string& errorStr, const string& txHash);
};

///////////////////////////////////////////////////////////////////////////////
class Clients
{
   friend class ZeroConfCallbacks_BDV;

private:
   TransactionalMap<string, shared_ptr<BDV_Server_Object>> BDVs_;
   mutable BlockingQueue<bool> gcCommands_;
   BlockDataManagerThread* bdmT_ = nullptr;

   function<void(void)> shutdownCallback_;

   atomic<bool> run_;

   vector<thread> controlThreads_;

   mutable BlockingQueue<shared_ptr<BDV_Notification>> outerBDVNotifStack_;
   BlockingQueue<shared_ptr<BDV_Notification_Packet>> innerBDVNotifStack_;
   BlockingQueue<shared_ptr<BDV_Payload>> packetQueue_;

   mutex shutdownMutex_;

private:
   void notificationThread(void) const;
   void unregisterAllBDVs(void);
   void bdvMaintenanceLoop(void);
   void bdvMaintenanceThread(void);
   void messageParserThread(void);

public:

   Clients(void)
   {}

   Clients(BlockDataManagerThread* bdmT,
      function<void(void)> shutdownLambda)
   {
      init(bdmT, shutdownLambda);
   }

   void init(BlockDataManagerThread* bdmT,
      function<void(void)> shutdownLambda);

   shared_ptr<BDV_Server_Object> get(const string& id) const;
   
   void processShutdownCommand(
      shared_ptr<::Codec_BDVCommand::StaticCommand>);
   shared_ptr<::google::protobuf::Message> registerBDV(
      shared_ptr<::Codec_BDVCommand::StaticCommand>, string bdvID);
   void unregisterBDV(const string& bdvId);
   void shutdown(void);
   void exitRequestLoop(void);
   
   void queuePayload(shared_ptr<BDV_Payload>& payload)
   {  
      packetQueue_.push_back(move(payload));
   }

   shared_ptr<::google::protobuf::Message> processUnregisteredCommand(
      const uint64_t& bdvId, shared_ptr<::Codec_BDVCommand::StaticCommand>);
   shared_ptr<::google::protobuf::Message> processCommand(
      shared_ptr<BDV_Payload>);
};

#endif
