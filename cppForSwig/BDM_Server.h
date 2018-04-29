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
#include "DataObject.h"
#include "BDM_seder.h"
#include "EncryptionUtils.h"
#include "LedgerEntry.h"
#include "DbHeader.h"
#include "BDV_Notification.h"
#include "ZeroConf.h"
#include "Server.h"

#define MAX_CONTENT_LENGTH 1024*1024*1024
#define CALLBACK_EXPIRE_COUNT 5

enum WalletType
{
   TypeWallet,
   TypeLockbox
};

///////////////////////////////////////////////////////////////////////////////
class SocketCallback : public Callback
{  
protected:
   Arguments respond_inner(vector<Callback::OrderStruct>& orderVec);

public:
   SocketCallback()
   {}

   ~SocketCallback(void) = 0;
   virtual void resetCounter(void) {}
   virtual Arguments respond(const string&) = 0;
};

///////////////////////////////////////////////////////////////////////////////
class LongPoll : public SocketCallback
{
private:
   mutex mu_;
   atomic<unsigned> count_;

   function<unsigned(void)> isReady_;

public:
   LongPoll(function<unsigned(void)> isReady) :
      SocketCallback(), isReady_(isReady)
   {
      count_.store(0, memory_order_relaxed);
   }

   Arguments respond(const string&);

   ~LongPoll(void)
   {
      Callback::shutdown();

      //after signaling shutdown, grab the mutex to make sure 
      //all responders threads have terminated
      unique_lock<mutex> lock(mu_);
   }

   void resetCounter(void)
   {
      count_.store(0, memory_order_relaxed);
   }

   bool isValid(void)
   {
      unique_lock<mutex> lock(mu_, defer_lock);

      if (lock.try_lock())
      {
         auto count = count_.fetch_add(1, memory_order_relaxed) + 1;
         if (count >= CALLBACK_EXPIRE_COUNT)
            return false;
      }

      return true;
   }
};

///////////////////////////////////////////////////////////////////////////////
class WS_Callback : public SocketCallback
{
private:
   const BinaryData bdvID_;

public:
   WS_Callback(const BinaryData& bdvid) :
      bdvID_(bdvid)
   {}

   Arguments respond(const string&) { return Arguments(); }
   void callback(Arguments&& arg, OrderType type);
};

///////////////////////////////////////////////////////////////////////////////
class BDV_Server_Object : public BlockDataViewer
{
   friend class Clients;

private:
   map<string, function<Arguments(
      const vector<string>&, Arguments&)>> methodMap_;
   
   thread initT_;
   unique_ptr<SocketCallback> cb_;

   string bdvID_;
   BlockDataManagerThread* bdmT_;

   map<string, LedgerDelegate> delegateMap_;

   struct walletRegStruct
   {
      vector<BinaryData> scrAddrVec;
      string IDstr;
      bool isNew;
      WalletType type_;
   };

   mutex registerWalletMutex_;
   map<string, walletRegStruct> wltRegMap_;

   shared_ptr<promise<bool>> isReadyPromise_;
   shared_future<bool> isReadyFuture_;

private:
   BDV_Server_Object(BDV_Server_Object&) = delete; //no copies
      
   void buildMethodMap(void);
   void startThreads(void);

   bool registerWallet(
      vector<BinaryData> const& scrAddrVec, string IDstr, bool wltIsNew);
   bool registerLockbox(
      vector<BinaryData> const& scrAddrVec, string IDstr, bool wltIsNew);
   void registerAddrVec(const string&, vector<BinaryData> const& scrAddrVec);

   void resetCounter(void) const
   {
      if (cb_ != nullptr)
         cb_->resetCounter();
   }

   void setup(void);

public:
   BDV_Server_Object(const string& id, BlockDataManagerThread *bdmT);

   ~BDV_Server_Object(void) 
   { 
      haltThreads(); 
   }

   const string& getID(void) const { return bdvID_; }
   void pushNotification(shared_ptr<BDV_Notification>);
   void init(void);

   Arguments executeCommand(const string& method, 
                              const vector<string>& ids, 
                              Arguments& args);
  
   void haltThreads(void);
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
   mutable BlockingStack<bool> gcCommands_;
   BlockDataManagerThread* bdmT_ = nullptr;

   function<void(void)> shutdownCallback_;

   atomic<bool> run_;

   vector<thread> controlThreads_;

   mutable BlockingStack<shared_ptr<BDV_Notification>> outerBDVNotifStack_;
   BlockingStack<shared_ptr<BDV_Notification_Packet>> innerBDVNotifStack_;

private:
   void commandThread(void) const;
   void garbageCollectorThread(void);
   void unregisterAllBDVs(void);
   void bdvMaintenanceLoop(void);
   void bdvMaintenanceThread(void);

public:

   Clients(void)
   {
      shutdownCallback_ = []() {};
   }

   Clients(BlockDataManagerThread* bdmT,
      function<void(void)> shutdownLambda)
   {
      init(bdmT, shutdownLambda);
   }

   void init(BlockDataManagerThread* bdmT,
      function<void(void)> shutdownLambda);

   const shared_ptr<BDV_Server_Object>& get(const string& id) const;
   
   Arguments runCommand_FCGI(const string& cmd);
   Arguments runCommand_WS(const BinaryData& bdvid, const string& cmdStr);


   Arguments processShutdownCommand(Command&);
   Arguments registerBDV(Command& cmd, string bdvID);
   void unregisterBDV(const string& bdvId);
   void shutdown(void);
   void exitRequestLoop(void);
};

#endif
