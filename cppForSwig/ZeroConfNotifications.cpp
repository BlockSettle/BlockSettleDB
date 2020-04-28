////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020, goatpig                                               //            
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                   
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <list>

#include "ZeroConfNotifications.h"
#include "ZeroConf.h"
#include "BDM_Server.h"
#include "LedgerEntry.h"
#include "txio.h"

using namespace std;
using namespace ::Codec_BDVCommand;

///////////////////////////////////////////////////////////////////////////////
//
// ZeroConfCallbacks
//
///////////////////////////////////////////////////////////////////////////////
set<string> ZeroConfCallbacks_BDV::hasScrAddr(const BinaryDataRef& addr) const
{
   //this is slow needs improved
   set<string> result;
   auto bdvPtr = clientsPtr_->BDVs_.get();

   for (auto& bdv_pair : *bdvPtr)
   {
      if (bdv_pair.second->hasScrAddress(addr))
         result.insert(bdv_pair.first);
   }

   return result;
}

///////////////////////////////////////////////////////////////////////////////
void ZeroConfCallbacks_BDV::pushZcNotification(
   shared_ptr<ZeroConfSharedStateSnapshot> ss,
   shared_ptr<map<BinaryData, shared_ptr<set<BinaryDataRef>>>> newZcKeys,
   map<string, ParsedZCData> flaggedBDVs,
   const string& requestorId, const string& bdvId,
   map<BinaryData, WatcherTxBody>& watcherMap)
{
   const auto& txiomap = ss->txioMap_;

   //map of <txHash, request> per bdvID
   map<string, map<BinaryData, string>> idsToHash;

   //prepare requestor id map per bdv
   if (!requestorId.empty())
   {
      //only populate this map if we have a primary requestor. there cannot
      //be secondary requestors without a primary one.
      for (auto& watcher : watcherMap)
      {
         //add secondary requestors if any, we only allow one request id for a
         //given tx per bdv, this is filtered at broadcast time
         for (auto& requestor : watcher.second.extraRequestors_)
         {
            auto& hashMap = idsToHash[requestor.second];
            hashMap.emplace(watcher.first, requestor.first);
         }
      }
   }

   //build notifications for each BDV
   auto bdvMap = clientsPtr_->BDVs_.get();
   for (auto& bdvObj : flaggedBDVs)
   {
      //get bdv object
      auto bdvIter = bdvMap->find(bdvObj.first);
      if (bdvIter == bdvMap->end())
      {
         LOGWARN << "pushing zc notification with invalid bdvid";
         return;
      }

      //create notif packet
      ZcNotificationPacket notificationPacket(bdvObj.first);
      notificationPacket.ssPtr_ = ss;

      //set txio map
      for (auto& sa : bdvObj.second.scrAddrs_)
      {
         auto saIter = txiomap.find(sa);
         if (saIter == txiomap.end())
            continue;

         //copy the txiomap for this scrAddr over to the notification object
         auto notifPacketIter = notificationPacket.txioMap_.emplace(
            saIter->first.getRef(), 
            map<BinaryDataRef, shared_ptr<TxIOPair>>());
         auto& notifTxioMap = notifPacketIter.first->second;
         
         for (auto& txio : saIter->second)
            notifTxioMap.emplace(txio.first.getRef(), txio.second);
      }

      //set invalidated keys
      if (bdvObj.second.invalidatedKeys_.size() != 0)
      {
         notificationPacket.purgePacket_ = make_shared<ZcPurgePacket>();
         notificationPacket.purgePacket_->invalidatedZcKeys_ =
            move(bdvObj.second.invalidatedKeys_);
      }

      //set requestor map
      auto requestorsIter = idsToHash.find(bdvObj.first);
      if (requestorsIter != idsToHash.end())
         notificationPacket.requestorMap_ = move(requestorsIter->second);

      //set the primary requestor if this is the caller bdv
      if (bdvObj.first == bdvId)
         notificationPacket.primaryRequestor_ = requestorId;

      //set new zc keys
      notificationPacket.newKeysAndScrAddr_ = newZcKeys;

      //create notif and push to bdv
      auto notifPacket = make_shared<BDV_Notification_Packet>();
      notifPacket->bdvPtr_ = bdvIter->second;
      notifPacket->notifPtr_ = make_shared<BDV_Notification_ZC>(notificationPacket);
      clientsPtr_->innerBDVNotifStack_.push_back(move(notifPacket));

      //dish out already-in-mempool errors for extra requestors
   }
}

///////////////////////////////////////////////////////////////////////////////
void ZeroConfCallbacks_BDV::pushZcError(
   const string& bdvID, const BinaryData& hash, 
   ArmoryErrorCodes errCode, const string& verbose, 
   const string& requestID)
{
   auto bdvMap = clientsPtr_->BDVs_.get();
   auto iter = bdvMap->find(bdvID);
   if (iter == bdvMap->end())
   {
      LOGWARN << "pushed zc error with invalid bdvid";
      return;
   }

   auto notifPacket = make_shared<BDV_Notification_Packet>();
   notifPacket->bdvPtr_ = iter->second;
   notifPacket->notifPtr_ = make_shared<BDV_Notification_Error>(
      bdvID, requestID, (int)errCode, hash, verbose);
   clientsPtr_->innerBDVNotifStack_.push_back(move(notifPacket));
}

///////////////////////////////////////////////////////////////////////////////
//
// ZcNotificationPacket
//
///////////////////////////////////////////////////////////////////////////////
void ZcNotificationPacket::toProtobufNotification(
   std::shared_ptr<::Codec_BDVCommand::BDVCallback> protoPtr, 
   const std::vector<LedgerEntry>& leVec) const
{
   //order ledger entries per request id
   map<string, list<const ::LedgerEntry*>> requestToLedgers;

   for (auto& le : leVec)
   {
      const auto& hash = le.getTxHash();
      
      auto iter = requestorMap_.find(hash);
      if (iter == requestorMap_.end())
      {
         //if this hash has no request id attached, pass it without one
         requestToLedgers[primaryRequestor_].push_back(&le);
      }
      else
      {
         requestToLedgers[iter->second].push_back(&le);
      }      
   }

   //create a notif per request
   for (auto& reqPair : requestToLedgers)
   {
      auto& leList = reqPair.second;

      if (!leList.empty())
      {
         auto notif = protoPtr->add_notification();
         notif->set_type(NotificationType::zc);
         auto ledgers = notif->mutable_ledgers();

         for (auto le : leList)
         {
            auto ledger_entry = ledgers->add_values();
            le->fillMessage(ledger_entry);
         }

         if (!reqPair.first.empty())
            notif->set_requestid(reqPair.first);
      }

   }

   if (purgePacket_ != nullptr &&
      !purgePacket_->invalidatedZcKeys_.empty())
   {
      auto notif = protoPtr->add_notification();
      notif->set_type(NotificationType::invalidated_zc);

      auto ids = notif->mutable_ids();
      for (auto& id : purgePacket_->invalidatedZcKeys_)
      {
         auto idPtr = ids->add_value();
         idPtr->set_data(id.second.getPtr(), id.second.getSize());
      }
   }
}