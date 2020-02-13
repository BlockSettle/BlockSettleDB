////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ClientClasses.h"
#include "WebSocketClient.h"
#include "protobuf/BDVCommand.pb.h"
#include "btc/ecc.h"

using namespace std;
using namespace ClientClasses;
using namespace ::Codec_BDVCommand;


///////////////////////////////////////////////////////////////////////////////
void ClientClasses::initLibrary()
{
   startupBIP150CTX(4, false);
   startupBIP151CTX();
   btc_ecc_start();
}

///////////////////////////////////////////////////////////////////////////////
//
// BlockHeader
//
///////////////////////////////////////////////////////////////////////////////
ClientClasses::BlockHeader::BlockHeader(
   const BinaryData& rawheader, unsigned height)
{
   unserialize(rawheader.getRef());
   blockHeight_ = height;
}

////////////////////////////////////////////////////////////////////////////////
void ClientClasses::BlockHeader::unserialize(uint8_t const * ptr, uint32_t size)
{
   if (size < HEADER_SIZE)
      throw BlockDeserializingException();
   dataCopy_.copyFrom(ptr, HEADER_SIZE);
   BtcUtils::getHash256(dataCopy_.getPtr(), HEADER_SIZE, thisHash_);
   difficultyDbl_ = BtcUtils::convertDiffBitsToDouble(
      BinaryDataRef(dataCopy_.getPtr() + 72, 4));
   isInitialized_ = true;
   blockHeight_ = UINT32_MAX;
}

///////////////////////////////////////////////////////////////////////////////
//
// LedgerEntry
//
///////////////////////////////////////////////////////////////////////////////
LedgerEntry::LedgerEntry(shared_ptr<::Codec_LedgerEntry::LedgerEntry> msg) :
   msgPtr_(msg), ptr_(msg.get())
{}

///////////////////////////////////////////////////////////////////////////////
LedgerEntry::LedgerEntry(BinaryDataRef bdr)
{
   auto msg = make_shared<::Codec_LedgerEntry::LedgerEntry>();
   msg->ParseFromArray(bdr.getPtr(), bdr.getSize());
   ptr_ = msg.get();
   msgPtr_ = msg;
}

///////////////////////////////////////////////////////////////////////////////
LedgerEntry::LedgerEntry(
   shared_ptr<::Codec_LedgerEntry::ManyLedgerEntry> msg, unsigned index) :
   msgPtr_(msg)
{
   ptr_ = &msg->values(index);
}

///////////////////////////////////////////////////////////////////////////////
LedgerEntry::LedgerEntry(
   shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i, unsigned y) :
   msgPtr_(msg)
{
   auto& notif = msg->notification(i);
   auto& ledgers = notif.ledgers();
   ptr_ = &ledgers.values(y);
}


///////////////////////////////////////////////////////////////////////////////
string LedgerEntry::getID() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   if (ptr_->has_id())
      return ptr_->id();
   return string();
}

///////////////////////////////////////////////////////////////////////////////
int64_t LedgerEntry::getValue() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->balance();
}

///////////////////////////////////////////////////////////////////////////////
uint32_t LedgerEntry::getBlockNum() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->txheight();
}

///////////////////////////////////////////////////////////////////////////////
BinaryDataRef LedgerEntry::getTxHash() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   auto& val = ptr_->txhash();
   BinaryDataRef bdr;
   bdr.setRef(val);
   return bdr;
}

///////////////////////////////////////////////////////////////////////////////
uint32_t LedgerEntry::getIndex() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->index();
}

///////////////////////////////////////////////////////////////////////////////
uint32_t LedgerEntry::getTxTime() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->txtime();
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isCoinbase() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->iscoinbase();
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isSentToSelf() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->issts();
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isChangeBack() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->ischangeback();
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isOptInRBF() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->optinrbf();
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isChainedZC() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->ischainedzc();
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isWitness() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->iswitness();
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::operator==(const LedgerEntry& rhs)
{
   if (getTxHash() != rhs.getTxHash())
      return false;

   if (getIndex() != rhs.getIndex())
      return false;

   return true;
}

///////////////////////////////////////////////////////////////////////////////
vector<BinaryData> LedgerEntry::getScrAddrList() const
{
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");

   vector<BinaryData> addrList;
   for (unsigned i = 0; i < ptr_->scraddr_size(); i++)
   {
      const auto& addrPtr = ptr_->scraddr(i);
      BinaryDataRef addrRef; addrRef.setRef(addrPtr);

      addrList.push_back(addrRef);
   }

   return addrList;
}

///////////////////////////////////////////////////////////////////////////////
//
// RemoteCallback
//
///////////////////////////////////////////////////////////////////////////////
RemoteCallback::~RemoteCallback(void)
{}

///////////////////////////////////////////////////////////////////////////////
bool RemoteCallback::processNotifications(
   shared_ptr<BDVCallback> callback)
{
   for(int i = 0; i<callback->notification_size(); i++)
   {
      auto& notif = callback->notification(i);

      switch (notif.type())
      {
      case NotificationType::continue_polling:
         break;

      case NotificationType::newblock:
      {
         if (!notif.has_newblock())
            break;

         auto newblock = notif.newblock();
         if (newblock.height() != 0)
         {
            BdmNotification bdmNotif(BDMAction_NewBlock);

            bdmNotif.height_ = newblock.height();
            if (newblock.has_branch_height())
               bdmNotif.branchHeight_ = newblock.branch_height();

            run(move(bdmNotif));
         }

         break;
      }

      case NotificationType::zc:
      {
         if (!notif.has_ledgers())
            break;

         auto& ledgers = notif.ledgers();

         BdmNotification bdmNotif(BDMAction_ZC);
         for (int y = 0; y < ledgers.values_size(); y++)
         {
            auto le = make_shared<LedgerEntry>(callback, i, y);
            bdmNotif.ledgers_.push_back(le);
         }

         run(move(bdmNotif));

         break;
      }

      case NotificationType::invalidated_zc:
      {

         if (!notif.has_ids())
            break;

         auto& ids = notif.ids();
         set<BinaryData> idSet;

         BdmNotification bdmNotif(BDMAction_InvalidatedZC);
         for (int y = 0; y < ids.value_size(); y++)
         {
            auto& id_str = ids.value(y).data();
            BinaryData id_bd((uint8_t*)id_str.c_str(), id_str.size());
            bdmNotif.invalidatedZc_.emplace(id_bd);
         }

         run(move(bdmNotif));

         break;
      }

      case NotificationType::refresh:
      {
         if (!notif.has_refresh())
            break;

         auto& refresh = notif.refresh();
         auto refreshType = (BDV_refresh)refresh.refreshtype();
         
         BdmNotification bdmNotif(BDMAction_Refresh);
         if (refreshType != BDV_filterChanged)
         {
            for (int y = 0; y < refresh.id_size(); y++)
            {
               auto& str = refresh.id(y);
               BinaryData bd; bd.copyFrom(str);
               bdmNotif.ids_.emplace_back(bd);
            }
         }
         else
         {
            bdmNotif.ids_.push_back(BinaryData::fromString(FILTER_CHANGE_FLAG));
         }

         run(move(bdmNotif));

         break;
      }

      case NotificationType::ready:
      {
         if (!notif.has_newblock())
            break;

         BdmNotification bdmNotif(BDMAction_Ready);
         bdmNotif.height_ = notif.newblock().height();
         run(move(bdmNotif));

         break;
      }

      case NotificationType::progress:
      {
         if (!notif.has_progress())
            break;

         auto pd = ProgressData::make_new(callback, i);
         progress(pd->phase(), pd->wltIDs(), pd->progress(),
            pd->time(), pd->numericProgress());

         break;
      }

      case NotificationType::terminate:
      {
         //shut down command from server
         return false;
      }

      case NotificationType::nodestatus:
      {
         if (!notif.has_nodestatus())
            break;

         BdmNotification bdmNotif(BDMAction_NodeStatus);
         bdmNotif.nodeStatus_ = 
            ClientClasses::NodeStatusStruct::make_new(callback, i);

         run(move(bdmNotif));
         break;
      }

      case NotificationType::error:
      {
         if (!notif.has_error())
            break;

         auto& msg = notif.error();

         BdmNotification bdmNotif(BDMAction_BDV_Error);
         bdmNotif.error_.errCode_ = msg.code();
         bdmNotif.error_.errorStr_ = msg.errstr();
         bdmNotif.error_.errData_ = BinaryData::fromString(msg.errdata());

         BinaryDataRef errDataRef; errDataRef.setRef(msg.errdata());
         bdmNotif.error_.errData_ = errDataRef;

         run(move(bdmNotif));
         break;
      }

      default:
         continue;
      }
   }

   return true;
}

///////////////////////////////////////////////////////////////////////////////
//
// NodeStatusStruct
//
///////////////////////////////////////////////////////////////////////////////
::ClientClasses::NodeStatusStruct::NodeStatusStruct(BinaryDataRef bdr)
{
   auto msg = make_shared<::Codec_NodeStatus::NodeStatus>();
   if (!msg->ParseFromArray(bdr.getPtr(), bdr.getSize()))
      throw runtime_error("invalid node status protobuf msg");
   ptr_ = msg.get();
   msgPtr_ = move(msg);
}

///////////////////////////////////////////////////////////////////////////////
::ClientClasses::NodeStatusStruct::NodeStatusStruct(
   shared_ptr<::Codec_NodeStatus::NodeStatus> msg)
{
   msgPtr_ = msg;
   ptr_ = msg.get();
}

///////////////////////////////////////////////////////////////////////////////
::ClientClasses::NodeStatusStruct::NodeStatusStruct(
   shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i) :
   msgPtr_(msg)
{
   auto& notif = msg->notification(i);
   ptr_ = &notif.nodestatus();
}

///////////////////////////////////////////////////////////////////////////////
NodeStatus ClientClasses::NodeStatusStruct::status() const
{
   return (NodeStatus)ptr_->status();
}

///////////////////////////////////////////////////////////////////////////////
bool ::ClientClasses::NodeStatusStruct::isSegWitEnabled() const
{
   if (ptr_->has_segwitenabled())
      return ptr_->segwitenabled();
   return false;
}

///////////////////////////////////////////////////////////////////////////////
RpcStatus ClientClasses::NodeStatusStruct::rpcStatus() const
{
   if (ptr_->has_rpcstatus())
      return (RpcStatus)ptr_->rpcstatus();
   return RpcStatus::RpcStatus_Disabled;
}

///////////////////////////////////////////////////////////////////////////////
::ClientClasses::NodeChainState 
   ClientClasses::NodeStatusStruct::chainState() const
{
   return NodeChainState(ptr_);
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<ClientClasses::NodeStatusStruct> 
ClientClasses::NodeStatusStruct::make_new(
   std::shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i)
{
   auto nss = make_shared<ClientClasses::NodeStatusStruct>(
      NodeStatusStruct(msg, i));
   return nss;
}

///////////////////////////////////////////////////////////////////////////////
//
// NodeChainState
//
///////////////////////////////////////////////////////////////////////////////
::ClientClasses::NodeChainState::NodeChainState(
   const ::Codec_NodeStatus::NodeStatus* ptr) :
   ptr_(&ptr->chainstate())
{}

///////////////////////////////////////////////////////////////////////////////
ChainStatus ClientClasses::NodeChainState::state() const
{
   return (ChainStatus)ptr_->state();
}

///////////////////////////////////////////////////////////////////////////////
float ClientClasses::NodeChainState::getBlockSpeed() const
{
   return ptr_->blockspeed();
}

///////////////////////////////////////////////////////////////////////////////
float ClientClasses::NodeChainState::getProgressPct() const
{
   return ptr_->pct();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t ClientClasses::NodeChainState::getETA() const
{
   return ptr_->eta();
}

///////////////////////////////////////////////////////////////////////////////
unsigned ClientClasses::NodeChainState::getBlocksLeft() const
{
   return ptr_->blocksleft();
}

///////////////////////////////////////////////////////////////////////////////
//
// ProgressData
//
///////////////////////////////////////////////////////////////////////////////
::ClientClasses::ProgressData::ProgressData(BinaryDataRef)
{
   auto msg = make_shared<::Codec_NodeStatus::ProgressData>();
   ptr_ = msg.get();
   msgPtr_ = msg;
}

///////////////////////////////////////////////////////////////////////////////
::ClientClasses::ProgressData::ProgressData(
   shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i) :
   msgPtr_(msg)
{
   auto& notif = msg->notification(i);
   ptr_ = &notif.progress();
}

///////////////////////////////////////////////////////////////////////////////
BDMPhase ClientClasses::ProgressData::phase() const
{
   return (BDMPhase)ptr_->phase();
}

///////////////////////////////////////////////////////////////////////////////
double ClientClasses::ProgressData::progress() const
{
   return ptr_->progress();
}

///////////////////////////////////////////////////////////////////////////////
unsigned ClientClasses::ProgressData::time() const
{
   return ptr_->time();
}

///////////////////////////////////////////////////////////////////////////////
unsigned ClientClasses::ProgressData::numericProgress() const
{
   return ptr_->numericprogress();
}

///////////////////////////////////////////////////////////////////////////////
vector<string> ClientClasses::ProgressData::wltIDs() const
{
   vector<string> vec;
   for (int i = 0; i < ptr_->id_size(); i++)
      vec.push_back(ptr_->id(i));

   return vec;
}

///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<ProgressData> ClientClasses::ProgressData::make_new(
   std::shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i)
{
   auto pd = make_shared<ProgressData>(ProgressData(msg, i));
   return pd;
}

