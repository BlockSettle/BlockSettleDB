////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "DBClientClasses.h"
#include "WebSocketClient.h"
#include "protobuf/BDVCommand.pb.h"
#include "btc/ecc.h"

using namespace std;
using namespace DBClientClasses;
using namespace Codec_BDVCommand;


///////////////////////////////////////////////////////////////////////////////
void initLibrary()
{
   startupBIP150CTX(4);
   startupBIP151CTX();
   btc_ecc_start();
}

///////////////////////////////////////////////////////////////////////////////
//
// BlockHeader
//
///////////////////////////////////////////////////////////////////////////////
DBClientClasses::BlockHeader::BlockHeader(
   const BinaryData& rawheader, unsigned height)
{
   unserialize(rawheader.getRef());
   blockHeight_ = height;
}

////////////////////////////////////////////////////////////////////////////////
void DBClientClasses::BlockHeader::unserialize(uint8_t const * ptr, uint32_t size)
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
   for (int i = 0; i < ptr_->scraddr_size(); i++)
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

         bdmNotif.requestID_ = notif.requestid();
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
            DBClientClasses::NodeStatus::make_new(callback, i);

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
         bdmNotif.requestID_ = notif.requestid();

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
// NodeStatus
//
///////////////////////////////////////////////////////////////////////////////
NodeStatus::NodeStatus(BinaryDataRef bdr)
{
   auto msg = make_shared<Codec_NodeStatus::NodeStatus>();
   if (!msg->ParseFromArray(bdr.getPtr(), bdr.getSize()))
      throw runtime_error("invalid node status protobuf msg");
   ptr_ = msg.get();
   msgPtr_ = move(msg);
}

///////////////////////////////////////////////////////////////////////////////
NodeStatus::NodeStatus(
   shared_ptr<Codec_NodeStatus::NodeStatus> msg)
{
   msgPtr_ = msg;
   ptr_ = msg.get();
}

///////////////////////////////////////////////////////////////////////////////
NodeStatus::NodeStatus(
   shared_ptr<Codec_BDVCommand::BDVCallback> msg, unsigned i) :
   msgPtr_(msg)
{
   auto& notif = msg->notification(i);
   ptr_ = &notif.nodestatus();
}

///////////////////////////////////////////////////////////////////////////////
CoreRPC::NodeState NodeStatus::state() const
{
   return (CoreRPC::NodeState)ptr_->state();
}

///////////////////////////////////////////////////////////////////////////////
bool NodeStatus::isSegWitEnabled() const
{
   if (ptr_->has_segwitenabled())
      return ptr_->segwitenabled();
   return false;
}

///////////////////////////////////////////////////////////////////////////////
CoreRPC::RpcState NodeStatus::rpcState() const
{
   if (ptr_->has_rpcstate())
      return (CoreRPC::RpcState)ptr_->rpcstate();
   return CoreRPC::RpcState::RpcState_Disabled;
}

///////////////////////////////////////////////////////////////////////////////
NodeChainStatus NodeStatus::chainStatus() const
{
   return NodeChainStatus(ptr_);
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<NodeStatus> NodeStatus::make_new(
   shared_ptr<Codec_BDVCommand::BDVCallback> msg, unsigned i)
{
   auto nss = make_shared<NodeStatus>(NodeStatus(msg, i));
   return nss;
}

///////////////////////////////////////////////////////////////////////////////
//
// NodeChainState
//
///////////////////////////////////////////////////////////////////////////////
NodeChainStatus::NodeChainStatus(
   const Codec_NodeStatus::NodeStatus* ptr) :
   ptr_(&ptr->chainstatus())
{}

///////////////////////////////////////////////////////////////////////////////
CoreRPC::ChainState NodeChainStatus::state() const
{
   return (CoreRPC::ChainState)ptr_->state();
}

///////////////////////////////////////////////////////////////////////////////
float NodeChainStatus::getBlockSpeed() const
{
   return ptr_->blockspeed();
}

///////////////////////////////////////////////////////////////////////////////
float NodeChainStatus::getProgressPct() const
{
   return ptr_->pct();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t NodeChainStatus::getETA() const
{
   return ptr_->eta();
}

///////////////////////////////////////////////////////////////////////////////
unsigned NodeChainStatus::getBlocksLeft() const
{
   return ptr_->blocksleft();
}

///////////////////////////////////////////////////////////////////////////////
//
// ProgressData
//
///////////////////////////////////////////////////////////////////////////////
ProgressData::ProgressData(BinaryDataRef)
{
   auto msg = make_shared<::Codec_NodeStatus::ProgressData>();
   ptr_ = msg.get();
   msgPtr_ = msg;
}

///////////////////////////////////////////////////////////////////////////////
ProgressData::ProgressData(
   shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i) :
   msgPtr_(msg)
{
   auto& notif = msg->notification(i);
   ptr_ = &notif.progress();
}

///////////////////////////////////////////////////////////////////////////////
BDMPhase ProgressData::phase() const
{
   return (BDMPhase)ptr_->phase();
}

///////////////////////////////////////////////////////////////////////////////
double ProgressData::progress() const
{
   return ptr_->progress();
}

///////////////////////////////////////////////////////////////////////////////
unsigned ProgressData::time() const
{
   return ptr_->time();
}

///////////////////////////////////////////////////////////////////////////////
unsigned ProgressData::numericProgress() const
{
   return ptr_->numericprogress();
}

///////////////////////////////////////////////////////////////////////////////
vector<string> ProgressData::wltIDs() const
{
   vector<string> vec;
   for (int i = 0; i < ptr_->id_size(); i++)
      vec.push_back(ptr_->id(i));

   return vec;
}

///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<ProgressData> ProgressData::make_new(
   std::shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i)
{
   auto pd = make_shared<ProgressData>(ProgressData(msg, i));
   return pd;
}

