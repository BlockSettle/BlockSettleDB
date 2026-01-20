////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "DBClientClasses.h"
#include "WebSocketClient.h"
#include "BDVCodec.h"
#include "btc/ecc.h"

using namespace std;
using namespace DBClientClasses;
#ifdef BUILD_PROTOBUF
using namespace Codec_BDVCommand;
#endif

///////////////////////////////////////////////////////////////////////////////
void initLibrary()
{
   startupBIP150CTX(4);
   startupBIP151CTX();
   CryptoECDSA::setupContext();
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
#ifdef BUILD_PROTOBUF
LedgerEntry::LedgerEntry(shared_ptr<::Codec_LedgerEntry::LedgerEntry> msg) :
   msgPtr_(msg), ptr_(msg.get())
{}
#endif

///////////////////////////////////////////////////////////////////////////////
LedgerEntry::LedgerEntry(BinaryDataRef bdr)
{
#ifdef BUILD_PROTOBUF
   auto msg = make_shared<::Codec_LedgerEntry::LedgerEntry>();
   msg->ParseFromArray(bdr.getPtr(), (int)bdr.getSize());
   ptr_ = msg.get();
   msgPtr_ = msg;
#endif
}

///////////////////////////////////////////////////////////////////////////////
#ifdef BUILD_PROTOBUF
LedgerEntry::LedgerEntry(
   shared_ptr<::Codec_LedgerEntry::ManyLedgerEntry> msg, unsigned index) :
   msgPtr_(msg)
{
   ptr_ = &msg->values(index);
}
#endif

///////////////////////////////////////////////////////////////////////////////
#ifdef BUILD_PROTOBUF
LedgerEntry::LedgerEntry(
   shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i, unsigned y) :
   msgPtr_(msg)
{
   auto& notif = msg->notification(i);
   auto& ledgers = notif.ledgers();
   ptr_ = &ledgers.values(y);
}
#endif

///////////////////////////////////////////////////////////////////////////////
string LedgerEntry::getID() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   if (ptr_->has_id())
      return ptr_->id();
#endif
   return string();
}

///////////////////////////////////////////////////////////////////////////////
int64_t LedgerEntry::getValue() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->balance();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
uint32_t LedgerEntry::getBlockNum() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->txheight();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
BinaryDataRef LedgerEntry::getTxHash() const
{
#if 0
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   auto& val = ptr_->txhash();
   BinaryDataRef bdr;
   bdr.setRef(val);
   return bdr;
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
uint32_t LedgerEntry::getIndex() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->index();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
uint32_t LedgerEntry::getTxTime() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->txtime();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isCoinbase() const
{
#if 0
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->iscoinbase();
#else
   return false;
#endif
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isSentToSelf() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->issts();
#else
   return false;
#endif
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isChangeBack() const
{
#if 0
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->ischangeback();
#else
   return false;
#endif
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isOptInRBF() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->optinrbf();
#else
   return false;
#endif
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isChainedZC() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->ischainedzc();
#else
   return false;
#endif
}

///////////////////////////////////////////////////////////////////////////////
bool LedgerEntry::isWitness() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_ == nullptr)
      throw runtime_error("uninitialized ledger entry");
   return ptr_->iswitness();
#else
   return false;
#endif
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
#ifdef BUILD_PROTOBUF
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
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
//
// RemoteCallback
//
///////////////////////////////////////////////////////////////////////////////
RemoteCallback::~RemoteCallback(void)
{}

///////////////////////////////////////////////////////////////////////////////
#ifdef BUILD_PROTOBUF
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
         progress(pd->phase(), pd->wltIDs(), (float)pd->progress(),
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
#endif

///////////////////////////////////////////////////////////////////////////////
//
// NodeStatus
//
///////////////////////////////////////////////////////////////////////////////
NodeStatus::NodeStatus(BinaryDataRef bdr)
{
#ifdef BUILD_PROTOBUF
   auto msg = make_shared<Codec_NodeStatus::NodeStatus>();
   if (!msg->ParseFromArray(bdr.getPtr(), (int)bdr.getSize()))
      throw runtime_error("invalid node status protobuf msg");
   ptr_ = msg.get();
   msgPtr_ = move(msg);
#endif
}

///////////////////////////////////////////////////////////////////////////////
#ifdef BUILD_PROTOBUF
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
#endif

///////////////////////////////////////////////////////////////////////////////
CoreRPC::NodeState NodeStatus::state() const
{
#ifdef BUILD_PROTOBUF
   return (CoreRPC::NodeState)ptr_->state();
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
bool NodeStatus::isSegWitEnabled() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_->has_segwitenabled())
      return ptr_->segwitenabled();
#endif
   return false;
}

///////////////////////////////////////////////////////////////////////////////
CoreRPC::RpcState NodeStatus::rpcState() const
{
#ifdef BUILD_PROTOBUF
   if (ptr_->has_rpcstate())
      return (CoreRPC::RpcState)ptr_->rpcstate();
#endif
   return CoreRPC::RpcState::RpcState_Disabled;
}

///////////////////////////////////////////////////////////////////////////////
NodeChainStatus NodeStatus::chainStatus() const
{
#ifdef BUILD_PROTOBUF
   return NodeChainStatus(ptr_);
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
#ifdef BUILD_PROTOBUF
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
#endif

///////////////////////////////////////////////////////////////////////////////
CoreRPC::ChainState NodeChainStatus::state() const
{
#ifdef BUILD_PROTOBUF
   return (CoreRPC::ChainState)ptr_->state();
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
float NodeChainStatus::getBlockSpeed() const
{
#ifdef BUILD_PROTOBUF
   return ptr_->blockspeed();
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
float NodeChainStatus::getProgressPct() const
{
#ifdef BUILD_PROTOBUF
   return ptr_->pct();
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
uint64_t NodeChainStatus::getETA() const
{
#ifdef BUILD_PROTOBUF
   return ptr_->eta();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
unsigned NodeChainStatus::getBlocksLeft() const
{
#ifdef BUILD_PROTOBUF
   return ptr_->blocksleft();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
//
// ProgressData
//
///////////////////////////////////////////////////////////////////////////////
ProgressData::ProgressData(BinaryDataRef)
{
#ifdef BUILD_PROTOBUF
   auto msg = make_shared<::Codec_NodeStatus::ProgressData>();
   ptr_ = msg.get();
   msgPtr_ = msg;
#endif
}

///////////////////////////////////////////////////////////////////////////////
#ifdef BUILD_PROTOBUF
ProgressData::ProgressData(
   shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i) :
   msgPtr_(msg)
{
   auto& notif = msg->notification(i);
   ptr_ = &notif.progress();
}
#endif

///////////////////////////////////////////////////////////////////////////////
BDMPhase ProgressData::phase() const
{
#ifdef BUILD_PROTOBUF
   return (BDMPhase)ptr_->phase();
#else
   return {};
#endif
}

///////////////////////////////////////////////////////////////////////////////
double ProgressData::progress() const
{
#ifdef BUILD_PROTOBUF
   return ptr_->progress();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
unsigned ProgressData::time() const
{
#ifdef BUILD_PROTOBUF
   return ptr_->time();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
unsigned ProgressData::numericProgress() const
{
#ifdef BUILD_PROTOBUF
   return ptr_->numericprogress();
#else
   return 0;
#endif
}

///////////////////////////////////////////////////////////////////////////////
vector<string> ProgressData::wltIDs() const
{
   vector<string> vec;
#ifdef BUILD_PROTOBUF
   for (int i = 0; i < ptr_->id_size(); i++)
      vec.push_back(ptr_->id(i));
#endif
   return vec;
}

///////////////////////////////////////////////////////////////////////////////
#ifdef BUILD_PROTOBUF
std::shared_ptr<ProgressData> ProgressData::make_new(
   std::shared_ptr<::Codec_BDVCommand::BDVCallback> msg, unsigned i)
{
   auto pd = make_shared<ProgressData>(ProgressData(msg, i));
   return pd;
}
#endif
