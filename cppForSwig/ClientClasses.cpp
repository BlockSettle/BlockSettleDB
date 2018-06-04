////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ClientClasses.h"
#include "WebSocketClient.h"

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
// RemoteCallback
//
///////////////////////////////////////////////////////////////////////////////
RemoteCallback::RemoteCallback(RemoteCallbackSetupStruct setupstruct) :
   sock_(setupstruct.sockPtr_), bdvID_(setupstruct.bdvId_), 
   setHeightLbd_(setupstruct.setHeightLambda_)
{
   orderMap_["continue"] = CBO_continue;
   orderMap_["NewBlock"] = CBO_NewBlock;
   orderMap_["BDV_ZC"] = CBO_ZC;
   orderMap_["BDV_Refresh"] = CBO_BDV_Refresh;
   orderMap_["BDM_Ready"] = CBO_BDM_Ready;
   orderMap_["BDV_Progress"] = CBO_progress;
   orderMap_["terminate"] = CBO_terminate;
   orderMap_["BDV_NodeStatus"] = CBO_NodeStatus;
   orderMap_["BDV_Error"] = CBO_BDV_Error;

   //set callback ptr for websocket client
   auto ws_ptr = dynamic_pointer_cast<WebSocketClient>(sock_);
   if (ws_ptr == nullptr)
      return;

   ws_ptr->setCallback(this);
}

///////////////////////////////////////////////////////////////////////////////
void RemoteCallback::start(void)
{
   pushCallbackRequest();
}

///////////////////////////////////////////////////////////////////////////////
RemoteCallback::~RemoteCallback(void)
{
   shutdown();
}

///////////////////////////////////////////////////////////////////////////////
void RemoteCallback::shutdown()
{
   run_ = false;
   SocketPrototype::closeSocket(sockfd_);
}

///////////////////////////////////////////////////////////////////////////////
void RemoteCallback::pushCallbackRequest(void)
{
   if (!run_)
      return;

   Command sendCmd;
   sendCmd.method_ = "registerCallback";
   sendCmd.ids_.push_back(bdvID_);
   BinaryDataObject bdo("getStatus");
   sendCmd.args_.push_back(move(bdo));

   Socket_WritePayload write_payload;
   sendCmd.serialize(write_payload.data_);

   auto callback = [this](BinaryDataRef bdr)->void
   {
      this->processArguments(bdr);
   };

   auto read_payload = make_shared<Socket_ReadPayload>(sendCmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_BinaryDataRef>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
bool RemoteCallback::processArguments(BinaryDataRef& bdr)
{
   Arguments args(bdr);

   while (args.hasArgs())
   {
      auto&& cb = args.get<BinaryDataObject>();

      auto orderIter = orderMap_.find(cb.toStr());
      if (orderIter == orderMap_.end())
      {
         continue;
      }

      switch (orderIter->second)
      {
      case CBO_continue:
         break;

      case CBO_NewBlock:
      {
         unsigned int newblock = args.get<IntType>().getVal();
         setHeightLbd_(newblock);

         if (newblock != 0)
            run(BDMAction::BDMAction_NewBlock, &newblock, newblock);

         break;
      }

      case CBO_ZC:
      {
         auto&& lev = args.get<LedgerEntryVector>();
         auto leVec = lev.toVector();

         run(BDMAction::BDMAction_ZC, &leVec, 0);

         break;
      }

      case CBO_BDV_Refresh:
      {
         auto&& refreshType = args.get<IntType>();
         auto&& idVec = args.get<BinaryDataVector>();

         auto refresh = BDV_refresh(refreshType.getVal());

         if (refresh != BDV_filterChanged)
            run(BDMAction::BDMAction_Refresh, (void*)&idVec.get(), 0);
         else
         {
            vector<BinaryData> bdvec;
            bdvec.push_back(BinaryData("wallet_filter_changed"));
            run(BDMAction::BDMAction_Refresh, (void*)&bdvec, 0);
         }

         break;
      }

      case CBO_BDM_Ready:
      {
         unsigned int topblock = args.get<IntType>().getVal();
         setHeightLbd_(topblock);

         run(BDMAction::BDMAction_Ready, nullptr, topblock);

         break;
      }

      case CBO_progress:
      {
         auto&& pd = args.get<ProgressData>();
         progress(pd.phase_, pd.wltIDs_, pd.progress_,
            pd.time_, pd.numericProgress_);

         break;
      }

      case CBO_terminate:
      {
         //shut down command from server
         return false;
      }

      case CBO_NodeStatus:
      {
         auto&& serData = args.get<BinaryDataObject>();
         NodeStatusStruct nss;
         nss.deserialize(serData.get());

         run(BDMAction::BDMAction_NodeStatus, &nss, 0);
         break;
      }

      case CBO_BDV_Error:
      {
         auto&& serData = args.get<BinaryDataObject>();
         BDV_Error_Struct bdvErr;
         bdvErr.deserialize(serData.get());

         run(BDMAction::BDMAction_BDV_Error, &bdvErr, 0);
         break;
      }

      default:
         continue;
      }
   }

   pushCallbackRequest();
   return true;
}
