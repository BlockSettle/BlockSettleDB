
////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2021, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "AsyncClient.h"
#include "EncryptionUtils.h"
#include "BDVCodec.h"
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "google/protobuf/text_format.h"
#include "ArmoryErrors.h"

using namespace std;
using namespace AsyncClient;
using namespace Codec_BDVCommand;
using namespace DBClientClasses;

///////////////////////////////////////////////////////////////////////////////
//
// BlockDataViewer
//
///////////////////////////////////////////////////////////////////////////////
unique_ptr<WritePayload_Protobuf> BlockDataViewer::make_payload(Methods method)
{
   auto payload = make_unique<WritePayload_Protobuf>();
   auto message = make_unique<BDVCommand>();
   message->set_method(method);

   payload->message_ = move(message);
   return payload;
}

///////////////////////////////////////////////////////////////////////////////
unique_ptr<WritePayload_Protobuf> BlockDataViewer::make_payload(
   StaticMethods method)
{
   auto payload = make_unique<WritePayload_Protobuf>();
   auto message = make_unique<StaticCommand>();
   message->set_method(method);

   payload->message_ = move(message);
   return payload;
}

///////////////////////////////////////////////////////////////////////////////
bool BlockDataViewer::hasRemoteDB(void)
{
   return sock_->testConnection();
}

///////////////////////////////////////////////////////////////////////////////
bool BlockDataViewer::connectToRemote(void)
{
   return sock_->connectToRemote();
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::addPublicKey(const SecureBinaryData& pubkey)
{
   auto wsSock = dynamic_pointer_cast<WebSocketClient>(sock_);
   if (wsSock == nullptr)
   {
      LOGERR << "invalid socket type for auth peer management";
      return;
   }

   wsSock->addPublicKey(pubkey);
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<BlockDataViewer> BlockDataViewer::getNewBDV(const string& addr,
   const string& port, const string& datadir, const PassphraseLambda& passLbd,
   const bool& ephemeralPeers, bool oneWayAuth,
   shared_ptr<RemoteCallback> callbackPtr)
{
   //create socket object
   auto sockptr = make_shared<WebSocketClient>(addr, port, datadir, passLbd,
      ephemeralPeers, oneWayAuth, callbackPtr);

   //instantiate bdv object
   BlockDataViewer* bdvPtr = new BlockDataViewer(sockptr);

   //create shared_ptr of bdv object
   shared_ptr<BlockDataViewer> bdvSharedPtr;
   bdvSharedPtr.reset(bdvPtr);

   return bdvSharedPtr;
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::registerWithDB(BinaryData magic_word)
{
   if (bdvID_.size() != 0)
      throw BDVAlreadyRegistered();

   //get bdvID
   try
   {
      auto payload = make_payload(StaticMethods::registerBDV);
      auto command = dynamic_cast<StaticCommand*>(payload->message_.get());
      command->set_magicword(magic_word.getPtr(), magic_word.getSize());
      
      //registration is always blocking as it needs to guarantee the bdvID

      auto promPtr = make_shared<promise<string>>();
      auto fut = promPtr->get_future();
      auto getResult = [promPtr](ReturnMessage<string> result)->void
      {
         try
         {
            promPtr->set_value(move(result.get()));
         }
         catch (exception&)
         {
            auto eptr = current_exception();
            promPtr->set_exception(eptr);
         }
      };

      auto read_payload = make_shared<Socket_ReadPayload>();
      read_payload->callbackReturn_ =
         make_unique<CallbackReturn_String>(getResult);
      sock_->pushPayload(move(payload), read_payload);
 
      bdvID_ = move(fut.get());
   }
   catch (runtime_error &e)
   {
      LOGERR << e.what();
      throw e;
   }
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::unregisterFromDB()
{
   if (sock_ == nullptr)
      return;

   if (sock_->type() == SocketWS)
   {
      auto sockws = dynamic_pointer_cast<WebSocketClient>(sock_);
      if(sockws == nullptr)
         return;

      sockws->shutdown();
      return;
   }

   auto payload = make_payload(StaticMethods::unregisterBDV);
   sock_->pushPayload(move(payload), nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::goOnline()
{
   auto payload = make_payload(Methods::goOnline);
   sock_->pushPayload(move(payload), nullptr);
}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::BlockDataViewer(void)
{
   cache_ = make_shared<ClientCache>();
}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::BlockDataViewer(shared_ptr<SocketPrototype> sock) :
   sock_(sock)
{
   cache_ = make_shared<ClientCache>();
}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::~BlockDataViewer()
{}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::shutdown(const string& cookie)
{
   auto payload = make_payload(StaticMethods::shutdown);
   auto command = dynamic_cast<StaticCommand*>(payload->message_.get());

   if (cookie.size() > 0)
      command->set_cookie(cookie);

   sock_->pushPayload(move(payload), nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::shutdownNode(const string& cookie)
{
   auto payload = make_payload(StaticMethods::shutdownNode);
   auto command = dynamic_cast<StaticCommand*>(payload->message_.get());

   if (cookie.size() > 0)
      command->set_cookie(cookie);

   sock_->pushPayload(move(payload), nullptr);
}

///////////////////////////////////////////////////////////////////////////////
AsyncClient::BtcWallet BlockDataViewer::instantiateWallet(const string& id)
{
   return move(BtcWallet(*this, id));
}

///////////////////////////////////////////////////////////////////////////////
Lockbox BlockDataViewer::instantiateLockbox(const string& id)
{
   return move(Lockbox(*this, id));
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getLedgerDelegateForWallets(
   function<void(ReturnMessage<LedgerDelegate>)> callback)
{
   auto payload = make_payload(Methods::getLedgerDelegateForWallets);
   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerDelegate>(sock_, bdvID_, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getLedgerDelegateForLockboxes(
   function<void(ReturnMessage<LedgerDelegate>)> callback)
{
   auto payload = make_payload(Methods::getLedgerDelegateForLockboxes);
   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerDelegate>(sock_, bdvID_, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
AsyncClient::Blockchain BlockDataViewer::blockchain(void)
{
   return Blockchain(*this);
}

///////////////////////////////////////////////////////////////////////////////
string BlockDataViewer::broadcastZC(const BinaryData& rawTx)
{
   auto tx = make_shared<Tx>(rawTx);
   cache_->insertTx(tx);

   auto payload = make_payload(Methods::broadcastZC);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->add_bindata(rawTx.getPtr(), rawTx.getSize());
   
   auto&& broadcastId = 
      BtcUtils::fortuna_.generateRandom(BROADCAST_ID_LENGTH).toHexStr();
   command->set_hash(broadcastId);

   sock_->pushPayload(move(payload), nullptr);
   return broadcastId;
}

///////////////////////////////////////////////////////////////////////////////
string BlockDataViewer::broadcastZC(const vector<BinaryData>& rawTxVec)
{
   auto payload = make_payload(Methods::broadcastZC);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& rawTx : rawTxVec)
   {
      auto tx = make_shared<Tx>(rawTx);
      cache_->insertTx(tx);

      command->add_bindata(rawTx.getPtr(), rawTx.getSize());
   }

   auto&& broadcastId = 
      BtcUtils::fortuna_.generateRandom(BROADCAST_ID_LENGTH).toHexStr();
   command->set_hash(broadcastId);

   sock_->pushPayload(move(payload), nullptr);
   return broadcastId;
}

///////////////////////////////////////////////////////////////////////////////
string BlockDataViewer::broadcastThroughRPC(const BinaryData& rawTx)
{
   auto tx = make_shared<Tx>(rawTx);
   cache_->insertTx(tx);

   auto payload = make_payload(Methods::broadcastThroughRPC);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->add_bindata(rawTx.getPtr(), rawTx.getSize());

   auto&& broadcastId = 
      BtcUtils::fortuna_.generateRandom(BROADCAST_ID_LENGTH).toHexStr();
   command->set_hash(broadcastId);

   sock_->pushPayload(move(payload), nullptr);
   return broadcastId;
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getTxByHash(
   const BinaryData& txHash, const TxCallback& callback)
{
   BinaryDataRef bdRef(txHash);
   BinaryData hash;

   if (txHash.getSize() != 32)
   {
      if (txHash.getSize() == 64)
      {
         string hashstr(txHash.toCharPtr(), txHash.getSize());
         hash = READHEX(hashstr);
         bdRef.setRef(hash);
      }
   }

   bool heightOnly = false;
   try
   {
      auto tx = cache_->getTx(bdRef);
      if (tx->getTxHeight() == UINT32_MAX)
      {
         //Throw out of this scope if the tx is cached but lacks a valid height.
         //Flag to only fetch the height as well.
         heightOnly = true;
         throw NoMatch();
      }

      /*
      We have this tx in cache, bypass the db and trigger the callback directly.
      
      This is an async interface, the expectation is that the callback will be 
      summoned from a different thread than the original call.

      Moreover, this framework always triggers return value callbacks in their own
      dedicated thread, as it does not expect users to treat the callback as a
      short-lived notification to return quickly from.

      Therefor, it is always acceptable to create a new thread to fire the 
      callback from.
      */
      ReturnMessage<TxResult> rm(tx);

      thread thr(callback, move(rm));
      if (thr.joinable())
         thr.detach();

      return;
   }
   catch(NoMatch&)
   {}

   auto payload = make_payload(Methods::getTxByHash);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_hash(bdRef.getPtr(), bdRef.getSize());
   command->set_flag(heightOnly);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Tx>(cache_, txHash, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getTxBatchByHash(
   const set<BinaryData>& hashes, const TxBatchCallback& callback)
{
   //only accepts hashes in binary format
   auto payload = make_payload(Methods::getTxBatchByHash);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   map<BinaryData, bool> hashesToFetch;
   TxBatchResult cachedTxs;
   for (auto& hash : hashes)
   {
      auto insertIter = cachedTxs.emplace(hash, nullptr).first;
      try
      {
         auto tx = cache_->getTx(hash.getRef());

         //flag to grab only the txheight if it's unset
         if(tx->getTxHeight() == UINT32_MAX)
            hashesToFetch.insert(make_pair(hash, true));
         else
            insertIter->second = tx;

         continue;
      }
      catch (NoMatch&)
      {}

      hashesToFetch.insert(make_pair(hash, false));
   }
      
   if (hashesToFetch.size() == 0)
   {
      //all tx in cache, fire the callback
      ReturnMessage<TxBatchResult> rm(move(cachedTxs));
      thread thr(callback, move(rm));
      if (thr.joinable())
         thr.detach();

      return;
   }
   
   for (auto& hash : hashesToFetch)
   {
      if (!hash.second)
      {
         command->add_bindata(hash.first.getPtr(), hash.first.getSize());
      }
      else
      {
         BinaryWriter bw(33);
         bw.put_BinaryDataRef(hash.first);
         bw.put_uint8_t(1);
         command->add_bindata(bw.getDataRef().getPtr(), 33);
      }
   }

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_TxBatch>(
         cache_, cachedTxs, hashesToFetch, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getRawHeaderForTxHash(const BinaryData& txHash,
   function<void(ReturnMessage<BinaryData>)> callback)
{
   BinaryDataRef bdRef(txHash);
   BinaryData hash;

   if (txHash.getSize() != 32)
   {
      if (txHash.getSize() == 64)
      {
         string hashstr(txHash.toCharPtr(), txHash.getSize());
         hash = READHEX(hashstr);
         bdRef.setRef(hash);
      }
   }

   try
   {
      auto& height = cache_->getHeightForTxHash(txHash);
      auto& rawHeader = cache_->getRawHeader(height);
      callback(rawHeader);
      return;
   }
   catch(NoMatch&)
   { }

   auto payload = make_payload(Methods::getHeaderByHash);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->add_bindata(txHash.getPtr(), txHash.getSize());

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_RawHeader>(
         cache_, UINT32_MAX, txHash, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getHeaderByHeight(unsigned height,
   function<void(ReturnMessage<BinaryData>)> callback)
{
   try
   {
      auto& rawHeader = cache_->getRawHeader(height);
      callback(rawHeader);
      return;
   }
   catch(NoMatch&)
   { }

   auto payload = make_payload(Methods::getHeaderByHeight);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_height(height);

   BinaryData txhash;
   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_RawHeader>(
         cache_, height, txhash, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getLedgerDelegateForScrAddr(
   const string& walletID, BinaryDataRef scrAddr,
   function<void(ReturnMessage<LedgerDelegate>)> callback)
{
   auto payload = make_payload(Methods::getLedgerDelegateForScrAddr);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID);
   command->set_scraddr(scrAddr.getPtr(), scrAddr.getSize());

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerDelegate>(sock_, bdvID_, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::updateWalletsLedgerFilter(
   const vector<BinaryData>& wltIdVec)
{
   auto payload = make_payload(Methods::updateWalletsLedgerFilter);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   for (auto bd : wltIdVec)
      command->add_bindata(bd.getPtr(), bd.getSize());

   sock_->pushPayload(move(payload), nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getNodeStatus(function<
   void(ReturnMessage<shared_ptr<DBClientClasses::NodeStatus>>)> callback)
{
   auto payload = make_payload(Methods::getNodeStatus);
   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_NodeStatus>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::estimateFee(unsigned blocksToConfirm, 
   const string& strategy, 
   function<void(ReturnMessage<FeeEstimateStruct>)> callback)
{
   auto payload = make_payload(Methods::estimateFee);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_value(blocksToConfirm);
   command->add_bindata(strategy);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_FeeEstimateStruct>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getFeeSchedule(const string& strategy, function<void(
   ReturnMessage<map<unsigned, FeeEstimateStruct>>)> callback)
{
   auto payload = make_payload(Methods::getFeeSchedule);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->add_bindata(strategy);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_FeeSchedule>(callback);
   sock_->pushPayload(move(payload), read_payload);
}


///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getHistoryForWalletSelection(
   const vector<string>& wldIDs, const string& orderingStr,
   function<void(ReturnMessage<vector<LedgerEntry>>)> callback)
{
   auto payload = make_payload(Methods::getHistoryForWalletSelection);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   if (orderingStr == "ascending")
      command->set_flag(true);
   else if (orderingStr == "descending")
      command->set_flag(false);
   else
      throw runtime_error("invalid ordering string");

   for (auto& id : wldIDs)
      command->add_bindata(id);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorLedgerEntry>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getSpentnessForOutputs(
   const map<BinaryData, set<unsigned>>& outputs,
   function<void(ReturnMessage<map<BinaryData, map<
      unsigned, SpentnessResult>>>)> callback)
{
   auto payload = make_payload(Methods::getSpentnessForOutputs);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& hashPair : outputs)
   {
      BinaryWriter bw;
      bw.put_BinaryData(hashPair.first);
      bw.put_var_int(hashPair.second.size());
      
      for (auto& id : hashPair.second)
         bw.put_var_int(id);

      command->add_bindata(bw.getDataRef().getPtr(), bw.getSize());
   }

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_SpentnessData>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getSpentnessForZcOutputs(
   const map<BinaryData, set<unsigned>>& outputs,
   function<void(ReturnMessage<map<BinaryData, map<
      unsigned, SpentnessResult>>>)> callback)
{
   auto payload = make_payload(Methods::getSpentnessForZcOutputs);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& hashPair : outputs)
   {
      BinaryWriter bw;
      bw.put_BinaryData(hashPair.first);
      bw.put_var_int(hashPair.second.size());
      
      for (auto& id : hashPair.second)
         bw.put_var_int(id);

      command->add_bindata(bw.getDataRef().getPtr(), bw.getSize());
   }

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_SpentnessData>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::setCheckServerKeyPromptLambda(
   function<bool(const BinaryData&, const string&)> lbd)
{
   auto wsSock = dynamic_pointer_cast<WebSocketClient>(sock_);
   if (wsSock == nullptr)
      return;

   wsSock->setPubkeyPromptLambda(lbd);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getOutputsForOutpoints(
   const map<BinaryData, set<unsigned>>& outpoints, bool withZc,
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = make_payload(Methods::getOutputsForOutpoints);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& hashPair : outpoints)
   {
      BinaryWriter bw;
      bw.put_BinaryData(hashPair.first);
      bw.put_var_int(hashPair.second.size());

      for (auto& id : hashPair.second)
         bw.put_var_int(id);

      command->add_bindata(bw.getDataRef().getPtr(), bw.getSize());
   }

   command->set_flag(withZc);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// LedgerDelegate
//
///////////////////////////////////////////////////////////////////////////////
LedgerDelegate::LedgerDelegate(shared_ptr<SocketPrototype> sock,
   const string& bdvid, const string& ldid) :
   delegateID_(ldid), bdvID_(bdvid), sock_(sock)
{}

///////////////////////////////////////////////////////////////////////////////
void LedgerDelegate::getHistoryPage(uint32_t id, 
   function<void(ReturnMessage<vector<LedgerEntry>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getHistoryPage);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_delegateid(delegateID_);
   command->set_pageid(id);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorLedgerEntry>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void LedgerDelegate::getPageCount(
   function<void(ReturnMessage<uint64_t>)> callback) const
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getPageCountForLedgerDelegate);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_delegateid(delegateID_);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_UINT64>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// BtcWallet
//
///////////////////////////////////////////////////////////////////////////////
AsyncClient::BtcWallet::BtcWallet(const BlockDataViewer& bdv, const string& id) :
   walletID_(id), bdvID_(bdv.bdvID_), sock_(bdv.sock_)
{}

///////////////////////////////////////////////////////////////////////////////
string AsyncClient::BtcWallet::registerAddresses(
   const vector<BinaryData>& addrVec, bool isNew)
{
   auto payload = BlockDataViewer::make_payload(Methods::registerWallet);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_flag(isNew);
   command->set_walletid(walletID_);

   auto&& registrationId = 
      BtcUtils::fortuna_.generateRandom(REGISTER_ID_LENGH).toHexStr();
   command->set_hash(registrationId);

   for (auto& addr : addrVec)
      command->add_bindata(addr.getPtr(), addr.getSize());
   sock_->pushPayload(move(payload), nullptr);

   return registrationId;
}

///////////////////////////////////////////////////////////////////////////////
string AsyncClient::BtcWallet::setUnconfirmedTarget(unsigned confTarget)
{
   auto payload = BlockDataViewer::make_payload(Methods::setWalletConfTarget);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);

   auto&& registrationId = 
      BtcUtils::fortuna_.generateRandom(REGISTER_ID_LENGH).toHexStr();
   command->set_hash(registrationId);
   command->set_height(confTarget);

   sock_->pushPayload(move(payload), nullptr);
   return registrationId;
}

///////////////////////////////////////////////////////////////////////////////
string AsyncClient::BtcWallet::unregisterAddresses(
   const set<BinaryData>& addrSet)
{
   auto payload = BlockDataViewer::make_payload(Methods::unregisterAddresses);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);

   auto&& registrationId = 
      BtcUtils::fortuna_.generateRandom(REGISTER_ID_LENGH).toHexStr();
   command->set_hash(registrationId);

   for (auto& addr : addrSet)
      command->add_bindata(addr.getCharPtr(), addr.getSize());

   sock_->pushPayload(move(payload), nullptr);
   return registrationId;
}

///////////////////////////////////////////////////////////////////////////////
string AsyncClient::BtcWallet::unregister()
{
   return unregisterAddresses({});
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getBalancesAndCount(uint32_t blockheight, 
   function<void(ReturnMessage<vector<uint64_t>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getBalancesAndCount);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);
   command->set_height(blockheight);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUINT64>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getSpendableTxOutListForValue(uint64_t val,
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getSpendableTxOutListForValue);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);
   command->set_value(val);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getSpendableZCList(
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getSpendableZCList);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getRBFTxOutList(
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getRBFTxOutList);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getAddrTxnCountsFromDB(
   function<void(ReturnMessage<map<BinaryData, uint32_t>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getAddrTxnCounts);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Map_BD_U32>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getAddrBalancesFromDB(
   function<void(ReturnMessage<map<BinaryData, vector<uint64_t>>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getAddrBalances);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Map_BD_VecU64>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getHistoryPage(uint32_t id,
   function<void(ReturnMessage<vector<LedgerEntry>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getHistoryPage);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);
   command->set_pageid(id);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorLedgerEntry>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getLedgerEntryForTxHash(
   const BinaryData& txhash, 
   function<void(ReturnMessage<shared_ptr<LedgerEntry>>)> callback)
{  
   //get history page with a hash as argument instead of an int will return 
   //the ledger entry for the tx instead of a page

   auto payload = BlockDataViewer::make_payload(Methods::getHistoryPage);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);
   command->set_hash(txhash.getPtr(), txhash.getSize());

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerEntry>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
ScrAddrObj AsyncClient::BtcWallet::getScrAddrObjByKey(const BinaryData& scrAddr,
   uint64_t full, uint64_t spendable, uint64_t unconf, uint32_t count)
{
   return ScrAddrObj(sock_, bdvID_, walletID_, scrAddr, INT32_MAX,
      full, spendable, unconf, count);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::createAddressBook(
   function<void(ReturnMessage<vector<AddressBookEntry>>)> callback) const
{
   auto payload = BlockDataViewer::make_payload(Methods::createAddressBook);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorAddressBookEntry>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// Lockbox
//
///////////////////////////////////////////////////////////////////////////////
void Lockbox::getBalancesAndCountFromDB(uint32_t topBlockHeight)
{
   auto setValue = [this](ReturnMessage<vector<uint64_t>> int_vec)->void
   {
      auto v = move(int_vec.get());
      if (v.size() != 4)
         throw runtime_error("unexpected vector size");

      fullBalance_ = v[0];
      spendableBalance_ = v[1];
      unconfirmedBalance_ = v[2];

      txnCount_ = v[3];
   };

   BtcWallet::getBalancesAndCount(topBlockHeight, setValue);
}

///////////////////////////////////////////////////////////////////////////////
string AsyncClient::Lockbox::registerAddresses(
   const vector<BinaryData>& addrVec, bool isNew)
{
   auto payload = BlockDataViewer::make_payload(Methods::registerLockbox);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_flag(isNew);
   command->set_walletid(walletID_);
   
   auto&& registrationId = 
      BtcUtils::fortuna_.generateRandom(REGISTER_ID_LENGH).toHexStr();
   command->set_hash(registrationId);

   for (auto& addr : addrVec)
      command->add_bindata(addr.getPtr(), addr.getSize());
   sock_->pushPayload(move(payload), nullptr);

   return registrationId;
}

///////////////////////////////////////////////////////////////////////////////
//
// ScrAddrObj
//
///////////////////////////////////////////////////////////////////////////////
ScrAddrObj::ScrAddrObj(shared_ptr<SocketPrototype> sock, const string& bdvId,
   const string& walletID, const BinaryData& scrAddr, int index,
   uint64_t full, uint64_t spendabe, uint64_t unconf, uint32_t count) :
   bdvID_(bdvId), walletID_(walletID), scrAddr_(scrAddr), sock_(sock),
   fullBalance_(full), spendableBalance_(spendabe),
   unconfirmedBalance_(unconf), count_(count), index_(index)
{}

///////////////////////////////////////////////////////////////////////////////
ScrAddrObj::ScrAddrObj(AsyncClient::BtcWallet* wlt, const BinaryData& scrAddr,
   int index, uint64_t full, uint64_t spendabe, uint64_t unconf, 
   uint32_t count) :
   bdvID_(wlt->bdvID_), walletID_(wlt->walletID_), 
   scrAddr_(scrAddr), sock_(wlt->sock_),
   fullBalance_(full), spendableBalance_(spendabe),
   unconfirmedBalance_(unconf), count_(count), index_(index)
{}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrObj::getSpendableTxOutList(
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getSpendableTxOutListForAddr);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_walletid(walletID_);
   command->set_scraddr(scrAddr_.getPtr(), scrAddr_.getSize());

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// Blockchain
//
///////////////////////////////////////////////////////////////////////////////
AsyncClient::Blockchain::Blockchain(const BlockDataViewer& bdv) :
   sock_(bdv.sock_), bdvID_(bdv.bdvID_)
{}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::Blockchain::getHeaderByHash(const BinaryData& hash,
   function<void(ReturnMessage<DBClientClasses::BlockHeader>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getHeaderByHash);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_hash(hash.getPtr(), hash.getSize());

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_BlockHeader>(UINT32_MAX, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::Blockchain::getHeaderByHeight(unsigned height,
   function<void(ReturnMessage<DBClientClasses::BlockHeader>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getHeaderByHeight);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());
   command->set_height(height);
   
   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_BlockHeader>(height, callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
pair<unsigned, unsigned> AsyncClient::BlockDataViewer::getRekeyCount() const
{
   auto wsSocket = dynamic_pointer_cast<WebSocketClient>(sock_);
   if (wsSocket == nullptr)
      return make_pair(0, 0);

   return wsSocket->getRekeyCount();
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BlockDataViewer::getCombinedBalances(
   const vector<string>& wltIDs,
   function<void(ReturnMessage<map<string, CombinedBalances>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(Methods::getCombinedBalances);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& id : wltIDs)
      command->add_bindata(id);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ = 
      make_unique<CallbackReturn_CombinedBalances>(callback);   
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BlockDataViewer::getCombinedAddrTxnCounts(
   const vector<string>& wltIDs,
   function<void(ReturnMessage<map<string, CombinedCounts>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getCombinedAddrTxnCounts);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& id : wltIDs)
      command->add_bindata(id);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ = 
      make_unique<CallbackReturn_CombinedCounts>(callback);   
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BlockDataViewer::getCombinedSpendableTxOutListForValue(
   const vector<string>& wltIDs, uint64_t value,
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getCombinedSpendableTxOutListForValue);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& id : wltIDs)
      command->add_bindata(id);

   command->set_value(value);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ = 
      make_unique<CallbackReturn_VectorUTXO>(callback);   
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BlockDataViewer::getCombinedSpendableZcOutputs(
   const vector<string>& wltIDs, 
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getCombinedSpendableZcOutputs);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& id : wltIDs)
      command->add_bindata(id);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BlockDataViewer::getCombinedRBFTxOuts(
   const vector<string>& wltIDs,
   function<void(ReturnMessage<vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getCombinedRBFTxOuts);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& id : wltIDs)
      command->add_bindata(id);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BlockDataViewer::getOutpointsForAddresses(
   const std::set<BinaryData>& addrVec, 
   unsigned startHeight, unsigned zcIndexCutoff, 
   std::function<void(ReturnMessage<OutpointBatch>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getOutpointsForAddresses);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   for (auto& id : addrVec)
      command->add_bindata(id.getCharPtr(), id.getSize());

   command->set_height(startHeight);
   command->set_zcid(zcIndexCutoff);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_AddrOutpoints>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BlockDataViewer::getUTXOsForAddress(
   const BinaryData& scrAddr, bool withZc,
   std::function<void(ReturnMessage<std::vector<UTXO>>)> callback)
{
   auto payload = BlockDataViewer::make_payload(
      Methods::getUTXOsForAddress);
   auto command = dynamic_cast<BDVCommand*>(payload->message_.get());

   command->set_scraddr(scrAddr.getCharPtr(), scrAddr.getSize());
   command->set_flag(withZc);

   auto read_payload = make_shared<Socket_ReadPayload>();
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(move(payload), read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// CallbackReturn children
//
///////////////////////////////////////////////////////////////////////////////
void AsyncClient::deserialize(
   google::protobuf::Message* ptr, const WebSocketMessagePartial& partialMsg)
{
   if (!partialMsg.getMessage(ptr))
   {
      ::Codec_BDVCommand::BDV_Error errorMsg;
      if (!partialMsg.getMessage(&errorMsg))
         throw ClientMessageError("unknown error deserializing message", -1);

      throw ClientMessageError(errorMsg.errstr(), errorMsg.code());
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_BinaryDataRef::callback(
   const WebSocketMessagePartial& partialMsg)
{
   auto msg = make_shared<::Codec_CommonTypes::BinaryData>();
   AsyncClient::deserialize(msg.get(), partialMsg);

   auto lbd = [this, msg](void)->void
   {
      auto str = msg->data();
      BinaryDataRef ref;
      ref.setRef(str);
      userCallbackLambda_(ref);
   };

   if (runInCaller())
   {
      lbd();
   }
   else
   {
      thread thr(lbd);
      if (thr.joinable())
         thr.detach();
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_String::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::Strings msg;
      AsyncClient::deserialize(&msg, partialMsg);

      if (msg.data_size() != 1)
         throw ClientMessageError(
            "invalid message in CallbackReturn_String", -1);

      auto str = msg.data(0);
      ReturnMessage<string> rm(str);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<string> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_LedgerDelegate::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::Strings msg;
      AsyncClient::deserialize(&msg, partialMsg);

      if (msg.data_size() != 1)
         throw ClientMessageError(
            "invalid message in CallbackReturn_LedgerDelegate", -1);

      auto& str = msg.data(0);

      LedgerDelegate ld(sockPtr_, bdvID_, str);
      ReturnMessage<LedgerDelegate> rm(ld);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<LedgerDelegate> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Tx::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::TxWithMetaData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      shared_ptr<Tx> tx;
      if (msg.has_rawtx())
      {
         tx = make_shared<Tx>();
         
         auto& rawtx = msg.rawtx();
         BinaryDataRef ref;
         ref.setRef(rawtx);

         tx->unserialize(ref);
         tx->setChainedZC(msg.ischainedzc());
         tx->setRBF(msg.isrbf());
         tx->setTxHeight(msg.height());
         tx->setTxIndex(msg.txindex());
         cache_->insertTx(txHash_, tx);
      }
      else
      {
         auto cachedTx = cache_->getTx_NoConst(txHash_.getRef());
         cachedTx->setTxHeight(msg.height());
         cachedTx->setTxIndex(msg.txindex());
         tx = cachedTx;
      }
      
      auto constTx = const_pointer_cast<const Tx>(tx);
      ReturnMessage<TxResult> rm(move(constTx));

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<TxResult> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_TxBatch::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::ManyTxWithMetaData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      if (!msg.isvalid())
      {
         throw ClientMessageError(
            "invalid TxBatch response", 
            (int)ArmoryErrorCodes::GetTxBatchError_Invalid);
      }

      if ((ssize_t)callMap_.size() != msg.tx_size())
      {
         throw ClientMessageError(
            "call map size mismatch", 
            (int)ArmoryErrorCodes::GetTxBatchError_CallMap);
      }

      unsigned counter = 0;
      for (auto callPair : callMap_)
      {
         auto& txObj = msg.tx(counter++);
         auto& txHash = callPair.first;
         shared_ptr<Tx> tx;

         //invalid tx, no data to deser
         if(txObj.txindex() != UINT32_MAX)
         {
            if (!callPair.second)
            {
               tx = make_shared<Tx>();

               BinaryDataRef ref;
               ref.setRef(txObj.rawtx());

               tx->unserialize(ref);
               tx->setChainedZC(txObj.ischainedzc());
               tx->setRBF(txObj.isrbf());
               tx->setTxHeight(txObj.height());
               tx->setTxIndex(txObj.txindex());

               for (int y = 0; y<txObj.opid_size(); y++)
                  tx->pushBackOpId(txObj.opid(y));
               
               cache_->insertTx(txHash, tx);
            }
            else
            {
               auto txFromCache = cache_->getTx_NoConst(txHash);
               txFromCache->setTxHeight(txObj.height());
               txFromCache->setTxIndex(txObj.txindex());

               for (int y = 0; y<txObj.opid_size(); y++)
                  txFromCache->pushBackOpId(txObj.opid(y));

               tx = txFromCache;
            }
         }

         if (tx == nullptr)
            continue;

         auto constTx = static_pointer_cast<const Tx>(tx);
         cachedTx_[txHash] = constTx;
      }

      ReturnMessage<TxBatchResult> rm(move(cachedTx_));

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<TxBatchResult> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_RawHeader::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::BinaryData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      auto& rawheader = msg.data();
      BinaryDataRef ref; ref.setRef(rawheader);
      BinaryRefReader brr(ref);
      auto&& header = brr.get_BinaryData(HEADER_SIZE);

      if (height_ == UINT32_MAX)
         height_ = brr.get_uint32_t();

      if (txHash_.getSize() != 0)
         cache_->insertHeightForTxHash(txHash_, height_);
      cache_->insertRawHeader(height_, header);

      ReturnMessage<BinaryData> rm(header);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<BinaryData> rm(e);
      userCallbackLambda_(move(rm));
   }
   catch (const runtime_error& e)
   {
      ClientMessageError cme(string(e.what()), -1);
      ReturnMessage<BinaryData> rm(cme);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_NodeStatus::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      auto msg = make_shared<Codec_NodeStatus::NodeStatus>();
      AsyncClient::deserialize(msg.get(), partialMsg);

      auto nss = make_shared<DBClientClasses::NodeStatus>(msg);
      
      ReturnMessage<shared_ptr<DBClientClasses::NodeStatus>> rm(nss);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<shared_ptr<DBClientClasses::NodeStatus>> rm(e);
      userCallbackLambda_(rm);
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_FeeEstimateStruct::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_FeeEstimate::FeeEstimate msg;
      AsyncClient::deserialize(&msg, partialMsg);

      FeeEstimateStruct fes(
         msg.feebyte(), msg.smartfee(), msg.error());

      ReturnMessage<FeeEstimateStruct> rm(fes);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<FeeEstimateStruct> rm(e);
      userCallbackLambda_(rm);
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_FeeSchedule::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_FeeEstimate::FeeSchedule msg;
      AsyncClient::deserialize(&msg, partialMsg);

      map<unsigned, FeeEstimateStruct> result;

      for (int i = 0; i < msg.estimate_size(); i++)
      {
         auto& feeByte = msg.estimate(i);
         FeeEstimateStruct fes(
            feeByte.feebyte(), feeByte.smartfee(), feeByte.error());

         auto target = msg.target(i);
         result.insert(make_pair(target, move(fes)));
      }

      ReturnMessage<map<unsigned, FeeEstimateStruct>> rm(result);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<map<unsigned, FeeEstimateStruct>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorLedgerEntry::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      auto msg = make_shared<::Codec_LedgerEntry::ManyLedgerEntry>();
      AsyncClient::deserialize(msg.get(), partialMsg);


      vector<LedgerEntry> lev;

      for (int i = 0; i < msg->values_size(); i++)
      {
         LedgerEntry le(msg, i);
         lev.push_back(move(le));
      }

      ReturnMessage<vector<LedgerEntry>> rm(lev);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<vector<LedgerEntry>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_UINT64::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::OneUnsigned msg;
      AsyncClient::deserialize(&msg, partialMsg);

      uint64_t result = msg.value();

      ReturnMessage<uint64_t> rm(result);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<uint64_t> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorUTXO::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_Utxo::ManyUtxo utxos;
      AsyncClient::deserialize(&utxos, partialMsg);

      vector<UTXO> utxovec;
      utxovec.reserve(utxos.value_size());
      for (int i = 0; i < utxos.value_size(); i++)
      {
         auto& proto_utxo = utxos.value(i);
         utxovec.emplace_back(UTXO::fromProtobuf(proto_utxo));
      }

      ReturnMessage<vector<UTXO>> rm(utxovec);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<vector<UTXO>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorUINT64::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::ManyUnsigned msg;
      AsyncClient::deserialize(&msg, partialMsg);

      vector<uint64_t> intvec(msg.value_size());
      for (int i = 0; i < msg.value_size(); i++)
         intvec[i] = msg.value(i);

      ReturnMessage<vector<uint64_t>> rm(intvec);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<vector<uint64_t>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Map_BD_U32::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_AddressData::ManyAddressData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      map<BinaryData, uint32_t> bdmap;

      for (int i = 0; i < msg.scraddrdata_size(); i++)
      {
         auto& addrData = msg.scraddrdata(i);
         auto& addr = addrData.scraddr();
         BinaryDataRef addrRef;
         addrRef.setRef(addr);

         if (addrData.value_size() != 1)
            throw runtime_error("invalid msg for CallbackReturn_Map_BD_U32");

         bdmap[addrRef] = addrData.value(0);
      }

      ReturnMessage<map<BinaryData, uint32_t>> rm(bdmap);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<map<BinaryData, uint32_t>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Map_BD_VecU64::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_AddressData::ManyAddressData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      map<BinaryData, vector<uint64_t>> bdMap;
      for (int i = 0; i < msg.scraddrdata_size(); i++)
      {
         auto& addrData = msg.scraddrdata(i);
         auto& addr = addrData.scraddr();
         BinaryDataRef addrRef;
         addrRef.setRef(addr);
         auto& vec = bdMap[addrRef];

         for (int y = 0; y < addrData.value_size(); y++)
            vec.push_back(addrData.value(y));
      }

      ReturnMessage<map<BinaryData, vector<uint64_t>>> rm(bdMap);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<map<BinaryData, vector<uint64_t>>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_LedgerEntry::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      auto msg = make_shared<::Codec_LedgerEntry::LedgerEntry>();
      AsyncClient::deserialize(msg.get(), partialMsg);

      auto le = make_shared<LedgerEntry>(msg);

      ReturnMessage<shared_ptr<LedgerEntry>> rm(le);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<shared_ptr<LedgerEntry>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorAddressBookEntry::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_AddressBook::AddressBook addressBook;
      AsyncClient::deserialize(&addressBook, partialMsg);

      vector<AddressBookEntry> abVec;
      for (int i = 0; i < addressBook.entry_size(); i++)
      {
         auto& entry = addressBook.entry(i);
         AddressBookEntry abe;
         abe.scrAddr_.copyFrom(entry.scraddr());

         for (int y = 0; y < entry.txhash_size(); y++)
         {
            auto& txhash = entry.txhash(y);
            BinaryData bd(txhash.c_str(), txhash.size());
            abe.txHashList_.push_back(move(bd));
         }

         abVec.push_back(move(abe));
      }

      ReturnMessage<vector<AddressBookEntry>> rm(abVec);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<vector<AddressBookEntry>> rm(e);
      userCallbackLambda_(move(rm));
   }
}
///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Bool::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::OneUnsigned msg;
      AsyncClient::deserialize(&msg, partialMsg);

      ReturnMessage<bool> rm(msg.value());

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<bool> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_BlockHeader::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_CommonTypes::BinaryData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      auto& str = msg.data();
      BinaryDataRef ref;
      ref.setRef(str);

      DBClientClasses::BlockHeader bh(ref, height_);

      ReturnMessage<DBClientClasses::BlockHeader> rm(bh);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<DBClientClasses::BlockHeader> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_BDVCallback::callback(
   const WebSocketMessagePartial& partialMsg)
{
   auto msg = make_shared<::Codec_BDVCommand::BDVCallback>();
   AsyncClient::deserialize(msg.get(), partialMsg);

   userCallbackLambda_(msg);
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_CombinedBalances::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_AddressData::ManyCombinedData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      map<string, CombinedBalances> result;

      for (int i=0; i<msg.packedbalance_size(); i++)
      {
         auto wltVals = msg.packedbalance(i);

         CombinedBalances cbal;
         cbal.walletId_.copyFrom(wltVals.id());

         for (int y=0; y<wltVals.idbalances_size(); y++)
            cbal.walletBalanceAndCount_.push_back(wltVals.idbalances(y));

         for (int y=0; y<wltVals.addrdata_size(); y++)
         {
            auto addrBals = wltVals.addrdata(y);
            auto&& scrAddr = BinaryData::fromString(addrBals.scraddr());

            vector<uint64_t> abl;
            for (int z=0; z<addrBals.value_size(); z++)
               abl.push_back(addrBals.value(z));

            cbal.addressBalances_.insert(make_pair(scrAddr, abl));
         }

         result.insert(make_pair(wltVals.id(), cbal));
      }
      
      ReturnMessage<map<string, CombinedBalances>> rm(result);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<map<string, CombinedBalances>> rm(e);
      userCallbackLambda_(move(rm));
   }  
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_CombinedCounts::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_AddressData::ManyCombinedData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      map<string, CombinedCounts> result;

      for (int i=0; i<msg.packedbalance_size(); i++)
      {
         auto wltVals = msg.packedbalance(i);

         CombinedCounts cbal;
         cbal.walletId_.copyFrom(wltVals.id());

         for (int y=0; y<wltVals.addrdata_size(); y++)
         {
            auto addrBals = wltVals.addrdata(y);
            auto&& scrAddr = BinaryData::fromString(addrBals.scraddr());

            uint64_t bl = addrBals.value(0);
            cbal.addressTxnCounts_.insert(make_pair(scrAddr, bl));
         }

         result.insert(make_pair(wltVals.id(), cbal));
      }
      
      ReturnMessage<map<string, CombinedCounts>> rm(result);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<map<string, CombinedCounts>> rm(e);
      userCallbackLambda_(move(rm));
   }  
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_AddrOutpoints::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_Utxo::AddressOutpointsData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      OutpointBatch result;
      result.heightCutoff_ = msg.heightcutoff();
      result.zcIndexCutoff_ = msg.zcindexcutoff();

      for (int i = 0; i < msg.addroutpoints_size(); i++)
      {
         auto& addrOutpoints = msg.addroutpoints(i);
         auto&& scrAddr = BinaryData::fromString(addrOutpoints.scraddr());

         vector<OutpointData> outpointVec(addrOutpoints.outpoints_size());
         for (int y = 0; y < addrOutpoints.outpoints_size(); y++)
         {
            auto& outpoint = addrOutpoints.outpoints(y);
            auto& opData = outpointVec[y];

            opData.value_ = outpoint.value();
            opData.txHeight_ = outpoint.txheight();
            opData.txOutIndex_ = outpoint.txoutindex();
            opData.txHash_.copyFrom(outpoint.txhash());
            opData.isSpent_ = outpoint.isspent();
            opData.txIndex_ = outpoint.txindex();
            if(opData.isSpent_)
               opData.spenderHash_.copyFrom(outpoint.spenderhash());
         }

         result.outpoints_.insert(make_pair(scrAddr, outpointVec));
      }

      ReturnMessage<OutpointBatch> rm(result);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<OutpointBatch> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_SpentnessData::callback(
   const WebSocketMessagePartial& partialMsg)
{
   try
   {
      ::Codec_Utxo::Spentness_BatchData msg;
      AsyncClient::deserialize(&msg, partialMsg);

      if ((ssize_t)msg.count() != msg.txdata_size())
         throw ClientMessageError("malformed spentness payload", -1);

      map<BinaryData, map<unsigned, SpentnessResult>> result;
      for (unsigned i=0; i<msg.count(); i++)
      {
         const auto& txData = msg.txdata(i);
         BinaryDataRef txHashRef; txHashRef.setRef(txData.hash());

         auto& opMap = result[txHashRef];
         for (int y=0; y<txData.outputdata_size(); y++)
         {
            const auto& opData = txData.outputdata(y);
            auto& spentnessData = opMap[opData.txoutindex()];
            
            spentnessData.state_ = (OutputSpentnessState)opData.state();
            switch (spentnessData.state_)
            {
               case OutputSpentnessState::Unspent:
               case OutputSpentnessState::Invalid:
                  break;

               case OutputSpentnessState::Spent:
               {
                  spentnessData.height_ = opData.spenderheight();
                  spentnessData.spender_ = 
                     BinaryData::fromString(opData.spenderhash());
                  break;
               }
            }
         }
      }

      ReturnMessage<map<BinaryData, map<unsigned, SpentnessResult>>> rm(result);

      if (runInCaller())
      {
         userCallbackLambda_(move(rm));
      }
      else
      {
         thread thr(userCallbackLambda_, move(rm));
         if (thr.joinable())
            thr.detach();
      }
   }
   catch (ClientMessageError& e)
   {
      ReturnMessage<map<BinaryData, map<unsigned, SpentnessResult>>> rm(e);
      userCallbackLambda_(move(rm));
   }
}

///////////////////////////////////////////////////////////////////////////////
//
// ClientCache
//
///////////////////////////////////////////////////////////////////////////////
void ClientCache::insertTx(std::shared_ptr<Tx> tx)
{
   ReentrantLock(this);
   txMap_.emplace(tx->getThisHash(), tx);
}

///////////////////////////////////////////////////////////////////////////////
void ClientCache::insertTx(const BinaryData& hash, std::shared_ptr<Tx> tx)
{
   ReentrantLock(this);
   txMap_.emplace(hash, tx);
}

///////////////////////////////////////////////////////////////////////////////
void ClientCache::insertRawHeader(unsigned& height, BinaryDataRef header)
{
   ReentrantLock(this);
   rawHeaderMap_.insert(make_pair(height, header));
}

///////////////////////////////////////////////////////////////////////////////
void ClientCache::insertHeightForTxHash(BinaryData& hash, unsigned& height)
{
   ReentrantLock(this);
   txHashToHeightMap_.insert(make_pair(hash, height));
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<const Tx> ClientCache::getTx(const BinaryDataRef& hashRef) const
{
   ReentrantLock(this);

   auto iter = txMap_.find(hashRef);
   if (iter == txMap_.end())
      throw NoMatch();

   auto constTx = const_pointer_cast<const Tx>(iter->second);
   return constTx;
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<Tx> ClientCache::getTx_NoConst(const BinaryDataRef& hashRef)
{
   ReentrantLock(this);

   auto iter = txMap_.find(hashRef);
   if (iter == txMap_.end())
      throw NoMatch();

   return iter->second;   
}

///////////////////////////////////////////////////////////////////////////////
const BinaryData& ClientCache::getRawHeader(const unsigned& height) const
{
   ReentrantLock(this);

   auto iter = rawHeaderMap_.find(height);
   if (iter == rawHeaderMap_.end())
      throw NoMatch();

   return iter->second;
}

///////////////////////////////////////////////////////////////////////////////
const unsigned& ClientCache::getHeightForTxHash(const BinaryData& height) const
{
   ReentrantLock(this);

   auto iter = txHashToHeightMap_.find(height);
   if (iter == txHashToHeightMap_.end())
      throw NoMatch();

   return iter->second;
}

///////////////////////////////////////////////////////////////////////////////
//
// OutpointBatch/Data
//
///////////////////////////////////////////////////////////////////////////////
void OutpointBatch::prettyPrint() const
{
   stringstream ss;

   ss << " - cutoffs: " << heightCutoff_ << ", " << zcIndexCutoff_ << endl;
   ss << " - address count: " << outpoints_.size() << endl;
   
   for (const auto& addrPair : outpoints_)
   {
      //convert scrAddr to address string
      auto addrStr = BtcUtils::getAddressStrFromScrAddr(addrPair.first);

      //address & outpoint count
      ss << "  ." << addrStr << ", op count: " << 
         addrPair.second.size() << endl;

      //outpoint data
      map<unsigned, map<BinaryDataRef, vector<OutpointData>>> heightHashMap;
      for (const auto& op : addrPair.second)
      {
         auto height = op.txHeight_;
         const auto& hash = op.txHash_;

         auto& hashMap = heightHashMap[height];
         auto& opVec = hashMap[hash.getRef()];
         opVec.emplace_back(op);
      }

      for (const auto& hashMap : heightHashMap)
      {
         ss << "   *height: " << hashMap.first << endl;
         
         for (const auto& opMap : hashMap.second)
         {
            ss << "    .hash: " << opMap.first.toHexStr(true) << endl;

            for (const auto& op : opMap.second)
               op.prettyPrint(ss);
         }
      }

      ss << endl;
   }

   cout << ss.str();
}

///////////////////////////////////////////////////////////////////////////////
void OutpointData::prettyPrint(ostream& st) const
{
   st << "     _id: " << txOutIndex_ << ", value: " << value_ << endl;

   st << "      spender: ";
   if (spenderHash_.empty())
      st << "N/A" << endl;
   else
      st << spenderHash_.toHexStr(true) << endl;
}