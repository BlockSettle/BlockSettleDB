
////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "AsyncClient.h"

using namespace AsyncClient;

///////////////////////////////////////////////////////////////////////////////
//
// BlockDataViewer
//
///////////////////////////////////////////////////////////////////////////////
bool BlockDataViewer::hasRemoteDB(void)
{
   return sock_->testConnection();
}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer BlockDataViewer::getNewBDV(const string& addr,
   const string& port, SocketType st)
{
   shared_ptr<SocketPrototype> sockptr = nullptr;

   switch (st)
   {
   case SocketHttp:
      sockptr = make_shared<HttpSocket>(addr, port);
      break;

   case SocketFcgi:
      sockptr = make_shared<FcgiSocket>(addr, port);
      break;

   case SocketWS:
      sockptr = WebSocketClient::getNew(addr, port);
      break;

   default:
      throw SocketError("unexpected socket type");
   }

   BlockDataViewer bdv(sockptr);
   return bdv;
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::registerWithDB(BinaryData magic_word)
{
   if (bdvID_.size() != 0)
      throw BDVAlreadyRegistered();

   //get bdvID
   try
   {
      Command cmd;
      cmd.method_ = "registerBDV";
      BinaryDataObject bdo(move(magic_word));
      cmd.args_.push_back(move(bdo));

      Socket_WritePayload write_payload;
      cmd.serialize(write_payload.data_);
      
      //registration is always blocking as it needs to guarantee the bdvID

      auto promPtr = make_shared<promise<string>>();
      auto fut = promPtr->get_future();
      auto getResult = [promPtr](string result)->void
      {
         promPtr->set_value(move(result));
      };

      auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
      read_payload->callbackReturn_ =
         make_unique<CallbackReturn_String>(getResult);
      sock_->pushPayload(write_payload, read_payload);
 
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
   if (sock_->type() == SocketWS)
      return;

   Command cmd;
   cmd.method_ = "unregisterBDV";
   cmd.ids_.push_back(bdvID_);

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   sock_->pushPayload(write_payload, nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::goOnline()
{
   Command cmd;
   cmd.method_ = "goOnline";
   cmd.ids_.push_back(bdvID_);
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   sock_->pushPayload(write_payload, nullptr);
}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::BlockDataViewer(void)
{
   txMap_ = make_shared<map<BinaryData, Tx>>();
   rawHeaderMap_ = make_shared<map<BinaryData, BinaryData>>();
}


///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::BlockDataViewer(const shared_ptr<SocketPrototype> sock) :
   sock_(sock)
{
   txMap_ = make_shared<map<BinaryData, Tx>>();
   rawHeaderMap_ = make_shared<map<BinaryData, BinaryData>>();
   sock->connectToRemote(); //TODO: move this to its own method
}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::~BlockDataViewer()
{}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::shutdown(const string& cookie)
{
   Command cmd;
   cmd.method_ = "shutdown";

   if (cookie.size() > 0)
   {
      BinaryDataObject bdo(cookie);
      cmd.args_.push_back(move(bdo));
   }

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   sock_->pushPayload(write_payload, nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::shutdownNode(const string& cookie)
{
   Command cmd;
   cmd.method_ = "shutdownNode";

   if (cookie.size() > 0)
   {
      BinaryDataObject bdo(cookie);
      cmd.args_.push_back(move(bdo));
   }

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   sock_->pushPayload(write_payload, nullptr);
}

///////////////////////////////////////////////////////////////////////////////
AsyncClient::BtcWallet BlockDataViewer::registerWallet(
   const string& id, const vector<BinaryData>& addrVec, bool isNew,
   function<void(bool)> callback)
{
   Command cmd;

   BinaryDataObject bdo(id);
   cmd.args_.push_back(move(bdo));
   cmd.args_.push_back(move(BinaryDataVector(addrVec)));
   cmd.args_.push_back(move(IntType(isNew)));

   cmd.method_ = "registerWallet";
   cmd.ids_.push_back(bdvID_);
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Bool>(callback);

   sock_->pushPayload(write_payload, read_payload);
   return BtcWallet(*this, id);
}

///////////////////////////////////////////////////////////////////////////////
Lockbox BlockDataViewer::registerLockbox(
   const string& id, const vector<BinaryData>& addrVec, bool isNew,
   function<void(bool)> callback)
{
   Command cmd;

   BinaryDataObject bdo(id);
   cmd.args_.push_back(move(bdo));
   cmd.args_.push_back(BinaryDataVector(addrVec));
   cmd.args_.push_back(move(IntType(isNew)));

   cmd.method_ = "registerLockbox";
   cmd.ids_.push_back(bdvID_);
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Bool>(callback);

   sock_->pushPayload(write_payload, read_payload);
   return Lockbox(*this, id, addrVec);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getLedgerDelegateForWallets(
   function<void(LedgerDelegate)> callback)
{
   Command cmd;

   cmd.method_ = "getLedgerDelegateForWallets";
   cmd.ids_.push_back(bdvID_);
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerDelegate>(sock_, bdvID_, callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getLedgerDelegateForLockboxes(
   function<void(LedgerDelegate)> callback)
{
   Command cmd;

   cmd.method_ = "getLedgerDelegateForLockboxes";
   cmd.ids_.push_back(bdvID_);

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerDelegate>(sock_, bdvID_, callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
AsyncClient::Blockchain BlockDataViewer::blockchain(void)
{
   return Blockchain(*this);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::broadcastZC(const BinaryData& rawTx)
{
   auto&& txHash = BtcUtils::getHash256(rawTx.getRef());
   Tx tx(rawTx);
   txMap_->insert(make_pair(txHash, tx));

   Command cmd;

   cmd.method_ = "broadcastZC";
   cmd.ids_.push_back(bdvID_);
   cmd.args_.push_back(BinaryDataObject(rawTx));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);
   sock_->pushPayload(write_payload, nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getTxByHash(const BinaryData& txHash, 
   function<void(Tx)> callback)
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

   auto iter = txMap_->find(bdRef);
   if (iter != txMap_->end())
   {
      callback(iter->second);
      return;
   }

   Command cmd;

   cmd.method_ = "getTxByHash";
   cmd.ids_.push_back(bdvID_);
   cmd.args_.push_back(BinaryDataObject(bdRef));
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Tx>(txMap_, txHash, callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getRawHeaderForTxHash(const BinaryData& txHash,
   function<void(BinaryData)> callback)
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

   auto iter = rawHeaderMap_->find(bdRef);
   if (iter != rawHeaderMap_->end())
   {
      callback(iter->second);
      return;
   }

   Command cmd;

   cmd.method_ = "getRawHeaderForTxHash";
   cmd.ids_.push_back(bdvID_);
   cmd.args_.push_back(BinaryDataObject(bdRef));
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_RawHeader>(rawHeaderMap_, txHash, callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getLedgerDelegateForScrAddr(
   const string& walletID, const BinaryData& scrAddr,
   function<void(LedgerDelegate)> callback)
{
   Command cmd;

   cmd.method_ = "getLedgerDelegateForScrAddr";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID);

   BinaryDataObject bdo(scrAddr);
   cmd.args_.push_back(move(bdo));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerDelegate>(sock_, bdvID_, callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::updateWalletsLedgerFilter(
   const vector<BinaryData>& wltIdVec)
{
   Command cmd;

   cmd.method_ = "updateWalletsLedgerFilter";
   cmd.ids_.push_back(bdvID_);

   BinaryDataVector bdVec;
   for (auto bd : wltIdVec)
      bdVec.push_back(move(bd));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);
   sock_->pushPayload(write_payload, nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getNodeStatus(function<void(NodeStatusStruct)> callback)
{
   Command cmd;

   cmd.method_ = "getNodeStatus";
   cmd.ids_.push_back(bdvID_);

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_NodeStatusStruct>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::estimateFee(unsigned blocksToConfirm, 
   const string& strategy, 
   function<void(ClientClasses::FeeEstimateStruct)> callback)
{
   Command cmd;

   cmd.method_ = "estimateFee";
   cmd.ids_.push_back(bdvID_);

   IntType inttype(blocksToConfirm);
   BinaryDataObject bdo(strategy);

   cmd.args_.push_back(move(inttype));
   cmd.args_.push_back(move(bdo));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_FeeEstimateStruct>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getHistoryForWalletSelection(
   const vector<string>& wldIDs, const string& orderingStr,
   function<void(vector<LedgerEntryData>)> callback)
{
   Command cmd;
   cmd.method_ = "getHistoryForWalletSelection";
   cmd.ids_.push_back(bdvID_);

   BinaryDataVector bdVec;
   for (auto& id : wldIDs)
   {
      BinaryData bd((uint8_t*)id.c_str(), id.size());
      bdVec.push_back(move(bd));
   }

   BinaryDataObject bdo(orderingStr);

   cmd.args_.push_back(move(bdVec));
   cmd.args_.push_back(move(bdo));
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorLedgerEntryData>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getValueForTxOut(const BinaryData& txHash, 
   unsigned inputId, function<void(uint64_t)> callback)
{
   Command cmd;
   cmd.method_ = "getValueForTxOut";
   cmd.ids_.push_back(bdvID_);

   BinaryDataObject bdo(txHash);
   IntType it_inputid(inputId);

   cmd.args_.push_back(move(bdo));
   cmd.args_.push_back(move(it_inputid));
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_UINT64>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::broadcastThroughRPC(const BinaryData& rawTx,
   function<void(string)> callback)
{
   Command cmd;
   cmd.method_ = "broadcastThroughRPC";
   cmd.ids_.push_back(bdvID_);

   BinaryDataObject bdo(rawTx);

   cmd.args_.push_back(move(bdo));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_String>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::registerAddrList(
   const BinaryData& id,
   const vector<BinaryData>& addrVec)
{
   Command cmd;

   cmd.method_ = "registerAddrList";
   cmd.ids_.push_back(bdvID_);

   BinaryDataObject bdo(id);
   BinaryDataVector bdVec;
   for (auto addr : addrVec)
      bdVec.push_back(move(addr));

   cmd.args_.push_back(move(bdo));
   cmd.args_.push_back(move(bdVec));
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);
   sock_->pushPayload(write_payload, nullptr);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::getUtxosForAddrVec(const vector<BinaryData>& addrVec,
   function<void(vector<UTXO>)> callback)
{
   Command cmd;

   cmd.method_ = "getUTXOsForAddrList";
   cmd.ids_.push_back(bdvID_);

   BinaryDataVector bdVec;
   for (auto addr : addrVec)
      bdVec.push_back(move(addr));

   cmd.args_.push_back(move(bdVec));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);
   
   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// LedgerDelegate
//
///////////////////////////////////////////////////////////////////////////////
LedgerDelegate::LedgerDelegate(shared_ptr<SocketPrototype> sock,
   const string& bdvid, const string& ldid) :
   sock_(sock), delegateID_(ldid), bdvID_(bdvid)
{}

///////////////////////////////////////////////////////////////////////////////
void LedgerDelegate::getHistoryPage(uint32_t id, 
   function<void(vector<LedgerEntryData>)> callback)
{
   Command cmd;
   cmd.method_ = "getHistoryPage";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(delegateID_);

   cmd.args_.push_back(move(IntType(id)));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorLedgerEntryData>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// BtcWallet
//
///////////////////////////////////////////////////////////////////////////////
AsyncClient::BtcWallet::BtcWallet(const BlockDataViewer& bdv, const string& id) :
   sock_(bdv.sock_), walletID_(id), bdvID_(bdv.bdvID_)
{}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getBalancesAndCount(uint32_t blockheight, 
   bool IGNOREZC, function<void(vector<uint64_t>)> callback)
{
   Command cmd;
   cmd.method_ = "getBalancesAndCount";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   unsigned int ignorezc = IGNOREZC;
   cmd.args_.push_back(move(IntType(blockheight)));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUINT64>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getSpendableTxOutListForValue(uint64_t val,
   function<void(vector<UTXO>)> callback)
{
   Command cmd;
   cmd.method_ = "getSpendableTxOutListForValue";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   cmd.args_.push_back(move(IntType(val)));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getSpendableZCList(
   function<void(vector<UTXO>)> callback)
{
   Command cmd;
   cmd.method_ = "getSpendableZCList";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getRBFTxOutList(
   function<void(vector<UTXO>)> callback)
{
   Command cmd;
   cmd.method_ = "getRBFTxOutList";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getAddrTxnCountsFromDB(
   function<void(map<BinaryData, uint32_t>)> callback)
{
   Command cmd;
   cmd.method_ = "getAddrTxnCounts";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Map_BD_U32>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getAddrBalancesFromDB(
   function<void(map<BinaryData, vector<uint64_t>>)> callback)
{
   Command cmd;
   cmd.method_ = "getAddrBalances";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Map_BD_VecU64>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getHistoryPage(uint32_t id,
   function<void(vector<LedgerEntryData>)> callback)
{
   Command cmd;
   cmd.method_ = "getHistoryPage";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   cmd.args_.push_back(move(IntType(id)));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorLedgerEntryData>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::BtcWallet::getLedgerEntryForTxHash(
   const BinaryData& txhash, function<void(LedgerEntryData)> callback)
{  
   Command cmd;
   cmd.method_ = "getHistoryPage";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   //get history page with a hash as argument instead of an int will return 
   //the ledger entry for the tx instead of a page
   cmd.args_.push_back(move(BinaryDataObject(txhash)));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_LedgerEntryData>(callback);
   sock_->pushPayload(write_payload, read_payload);
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
   function<void(vector<AddressBookEntry>)> callback) const
{
   Command cmd;
   cmd.method_ = "createAddressBook";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorAddressBookEntry>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
RemoteCallbackSetupStruct BlockDataViewer::getRemoteCallbackSetupStruct() const
{
   auto callback = [this](unsigned height)->void
   {
      this->setTopBlock(height);
   };

   shared_ptr<SocketPrototype> sockPtr;

   switch (sock_->type())
   {
   case SocketHttp:
   {
      sockPtr = 
         make_shared<HttpSocket>(sock_->getAddrStr(), sock_->getPortStr());
      sockPtr->connectToRemote();
      break;
   }

   case SocketFcgi:
   {
      sockPtr =
         make_shared<FcgiSocket>(sock_->getAddrStr(), sock_->getPortStr());
      sockPtr->connectToRemote();
      break;
   }

   default:
      sockPtr = sock_;
   }

   return RemoteCallbackSetupStruct(sockPtr, bdvID_, callback);
}

///////////////////////////////////////////////////////////////////////////////
//
// Lockbox
//
///////////////////////////////////////////////////////////////////////////////
void Lockbox::getBalancesAndCountFromDB(uint32_t topBlockHeight, bool IGNOREZC)
{
   auto setValue = [this](vector<uint64_t> int_vec)->void
   {
      if (int_vec.size() != 4)
         throw runtime_error("unexpected vector size");

      fullBalance_ = int_vec[0];
      spendableBalance_ = int_vec[1];
      unconfirmedBalance_ = int_vec[2];

      txnCount_ = int_vec[3];
   };

   BtcWallet::getBalancesAndCount(topBlockHeight, IGNOREZC, setValue);
}

///////////////////////////////////////////////////////////////////////////////
bool Lockbox::hasScrAddr(const BinaryData& addr) const
{
   auto addrIter = scrAddrSet_.find(addr);
   return addrIter != scrAddrSet_.end();
}

///////////////////////////////////////////////////////////////////////////////
//
// ScrAddrObj
//
///////////////////////////////////////////////////////////////////////////////
ScrAddrObj::ScrAddrObj(shared_ptr<SocketPrototype> sock, const string& bdvId,
   const string& walletID, const BinaryData& scrAddr, int index,
   uint64_t full, uint64_t spendabe, uint64_t unconf, uint32_t count) :
   sock_(sock), bdvID_(bdvId), walletID_(walletID), scrAddr_(scrAddr),
   index_(index), fullBalance_(full), spendableBalance_(spendabe),
   unconfirmedBalance_(unconf), count_(count)
{}

///////////////////////////////////////////////////////////////////////////////
ScrAddrObj::ScrAddrObj(AsyncClient::BtcWallet* wlt, const BinaryData& scrAddr,
   int index, uint64_t full, uint64_t spendabe, uint64_t unconf, uint32_t count) :
   sock_(wlt->sock_), bdvID_(wlt->bdvID_), walletID_(wlt->walletID_),
   scrAddr_(scrAddr), index_(index),
   fullBalance_(full), spendableBalance_(spendabe),
   unconfirmedBalance_(unconf), count_(count)
{}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrObj::getSpendableTxOutList(bool ignoreZC, 
   function<void(vector<UTXO>)> callback)
{
   Command cmd;
   cmd.method_ = "getSpendableTxOutListForAddr";
   cmd.ids_.push_back(bdvID_);
   cmd.ids_.push_back(walletID_);

   BinaryDataObject bdo(scrAddr_);
   cmd.args_.push_back(move(bdo));
   cmd.args_.push_back(move(IntType(ignoreZC)));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_VectorUTXO>(callback);
   sock_->pushPayload(write_payload, read_payload);
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
void AsyncClient::Blockchain::hasHeaderWithHash(const BinaryData& hash,
   function<void(bool)> callback)
{
   Command cmd;
   cmd.method_ = "hasHeaderWithHash";
   cmd.ids_.push_back(bdvID_);

   BinaryDataObject bdo(hash);
   cmd.args_.push_back(move(bdo));

   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_Bool>(callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
void AsyncClient::Blockchain::getHeaderByHeight(unsigned height,
   function<void(ClientClasses::BlockHeader)> callback)
{
   Command cmd;

   cmd.method_ = "getHeaderByHeight";
   cmd.ids_.push_back(bdvID_);
   cmd.args_.push_back(move(IntType(height)));
   
   Socket_WritePayload write_payload;
   cmd.serialize(write_payload.data_);

   auto read_payload = make_shared<Socket_ReadPayload>(cmd.args_.getMessageId());
   read_payload->callbackReturn_ =
      make_unique<CallbackReturn_BlockHeader>(height, callback);
   sock_->pushPayload(write_payload, read_payload);
}

///////////////////////////////////////////////////////////////////////////////
//
// CallbackReturn children
//
///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_BinaryDataRef::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   userCallbackLambda_(bdr);
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_String::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments args(bdr);
   auto&& bdoID = args.get<BinaryDataObject>();
   userCallbackLambda_(move(bdoID.toStr()));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_LedgerDelegate::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments retval(bdr);
   auto&& ldid = retval.get<BinaryDataObject>().toStr();

   LedgerDelegate ld(sockPtr_, bdvID_, ldid);
   userCallbackLambda_(move(ld));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Tx::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments retval(bdr);
   auto&& rawtx = retval.get<BinaryDataObject>();

   Tx tx;
   tx.unserializeWithMetaData(rawtx.get());
   txMap_->insert(move(make_pair(move(txHash_), tx)));
   userCallbackLambda_(move(tx));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_RawHeader::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments retval(bdr);
   auto&& rawheader = retval.get<BinaryDataObject>();

   rawHeaderMap_->insert(move(make_pair(move(txHash_), rawheader.get())));

   userCallbackLambda_(move(rawheader.get()));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_NodeStatusStruct::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments retval(bdr);
   auto&& serData = retval.get<BinaryDataObject>();

   NodeStatusStruct nss;
   nss.deserialize(serData.get());
   
   userCallbackLambda_(move(nss));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_FeeEstimateStruct::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments args(bdr);

   //fee/byte
   auto serData = args.get<BinaryDataObject>();
   BinaryRefReader brr(serData.get().getRef());
   auto val = brr.get_double();

   //issmart
   auto boolObj = args.get<IntType>();
   auto boolVal = bool(boolObj.getVal());

   //error msg
   string error;
   auto errorData = args.get<BinaryDataObject>().get();
   if (errorData.getSize() > 0)
      error = move(string(errorData.getCharPtr(), errorData.getSize()));

   ClientClasses::FeeEstimateStruct fes(val, boolVal, error);
   userCallbackLambda_(move(fes));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorLedgerEntryData::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments args(bdr);

   auto&& lev = args.get<LedgerEntryVector>();
   userCallbackLambda_(move(lev.toVector()));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_UINT64::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments args(bdr);

   auto value = args.get<IntType>();
   userCallbackLambda_(move(value.getVal()));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorUTXO::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments arg(bdr);
   auto count = arg.get<IntType>().getVal();

   vector<UTXO> utxovec;
   for (unsigned i = 0; i < count; i++)
   {
      auto&& bdo = arg.get<BinaryDataObject>();
      UTXO utxo;
      utxo.unserialize(bdo.get());

      utxovec.push_back(move(utxo));
   }

   userCallbackLambda_(move(utxovec));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorUINT64::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments arg(bdr);

   vector<uint64_t> intvec;
   auto&& count = arg.get<IntType>().getVal();

   for (uint64_t i = 0; i < count; i++)
   {
      auto&& val = arg.get<IntType>().getVal();
      intvec.push_back(val);
   }

   userCallbackLambda_(move(intvec));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Map_BD_U32::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments arg(bdr);

   map<BinaryData, uint32_t> bdmap;
   auto&& count = arg.get<IntType>().getVal();

   for (uint64_t i = 0; i < count; i++)
   {
      auto&& addr = arg.get<BinaryDataObject>();
      auto&& txcount = arg.get<IntType>().getVal();

      bdmap[addr.get()] = txcount;
   }

   userCallbackLambda_(move(bdmap));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Map_BD_VecU64::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments arg(bdr);

   map<BinaryData, vector<uint64_t>> bdMap;

   auto&& count = arg.get<IntType>().getVal();
   for (unsigned i = 0; i < count; i++)
   {
      auto&& bd = arg.get<BinaryDataObject>();
      auto& vec = bdMap[bd.get()];

      auto&& count = arg.get<IntType>().getVal();

      for (uint64_t y = 0; y < count; y++)
      {
         vec.push_back(arg.get<IntType>().getVal());
      }
   }

   userCallbackLambda_(move(bdMap));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_LedgerEntryData::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments arg(bdr);
   auto&& lev = arg.get<LedgerEntryVector>();

   auto& levData = lev.toVector();
   userCallbackLambda_(move(levData[0]));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_VectorAddressBookEntry::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments arg(bdr);
   auto count = arg.get<IntType>().getVal();

   vector<AddressBookEntry> abVec;

   for (unsigned i = 0; i < count; i++)
   {
      auto&& bdo = arg.get<BinaryDataObject>();
      AddressBookEntry abe;
      abe.unserialize(bdo.get());

      abVec.push_back(move(abe));
   }

   userCallbackLambda_(move(abVec));
}
///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_Bool::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments arg(bdr);
   auto&& hasHash = arg.get<IntType>().getVal();

   userCallbackLambda_(bool(hasHash));
}

///////////////////////////////////////////////////////////////////////////////
void CallbackReturn_BlockHeader::callback(
   const BinaryDataRef& bdr, exception_ptr eptr)
{
   Arguments retval(bdr);
   auto&& rawheader = retval.get<BinaryDataObject>();

   ClientClasses::BlockHeader bh(rawheader.get(), height_);
   userCallbackLambda_(move(bh));
}