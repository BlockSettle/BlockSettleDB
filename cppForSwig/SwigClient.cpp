
////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "SwigClient.h"

using namespace SwigClient;

///////////////////////////////////////////////////////////////////////////////
//
// BlockDataViewer
//
///////////////////////////////////////////////////////////////////////////////
bool BlockDataViewer::hasRemoteDB(void)
{
   return bdvAsync_.hasRemoteDB();
}

///////////////////////////////////////////////////////////////////////////////
const BlockDataViewer& BlockDataViewer::operator=(const BlockDataViewer& rhs)
{
   bdvAsync_ = rhs.bdvAsync_;

   return *this;
}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer BlockDataViewer::getNewBDV(const string& addr,
   const string& port, SocketType st)
{
   auto&& bdvAsync = AsyncClient::BlockDataViewer::getNewBDV(addr, port, st);
   return BlockDataViewer(bdvAsync);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::registerWithDB(BinaryData magic_word)
{
   //register is blocking with async client
   bdvAsync_.registerWithDB(magic_word);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::unregisterFromDB()
{
   bdvAsync_.unregisterFromDB();
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::goOnline()
{
   bdvAsync_.goOnline();
}


///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::BlockDataViewer(AsyncClient::BlockDataViewer& bdvasync) :
   bdvAsync_(bdvasync)
{}

///////////////////////////////////////////////////////////////////////////////
BlockDataViewer::~BlockDataViewer()
{}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::shutdown(const string& cookie)
{
   bdvAsync_.shutdown(cookie);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::shutdownNode(const string& cookie)
{
   bdvAsync_.shutdownNode(cookie);
}

///////////////////////////////////////////////////////////////////////////////
SwigClient::BtcWallet BlockDataViewer::registerWallet(
   const string& id, const vector<BinaryData>& addrVec, bool isNew)
{
   auto promPtr = make_shared<promise<bool>>();
   auto fut = promPtr->get_future();

   auto callback = [promPtr](bool result)->void
   {
      promPtr->set_value(result);
   };

   auto&& asyncWallet = bdvAsync_.registerWallet(id, addrVec, isNew, callback);

   fut.get();
   return BtcWallet(asyncWallet);
}

///////////////////////////////////////////////////////////////////////////////
Lockbox BlockDataViewer::registerLockbox(
   const string& id, const vector<BinaryData>& addrVec, bool isNew)
{
   auto promPtr = make_shared<promise<bool>>();
   auto fut = promPtr->get_future();

   auto callback = [promPtr](bool result)->void
   {
      promPtr->set_value(result);
   };

   auto&& asyncLocbox = bdvAsync_.registerLockbox(id, addrVec, isNew, callback);

   fut.get();
   return Lockbox(asyncLocbox);
}

///////////////////////////////////////////////////////////////////////////////
LedgerDelegate BlockDataViewer::getLedgerDelegateForWallets()
{
   auto prom = make_shared<promise<LedgerDelegate>>();
   auto fut = prom->get_future();

   auto returnLBD = [prom](AsyncClient::LedgerDelegate as_led)->void
   {
      LedgerDelegate led(as_led);
      prom->set_value(move(led));
   };

   bdvAsync_.getLedgerDelegateForWallets(returnLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
LedgerDelegate BlockDataViewer::getLedgerDelegateForLockboxes()
{
   auto prom = make_shared<promise<LedgerDelegate>>();
   auto fut = prom->get_future();

   auto returnLBD = [prom](AsyncClient::LedgerDelegate as_led)->void
   {
      LedgerDelegate led(as_led);
      prom->set_value(move(led));
   };

   bdvAsync_.getLedgerDelegateForLockboxes(returnLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
SwigClient::Blockchain BlockDataViewer::blockchain(void)
{
   return Blockchain(*this);
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::broadcastZC(const BinaryData& rawTx)
{
   bdvAsync_.broadcastZC(rawTx);
}

///////////////////////////////////////////////////////////////////////////////
Tx BlockDataViewer::getTxByHash(const BinaryData& txHash)
{
   auto prom = make_shared<promise<Tx>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](Tx tx)->void
   {
      prom->set_value(move(tx));
   };

   bdvAsync_.getTxByHash(txHash, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
BinaryData BlockDataViewer::getRawHeaderForTxHash(const BinaryData& txHash)
{
   auto prom = make_shared<promise<BinaryData>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](BinaryData data)->void
   {
      prom->set_value(move(data));
   };

   bdvAsync_.getRawHeaderForTxHash(txHash, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
LedgerDelegate BlockDataViewer::getLedgerDelegateForScrAddr(
   const string& walletID, const BinaryData& scrAddr)
{
   auto prom = make_shared<promise<LedgerDelegate>>();
   auto fut = prom->get_future();

   auto returnLBD = [prom](AsyncClient::LedgerDelegate as_led)->void
   {
      LedgerDelegate led(as_led);
      prom->set_value(move(led));
   };

   bdvAsync_.getLedgerDelegateForScrAddr(walletID, scrAddr, returnLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::updateWalletsLedgerFilter(
   const vector<BinaryData>& wltIdVec)
{
   bdvAsync_.updateWalletsLedgerFilter(wltIdVec);
}

///////////////////////////////////////////////////////////////////////////////
NodeStatusStruct BlockDataViewer::getNodeStatus()
{
   auto prom = make_shared<promise<NodeStatusStruct>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](NodeStatusStruct nss)->void
   {
      prom->set_value(move(nss));
   };

   bdvAsync_.getNodeStatus(resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
ClientClasses::FeeEstimateStruct BlockDataViewer::estimateFee(
   unsigned blocksToConfirm, const string& strategy)
{
   auto prom = make_shared<promise<ClientClasses::FeeEstimateStruct>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](ClientClasses::FeeEstimateStruct fes)->void
   {
      prom->set_value(move(fes));
   };

   bdvAsync_.estimateFee(blocksToConfirm, strategy, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
vector<LedgerEntryData> BlockDataViewer::getHistoryForWalletSelection(
   const vector<string>& wltIDs, const string& orderingStr)
{
   auto prom = make_shared<promise<vector<LedgerEntryData>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<LedgerEntryData> vec)->void
   {
      prom->set_value(move(vec));
   };

   bdvAsync_.getHistoryForWalletSelection(wltIDs, orderingStr, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
uint64_t BlockDataViewer::getValueForTxOut(
   const BinaryData& txHash, unsigned inputId)
{
   auto prom = make_shared<promise<uint64_t>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](uint64_t val)->void
   {
      prom->set_value(move(val));
   };

   bdvAsync_.getValueForTxOut(txHash, inputId, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
string BlockDataViewer::broadcastThroughRPC(const BinaryData& rawTx)
{
   auto prom = make_shared<promise<string>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](string val)->void
   {
      prom->set_value(move(val));
   };

   bdvAsync_.broadcastThroughRPC(rawTx, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
void BlockDataViewer::registerAddrList(
   const BinaryData& id,
   const vector<BinaryData>& addrVec)
{
   bdvAsync_.registerAddrList(id, addrVec);
}

///////////////////////////////////////////////////////////////////////////////
vector<UTXO> BlockDataViewer::getUtxosForAddrVec(
   const vector<BinaryData>& addrVec)
{
   auto prom = make_shared<promise<vector<UTXO>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<UTXO> vec)->void
   {
      prom->set_value(move(vec));
   };

   bdvAsync_.getUtxosForAddrVec(addrVec, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
unsigned BlockDataViewer::getTopBlock() const
{
   return bdvAsync_.getTopBlock();
}

///////////////////////////////////////////////////////////////////////////////
bool BlockDataViewer::isValid() const
{
   return bdvAsync_.isValid();
}

///////////////////////////////////////////////////////////////////////////////
const string& BlockDataViewer::getID() const
{
   return bdvAsync_.getID();
}

///////////////////////////////////////////////////////////////////////////////
//
// LedgerDelegate
//
///////////////////////////////////////////////////////////////////////////////
LedgerDelegate::LedgerDelegate(AsyncClient::LedgerDelegate& led) :
   asyncLed_(move(led))
{}

///////////////////////////////////////////////////////////////////////////////
vector<LedgerEntryData> LedgerDelegate::getHistoryPage(uint32_t id)
{
   auto prom = make_shared<promise<vector<LedgerEntryData>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<LedgerEntryData> vec)->void
   {
      prom->set_value(move(vec));
   };

   asyncLed_.getHistoryPage(id, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
//
// BtcWallet
//
///////////////////////////////////////////////////////////////////////////////
SwigClient::BtcWallet::BtcWallet(AsyncClient::BtcWallet& wlt) :
   asyncWallet_(move(wlt))
{}

///////////////////////////////////////////////////////////////////////////////
vector<uint64_t> SwigClient::BtcWallet::getBalancesAndCount(
   uint32_t blockheight, bool IGNOREZC)
{
   auto prom = make_shared<promise<vector<uint64_t>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<uint64_t> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getBalancesAndCount(blockheight, IGNOREZC, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
vector<UTXO> SwigClient::BtcWallet::getSpendableTxOutListForValue(uint64_t val)
{
   auto prom = make_shared<promise<vector<UTXO>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<UTXO> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getSpendableTxOutListForValue(val, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
vector<UTXO> SwigClient::BtcWallet::getSpendableZCList()
{
   auto prom = make_shared<promise<vector<UTXO>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<UTXO> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getSpendableZCList(resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
vector<UTXO> SwigClient::BtcWallet::getRBFTxOutList()
{
   auto prom = make_shared<promise<vector<UTXO>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<UTXO> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getRBFTxOutList(resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
map<BinaryData, uint32_t> SwigClient::BtcWallet::getAddrTxnCountsFromDB()
{
   auto prom = make_shared<promise<map<BinaryData, uint32_t>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](map<BinaryData, uint32_t> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getAddrTxnCountsFromDB(resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
map<BinaryData, vector<uint64_t>>
   SwigClient::BtcWallet::getAddrBalancesFromDB(void)
{
   auto prom = make_shared<promise<map<BinaryData, vector<uint64_t>>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](map<BinaryData, vector<uint64_t>> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getAddrBalancesFromDB(resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
vector<LedgerEntryData> SwigClient::BtcWallet::getHistoryPage(uint32_t id)
{
   auto prom = make_shared<promise<vector<LedgerEntryData>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<LedgerEntryData> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getHistoryPage(id, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
LedgerEntryData SwigClient::BtcWallet::getLedgerEntryForTxHash(
   const BinaryData& txhash)
{
   auto prom = make_shared<promise<LedgerEntryData>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](LedgerEntryData val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.getLedgerEntryForTxHash(txhash, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
ScrAddrObj SwigClient::BtcWallet::getScrAddrObjByKey(const BinaryData& scrAddr,
   uint64_t full, uint64_t spendable, uint64_t unconf, uint32_t count)
{
   auto&& asyncAddr = 
      asyncWallet_.getScrAddrObjByKey(scrAddr, full, spendable, unconf, count);
   return ScrAddrObj(asyncAddr);
}

///////////////////////////////////////////////////////////////////////////////
vector<AddressBookEntry> SwigClient::BtcWallet::createAddressBook(void) const
{
   auto prom = make_shared<promise<vector<AddressBookEntry>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<AddressBookEntry> val)->void
   {
      prom->set_value(move(val));
   };

   asyncWallet_.createAddressBook(resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
//
// Lockbox
//
///////////////////////////////////////////////////////////////////////////////
Lockbox::Lockbox(AsyncClient::Lockbox& asynclb) :
asyncLockbox_(asynclb), BtcWallet(asynclb)
{}

///////////////////////////////////////////////////////////////////////////////
void Lockbox::getBalancesAndCountFromDB(uint32_t topBlockHeight, bool IGNOREZC)
{
   asyncLockbox_.getBalancesAndCountFromDB(topBlockHeight, IGNOREZC);
}

///////////////////////////////////////////////////////////////////////////////
bool Lockbox::hasScrAddr(const BinaryData& addr) const
{
   //TODO: revisit this method once network refactor congeals
   return asyncLockbox_.hasScrAddr(addr);
}

///////////////////////////////////////////////////////////////////////////////
uint64_t Lockbox::getFullBalance() const
{
   return asyncLockbox_.getFullBalance();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t Lockbox::getSpendableBalance() const
{
   return asyncLockbox_.getSpendableBalance();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t Lockbox::getUnconfirmedBalance() const
{
   return asyncLockbox_.getUnconfirmedBalance();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t Lockbox::getWltTotalTxnCount() const
{
   return asyncLockbox_.getWltTotalTxnCount();
}

///////////////////////////////////////////////////////////////////////////////
//
// ScrAddrObj
//
///////////////////////////////////////////////////////////////////////////////
ScrAddrObj::ScrAddrObj(AsyncClient::ScrAddrObj& asyncAddr) :
   asyncAddr_(move(asyncAddr))
{}

///////////////////////////////////////////////////////////////////////////////
vector<UTXO> ScrAddrObj::getSpendableTxOutList(bool ignoreZC)
{
   auto prom = make_shared<promise<vector<UTXO>>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](vector<UTXO> val)->void
   {
      prom->set_value(move(val));
   };

   asyncAddr_.getSpendableTxOutList(ignoreZC, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
uint64_t ScrAddrObj::getFullBalance(void) const
{
   return asyncAddr_.getFullBalance();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t ScrAddrObj::getSpendableBalance(void) const
{
   return asyncAddr_.getSpendableBalance();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t ScrAddrObj::getUnconfirmedBalance(void) const
{
   return asyncAddr_.getUnconfirmedBalance();
}

///////////////////////////////////////////////////////////////////////////////
uint64_t ScrAddrObj::getTxioCount(void) const
{
   return asyncAddr_.getTxioCount();
}

///////////////////////////////////////////////////////////////////////////////
const BinaryData& ScrAddrObj::getScrAddr(void) const
{
   return asyncAddr_.getScrAddr();
}

///////////////////////////////////////////////////////////////////////////////
const BinaryData& ScrAddrObj::getAddrHash(void) const
{
   return asyncAddr_.getAddrHash();
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrObj::setComment(const string& comment)
{
   return asyncAddr_.setComment(comment);
}

///////////////////////////////////////////////////////////////////////////////
const string& ScrAddrObj::getComment(void) const
{
   return asyncAddr_.getComment();
}

///////////////////////////////////////////////////////////////////////////////
int ScrAddrObj::getIndex(void) const
{
   return asyncAddr_.getIndex();
}

///////////////////////////////////////////////////////////////////////////////
//
// Blockchain
//
///////////////////////////////////////////////////////////////////////////////
SwigClient::Blockchain::Blockchain(const BlockDataViewer& bdv) :
   asyncBlockchain_(bdv.bdvAsync_)
{}

///////////////////////////////////////////////////////////////////////////////
bool SwigClient::Blockchain::hasHeaderWithHash(const BinaryData& hash)
{
   auto prom = make_shared<promise<bool>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](bool val)->void
   {
      prom->set_value(move(val));
   };

   asyncBlockchain_.hasHeaderWithHash(hash, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
ClientClasses::BlockHeader SwigClient::Blockchain::getHeaderByHeight(unsigned height)
{
   auto prom = make_shared<promise<ClientClasses::BlockHeader>>();
   auto fut = prom->get_future();

   auto resultLBD = [prom](ClientClasses::BlockHeader val)->void
   {
      prom->set_value(move(val));
   };

   asyncBlockchain_.getHeaderByHeight(height, resultLBD);
   return move(fut.get());
}

///////////////////////////////////////////////////////////////////////////////
//
// ProcessMutex
//
///////////////////////////////////////////////////////////////////////////////
ProcessMutex::~ProcessMutex()
{}

///////////////////////////////////////////////////////////////////////////////
bool ProcessMutex::acquire()
{
   {
      string str;
      if (test(str))
         return false;
   }

   auto holdldb = [this]()
   {
      this->hodl();
   };

   holdThr_ = thread(holdldb);
   return true;
}

///////////////////////////////////////////////////////////////////////////////
bool ProcessMutex::test(const string& uriLink)
{
   auto sock = SimpleSocket(addr_, port_);

   if (!sock.openSocket(false))
      return false;

   try
   {
      BinaryWriter bw;
      BinaryDataRef bdr;
      bdr.setRef(uriLink);

      bw.put_var_int(uriLink.size());
      bw.put_BinaryDataRef(bdr);
      auto bwRef = bw.getDataRef();

      //serialize argv
      Socket_WritePayload payload;
      payload.data_.resize(bwRef.getSize());
      memcpy(&payload.data_[0], bwRef.getPtr(), bwRef.getSize());
      sock.pushPayload(payload, nullptr);
   }
   catch (...)
   {
      return false;
   }
   
   return true;
}

///////////////////////////////////////////////////////////////////////////////
void ProcessMutex::hodl()
{
   auto server = make_unique<ListenServer>(addr_, port_);
   
   auto readLdb = [this](vector<uint8_t> data, exception_ptr eptr)->bool
   {
      if (data.size() == 0 || eptr != nullptr)
         return false;

      //unserialize urilink
      string urilink;

      try
      {
         BinaryDataRef bdr(&data[0], data.size());
         BinaryRefReader brr(bdr);

         auto len = brr.get_var_int();
         auto uriRef = brr.get_BinaryDataRef(len);

         urilink = move(string((char*)uriRef.getPtr(), len));
      }
      catch (...)
      {
         return false;
      }

      //callback
      mutexCallback(urilink);

      //return false to close the socket
      return false;
   };

   server->start(readLdb);
   server->join();
}
