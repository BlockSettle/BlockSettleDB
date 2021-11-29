////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                                                                            //
//  Copyright (C) 2016-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////
#include "TestUtils.h"
#include "BIP15x_Handshake.h"

using namespace std;
using namespace Codec_BDVCommand;

using namespace Armory::Assets;
using namespace Armory::Wallets;

#if ! defined(_MSC_VER) && ! defined(__MINGW32__)

   /////////////////////////////////////////////////////////////////////////////
   void mkdir(string newdir)
   {
      char* syscmd = new char[4096];
      sprintf(syscmd, "mkdir -p %s", newdir.c_str());
      system(syscmd);
      delete[] syscmd;
   }
#endif

////////////////////////////////////////////////////////////////////////////////
namespace TestUtils
{

   /////////////////////////////////////////////////////////////////////////////
   bool searchFile(const string& filename, BinaryData& data)
   {
      //create mmap of file
      auto filemap = DBUtils::getMmapOfFile(filename);

      if (data.getSize() < 8)
         throw runtime_error("only for buffers 8 bytes and larger");

      //search it
      uint64_t sample;
      uint64_t* data_head = (uint64_t*)data.getPtr();

      bool result = false;
      for (unsigned i = 0; i < filemap.size_ - data.getSize(); i++)
      {
         memcpy(&sample, filemap.filePtr_ + i, 8);
         if (sample == *data_head)
         {
            BinaryDataRef bdr(filemap.filePtr_ + i, data.getSize());
            if (bdr == data.getRef())
            {
               result = true;
               break;
            }
         }
      }

      //clean up
      filemap.unmap();

      //return
      return result;
   }

   /////////////////////////////////////////////////////////////////////////////
   uint32_t getTopBlockHeightInDB(BlockDataManager &bdm, DB_SELECT db)
   {
      StoredDBInfo sdbi;
      bdm.getIFace()->getStoredDBInfo(db, 0);
      return sdbi.topBlkHgt_;
   }

   /////////////////////////////////////////////////////////////////////////////
   uint64_t getDBBalanceForHash160(
      BlockDataManager &bdm,
      BinaryDataRef addr160
      )
   {
      StoredScriptHistory ssh;

      bdm.getIFace()->getStoredScriptHistory(ssh, HASH160PREFIX + addr160);
      if (!ssh.isInitialized())
         return 0;

      return ssh.getScriptBalance();
   }

   /////////////////////////////////////////////////////////////////////////////
   int char2int(char input)
   {
      if (input >= '0' && input <= '9')
         return input - '0';
      if (input >= 'A' && input <= 'F')
         return input - 'A' + 10;
      if (input >= 'a' && input <= 'f')
         return input - 'a' + 10;
      return 0;
   }

   /////////////////////////////////////////////////////////////////////////////
   void hex2bin(const char* src, unsigned char* target)
   {
      while (*src && src[1])
      {
         *(target++) = char2int(*src) * 16 + char2int(src[1]);
         src += 2;
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   void concatFile(const string &from, const string &to)
   {
      std::ifstream i(from, ios::binary);
      std::ofstream o(to, ios::app | ios::binary);

      o << i.rdbuf();
   }

   /////////////////////////////////////////////////////////////////////////////
   void appendBlocks(const std::vector<std::string> &files, const std::string &to)
   {
      for (const std::string &f : files)
         concatFile("../reorgTest/blk_" + f + ".dat", to);
   }

   /////////////////////////////////////////////////////////////////////////////
   void setBlocks(const std::vector<std::string> &files, const std::string &to)
   {
      std::ofstream o(to, ios::trunc | ios::binary);
      o.close();

      for (const std::string &f : files)
         concatFile("../reorgTest/blk_" + f + ".dat", to);
   }

   /////////////////////////////////////////////////////////////////////////////
   void nullProgress(unsigned, double, unsigned, unsigned)
   {}

   /////////////////////////////////////////////////////////////////////////////
   BinaryData getTx(unsigned height, unsigned id)
   {
      stringstream ss;
      ss << "../reorgTest/blk_" << height << ".dat";

      ifstream blkfile(ss.str(), ios::binary);
      blkfile.seekg(0, ios::end);
      auto size = blkfile.tellg();
      blkfile.seekg(0, ios::beg);

      vector<char> vec;
      vec.resize(size);
      blkfile.read(&vec[0], size);
      blkfile.close();

      BinaryRefReader brr((uint8_t*)&vec[0], size);
      StoredHeader sbh;
      sbh.unserializeFullBlock(brr, false, true);

      if (sbh.stxMap_.size() - 1 < id)
         throw range_error("invalid tx id");

      auto& stx = sbh.stxMap_[id];
      return stx.dataCopy_;
   }

   ////////////////////////////////////////////////////////////////////////////////
   std::shared_ptr<AssetEntry> getMainAccountAssetForIndex(
      std::shared_ptr<AssetWallet> wlt, Armory::Wallets::AssetKeyType index)
   {
      auto mainAcc = wlt->getAccountForID(wlt->getMainAccountID());
      auto outerAcc = mainAcc->getOuterAccount();
      return outerAcc->getAssetForKey(index);
   }

   ////////////////////////////////////////////////////////////////////////////////
   size_t getMainAccountAssetCount(std::shared_ptr<AssetWallet> wlt)
   {
      auto mainAcc = wlt->getAccountForID(wlt->getMainAccountID());
      auto outerAcc = mainAcc->getOuterAccount();
      return outerAcc->getAssetCount();
   }
}

////////////////////////////////////////////////////////////////////////////////
namespace DBTestUtils
{
   unsigned commandCtr_ = 0;
   deque<unsigned> zcDelays_;

   /////////////////////////////////////////////////////////////////////////////
   unsigned getTopBlockHeight(LMDBBlockDatabase* db, DB_SELECT dbSelect)
   {
      auto&& sdbi = db->getStoredDBInfo(dbSelect, 0);
      return sdbi.topBlkHgt_;
   }

   /////////////////////////////////////////////////////////////////////////////
   BinaryData getTopBlockHash(LMDBBlockDatabase* db, DB_SELECT dbSelect)
   {
      auto&& sdbi = db->getStoredDBInfo(dbSelect, 0);
      return sdbi.topScannedBlkHash_;
   }

   /////////////////////////////////////////////////////////////////////////////
   string registerBDV(Clients* clients, const BinaryData& magic_word)
   {
      auto message = make_shared<StaticCommand>();
      message->set_method(StaticMethods::registerBDV);
      message->set_magicword(magic_word.getPtr(), magic_word.getSize());

      auto&& result = clients->processUnregisteredCommand(0, message);
      auto response =
         dynamic_pointer_cast<::Codec_CommonTypes::BinaryData>(result);

      return response->data();
   }

   /////////////////////////////////////////////////////////////////////////////
   void goOnline(Clients* clients, const string& id)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::goOnline);
      message->set_bdvid(id);

      processCommand(clients, message);
   }

   /////////////////////////////////////////////////////////////////////////////
   const shared_ptr<BDV_Server_Object> getBDV(Clients* clients, const string& id)
   {
      return clients->get(id);
   }

   /////////////////////////////////////////////////////////////////////////////
   void registerWallet(Clients* clients, const string& bdvId,
      const vector<BinaryData>& scrAddrs, const string& wltName)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::registerWallet);
      message->set_bdvid(bdvId);
      message->set_walletid(wltName);
      message->set_flag(false);
      auto&& id = CryptoPRNG::generateRandom(5).toHexStr();
      message->set_hash(id);

      for (auto& scrAddr : scrAddrs)
         message->add_bindata(scrAddr.getPtr(), scrAddr.getSize());

      processCommand(clients, message);
      while (1)
      {
         auto&& callbackPtr = waitOnSignal(clients, bdvId, NotificationType::refresh);
         auto& notif = get<0>(callbackPtr)->notification(get<1>(callbackPtr));
         
         if (!notif.has_refresh())
            continue;

         auto& refresh = notif.refresh();
         for (int i = 0; i < refresh.id_size(); i++)
         {
            if (refresh.id(i) == id)
               return;
         }
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   void regLockbox(Clients* clients, const string& bdvId,
      const vector<BinaryData>& scrAddrs, const string& wltName)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::registerLockbox);
      message->set_bdvid(bdvId);
      message->set_walletid(wltName);
      message->set_flag(false);
      auto&& id = CryptoPRNG::generateRandom(5).toHexStr();
      message->set_hash(id);

      for (auto& scrAddr : scrAddrs)
         message->add_bindata(scrAddr.getPtr(), scrAddr.getSize());

      processCommand(clients, message);
      while (1)
      {
         auto&& callbackPtr = waitOnSignal(clients, bdvId, NotificationType::refresh);
         auto& notif = get<0>(callbackPtr)->notification(get<1>(callbackPtr));

         if (!notif.has_refresh())
            continue;

         auto& refresh = notif.refresh();
         for (int i = 0; i < refresh.id_size(); i++)
         {
            if (refresh.id(i) == id)
               return;
         }
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   vector<uint64_t> getBalanceAndCount(Clients* clients,
      const string& bdvId, const string& walletId, unsigned blockheight)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::getBalancesAndCount);
      message->set_bdvid(bdvId);
      message->set_walletid(walletId);
      message->set_height(blockheight);

      auto&& result = processCommand(clients, message);
      auto response =
         dynamic_pointer_cast<::Codec_CommonTypes::ManyUnsigned>(result);

      auto&& balance_full = response->value(0);
      auto&& balance_spen = response->value(1);
      auto&& balance_unco = response->value(2);
      auto&& count = response->value(3);

      vector<uint64_t> balanceVec;
      balanceVec.push_back(balance_full);
      balanceVec.push_back(balance_spen);
      balanceVec.push_back(balance_unco);
      balanceVec.push_back(count);

      return balanceVec;
   }

   /////////////////////////////////////////////////////////////////////////////
   string getLedgerDelegate(Clients* clients, const string& bdvId)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::getLedgerDelegateForWallets);
      message->set_bdvid(bdvId);

      //check result
      auto&& result = processCommand(clients, message);
      auto response =
         dynamic_pointer_cast<::Codec_CommonTypes::Strings>(result);
      return response->data(0);
   }

   /////////////////////////////////////////////////////////////////////////////
   vector<DBClientClasses::LedgerEntry> getHistoryPage(
      Clients* clients, const string& bdvId,
      const string& delegateId, uint32_t pageId)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::getHistoryPage);
      message->set_bdvid(bdvId);
      message->set_delegateid(delegateId);
      message->set_pageid(pageId);


      auto&& result = processCommand(clients, message);
      auto response =
         dynamic_pointer_cast<Codec_LedgerEntry::ManyLedgerEntry>(result);

      vector<DBClientClasses::LedgerEntry> levData;
      for (int i = 0; i < response->values_size(); i++)
      {
         DBClientClasses::LedgerEntry led(response, i);
         levData.push_back(led);
      }

      return levData;
   }

   /////////////////////////////////////////////////////////////////////////////
   tuple<shared_ptr<BDVCallback>, unsigned> waitOnSignal(
      Clients* clients, const string& bdvId, NotificationType signal)
   {
      shared_ptr<BDVCallback> callbackPtr;
      unsigned index;

      auto processCallback =
      [&](shared_ptr<::google::protobuf::Message> cmd)->bool
      {
         auto notifPtr = dynamic_pointer_cast<BDVCallback>(cmd);
         for (int i = 0; i < notifPtr->notification_size(); i++)
         {
            auto& notif = notifPtr->notification(i);
            if (notif.type() == signal)
            {
               callbackPtr = notifPtr;
               index = i;
               return true;
            }
         }

         return false;
      };

      auto bdv_obj = clients->get(bdvId);
      auto cbPtr = bdv_obj->cb_.get();
      auto unittest_cbptr = dynamic_cast<UnitTest_Callback*>(cbPtr);
      if (unittest_cbptr == nullptr)
         throw runtime_error("unexpected callback ptr type");

      while (true)
      {
         auto&& notifPtr = unittest_cbptr->getNotification();
         if (processCallback(notifPtr))
            return make_tuple(callbackPtr, index);
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   void waitOnBDMReady(Clients* clients, const string& bdvId)
   {
      waitOnSignal(clients, bdvId, NotificationType::ready);
   }

   /////////////////////////////////////////////////////////////////////////////
   tuple<shared_ptr<BDVCallback>, unsigned> waitOnNewBlockSignal(
      Clients* clients, const string& bdvId)
   {
      return waitOnSignal(clients, bdvId, NotificationType::newblock);
   }

   /////////////////////////////////////////////////////////////////////////////
   pair<vector<DBClientClasses::LedgerEntry>, set<BinaryData>> waitOnNewZcSignal(
      Clients* clients, const string& bdvId)
   {
      auto&& result = waitOnSignal(
         clients, bdvId, NotificationType::zc);

      auto& callbackPtr = get<0>(result);
      auto& index = get<1>(result);
      auto& notif = callbackPtr->notification(index);

      if (!notif.has_ledgers())
      {
         cout << "invalid result vector size in waitOnNewZcSignal";
         throw runtime_error("");
      }

      auto lev = notif.ledgers();

      pair<vector<DBClientClasses::LedgerEntry>, set<BinaryData>> levData;
      for (int i = 0; i < lev.values_size(); i++)
      {
         DBClientClasses::LedgerEntry led(callbackPtr, index, i);
         levData.first.push_back(led);
      }

      if (callbackPtr->notification_size() >= (int)index + 2)
      {
         auto& invalidated_notif = callbackPtr->notification(index + 1);
         if (invalidated_notif.has_ids())
         {
            auto ids = invalidated_notif.ids();
            for (int i = 0; i < ids.value_size(); i++)
            {
               auto& id_str = ids.value(i).data();
               BinaryData id_bd((uint8_t*)id_str.c_str(), id_str.size());
               levData.second.insert(id_bd);
            }
         }
      }

      return levData;
   }

   /////////////////////////////////////////////////////////////////////////////
   void waitOnWalletRefresh(Clients* clients, const string& bdvId,
      const BinaryData& wltId)
   {
      while (1)
      {
         auto&& result = waitOnSignal(
            clients, bdvId, NotificationType::refresh);

         if (wltId.getSize() == 0)
            return;

         auto& callbackPtr = get<0>(result);
         auto& index = get<1>(result);
         auto& notif = callbackPtr->notification(index);
         
         if (!notif.has_refresh())
         {
            cout << "invalid result vector size in waitOnWalletRefresh";
            throw runtime_error("");
         }

         auto& refresh = notif.refresh();
         for (int i = 0; i < refresh.id_size(); i++)
         {
            auto& id = notif.refresh().id(i);
            BinaryDataRef bdr;
            bdr.setRef(id);
            if (bdr == wltId)
               return;
         }
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   void triggerNewBlockNotification(BlockDataManagerThread* bdmt)
   {
      auto nodePtr = bdmt->bdm()->processNode_;
      auto nodeUnitTest = (NodeUnitTest*)nodePtr.get();

      nodeUnitTest->notifyNewBlock();
   }

   /////////////////////////////////////////////////////////////////////////////
   void mineNewBlock(BlockDataManagerThread* bdmt, const BinaryData& h160, 
      unsigned count)
   {
      auto nodePtr = bdmt->bdm()->processNode_;
      auto nodeUnitTest = (NodeUnitTest*)nodePtr.get();

      nodeUnitTest->mineNewBlock(bdmt->bdm(), count, h160);
   }

   /////////////////////////////////////////////////////////////////////////////
   std::vector<UnitTestBlock> getMinedBlocks(BlockDataManagerThread* bdmt)
   {
      auto nodePtr = bdmt->bdm()->processNode_;
      auto nodeUnitTest = (NodeUnitTest*)nodePtr.get();

      return nodeUnitTest->getMinedBlocks();
   }

   /////////////////////////////////////////////////////////////////////////////
   void setReorgBranchingPoint(
      BlockDataManagerThread* bdmt, const BinaryData& hash)
   {
      auto nodePtr = bdmt->bdm()->processNode_;
      auto nodeUnitTest = (NodeUnitTest*)nodePtr.get();

      auto headerPtr = bdmt->bdm()->blockchain()->getHeaderByHash(hash);
      nodeUnitTest->setReorgBranchPoint(headerPtr);
   }

   /////////////////////////////////////////////////////////////////////////////
   void pushNewZc(BlockDataManagerThread* bdmt, const ZcVector& zcVec, 
      bool stage)
   {
      auto nodePtr = bdmt->bdm()->processNode_;
      auto nodeUnitTest = (NodeUnitTest*)nodePtr.get();

      unsigned delay = UINT32_MAX;
      if (zcDelays_.size() != 0)
      {
         delay = zcDelays_.front();
         zcDelays_.pop_front();
      }

      std::vector<pair<BinaryData, unsigned>> txVec;
      for (auto& newzc : zcVec.zcVec_)
      {
         BinaryData bdTx(newzc.first.getPtr(), newzc.first.getSize());

         auto localDelay = newzc.second;
         if (newzc.second == 0 && delay != UINT32_MAX)
            localDelay = delay;

         txVec.push_back(make_pair(bdTx, localDelay));
      }

      nodeUnitTest->pushZC(txVec, stage);
   }

   /////////////////////////////////////////////////////////////////////////////
   void setNextZcPushDelay(unsigned delay)
   {
      zcDelays_.push_back(delay);
   }

   /////////////////////////////////////////////////////////////////////////////
   pair<BinaryData, BinaryData> getAddrAndPubKeyFromPrivKey(
      BinaryData privKey, bool compressed)
   {
      auto&& pubkey = CryptoECDSA().ComputePublicKey(privKey, compressed);
      auto&& h160 = BtcUtils::getHash160(pubkey);

      pair<BinaryData, BinaryData> result;
      result.second = pubkey;
      result.first = h160;

      return result;
   }

   /////////////////////////////////////////////////////////////////////////////
   Tx getTxByHash(Clients* clients, const string bdvId,
      const BinaryData& txHash)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::getTxByHash);
      message->set_bdvid(bdvId);
      message->set_hash(txHash.getPtr(), txHash.getSize());

      auto&& result = processCommand(clients, message);
      auto response =
         dynamic_pointer_cast<::Codec_CommonTypes::TxWithMetaData>(result);
      if (response == nullptr)
         throw runtime_error("getTxByHash failed");
      
      auto& txstr = response->rawtx();
      BinaryDataRef txbdr; txbdr.setRef(txstr);
      Tx txobj(txbdr);
      txobj.setChainedZC(response->ischainedzc());
      txobj.setRBF(response->isrbf());
      return txobj;
   }

   /////////////////////////////////////////////////////////////////////////////
   std::vector<UTXO> getUtxoForAddress(Clients* clients, const string bdvId, 
      const BinaryData& scrAddr, bool withZc)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::getUTXOsForAddress);
      message->set_bdvid(bdvId);
      message->set_scraddr(scrAddr.getCharPtr(), scrAddr.getSize());
      message->set_flag(withZc);

      auto&& result = processCommand(clients, message);
      auto response =
         dynamic_pointer_cast<::Codec_Utxo::ManyUtxo>(result);
      if (response == nullptr)
         throw runtime_error("getUtxoForAddress failed");
      
      vector<UTXO> utxovec(response->value_size());
      for (int i = 0; i < response->value_size(); i++)
      {
         auto& proto_utxo = response->value(i);
         auto& utxo = utxovec[i];

         utxo.value_ = proto_utxo.value();
         utxo.script_.copyFrom(proto_utxo.script());
         utxo.txHeight_ = proto_utxo.txheight();
         utxo.txIndex_ = proto_utxo.txindex();
         utxo.txOutIndex_ = proto_utxo.txoutindex();
         utxo.txHash_.copyFrom(proto_utxo.txhash());
      }

      return utxovec;
   }


   /////////////////////////////////////////////////////////////////////////////
   void addTxioToSsh(StoredScriptHistory& ssh, 
      const map<BinaryDataRef, shared_ptr<const TxIOPair>>& txioMap)
   {
      for (auto& txio_pair : txioMap)
      {
         auto subssh_key = txio_pair.first.getSliceRef(0, 4);

         auto& subssh = ssh.subHistMap_[subssh_key];
         subssh.txioMap_[txio_pair.first] = *txio_pair.second;

         unsigned txioCount = 1;
         if (txio_pair.second->hasTxIn())
         {
            ssh.totalUnspent_ -= txio_pair.second->getValue();

            auto txinKey_prefix = 
               txio_pair.second->getDBKeyOfInput().getSliceCopy(0, 4);
            if (txio_pair.second->getDBKeyOfOutput().startsWith(txinKey_prefix))
            {
               ssh.totalUnspent_ += txio_pair.second->getValue();
               ++txioCount;
            }
         }
         else
         {
            ssh.totalUnspent_ += txio_pair.second->getValue();
         }

         ssh.totalTxioCount_ += txioCount;
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   void prettyPrintSsh(StoredScriptHistory& ssh)
   {
      cout << "balance: " << ssh.totalUnspent_ << endl;
      cout << "txioCount: " << ssh.totalTxioCount_ << endl;

      for(auto& subssh : ssh.subHistMap_)
      {
         cout << "key: " << subssh.first.toHexStr() << ", txCount:" << 
            subssh.second.txioCount_ << endl;
        
         for(auto& txio : subssh.second.txioMap_)
         {
            cout << "   amount: " << txio.second.getValue();
            cout << "   keys: " << txio.second.getDBKeyOfOutput().toHexStr();
            if (txio.second.hasTxIn())
            {
               cout << " to " << txio.second.getDBKeyOfInput().toHexStr();
            }

            cout << ", isUTXO: " << txio.second.isUTXO();
            cout << endl;
         }
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   LedgerEntry getLedgerEntryFromWallet(
      shared_ptr<BtcWallet> wlt, const BinaryData& txHash)
   {
      //get ledgermap from wallet
      auto ledgerMap = wlt->getHistoryPage(0);

      //grab ledger by hash
      for (auto& ledger : *ledgerMap)
      {
         if (ledger.second.getTxHash() == txHash)
            return ledger.second;
      }

      return LedgerEntry();
   }

   /////////////////////////////////////////////////////////////////////////////
   LedgerEntry getLedgerEntryFromAddr(
      ScrAddrObj* scrAddrObj, const BinaryData& txHash)
   {
      //get ledgermap from wallet
      auto&& ledgerMap = scrAddrObj->getHistoryPageById(0);

      //grab ledger by hash
      for (auto& ledger : ledgerMap)
      {
         if (ledger.getTxHash() == txHash)
            return ledger;
      }

      return LedgerEntry();
   }

   /////////////////////////////////////////////////////////////////////////////
   void updateWalletsLedgerFilter(
      Clients* clients, const string& bdvId, const vector<string>& idVec)
   {
      auto message = make_shared<BDVCommand>();
      message->set_method(Methods::updateWalletsLedgerFilter);
      message->set_bdvid(bdvId);
      for (auto id : idVec)
         message->add_bindata(id);

      processCommand(clients, message);
   }

   /////////////////////////////////////////////////////////////////////////////
   void init(void)
   {
      /*
      Need a counter to increment the message id of the packets sent to the 
      BDV object. This counter has to be reset when the BDM is reset. Since 
      the counter is global to the namespace, this means this test interface
      cannot sustain multiple concurent BDVs. 

      Use the websocket interface to have multiple clients instead.

      The counter has to start at 1 since the first message is always BDV
      registration, which does not occur when bypassing the websocet interface.
      */
      commandCtr_ = 1;
   }

   /////////////////////////////////////////////////////////////////////////////
   shared_ptr<::google::protobuf::Message> processCommand(
      Clients* clients, shared_ptr<::google::protobuf::Message> msg)
   {
      auto len = msg->ByteSizeLong();
      vector<uint8_t> buffer(len);
      msg->SerializeToArray(&buffer[0], len);
      auto&& bdVec = WebSocketMessageCodec::serialize(
         buffer, nullptr,
         ArmoryAEAD::BIP151_PayloadType::FragmentHeader, commandCtr_++);

      if (bdVec.size() > 1)
         LOGWARN << "large message in unit tests";

      auto payload = make_shared<BDV_Payload>();
      payload->messageID_ = 0;
      payload->bdvID_ = 0;

      auto bdRef = bdVec[0].getSliceRef(
         LWS_PRE, bdVec[0].getSize() - LWS_PRE);
      payload->packetData_ = bdRef;

      BinaryData zero;
      zero.resize(8);
      memset(zero.getPtr(), 0, 8);
      payload->bdvPtr_ = clients->get(zero.toHexStr());

      return clients->processCommand(payload);
   }

   /////////////////////////////////////////////////////////////////////////////
   AsyncClient::LedgerDelegate getLedgerDelegate(
      shared_ptr<AsyncClient::BlockDataViewer> bdv)
   {
      auto prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
      auto fut = prom->get_future();
      auto getDelegate = [prom]
         (ReturnMessage<AsyncClient::LedgerDelegate> msg)->void
      {
         prom->set_value(msg.get());
      };
      bdv->getLedgerDelegateForWallets(getDelegate);
      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   AsyncClient::LedgerDelegate getLedgerDelegateForScrAddr(
      shared_ptr<AsyncClient::BlockDataViewer> bdv,
      const string& walletId, const BinaryData& scrAddr)
   {
      auto prom = make_shared<promise<AsyncClient::LedgerDelegate>>();
      auto fut = prom->get_future();
      auto getDelegate = [prom]
         (ReturnMessage<AsyncClient::LedgerDelegate> msg)->void
      {
         prom->set_value(msg.get());
      };
      bdv->getLedgerDelegateForScrAddr(walletId, scrAddr, getDelegate);
      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   vector<DBClientClasses::LedgerEntry> getHistoryPage(
      AsyncClient::LedgerDelegate& del, uint32_t id)
   {
      auto prom = make_shared<promise<vector<DBClientClasses::LedgerEntry>>>();
      auto fut = prom->get_future();
      auto lbd = [prom](ReturnMessage<vector<DBClientClasses::LedgerEntry>> msg)
      {
         prom->set_value(msg.get());
      };
      del.getHistoryPage(id, lbd);

      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   uint64_t getPageCount(AsyncClient::LedgerDelegate& del)
   {
      auto prom = make_shared<promise<uint64_t>>();
      auto fut = prom->get_future();
      auto lbd = [prom](ReturnMessage<uint64_t> msg)
      {
         prom->set_value(msg.get());
      };
      del.getPageCount(lbd);

      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   map<BinaryData, vector<uint64_t>> getAddrBalancesFromDB(
      AsyncClient::BtcWallet& wlt)
   {
      auto prom = make_shared<promise<map<BinaryData, vector<uint64_t>>>>();
      auto fut = prom->get_future();
      auto lbd = [prom](ReturnMessage<map<BinaryData, vector<uint64_t>>> msg)
      {
         prom->set_value(msg.get());
      };

      wlt.getAddrBalancesFromDB(lbd);
      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   vector<uint64_t> getBalancesAndCount(AsyncClient::BtcWallet& wlt,
      uint32_t blockheight)
   {
      auto prom = make_shared<promise<vector<uint64_t>>>();
      auto fut = prom->get_future();
      auto lbd = [prom](ReturnMessage<vector<uint64_t>> msg)
      {
         prom->set_value(msg.get());
      };

      wlt.getBalancesAndCount(blockheight, lbd);
      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   AsyncClient::TxResult getTxByHash(
      shared_ptr<AsyncClient::BlockDataViewer> bdv, const BinaryData& hash)
   {
      auto prom = make_shared<promise<AsyncClient::TxResult>>();
      auto fut = prom->get_future();
      auto lbd = [prom](ReturnMessage<AsyncClient::TxResult> msg)->void
      {
         prom->set_value(msg.get());
      };
      bdv->getTxByHash(hash, lbd);
      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   vector<UTXO> getSpendableTxOutListForValue(
      AsyncClient::BtcWallet& wlt, uint64_t value)
   {
      auto prom = make_shared<promise<vector<UTXO>>>();
      auto fut = prom->get_future();
      auto lbd = [prom](ReturnMessage<vector<UTXO>> msg)->void
      {
         prom->set_value(msg.get());
      };
      wlt.getSpendableTxOutListForValue(value, lbd);

      return fut.get();
   }

   /////////////////////////////////////////////////////////////////////////////
   vector<UTXO> getSpendableZCList(AsyncClient::BtcWallet& wlt)
   {
      auto prom = make_shared<promise<vector<UTXO>>>();
      auto fut = prom->get_future();
      auto lbd = [prom](ReturnMessage<vector<UTXO>> msg)->void
      {
         prom->set_value(msg.get());
      };
      wlt.getSpendableZCList(lbd);

      return fut.get();
   }
}
