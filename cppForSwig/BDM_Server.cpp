////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2021, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BDM_Server.h"
#include "ArmoryErrors.h"

using namespace std;
using namespace ::google::protobuf;
using namespace ::Codec_BDVCommand;
using namespace ::Armory::Threading;

///////////////////////////////////////////////////////////////////////////////
//
// BDV_Server_Object
//
///////////////////////////////////////////////////////////////////////////////
BDVCommandProcessingResultType BDV_Server_Object::processCommand(
   shared_ptr<BDVCommand> command, shared_ptr<Message>& resultingPayload)
{
   /*
   BDV_Command messages using any of the following methods need to carry a 
   valid BDV id
   */

   switch (command->method())
   {
   /***
   ZC broadcasting has to be handled at the Clients level because
   it requires the BDV_Server_Object shared_ptr. We don't want the 
   bdv object holding it's own shared_ptr.
   ***/

   case Methods::broadcastZC:
   {
      resultingPayload = command;
      return BDVCommandProcess_ZC_P2P;
   }

   case Methods::broadcastThroughRPC:
   {
      resultingPayload = command;
      return BDVCommandProcess_ZC_RPC;
   }

   case Methods::unregisterAddresses:
   {
      resultingPayload = command;
      return BDVCommandProcess_UnregisterAddresses;
   }

   case Methods::waitOnBDVInit:
   case Methods::waitOnBDVNotification:
   {
      /* in: void
         out: BDVCallback
      */
      break;
   }

   case Methods::goOnline:
   {
      /* in: void
         out: void
      */
      this->startThreads();
      break;
   }

   case Methods::getTopBlockHeight:
   {
      /* in: void
         out: Codec_CommonTypes::OneUnsigned
      */
      auto response = make_shared<::Codec_CommonTypes::OneUnsigned>();
      response->set_value(this->getTopBlockHeight());

      resultingPayload = response;
      break;
   }

   case Methods::getHistoryPage:
   {
      /*
         in: delegateID + pageID or
             walletID + pageID
         out: Codec_LedgerEntry::ManyLedgerEntry
      */

      auto toLedgerEntryVector = []
      (vector<LedgerEntry>& leVec)->shared_ptr<Message>
      {
         auto response = make_shared<::Codec_LedgerEntry::ManyLedgerEntry>();

         for (auto& le : leVec)
         {
            auto lePtr = response->add_values();
            le.fillMessage(lePtr);
         }

         return response;
      };


      //is it a ledger from a delegate?
      if (command->has_delegateid() && command->delegateid().size() != 0)
      {
         auto delegateIter = delegateMap_.find(command->delegateid());
         if (delegateIter != delegateMap_.end())
         {
            if (!command->has_pageid())
               throw runtime_error("invalid command for getHistoryPage");

            auto& delegateObject = delegateIter->second;
            auto pageId = command->pageid();

            auto&& retVal = delegateObject.getHistoryPage(pageId);
            resultingPayload = toLedgerEntryVector(retVal);
            break;
         }
      }
      else if(command->has_walletid() && command->walletid().size() != 0)
      {
         auto& wltID = command->walletid();
         auto theWallet = getWalletOrLockbox(wltID);
         if (theWallet != nullptr)
         {
            BinaryDataRef txHash;

            if (command->has_pageid())
            {
               auto&& retVal = theWallet->getHistoryPageAsVector(
                  command->pageid());
               resultingPayload = toLedgerEntryVector(retVal);
               break;
            }
         }      
      }

      throw runtime_error("invalid command for getHistoryPage");
   }

   case Methods::getPageCountForLedgerDelegate:
   {
      /*
         in: delegateID 
         out: Codec_CommonTypes::OneUnsigned
      */

      if (!command->has_delegateid() || command->delegateid().size() == 0)
         throw runtime_error(
            "invalid command for getPageCountForLedgerDelegate");

      auto delegateIter = delegateMap_.find(command->delegateid());
      if (delegateIter != delegateMap_.end())
      {
         auto count = delegateIter->second.getPageCount();
         
         auto response = make_shared<::Codec_CommonTypes::OneUnsigned>();
         response->set_value(count);

         resultingPayload = response;
      }
      
      break;
   }

   case Methods::registerWallet:
   {
      /*
      in: 
         walletid
         flag: set to true if the wallet is new
         hash: registration id. The callback notifying the registration 
               completion will carry this id. If the registration
               id is empty, no callback will be triggered on completion.
         bindata[]: addresses

      out: void, registration completion is signaled by callback
      */
      if (!command->has_walletid() || command->walletid().size() == 0)
         throw runtime_error("malformed registerWallet command");

      if (command->has_hash() && command->hash().size() != REGISTER_ID_LENGH * 2)
            throw runtime_error("invalid registration id length");

      this->registerWallet(command);
      break;
   }

   case Methods::registerLockbox:
   {
      /* see registerWallet */

      if (!command->has_walletid() || command->walletid().size() == 0)
         throw runtime_error("malformed registerLockbox command");

      if (command->has_hash() && command->hash().size() != REGISTER_ID_LENGH * 2)
            throw runtime_error("invalid registration id length");

      this->registerLockbox(command);
      break;
   }

   case Methods::getLedgerDelegateForWallets:
   {
      /*
      in: void
      out: ledger delegate id as a string wrapped in Codec_CommonTypes::Strings
      */
      auto&& ledgerdelegate = this->getLedgerDelegateForWallets();

      string id = this->getID();
      id.append("_w");

      this->delegateMap_.insert(make_pair(id, ledgerdelegate));

      auto response = make_shared<::Codec_CommonTypes::Strings>();
      response->add_data(id);

      resultingPayload = response;
      break;
   }

   case Methods::getLedgerDelegateForLockboxes:
   {
      /* see getLedgerDelegateForWallets */
      auto&& ledgerdelegate = this->getLedgerDelegateForLockboxes();

      string id = this->getID();
      id.append("_l");

      this->delegateMap_.insert(make_pair(id, ledgerdelegate));

      auto response = make_shared<::Codec_CommonTypes::Strings>();
      response->add_data(id);

      resultingPayload = response;
      break;
   }

   case Methods::getLedgerDelegateForScrAddr:
   {
      /*
      in:
         walletid
         scraddr
      out: ledger delegate id as a string wrapped in Codec_CommonTypes::Strings
      */
      if (!command->has_walletid() || !command->has_scraddr())
         throw runtime_error("invalid command for getLedgerDelegateForScrAddr");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      auto& scrAddr = command->scraddr();
      if (scrAddr.size() == 0 || scrAddr.size() > 33) 
         throw runtime_error("invalid addr size");
      BinaryData addr; addr.copyFrom(scrAddr);

      auto&& ledgerdelegate =
         this->getLedgerDelegateForScrAddr(walletId, addr);
      string id = addr.toHexStr();

      this->delegateMap_.insert(make_pair(id, ledgerdelegate));
      auto response = make_shared<::Codec_CommonTypes::Strings>();
      response->add_data(id);

      resultingPayload = response;
      break;
   }

   case Methods::getBalancesAndCount:
   {
      /*
      in:
         walletid
         height
      out: full, spendable and unconfirmed balance + transaction count
         wrapped in Codec_CommonTypes::ManyUnsigned
      */
      if (! command->has_walletid() || !command->has_height())
         throw runtime_error("invalid command for getBalancesAndCount");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet/lockbox ID");

      uint32_t height = command->height();

      auto response = make_shared<::Codec_CommonTypes::ManyUnsigned>();
      response->add_value(wltPtr->getFullBalance());
      response->add_value(wltPtr->getSpendableBalance(height));
      response->add_value(wltPtr->getUnconfirmedBalance(height));
      response->add_value(wltPtr->getWltTotalTxnCount());

      resultingPayload = response;
      break;
   }

   case Methods::setWalletConfTarget:
   {
      /*
      in:
         walletid
         height: conf target
         hash: event id. The callback notifying the change in conf target
               completion will carry this id. If the event id is empty, no 
               callback will be triggered on completion.
      out: N/A
      */
      if (!command->has_walletid() || !command->has_height() || !command->has_hash())
         throw runtime_error("invalid command for setWalletConfTarget");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet/lockbox ID");

      uint32_t height = command->height();
      auto hash = command->hash();
      wltPtr->setConfTarget(height, hash);
      break;
   }

   case Methods::getSpendableTxOutListForValue:
   {
      /*
      in:
         walletid
         value
      out: enough UTXOs to cover value twice, as Codec_Utxo::ManyUtxo
      */

      if (!command->has_walletid() || !command->has_value())
         throw runtime_error("invalid command for getSpendableTxOutListForValue");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet or lockbox ID");

      auto&& utxoVec = wltPtr->getSpendableTxOutListForValue(
         command->value());

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();
      for (auto& utxo : utxoVec)
      {
         auto utxoPtr = response->add_value();
         utxoPtr->set_value(utxo.value_);
         utxoPtr->set_script(utxo.script_.getPtr(), utxo.script_.getSize());
         utxoPtr->set_txheight(utxo.txHeight_);
         utxoPtr->set_txindex(utxo.txIndex_);
         utxoPtr->set_txoutindex(utxo.txOutIndex_);
         utxoPtr->set_txhash(utxo.txHash_.getPtr(), utxo.txHash_.getSize());
      }

      resultingPayload = response;
      break;
   }

   case Methods::getSpendableZCList:
   {
      /*
      in:
      walletid
      out: all ZC UTXOs for this wallet, as Codec_Utxo::ManyUtxo
      */

      if (!command->has_walletid())
         throw runtime_error("invalid command for getSpendableZCList");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet or lockbox ID");

      auto&& utxoVec = wltPtr->getSpendableTxOutListZC();

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();
      for (auto& utxo : utxoVec)
      {
         auto utxoPtr = response->add_value();
         utxoPtr->set_value(utxo.value_);
         utxoPtr->set_script(utxo.script_.getPtr(), utxo.script_.getSize());
         utxoPtr->set_txheight(utxo.txHeight_);
         utxoPtr->set_txindex(utxo.txIndex_);
         utxoPtr->set_txoutindex(utxo.txOutIndex_);
         utxoPtr->set_txhash(utxo.txHash_.getPtr(), utxo.txHash_.getSize());
      }

      resultingPayload = response;
      break;
   }

   case Methods::getRBFTxOutList:
   {
      /*
      in:
      walletid
      out: all RBF UTXOs for this wallet, as Codec_Utxo::ManyUtxo
      */

      if (!command->has_walletid())
         throw runtime_error("invalid command for getSpendableZCList");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid size for wallet id");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet or lockbox ID");

      auto&& utxoVec = wltPtr->getRBFTxOutList();

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();
      for (auto& utxo : utxoVec)
      {
         auto utxoPtr = response->add_value();
         utxoPtr->set_value(utxo.value_);
         utxoPtr->set_script(utxo.script_.getPtr(), utxo.script_.getSize());
         utxoPtr->set_txheight(utxo.txHeight_);
         utxoPtr->set_txindex(utxo.txIndex_);
         utxoPtr->set_txoutindex(utxo.txOutIndex_);
         utxoPtr->set_txhash(utxo.txHash_.getPtr(), utxo.txHash_.getSize());
      }

      resultingPayload = response;
      break;
   }

   case Methods::getSpendableTxOutListForAddr:
   {
      /*
      in:
      walletid
      scraddr
      out: all UTXOs for this address, as Codec_Utxo::ManyUtxo
      */

      if (!command->has_walletid() || !command->has_scraddr())
         throw runtime_error("invalid command for getSpendableZCList");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet or lockbox ID");

      auto& scrAddr = command->scraddr();
      if (scrAddr.size() == 0 || scrAddr.size() > 33)
         throw runtime_error("invalid addr size");
      BinaryDataRef scrAddrRef((uint8_t*)scrAddr.data(), scrAddr.size());

      auto addrObj = wltPtr->getScrAddrObjByKey(scrAddrRef);

      auto spentByZC = [this](const BinaryData& dbkey)->bool
      { return this->isTxOutSpentByZC(dbkey); };

      auto&& utxoVec = addrObj->getAllUTXOs(spentByZC);

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();
      for (auto& utxo : utxoVec)
      {
         auto utxoPtr = response->add_value();
         utxoPtr->set_value(utxo.value_);
         utxoPtr->set_script(utxo.script_.getPtr(), utxo.script_.getSize());
         utxoPtr->set_txheight(utxo.txHeight_);
         utxoPtr->set_txindex(utxo.txIndex_);
         utxoPtr->set_txoutindex(utxo.txOutIndex_);
         utxoPtr->set_txhash(utxo.txHash_.getPtr(), utxo.txHash_.getSize());
      }

      resultingPayload = response;
      break;
   }

   case Methods::getAddrTxnCounts:
   {
      /*
      in: walletid
      out: transaction count for each address in wallet, 
           as Codec_AddressData::ManyAddressData
      */
      if (!command->has_walletid())
         throw runtime_error("invalid command for getSpendableZCList");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet or lockbox ID");

      auto&& countMap = wltPtr->getAddrTxnCounts(updateID_);

      auto response = make_shared<::Codec_AddressData::ManyAddressData>();
      for (auto count : countMap)
      {
         auto addrData = response->add_scraddrdata();
         addrData->set_scraddr(count.first.getPtr(), count.first.getSize());
         addrData->add_value(count.second);
      }

      resultingPayload = response;
      break;
   }

   case Methods::getAddrBalances:
   {
      /*
      in: walletid
      out: full, spendable and unconfirmed balance for each address in
           wallet, as Codec_AddressData::ManyAddressData
      */

      if (!command->has_walletid())
         throw runtime_error("invalid command for getSpendableZCList");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      shared_ptr<BtcWallet> wltPtr = nullptr;
      for (auto& group : this->groups_)
      {
         auto wltIter = group.wallets_.find(walletId);
         if (wltIter != group.wallets_.end())
            wltPtr = wltIter->second;
      }

      if (wltPtr == nullptr)
         throw runtime_error("unknown wallet or lockbox ID");

      auto&& balanceMap = wltPtr->getAddrBalances(
         updateID_, this->getTopBlockHeight());

      auto response = make_shared<::Codec_AddressData::ManyAddressData>();
      for (auto balances : balanceMap)
      {
         auto addrData = response->add_scraddrdata();
         addrData->set_scraddr(balances.first.getPtr(), balances.first.getSize());
         addrData->add_value(get<0>(balances.second));
         addrData->add_value(get<1>(balances.second));
         addrData->add_value(get<2>(balances.second));
      }

      resultingPayload = response;
      break;
   }

   case Methods::getTxByHash:
   {
      /*
      in: 
         txhash as hash
         flag: true to return only the tx height
      out: tx as Codec_CommonTypes::TxWithMetaData
      */


      //TODO: consider decoupling txheight/index fetch into its own method

      if (!command->has_hash())
         throw runtime_error("invalid command for getTxByHash");

      bool heightOnly = false;
      if (command->has_flag())
         heightOnly =  command->flag();

      Tx retval;
      auto& txHash = command->hash();
      if (txHash.size() != 32)
         throw runtime_error("invalid hash size");
      BinaryDataRef txHashRef; txHashRef.setRef(txHash);

      if (!heightOnly)
      {
         retval = move(this->getTxByHash(txHashRef));
         if (!retval.isInitialized())
            throw runtime_error("failed to grab tx by hash");
      }
      else
      {
         auto&& txData = getTxMetaData(txHashRef, false);
         retval.setTxHeight(get<0>(txData));
         retval.setTxIndex(get<1>(txData));
      }
      
      auto response = make_shared<::Codec_CommonTypes::TxWithMetaData>();
      if (retval.isInitialized())
      {
         response->set_rawtx(retval.getPtr(), retval.getSize());
         response->set_isrbf(retval.isRBF());
         response->set_ischainedzc(retval.isChained());
      }

      response->set_height(retval.getTxHeight());
      response->set_txindex(retval.getTxIndex());

      resultingPayload = response;
      break;
   }

   case Methods::getTxBatchByHash:
   {
      /*
      in: 
         Set of tx identifier as bindata[]
         An identifier is a txhash concatenated with an optional binary flag:
            tx hash (32) | flag (1)
         The flag defaults to false. If present and set to a non zero value,
         only the tx height is returned, without the tx body, for this one entry.

      out: a set of transaction as Codec_CommonTypes::ManyTxWithMetaData
      */

      if (command->bindata_size() == 0)
         throw runtime_error("invalid command for getTxBatchByHash");

      vector<Tx> result;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         Tx tx;
         auto& txHash = command->bindata(i);
         if (txHash.size() < 32)
         {
            result.emplace_back();
            continue;
         }

         BinaryDataRef txHashRef;
         txHashRef.setRef((const uint8_t*)txHash.c_str(), 32);

         bool heightOnly = false;
         if (txHash.size() == 33)
            heightOnly = (bool)txHash.c_str()[32];

         if (!heightOnly)
         {
            tx = move(this->getTxByHash(txHashRef));
         }
         else
         {
            auto&& txData = getTxMetaData(txHashRef, true);
            tx.setTxHeight(get<0>(txData));
            tx.setTxIndex(get<1>(txData));

            auto& opIds = get<2>(txData);
            for (auto& id : opIds)
               tx.pushBackOpId(id);
         }

         result.emplace_back(move(tx));
      }

      auto response = make_shared<::Codec_CommonTypes::ManyTxWithMetaData>();
      for (auto& tx : result)
      {
         auto txPtr = response->add_tx();
         if (tx.isInitialized())
         {
            txPtr->set_rawtx(tx.getPtr(), tx.getSize());
            txPtr->set_isrbf(tx.isRBF());
            txPtr->set_ischainedzc(tx.isChained());
         }

         txPtr->set_height(tx.getTxHeight());
         txPtr->set_txindex(tx.getTxIndex());

         for (auto& opID : tx.getOpIdVec())
            txPtr->add_opid(opID);
      }

      response->set_isvalid(true);
      resultingPayload = response;
      break;
   }

   case Methods::getAddressFullBalance:
   {
      /*
      in: scraddr
      out: current balance in DB (does not cover ZC), 
           as Codec_CommonTypes::OneUnsigned
      */

      if (!command->has_scraddr())
         throw runtime_error("invalid command for getAddressFullBalance");

      auto& scrAddr = command->scraddr();
      BinaryDataRef scrAddrRef; scrAddrRef.setRef(scrAddr);
      if (scrAddrRef.getSize() == 0 || scrAddrRef.getSize() > 33)
         throw runtime_error("invalid addr size");

      auto&& retval = this->getAddrFullBalance(scrAddrRef);

      auto response = make_shared<::Codec_CommonTypes::OneUnsigned>();
      response->set_value(get<0>(retval));

      resultingPayload = response;
      break;
   }

   case Methods::getAddressTxioCount:
   {
      /*
      in: scraddr
      out: current transaction count in DB (does not cover ZC), 
           as Codec_CommonTypes::OneUnsigned
      */
      if (!command->has_scraddr())
         throw runtime_error("invalid command for getAddressFullBalance");

      auto& scrAddr = command->scraddr();
      BinaryDataRef scrAddrRef; scrAddrRef.setRef(scrAddr);
      if (scrAddrRef.getSize() == 0 || scrAddrRef.getSize() > 33)
         throw runtime_error("invalid addr size");

      auto&& retval = this->getAddrFullBalance(scrAddrRef);

      auto response = make_shared<::Codec_CommonTypes::OneUnsigned>();
      response->set_value(get<1>(retval));

      resultingPayload = response;
      break;
   }

   case Methods::getHeaderByHeight:
   {
      /*
      in: height
      out: raw header, as Codec_CommonTypes::BinaryData
      */

      if (!command->has_height())
         throw runtime_error("invalid command for getHeaderByHeight");

      auto header = blockchain().getHeaderByHeight(command->height(), 0xFF);
      auto& headerData = header->serialize();

      auto response = make_shared<::Codec_CommonTypes::BinaryData>();
      response->set_data(headerData.getPtr(), headerData.getSize());

      resultingPayload = response;
      break;
   }

   case Methods::createAddressBook:
   {
      /*
      in: walletid
      out: Codec_AddressBook::AddressBook
      */

      if (!command->has_walletid())
         throw runtime_error("invalid command for createAddressBook");

      auto& walletId = command->walletid();
      if (walletId.size() == 0)
         throw runtime_error("invalid wallet id size");

      auto wltPtr = getWalletOrLockbox(walletId);
      if (wltPtr == nullptr)
         throw runtime_error("invalid id");

      auto&& abeVec = wltPtr->createAddressBook();

      auto response = make_shared<::Codec_AddressBook::AddressBook>();
      for (auto& abe : abeVec)
      {
         auto entry = response->add_entry();
         auto& scrAddr = abe.getScrAddr();
         entry->set_scraddr(scrAddr.getPtr(), scrAddr.getSize());

         auto& txHashList = abe.getTxHashList();
         for (auto txhash : txHashList)
            entry->add_txhash(txhash.getPtr(), txhash.getSize());
      }

      resultingPayload = response;
      break;
   }

   case Methods::updateWalletsLedgerFilter:
   {
      /*
      in: vector of wallet ids to display in wallet ledger delegate, as bindata
      out: void
      */
      vector<string> bdVec;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& val = command->bindata(i);
         if (val.size() == 0)
            continue;
         bdVec.push_back(val);
      }

      this->updateWalletsLedgerFilter(bdVec);
      break;
   }

   case Methods::getNodeStatus:
   {
      /*
      in: void
      out: Codec_NodeStatus::NodeStatus
      */
      auto&& nodeStatus = this->bdmPtr_->getNodeStatus();

      auto response = make_shared<::Codec_NodeStatus::NodeStatus>();
      response->set_state((unsigned)nodeStatus.state_);
      response->set_segwitenabled(nodeStatus.SegWitEnabled_);
      response->set_rpcstate((unsigned)nodeStatus.rpcState_);

      auto chainStatus_proto = new ::Codec_NodeStatus::NodeChainStatus();
      chainStatus_proto->set_state((unsigned)nodeStatus.chainStatus_.state());
      chainStatus_proto->set_blockspeed(nodeStatus.chainStatus_.getBlockSpeed());
      chainStatus_proto->set_eta(nodeStatus.chainStatus_.getETA());
      chainStatus_proto->set_pct(nodeStatus.chainStatus_.getProgressPct());
      chainStatus_proto->set_blocksleft(nodeStatus.chainStatus_.getBlocksLeft());
      response->set_allocated_chainstatus(chainStatus_proto);

      resultingPayload = response;
      break;
   }

   case Methods::estimateFee:
   {
      /*
      in: 
         value
         startegy as bindata[0]
      out: 
         Codec_FeeEstimate::FeeEstimate
      */
      if (!command->has_value() || command->bindata_size() != 1)
         throw runtime_error("invalid command for estimateFee");

      uint32_t blocksToConfirm = command->value();
      auto strat = command->bindata(0);

      auto feeByte = this->bdmPtr_->nodeRPC_->getFeeByte(
            blocksToConfirm, strat);

      auto response = make_shared<::Codec_FeeEstimate::FeeEstimate>();
      response->set_feebyte(feeByte.feeByte_);
      response->set_smartfee(feeByte.smartFee_);
      response->set_error(feeByte.error_);

      resultingPayload = response;
      break;
   }

   case Methods::getFeeSchedule:
   {
      /*
      in:
         startegy as bindata[0]
      out:
         Codec_FeeEstimate::FeeScehdule
      */
      if (command->bindata_size() != 1)
         throw runtime_error("invalid command for getFeeSchedule");

      auto strat = command->bindata(0);
      auto feeBytes = this->bdmPtr_->nodeRPC_->getFeeSchedule(strat);

      auto response = make_shared<::Codec_FeeEstimate::FeeSchedule>();
      for (auto& feeBytePair : feeBytes)
      {
         auto& feeByte = feeBytePair.second;

         response->add_target(feeBytePair.first);
         auto estimate = response->add_estimate();
         estimate->set_feebyte(feeByte.feeByte_);
         estimate->set_smartfee(feeByte.smartFee_);
         estimate->set_error(feeByte.error_);
      }

      resultingPayload = response;
      break;
   }

   case Methods::getHistoryForWalletSelection:
   {
      /*
      in:
         vector of wallet ids to get history for, as bindata
         flag, set to true to order history ascending
      out:
         history for wallet list, as Codec_LedgerEntry::ManyLedgerEntry
      */

      if (!command->has_flag())
         throw runtime_error("invalid command for getHistoryForWalletSelection");

      vector<string> wltIDs;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& id = command->bindata(i);
         if (id.size() == 0)
            continue;

         wltIDs.push_back(id);
      }

      auto orderingFlag = command->flag();

      HistoryOrdering ordering;
      if (orderingFlag)
         ordering = order_ascending;
      else 
         ordering = order_descending;

      auto&& wltGroup = this->getStandAloneWalletGroup(wltIDs, ordering);

      auto response = make_shared<::Codec_LedgerEntry::ManyLedgerEntry>();
      for (unsigned y = 0; y < wltGroup.getPageCount(); y++)
      {
         auto&& histPage = wltGroup.getHistoryPage(y, false, false, UINT32_MAX);

         for (auto& le : histPage)
         {
            auto lePtr = response->add_values();
            le.fillMessage(lePtr);
         }
      }

      resultingPayload = response;
      break;
   }

   case Methods::getHeaderByHash:
   {
      /*
      in: tx hash
      out: raw header, as Codec_CommonTypes::BinaryData
      */

      if (!command->has_hash())
         throw runtime_error("invalid command for getHeaderByHash");

      auto& txHash = command->hash();
      if (txHash.size() != 32)
         throw runtime_error("invalid hash size");
      BinaryDataRef txHashRef; txHashRef.setRef(txHash);

      auto&& dbKey = this->db_->getDBKeyForHash(txHashRef);

      if (dbKey.getSize() == 0)
         break;

      unsigned height; uint8_t dup;
      BinaryRefReader key_brr(dbKey.getRef());
      DBUtils::readBlkDataKeyNoPrefix(key_brr, height, dup);

      BinaryData bw;
      try
      {
         auto block = this->blockchain().getHeaderByHeight(height, 0xFF);
         auto rawHeader = block->serialize();
         BinaryWriter bw(rawHeader.getSize() + 4);
         bw.put_uint32_t(height);
         bw.put_BinaryData(rawHeader);
      }
      catch (exception&)
      {
         break;
      }

      auto response = make_shared<::Codec_CommonTypes::BinaryData>();
      response->set_data(bw.getPtr(), bw.getSize());

      resultingPayload = response;
      break;
   }

   case Methods::getCombinedBalances:
   {
      /*
      in: set of wallets ids as bindata[]
      out: 
         Codec_AddressData::ManyCombinedData:
         {
            walletid,
               ManyUnsigned{full, unconf, spendable},
               ManyAddressData
         }
      */

      vector<string> wltIDs;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& id = command->bindata(i);
         if (id.size() == 0)
            continue;
         wltIDs.push_back(id);
      }
      
      uint32_t height = getTopBlockHeader()->getBlockHeight();
      auto response = make_shared<::Codec_AddressData::ManyCombinedData>();

      for (auto& id : wltIDs)
      {
         shared_ptr<BtcWallet> wltPtr = nullptr;
         for (auto& group : this->groups_)
         {
            auto wltIter = group.wallets_.find(id);
            if (wltIter != group.wallets_.end())
               wltPtr = wltIter->second;
         }

         if (wltPtr == nullptr)
         {
            LOGERR << "getCombinedBalances: " << 
               "unknown wallet ID (" << id << ")";
            throw runtime_error("unknown wallet ID");
         }

         auto combinedData = response->add_packedbalance();
         
         try 
         {
            //wallet balances and count
            combinedData->set_id(id);
            combinedData->add_idbalances(wltPtr->getFullBalance());
            combinedData->add_idbalances(wltPtr->getSpendableBalance(height));
            combinedData->add_idbalances(wltPtr->getUnconfirmedBalance(height));
            combinedData->add_idbalances(wltPtr->getWltTotalTxnCount());
         }
         catch (const exception& e)
         {
            LOGERR << "getCombinedBalances: " << 
               "failed to get balance for wallet" << id << 
               "with error: " << e.what();
            throw e;
         }

         //address balances and counts
         try
         {
            auto&& balanceMap = wltPtr->getAddrBalances(
               updateID_, this->getTopBlockHeight());

            for (auto balances : balanceMap)
            {
               auto addrData = combinedData->add_addrdata();
               addrData->set_scraddr(
                  balances.first.getPtr(), balances.first.getSize());
               addrData->add_value(get<0>(balances.second));
               addrData->add_value(get<1>(balances.second));
               addrData->add_value(get<2>(balances.second));
            }
         }
         catch (const exception& e)
         {
            LOGERR << "getCombinedBalances: " << 
         #ifdef NDEBUG
               "failed to get balance for address";
         #else
               "failed to get balance for address with error: " << e.what();
         #endif
            throw e;
         }
      }

      resultingPayload = response;
      break;
   }

   case Methods::getCombinedAddrTxnCounts:
   {
      /*
      in: set of wallets ids as bindata[]
      out: transaction count for each address in each wallet, 
           as Codec_AddressData::CombinedData
      */
      vector<string> wltIDs;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& id = command->bindata(i);
         if (id.size() == 0)
            continue;
         wltIDs.push_back(id);
      }

      auto response = make_shared<::Codec_AddressData::ManyCombinedData>();

      for (auto id : wltIDs)
      {
         shared_ptr<BtcWallet> wltPtr = nullptr;
         for (auto& group : this->groups_)
         {
            auto wltIter = group.wallets_.find(id);
            if (wltIter != group.wallets_.end())
               wltPtr = wltIter->second;
         }

         if (wltPtr == nullptr)
         {
            LOGERR << "getCombinedAddrTxnCounts: " << 
               "unknown wallet ID (" << id << ")";
            throw runtime_error("unknown wallet ID");
         }

         auto&& countMap = wltPtr->getAddrTxnCounts(updateID_);
         if (countMap.size() == 0)
            continue;

         auto packedBal = response->add_packedbalance();
         packedBal->set_id(id);

         for (auto count : countMap)
         {
            auto addrData = packedBal->add_addrdata();
            addrData->set_scraddr(count.first.getPtr(), count.first.getSize());
            addrData->add_value(count.second);
         }
      }

      resultingPayload = response;
      break;
   }

   case Methods::getCombinedSpendableTxOutListForValue:
   {
      /*
      in:
         value
         wallet ids as bindata[]
      out: 
         enough UTXOs to cover value twice, as Codec_Utxo::ManyUtxo

      The order in which wallets are presented will be the order by 
      which utxo fetching will be prioritize, i.e. if the first wallet 
      has enough UTXOs to cover value twice over, there will not be any
      UTXOs returned for the other wallets.
      */

      if (!command->has_value())
      {
         throw runtime_error(
            "invalid command for getCombinedSpendableTxOutListForValue");
      }

      vector<string> wltIDs;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& id = command->bindata(i);
         if (id.size() == 0)
            continue;
         wltIDs.push_back(id);
      }

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();
      uint64_t totalValue = 0;

      for (auto id : wltIDs)
      {
         shared_ptr<BtcWallet> wltPtr = nullptr;
         for (auto& group : this->groups_)
         {
            auto wltIter = group.wallets_.find(id);
            if (wltIter != group.wallets_.end())
               wltPtr = wltIter->second;
         }

         if (wltPtr == nullptr)
            throw runtime_error("unknown wallet or lockbox ID");

         auto&& utxoVec = wltPtr->getSpendableTxOutListForValue(
            command->value());

         for (auto& utxo : utxoVec)
         {
            totalValue += utxo.getValue();

            auto utxoPtr = response->add_value();
            utxoPtr->set_value(utxo.value_);
            utxoPtr->set_script(utxo.script_.getPtr(), utxo.script_.getSize());
            utxoPtr->set_txheight(utxo.txHeight_);
            utxoPtr->set_txindex(utxo.txIndex_);
            utxoPtr->set_txoutindex(utxo.txOutIndex_);
            utxoPtr->set_txhash(utxo.txHash_.getPtr(), utxo.txHash_.getSize());
         }

         if (totalValue >= command->value() * 2)
            break;
      }

      resultingPayload = response;
      break;
   }

   case Methods::getCombinedSpendableZcOutputs:
   {
      /*
      in:
         value
         wallet ids as bindata[]
      out:
         enough UTXOs to cover value twice, as Codec_Utxo::ManyUtxo

      The order in which wallets are presented will be the order by
      which utxo fetching will be prioritize, i.e. if the first wallet
      has enough UTXOs to cover value twice over, there will not be any
      UTXOs returned for the other wallets.
      */

      vector<string> wltIDs;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& id = command->bindata(i);
         if (id.size() == 0)
            continue;
         wltIDs.push_back(id);
      }

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();

      for (auto id : wltIDs)
      {
         shared_ptr<BtcWallet> wltPtr = nullptr;
         for (auto& group : this->groups_)
         {
            auto wltIter = group.wallets_.find(id);
            if (wltIter != group.wallets_.end())
               wltPtr = wltIter->second;
         }

         if (wltPtr == nullptr)
            throw runtime_error("unknown wallet or lockbox ID");

         auto&& utxoVec = wltPtr->getSpendableTxOutListZC();
         for (auto& utxo : utxoVec)
         {
            auto utxoPtr = response->add_value();
            utxoPtr->set_value(utxo.value_);
            utxoPtr->set_script(utxo.script_.getPtr(), utxo.script_.getSize());
            utxoPtr->set_txheight(utxo.txHeight_);
            utxoPtr->set_txindex(utxo.txIndex_);
            utxoPtr->set_txoutindex(utxo.txOutIndex_);
            utxoPtr->set_txhash(utxo.txHash_.getPtr(), utxo.txHash_.getSize());
         }
      }

      resultingPayload = response;
      break;
   }

   case Methods::getCombinedRBFTxOuts:
   {
      /*
      in:
         wallet ids as bindata[]
      out:
         enough UTXOs to cover value twice, as Codec_Utxo::ManyUtxo

      The order in which wallets are presented will be the order by
      which utxo fetching will be prioritized, i.e. if the first wallet
      has enough UTXOs to cover value twice over, there will not be any
      UTXOs returned for the other wallets.
      */

      vector<string> wltIDs;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& id = command->bindata(i);
         if (id.size() == 0)
            continue;
         wltIDs.push_back(id);
      }

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();

      for (auto id : wltIDs)
      {
         shared_ptr<BtcWallet> wltPtr = nullptr;
         for (auto& group : this->groups_)
         {
            auto wltIter = group.wallets_.find(id);
            if (wltIter != group.wallets_.end())
               wltPtr = wltIter->second;
         }

         if (wltPtr == nullptr)
            throw runtime_error("unknown wallet or lockbox ID");

         auto&& utxoVec = wltPtr->getRBFTxOutList();
         for (auto& utxo : utxoVec)
         {
            auto utxoPtr = response->add_value();
            utxoPtr->set_value(utxo.value_);
            utxoPtr->set_script(utxo.script_.getPtr(), utxo.script_.getSize());
            utxoPtr->set_txheight(utxo.txHeight_);
            utxoPtr->set_txindex(utxo.txIndex_);
            utxoPtr->set_txoutindex(utxo.txOutIndex_);
            utxoPtr->set_txhash(utxo.txHash_.getPtr(), utxo.txHash_.getSize());
         }
      }

      resultingPayload = response;
      break;
   }

   case Methods::getOutpointsForAddresses:
   {
      /*
      in: set of scrAddr as bindata[]
      out: outpoints for each address as Codec_Utxo::AddressOutpointsData
      */

      set<BinaryDataRef> scrAddrSet;
      for (int i = 0; i < command->bindata_size(); i++)
      {
         auto& scrAddr = command->bindata(i);
         if (scrAddr.size() == 0 || scrAddr.size() > 33)
            continue;
         
         BinaryDataRef scrAddrRef; scrAddrRef.setRef(scrAddr);
         scrAddrSet.insert(scrAddrRef);
      }

      unsigned heightCutOff = command->height();
      unsigned zcCutOff = command->zcid();
      auto response = make_shared<::Codec_Utxo::AddressOutpointsData>();

      //sanity check
      if (scrAddrSet.size() == 0)
      {
         response->set_heightcutoff(heightCutOff);
         response->set_zcindexcutoff(zcCutOff);

         resultingPayload = response;
         break;
      }

      //this call will update the cutoff values
      auto&& outpointMap = getAddressOutpoints(scrAddrSet, heightCutOff, zcCutOff);

      //fill in response
      for (auto& addrPair : outpointMap)
      {
         auto addrop = response->add_addroutpoints();
         addrop->set_scraddr(addrPair.first.getPtr(), addrPair.first.getSize());

         for (auto& outpointMap : addrPair.second)
         {
            for (auto& outpointPair : outpointMap.second)
            {
               auto opPtr = addrop->add_outpoints();
               opPtr->set_txhash(
                  outpointMap.first.getPtr(), outpointMap.first.getSize());
               
               opPtr->set_txoutindex(outpointPair.first);
               opPtr->set_value(outpointPair.second.value_);
               opPtr->set_isspent(outpointPair.second.isspent_);

               opPtr->set_txheight(outpointPair.second.height_);
               opPtr->set_txindex(outpointPair.second.txindex_);

               if (outpointPair.second.isspent_)
               {
                  opPtr->set_spenderhash(
                     outpointPair.second.spenderHash_.getCharPtr(),
                     outpointPair.second.spenderHash_.getSize());
               }
            }
         }
      }

      //set cutoffs
      response->set_heightcutoff(heightCutOff);
      response->set_zcindexcutoff(zcCutOff);

      resultingPayload = response;
      break;
   }

   case Methods::getUTXOsForAddress:
   {
      /*
      in: scrAddr as scraddr
      out: utxos as Codec_Utxo::ManyUtxo
      */

      auto& addr = command->scraddr();
      if (addr.size() == 0 || addr.size() > 33)
         throw runtime_error("expected address for getUTXOsForAddress");

      BinaryDataRef scrAddr;
      scrAddr.setRef((const uint8_t*)addr.c_str(), addr.size());

      auto withZc = command->flag();
      auto&& utxoVec = getUtxosForAddress(scrAddr, withZc);

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();
      for (auto& utxo : utxoVec)
      {
         auto utxoPtr = response->add_value();
         utxo.toProtobuf(*utxoPtr);
      }

      resultingPayload = response;
      break;
   }

   case Methods::getSpentnessForOutputs:
   {
      /*
      in: 
         output hash & id concatenated as: 
         txhash (32) | txout count (varint) | txout index #1 (varint) | txout index #2 ...
         
      out:
         Codec_Utxo::Spentness_BatchData
      */

      if(command->bindata_size() == 0)
         throw runtime_error("expected bindata for getSpentnessForOutputs");

      map<BinaryDataRef, map<unsigned, SpentnessResult>> spenderMap;
      {
         //grab all spentness data for these outputs
         auto&& spentness_tx = db_->beginTransaction(SPENTNESS, LMDB::ReadOnly);

         for (int i = 0; i < command->bindata_size(); i++)
         {
            auto& rawOutputs = command->bindata(i);
            if (rawOutputs.size() < 33)
               throw runtime_error("malformed output data");

            BinaryRefReader brr((const uint8_t*)rawOutputs.c_str(), rawOutputs.size());
            auto txHashRef = brr.get_BinaryDataRef(32);
            auto& opMap = spenderMap[txHashRef];

            //get dbkey for this txhash
            auto&& dbkey = db_->getDBKeyForHash(txHashRef);

            //convert id to block height and setup stxo
            StoredTxOut stxo;

            if (dbkey.getSize() != 0)
            {
               BinaryRefReader keyReader(dbkey);
               uint32_t blockid; uint8_t dup;
               DBUtils::readBlkDataKeyNoPrefix(keyReader,
                  blockid, dup, stxo.txIndex_);

               auto headerPtr = blockchain().getHeaderById(blockid);
               stxo.blockHeight_ = headerPtr->getBlockHeight();
               stxo.duplicateID_ = headerPtr->getDuplicateID();
            }
            
            //run through txout indices
            auto outputCount = brr.get_var_int();
            for (unsigned y = 0; y < outputCount; y++)
            {
               auto txOutIndex = brr.get_var_int();
               auto opInsertIter = opMap.insert(make_pair(
                  txOutIndex, SpentnessResult()));
               if (dbkey.getSize() == 0 || !opInsertIter.second)
                  continue;

               //set txout index
               stxo.txOutIndex_ = txOutIndex;
             
               //get spentness for index
               db_->getSpentness(stxo);

               //add to the result vector
               if (stxo.isSpent())
               {
                  opInsertIter.first->second.state_ = 
                     OutputSpentnessState::Spent;
                  
                  opInsertIter.first->second.spender_ = 
                     stxo.spentByTxInKey_;
               }
               else
               {
                  opInsertIter.first->second.state_ = 
                     OutputSpentnessState::Unspent;
               }
            }
         }
      }

      //resolve spender dbkeys to tx hashes
      map<BinaryData, pair<BinaryData, unsigned>> cache;
      for (auto& txHashPair : spenderMap)
      {
         for (auto& opPair : txHashPair.second)
         {
            auto& key = opPair.second.spender_;
            if (key.getSize() == 0)
               continue; //no spender, move on

            //check the cache for this resolved hash
            auto keyShort = key.getSliceRef(0, 6);
            auto cacheIter = cache.find(keyShort);
            if (cacheIter != cache.end())
            {
               //set the spender hash and height
               key = cacheIter->second.first;
               opPair.second.height_ = cacheIter->second.second;
               continue;
            }

            //create cache entry
            auto cacheInsertIter = cache.emplace(
               keyShort, pair<BinaryData, unsigned>()).first;

            //resolve spender hash and extract height
            auto&& hash = db_->getHashForDBKey(keyShort);
            auto height = DBUtils::hgtxToHeight(key.getSliceRef(0, 4));

            //set hash and key
            key = hash; opPair.second.height_ = height;
            
            //fill cache entry
            cacheInsertIter->second.first = move(hash);
            cacheInsertIter->second.second = height;
         }
      }

      //create response object
      auto response = make_shared<::Codec_Utxo::Spentness_BatchData>();
      response->set_count(spenderMap.size());
      for (auto& txHashPair : spenderMap)
      {
         auto txData = response->add_txdata();
         txData->set_hash(txHashPair.first.getPtr(), txHashPair.first.getSize());

         for (auto& opPair : txHashPair.second)
         {
            auto opData = txData->add_outputdata();

            opData->set_txoutindex(opPair.first);
            opData->set_state(opPair.second.state_);
            
            if (opPair.second.state_ != OutputSpentnessState::Spent)
               continue;

            opData->set_spenderheight(opPair.second.height_);
            opData->set_spenderhash(
               opPair.second.spender_.getCharPtr(), 
               opPair.second.spender_.getSize());
         }
      }

      resultingPayload = response;
      break;
   }

   case Methods::getSpentnessForZcOutputs:
   {
      /*
      in: 
         zc output hash & id concatenated as: 
         txhash (32) | txout count (varint) | txout index #1 (varint) | txout index #2 ...
         
      out:
         Codec_Utxo::Spentness_BatchData
      */

      map<BinaryDataRef, map<unsigned, SpentnessResult>> spenderMap;
      {
         //grab all spentness data for these zc outputs
         auto snapshot = zc_->getSnapshot();
         for (int i = 0; i < command->bindata_size(); i++)
         {
            auto& rawOutputs = command->bindata(i);
            if (rawOutputs.size() < 33)
               throw runtime_error("malformed output data");

            BinaryRefReader brr((const uint8_t*)rawOutputs.c_str(), rawOutputs.size());
            auto txHashRef = brr.get_BinaryDataRef(32);

            auto& opMap = spenderMap[txHashRef];

            //get zctx
            auto txPtr = snapshot->getTxByHash(txHashRef);

            //TODO: harden loops running on count from client msg

            //run through txout indices
            auto outputCount = brr.get_var_int();
            if (outputCount >= 10000)
               throw runtime_error("outpout count overflow");

            for (size_t y = 0; y < outputCount; y++)
            {
               auto txOutIdx = brr.get_var_int();
               auto& spentnessData = opMap[txOutIdx];
               
               if (txPtr == nullptr)
                  continue;

               spentnessData.state_ = OutputSpentnessState::Unspent;

               //get output scrAddr
               auto& scrAddr = txPtr->outputs_[txOutIdx].scrAddr_;

               //get txiopair for this scrAddr
               auto txioMap = snapshot->getTxioMapForScrAddr(scrAddr);

               //create dbkey for output
               BinaryWriter bwKey;
               bwKey.put_BinaryData(txPtr->getKeyRef());
               bwKey.put_uint16_t((uint16_t)y, BE);

               //grab txio
               auto txioIter = txioMap.find(bwKey.getData());
               if (txioIter == txioMap.end())
                  continue;

               auto txRef = txioIter->second->getTxRefOfInput();
               auto spenderKey = txRef.getDBKeyRef();
               if (spenderKey.empty())
                  continue;

               //we have a spender in this txio, resolve the hash
               auto txFromSS = snapshot->getTxByKey(spenderKey);
               if (txFromSS == nullptr)
                  continue;

               spentnessData.spender_ = txFromSS->getTxHash();
               const auto& inputRef = txioIter->second->getTxRefOfInput();
               BinaryRefReader brr(inputRef.getDBKeyRef());
               brr.advance(2);
               spentnessData.height_ = brr.get_uint32_t(BE);
               spentnessData.state_ = OutputSpentnessState::Spent;
            }
         }
      } 
      
      //create response object
      auto response = make_shared<::Codec_Utxo::Spentness_BatchData>();
      response->set_count(spenderMap.size());
      for (auto& txHashPair : spenderMap)
      {
         auto txData = response->add_txdata();
         txData->set_hash(txHashPair.first.getPtr(), txHashPair.first.getSize());

         for (auto& opPair : txHashPair.second)
         {
            auto opData = txData->add_outputdata();

            opData->set_txoutindex(opPair.first);
            opData->set_state(opPair.second.state_);
            
            if (opPair.second.state_ != OutputSpentnessState::Spent)
               continue;

            opData->set_spenderheight(opPair.second.height_);
            opData->set_spenderhash(
               opPair.second.spender_.getCharPtr(), 
               opPair.second.spender_.getSize());
         }
      }

      resultingPayload = response;
      break;
   }

   case Methods::getOutputsForOutpoints:
   {
      /*
      in:
         output hash & id concatenated as:
         txhash (32) | txout count (varint) | txout index #1 (varint) | txout index #2 ...
         flag as bool: true to get zc outputs as well
      out:
         vector<UTXO>
      */

      if (command->bindata_size() == 0)
         throw runtime_error("expected bindata for getSpentnessForOutputs");

      bool withZc = command->flag();
      vector<pair<StoredTxOut, BinaryDataRef>> result;
      {
         map<BinaryDataRef, set<unsigned>> outpointMap;
         //grab the outputs pointed to by these outpoints
         for (int i = 0; i < command->bindata_size(); i++)
         {
            auto& rawOutputs = command->bindata(i);
            if (rawOutputs.size() < 33)
               throw runtime_error("malformed output data");

            BinaryRefReader brr((const uint8_t*)rawOutputs.c_str(), rawOutputs.size());
            auto txHashRef = brr.get_BinaryDataRef(32);

            auto& opSet = outpointMap[txHashRef];
            auto outputCount = brr.get_var_int();
            for (unsigned y = 0; y < outputCount; y++)
            {
               //set txout index
               uint16_t txOutId = brr.get_var_int();
               opSet.insert(txOutId);
            }
         }

         result = move(getOutputsForOutpoints(outpointMap, withZc));
      }

      auto response = make_shared<::Codec_Utxo::ManyUtxo>();
      for (auto& stxoPair : result)
      {
         auto& stxo = stxoPair.first;
         auto utxoPtr = response->add_value();
         utxoPtr->set_value(stxo.getValue());
         auto scriptRef = stxo.getScriptRef();
         utxoPtr->set_script(scriptRef.getPtr(), scriptRef.getSize());
         utxoPtr->set_txheight(stxo.getHeight());
         utxoPtr->set_txindex(stxo.txIndex_);
         utxoPtr->set_txoutindex(stxo.txOutIndex_);
         utxoPtr->set_txhash(
            stxoPair.second.getPtr(), stxoPair.second.getSize());
      }   

      resultingPayload = response;
      break;
   }

   default:
      LOGWARN << "unknown command";
      throw runtime_error("unknown command");
   }

   return BDVCommandProcess_Success;
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<BDV_Server_Object> Clients::get(const string& id) const
{
   auto bdvmap = BDVs_.get();
   auto iter = bdvmap->find(id);
   if (iter == bdvmap->end())
      return nullptr;

   return iter->second;
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::setup()
{
   started_.store(0, memory_order_relaxed);
   packetProcess_threadLock_.store(0, memory_order_relaxed);
   notificationProcess_threadLock_.store(0, memory_order_relaxed);

   isReadyPromise_ = make_shared<promise<bool>>();
   isReadyFuture_ = isReadyPromise_->get_future();
   auto lbdFut = isReadyFuture_;

   //unsafe, should consider creating the blockchain object as a shared_ptr
   auto bc = &blockchain();

   auto isReadyLambda = [lbdFut, bc](void)->unsigned
   {
      if (lbdFut.wait_for(chrono::seconds(0)) == future_status::ready)
      {
         return bc->top()->getBlockHeight();
      }

      return UINT32_MAX;
   };

   switch (Armory::Config::DBSettings::getServiceType())
   {
   case SERVICE_WEBSOCKET:
   case SERVICE_UNITTEST_WITHWS:
   {
      auto&& bdid = READHEX(getID());
      if (bdid.getSize() != 8)
         throw runtime_error("invalid bdv id");

      auto intid = (uint64_t*)bdid.getPtr();
      cb_ = make_unique<WS_Callback>(*intid);
      break;
   }
   
   case SERVICE_UNITTEST:
      cb_ = make_unique<UnitTest_Callback>();
      break;

   default:
      throw runtime_error("unexpected service type");
   }
}

///////////////////////////////////////////////////////////////////////////////
BDV_Server_Object::BDV_Server_Object(
   const string& id, BlockDataManagerThread *bdmT) :
   BlockDataViewer(bdmT->bdm()), bdvID_(id), bdmT_(bdmT)
{
   setup();
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::startThreads()
{
   if (started_.fetch_or(1, memory_order_relaxed) != 0)
      return;
   
   auto initLambda = [this](void)->void
   { this->init(); };

   initT_ = thread(initLambda);
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::haltThreads()
{
   if(cb_ != nullptr)
      cb_->shutdown();
   if (initT_.joinable())
      initT_.join();
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::init()
{
   bdmPtr_->blockUntilReady();

   while (1)
   {
      map<string, walletRegStruct> wltMap;

      {
         unique_lock<mutex> lock(registerWalletMutex_);

         if (wltRegMap_.size() == 0)
            break;

         wltMap = move(wltRegMap_);
         wltRegMap_.clear();
      }

      //create address batch
      auto batch = make_shared<RegistrationBatch>();
      batch->isNew_ = false;

      //fill with addresses from protobuf payloads
      for (auto& wlt : wltMap)
      {
         for (int i = 0; i < wlt.second.command_->bindata_size(); i++)
         {
            auto& addrStr = wlt.second.command_->bindata(i);
            if (addrStr.size() == 0)
               continue;

            BinaryDataRef addrRef; addrRef.setRef(addrStr);
            batch->scrAddrSet_.insert(move(addrRef));
         }
      }

      //callback only serves to wait on the registration event
      auto promPtr = make_shared<promise<bool>>();
      auto fut = promPtr->get_future();
      auto callback = [promPtr](set<BinaryDataRef>&)->void
      {
         promPtr->set_value(true);
      };

      batch->callback_ = callback;

      //register the batch
      auto saf = bdmPtr_->getScrAddrFilter();
      saf->pushAddressBatch(batch);
      fut.get();

      //addresses are now registered, populate the wallet maps
      populateWallets(wltMap);
   }

   //could a wallet registration event get lost in between the init loop 
   //and setting the promise?

   //init wallets
   auto&& notifPtr = make_unique<BDV_Notification_Init>();
   scanWallets(move(notifPtr));

   //create zc packet and pass to wallets
   auto addrSet = getAddrSet();
   auto zcstruct = createZcNotification(addrSet);
   auto zcAction = dynamic_cast<BDV_Notification_ZC*>(zcstruct.get());
   if (zcAction != nullptr && zcAction->packet_.scrAddrToTxioKeys_.size() > 0)
      scanWallets(move(zcstruct));
   
   //mark bdv object as ready
   isReadyPromise_->set_value(true);

   //callback client with BDM_Ready packet
   auto message = make_shared<BDVCallback>();
   auto notif = message->add_notification();
   notif->set_type(NotificationType::ready);
   auto newBlockNotif = notif->mutable_newblock();
   newBlockNotif->set_height(blockchain().top()->getBlockHeight());
   cb_->callback(message);
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::processNotification(
   shared_ptr<BDV_Notification> notifPtr)
{
   auto action = notifPtr->action_type();
   if (action < BDV_Progress)
   {
      //skip all but progress notifications if BDV isn't ready
      if (isReadyFuture_.wait_for(chrono::seconds(0)) != future_status::ready)
         return;
   }

   scanWallets(notifPtr);

   auto callbackPtr = make_shared<BDVCallback>();

   switch (action)
   {
   case BDV_NewBlock:
   {
      auto notif = callbackPtr->add_notification();
      notif->set_type(NotificationType::newblock);
      auto&& payload =
         dynamic_pointer_cast<BDV_Notification_NewBlock>(notifPtr);

      auto newblockNotif = notif->mutable_newblock();
      newblockNotif->set_height(payload->reorgState_.newTop_->getBlockHeight());
      if (!payload->reorgState_.prevTopStillValid_)
      {
         newblockNotif->set_branch_height(
            payload->reorgState_.reorgBranchPoint_->getBlockHeight());
      }

      if (payload->zcPurgePacket_ != nullptr && 
         payload->zcPurgePacket_->invalidatedZcKeys_.size() != 0)
      {
         auto notif = callbackPtr->add_notification();
         notif->set_type(NotificationType::invalidated_zc);
         
         auto ids = notif->mutable_ids();
         for (auto& id : payload->zcPurgePacket_->invalidatedZcKeys_)
         {
            auto idPtr = ids->add_value();
            idPtr->set_data(id.second.getPtr(), id.second.getSize());
         }
      }

      break;
   }

   case BDV_Refresh:
   {
      auto&& payload =
         dynamic_pointer_cast<BDV_Notification_Refresh>(notifPtr);

      auto& bdId = payload->refreshID_;

      auto notif = callbackPtr->add_notification();
      notif->set_type(NotificationType::refresh);
      auto refresh = notif->mutable_refresh();
      refresh->set_refreshtype(payload->refresh_);
      refresh->add_id(bdId.getPtr(), bdId.getSize());

      break;
   }

   case BDV_ZC:
   {
      auto&& payload =
         dynamic_pointer_cast<BDV_Notification_ZC>(notifPtr);
      payload->packet_.toProtobufNotification(callbackPtr, payload->leVec_);

      break;
   }

   case BDV_Progress:
   {
      auto&& payload =
         dynamic_pointer_cast<BDV_Notification_Progress>(notifPtr);

      auto notif = callbackPtr->add_notification();
      notif->set_type(NotificationType::progress);
      auto pd = notif->mutable_progress();

      pd->set_phase(payload->phase_);
      pd->set_progress(payload->progress_);
      pd->set_time(payload->time_);
      pd->set_numericprogress(payload->numericProgress_);
      for (auto& id : payload->walletIDs_)
         pd->add_id(move(id));
    
      break;
   }

   case BDV_NodeStatus:
   {
      auto&& payload =
         dynamic_pointer_cast<BDV_Notification_NodeStatus>(notifPtr);

      auto notif = callbackPtr->add_notification();
      notif->set_type(NotificationType::nodestatus);
      auto status = notif->mutable_nodestatus();

      auto& nodeStatus = payload->status_;

      status->set_state((unsigned)nodeStatus.state_);
      status->set_segwitenabled(nodeStatus.SegWitEnabled_);
      status->set_rpcstate((unsigned)nodeStatus.rpcState_);

      auto chainStatus_proto = new Codec_NodeStatus::NodeChainStatus();
      chainStatus_proto->set_state((unsigned)nodeStatus.chainStatus_.state());
      chainStatus_proto->set_blockspeed(nodeStatus.chainStatus_.getBlockSpeed());
      chainStatus_proto->set_eta(nodeStatus.chainStatus_.getETA());
      chainStatus_proto->set_pct(nodeStatus.chainStatus_.getProgressPct());
      chainStatus_proto->set_blocksleft(nodeStatus.chainStatus_.getBlocksLeft());
      status->set_allocated_chainstatus(chainStatus_proto);

      break;
   }

   case BDV_Action::BDV_Error:
   {
      auto&& payload =
         dynamic_pointer_cast<BDV_Notification_Error>(notifPtr);

      auto notif = callbackPtr->add_notification();
      notif->set_type(NotificationType::error);
      auto error = notif->mutable_error();

      error->set_code(payload->errStruct.errCode_);      
      if (!payload->errStruct.errData_.empty())
      {
         error->set_errdata(
            payload->errStruct.errData_.getCharPtr(), 
            payload->errStruct.errData_.getSize());
      }

      if (!payload->errStruct.errorStr_.empty())
      {
         error->set_errstr(payload->errStruct.errorStr_);
      }

      if (!payload->requestID_.empty())
      {
         notif->set_requestid(payload->requestID_);
      }

      break;
   }

   default:
      return;
   }

   if(callbackPtr->notification_size() > 0)
      cb_->callback(callbackPtr);
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::registerWallet(
   shared_ptr<::Codec_BDVCommand::BDVCommand> command)
{
   if (isReadyFuture_.wait_for(chrono::seconds(0)) != future_status::ready)
   {
      //sanity check
      if (!command->has_hash() || command->hash().size() == 0)
         throw runtime_error("invalid registerWallet command");

      //only run this code if the bdv maintenance thread hasn't started yet
      unique_lock<mutex> lock(registerWalletMutex_);
      
      //save data
      auto& wltregstruct = wltRegMap_[command->hash()];
      wltregstruct.command_ = command;
      wltregstruct.type_ = TypeWallet;

      auto notif = make_unique<BDV_Notification_Refresh>(
         getID(), BDV_registrationCompleted, 
         BinaryData::fromString(command->hash()));
      notifLambda_(move(notif));

      return;
   }

   //register wallet with BDV
   auto bdvPtr = (BlockDataViewer*)this;
   bdvPtr->registerWallet(command);
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::registerLockbox(
   shared_ptr<::Codec_BDVCommand::BDVCommand> command)
{
   if (isReadyFuture_.wait_for(chrono::seconds(0)) != future_status::ready)
   {
      //sanity check
      if (!command->has_hash() || command->hash().size() == 0)
         throw runtime_error("invalid registerWallet command");

      //only run this code if the bdv maintenance thread hasn't started yet
      unique_lock<mutex> lock(registerWalletMutex_);

      //save data
      auto& wltregstruct = wltRegMap_[command->hash()];
      wltregstruct.command_ = command;
      wltregstruct.type_ = TypeLockbox;

      auto notif = make_unique<BDV_Notification_Refresh>(
         getID(), BDV_registrationCompleted, 
         BinaryData::fromString(command->hash()));
      notifLambda_(move(notif));
      return;
   }

   //register wallet with BDV
   auto bdvPtr = (BlockDataViewer*)this;
   bdvPtr->registerLockbox(command);
}

///////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::populateWallets(map<string, walletRegStruct>& wltMap)
{
   auto safPtr = getSAF();
   auto addrMap = safPtr->getScanFilterAddrMap();

   for (auto& wlt : wltMap)
   {
      auto& walletId = wlt.second.command_->walletid();

      shared_ptr<BtcWallet> theWallet;
      if (wlt.second.type_ == TypeWallet)
         theWallet = groups_[group_wallet].getOrSetWallet(walletId);
      else
         theWallet = groups_[group_lockbox].getOrSetWallet(walletId);

      if (theWallet == nullptr)
      {
         LOGERR << "failed to get or set wallet";
         continue;
      }

      map<BinaryDataRef, shared_ptr<ScrAddrObj>> newAddrMap;
      for (int i = 0; i < wlt.second.command_->bindata_size(); i++)
      {
         auto& addrStr = wlt.second.command_->bindata(i);
         BinaryDataRef addrRef; addrRef.setRef(addrStr);

         if (theWallet->hasScrAddress(addrRef))
            continue;

         auto iter = addrMap->find(addrRef);
         if (iter == addrMap->end())
            throw runtime_error("address missing from saf");

         auto addrObj = make_shared<ScrAddrObj>(
            db_, &blockchain(), zeroConfCont_.get(), iter->first);
         newAddrMap.insert(move(make_pair(iter->first, addrObj)));
      }

      if (newAddrMap.size() == 0)
         continue;

      theWallet->scrAddrMap_.update(newAddrMap);
   }
}

////////////////////////////////////////////////////////////////////////////////
void BDV_Server_Object::flagRefresh(
   BDV_refresh refresh, const BinaryData& refreshID,
   unique_ptr<BDV_Notification_ZC> zcPtr)
{
   auto notif = make_unique<BDV_Notification_Refresh>(
      getID(), refresh, refreshID);
   if (zcPtr != nullptr)
      notif->zcPacket_ = move(zcPtr->packet_);

   if (notifLambda_)
      notifLambda_(move(notif));
}

////////////////////////////////////////////////////////////////////////////////
BDVCommandProcessingResultType BDV_Server_Object::processPayload(
   shared_ptr<BDV_Payload>& packet, shared_ptr<Message>& result)
{
   /*
   Only ever one thread gets this far at any given time, therefor none of the
   underlying objects need to be thread safe
   */

   if (packet == nullptr)
   {
      LOGWARN << "null packet";
      return BDVCommandProcess_PayloadNotReady;
   }

   auto nextId = lastValidMessageId_ + 1;

   if (packet->packetData_.getSize() != 0)
   {
      //grab and check the packet's message id
      auto msgId = BDV_PartialMessage::getMessageId(packet);

      if (msgId != UINT32_MAX)
      {
         //get the PartialMessage object for this id
         auto msgIter = messageMap_.find(msgId);
         if (msgIter == messageMap_.end())
         {
            //create this PartialMessage if it's missing
            msgIter = messageMap_.emplace(
               make_pair(msgId, BDV_PartialMessage())).first;
         }

         auto& msgRef = msgIter->second;

         //try to reconstruct the message
         shared_ptr<BDV_Payload> currentPacket = packet;
         auto parsed = msgRef.parsePacket(currentPacket);
         if (!parsed)
         {
            //failed to reconstruct from this packet, this 
            //shouldn't happen anymore
            LOGWARN << "failed to parse packet, reinjecting. " <<
               "!This shouldn't happen anymore!";

            return BDVCommandProcess_Failure;
         }

         //some verbose, this can be removed later
         if (msgIter->second.isReady())
         {
            if (msgId >= lastValidMessageId_ + 10)
               LOGWARN << "completed a message that exceeds the counter by " <<
                  msgId - lastValidMessageId_;

            if (msgId != nextId)
               return BDVCommandProcess_PayloadNotReady;
         }
         else
         {
            return BDVCommandProcess_PayloadNotReady;
         }
      }
   }

   //grab the expected next message
   auto msgIter = messageMap_.find(nextId);

   //exit if we dont have this message id
   if (msgIter == messageMap_.end())
      return BDVCommandProcess_PayloadNotReady;

   //or the message isn't complete
   if (!msgIter->second.isReady())
      return BDVCommandProcess_PayloadNotReady;

   //move in the completed message, it now lives within this scope
   auto msgObj = move(msgIter->second);

   //clean up from message map
   messageMap_.erase(msgIter);

   //update ids
   lastValidMessageId_ = nextId;
   packet->messageID_ = nextId;

   //parse the protobuf payload
   auto message = make_shared<BDVCommand>();
   if (!msgObj.getMessage(message))
   {
      //failed, this could be a different type of protobuf message
      auto staticCommand = make_shared<StaticCommand>();
      if (msgObj.getMessage(staticCommand))
      {   
         result = staticCommand;
         return BDVCommandProcess_Static;
      }

      return BDVCommandProcess_Failure;
   }
      
   try
   {
      return processCommand(message, result);
   }
   catch (exception &e)
   {
      auto errMsg = make_shared<::Codec_BDVCommand::BDV_Error>();
      stringstream ss;
      ss << "Error processing command: " << (int)message->method() << endl;
      ss << "   errMsg: \"" << e.what() << "\"";

      errMsg->set_code(-1);
      errMsg->set_errstr(ss.str());
         
      result = errMsg;
   }
      
   return BDVCommandProcess_Failure;
}

///////////////////////////////////////////////////////////////////////////////
//
// Clients
//
///////////////////////////////////////////////////////////////////////////////
void Clients::init(BlockDataManagerThread* bdmT,
   function<void(void)> shutdownLambda)
{
   bdmT_ = bdmT;
   shutdownCallback_ = shutdownLambda;

   run_.store(true, memory_order_relaxed);

   auto mainthread = [this](void)->void
   {
      notificationThread();
   };

   auto outerthread = [this](void)->void
   {
      bdvMaintenanceLoop();
   };

   auto innerthread = [this](void)->void
   {
      bdvMaintenanceThread();
   };

   auto parserThread = [this](void)->void
   {
      this->messageParserThread();
   };

   auto unregistrationThread = [this](void)->void
   {
      this->unregisterBDVThread();
   };

   auto rpcThread = [this](void)->void
   {
      this->broadcastThroughRPC();
   };

   controlThreads_.push_back(thread(mainthread));
   controlThreads_.push_back(thread(outerthread));
   controlThreads_.push_back(thread(rpcThread));
   unregThread_ = thread(unregistrationThread);

   unsigned innerThreadCount = 2;
   if (Armory::Config::DBSettings::getDbType() == ARMORY_DB_SUPER &&
      Armory::Config::DBSettings::getServiceType() != SERVICE_UNITTEST)
      innerThreadCount = thread::hardware_concurrency();
   for (unsigned i = 0; i < innerThreadCount; i++)
   {
      controlThreads_.push_back(thread(innerthread));
      controlThreads_.push_back(thread(parserThread));
   }

   auto callbackPtr = make_unique<ZeroConfCallbacks_BDV>(this);
   bdmT_->bdm()->registerZcCallbacks(move(callbackPtr));
}

///////////////////////////////////////////////////////////////////////////////
void Clients::bdvMaintenanceLoop()
{
   while (1)
   {
      shared_ptr<BDV_Notification> notifPtr;
      try
      {
         notifPtr = move(outerBDVNotifStack_.pop_front());
      }
      catch (StopBlockingLoop&)
      {
         LOGINFO << "Shutting down BDV event loop";
         break;
      }

      auto bdvMap = BDVs_.get();
      auto& bdvID = notifPtr->bdvID();
      if (bdvID.size() == 0)
      {
         //empty bdvID means broadcast notification to all BDVs
         for (auto& bdv_pair : *bdvMap)
         {
            auto notifPacket = make_shared<BDV_Notification_Packet>();
            notifPacket->bdvPtr_ = bdv_pair.second;
            notifPacket->notifPtr_ = notifPtr;
            innerBDVNotifStack_.push_back(move(notifPacket));
         }
      }
      else
      {
         //grab bdv
         auto iter = bdvMap->find(bdvID);
         if (iter == bdvMap->end())
            continue;

         auto notifPacket = make_shared<BDV_Notification_Packet>();
         notifPacket->bdvPtr_ = iter->second;
         notifPacket->notifPtr_ = notifPtr;
         innerBDVNotifStack_.push_back(move(notifPacket));
      }
   }
}

///////////////////////////////////////////////////////////////////////////////
void Clients::bdvMaintenanceThread()
{
   while (1)
   {
      shared_ptr<BDV_Notification_Packet> notifPtr;
      try
      {
         notifPtr = move(innerBDVNotifStack_.pop_front());
      }
      catch (StopBlockingLoop&)
      {
         break;
      }

      if (notifPtr->bdvPtr_ == nullptr)
      {
         LOGWARN << "null bdvPtr in notification";
         continue;
      }

      auto bdvPtr = notifPtr->bdvPtr_;
      unsigned zero = 0;
      if (!bdvPtr->notificationProcess_threadLock_.compare_exchange_weak(
         zero, 1))
      {
         //Failed to grab lock, there's already a thread processing a payload
         //for this bdv. Insert the payload back into the queue. Another 
         //thread will eventually pick it up and successfully grab the lock 
         if (notifPtr == nullptr)
            LOGERR << "!!!!!! empty notif at reinsertion";

         innerBDVNotifStack_.push_back(move(notifPtr));
         continue;
      }

      bdvPtr->processNotification(notifPtr->notifPtr_);
      bdvPtr->notificationProcess_threadLock_.store(0);
   }
}

///////////////////////////////////////////////////////////////////////////////
void Clients::processShutdownCommand(shared_ptr<StaticCommand> command)
{
   const auto& thisCookie = Armory::Config::NetworkSettings::cookie();
   if (thisCookie.empty())
      return;

   try
   {
      if (!command->has_cookie())
         throw runtime_error("malformed command for processShutdownCommand");
      auto& cookie = command->cookie();

      if ((cookie.size() == 0) || (cookie != thisCookie))
         throw runtime_error("spawnId mismatch");
   }
   catch (...)
   {
      return;
   }

   switch (command->method())
   {
   case StaticMethods::shutdown:
   {
      auto shutdownLambda = [this](void)->void
      {
         this->exitRequestLoop();
      };

      //run shutdown sequence in its own thread so that the server listen
      //loop can exit properly.
      thread shutdownThr(shutdownLambda);
      if (shutdownThr.joinable())
         shutdownThr.detach();
      break;
   }

   case StaticMethods::shutdownNode:
   {
      if (bdmT_->bdm()->nodeRPC_ != nullptr)
         bdmT_->bdm()->nodeRPC_->shutdown();
      break;
   }

   default:
      LOGWARN << "unexpected command in processShutdownCommand";
   }
}

///////////////////////////////////////////////////////////////////////////////
void Clients::shutdown()
{
   unique_lock<mutex> lock(shutdownMutex_, defer_lock);
   if (!lock.try_lock())
      return;
   
   /*shutdown sequence*/
   if (!run_.load(memory_order_relaxed))
      return;

   //prevent all new commands from running
   run_.store(false, memory_order_relaxed);

   //shutdown rpc write queue
   rpcBroadcastQueue_.terminate();

   //shutdown Clients gc thread
   gcCommands_.completed();

   //shutdown unregistration thread and wait on it
   unregBDVQueue_.terminate();
   if (unregThread_.joinable())
      unregThread_.join();

   //cleanup all BDVs
   unregisterAllBDVs();

   //shutdown maintenance threads
   outerBDVNotifStack_.completed();
   innerBDVNotifStack_.completed();
   packetQueue_.terminate();

   //exit BDM maintenance thread
   if (!bdmT_->shutdown())
      return;

   vector<thread::id> idVec;
   for (auto& thr : controlThreads_)
   {
      idVec.push_back(thr.get_id());
      if (thr.joinable())
         thr.join();
   }

   //shutdown ZC container
   bdmT_->bdm()->disableZeroConf();
   bdmT_->bdm()->getScrAddrFilter()->shutdown();
}

///////////////////////////////////////////////////////////////////////////////
void Clients::exitRequestLoop()
{
   /*terminate request processing loop*/
   LOGINFO << "proceeding to shutdown";

   //shutdown loop on server side
   if (shutdownCallback_)
      shutdownCallback_();
}

///////////////////////////////////////////////////////////////////////////////
void Clients::unregisterAllBDVs()
{
   auto bdvs = BDVs_.get();
   BDVs_.clear();

   for (auto& bdv : *bdvs)
      bdv.second->haltThreads();
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<Message> Clients::registerBDV(
   shared_ptr<StaticCommand> command, string bdvID)
{
   try
   {
      if (!command->has_magicword())
         throw runtime_error("invalid command for registerBDV");
      auto& magic_word = command->magicword();
      BinaryDataRef magic_word_ref; magic_word_ref.setRef(magic_word);
      auto& thisMagicWord = Armory::Config::BitcoinSettings::getMagicBytes();

      if (thisMagicWord != magic_word_ref)
         throw runtime_error("magic word mismatch");
   }
   catch (runtime_error& e)
   {
      auto response = make_shared<::Codec_BDVCommand::BDV_Error>();
      response->set_code(-1);
      response->set_errstr(e.what());
      return response;
   }

   if (bdvID.size() == 0)
      bdvID = BtcUtils::fortuna_.generateRandom(10).toHexStr();
   auto newBDV = make_shared<BDV_Server_Object>(bdvID, bdmT_);

   auto notiflbd = [this](unique_ptr<BDV_Notification> notifPtr)
   {
      this->outerBDVNotifStack_.push_back(move(notifPtr));
   };

   newBDV->notifLambda_ = notiflbd;

   //add to BDVs map
   string newID(newBDV->getID());
   BDVs_.insert(move(make_pair(newID, newBDV)));

   LOGINFO << "registered bdv: " << newID;

   auto response = make_shared<::Codec_CommonTypes::BinaryData>();
   response->set_data(newID);
   return response;
}

///////////////////////////////////////////////////////////////////////////////
void Clients::unregisterBDV(std::string bdvId)
{
   unregBDVQueue_.push_back(move(bdvId));
}

///////////////////////////////////////////////////////////////////////////////
void Clients::unregisterBDVThread()
{
   while(true)
   {
      //grab bdv id
      string bdvId;
      try
      {
         bdvId = move(unregBDVQueue_.pop_front());
      }
      catch(StopBlockingLoop&)
      {
         break;
      }
      
      //grab bdv ptr
      shared_ptr<BDV_Server_Object> bdvPtr;
      {
         auto bdvMap = BDVs_.get();
         auto bdvIter = bdvMap->find(bdvId);
         if (bdvIter == bdvMap->end())
            return;

         //copy shared_ptr and erase from bdv map
         bdvPtr = bdvIter->second;
         BDVs_.erase(bdvId);
      }

      if (bdvPtr == nullptr)
      {
         LOGERR << "empty bdv ptr before unregistration";
         return;
      }

      //shutdown bdv threads
      bdvPtr->haltThreads();

      //done
      bdvPtr.reset();
      LOGINFO << "unregistered bdv: " << bdvId;
   }
}

///////////////////////////////////////////////////////////////////////////////
void Clients::notificationThread(void) const
{
   if (bdmT_ == nullptr)
      throw runtime_error("invalid BDM thread ptr");

   while (1)
   {
      bool timedout = true;
      shared_ptr<BDV_Notification> notifPtr;

      try
      {
         notifPtr = move(bdmT_->bdm()->notificationStack_.pop_front(
            chrono::seconds(60)));
         if (notifPtr == nullptr)
            continue;
         timedout = false;
      }
      catch (StackTimedOutException&)
      {
         //nothing to do
      }
      catch (StopBlockingLoop&)
      {
         return;
      }
      catch (IsEmpty&)
      {
         LOGERR << "caught isEmpty in Clients maintenance loop";
         continue;
      }

      //trigger gc thread
      if (timedout == true || notifPtr->action_type() != BDV_Progress)
         gcCommands_.push_back(true);

      //don't go any futher if there is no new top
      if (timedout)
         continue;

      outerBDVNotifStack_.push_back(move(notifPtr));
   }
}

///////////////////////////////////////////////////////////////////////////////
void Clients::messageParserThread(void)
{
   while (1)
   {
      shared_ptr<BDV_Payload> payloadPtr;
      
      try
      {
         payloadPtr = move(packetQueue_.pop_front());
      }
      catch (StopBlockingLoop&)
      {
         break;
      }

      //sanity check
      if (payloadPtr == nullptr)
      {
         LOGERR << "????????? empty payload";
         continue;
      }

      if (payloadPtr->bdvPtr_ == nullptr)
      {
         LOGERR << "???????? empty bdv ptr";
         continue;
      }

      auto bdvPtr = payloadPtr->bdvPtr_;
      unsigned zero = 0;
      if (!bdvPtr->packetProcess_threadLock_.compare_exchange_weak(
            zero, 1, memory_order_relaxed, memory_order_relaxed))
      {
         //Failed to grab lock, there's already a thread processing a payload
         //for this bdv. Insert the payload back into the queue. Another 
         //thread will eventually pick it up and successfully grab the lock 
         if(payloadPtr == nullptr)
            LOGERR << "!!!!!! empty payload at reinsertion";

         packetQueue_.push_back(move(payloadPtr));
         continue;
      }

      /*
      Grabbed the thread lock, time to process the payload.

      However, since the thread lock is only a spin lock with loose ordering
      semantics (for speed), we need the current thread to be up to date with 
      all changes previous threads have made to this bdv object, hence acquiring 
      the object's process mutex
      */
      unique_lock<mutex> lock(bdvPtr->processPacketMutex_);
      auto result = processCommand(payloadPtr);

      //check if the map has the next message
      {
         auto msgIter = bdvPtr->messageMap_.find(
            bdvPtr->lastValidMessageId_ + 1);
         
         if (msgIter != bdvPtr->messageMap_.end() && 
            msgIter->second.isReady())
         {
            /*
            We have the next message and it is ready, push a packet
            with no data on the queue to assign this bdv a new processing
            thread. 
            
            This is done because we don't want one bdv to hog a thread 
            constantly if it has a lot of queue up messages. It should
            complete for a thread like all other bdv objects, regardless
            of the its message queue depth.
            */
            auto flagPacket = make_shared<BDV_Payload>();
            flagPacket->bdvPtr_ = bdvPtr;
            flagPacket->bdvID_ = payloadPtr->bdvID_;
            packetQueue_.push_back(move(flagPacket));
         }
      }
      
      //release the locks
      lock.unlock();
      bdvPtr->packetProcess_threadLock_.store(0);

      //write return value if any
      if (result != nullptr)
         WebSocketServer::write(
            payloadPtr->bdvID_, payloadPtr->messageID_, result);
   }
}

///////////////////////////////////////////////////////////////////////////////
void Clients::broadcastThroughRPC()
{
   auto notifyError = [this](
      const BinaryData& hash, std::shared_ptr<BDV_Server_Object> bdvPtr,
      int errCode, const std::string& verbose,
      const string& requestID)->void
   {
      auto notifPacket = make_shared<BDV_Notification_Packet>();
      notifPacket->bdvPtr_ = bdvPtr;
      notifPacket->notifPtr_ = make_shared<BDV_Notification_Error>(
         bdvPtr->getID(), requestID, errCode, hash, verbose);
      innerBDVNotifStack_.push_back(move(notifPacket));
   };

   while (true)
   {
      RpcBroadcastPacket packet;
      try
      {
         packet = move(rpcBroadcastQueue_.pop_front());
      }
      catch (StopBlockingLoop&)
      {
         break;
      }

      //create & set a zc batch for this tx
      Tx tx(*packet.rawTx_);
      vector<BinaryData> hashes = { tx.getThisHash() };
      auto zcPtr = bdmT_->bdm()->zeroConfCont();

      //feed the watcher map with all relevant requestor/bdv ids
      {
         //if this is a RPC fallback from a timed out P2P zc push
         //we may have extra requestors attached to this broadcast
         map<string, string> extraRequestors;
         for (auto& reqPair : packet.extraRequestors_)
            extraRequestors.emplace(reqPair.first, reqPair.second->getID());

         if (!zcPtr->insertWatcherEntry(
            *hashes.begin(), packet.rawTx_, //tx
            packet.bdvPtr_->getID(), packet.requestID_, //main requestor
            extraRequestors, //extra requestor, in case this is a fallback
            false)) //do not process watcher node invs for this entry
         {
            //there is already a watcher entry for this tx, our request has been 
            //attached to it, skip the RPC broadcast
            continue;
         }
      }

      auto batchPtr = zcPtr->initiateZcBatch(
         hashes, 
         0, //no timeout, this batch promise has to be set to progress
         nullptr, //no error callback
         true,
         packet.bdvPtr_->getID(),
         packet.requestID_);

      //push to rpc
      string verbose;
      auto result =
         bdmT_->bdm()->nodeRPC_->broadcastTx(packet.rawTx_->getRef(), verbose);

      switch (ArmoryErrorCodes(result))
      {
      case ArmoryErrorCodes::Success:
      {
         /*
         RPC zc broadcast will return success whether the tx was in 
         the node's mempool or not.
         */

         //fulfill the batch to parse the tx
         try 
         {
            //set the tx body and batch promise
            auto txPtr = batchPtr->zcMap_.begin()->second;
            txPtr->tx_.unserialize(*packet.rawTx_);
            txPtr->tx_.setTxTime(time(0));
            batchPtr->isReadyPromise_->set_value(ArmoryErrorCodes::Success);
         }
         catch (future_error&)
         {
            LOGWARN << "rpc broadcast promise was already set";
         }

         //signal all extra requestors for an already-in-mempool error
         for (auto& requestor : packet.extraRequestors_)
         {
            notifyError(*hashes.begin(), requestor.second, 
               (int)ArmoryErrorCodes::ZcBroadcast_AlreadyInMempool, 
               "Extra requestor RPC broadcast error: Already in mempool",
               requestor.first);
         }

         LOGINFO << "rpc broadcast success";
         break;
      }

      default:
         LOGINFO << "RPC broadcast for tx: " << hashes.begin()->toHexStr() << 
            ", verbose: " << verbose;

         //cleanup watcher map
         auto watcherEntry = zcPtr->eraseWatcherEntry(*hashes.begin());
         if (watcherEntry != nullptr)
         {
            /*
            The watcher entry may have received extra requestors we
            didn't start with. We need to add those to our RPC packet
            requestor map. Those carry full on BDV objects so we need
            to curate the map first (for our own extra requestors), then
            resolve the IDs to the BDV objects.
            */
            auto extraReqIter = watcherEntry->extraRequestors_.begin();
            while (extraReqIter != watcherEntry->extraRequestors_.end())
            {
               if (packet.extraRequestors_.find(extraReqIter->first) !=
                  packet.extraRequestors_.end())
               {
                  watcherEntry->extraRequestors_.erase(extraReqIter++);
                  continue;
               }

               ++extraReqIter;
            }

            if (!watcherEntry->extraRequestors_.empty())
            {
               auto bdvMap = BDVs_.get();
               for (auto& extraReq : watcherEntry->extraRequestors_)
               {
                  auto bdvIter = bdvMap->find(extraReq.second);
                  if (bdvIter == bdvMap->end())
                     continue;

                  packet.extraRequestors_.emplace(
                     extraReq.first, bdvIter->second);
               }
            }
         }

         //fail the batch promise
         batchPtr->isReadyPromise_->set_exception(
            make_exception_ptr(ZcBatchError()));

         //notify the bdv of the error
         stringstream errMsg;
         errMsg << "RPC broadcast error: " << verbose;
         notifyError(*hashes.begin(), packet.bdvPtr_, 
            result, errMsg.str(), packet.requestID_);         

         //notify extra requestors of the error as well
         for (auto& requestor : packet.extraRequestors_)
         {
            stringstream reqMsg;
            reqMsg << "Extra requestor broadcast error: " << verbose;
            notifyError(*hashes.begin(), requestor.second, 
               result, reqMsg.str(), requestor.first);
         }
      }
   }
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<Message> Clients::processCommand(shared_ptr<BDV_Payload> payload)
{
   //clear bdvPtr from the payload to avoid circular ownership
   auto bdvPtr = payload->bdvPtr_;
   payload->bdvPtr_.reset();

   //process payload
   shared_ptr<Message> _result;
   auto status = bdvPtr->processPayload(payload, _result);

   switch (status)
   {
   case BDVCommandProcess_Static:
   {
      auto staticCommand = dynamic_pointer_cast<StaticCommand>(_result);
      if (staticCommand == nullptr)
         return nullptr;

      _result = processUnregisteredCommand(payload->bdvID_, staticCommand);
      break;
   }

   /*
   ZC commands are processed by Clients since they require the BDV ptr
   */

   case BDVCommandProcess_ZC_P2P:
   {
      //cast to bdv_command
      auto message = dynamic_pointer_cast<BDVCommand>(_result);
      if (message == nullptr)
         return nullptr;

      /*
      Reset _result as broadcast commands do not have return values. 
      ZC broadcast notifications are delivered through the callback API.
      */
      _result = nullptr;

      /*
      in: raw tx as bindata
          broadcastId as hash
      out: void
      */

      if (message->bindata_size() == 0)
         break;

      vector<BinaryDataRef> rawZcVec;
      rawZcVec.reserve(message->bindata_size());
      for (int i=0; i<message->bindata_size(); i++)
      {
         const auto& rawTx = message->bindata(i);
         if (rawTx.size() == 0)
            continue;
         BinaryDataRef rawTxRef; rawTxRef.setRef(rawTx);
         rawZcVec.push_back(rawTxRef);
      }

      const auto& broadcastId = message->hash();
      if (broadcastId.size() != BROADCAST_ID_LENGTH * 2)
         return nullptr;

      //TODO: do not tolerate duplicate broadcast ids

      auto errorCallback = [this, bdvPtr, broadcastId](
         vector<ZeroConfBatchFallbackStruct> zcVec)->void
      {
         vector<RpcBroadcastPacket> rpcPackets;

         auto bdvMap = BDVs_.get();
         for (auto& fallbackStruct : zcVec)
         {
            map<string, shared_ptr<BDV_Server_Object>> extraRequestors;
            for (auto& extraBdvId : fallbackStruct.extraRequestors_)
            {
               auto iter = bdvMap->find(extraBdvId.second);
               if (iter == bdvMap->end())
                  continue;

               extraRequestors.emplace(extraBdvId.first, iter->second);
            }

            if (fallbackStruct.err_ != ArmoryErrorCodes::ZcBatch_Timeout)
            {
               //signal error to caller
               auto notifPacket = make_shared<BDV_Notification_Packet>();
               notifPacket->bdvPtr_ = bdvPtr;
               notifPacket->notifPtr_ = make_shared<BDV_Notification_Error>(
                  bdvPtr->getID(), broadcastId, (int)fallbackStruct.err_,
                  fallbackStruct.txHash_, string());
               innerBDVNotifStack_.push_back(move(notifPacket));

               //then signal extra requestors
               for (auto& extraBDV : extraRequestors)
               {
                  auto notifPacket = make_shared<BDV_Notification_Packet>();
                  notifPacket->bdvPtr_ = extraBDV.second;
                  notifPacket->notifPtr_ = make_shared<BDV_Notification_Error>(
                     extraBDV.second->getID(), extraBDV.first, (int)fallbackStruct.err_,
                     fallbackStruct.txHash_, string());
                  innerBDVNotifStack_.push_back(move(notifPacket));                  
               }

               //finally, skip RPC fallback
               continue;
            }

            //tally timed out zc
            RpcBroadcastPacket packet;
            packet.rawTx_ = fallbackStruct.rawTxPtr_;
            packet.bdvPtr_ = bdvPtr;
            packet.extraRequestors_ = move(extraRequestors);
            packet.requestID_ = broadcastId;
            rpcPackets.push_back(move(packet));
         }

         if (rpcPackets.empty())
            return;

         //push through rpc
         for (auto& packet : rpcPackets)
            rpcBroadcastQueue_.push_back(move(packet));
      };

      //run through submitted ZCs, prune already mined ones
      for (auto& rawZcRef : rawZcVec)
      {
         Tx tx(rawZcRef);
         auto hash = tx.getThisHash();

         auto dbKey = bdvPtr->db_->getDBKeyForHash(hash);
         if (!dbKey.empty())
         {
            //notify the bdv of the error
            auto notifPacket = make_shared<BDV_Notification_Packet>();
            notifPacket->bdvPtr_ = bdvPtr;
            notifPacket->notifPtr_ = make_shared<BDV_Notification_Error>(
               bdvPtr->getID(), broadcastId, 
               (int)ArmoryErrorCodes::ZcBroadcast_AlreadyInChain,
               hash, "RPC broadcast error: Already in chain");
            innerBDVNotifStack_.push_back(move(notifPacket));

            //reset data ref so as to not parse the zc
            rawZcRef.reset();
         }
      }

      bdmT_->bdm()->zeroConfCont_->broadcastZC(
         rawZcVec, 5000, errorCallback, bdvPtr->getID(), broadcastId);

      break;
   }

   case BDVCommandProcess_ZC_RPC:
   {
      //cast to bdv_command
      auto message = dynamic_pointer_cast<BDVCommand>(_result);
      if (message == nullptr)
         return nullptr;

      /*
      Reset _result as broadcast commands do not have return values. 
      ZC broadcast notifications are delivered through the callback API.
      */
      _result = nullptr;

      /*
      in: raw tx as bindata[0]
      out: void
      */

      if (message->bindata_size() != 1)
         break;

      const auto& broadcastId = message->hash();
      if (broadcastId.size() != BROADCAST_ID_LENGTH * 2)
         break;

      //TODO: do not tolerate duplicate broadcast ids

      auto& rawTx = message->bindata(0);
      if (rawTx.size() == 0)
         throw runtime_error("invalid tx size");

      RpcBroadcastPacket packet;
      packet.rawTx_ = make_shared<BinaryData>(
         (uint8_t*)rawTx.c_str(), rawTx.size());
      packet.bdvPtr_ = bdvPtr;
      packet.requestID_ = broadcastId;
      rpcBroadcastQueue_.push_back(move(packet));

      break;
   }

   case BDVCommandProcess_UnregisterAddresses:
   {
      //cast to bdv_command
      auto message = dynamic_pointer_cast<BDVCommand>(_result);
      if (message == nullptr)
         return nullptr;

      //Reset _result, unregistration events are 
      //notified through the callback API.
      _result = nullptr;

      /*
      in: 
         hash: id for this registation event, will be
            passed in the notification if set
         
         walletId: id of the relevant wallet
         bindata: set of addresses to unregister (optional)

      out:
         void

      Note: if bindata is set, these addresses will be unregistered
         from the wallet and the address filter (if eligible). 

         If bindata is empty, all the addresses in the wallet are 
         unregistered from the address filter (if eligible) and the
         wallet is erased from the parent bdv.
      */

      //sanity check
      if (!message->has_walletid())
      {
         LOGERR << "need wallet for address unregistration command";
         return nullptr;
      }
      
      //registration event id
      BinaryData refreshId;
      if (message->has_hash())
      {
         refreshId = BinaryData::fromString(message->hash());
         if (refreshId.getSize() != REGISTER_ID_LENGH * 2)
         {
            LOGERR << "invalid registration id length";
            return nullptr;
         }
      }

      set<BinaryDataRef> addrSetRef;
      const auto& walletId = message->walletid();
      auto wltPtr = bdvPtr->getWalletOrLockbox(walletId);
      if (wltPtr == nullptr)
      {
         LOGWARN << "trying to unregister unknown wallet";
         break;
      }

      //are we unregistering a whole wallet or just some addresses?
      bool unregisterWallet = false;
      if (message->bindata_size() == 0)
      {
         unregisterWallet = true;
         auto addrMapPtr = wltPtr->getAddrMap();
         for (auto& addrPair : *addrMapPtr)
            addrSetRef.emplace(addrPair.first);
      }
      else
      {
         for (int i=0; i<message->bindata_size(); i++)
         {
            const auto& scrAddrProto = message->bindata(i);
            if (scrAddrProto.size() == 0 || scrAddrProto.size() > 50)
               continue;

            BinaryDataRef bdr; bdr.setRef(scrAddrProto);
            addrSetRef.emplace(move(bdr));
         }

         //only unregistering some addresses, clean them up from the wallet
         wltPtr->unregisterAddresses(addrSetRef);
      }

      //do not unregister an address if it's watched by another bdv
      auto bdvMap = BDVs_.get();

      auto scrAddrIter = addrSetRef.begin();
      while (scrAddrIter != addrSetRef.end())
      {
         bool hasCollision = false;
         for (auto& bdv_pair : *bdvMap)
         {
            if (bdv_pair.second->hasScrAddress(*scrAddrIter) && 
               bdv_pair.first != bdvPtr->bdvID_) //TODO: slow parsing, speed this up
            {
               hasCollision = true;
               addrSetRef.erase(scrAddrIter++);
               break;
            }
         }

         if (hasCollision)
            continue;

         ++scrAddrIter;
      }

      auto completionCallback = [this, bdvPtr, refreshId](void)->void
      {
         auto notifPacket = make_shared<BDV_Notification_Packet>();
         notifPacket->bdvPtr_ = bdvPtr;
         notifPacket->notifPtr_ = make_shared<BDV_Notification_Refresh>(
            bdvPtr->getID(), BDV_registrationCompleted, refreshId);

         innerBDVNotifStack_.push_back(move(notifPacket));
      };

      if (unregisterWallet)
      {
         //get rid of the wallet
         bdvPtr->unregisterWallet(walletId);
      }

      if (addrSetRef.empty())
      {
         //fire the callback if there are no addresses to delete
         completionCallback();
      }
      else
      {
         //unregister these addresses
         auto safPtr = bdmT_->bdm()->getScrAddrFilter();
         safPtr->unregisterAddresses(addrSetRef, completionCallback);
      }

      break;
   }

   default:
      break;
   }

   return _result;
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<Message> Clients::processUnregisteredCommand(const uint64_t& bdvId, 
   shared_ptr<StaticCommand> command)
{
   switch (command->method())
   {
   case StaticMethods::shutdown:
   case StaticMethods::shutdownNode:
   {
      /*
      in: cookie
      out: void
      */
      processShutdownCommand(command);
      break;
   }

   case StaticMethods::registerBDV:
   {
      /*
      in: network magic word
      out: bdv id as string
      */
      BinaryDataRef bdr;
      bdr.setRef((uint8_t*)&bdvId, 8);
      return registerBDV(command, bdr.toHexStr());
   }

   case StaticMethods::unregisterBDV:
      break;

   default:
      return nullptr;
   }

   return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
//
// Callback
//
///////////////////////////////////////////////////////////////////////////////
Callback::~Callback()
{}

///////////////////////////////////////////////////////////////////////////////
void WS_Callback::callback(shared_ptr<BDVCallback> command)
{
   //write to socket
   WebSocketServer::write(bdvID_, WEBSOCKET_CALLBACK_ID, command);
}

///////////////////////////////////////////////////////////////////////////////
void UnitTest_Callback::callback(shared_ptr<BDVCallback> command)
{
   //stash the notification, unit test will pull it as needed
   notifQueue_.push_back(move(command));
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<::Codec_BDVCommand::BDVCallback> UnitTest_Callback::getNotification()
{
   try
   {
      return notifQueue_.pop_front();
   }
   catch (StopBlockingLoop&)
   {}

   return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
//
// BDV_PartialMessage
//
///////////////////////////////////////////////////////////////////////////////
bool BDV_PartialMessage::parsePacket(shared_ptr<BDV_Payload> packet)
{
   auto&& bdr = packet->packetData_.getRef();
   auto result = partialMessage_.parsePacket(bdr);
   if (!result)
      return false;

   payloads_.push_back(packet);
   return true;
}

///////////////////////////////////////////////////////////////////////////////
void BDV_PartialMessage::reset()
{
   partialMessage_.reset();
   payloads_.clear();
}

///////////////////////////////////////////////////////////////////////////////
bool BDV_PartialMessage::getMessage(shared_ptr<Message> msgPtr)
{
   if (!isReady())
      return false;

   return partialMessage_.getMessage(msgPtr.get());
}

///////////////////////////////////////////////////////////////////////////////
size_t BDV_PartialMessage::topId() const
{
   auto& packetMap = partialMessage_.getPacketMap();
   if (packetMap.size() == 0)
      return SIZE_MAX;

   return packetMap.rbegin()->first;
}

///////////////////////////////////////////////////////////////////////////////
unsigned BDV_PartialMessage::getMessageId(shared_ptr<BDV_Payload> packet)
{
   return WebSocketMessagePartial::getMessageId(packet->packetData_.getRef());
}