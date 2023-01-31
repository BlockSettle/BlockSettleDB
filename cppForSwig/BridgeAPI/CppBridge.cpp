////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "CppBridge.h"
#include "BridgeSocket.h"
#include "TerminalPassphrasePrompt.h"
#include "PassphrasePrompt.h"
#include "../ArmoryBackups.h"
#include "ProtobufConversions.h"
#include "ProtobufCommandParser.h"
#include "../Signer/ResolverFeed_Wallets.h"
#include "../Wallets/WalletIdTypes.h"

using namespace std;

using namespace ::google::protobuf;
using namespace ::BridgeProto;
using namespace Armory::Threading;
using namespace Armory::Signer;
using namespace Armory::Wallets;
using namespace Armory::CoinSelection;
using namespace Armory::Bridge;

enum CppBridgeState
{
   CppBridge_Ready = 20,
   CppBridge_Registered
};

#define BRIDGE_CALLBACK_BDM         "bdm_callback"
#define BRIDGE_CALLBACK_PROGRESS    "progress"
#define DISCONNECTED_CALLBACK_ID    "disconnected"

////////////////////////////////////////////////////////////////////////////////
////
////  CppBridge
////
////////////////////////////////////////////////////////////////////////////////
CppBridge::CppBridge(const string& path, const string& dbAddr,
   const string& dbPort, bool oneWayAuth, bool offline) :
   path_(path), dbAddr_(dbAddr), dbPort_(dbPort),
   dbOneWayAuth_(oneWayAuth), dbOffline_(offline)
{
   commandWithCallbackQueue_ = make_shared<
      Armory::Threading::BlockingQueue<BridgeProto::Request>>();
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::startThreads()
{
   auto commandLbd = [this]()
   {
      this->processCommandWithCallbackThread();
   };

   commandWithCallbackProcessThread_ = thread(commandLbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::stopThreads()
{
   commandWithCallbackQueue_->terminate();

   if (commandWithCallbackProcessThread_.joinable())
      commandWithCallbackProcessThread_.join();
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::processData(BinaryDataRef socketData)
{
   return ProtobufCommandParser::processData(this, socketData);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::queueCommandWithCallback(BridgeProto::Request msg)
{
   commandWithCallbackQueue_->push_back(move(msg));
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::processCommandWithCallbackThread()
{
   /***
   This class of methods needs to interact several times with the user in the
   course of their lifetime. A dedicated callback object to keep track of the
   methods running thread and set of callbacks awaiting a return.
   ***/

   while (true)
   {
      BridgeProto::Request msg;
      try
      {
         msg = move(commandWithCallbackQueue_->pop_front());
      }
      catch (const StopBlockingLoop&)
      {
         break;
      }

      /*BinaryDataRef opaqueRef;
      if (msg.byteargs_size() < 2)
      {
         //msg has to carry a callback id
         if (msg.byteargs_size() == 0)
            throw runtime_error("malformed command");
      }
      else
      {
         //grab opaque data
         opaqueRef.setRef(msg.byteargs(1));
      }

      //grab callback id
      BinaryDataRef callbackId;
      callbackId.setRef(msg.byteargs(0));

      auto getCallbackHandler = [this, &callbackId]()->
         shared_ptr<MethodCallbacksHandler>
      {
         //grab the callback handler, add to map if missing
         auto iter = callbackHandlerMap_.find(callbackId);
         if (iter == callbackHandlerMap_.end())
         {
            auto insertIter = callbackHandlerMap_.emplace(
               callbackId, make_shared<MethodCallbacksHandler>(
                  callbackId, commandWithCallbackQueue_));
            
            iter = insertIter.first;
         }

         return iter->second;
      };

      auto deleteCallbackHandler = [this, &callbackId]()
      {
         callbackHandlerMap_.erase(callbackId);
      };

      //process the commands
      try
      {
         switch (msg.method_case())
         {
            case MethodsWithCallback::followUp:
            {
               //this is a reply to an existing callback
               if (msg.intargs_size() == 0)
                  throw runtime_error("missing callback arguments");

               auto handler = getCallbackHandler();
               handler->processCallbackReply(msg.intargs(0), opaqueRef);
               break;
            }

            case MethodsWithCallback::cleanup:
            {
               //caller is done, cleanup callbacks entry from map
               deleteCallbackHandler();
               break;
            }

            //Entry point to the methods, they will populate their respective
            //callbacks object with lambdas to process the returned values
            case MethodsWithCallback::restoreWallet:
            {
               auto handler = getCallbackHandler();
               restoreWallet(opaqueRef, handler);
               break;
            }

            default:
               throw runtime_error("unknown command");
         }
      }
      catch (const exception& e)
      {
         //make sure to cleanup the callback map entry on throws
         deleteCallbackHandler();

         //rethrow so that the caller can handle the error
         throw e;
      }*/
   }
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::writeToClient(BridgePayload msgPtr) const
{
   auto payload = make_unique<WritePayload_Bridge>();
   payload->message_ = move(msgPtr);
   writeLambda_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
PassphraseLambda CppBridge::createPassphrasePrompt(UnlockPromptType promptType)
{
   unique_lock<mutex> lock(passPromptMutex_);
   auto&& id = fortuna_.generateRandom(6).toHexStr();
   auto passPromptObj = make_shared<BridgePassphrasePrompt>(id, writeLambda_);

   promptMap_.insert(make_pair(id, passPromptObj));
   return passPromptObj->getLambda(promptType);
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::returnPassphrase(
   const string& promptId, const string& passphrase)
{
   unique_lock<mutex> lock(passPromptMutex_);
   auto iter = promptMap_.find(promptId);
   if (iter == promptMap_.end())
      return false;

   iter->second->setReply(passphrase);
   return false;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::loadWallets(unsigned id)
{
   if (wltManager_ != nullptr)
      return;

   auto thrLbd = [this, id](void)->void
   {
      auto lbd = createPassphrasePrompt(UnlockPromptType::migrate);
      wltManager_ = make_shared<WalletManager>(path_, lbd);
      auto response = createWalletsPacket();
      response->mutable_reply()->set_reference_id(id);
      writeToClient(move(response));
   };

   thread thr(thrLbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::createWalletsPacket()
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   auto walletProto = reply->mutable_wallet()->mutable_multiple_wallets();

   //grab wallet map
   auto accountIdMap = wltManager_->getAccountIdMap();
   for (auto& idIt : accountIdMap)
   {
      if (idIt.first.empty() || idIt.second.empty())
         continue;

      auto firstCont = wltManager_->getWalletContainer(
         idIt.first, *idIt.second.begin());
      auto wltPtr = firstCont->getWalletPtr();
      auto commentMap = wltPtr->getCommentMap();

      for (auto& accId : idIt.second)
      {
         auto wltContainer = wltManager_->getWalletContainer(
            idIt.first, accId);

         auto payload = walletProto->add_wallet();
         CppToProto::wallet(payload, wltPtr, accId, commentMap);
      }
   }

   reply->set_success(true);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::deleteWallet(const string& id)
{
   try
   {
      auto wai = WalletAccountIdentifier::deserialize(id);
      wltManager_->deleteWallet(wai.walletId, wai.accountId);
   }
   catch (const exception& e)
   {
      LOGWARN << "failed to delete wallet with error: " << e.what();
      return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::setupDB()
{
   if (dbOffline_)
   {
      LOGWARN << "attempt to connect to DB in offline mode, ignoring";
      return;
   }

   auto lbd = [this](void)->void
   {
      //sanity check
      if (bdvPtr_ != nullptr)
         return;

      if (wltManager_ == nullptr)
         throw runtime_error("wallet manager is not initialized");

      //lambda to push notifications over to the gui socket
      auto pushNotif = [this](BridgePayload msg)->void
      {
         this->writeToClient(move(msg));
      };

      //setup bdv obj
      callbackPtr_ = make_shared<BridgeCallback>(wltManager_, pushNotif);
      bdvPtr_ = AsyncClient::BlockDataViewer::getNewBDV(
         dbAddr_, dbPort_, path_,
         TerminalPassphrasePrompt::getLambda("db identification key"),
         true, dbOneWayAuth_, callbackPtr_);

      //TODO: set gui prompt to accept server pubkeys
      bdvPtr_->setCheckServerKeyPromptLambda(
         [](const BinaryData&, const string&)->bool{return true;});

      //set bdvPtr in wallet manager
      wltManager_->setBdvPtr(bdvPtr_);

      //connect to db
      try
      {
         bdvPtr_->connectToRemote();
         bdvPtr_->registerWithDB(
            Armory::Config::BitcoinSettings::getMagicBytes());

         //notify setup is done
         callbackPtr_->notify_SetupDone();
      }
      catch (exception& e)
      {
         LOGERR << "failed to connect to db with error: " << e.what();
      }
   };

   thread thr(lbd);
   if (thr.joinable())
      thr.join(); //set back to detach
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::registerWallets()
{
   auto&& regIds = wltManager_->registerWallets();

   set<string> walletIds;
   auto accountIdMap = wltManager_->getAccountIdMap();
   for (auto& idIt : accountIdMap)
   {
      for (auto& accId : idIt.second)
      {
         WalletAccountIdentifier wai(idIt.first, accId);
         walletIds.insert(wai.serialize());
      }
   }

   auto cbPtr = callbackPtr_;
   auto lbd = [regIds, walletIds, cbPtr](void)->void
   {
      for (auto& id : regIds)
         cbPtr->waitOnId(id);

      cbPtr->notify_SetupRegistrationDone(walletIds);
   };

   thread thr(lbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::registerWallet(const string& id, bool isNew)
{
   try
   {
      auto wai = WalletAccountIdentifier::deserialize(id);
      auto&& regId = wltManager_->registerWallet(
         wai.walletId, wai.accountId, isNew);
      callbackPtr_->waitOnId(regId);
   }
   catch (const exception& e)
   {
      LOGERR << "failed to register wallet with error: " << e.what();
   }
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::createBackupStringForWallet(
   const string& id, unsigned msgId)
{
   auto passLbd = createPassphrasePrompt(UnlockPromptType::decrypt);
   auto wai = WalletAccountIdentifier::deserialize(id);

   const auto& walletId = wai.walletId;
   auto backupStringLbd = [this, walletId, msgId, passLbd]()->void
   {
      Armory::Backups::WalletBackup backupData;
      try
      {
         //grab wallet
         auto wltContainer = wltManager_->getWalletContainer(walletId);

         //grab root
         backupData = move(wltContainer->getBackupStrings(passLbd));
      }
      catch (const exception&)
      {}

      //wind down passphrase prompt
      passLbd({BridgePassphrasePrompt::concludeKey});

      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_reference_id(msgId);

      if (backupData.rootClear_.empty())
      {
         //return on error
         reply->set_success(false);
         writeToClient(move(payload));
         return;
      }

      auto backupStringProto = reply->mutable_wallet()->mutable_backup_string();
      for (auto& line : backupData.rootClear_)
         backupStringProto->add_root_clear(line);

      for (auto& line : backupData.rootEncr_)
         backupStringProto->add_root_encr(line);

      if (!backupData.chaincodeClear_.empty())
      {
         for (auto& line : backupData.chaincodeClear_)
            backupStringProto->add_chain_clear(line);

         for (auto& line : backupData.chaincodeEncr_)
            backupStringProto->add_chain_encr(line);
      }

      //secure print passphrase
      backupStringProto->set_sp_pass(
         backupData.spPass_.toCharPtr(), backupData.spPass_.getSize());

      reply->set_success(true);
      writeToClient(move(payload));
   };

   thread thr(backupStringLbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::restoreWallet(
   const BinaryDataRef& msgRef, shared_ptr<MethodCallbacksHandler> handler)
{
   /*
   Needs 2 lines for the root, possibly another 2 for the chaincode, possibly
   1 more for the SecurePrint passphrase.

   This call will block waiting on user replies to the prompt for the different 
   steps in the wallet restoration process (checking id, checkums, passphrase
   requests). It has to run in its own thread.
   */

   RestoreWalletPayload msg;
   msg.ParseFromArray(msgRef.getPtr(), msgRef.getSize());

   if (msg.root_size() != 2)
      throw runtime_error("[restoreWallet] invalid root lines count");

   //
   auto restoreLbd = [this, handler](RestoreWalletPayload msg)
   {
      auto createCallbackMessage = [handler](
         int promptType,
         const vector<int> chkResults,
         SecureBinaryData& extra)->unique_ptr<BridgeProto::Payload>
      {
         RestorePrompt opaqueMsg;
         opaqueMsg.set_prompttype((RestorePromptType)promptType);
         for (auto& chk : chkResults)
            opaqueMsg.add_checksums(chk);

         if (!extra.empty())
            opaqueMsg.set_extra(extra.toCharPtr(), extra.getSize());

         //wrap in opaque payload
         auto payload = make_unique<BridgeProto::Payload>();
         auto callback = payload->mutable_callback();
         callback->set_callback_id(
            handler->id().getCharPtr(), handler->id().getSize());

         /*callbackMsg->set_payloadtype(OpaquePayloadType::commandWithCallback);

         string serializedOpaqueData;
         opaqueMsg.SerializeToString(&serializedOpaqueData);
         callbackMsg->set_payload(serializedOpaqueData);*/

         return payload;
      };

      auto callback = [this, handler, createCallbackMessage](
         Armory::Backups::RestorePromptType promptType,
         const vector<int> chkResults,
         SecureBinaryData& extra)->bool
      {
         //convert prompt args to protobuf
         auto callbackMsg = createCallbackMessage(
            promptType, chkResults, extra);

         //setup reply lambda
         auto prom = make_shared<promise<BinaryData>>();
         auto fut = prom->get_future();
         auto replyLbd = [prom](BinaryData data)->void
         {
            prom->set_value(data);
         };

         //register reply lambda will callbacks handler
         //auto callbackId = handler->addCallback(replyLbd);
         //callbackMsg->mutable_callback()->set_callback_id(callbackId);
         writeToClient(move(callbackMsg));

         //wait on reply
         auto&& data = fut.get();

         //process it
         RestoreReply reply;
         reply.ParseFromArray(data.getPtr(), data.getSize());

         if (!reply.extra().empty())
            extra = move(SecureBinaryData::fromString(reply.extra()));

         return reply.result();
      };

      //grab passphrase
      BinaryDataRef passphrase;
      passphrase.setRef(msg.sppass());

      //grab backup lines
      vector<BinaryDataRef> lines;
      for (unsigned i=0; i<2; i++)
      {
         const auto& line = msg.root(i);
         lines.emplace_back((const uint8_t*)line.c_str(), line.size());
      }

      for (int i=0; i<msg.secondary_size(); i++)
      {
         const auto& line = msg.secondary(i);
         lines.emplace_back((const uint8_t*)line.c_str(), line.size());
      }

      try
      {
         //create wallet from backup
         auto wltPtr = Armory::Backups::Helpers::restoreFromBackup(
            lines, passphrase, wltManager_->getWalletDir(), callback);

         if (wltPtr == nullptr)
            throw runtime_error("empty wallet");

         //add wallet to manager
         auto accIds = wltPtr->getAccountIDs();
         for (const auto& accId : accIds)
            wltManager_->addWallet(wltPtr, accId);

         //signal caller of success
         SecureBinaryData dummy;
         auto successMsg = createCallbackMessage(
            RestorePromptType::Success, {}, dummy);
         successMsg->mutable_callback()->set_callback_id(
            BRIDGE_CALLBACK_PROMPTUSER);
         writeToClient(move(successMsg));
      }
      catch (const Armory::Backups::RestoreUserException& e)
      {
         /*
         These type of errors are the result of user actions. They should have
         an opportunity to fix the issue. Consequently, no error flag will be 
         pushed to the client.
         */

         LOGWARN << "[restoreFromBackup] user exception: " << e.what();
      }
      catch (const exception& e)
      {
         LOGERR << "[restoreFromBackup] fatal error: " << e.what();

         /*
         Report error to client. This will catch throws in the
         callbacks reply handler too.
         */
         /*auto errorMsg = make_unique<OpaquePayload>();
         errorMsg->set_payloadtype(OpaquePayloadType::commandWithCallback);
         errorMsg->set_uniqueid(
            handler->id().getPtr(), handler->id().getSize());
         errorMsg->set_intid(UINT32_MAX); //error flag

         BridgeProto::Strings errorVerbose;
         errorVerbose.add_reply(e.what());

         string serializedOpaqueData;
         errorVerbose.SerializeToString(&serializedOpaqueData);
         errorMsg->set_payload(serializedOpaqueData);*/

         auto payload = make_unique<BridgeProto::Payload>();
         auto callback = payload->mutable_callback();
         callback->set_callback_id(
            handler->id().toCharPtr(), handler->id().getSize());
         callback->set_error(e.what());
         writeToClient(move(payload));
      }

      handler->flagForCleanup();
   };

   handler->methodThr_ = thread(restoreLbd, move(msg));
}

////////////////////////////////////////////////////////////////////////////////
const string& CppBridge::getLedgerDelegateIdForWallets()
{
   auto promPtr = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto fut = promPtr->get_future();
   auto lbd = [promPtr](
      ReturnMessage<AsyncClient::LedgerDelegate> result)->void
   {
      promPtr->set_value(move(result.get()));
   };

   bdvPtr_->getLedgerDelegateForWallets(lbd);
   auto&& delegate = fut.get();
   auto insertPair = 
      delegateMap_.emplace(make_pair(delegate.getID(), move(delegate)));

   if (!insertPair.second)
      insertPair.first->second = move(delegate);

   return insertPair.first->second.getID();
}

////////////////////////////////////////////////////////////////////////////////
const string& CppBridge::getLedgerDelegateIdForScrAddr(
   const string& wltId, const BinaryDataRef& addrHash)
{
   auto promPtr = make_shared<promise<AsyncClient::LedgerDelegate>>();
   auto fut = promPtr->get_future();
   auto lbd = [promPtr](
      ReturnMessage<AsyncClient::LedgerDelegate> result)->void
   {
      promPtr->set_value(move(result.get()));
   };

   bdvPtr_->getLedgerDelegateForScrAddr(wltId, addrHash, lbd);
   auto&& delegate = fut.get();
   auto insertPair =
      delegateMap_.emplace(make_pair(delegate.getID(), delegate));

   if (!insertPair.second)
      insertPair.first->second = delegate;

   return insertPair.first->second.getID();
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getHistoryPageForDelegate(
   const string& id, unsigned pageId, unsigned msgId)
{
   auto iter = delegateMap_.find(id);
   if (iter == delegateMap_.end())
      throw runtime_error("unknown delegate: " + id);

   auto lbd = [this, msgId](
      ReturnMessage<vector<DBClientClasses::LedgerEntry>> result)->void
   {
      auto&& leVec = result.get();
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto ledgers = reply->mutable_service()->mutable_ledger_history();
      for (auto& le : leVec)
      {
         auto leProto = ledgers->add_ledger();
         CppToProto::ledger(leProto, le);
      }

      this->writeToClient(move(payload));
   };

   iter->second.getHistoryPage(pageId, lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getHistoryForWalletSelection(
   const string& order, vector<string> wltIds, unsigned msgId)
{
   auto lbd = [this, msgId](
      ReturnMessage<vector<DBClientClasses::LedgerEntry>> result)->void
   {
      auto&& leVec = result.get();
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto ledgers = reply->mutable_service()->mutable_ledger_history();
      for (auto& le : leVec)
      {
         auto leProto = ledgers->add_ledger();
         CppToProto::ledger(leProto, le);
      }

      this->writeToClient(move(payload));
   };

   bdvPtr_->getHistoryForWalletSelection(wltIds, order, lbd);
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getNodeStatus()
{
   //grab node status
   auto promPtr = make_shared<
      promise<shared_ptr<DBClientClasses::NodeStatus>>>();
   auto fut = promPtr->get_future();
   auto lbd = [promPtr](
      ReturnMessage<shared_ptr<DBClientClasses::NodeStatus>> result)->void
   {
      try
      {
         auto&& nss = result.get();
         promPtr->set_value(move(nss));
      }
      catch(const std::exception&)
      {
         promPtr->set_exception(current_exception());
      }
   };
   bdvPtr_->getNodeStatus(lbd);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   try
   {
      auto nodeStatus = fut.get();

      //create protobuf message
      CppToProto::nodeStatus(
         reply->mutable_service()->mutable_node_status(), *nodeStatus);
      reply->set_success(true);
   }
   catch (const exception&)
   {
      reply->set_success(false);
   }

   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getBalanceAndCount(const string& id)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();

   auto balance = reply->mutable_wallet()->mutable_balance_and_count();
   balance->set_full(wltContainer->getFullBalance());
   balance->set_spendable(wltContainer->getSpendableBalance());
   balance->set_unconfirmed(wltContainer->getUnconfirmedBalance());
   balance->set_count(wltContainer->getTxIOCount());

   reply->set_success(true);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getAddrCombinedList(const string& id)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto addrMap = wltContainer->getAddrBalanceMap();

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();

   auto aabData = reply->mutable_wallet()->mutable_address_and_balance_data();
   for (auto& addrPair : addrMap)
   {
      auto addr = aabData->add_balance();
      addr->set_id(addrPair.first.toCharPtr(), addrPair.first.getSize());

      auto balance = addr->mutable_balance();
      balance->set_full(addrPair.second[0]);
      balance->set_spendable(addrPair.second[1]);
      balance->set_unconfirmed(addrPair.second[2]);
      balance->set_count(addrPair.second[3]);
   }

   auto updatedMap = wltContainer->getUpdatedAddressMap();
   auto accPtr = wltContainer->getAddressAccount();

   for (auto& addrPair : updatedMap)
   {
      auto newAsset = aabData->add_updated_asset();
      CppToProto::addr(newAsset, addrPair.second, accPtr);
   }

   reply->set_success(true);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getHighestUsedIndex(const string& id)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto index = reply->mutable_wallet()->mutable_highest_used_index();
   index->set_index(wltContainer->getHighestUsedIndex());

   return payload;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::extendAddressPool(const string& wltId,
   unsigned count, const string& callbackId, unsigned msgId)
{
   auto wai = WalletAccountIdentifier::deserialize(wltId);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();
   const auto& accId = wai.accountId;

   //run chain extention in another thread
   auto extendChain =
      [this, wltPtr, accId, count, msgId, callbackId]()
   {
      auto accPtr = wltPtr->getAccountForID(accId);

      //setup progress reporting
      size_t tickTotal = count * accPtr->getNumAssetAccounts();
      size_t tickCount = 0;
      int reportedTicks = -1;
      auto now = chrono::system_clock::now();

      //progress callback
      auto updateProgress = [this, callbackId, tickTotal,
         &tickCount, &reportedTicks, now](int)
      {
         ++tickCount;
         auto msElapsed = chrono::duration_cast<chrono::milliseconds>(
            chrono::system_clock::now() - now).count();

         //report an event every 250ms
         int eventCount = msElapsed / 250;
         if (eventCount < reportedTicks)
            return;

         reportedTicks = eventCount;
         float progressFloat = float(tickCount) / float(tickTotal);

         auto payloadProgess = make_unique<BridgeProto::Payload>();
         auto callbackProgress = payloadProgess->mutable_callback();
         callbackProgress->set_callback_id(BRIDGE_CALLBACK_PROGRESS);

         auto progressProto = callbackProgress->mutable_progress();
         progressProto->set_progress(progressFloat);
         progressProto->set_progress_numeric(tickCount);
         progressProto->add_id(callbackId);

         this->writeToClient(move(payloadProgess));
      };

      //extend chain
      accPtr->extendPublicChain(wltPtr->getIface(), count, updateProgress);

      //shutdown progress dialog
      auto payloadProgess = make_unique<BridgeProto::Payload>();
      auto callbackProgress = payloadProgess->mutable_callback();
      callbackProgress->set_callback_id(BRIDGE_CALLBACK_PROGRESS);

      auto progressProto = callbackProgress->mutable_progress();
      progressProto->set_progress(0);
      progressProto->set_progress_numeric(0);
      progressProto->set_phase(BDMPhase_Completed);
      progressProto->add_id(callbackId);
      this->writeToClient(move(payloadProgess));

      //complete process
      auto payloadComplete = make_unique<BridgeProto::Payload>();
      auto reply = payloadComplete->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto walletProto = reply->mutable_wallet()->mutable_wallet_data();
      CppToProto::wallet(walletProto, wltPtr, accId, {});
      this->writeToClient(move(payloadComplete));
   };

   thread thr(extendChain);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
string CppBridge::createWallet(const Utils::CreateWallet& msg)
{
   if (wltManager_ == nullptr)
      throw runtime_error("wallet manager is not initialized");
   const auto& createWalletProto = msg.wallet_struct();

   //extra entropy
   SecureBinaryData extraEntropy;
   if (createWalletProto.has_extra_entropy())
   {
      extraEntropy = SecureBinaryData::fromString(
         createWalletProto.extra_entropy());
   }

   //passphrase
   SecureBinaryData passphrase;
   if (createWalletProto.has_passphrase())
   {
      passphrase = SecureBinaryData::fromString(
         createWalletProto.passphrase());
   }

   //control passphrase
   SecureBinaryData controlPass;
   if (createWalletProto.has_control_passphrase())
   {
      controlPass = SecureBinaryData::fromString(
         createWalletProto.control_passphrase());
   }

   //lookup
   auto lookup = createWalletProto.lookup();

   //create wallet
   auto&& wallet = wltManager_->createNewWallet(
      passphrase, controlPass, extraEntropy, lookup);

   //set labels
   auto wltPtr = wallet->getWalletPtr();

   if (createWalletProto.has_label())
      wltPtr->setLabel(createWalletProto.label());
   if (createWalletProto.has_description())
      wltPtr->setDescription(createWalletProto.description());

   return wltPtr->getID();
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getWalletPacket(const string& id) const
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto wltPtr = wltContainer->getWalletPtr();
   auto commentMap = wltPtr->getCommentMap();

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto walletProto = reply->mutable_wallet()->mutable_wallet_data();
   CppToProto::wallet(walletProto, wltPtr, wai.accountId, commentMap);

   return move(payload);
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getNewAddress(const string& id, unsigned type)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();
   auto accPtr = wltContainer->getAddressAccount();
   auto addrPtr = accPtr->getNewAddress(
      wltPtr->getIface(), (AddressEntryType)type);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto addrProto = reply->mutable_wallet()->mutable_asset();
   CppToProto::addr(addrProto, addrPtr, accPtr);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getChangeAddress(const string& id, unsigned type)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();
   auto accPtr = wltContainer->getAddressAccount();
   auto addrPtr = accPtr->getNewChangeAddress(
      wltPtr->getIface(), (AddressEntryType)type);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto addrProto = reply->mutable_wallet()->mutable_asset();
   CppToProto::addr(addrProto, addrPtr, accPtr);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::peekChangeAddress(const string& id, unsigned type)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();
   auto accPtr = wltContainer->getAddressAccount();
   auto addrPtr = accPtr->getNewChangeAddress(
      wltPtr->getIface(), (AddressEntryType)type);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto addrProto = reply->mutable_wallet()->mutable_asset();
   CppToProto::addr(addrProto, addrPtr, accPtr);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getTxByHash(const BinaryData& hash, unsigned msgId)
{
   auto lbd = [this, msgId](ReturnMessage<AsyncClient::TxResult> result)->void
   {
      shared_ptr<const ::Tx> tx;
      bool valid = false;
      try
      {
         tx = result.get();
         if (tx != nullptr)
            valid = true;
      }
      catch(exception&)
      {}

      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_reference_id(msgId);
      if (valid)
      {
         auto txRaw = tx->serialize();

         auto txProto = reply->mutable_service()->mutable_tx();
         txProto->set_raw(txRaw.getCharPtr(), txRaw.getSize());
         txProto->set_rbf(tx->isRBF());
         txProto->set_chained_zc(tx->isChained());
         txProto->set_height(tx->getTxHeight());
         txProto->set_tx_index(tx->getTxIndex());
         reply->set_success(true);
      }
      else
      {
         reply->set_success(false);
      }

      this->writeToClient(move(payload));
   };

   bdvPtr_->getTxByHash(hash, lbd);
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getTxInScriptType(
   const BinaryData& script, const BinaryData& hash) const
{
   auto typeInt = BtcUtils::getTxInScriptTypeInt(script, hash);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto scriptType = reply->mutable_script_utils()->mutable_txin_script_type();
   scriptType->set_script_type(typeInt);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getTxOutScriptType(const BinaryData& script) const
{
   auto typeInt = BtcUtils::getTxOutScriptTypeInt(script);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto scriptType = reply->mutable_script_utils()->mutable_txout_script_type();
   scriptType->set_script_type(typeInt);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getScrAddrForScript(
   const BinaryData& script) const
{
   auto resultBd = BtcUtils::getScrAddrForScript(script);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);
   auto scrAddr = reply->mutable_script_utils()->mutable_scraddr();
   scrAddr->set_scraddr(resultBd.toCharPtr(), resultBd.getSize());
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getScrAddrForAddrStr(const string& addrStr) const
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();

   try
   {
      auto resultBd = BtcUtils::getScrAddrForAddrStr(addrStr);
      reply->set_success(true);
      auto scrAddr = reply->mutable_script_utils()->mutable_scraddr();
      scrAddr->set_scraddr(resultBd.toCharPtr(), resultBd.getSize());
   }
   catch (const exception& e)
   {
      reply->set_success(false);
      reply->set_error(e.what());
   }

   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getLastPushDataInScript(const BinaryData& script) const
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   auto result = BtcUtils::getLastPushDataInScript(script);
   if (result.empty())
   {
      reply->set_success(false);
   }
   else
   {
      reply->set_success(true);
      auto pushData = reply->mutable_script_utils()->mutable_push_data();
      pushData->set_data(result.getCharPtr(), result.getSize());
   }
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getHash160(const BinaryDataRef& dataRef) const
{
   auto hash = BtcUtils::getHash160(dataRef);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto hashMsg = reply->mutable_utils()->mutable_hash();
   hashMsg->set_data(hash.getCharPtr(), hash.getSize());
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getTxOutScriptForScrAddr(const BinaryData& script) const
{
   auto resultBd = BtcUtils::getTxOutScriptForScrAddr(script);

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto scriptReply = reply->mutable_script_utils()->mutable_script_data();
   scriptReply->set_data(resultBd.toCharPtr(), resultBd.getSize());
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getAddrStrForScrAddr(const BinaryData& script) const
{
   auto payload = make_unique<BridgeProto::Payload>();
   try
   {
      auto addrStr = BtcUtils::getAddressStrFromScrAddr(script);

      auto reply = payload->mutable_reply();
      reply->set_success(true);
      auto scriptUtilsReply = reply->mutable_script_utils();
      auto addr = scriptUtilsReply->mutable_address_string();
      addr->set_address(addrStr);
   }
   catch (const exception& e)
   {
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(false);
      reply->set_error(e.what());
   }

   return payload;
}

////////////////////////////////////////////////////////////////////////////////
string CppBridge::getNameForAddrType(int addrTypeInt) const
{
   string result;

   auto nestedFlag = addrTypeInt & ADDRESS_NESTED_MASK;
   bool nested = false;
   switch (nestedFlag)
   {
   case 0:
      break;

   case AddressEntryType_P2SH:
      result += "P2SH";
      nested = true;
      break;

   case AddressEntryType_P2WSH:
      result += "P2WSH";
      nested = true;
      break;

   default:
      throw runtime_error("[getNameForAddrType] unknown nested flag");
   }

   auto addressType = addrTypeInt & ADDRESS_TYPE_MASK;
   if (addressType == 0)
      return result;

   if (nested)
      result += "-";

   switch (addressType)
   {
   case AddressEntryType_P2PKH:
      result += "P2PKH";
      break;

   case AddressEntryType_P2PK:
      result += "P2PK";
      break;

   case AddressEntryType_P2WPKH:
      result += "P2WPKH";
      break;

   case AddressEntryType_Multisig:
      result += "Multisig";
      break;

   default:
      throw runtime_error("[getNameForAddrType] unknown address type");
   }

   if (addrTypeInt & ADDRESS_COMPRESSED_MASK)
      result += " (Uncompressed)";

   if (result.empty())
      result = "N/A";
   return result;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::setAddressTypeFor(
   const string& walletId, const string& assetIdStr, uint32_t addrType) const
{
   auto wai = WalletAccountIdentifier::deserialize(walletId);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();

   BinaryDataRef bdr; bdr.setRef(assetIdStr);
   auto assetId = Armory::Wallets::AssetId::deserializeKey(
      bdr, PROTO_ASSETID_PREFIX);

   //set address type in wallet
   wltPtr->updateAddressEntryType(assetId, (AddressEntryType)addrType);

   //get address entry object
   auto accPtr = wltPtr->getAccountForID(assetId.getAddressAccountId());
   auto addrPtr = accPtr->getAddressEntryForID(assetId);

   //return address proto payload
   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto addrProto = reply->mutable_wallet()->mutable_asset();
   CppToProto::addr(addrProto, addrPtr, accPtr);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getHeaderByHeight(unsigned height, unsigned msgId)
{
   auto lbd = [this, msgId](ReturnMessage<BinaryData> result)->void
   {
      auto headerRaw = result.get();

      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto headerData = reply->mutable_service()->mutable_header_data();
      headerData->set_data(headerRaw.getCharPtr(), headerRaw.getSize());

      this->writeToClient(move(payload));
   };

   bdvPtr_->getHeaderByHeight(height, lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::setupNewCoinSelectionInstance(const string& id,
   unsigned height, unsigned msgId)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto csId = fortuna_.generateRandom(6).toHexStr();
   auto insertIter = csMap_.insert(
      make_pair(csId, shared_ptr<CoinSelectionInstance>())).first;
   auto csPtr = &insertIter->second;

   auto lbd = [this, wltContainer, csPtr, csId, height, msgId](
      ReturnMessage<vector<::AddressBookEntry>> result)->void
   {
      auto fetchLbd = [wltContainer](uint64_t val)->vector<UTXO>
      {
         auto promPtr = make_shared<promise<vector<UTXO>>>();
         auto fut = promPtr->get_future();
         auto lbd = [promPtr](ReturnMessage<std::vector<UTXO>> result)->void
         {
            promPtr->set_value(result.get());
         };
         wltContainer->getSpendableTxOutListForValue(val, lbd);

         return fut.get();
      };

      auto&& aeVec = result.get();
      *csPtr = make_shared<CoinSelectionInstance>(
         wltContainer->getWalletPtr(), fetchLbd, aeVec,
         wltContainer->getSpendableBalance(), height);

      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto walletReply = reply->mutable_wallet();
      auto csReply = walletReply->mutable_coin_selection_id();
      csReply->set_id(csId);

      this->writeToClient(move(payload));
   };

   wltContainer->createAddressBook(lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::destroyCoinSelectionInstance(const string& csId)
{
   csMap_.erase(csId);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<CoinSelectionInstance> CppBridge::coinSelectionInstance(
   const std::string& csId) const
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      return nullptr;

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::createAddressBook(const string& id, unsigned msgId)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto lbd = [this, msgId](
      ReturnMessage<vector<::AddressBookEntry>> result)->void
   {
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto addressBookProto = reply->mutable_wallet()->mutable_address_book();
      auto&& aeVec = result.get();
      for (auto& ae : aeVec)
      {
         auto bridgeAe = addressBookProto->add_address();

         auto& scrAddr = ae.getScrAddr();
         bridgeAe->set_scraddr(scrAddr.getCharPtr(), scrAddr.getSize());

         auto& hashList = ae.getTxHashList();
         for (auto& hash : hashList)
            bridgeAe->add_tx_hash(hash.getCharPtr(), hash.getSize());
      }

      this->writeToClient(move(payload));
   };

   wltContainer->createAddressBook(lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::setComment(const string& walletId,
   const BridgeProto::Wallet::SetComment& msg)
{
   auto wai = WalletAccountIdentifier::deserialize(walletId);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   wltContainer->setComment(msg.hash_key(), msg.comment());
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::setWalletLabels(const string& walletId,
   const BridgeProto::Wallet::SetLabels& msg)
{
   auto wai = WalletAccountIdentifier::deserialize(walletId);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   wltContainer->setLabels(msg.title(), msg.description());
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getUtxosForValue(const string& id,
   uint64_t value, unsigned msgId)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto lbd = [this, msgId](ReturnMessage<vector<UTXO>> result)->void
   {
      auto utxoVec = move(result.get());
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);

      auto utxoList = reply->mutable_wallet()->mutable_utxo_list();
      for (auto& utxo : utxoVec)
      {
         auto utxoProto = utxoList->add_utxo();
         CppToProto::utxo(utxoProto, utxo);
      }

      this->writeToClient(move(payload));
   };

   wltContainer->getSpendableTxOutListForValue(value, lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getSpendableZCList(const string& id, unsigned msgId)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto lbd = [this, msgId](ReturnMessage<vector<UTXO>> result)->void
   {
      auto utxoVec = move(result.get());
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);

      auto utxoList = reply->mutable_wallet()->mutable_utxo_list();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = utxoList->add_utxo();
         CppToProto::utxo(utxoProto, utxo);
      }

      this->writeToClient(move(payload));
   };

   wltContainer->getSpendableZcTxOutList(lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getRBFTxOutList(const string& id, unsigned msgId)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto lbd = [this, msgId](ReturnMessage<vector<UTXO>> result)->void
   {
      auto utxoVec = move(result.get());
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto utxoList = reply->mutable_wallet()->mutable_utxo_list();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = utxoList->add_utxo();
         CppToProto::utxo(utxoProto, utxo);
      }

      this->writeToClient(move(payload));
   };

   wltContainer->getRBFTxOutList(lbd);
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::initNewSigner()
{
   auto id = fortuna_.generateRandom(6).toHexStr();
   signerMap_.emplace(make_pair(id, make_shared<CppBridgeSignerStruct>()));

   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();
   reply->set_success(true);

   auto signerId = reply->mutable_signer()->mutable_signer_id();
   signerId->set_id(id);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::destroySigner(const string& id)
{
   signerMap_.erase(id);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<CppBridgeSignerStruct> CppBridge::signerInstance(
   const string& id) const
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      return nullptr;
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::signer_signTx(
   const string& id, const string& wltId, unsigned msgId)
{
   //grab signer
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");
   auto signerPtr = iter->second;

   //grab wallet
   auto wai = WalletAccountIdentifier::deserialize(wltId);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();

   auto passLbd = createPassphrasePrompt(UnlockPromptType::decrypt);

   //instantiate and set resolver feed
   auto signLbd = [wltPtr, signerPtr, passLbd, msgId, this](void)->void
   {
      bool success = true;
      try
      {
         auto wltSingle = dynamic_pointer_cast<AssetWallet_Single>(wltPtr);
         auto feed = make_shared<ResolverFeed_AssetWalletSingle>(wltSingle);

         signerPtr->signer_.resetFeed();
         signerPtr->signer_.setFeed(feed);

         //create & set wallet lambda
         wltPtr->setPassphrasePromptLambda(passLbd);

         //lock wallet
         auto lock = wltPtr->lockDecryptedContainer();

         //sign
         signerPtr->signer_.sign();
      }
      catch (exception&)
      {
         success = false;
      }

      //signal Python that we're done
      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(success);
      reply->set_reference_id(msgId);
      this->writeToClient(move(payload));

      //wind down passphrase prompt
      passLbd({BridgePassphrasePrompt::concludeKey});
   };

   thread thr(signLbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::signer_resolve(
   const string& sId, const string& wltId) const
{
   //grab signer
   auto iter = signerMap_.find(sId);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");
   auto& signer = iter->second->signer_;

   //grab wallet
   auto wai = WalletAccountIdentifier::deserialize(wltId);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();

   //get wallet feed
   auto wltSingle = dynamic_pointer_cast<AssetWallet_Single>(wltPtr);
   auto feed = make_shared<ResolverFeed_AssetWalletSingle>(wltSingle);

   //set feed & resolve
   signer.resetFeed();
   signer.setFeed(feed);
   signer.resolvePublicData();

   return true;
}

////////////////////////////////////////////////////////////////////////////////
BridgePayload CppBridge::getSignedStateForInput(
   const string& id, unsigned inputId)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");

   if (iter->second->signState_ == nullptr)
   {
      iter->second->signState_ = make_unique<TxEvalState>(
         iter->second->signer_.evaluateSignedState());
   }

   const auto signState = iter->second->signState_.get();
   auto payload = make_unique<BridgeProto::Payload>();
   auto reply = payload->mutable_reply();

   auto signStateInput = signState->getSignedStateForInput(inputId);
   auto inputState = reply->mutable_signer()->mutable_input_signed_state();
   CppToProto::signatureState(inputState, signStateInput);

   reply->set_success(true);
   return payload;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::broadcastTx(const vector<BinaryData>& rawTxVec)
{
   bdvPtr_->broadcastZC(rawTxVec);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getBlockTimeByHeight(uint32_t height, uint32_t msgId) const
{
   auto callback = [this, msgId, height](ReturnMessage<BinaryData> rawHeader)->void
   {
      uint32_t timestamp = UINT32_MAX;
      try
      {
         DBClientClasses::BlockHeader header(rawHeader.get(), UINT32_MAX);
         timestamp = header.getTimestamp();
      }
      catch (const ClientMessageError& e)
      {
         LOGERR << "getBlockTimeByHeight failed for height: " << height <<
            " with error: \"" << e.what() << "\"";
      }

      auto payload = make_unique<BridgeProto::Payload>();
      auto reply = payload->mutable_reply();
      reply->set_success(true);
      reply->set_reference_id(msgId);

      auto blockTime = reply->mutable_service()->mutable_block_time();
      blockTime->set_timestamp(timestamp);

      this->writeToClient(move(payload));
   };

   bdvPtr_->getHeaderByHeight(height, callback);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::estimateFee(uint32_t blocks,
   const string& strat, uint32_t msgId) const
{
   auto callback = [this, msgId](
      ReturnMessage<DBClientClasses::FeeEstimateStruct> feeResult)
   {
      auto payload = make_unique<BridgeProto::Payload>();
      auto result = payload->mutable_reply();
      result->set_reference_id(msgId);
      try
      {
         auto feeData = feeResult.get();

         result->set_success(true);
         auto feeMsg = result->mutable_service()->mutable_fee_estimate();
         feeMsg->set_feebyte(feeData.val_);
         feeMsg->set_smartfee(feeData.isSmart_);
      }
      catch (const ClientMessageError& e)
      {
         result->set_success(false);
         result->set_error(e.what());
      }

      this->writeToClient(move(payload));
   };

   bdvPtr_->estimateFee(blocks, strat, callback);
}

////////////////////////////////////////////////////////////////////////////////
////
////  BridgeCallback
////
////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::waitOnId(const string& id)
{
   string currentId;
   while(true)
   {
      {
         if (currentId == id)
             return;

         unique_lock<mutex> lock(idMutex_);
         auto iter = validIds_.find(id);
         if (*iter == id)
         {
            validIds_.erase(iter);
            return;
         }

         validIds_.insert(currentId);
         currentId.clear();
      }

      //TODO: implement queue wake up logic
      currentId = move(idQueue_.pop_front());
   }
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::run(BdmNotification notif)
{
   switch (notif.action_)
   {
      case BDMAction_NewBlock:
      {
         auto height = notif.height_;
         auto lbd = [this, height](void)->void
         {
            this->notify_NewBlock(height);
         };
         wltManager_->updateStateFromDB(lbd);
         break;
      }

      case BDMAction_ZC:
      {
         auto payload = make_unique<BridgeProto::Payload>();
         auto callback = payload->mutable_callback();
         callback->set_callback_id(BRIDGE_CALLBACK_BDM);
         auto zcProto = callback->mutable_zero_conf();

         for (auto& le : notif.ledgers_)
         {
            auto protoLe = zcProto->add_ledger();
            CppToProto::ledger(protoLe, *le);
         }

         pushNotifLbd_(move(payload));
         break;
      }

      case BDMAction_InvalidatedZC:
      {
         //notify zc
         break;
      }

      case BDMAction_Refresh:
      {
         auto payload = make_unique<BridgeProto::Payload>();
         auto callback = payload->mutable_callback();
         callback->set_callback_id(BRIDGE_CALLBACK_BDM);
         auto refreshProto = callback->mutable_refresh();

         for (auto& id : notif.ids_)
         {
            string idStr(id.toCharPtr(), id.getSize());
            refreshProto->add_id(idStr);

            //TODO: dumb way to watch over the pre bdm_ready wallet
            //registration, fix this crap
            if (idStr != FILTER_CHANGE_FLAG)
               idQueue_.push_back(move(idStr));
         }

         pushNotifLbd_(move(payload));
         break;
      }

      case BDMAction_Ready:
      {
         auto height = notif.height_;
         auto lbd = [this, height](void)->void
         {
            this->notify_Ready(height);
         };

         wltManager_->updateStateFromDB(lbd);
         break;
      }

      case BDMAction_NodeStatus:
      {
         //notify node status
         auto payload = make_unique<BridgeProto::Payload>();
         auto callback = payload->mutable_callback();
         callback->set_callback_id(BRIDGE_CALLBACK_BDM);
         auto nodeProto = callback->mutable_node_status();
         CppToProto::nodeStatus(nodeProto, *notif.nodeStatus_);

         pushNotifLbd_(move(payload));
         break;
      }

      case BDMAction_BDV_Error:
      {
         //notify error
         LOGINFO << "bdv error:";
         LOGINFO << "  code: " << notif.error_.errCode_;
         LOGINFO << "  data: " << notif.error_.errData_.toHexStr();

         break;
      }

      default:
         return;
   }
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::progress(
   BDMPhase phase,
   const std::vector<std::string> &walletIdVec,
   float progress, unsigned secondsRem,
   unsigned progressNumeric)
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto callback = payload->mutable_callback();
   callback->set_callback_id(BRIDGE_CALLBACK_PROGRESS);
   auto progressMsg = callback->mutable_progress();

   progressMsg->set_phase((uint32_t)phase);
   progressMsg->set_progress(progress);
   progressMsg->set_etasec(secondsRem);
   progressMsg->set_progress_numeric(progressNumeric);

   for (auto& id : walletIdVec)
      progressMsg->add_id(id);
   pushNotifLbd_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_SetupDone()
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto callback = payload->mutable_callback();
   callback->set_callback_id(BRIDGE_CALLBACK_BDM);
   callback->mutable_setup_done();

   pushNotifLbd_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_SetupRegistrationDone(const set<string>& ids)
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto callback = payload->mutable_callback();
   callback->set_callback_id(BRIDGE_CALLBACK_BDM);

   auto registered = callback->mutable_registered();
   for (auto& id : ids)
      registered->add_id(id);
   pushNotifLbd_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_RegistrationDone(const set<string>& ids)
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto callback = payload->mutable_callback();
   callback->set_callback_id(BRIDGE_CALLBACK_BDM);

   auto refresh = callback->mutable_refresh();
   for (auto& id : ids)
      refresh->add_id(id);

   pushNotifLbd_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_NewBlock(unsigned height)
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto callback = payload->mutable_callback();
   callback->set_callback_id(BRIDGE_CALLBACK_BDM);
   callback->mutable_new_block()->set_height(height);

   pushNotifLbd_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_Ready(unsigned height)
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto callback = payload->mutable_callback();
   callback->set_callback_id(BRIDGE_CALLBACK_BDM);
   callback->mutable_ready()->set_height(height);

   pushNotifLbd_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::disconnected()
{
   auto payload = make_unique<BridgeProto::Payload>();
   auto callback = payload->mutable_callback();
   callback->set_callback_id(BRIDGE_CALLBACK_BDM);
   callback->mutable_disconnected();

   pushNotifLbd_(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
////
////  MethodCallbacksHandler
////
////////////////////////////////////////////////////////////////////////////////
void MethodCallbacksHandler::processCallbackReply(
   unsigned callbackId, BinaryDataRef& dataRef)
{
   auto iter = callbacks_.find(callbackId);
   if (iter == callbacks_.end())
      return; //ignore unknown callbacks ids

   auto callbackLbd = move(iter->second);
   callbacks_.erase(iter);
   callbackLbd(dataRef);
}

////////////////////////////////////////////////////////////////////////////////
void MethodCallbacksHandler::flagForCleanup()
{
   /*
   Mock a shutdown message and queue it up. This message will trigger the 
   deletion of this callback handler from the callback map;
   */
   if (parentCommandQueue_ == nullptr)
      return;

   BridgeProto::Request msg;

   /*msg.set_method(Methods::methodWithCallback);
   msg.set_methodwithcallback(MethodsWithCallback::cleanup);
   msg.add_byteargs(id_.toCharPtr(), id_.getSize());*/

   parentCommandQueue_->push_back(move(msg));
   parentCommandQueue_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
unsigned MethodCallbacksHandler::addCallback(
   const function<void(BinaryData)>& callback)
{
   /*
   This method isn't thread safe.
   */
   auto id = counter_++;
   callbacks_.emplace(id, callback);
   return id;
}