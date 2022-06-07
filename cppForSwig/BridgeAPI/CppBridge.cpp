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
using namespace ::Codec_ClientProto;
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

#define BRIDGE_CALLBACK_BDM         UINT32_MAX
#define BRIDGE_CALLBACK_PROGRESS    UINT32_MAX - 1
#define DISCONNECTED_CALLBACK_ID    0xff543ad8

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
      Armory::Threading::BlockingQueue<ClientCommand>>();
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
void CppBridge::queueCommandWithCallback(ClientCommand msg)
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
      ClientCommand msg;
      try
      {
         msg = move(commandWithCallbackQueue_->pop_front());
      }
      catch (const StopBlockingLoop&)
      {
         break;
      }

      BinaryDataRef opaqueRef;
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
         switch (msg.methodwithcallback())
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

            /*
            Entry point to the methods, they will populate their respective
            callbacks object with lambdas to process the returned values
            */
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
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::writeToClient(BridgeReply msgPtr, unsigned id) const
{
   auto payload = make_unique<WritePayload_Bridge>();
   payload->message_ = move(msgPtr);
   payload->id_ = id;
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
      auto response = move(createWalletsPacket());
      writeToClient(move(response), id);
   };

   thread thr(thrLbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::createWalletsPacket()
{
   auto response = make_unique<WalletPayload>();

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

         auto payload = response->add_wallets();
         CppToProto::wallet(payload, wltPtr, accId, commentMap);
      }
   }

   return response;
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
      auto pushNotif = [this](BridgeReply msg, unsigned id)->void
      {
         this->writeToClient(move(msg), id);
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

      if (backupData.rootClear_.empty())
      {
         //return on error
         auto result = make_unique<BridgeBackupString>();
         result->set_isvalid(false);
         writeToClient(move(result), msgId);
         return;
      }

      auto backupStringProto = make_unique<BridgeBackupString>();

      for (auto& line : backupData.rootClear_)
         backupStringProto->add_rootclear(line);

      for (auto& line : backupData.rootEncr_)
         backupStringProto->add_rootencr(line);

      if (!backupData.chaincodeClear_.empty())
      {
         for (auto& line : backupData.chaincodeClear_)
            backupStringProto->add_chainclear(line);

         for (auto& line : backupData.chaincodeEncr_)
            backupStringProto->add_chainencr(line);
      }

      //secure print passphrase
      backupStringProto->set_sppass(
         backupData.spPass_.toCharPtr(), backupData.spPass_.getSize());
         
      //return to client
      backupStringProto->set_isvalid(true);
      writeToClient(move(backupStringProto), msgId);
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
         SecureBinaryData& extra)->unique_ptr<OpaquePayload>
      {
         RestorePrompt opaqueMsg;
         opaqueMsg.set_prompttype((RestorePromptType)promptType);
         for (auto& chk : chkResults)
            opaqueMsg.add_checksums(chk);

         if (!extra.empty())
            opaqueMsg.set_extra(extra.toCharPtr(), extra.getSize());

         //wrap in opaque payload
         auto callbackMsg = make_unique<OpaquePayload>();
         callbackMsg->set_payloadtype(OpaquePayloadType::commandWithCallback);
         callbackMsg->set_uniqueid(
            handler->id().getPtr(), handler->id().getSize());

         string serializedOpaqueData;
         opaqueMsg.SerializeToString(&serializedOpaqueData);
         callbackMsg->set_payload(serializedOpaqueData);

         return callbackMsg;
      };

      auto callback = [this, handler, createCallbackMessage](
         Armory::Backups::RestorePromptType promptType, 
         const vector<int> chkResults, 
         SecureBinaryData& extra)->bool
      {
         //convert prompt args to protobuf
         auto callbackMsg = 
            createCallbackMessage(promptType, chkResults, extra);

         //setup reply lambda
         auto prom = make_shared<promise<BinaryData>>();
         auto fut = prom->get_future();
         auto replyLbd = [prom](BinaryData data)->void
         {
            prom->set_value(data);
         };

         //register reply lambda will callbacks handler
         auto callbackId = handler->addCallback(replyLbd);
         callbackMsg->set_intid(callbackId);

         writeToClient(move(callbackMsg), BRIDGE_CALLBACK_PROMPTUSER);

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
         writeToClient(move(successMsg), BRIDGE_CALLBACK_PROMPTUSER);
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
         auto errorMsg = make_unique<OpaquePayload>();
         errorMsg->set_payloadtype(OpaquePayloadType::commandWithCallback);
         errorMsg->set_uniqueid(
            handler->id().getPtr(), handler->id().getSize());
         errorMsg->set_intid(UINT32_MAX); //error flag
         
         ReplyStrings errorVerbose;
         errorVerbose.add_reply(e.what());

         string serializedOpaqueData;
         errorVerbose.SerializeToString(&serializedOpaqueData);
         errorMsg->set_payload(serializedOpaqueData);
         
         writeToClient(move(errorMsg), BRIDGE_CALLBACK_PROMPTUSER);
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
   const std::string& id, unsigned pageId, unsigned msgId)
{
   auto iter = delegateMap_.find(id);
   if (iter == delegateMap_.end())
      throw runtime_error("unknown delegate: " + id);

   auto lbd = [this, msgId](
      ReturnMessage<vector<DBClientClasses::LedgerEntry>> result)->void
   {
      auto&& leVec = result.get();
      auto msgProto = make_unique<BridgeLedgers>();
      for (auto& le : leVec)
      {
         auto leProto = msgProto->add_le();
         CppToProto::ledger(leProto, le);
      }

      this->writeToClient(move(msgProto), msgId);
   };

   iter->second.getHistoryPage(pageId, lbd);
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getNodeStatus()
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

   auto msg = make_unique<BridgeNodeStatus>();
   try
   {
      auto nodeStatus = fut.get();
      
      //create protobuf message
      CppToProto::nodeStatus(msg.get(), *nodeStatus);
   }
   catch(exception&)
   {
      msg->set_isvalid(false);
   }

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getBalanceAndCount(const string& id)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto msg = make_unique<BridgeBalanceAndCount>();
   msg->set_full(wltContainer->getFullBalance());
   msg->set_spendable(wltContainer->getSpendableBalance());
   msg->set_unconfirmed(wltContainer->getUnconfirmedBalance());
   msg->set_count(wltContainer->getTxIOCount());

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getAddrCombinedList(const string& id)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto addrMap = wltContainer->getAddrBalanceMap();

   auto msg = make_unique<BridgeMultipleBalanceAndCount>();
   for (auto& addrPair : addrMap)
   {
      auto data = msg->add_data();
      data->set_full(addrPair.second[0]);
      data->set_spendable(addrPair.second[1]);
      data->set_unconfirmed(addrPair.second[2]);
      data->set_count(addrPair.second[3]);

      msg->add_ids(
         addrPair.first.toCharPtr(), addrPair.first.getSize());
   }

   auto&& updatedMap = wltContainer->getUpdatedAddressMap();
   auto accPtr = wltContainer->getAddressAccount();

   for (auto& addrPair : updatedMap)
   {
      auto newAsset = msg->add_updatedassets();
      CppToProto::addr(newAsset, addrPair.second, accPtr);
   }

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getHighestUsedIndex(const string& id)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto msg = make_unique<ReplyNumbers>();
   msg->add_ints(wltContainer->getHighestUsedIndex());
   return msg;
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

         auto msg = make_unique<CppProgressCallback>();
         msg->set_progress(progressFloat);
         msg->set_progressnumeric(tickCount);
         msg->add_ids(callbackId);

         this->writeToClient(move(msg), BRIDGE_CALLBACK_PROGRESS);
      };

      //extend chain
      accPtr->extendPublicChain(wltPtr->getIface(), count, updateProgress);

      //shutdown progress dialog
      auto msgProgress = make_unique<CppProgressCallback>();
      msgProgress->set_progress(0);
      msgProgress->set_progressnumeric(0);
      msgProgress->set_phase(BDMPhase_Completed);
      msgProgress->add_ids(callbackId);
      this->writeToClient(move(msgProgress), BRIDGE_CALLBACK_PROGRESS);

      //complete process
      auto msgComplete = make_unique<WalletData>();
      CppToProto::wallet(msgComplete.get(), wltPtr, accId, {});
      this->writeToClient(move(msgComplete), msgId);
   };

   thread thr(extendChain);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
string CppBridge::createWallet(const ClientCommand& msg)
{
   if (wltManager_ == nullptr)
      throw runtime_error("wallet manager is not initialized");

   if (msg.byteargs_size() != 1)
      throw runtime_error("invalid create wallet payload");

   BridgeCreateWalletStruct createWalletProto;
   if (!createWalletProto.ParseFromString(msg.byteargs(0)))
      throw runtime_error("failed to read create wallet protobuf message");

   //extra entropy
   SecureBinaryData extraEntropy;
   if (createWalletProto.has_extraentropy())
   {
      extraEntropy = SecureBinaryData::fromString(
         createWalletProto.extraentropy());
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
   if (createWalletProto.has_controlpassphrase())
   {
      controlPass = SecureBinaryData::fromString(
         createWalletProto.controlpassphrase());
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
BridgeReply CppBridge::getWalletPacket(const string& id) const
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto response = make_unique<WalletPayload>();
   auto wltPtr = wltContainer->getWalletPtr();
   auto commentMap = wltPtr->getCommentMap();
   auto payload = response->add_wallets();
   CppToProto::wallet(payload, wltPtr, wai.accountId, commentMap);

   return move(response);
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getNewAddress(const string& id, unsigned type)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();
   auto accPtr = wltContainer->getAddressAccount();
   auto addrPtr = accPtr->getNewAddress(
      wltPtr->getIface(), (AddressEntryType)type);

   auto msg = make_unique<WalletAsset>();
   CppToProto::addr(msg.get(), addrPtr, accPtr);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getChangeAddress(const string& id, unsigned type)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();
   auto accPtr = wltContainer->getAddressAccount();
   auto addrPtr = accPtr->getNewChangeAddress(
      wltPtr->getIface(), (AddressEntryType)type);

   auto msg = make_unique<WalletAsset>();
   CppToProto::addr(msg.get(), addrPtr, accPtr);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::peekChangeAddress(const string& id, unsigned type)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);
   auto wltPtr = wltContainer->getWalletPtr();
   auto accPtr = wltContainer->getAddressAccount();
   auto addrPtr = accPtr->getNewChangeAddress(
      wltPtr->getIface(), (AddressEntryType)type);

   auto msg = make_unique<WalletAsset>();
   CppToProto::addr(msg.get(), addrPtr, accPtr);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getTxByHash(const BinaryData& hash, unsigned msgid)
{
   auto lbd = [this, msgid](ReturnMessage<AsyncClient::TxResult> result)->void
   {
      shared_ptr<const Tx> tx;
      bool valid = false;
      try
      {
         tx = result.get();
         if (tx != nullptr)
            valid = true;
      }
      catch(exception&)
      {}
      
      auto msg = make_unique<BridgeTx>();
      if (valid)
      {
         auto&& txRaw = tx->serialize();
         msg->set_raw(txRaw.getCharPtr(), txRaw.getSize());
         msg->set_isrbf(tx->isRBF());
         msg->set_ischainedzc(tx->isChained());
         msg->set_height(tx->getTxHeight());
         msg->set_txindex(tx->getTxIndex());
         msg->set_isvalid(true);
      }
      else
      {
         msg->set_isvalid(false);
      }
      
      this->writeToClient(move(msg), msgid);
   };

   bdvPtr_->getTxByHash(hash, lbd);
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getTxInScriptType(
   const BinaryData& script, const BinaryData& hash) const
{
   auto msg = make_unique<ReplyNumbers>();
   msg->add_ints(BtcUtils::getTxInScriptTypeInt(script, hash));
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getTxOutScriptType(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyNumbers>();
   msg->add_ints(BtcUtils::getTxOutScriptTypeInt(script));
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getScrAddrForScript(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyBinary>();
   auto&& resultBd = BtcUtils::getScrAddrForScript(script);
   msg->add_reply(resultBd.toCharPtr(), resultBd.getSize());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getScrAddrForAddrStr(const string& addrStr) const
{
   try
   {
      auto msg = make_unique<ReplyBinary>();
      auto resultBd = BtcUtils::getScrAddrForAddrStr(addrStr);
      msg->add_reply(resultBd.toCharPtr(), resultBd.getSize());
      return msg;
   }
   catch (const exception& e)
   {
      auto msg = make_unique<ReplyError>();
      msg->set_iserror(true);
      msg->set_error(e.what());
      return msg;
   }
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getLastPushDataInScript(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyBinary>();
   auto result = BtcUtils::getLastPushDataInScript(script);
   if (!result.empty())
      msg->add_reply(result.getCharPtr(), result.getSize());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getHash160(const BinaryDataRef& dataRef) const
{
   auto&& hash = BtcUtils::getHash160(dataRef);
   auto msg = make_unique<ReplyBinary>();
   msg->add_reply(hash.getCharPtr(), hash.getSize());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getTxOutScriptForScrAddr(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyBinary>();
   auto&& resultBd = BtcUtils::getTxOutScriptForScrAddr(script);
   msg->add_reply(resultBd.toCharPtr(), resultBd.getSize());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::getAddrStrForScrAddr(
   const BinaryData& script) const
{
   try
   {
      auto msg = make_unique<ReplyStrings>();
      auto&& resultStr = BtcUtils::getAddressStrFromScrAddr(script);
      msg->add_reply(resultStr);
      return msg;
   }
   catch (const exception& e)
   {
      auto msg = make_unique<ReplyError>();
      msg->set_iserror(true);
      msg->set_error(e.what());
      return msg;
   }
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
BridgeReply CppBridge::setAddressTypeFor(
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
   auto result = make_unique<WalletAsset>();
   CppToProto::addr(result.get(), addrPtr, accPtr);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getHeaderByHeight(unsigned height, unsigned msgid)
{
   auto lbd = [this, msgid](ReturnMessage<BinaryData> result)->void
   {
      auto headerRaw = result.get();
      auto msg = make_unique<ReplyBinary>();
      msg->add_reply(headerRaw.getCharPtr(), headerRaw.getSize());
      
      this->writeToClient(move(msg), msgid);
   };

   bdvPtr_->getHeaderByHeight(height, lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::setupNewCoinSelectionInstance(const string& id,
   unsigned height, unsigned msgid)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto csId = fortuna_.generateRandom(6).toHexStr();
   auto insertIter = csMap_.insert(
      make_pair(csId, shared_ptr<CoinSelectionInstance>())).first;
   auto csPtr = &insertIter->second;

   auto lbd = [this, wltContainer, csPtr, csId, height, msgid](
      ReturnMessage<vector<AddressBookEntry>> result)->void
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

      auto msg = make_unique<ReplyStrings>();
      msg->add_reply(csId);

      this->writeToClient(move(msg), msgid);
   };

   wltContainer->createAddressBook(lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::destroyCoinSelectionInstance(const string& csId)
{
   csMap_.erase(csId);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::resetCoinSelection(const std::string& csId)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");

   iter->second->resetRecipients();
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::setCoinSelectionRecipient(
   const string& csId, const string& addrStr, uint64_t value, unsigned recId)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
   {
      LOGERR << "[setCoinSelectionRecipient] invalid csId";
      return false;
   }

   try
   {
      iter->second->updateRecipient(recId, addrStr, value);
   }
   catch (const exception&)
   {
      return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::cs_SelectUTXOs(
   const string& csId, uint64_t fee, float feeByte, unsigned flags)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");

   return iter->second->selectUTXOs(fee, feeByte, flags);
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::cs_getUtxoSelection(const string& csId)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");
   
   auto&& utxoVec = iter->second->getUtxoSelection();

   auto msg = make_unique<BridgeUtxoList>();
   for (auto& utxo : utxoVec)
   {
      auto utxoProto = msg->add_data();
      CppToProto::utxo(utxoProto, utxo);
   }

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::cs_getFlatFee(const string& csId)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");
   
   auto flatFee = iter->second->getFlatFee();

   auto msg = make_unique<ReplyNumbers>();
   msg->add_longs(flatFee);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::cs_getFeeByte(const string& csId)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");
   
   auto flatFee = iter->second->getFeeByte();

   auto msg = make_unique<ReplyNumbers>();
   msg->add_floats(flatFee);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::cs_getSizeEstimate(const string& csId)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");
   
   auto sizeEstimate = iter->second->getSizeEstimate();

   auto msg = make_unique<ReplyNumbers>();
   msg->add_longs(sizeEstimate);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::cs_ProcessCustomUtxoList(const ClientCommand& msg)
{
   if (msg.stringargs_size() != 1 ||
      msg.longargs_size() != 1 ||
      msg.floatargs_size() != 1 ||
      msg.intargs_size() != 1)
   {
      throw runtime_error("invalid command cs_ProcessCustomUtxoList");
   }

   auto iter = csMap_.find(msg.stringargs(0));
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");

   auto flatFee = msg.longargs(0);
   auto feeByte = msg.floatargs(0);
   auto flags = msg.intargs(0);

   vector<UTXO> utxos;
   for (int i=0; i<msg.byteargs_size(); i++)
   {
      auto& utxoSer = msg.byteargs(i);
      BridgeUtxo utxoProto;
      if (!utxoProto.ParseFromArray(utxoSer.c_str(), utxoSer.size()))
         return false;

      BinaryData hash(utxoProto.txhash().c_str(), utxoProto.txhash().size());
      BinaryData script(utxoProto.script().c_str(), utxoProto.script().size());
      UTXO utxo(utxoProto.value(), 
         utxoProto.txheight(), utxoProto.txindex(), utxoProto.txoutindex(),
         hash, script);

      utxos.emplace_back(utxo);
   }

   try
   {   
      iter->second->processCustomUtxoList(utxos, flatFee, feeByte, flags);
      return true;
   }
   catch (CoinSelectionException&)
   {}

   return false;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::createAddressBook(const string& id, unsigned msgId)
{
   auto wai = WalletAccountIdentifier::deserialize(id);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   auto lbd = [this, msgId](
      ReturnMessage<vector<AddressBookEntry>> result)->void
   {
      auto msg = make_unique<BridgeAddressBook>();

      auto&& aeVec = result.get();
      for (auto& ae : aeVec)
      {
         auto bridgeAe = msg->add_data();

         auto& scrAddr = ae.getScrAddr();
         bridgeAe->set_scraddr(scrAddr.getCharPtr(), scrAddr.getSize());

         auto& hashList = ae.getTxHashList();
         for (auto& hash : hashList)
            bridgeAe->add_txhashes(hash.getCharPtr(), hash.getSize());
      }

      this->writeToClient(move(msg), msgId);
   };

   wltContainer->createAddressBook(lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::setComment(const ClientCommand& msg)
{
   if (msg.stringargs_size() != 2 || msg.byteargs_size() != 1)
      throw runtime_error("invalid command: setComment");

   const auto& walletId = msg.stringargs(0);

   auto wai = WalletAccountIdentifier::deserialize(walletId);
   auto wltContainer = wltManager_->getWalletContainer(
      wai.walletId, wai.accountId);

   const auto& hashKey = msg.byteargs(0);
   const auto& comment = msg.stringargs(1);
   wltContainer->setComment(hashKey, comment);
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
      auto&& utxoVec = result.get();
      auto msg = make_unique<BridgeUtxoList>();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = msg->add_data();
         CppToProto::utxo(utxoProto, utxo);
      }

      this->writeToClient(move(msg), msgId);
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
      auto&& utxoVec = result.get();
      auto msg = make_unique<BridgeUtxoList>();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = msg->add_data();
         CppToProto::utxo(utxoProto, utxo);
      }

      this->writeToClient(move(msg), msgId);
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
      auto&& utxoVec = result.get();
      auto msg = make_unique<BridgeUtxoList>();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = msg->add_data();
         CppToProto::utxo(utxoProto, utxo);
      }

      this->writeToClient(move(msg), msgId);
   };

   wltContainer->getRBFTxOutList(lbd);
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::initNewSigner()
{
   auto id = fortuna_.generateRandom(6).toHexStr();
   signerMap_.emplace(make_pair(id, make_shared<CppBridgeSignerStruct>()));

   auto msg = make_unique<ReplyStrings>();
   msg->add_reply(id);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::destroySigner(const string& id)
{
   signerMap_.erase(id);
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::signer_SetVersion(const string& id, unsigned version)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      return false;

   iter->second->signer_.setVersion(version);
   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::signer_SetLockTime(const string& id, unsigned locktime)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      return false;

   iter->second->signer_.setLockTime(locktime);
   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::signer_addSpenderByOutpoint(
   const string& id, const BinaryDataRef& hash, 
   unsigned txOutId, unsigned sequence)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      return false;

   iter->second->signer_.addSpender_ByOutpoint(hash, txOutId, sequence);
   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::signer_populateUtxo(
   const string& id, const BinaryDataRef& hash, 
   unsigned txOutId, uint64_t value, const BinaryDataRef& script)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      return false;
   
   try
   {
      UTXO utxo(value, UINT32_MAX, UINT32_MAX, txOutId, hash, script);
      iter->second->signer_.populateUtxo(utxo);
   }
   catch(exception&)
   {
      return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::signer_addRecipient(
   const std::string& id, const BinaryDataRef& script, uint64_t value)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      return false;

   try
   {
      auto&& hash = BtcUtils::getTxOutScrAddr(script);
      iter->second->signer_.addRecipient(
         CoinSelectionInstance::createRecipient(hash, value));
   }
   catch (ScriptRecipientException&)
   {
      return false;
   }
   
   return true;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::signer_getSerializedState(const string& id) const
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");
 
   auto signerState = iter->second->signer_.serializeState();
   string signerStateStr;
   if (!signerState.SerializeToString(&signerStateStr))
      throw runtime_error("failed to serialized signer state");

   auto msg = make_unique<ReplyBinary>();
   msg->add_reply(signerStateStr);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
bool CppBridge::signer_unserializeState(
   const string& id, const BinaryData& state)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");

   try
   {
      Codec_SignerState::SignerState signerState;
      if (!signerState.ParseFromArray(state.getPtr(), state.getSize()))
         throw runtime_error("invalid signer state");

      iter->second->signer_.deserializeState(signerState);
   }
   catch (exception&)
   {
      return false;
   }

   return true;
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
      auto msg = make_unique<ReplyNumbers>();
      msg->add_ints(success);
      this->writeToClient(move(msg), msgId);

      //wind down passphrase prompt
      passLbd({BridgePassphrasePrompt::concludeKey});
   };

   thread thr(signLbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::signer_getSignedTx(const string& id) const
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");

   BinaryDataRef data;
   try
   {
      data = iter->second->signer_.serializeSignedTx();
   }
   catch (const exception&)
   {}

   auto response = make_unique<ReplyBinary>();
   response->add_reply(data.toCharPtr(), data.getSize());
   return response;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::signer_getUnsignedTx(const string& id) const
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");

   BinaryDataRef data;
   try
   {
      data = iter->second->signer_.serializeUnsignedTx();
   }
   catch (const exception&)
   {}

   auto response = make_unique<ReplyBinary>();
   response->add_reply(data.toCharPtr(), data.getSize());
   return response;
}


////////////////////////////////////////////////////////////////////////////////
int CppBridge::signer_resolve(
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

   return 1;
}

////////////////////////////////////////////////////////////////////////////////
BridgeReply CppBridge::signer_getSignedStateForInput(
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
   auto result = make_unique<BridgeInputSignedState>();

   auto signStateInput = signState->getSignedStateForInput(inputId);
   CppToProto::signatureState(result.get(), signStateInput);
   return result;
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

      auto result = make_unique<ReplyNumbers>();
      result->add_ints(timestamp);

      this->writeToClient(move(result), msgId);
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
      auto result = make_unique<BridgeFeeEstimate>();
      try
      {
         auto feeData = feeResult.get();

         result->set_feebyte(feeData.val_);
         result->set_smartfee(feeData.isSmart_);
         result->set_error(feeData.error_);
      }
      catch (const ClientMessageError& e)
      {
         result->set_feebyte(0);
         result->set_smartfee(false);
         result->set_error(e.what());
      }

      this->writeToClient(move(result), msgId);
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
         BridgeLedgers payload;
         for (auto& le : notif.ledgers_)
         {
            auto protoLe = payload.add_le();
            CppToProto::ledger(protoLe, *le);
         }

         vector<uint8_t> payloadVec(payload.ByteSizeLong());
         payload.SerializeToArray(&payloadVec[0], payloadVec.size());

         auto msg = make_unique<CppBridgeCallback>();
         msg->set_type(BDMAction_ZC);
         msg->add_opaque(&payloadVec[0], payloadVec.size());
         
         pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
         break;
      }

      case BDMAction_InvalidatedZC:
      {
         //notify zc
         break;
      }

      case BDMAction_Refresh:
      {
         for (auto& id : notif.ids_)
         {
            string idStr(id.toCharPtr(), id.getSize());
            if (idStr == FILTER_CHANGE_FLAG)
            {
               //notify filter change
            }

            idQueue_.push_back(move(idStr));
         }

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
         BridgeNodeStatus nodeStatusMsg;
         CppToProto::nodeStatus(&nodeStatusMsg, *notif.nodeStatus_);
         vector<uint8_t> serializedNodeStatus(nodeStatusMsg.ByteSizeLong());
         nodeStatusMsg.SerializeToArray(
            &serializedNodeStatus[0], serializedNodeStatus.size());
         
         auto msg = make_unique<CppBridgeCallback>();
         msg->set_type(BDMAction_NodeStatus);
         msg->add_opaque(
            &serializedNodeStatus[0], serializedNodeStatus.size());
         
         pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
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
   auto msg = make_unique<CppProgressCallback>();
   msg->set_phase((uint32_t)phase);
   msg->set_progress(progress);
   msg->set_etasec(secondsRem);
   msg->set_progressnumeric(progressNumeric);

   for (auto& id : walletIdVec)
      msg->add_ids(id);

   pushNotifLbd_(move(msg), BRIDGE_CALLBACK_PROGRESS);
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_SetupDone()
{
   auto msg = make_unique<CppBridgeCallback>();
   msg->set_type(CppBridgeState::CppBridge_Ready);

   pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_SetupRegistrationDone(const set<string>& ids)
{
   auto msg = make_unique<CppBridgeCallback>();
   msg->set_type(CppBridgeState::CppBridge_Registered);
   for (auto& id : ids)
      msg->add_ids(id);

   pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_RegistrationDone(const set<string>& ids)
{
   auto msg = make_unique<CppBridgeCallback>();
   msg->set_type(BDMAction_Refresh);
   for (auto& id : ids)
      msg->add_ids(id);

   pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_NewBlock(unsigned height)
{
   auto msg = make_unique<CppBridgeCallback>();
   msg->set_type(BDMAction_NewBlock);
   msg->set_height(height);

   pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::notify_Ready(unsigned height)
{
   auto msg = make_unique<CppBridgeCallback>();
   msg->set_type(BDMAction_Ready);
   msg->set_height(height);

   pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
}

////////////////////////////////////////////////////////////////////////////////
void BridgeCallback::disconnected()
{
   auto msg = make_unique<CppBridgeCallback>();
   msg->set_type(DISCONNECTED_CALLBACK_ID);

   pushNotifLbd_(move(msg), BRIDGE_CALLBACK_BDM);
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

   ClientCommand msg;

   msg.set_method(Methods::methodWithCallback);
   msg.set_methodwithcallback(MethodsWithCallback::cleanup);
   msg.add_byteargs(id_.toCharPtr(), id_.getSize());

   parentCommandQueue_->push_back(move(msg));
   parentCommandQueue_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
unsigned MethodCallbacksHandler::addCallback(const function<void(BinaryData)>& cbk)
{
   /*
   This method isn't thread safe.
   */
   auto id = counter_++;
   callbacks_.emplace(id, cbk);
   return id;
}