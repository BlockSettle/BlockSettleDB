////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "CppBridge.h"
#include "TerminalPassphrasePrompt.h"

using namespace std;

using namespace ::google::protobuf;
using namespace ::Codec_ClientProto;
using namespace ArmoryThreading;

enum CppBridgeState
{
   CppBridge_Ready = 20,
   CppBridge_Registered
};

#define BRIDGE_CALLBACK_BDM         UINT32_MAX
#define BRIDGE_CALLBACK_PROGRESS    UINT32_MAX - 1
#define BRIDGE_CALLBACK_PROMPTUSER  UINT32_MAX - 2

#define SHUTDOWN_PASSPROMPT_GUI     "concludePrompt"

////////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
   btc_ecc_start();
   startupBIP151CTX();
   startupBIP150CTX(4, false);

   //init static configuration variables
   BlockDataManagerConfig bdmConfig;
   bdmConfig.parseArgs(argc, argv);

   //enable logs
   STARTLOGGING(bdmConfig.logFilePath_, LogLvlDebug);

   //setup the bridge
   auto bridge = make_unique<CppBridge>(
      bdmConfig.dataDir_, "46122",
      "127.0.0.1", bdmConfig.listenPort_);
  
   //enter the command loop
   bridge->commandLoop();

   //done
   LOGINFO << "exiting";

   shutdownBIP151CTX();
   btc_ecc_stop();

   return 0;
}

////////////////////////////////////////////////////////////////////////////////
////
////  help functions
////
////////////////////////////////////////////////////////////////////////////////
void cppLedgerToProtoLedger(
   BridgeLedger* ledgerProto, const ClientClasses::LedgerEntry& ledgerCpp)
{
   ledgerProto->set_value(ledgerCpp.getValue());

   auto hash = ledgerCpp.getTxHash();
   ledgerProto->set_hash(hash.toCharPtr(), hash.getSize());
   ledgerProto->set_id(ledgerCpp.getID());
   
   ledgerProto->set_height(ledgerCpp.getBlockNum());
   ledgerProto->set_txindex(ledgerCpp.getIndex());
   ledgerProto->set_txtime(ledgerCpp.getTxTime());
   ledgerProto->set_iscoinbase(ledgerCpp.isCoinbase());
   ledgerProto->set_issenttoself(ledgerCpp.isSentToSelf());
   ledgerProto->set_ischangeback(ledgerCpp.isChangeBack());
   ledgerProto->set_ischainedzc(ledgerCpp.isChainedZC());
   ledgerProto->set_iswitness(ledgerCpp.isWitness());
   ledgerProto->set_isrbf(ledgerCpp.isOptInRBF());

   for (auto& scrAddr : ledgerCpp.getScrAddrList())
      ledgerProto->add_scraddrlist(scrAddr.getCharPtr(), scrAddr.getSize());
}

////////////////////////////////////////////////////////////////////////////////
void cppAddrToProtoAddr(WalletAsset* assetPtr, 
   shared_ptr<AddressEntry> addrPtr, shared_ptr<AssetWallet> wltPtr)
{
   auto addrID = addrPtr->getID();
   auto wltAsset = wltPtr->getAssetForID(addrID);

   //address
   auto& addr = addrPtr->getPrefixedHash();
   assetPtr->set_prefixedhash(addr.toCharPtr(), addr.getSize());

   //address type & pubkey
   BinaryDataRef pubKeyRef;
   uint32_t addrType = (uint32_t)addrPtr->getType();
   auto addrNested = dynamic_pointer_cast<AddressEntry_Nested>(addrPtr);
   if (addrNested != nullptr)
   {
      addrType |= (uint32_t)addrNested->getPredecessor()->getType();
      pubKeyRef = addrNested->getPredecessor()->getPreimage().getRef();
   }
   else
   {
      pubKeyRef = addrPtr->getPreimage().getRef();
   }
   
   assetPtr->set_addrtype(addrType);
   assetPtr->set_publickey(pubKeyRef.toCharPtr(), pubKeyRef.getSize());

   //index
   assetPtr->set_id(wltAsset->getIndex());

   //address string
   auto& addrStr = addrPtr->getAddress();
   assetPtr->set_addressstring(addrStr);

   //precursor, if any
   if (addrNested == nullptr)
      return;

   auto& precursor = addrNested->getPredecessor()->getScript();
   assetPtr->set_precursorscript(precursor.getCharPtr(), precursor.getSize());
}

////////////////////////////////////////////////////////////////////////////////
void cppWalletToProtoWallet(
   WalletData* wltProto, shared_ptr<AssetWallet> wltPtr)
{
   wltProto->set_id(wltPtr->getID());

   //wo status
   bool isWO = true;
   auto wltSingle = dynamic_pointer_cast<AssetWallet_Single>(wltPtr);
   if (wltSingle != nullptr)
      isWO = wltSingle->isWatchingOnly();
   wltProto->set_watchingonly(isWO);

   //use index
   auto accPtr = wltPtr->getAccountForID(wltPtr->getMainAccountID());
   auto assetAccountPtr = accPtr->getOuterAccount();
   wltProto->set_lookupcount(assetAccountPtr->getAssetCount());
   wltProto->set_usecount(assetAccountPtr->getHighestUsedIndex());

   //address map
   auto addrMap = accPtr->getUsedAddressMap();
   unsigned i=0;
   for (auto& addrPair : addrMap)
   {
      auto assetPtr = wltProto->add_assets();
      cppAddrToProtoAddr(assetPtr, addrPair.second, wltPtr);
   }

   //comments
   wltProto->set_label(wltPtr->getLabel());
   wltProto->set_desc(wltPtr->getDescription());
}

////////////////////////////////////////////////////////////////////////////////
void cppUtxoToProtoUtxo(BridgeUtxo* utxoProto, const UTXO& utxo)
{
   auto& hash = utxo.getTxHash();
   utxoProto->set_txhash(hash.getCharPtr(), hash.getSize());
   utxoProto->set_txoutindex(utxo.getTxOutIndex());

   utxoProto->set_value(utxo.getValue());
   utxoProto->set_txheight(utxo.getHeight());
   utxoProto->set_txindex(utxo.getTxIndex());

   auto& script = utxo.getScript();
   utxoProto->set_script(script.getCharPtr(), script.getSize());

   auto scrAddr = utxo.getRecipientScrAddr();
   utxoProto->set_scraddr(scrAddr.getCharPtr(), scrAddr.getSize());
}

////////////////////////////////////////////////////////////////////////////////
void cppNodeStatusToProtoNodeStatus(
   BridgeNodeStatus* nsProto, const ClientClasses::NodeStatusStruct& nsCpp)
{
   auto chainState = nsCpp.chainState();

   nsProto->set_isvalid(true);
   nsProto->set_nodestatus(nsCpp.status());
   nsProto->set_issegwitenabled(nsCpp.isSegWitEnabled());
   nsProto->set_rpcstatus(nsCpp.rpcStatus());
   
   auto chainStateProto = nsProto->mutable_chainstate();

   chainStateProto->set_chainstate(chainState.state());
   chainStateProto->set_blockspeed(chainState.getBlockSpeed());
   chainStateProto->set_progresspct(chainState.getProgressPct());
   chainStateProto->set_eta(chainState.getETA());
   chainStateProto->set_blocksleft(chainState.getBlocksLeft());
}

////////////////////////////////////////////////////////////////////////////////
void cppSignStateToPythonSignState(
   BridgeInputSignedState* ssProto, const TxInEvalState& ssCpp)
{
   ssProto->set_isvalid(ssCpp.isValid());
   ssProto->set_m(ssCpp.getM());
   ssProto->set_n(ssCpp.getN());
   ssProto->set_sigcount(ssCpp.getSigCount());
   
   const auto& pubKeyMap = ssCpp.getPubKeyMap();
   for (auto& pubKeyPair : pubKeyMap)
   {
      auto keyData = ssProto->add_signstatelist();
      keyData->set_pubkey(
         pubKeyPair.first.getCharPtr(), pubKeyPair.first.getSize());
      keyData->set_hassig(pubKeyPair.second);
   }
}

////////////////////////////////////////////////////////////////////////////////
////
////  BridgePassphrasePrompt
////
////////////////////////////////////////////////////////////////////////////////
PassphraseLambda BridgePassphrasePrompt::getLambda(BridgePromptType type)
{
   auto lbd = [this, type](const set<BinaryData>& ids)->SecureBinaryData
   {
      BridgePromptState promptState = BridgePromptState::cycle;
      if (ids != ids_)
         promptState = BridgePromptState::start;

      //cycle the promise & future
      promPtr_ = make_unique<promise<SecureBinaryData>>();
      futPtr_ = make_unique<shared_future<SecureBinaryData>>(
         promPtr_->get_future());

      //create protobuf payload
      auto msg = make_unique<CppUserPromptCallback>();
      msg->set_promptid(id_);
      msg->set_prompttype(type);

      switch (type)
      {
         case BridgePromptType::decrypt:
         {
            msg->set_verbose("Unlock Wallet");
            break;
         }

         case BridgePromptType::migrate:
         {
            msg->set_verbose("Migrate Wallet");
            break;
         }

         default:
            msg->set_verbose("undefined prompt type");
      }

      bool exit = false;
      if (!ids.empty())
      {
         auto iter = ids.begin();
         bool hasAscii = false;
         auto ptr = iter->getCharPtr();
         for (unsigned i=0; i<iter->getSize(); i++)
         {
            
            if (ptr[i] < 33 || ptr[i] > 127)
            {
               hasAscii = true;
               break;
            }
         }

         string wltId;
         if (!hasAscii) 
            wltId = string(iter->toCharPtr(), iter->getSize());
         else
            wltId = iter->toHexStr();

         if (wltId == SHUTDOWN_PASSPROMPT_GUI)
         {
            promptState = BridgePromptState::stop;
            exit = true;
         }

         msg->set_walletid(wltId);
      }

      msg->set_state(promptState);


      //push over socket
      auto payload = make_unique<WritePayload_Bridge>();
      payload->message_ = move(msg);
      payload->id_ = BRIDGE_CALLBACK_PROMPTUSER;
      writeQueue_->push_back(move(payload));

      if (exit)
         return {};

      //wait on future
      return futPtr_->get();
   };

   return lbd;
}

////////////////////////////////////////////////////////////////////////////////
void BridgePassphrasePrompt::setReply(const string& passphrase)
{
   auto&& passSBD = SecureBinaryData::fromString(passphrase);
   promPtr_->set_value(passSBD);
}

////////////////////////////////////////////////////////////////////////////////
////
////  CppBridge
////
////////////////////////////////////////////////////////////////////////////////
void CppBridge::commandLoop()
{  
   writeQueue_ = make_shared<BlockingQueue<unique_ptr<WritePayload_Bridge>>>();
   auto writeLbd = [this](void)->void
   {
      this->writeThread();
   };
   writeThr_ = thread(writeLbd);

   //sanity check
   if (sockPtr_ != nullptr)
      throw runtime_error("socket already exists");

   //create socket and connect it
   sockPtr_ = make_unique<SimpleSocket>("127.0.0.1", port_);
   sockPtr_->connectToRemote();

   //command processing loop
   vector<uint8_t> socketData;
   bool run = true;
   while (run)
   {
      {
         auto payload = sockPtr_->readFromSocket();
         if (payload.size() == 0)
            break;

         socketData.insert(socketData.end(), payload.begin(), payload.end());
      }

      size_t offset = 0;
      while (offset + 4 < socketData.size())
      {
         auto lenPtr = (uint32_t*)(&socketData[0] + offset);
         offset += 4;
         if (*lenPtr > socketData.size() - offset)
            break;

         ClientCommand msg;
         if (!msg.ParseFromArray(&socketData[offset], *lenPtr))
         {
            LOGERR << "failed to parse protobuf msg";
            offset += *lenPtr;
            continue;
         }
         offset += *lenPtr;

         auto id = msg.payloadid();
         unique_ptr<Message> response;

         switch (msg.method())
         {
            case Methods::loadWallets:
            {
               loadWallets(id);
               break;
            }

            case Methods::setupDB:
            {
               setupDB();
               break;
            }

            case Methods::registerWallets:
            {
               registerWallets();
               break;
            }

            case Methods::registerWallet:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
                  throw runtime_error("invalid command: registerWallet");
               registerWallet(msg.stringargs(0), msg.intargs(0));
               break;
            }

            case Methods::goOnline:
            {
               if (bdvPtr_ == nullptr)
                  throw runtime_error("null bdv ptr");
               bdvPtr_->goOnline();
               break;
            }

            case Methods::shutdown:
            {
               writeQueue_->terminate();
               if (writeThr_.joinable())
                  writeThr_.join();

               bdvPtr_->unregisterFromDB();
               bdvPtr_.reset();
               callbackPtr_.reset();

               run = false;
               break;
            }

            case Methods::getLedgerDelegateIdForWallets:
            {
               auto& delegateId = getLedgerDelegateIdForWallets();
               auto replyMsg = make_unique<ReplyStrings>();
               replyMsg->add_reply(delegateId);
               response = move(replyMsg);
               break;
            }

            case Methods::updateWalletsLedgerFilter:
            {
               vector<BinaryData> idVec;
               for (unsigned i=0; i<msg.stringargs_size(); i++)
                  idVec.push_back(BinaryData::fromString(msg.stringargs(i)));

               bdvPtr_->updateWalletsLedgerFilter(idVec);
               break;
            }

            case Methods::getHistoryPageForDelegate:
            {
               if (msg.stringargs_size() == 0 || msg.intargs_size() == 0)
                  throw runtime_error("invalid command: getHistoryPageForDelegate");
               getHistoryPageForDelegate(msg.stringargs(0), msg.intargs(0), id);
               break;
            }

            case Methods::getNodeStatus:
            {
               response = move(getNodeStatus());
               break;
            }

            case Methods::getBalanceAndCount:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: getBalanceAndCount");
               response = move(getBalanceAndCount(msg.stringargs(0)));
               break;
            }

            case Methods::getAddrCombinedList:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: getAddrCombinedList");
               response = move(getAddrCombinedList(msg.stringargs(0)));
               break;           
            }

            case Methods::getHighestUsedIndex:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: getHighestUsedIndex");
               response = move(getHighestUsedIndex(msg.stringargs(0)));
               break;                      
            }

            case Methods::extendAddressPool:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
                  throw runtime_error("invalid command: getHighestUsedIndex");
               extendAddressPool(msg.stringargs(0), msg.intargs(0), id);
               break;                      
            }

            case Methods::createWallet:
            {
               auto&& wltId = createWallet(msg);
               auto replyMsg = make_unique<ReplyStrings>();
               replyMsg->add_reply(wltId);
               response = move(replyMsg);
               break;
            }
         
            case Methods::getTxByHash:
            {
               if (msg.byteargs_size() != 1)
                  throw runtime_error("invalid command: getTxByHash");
               auto& byteargs = msg.byteargs(0);
               BinaryData hash((uint8_t*)byteargs.c_str(), byteargs.size());
               getTxByHash(hash, id);
               break;
            }

            case Methods::getTxInScriptType:
            {
               if (msg.byteargs_size() != 2)
                  throw runtime_error("invalid command: getTxInScriptType");
               
               auto& script = msg.byteargs(0);
               BinaryData scriptBd((uint8_t*)script.c_str(), script.size());
               
               auto& hash = msg.byteargs(1);
               BinaryData hashBd((uint8_t*)hash.c_str(), hash.size());
               
               response = getTxInScriptType(scriptBd, hashBd);
               break;
            }

            case Methods::getTxOutScriptType:
            {
               if (msg.byteargs_size() != 1)
                  throw runtime_error("invalid command: getTxOutScriptType");
               auto& byteargs = msg.byteargs(0);
               BinaryData script((uint8_t*)byteargs.c_str(), byteargs.size());
               response = getTxOutScriptType(script);
               break;
            }

            case Methods::getScrAddrForScript:
            {
               if (msg.byteargs_size() != 1)
                  throw runtime_error("invalid command: getScrAddrForScript");
               auto& byteargs = msg.byteargs(0);
               BinaryData script((uint8_t*)byteargs.c_str(), byteargs.size());
               response = getScrAddrForScript(script);
               break;
            }

            case Methods::getLastPushDataInScript:
            {
               if (msg.byteargs_size() != 1)
                  throw runtime_error("invalid command: getLastPushDataInScript");
               
               auto& script = msg.byteargs(0);
               BinaryData scriptBd((uint8_t*)script.c_str(), script.size());
                           
               response = getLastPushDataInScript(scriptBd);
               break;
            }

            case Methods::getTxOutScriptForScrAddr:
            {
               if (msg.byteargs_size() != 1)
                  throw runtime_error("invalid command: getTxOutScriptForScrAddr");
               
               auto& script = msg.byteargs(0);
               BinaryData scriptBd((uint8_t*)script.c_str(), script.size());
                           
               response = getTxOutScriptForScrAddr(scriptBd);
               break;
            }

            case Methods::getHeaderByHeight:
            {
               if (msg.intargs_size() != 1)
                  throw runtime_error("invalid command: getHeaderByHeight");
               auto intArgs = msg.intargs(0);
               getHeaderByHeight(intArgs, id);
               break;
            }

            case Methods::setupNewCoinSelectionInstance:
            {
               if (msg.intargs_size() != 1 || msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: setupNewCoinSelectionInstance");

               setupNewCoinSelectionInstance(msg.stringargs(0), msg.intargs(0), id);
               break;
            }

            case Methods::destroyCoinSelectionInstance:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: destroyCoinSelectionInstance");

               destroyCoinSelectionInstance(msg.stringargs(0));
               break;
            }

            case Methods::resetCoinSelection:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: resetCoinSelection");
               resetCoinSelection(msg.stringargs(0));
               break;
            }

            case Methods::setCoinSelectionRecipient:
            {
               if (msg.longargs_size() != 1 ||
                  msg.stringargs_size() != 2 ||
                  msg.intargs_size() != 1)
               {
                  throw runtime_error("invalid command: setCoinSelectionRecipient");
               }

               auto success = setCoinSelectionRecipient(msg.stringargs(0), 
                  msg.stringargs(1), msg.longargs(0), msg.intargs(0));

               auto responseProto = make_unique<ReplyNumbers>();
               responseProto->add_ints(success);
               response = move(responseProto);
               break;
            }

            case Methods::cs_SelectUTXOs:
            {
               if (msg.longargs_size() != 1 ||
                  msg.stringargs_size() != 1 ||
                  msg.intargs_size() != 1 ||
                  msg.floatargs_size() != 1)
               {
                  throw runtime_error("invalid command: cs_SelectUTXOs");
               }

               auto success = cs_SelectUTXOs(msg.stringargs(0), 
                  msg.longargs(0), msg.floatargs(0), msg.intargs(0));

               auto responseProto = make_unique<ReplyNumbers>();
               responseProto->add_ints(success);
               response = move(responseProto);
               break;
            }

            case Methods::cs_getUtxoSelection:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: cs_getUtxoSelection");

               response = cs_getUtxoSelection(msg.stringargs(0));
               break;
            }

            case Methods::cs_getFlatFee:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: cs_getFlatFee");

               response = cs_getFlatFee(msg.stringargs(0));
               break;
            }

            case Methods::cs_getFeeByte:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: cs_getFeeByte");

               response = cs_getFeeByte(msg.stringargs(0));
               break;
            }

            case Methods::cs_ProcessCustomUtxoList:
            {
               auto success = cs_ProcessCustomUtxoList(msg);

               auto responseProto = make_unique<ReplyNumbers>();
               responseProto->add_ints(success);
               response = move(responseProto);
               break;
            }

            case Methods::generateRandomHex:
            {
               if (msg.intargs_size() != 1)
                  throw runtime_error("invalid command: generateRandomHex");
               auto size = msg.intargs(0);
               auto&& str = fortuna_.generateRandom(size).toHexStr();

               auto msg = make_unique<ReplyStrings>();
               msg->add_reply(str);
               response = move(msg);
               break;
            }

            case Methods::createAddressBook:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: createAddressBook");
               createAddressBook(msg.stringargs(0), id);
               break;
            }

            case Methods::getUtxosForValue:
            {
               if (msg.stringargs_size() != 1 || msg.longargs_size() != 1)
                  throw runtime_error("invalid command: getUtxosForValue");
               getUtxosForValue(msg.stringargs(0), msg.longargs(0), id);
               break;
            }

            case Methods::getSpendableZCList:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command getSpendableZCList");
               getSpendableZCList(msg.stringargs(0), id);
               break;
            }

            case Methods::getRBFTxOutList:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: getRBFTxOutList");
               getRBFTxOutList(msg.stringargs(0), id);
               break;
            }

            case Methods::getNewAddress:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
                  throw runtime_error("invalid command: getNewAddress");
               response = getNewAddress(msg.stringargs(0), msg.intargs(0));
               break;
            }

            case Methods::getChangeAddress:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
                  throw runtime_error("invalid command: getChangeAddress");
               response = getChangeAddress(msg.stringargs(0), msg.intargs(0));
               break;
            }

            case Methods::peekChangeAddress:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
                  throw runtime_error("invalid command: peekChangeAddress");
               response = peekChangeAddress(msg.stringargs(0), msg.intargs(0));
               break;
            }

            case Methods::getHash160:
            {
               if (msg.byteargs_size() != 1)
                  throw runtime_error("invalid command: getHash160");
               BinaryDataRef bdRef; bdRef.setRef(msg.byteargs(0));
               response = getHash160(bdRef);
               break;
            }

            case Methods::initNewSigner:
            {
               response = initNewSigner();
               break;
            }

            case Methods::destroySigner:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: destroySigner");            
               destroySigner(msg.stringargs(0));
               break;
            }

            case Methods::signer_SetVersion:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
                  throw runtime_error("invalid command: signer_SetVersion");
               auto success = signer_SetVersion(msg.stringargs(0), msg.intargs(0));
               auto resultProto = make_unique<ReplyNumbers>();
               resultProto->add_ints(success);
               response = move(resultProto);
               break;
            }

            case Methods::signer_SetLockTime:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
                  throw runtime_error("invalid command: signer_SetLockTime");
               auto result = signer_SetLockTime(msg.stringargs(0), msg.intargs(0));
               auto resultProto = make_unique<ReplyNumbers>();
               resultProto->add_ints(result);
               response = move(resultProto);
               break;
            }

            case Methods::signer_addSpenderByOutpoint:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 2 ||
                  msg.byteargs_size() != 1 || msg.longargs_size() != 1)
                  throw runtime_error("invalid command: signer_addSpenderByOutpoint");

               BinaryDataRef hash; hash.setRef(msg.byteargs(0));
               auto result = signer_addSpenderByOutpoint(msg.stringargs(0), 
                  hash, msg.intargs(0), msg.intargs(1), msg.longargs(0));

               auto resultProto = make_unique<ReplyNumbers>();
               resultProto->add_ints(result);
               response = move(resultProto);
               break;
            }

            case Methods::signer_populateUtxo:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1 ||
                  msg.byteargs_size() != 2 || msg.longargs_size() != 1)
                  throw runtime_error("invalid command: signer_populateUtxo");

               BinaryDataRef hash; hash.setRef(msg.byteargs(0));
               BinaryDataRef script; script.setRef(msg.byteargs(1));

               auto result = signer_populateUtxo(msg.stringargs(0), 
                  hash, msg.intargs(0), msg.longargs(0), script);

               auto resultProto = make_unique<ReplyNumbers>();
               resultProto->add_ints(result);
               response = move(resultProto);
               break;
            }

            case Methods::signer_addRecipient:
            {
               if (msg.stringargs_size() != 1 ||
                  msg.byteargs_size() != 1 || msg.longargs_size() != 1)
                  throw runtime_error("invalid command: signer_addRecipient");

               BinaryDataRef script; script.setRef(msg.byteargs(0));
               auto result = signer_addRecipient(msg.stringargs(0), 
                  script, msg.longargs(0));
                  
               auto resultProto = make_unique<ReplyNumbers>();
               resultProto->add_ints(result);
               response = move(resultProto);
               break;
            }

            case Methods::signer_getSerializedState:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: signer_getSerializedState");
               response = signer_getSerializedState(msg.stringargs(0));
               break;
            }

            case Methods::signer_unserializeState:
            {
               if (msg.stringargs_size() != 1 || msg.byteargs_size() != 1)
                  throw runtime_error("invalid command: signer_unserializeState");

               auto result = signer_unserializeState(
                  msg.stringargs(0), BinaryData::fromString(msg.byteargs(0)));

               auto resultProto = make_unique<ReplyNumbers>();
               resultProto->add_ints(result);
               response = move(resultProto);
               break;
            }

            case Methods::signer_signTx:
            {
               if (msg.stringargs_size() != 2)
                  throw runtime_error("invalid command: signer_signTx");
               signer_signTx(msg.stringargs(0), msg.stringargs(1), id);
               break;
            }

            case Methods::signer_getSignedTx:
            {
               if (msg.stringargs_size() != 1)
                  throw runtime_error("invalid command: signer_getSignedTx");

               response = signer_getSignedTx(msg.stringargs(0));
               break;
            }

            case Methods::signer_getSignedStateForInput:
            {
               if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
               {
                  throw runtime_error(
                     "invalid command: signer_getSignedStateForInput");
               }
                  
               response = signer_getSignedStateForInput(
                  msg.stringargs(0), msg.intargs(0));
               break;
            }

            case Methods::returnPassphrase:
            {
               if (msg.stringargs_size() != 2)
                  throw runtime_error("invalid command: returnPassphrase");

               auto result = returnPassphrase(msg.stringargs(0), msg.stringargs(1));

               auto resultProto = make_unique<ReplyNumbers>();
               resultProto->add_ints(result);
               response = move(resultProto);
               break;
            }

            case Methods::broadcastTx:
            {
               if (msg.byteargs_size() == 0)
                  throw runtime_error("invalid command: broadcastTx");

               vector<BinaryData> bdVec;
               for (unsigned i=0; i<msg.byteargs_size(); i++)
                  bdVec.emplace_back(move(BinaryData::fromString(msg.byteargs(i))));

               broadcastTx(bdVec);
               break;
            }

            default:
               stringstream ss;
               ss << "unknown client method: " << msg.method();
               throw runtime_error(ss.str());
         }

         if (response == nullptr)
            continue;

         //write response to socket
         writeToClient(move(response), id);
      }

      if (offset == socketData.size())
      {
         socketData.clear();
         continue;
      }

      memcpy(&socketData[0], &socketData[offset], socketData.size() - offset);
   }

   //wind down
   writeQueue_->terminate();
   sockPtr_->shutdown();

   if (writeThr_.joinable())
      writeThr_.join();
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::writeToClient(unique_ptr<Message> msgPtr, unsigned id)
{
   auto payload = make_unique<WritePayload_Bridge>();
   payload->message_ = move(msgPtr);
   payload->id_ = id;
   writeQueue_->push_back(move(payload));
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::writeThread()
{
   while(true)
   {
      unique_ptr<WritePayload_Bridge> payload;
      try
      {
         payload = move(writeQueue_->pop_front());
      }
      catch (StopBlockingLoop&)
      {
         break;
      }

      sockPtr_->pushPayload(move(payload), nullptr);
   }
}

////////////////////////////////////////////////////////////////////////////////
PassphraseLambda CppBridge::createPassphrasePrompt(BridgePromptType type)
{
   unique_lock<mutex> lock(passPromptMutex_);
   auto&& id = fortuna_.generateRandom(6).toHexStr();
   auto passPromptObj = make_shared<BridgePassphrasePrompt>(id, writeQueue_);

   promptMap_.insert(make_pair(id, passPromptObj));
   return passPromptObj->getLambda(type);
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
      auto lbd = createPassphrasePrompt(BridgePromptType::migrate);
      wltManager_ = make_shared<WalletManager>(path_, lbd);
      auto response = move(createWalletPacket());
      writeToClient(move(response), id);
   };

   thread thr(thrLbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::createWalletPacket()
{
   auto response = make_unique<WalletPayload>();

   //grab wallet map
   auto& wltMap = wltManager_->getMap();
   for (auto& wltPair : wltMap)
   {
      auto wltPtr = wltPair.second->getWalletPtr();
      auto payload = response->add_wallets();

      cppWalletToProtoWallet(payload, wltPtr);
   }

   return response;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::setupDB()
{
   auto lbd = [this](void)->void
   {
      //sanity check
      if (bdvPtr_ != nullptr)
         return;

      if (wltManager_ == nullptr)
         throw runtime_error("wallet manager is not initialized");

      //lambda to push notifications over to the gui socket
      auto pushNotif = [this](unique_ptr<Message> msg, unsigned id)->void
      {
         this->writeToClient(move(msg), id);
      };

      //setup bdv obj
      callbackPtr_ = make_shared<BridgeCallback>(wltManager_, pushNotif);
      bdvPtr_ = AsyncClient::BlockDataViewer::getNewBDV(
         dbAddr_, dbPort_, path_, 
         TerminalPassphrasePrompt::getLambda("db identification key"), 
         true, callbackPtr_);

      //TODO: set gui prompt to accept server pub keys
      bdvPtr_->setCheckServerKeyPromptLambda(
         [](const BinaryData&, const string&)->bool{return true;});

      //set bdvPtr in wallet manager
      wltManager_->setBdvPtr(bdvPtr_);

      //connect to db
      bdvPtr_->connectToRemote();
      bdvPtr_->registerWithDB(NetworkConfig::getMagicBytes());

      //notify setup is done
      callbackPtr_->notify_SetupDone();       
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
   auto& wltMap = wltManager_->getMap();
   for (auto& wltPair : wltMap)
      walletIds.insert(wltPair.first);

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
void CppBridge::registerWallet(const string& walletId, bool isNew)
{
   auto&& regId = wltManager_->registerWallet(walletId, isNew);
   callbackPtr_->waitOnId(regId);
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
void CppBridge::getHistoryPageForDelegate(
   const std::string& id, unsigned pageId, unsigned msgId)
{
   auto iter = delegateMap_.find(id);
   if (iter == delegateMap_.end())
      throw runtime_error("unknow delegate");

   auto lbd = [this, msgId](
      ReturnMessage<vector<ClientClasses::LedgerEntry>> result)->void
   {
      auto&& leVec = result.get();
      auto msgProto = make_unique<BridgeLedgers>();
      for (auto& le : leVec)
      {
         auto leProto = msgProto->add_le();
         cppLedgerToProtoLedger(leProto, le);
      }

      this->writeToClient(move(msgProto), msgId);
   };

   iter->second.getHistoryPage(pageId, lbd);
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getNodeStatus()
{
   //grab node status
   auto promPtr = make_shared<
      promise<shared_ptr<ClientClasses::NodeStatusStruct>>>();
   auto fut = promPtr->get_future();
   auto lbd = [promPtr](
      ReturnMessage<shared_ptr<ClientClasses::NodeStatusStruct>> result)->void
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
      cppNodeStatusToProtoNodeStatus(msg.get(), *nodeStatus);
   }
   catch(exception&)
   {
      msg->set_isvalid(false);
   }

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getBalanceAndCount(const string& wltId)
{
   auto wltMap = wltManager_->getMap();
   auto iter = wltMap.find(wltId);
   if (iter == wltMap.end())
      throw runtime_error("unknown wallet id");

   auto msg = make_unique<BridgeBalanceAndCount>();
   msg->set_full(iter->second->getFullBalance());
   msg->set_spendable(iter->second->getSpendableBalance());
   msg->set_unconfirmed(iter->second->getUnconfirmedBalance());
   msg->set_count(iter->second->getTxIOCount());

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getAddrCombinedList(const string& wltId)
{
   auto wltMap = wltManager_->getMap();
   auto iter = wltMap.find(wltId);
   if (iter == wltMap.end())
      throw runtime_error("unknown wallet id");

   auto addrMap = iter->second->getAddrBalanceMap();

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

   auto&& updatedMap = iter->second->getUpdatedAddressMap();

   for (auto& addrPair : updatedMap)
   {
      auto newAsset = msg->add_updatedassets();
      cppAddrToProtoAddr(
         newAsset, addrPair.second, iter->second->getWalletPtr());
   }

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getHighestUsedIndex(const string& wltId)
{
   auto wltMap = wltManager_->getMap();
   auto iter = wltMap.find(wltId);
   if (iter == wltMap.end())
      throw runtime_error("unknown wallet id");
   
   auto msg = make_unique<ReplyNumbers>();
   msg->add_ints(iter->second->getHighestUsedIndex());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::extendAddressPool(
   const string& wltId, unsigned count, unsigned msgId)
{
   auto wltMap = wltManager_->getMap();
   auto iter = wltMap.find(wltId);
   if (iter == wltMap.end())
      throw runtime_error("unknown wallet id");

   auto wltPtr = iter->second->getWalletPtr();
   auto lbd = [this, wltPtr, count, msgId](void)->void
   {
      wltPtr->extendPublicChain(count);
      
      auto msg = make_unique<WalletData>();
      cppWalletToProtoWallet(msg.get(), wltPtr);
      this->writeToClient(move(msg), msgId);
   };

   thread thr(lbd);
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
      passphrase = SecureBinaryData::fromString(
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
unique_ptr<Message> CppBridge::getNewAddress(const string& wltId, unsigned type)
{
   auto wltMap = wltManager_->getMap();
   auto iter = wltMap.find(wltId);
   if (iter == wltMap.end())
      throw runtime_error("unknown wallet id");
   
   auto wltPtr = iter->second->getWalletPtr();
   auto addrPtr = wltPtr->getNewAddress((AddressEntryType)type);

   auto msg = make_unique<WalletAsset>();
   cppAddrToProtoAddr(msg.get(), addrPtr, wltPtr);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getChangeAddress(
   const string& wltId, unsigned type)
{
   auto wltMap = wltManager_->getMap();
   auto iter = wltMap.find(wltId);
   if (iter == wltMap.end())
      throw runtime_error("unknown wallet id");
   
   auto wltPtr = iter->second->getWalletPtr();
   auto addrPtr = wltPtr->getNewChangeAddress((AddressEntryType)type);

   auto msg = make_unique<WalletAsset>();
   cppAddrToProtoAddr(msg.get(), addrPtr, wltPtr);
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::peekChangeAddress(
   const string& wltId, unsigned type)
{
   auto wltMap = wltManager_->getMap();
   auto iter = wltMap.find(wltId);
   if (iter == wltMap.end())
      throw runtime_error("unknown wallet id");
   
   auto wltPtr = iter->second->getWalletPtr();
   auto addrPtr = wltPtr->peekNextChangeAddress((AddressEntryType)type);

   auto msg = make_unique<WalletAsset>();
   cppAddrToProtoAddr(msg.get(), addrPtr, wltPtr);
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
unique_ptr<Message> CppBridge::getTxInScriptType(
   const BinaryData& script, const BinaryData& hash) const
{
   auto msg = make_unique<ReplyNumbers>();
   msg->add_ints(BtcUtils::getTxInScriptTypeInt(script, hash));
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getTxOutScriptType(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyNumbers>();
   msg->add_ints(BtcUtils::getTxOutScriptTypeInt(script));
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getScrAddrForScript(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyBinary>();
   auto&& resultBd = BtcUtils::getScrAddrForScript(script);
   msg->add_reply(resultBd.toCharPtr(), resultBd.getSize());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getLastPushDataInScript(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyBinary>();
   auto&& result = BtcUtils::getLastPushDataInScript(script);
   msg->add_reply(result.getCharPtr(), result.getSize());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getHash160(const BinaryDataRef& dataRef) const
{
   auto&& hash = BtcUtils::getHash160(dataRef);
   auto msg = make_unique<ReplyBinary>();
   msg->add_reply(hash.getCharPtr(), hash.getSize());
   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::getTxOutScriptForScrAddr(
   const BinaryData& script) const
{
   auto msg = make_unique<ReplyBinary>();
   auto&& resultBd = BtcUtils::getTxOutScriptForScrAddr(script);
   msg->add_reply(resultBd.toCharPtr(), resultBd.getSize());
   return msg;
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
void CppBridge::setupNewCoinSelectionInstance(
   const string& wltId, unsigned height, unsigned msgid)
{
   auto& wltMap = wltManager_->getMap();
   auto wltIter = wltMap.find(wltId);
   if (wltIter == wltMap.end())
      throw runtime_error("invalid wallet id");
   auto wltPtr = wltIter->second;
   
   auto csId = fortuna_.generateRandom(6).toHexStr();
   auto insertIter = csMap_.insert(
      make_pair(csId, shared_ptr<CoinSelectionInstance>())).first;
   auto csPtr = &insertIter->second;

   auto lbd = [this, wltPtr, csPtr, csId, height, msgid](
      ReturnMessage<vector<AddressBookEntry>> result)->void
   {
      auto&& aeVec = result.get();
      *csPtr = make_shared<CoinSelectionInstance>(wltPtr, aeVec, height);

      auto msg = make_unique<ReplyStrings>();
      msg->add_reply(csId);

      this->writeToClient(move(msg), msgid);
   };

   wltIter->second->createAddressBook(lbd);
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
      throw runtime_error("invalid cs id");

   BinaryData scrAddr;
   try
   {
      scrAddr = move(BtcUtils::base58toScrAddr(addrStr));
   }
   catch(const exception&)
   {   
      try
      {
         scrAddr = move(BtcUtils::segWitAddressToScrAddr(addrStr));
      }
      catch(const exception&)
      {
         return false;
      }
   }
   
   iter->second->updateRecipient(recId, scrAddr, value);
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
unique_ptr<Message> CppBridge::cs_getUtxoSelection(const string& csId)
{
   auto iter = csMap_.find(csId);
   if (iter == csMap_.end())
      throw runtime_error("invalid cs id");
   
   auto&& utxoVec = iter->second->getUtxoSelection();

   auto msg = make_unique<BridgeUtxoList>();
   for (auto& utxo : utxoVec)
   {
      auto utxoProto = msg->add_data();
      cppUtxoToProtoUtxo(utxoProto, utxo);
   }

   return msg;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::cs_getFlatFee(const string& csId)
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
unique_ptr<Message> CppBridge::cs_getFeeByte(const string& csId)
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
   for (unsigned i=0; i<msg.byteargs_size(); i++)
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
void CppBridge::createAddressBook(const string& wltId, unsigned msgId)
{
   auto& wltMap = wltManager_->getMap();
   auto wltIter = wltMap.find(wltId);
   if (wltIter == wltMap.end())
      throw runtime_error("invalid wallet id");
   auto wltPtr = wltIter->second;

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

   wltPtr->createAddressBook(lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getUtxosForValue(
   const std::string& wltId, uint64_t value, unsigned msgId)
{
   auto& wltMap = wltManager_->getMap();
   auto wltIter = wltMap.find(wltId);
   if (wltIter == wltMap.end())
      throw runtime_error("invalid wallet id");
   auto wltPtr = wltIter->second;

   auto lbd = [this, msgId](ReturnMessage<vector<UTXO>> result)->void
   {
      auto&& utxoVec = result.get();
      auto msg = make_unique<BridgeUtxoList>();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = msg->add_data();
         cppUtxoToProtoUtxo(utxoProto, utxo);
      }

      this->writeToClient(move(msg), msgId);
   };

   wltPtr->getSpendableTxOutListForValue(value, lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getSpendableZCList(
   const std::string& wltId, unsigned msgId)
{
   auto& wltMap = wltManager_->getMap();
   auto wltIter = wltMap.find(wltId);
   if (wltIter == wltMap.end())
      throw runtime_error("invalid wallet id");
   auto wltPtr = wltIter->second;

   auto lbd = [this, msgId](ReturnMessage<vector<UTXO>> result)->void
   {
      auto&& utxoVec = result.get();
      auto msg = make_unique<BridgeUtxoList>();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = msg->add_data();
         cppUtxoToProtoUtxo(utxoProto, utxo);
      }

      this->writeToClient(move(msg), msgId);
   };

   wltPtr->getSpendableZcTxOutList(lbd);
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::getRBFTxOutList(
   const std::string& wltId, unsigned msgId)
{
   auto& wltMap = wltManager_->getMap();
   auto wltIter = wltMap.find(wltId);
   if (wltIter == wltMap.end())
      throw runtime_error("invalid wallet id");
   auto wltPtr = wltIter->second;

   auto lbd = [this, msgId](ReturnMessage<vector<UTXO>> result)->void
   {
      auto&& utxoVec = result.get();
      auto msg = make_unique<BridgeUtxoList>();
      for(auto& utxo : utxoVec)
      {
         auto utxoProto = msg->add_data();
         cppUtxoToProtoUtxo(utxoProto, utxo);
      }

      this->writeToClient(move(msg), msgId);
   };

   wltPtr->getRBFTxOutList(lbd);
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::initNewSigner()
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
   unsigned txOutId, unsigned sequence, uint64_t value)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      return false;

   iter->second->signer_.addSpender_ByOutpoint(hash, txOutId, sequence, value);
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
unique_ptr<Message> CppBridge::signer_getSerializedState(const string& id) const
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");
 
   auto&& serData = iter->second->signer_.serializeState();
   auto msg = make_unique<ReplyBinary>();
   msg->add_reply(serData.toCharPtr(), serData.getSize());
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
      iter->second->signer_.deserializeState(state);
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
   auto wltMap = wltManager_->getMap();
   auto wltIter = wltMap.find(wltId);
   auto wltPtr = wltIter->second->getWalletPtr();

   auto passLbd = createPassphrasePrompt(BridgePromptType::decrypt);

   //instantiate and set resolver feed
   auto signLbd = [wltPtr, signerPtr, passLbd, msgId, this](void)->void
   {
      bool success = true;
      try
      {
         auto wltSingle = dynamic_pointer_cast<AssetWallet_Single>(wltPtr);      
         auto feed = make_shared<ResolverFeed_AssetWalletSingle>(wltSingle);

         signerPtr->signer_.resetFeeds();
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
      passLbd({BinaryData::fromString(SHUTDOWN_PASSPROMPT_GUI)});
   };

   thread thr(signLbd);
   if (thr.joinable())
      thr.detach();
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::signer_getSignedTx(const string& id) const
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");

   BinaryDataRef data;
   try
   {
      data = iter->second->signer_.serialize();
   }
   catch (ScriptException&)
   {}
   
   auto response = make_unique<ReplyBinary>();
   response->add_reply(data.toCharPtr(), data.getSize());
   return response;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<Message> CppBridge::signer_getSignedStateForInput(
   const string& id, unsigned inputId)
{
   auto iter = signerMap_.find(id);
   if (iter == signerMap_.end())
      throw runtime_error("invalid signer id");

   if (iter->second->signState_ == nullptr)
   {
      auto&& signedState = iter->second->signer_.evaluateSignedState();
      iter->second->signState_ = make_unique<TxEvalState>(
         iter->second->signer_.evaluateSignedState());
   }

   const auto signState = iter->second->signState_.get();
   auto result = make_unique<BridgeInputSignedState>();

   auto signStateInput = signState->getSignedStateForInput(inputId);
   cppSignStateToPythonSignState(result.get(), signStateInput);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
void CppBridge::broadcastTx(const vector<BinaryData>& rawTxVec)
{
   bdvPtr_->broadcastZC(rawTxVec);
}

////////////////////////////////////////////////////////////////////////////////
////
////  WritePayload_Bridge
////
////////////////////////////////////////////////////////////////////////////////
void WritePayload_Bridge::serialize(std::vector<uint8_t>& data)
{
   if (message_ == nullptr)
      return;

   data.resize(message_->ByteSize() + 8);

   //set packet size
   auto sizePtr = (uint32_t*)&data[0];
   *sizePtr = data.size() - 4;

   //set id
   auto idPtr = (uint32_t*)&data[4];
   *idPtr = id_;

   //serialize protobuf message
   message_->SerializeToArray(&data[8], data.size() - 8);
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
            cppLedgerToProtoLedger(protoLe, *le);
         }

         vector<uint8_t> payloadVec(payload.ByteSize());
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
         cppNodeStatusToProtoNodeStatus(&nodeStatusMsg, *notif.nodeStatus_);
         vector<uint8_t> serializedNodeStatus(nodeStatusMsg.ByteSize());
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