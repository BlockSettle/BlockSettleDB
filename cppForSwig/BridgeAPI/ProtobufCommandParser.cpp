////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020-21, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ProtobufCommandParser.h"
#include "CppBridge.h"
#include "../protobuf/ClientProto.pb.h"

using namespace std;
using namespace ArmoryBridge;
using namespace ::google::protobuf;
using namespace ::Codec_ClientProto;

////////////////////////////////////////////////////////////////////////////////
bool ProtobufCommandParser::processData(
   CppBridge* bridge, BinaryDataRef socketData)
{
   ClientCommand msg;
   if (!msg.ParseFromArray(socketData.getPtr() + 1, socketData.getSize() - 1))
   {
      LOGERR << "failed to parse protobuf msg";
      return false;
   }

   auto id = msg.payloadid();
   BridgeReply response;

   switch (msg.method())
   {
   case Methods::methodWithCallback:
   {
      try
      {
         bridge->queueCommandWithCallback(move(msg));
      }
      catch (const exception& e)
      {
         LOGERR << "[methodWithCallback] " << e.what();
         auto errMsg = make_unique<ReplyError>();
         errMsg->set_error(e.what());

         response = move(errMsg);
      }

      break;
   }

   case Methods::loadWallets:
   {
      bridge->loadWallets(id);
      break;
   }

   case Methods::setupDB:
   {
      bridge->setupDB();
      break;
   }

   case Methods::registerWallets:
   {
      bridge->registerWallets();
      break;
   }

   case Methods::registerWallet:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
         throw runtime_error("invalid command: registerWallet");
      bridge->registerWallet(msg.stringargs(0), msg.intargs(0));
      break;
   }

   case Methods::createBackupStringForWallet:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: getRootData");
      bridge->createBackupStringForWallet(msg.stringargs(0), id);
      break;
   }

   case Methods::goOnline:
   {
      if (bridge->bdvPtr_ == nullptr)
         throw runtime_error("null bdv ptr");
      bridge->bdvPtr_->goOnline();
      break;
   }

   case Methods::shutdown:
   {
      if (bridge->bdvPtr_ != nullptr)
      {
         bridge->bdvPtr_->unregisterFromDB();
         bridge->bdvPtr_.reset();
         bridge->callbackPtr_.reset();
      }

      return false;
   }

   case Methods::getLedgerDelegateIdForWallets:
   {
      auto& delegateId = bridge->getLedgerDelegateIdForWallets();
      auto replyMsg = make_unique<ReplyStrings>();
      replyMsg->add_reply(delegateId);
      response = move(replyMsg);
      break;
   }

   case Methods::updateWalletsLedgerFilter:
   {
      vector<BinaryData> idVec;
      for (int i=0; i<msg.stringargs_size(); i++)
         idVec.push_back(BinaryData::fromString(msg.stringargs(i)));

      bridge->bdvPtr_->updateWalletsLedgerFilter(idVec);
      break;
   }

   case Methods::getLedgerDelegateIdForScrAddr:
   {
      if (msg.stringargs_size() == 0 || msg.byteargs_size() == 0)
         throw runtime_error("invalid command: getLedgerDelegateIdForScrAddr");

      auto addrHashRef = BinaryDataRef::fromString(msg.byteargs(0));
      auto& delegateId = bridge->getLedgerDelegateIdForScrAddr(
         msg.stringargs(0), addrHashRef);

      auto replyMsg = make_unique<ReplyStrings>();
      replyMsg->add_reply(delegateId);
      response = move(replyMsg);
      break;
   }

   case Methods::getHistoryPageForDelegate:
   {
      if (msg.stringargs_size() == 0 || msg.intargs_size() == 0)
         throw runtime_error("invalid command: getHistoryPageForDelegate");
      bridge->getHistoryPageForDelegate(msg.stringargs(0), msg.intargs(0), id);
      break;
   }

   case Methods::getNodeStatus:
   {
      response = move(bridge->getNodeStatus());
      break;
   }

   case Methods::getBalanceAndCount:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: getBalanceAndCount");
      response = move(bridge->getBalanceAndCount(msg.stringargs(0)));
      break;
   }

   case Methods::getAddrCombinedList:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: getAddrCombinedList");
      response = move(bridge->getAddrCombinedList(msg.stringargs(0)));
      break;
   }

   case Methods::getHighestUsedIndex:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: getHighestUsedIndex");
      response = move(bridge->getHighestUsedIndex(msg.stringargs(0)));
      break;
   }

   case Methods::extendAddressPool:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
         throw runtime_error("invalid command: getHighestUsedIndex");
      bridge->extendAddressPool(msg.stringargs(0), msg.intargs(0), id);
      break;
   }

   case Methods::createWallet:
   {
      auto&& wltId = bridge->createWallet(msg);
      auto replyMsg = make_unique<ReplyStrings>();
      replyMsg->add_reply(wltId);
      response = move(replyMsg);
      break;
   }

   case Methods::deleteWallet:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: deleteWallet");
      auto result = bridge->deleteWallet(msg.stringargs(0));

      auto replyMsg = make_unique<ReplyNumbers>();
      replyMsg->add_ints(result);
      response = move(replyMsg);
      break;
   }

   case Methods::getWalletData:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: deleteWallet");
      response = move(bridge->getWalletPacket(msg.stringargs(0)));
      break;
   }

   case Methods::getTxByHash:
   {
      if (msg.byteargs_size() != 1)
         throw runtime_error("invalid command: getTxByHash");
      auto& byteargs = msg.byteargs(0);
      BinaryData hash((uint8_t*)byteargs.c_str(), byteargs.size());
      bridge->getTxByHash(hash, id);
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

      response = bridge->getTxInScriptType(scriptBd, hashBd);
      break;
   }

   case Methods::getTxOutScriptType:
   {
      if (msg.byteargs_size() != 1)
         throw runtime_error("invalid command: getTxOutScriptType");
      auto& byteargs = msg.byteargs(0);
      BinaryData script((uint8_t*)byteargs.c_str(), byteargs.size());
      response = bridge->getTxOutScriptType(script);
      break;
   }

   case Methods::getScrAddrForScript:
   {
      if (msg.byteargs_size() != 1)
         throw runtime_error("invalid command: getScrAddrForScript");
      auto& byteargs = msg.byteargs(0);
      BinaryData script((uint8_t*)byteargs.c_str(), byteargs.size());
      response = bridge->getScrAddrForScript(script);
      break;
   }

   case Methods::getLastPushDataInScript:
   {
      if (msg.byteargs_size() != 1)
         throw runtime_error("invalid command: getLastPushDataInScript");

      auto& script = msg.byteargs(0);
      BinaryData scriptBd((uint8_t*)script.c_str(), script.size());

      response = bridge->getLastPushDataInScript(scriptBd);
      break;
   }

   case Methods::getTxOutScriptForScrAddr:
   {
      if (msg.byteargs_size() != 1)
         throw runtime_error("invalid command: getTxOutScriptForScrAddr");

      auto& script = msg.byteargs(0);
      BinaryData scriptBd((uint8_t*)script.c_str(), script.size());

      response = bridge->getTxOutScriptForScrAddr(scriptBd);
      break;
   }

   case Methods::getAddrStrForScrAddr:
   {
      if (msg.byteargs_size() != 1)
         throw runtime_error("invalid command: getAddrStrForScrAddr");
      auto& byteargs = msg.byteargs(0);
      BinaryData script((uint8_t*)byteargs.c_str(), byteargs.size());
      response = bridge->getAddrStrForScrAddr(script);
      break;
   }

   case Methods::getNameForAddrType:
   {
      if (msg.intargs_size() != 1)
         throw runtime_error("invalid command: getNameForAddrType");
      auto addrTypeInt = msg.intargs(0);
      auto typeName = bridge->getNameForAddrType(addrTypeInt);

      auto replyMsg = make_unique<ReplyStrings>();
      replyMsg->add_reply(typeName);
      response = move(replyMsg);
      break;
   }

   case Methods::getHeaderByHeight:
   {
      if (msg.intargs_size() != 1)
         throw runtime_error("invalid command: getHeaderByHeight");
      auto intArgs = msg.intargs(0);
      bridge->getHeaderByHeight(intArgs, id);
      break;
   }

   case Methods::setupNewCoinSelectionInstance:
   {
      if (msg.intargs_size() != 1 || msg.stringargs_size() != 1)
         throw runtime_error("invalid command: setupNewCoinSelectionInstance");

      bridge->setupNewCoinSelectionInstance(
         msg.stringargs(0), msg.intargs(0), id);
      break;
   }

   case Methods::destroyCoinSelectionInstance:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: destroyCoinSelectionInstance");

      bridge->destroyCoinSelectionInstance(msg.stringargs(0));
      break;
   }

   case Methods::resetCoinSelection:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: resetCoinSelection");
      bridge->resetCoinSelection(msg.stringargs(0));
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

      auto success = bridge->setCoinSelectionRecipient(msg.stringargs(0),
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

      auto success = bridge->cs_SelectUTXOs(msg.stringargs(0),
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

      response = bridge->cs_getUtxoSelection(msg.stringargs(0));
      break;
   }

   case Methods::cs_getFlatFee:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: cs_getFlatFee");

      response = bridge->cs_getFlatFee(msg.stringargs(0));
      break;
   }

   case Methods::cs_getFeeByte:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: cs_getFeeByte");

      response = bridge->cs_getFeeByte(msg.stringargs(0));
      break;
   }

   case Methods::cs_ProcessCustomUtxoList:
   {
      auto success = bridge->cs_ProcessCustomUtxoList(msg);

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
      auto&& str = bridge->fortuna_.generateRandom(size).toHexStr();

      auto msg = make_unique<ReplyStrings>();
      msg->add_reply(str);
      response = move(msg);
      break;
   }

   case Methods::createAddressBook:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: createAddressBook");
      bridge->createAddressBook(msg.stringargs(0), id);
      break;
   }

   case Methods::getUtxosForValue:
   {
      if (msg.stringargs_size() != 1 || msg.longargs_size() != 1)
         throw runtime_error("invalid command: getUtxosForValue");
      bridge->getUtxosForValue(msg.stringargs(0), msg.longargs(0), id);
      break;
   }

   case Methods::getSpendableZCList:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command getSpendableZCList");
      bridge->getSpendableZCList(msg.stringargs(0), id);
      break;
   }

   case Methods::getRBFTxOutList:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: getRBFTxOutList");
      bridge->getRBFTxOutList(msg.stringargs(0), id);
      break;
   }

   case Methods::getNewAddress:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
         throw runtime_error("invalid command: getNewAddress");
      response = bridge->getNewAddress(msg.stringargs(0), msg.intargs(0));
      break;
   }

   case Methods::getChangeAddress:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
         throw runtime_error("invalid command: getChangeAddress");
      response = bridge->getChangeAddress(msg.stringargs(0), msg.intargs(0));
      break;
   }

   case Methods::peekChangeAddress:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
         throw runtime_error("invalid command: peekChangeAddress");
      response = bridge->peekChangeAddress(msg.stringargs(0), msg.intargs(0));
      break;
   }

   case Methods::getHash160:
   {
      if (msg.byteargs_size() != 1)
         throw runtime_error("invalid command: getHash160");
      BinaryDataRef bdRef; bdRef.setRef(msg.byteargs(0));
      response = bridge->getHash160(bdRef);
      break;
   }

   case Methods::initNewSigner:
   {
      response = bridge->initNewSigner();
      break;
   }

   case Methods::destroySigner:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: destroySigner");
      bridge->destroySigner(msg.stringargs(0));
      break;
   }

   case Methods::signer_SetVersion:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
         throw runtime_error("invalid command: signer_SetVersion");
      auto success = bridge->signer_SetVersion(msg.stringargs(0), msg.intargs(0));
      auto resultProto = make_unique<ReplyNumbers>();
      resultProto->add_ints(success);
      response = move(resultProto);
      break;
   }

   case Methods::signer_SetLockTime:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
         throw runtime_error("invalid command: signer_SetLockTime");
      auto result = bridge->signer_SetLockTime(msg.stringargs(0), msg.intargs(0));
      auto resultProto = make_unique<ReplyNumbers>();
      resultProto->add_ints(result);
      response = move(resultProto);
      break;
   }

   case Methods::signer_addSpenderByOutpoint:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 2 ||
         msg.byteargs_size() != 1)
      throw runtime_error("invalid command: signer_addSpenderByOutpoint");

      BinaryDataRef hash; hash.setRef(msg.byteargs(0));
      auto result = bridge->signer_addSpenderByOutpoint(msg.stringargs(0),
         hash, msg.intargs(0), msg.intargs(1));

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

      auto result = bridge->signer_populateUtxo(msg.stringargs(0),
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
      auto result = bridge->signer_addRecipient(msg.stringargs(0),
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
      response = bridge->signer_getSerializedState(msg.stringargs(0));
      break;
   }

   case Methods::signer_unserializeState:
   {
      if (msg.stringargs_size() != 1 || msg.byteargs_size() != 1)
         throw runtime_error("invalid command: signer_unserializeState");

      auto result = bridge->signer_unserializeState(
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
      bridge->signer_signTx(msg.stringargs(0), msg.stringargs(1), id);
      break;
   }

   case Methods::signer_getSignedTx:
   {
      if (msg.stringargs_size() != 1)
         throw runtime_error("invalid command: signer_getSignedTx");

      response = bridge->signer_getSignedTx(msg.stringargs(0));
      break;
   }

   case Methods::signer_resolve:
   {
      if (msg.stringargs_size() != 1 || msg.byteargs_size() != 1)
         throw runtime_error("invalid command: signer_resolve");

      response = bridge->signer_resolve(msg.byteargs(0), msg.stringargs(0));
      break;
   }

   case Methods::signer_getSignedStateForInput:
   {
      if (msg.stringargs_size() != 1 || msg.intargs_size() != 1)
      {
         throw runtime_error(
            "invalid command: signer_getSignedStateForInput");
      }

      response = bridge->signer_getSignedStateForInput(
         msg.stringargs(0), msg.intargs(0));
      break;
   }

   case Methods::returnPassphrase:
   {
      if (msg.stringargs_size() != 2)
         throw runtime_error("invalid command: returnPassphrase");

      auto result = bridge->returnPassphrase(msg.stringargs(0), msg.stringargs(1));

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
      for (int i=0; i<msg.byteargs_size(); i++)
         bdVec.emplace_back(move(BinaryData::fromString(msg.byteargs(i))));

      bridge->broadcastTx(bdVec);
      break;
   }

   case Methods::getBlockTimeByHeight:
   {
      if (msg.intargs_size() != 1)
         throw runtime_error("invalid command: getBlockTimeByHeight");
      bridge->getBlockTimeByHeight(msg.intargs(0), id);
      break;
   }

   default:
      stringstream ss;
      ss << "unknown client method: " << msg.method();
      throw runtime_error(ss.str());
   }

   if (response != nullptr)
   {
      //write response to socket
      bridge->writeToClient(move(response), id);
   }

   return true;
}
