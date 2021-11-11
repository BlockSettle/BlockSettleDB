////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ProtobufConversions.h"
#include "../Wallets/WalletIdTypes.h"

#include "DBClientClasses.h"
#include "TxEvalState.h"
#include "Wallets.h"

using namespace std;
using namespace ArmoryBridge;

using namespace Codec_ClientProto;

/***
TODO: use the same protobuf as the DB for all things regarding wallet balance
      instead of rolling dedicated protobuf formas for the bridge
***/

////////////////////////////////////////////////////////////////////////////////
void CppToProto::ledger(
   BridgeLedger* ledgerProto, const DBClientClasses::LedgerEntry& ledgerCpp)
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
void CppToProto::addr(WalletAsset* assetPtr,
   shared_ptr<AddressEntry> addrPtr, shared_ptr<AddressAccount> accPtr)
{
   if (accPtr == nullptr)
      throw runtime_error("[CppToProto::addr] null acc ptr");

   auto assetID = addrPtr->getID();
   auto wltAsset = accPtr->getAssetForID(assetID);

   //address
   auto& addrHash = addrPtr->getPrefixedHash();
   assetPtr->set_prefixedhash(addrHash.toCharPtr(), addrHash.getSize());

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
   const auto& serAssetId = assetID.getSerializedKey(PROTO_ASSETID_PREFIX);
   assetPtr->set_assetid(serAssetId.getCharPtr(), serAssetId.getSize());

   //address string
   auto& addrStr = addrPtr->getAddress();
   assetPtr->set_addressstring(addrStr);

   auto isUsed = accPtr->isAssetInUse(addrPtr->getID());
   assetPtr->set_isused(isUsed);

   //resolve change status
   bool isChange = accPtr->isAssetChange(addrPtr->getID());
   assetPtr->set_ischange(isChange);

   //precursor, if any
   if (addrNested == nullptr)
      return;

   auto& precursor = addrNested->getPredecessor()->getScript();
   assetPtr->set_precursorscript(precursor.getCharPtr(), precursor.getSize());
}

////////////////////////////////////////////////////////////////////////////////
void CppToProto::wallet(WalletData* wltProto, shared_ptr<AssetWallet> wltPtr,
   const Armory::Wallets::AddressAccountId& accId)
{
   string wltId = wltPtr->getID() + ":" + accId.toHexStr();
   wltProto->set_id(wltId);

   //wo status
   bool isWO = true;
   auto wltSingle = dynamic_pointer_cast<AssetWallet_Single>(wltPtr);
   if (wltSingle != nullptr)
      isWO = wltSingle->isWatchingOnly();
   wltProto->set_watchingonly(isWO);

   //the address account
   auto accPtr = wltSingle->getAccountForID(accId);

   //address types
   const auto& addrTypes = accPtr->getAddressTypeSet();
   for (const auto& addrType : addrTypes)
      wltProto->add_addresstypes(addrType);
   wltProto->set_defaultaddresstype((uint32_t)accPtr->getAddressType());

   //use index
   auto assetAccountPtr = accPtr->getOuterAccount();
   wltProto->set_lookupcount(assetAccountPtr->getLastComputedIndex());
   wltProto->set_usecount(assetAccountPtr->getHighestUsedIndex());

   //address map
   auto addrMap = accPtr->getUsedAddressMap();
   for (auto& addrPair : addrMap)
   {
      auto assetPtr = wltProto->add_assets();
      CppToProto::addr(assetPtr, addrPair.second, accPtr);
   }

   //comments
   wltProto->set_label(wltPtr->getLabel());
   wltProto->set_desc(wltPtr->getDescription());
}

////////////////////////////////////////////////////////////////////////////////
void CppToProto::utxo(BridgeUtxo* utxoProto, const UTXO& utxo)
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
void CppToProto::nodeStatus(
   BridgeNodeStatus* nsProto, const DBClientClasses::NodeStatus& nsCpp)
{
   auto chainStatus = nsCpp.chainStatus();

   nsProto->set_isvalid(true);
   nsProto->set_nodestate(nsCpp.state());
   nsProto->set_issegwitenabled(nsCpp.isSegWitEnabled());
   nsProto->set_rpcstate(nsCpp.rpcState());
   
   auto chainStatusProto = nsProto->mutable_chainstatus();

   chainStatusProto->set_chainstate(chainStatus.state());
   chainStatusProto->set_blockspeed(chainStatus.getBlockSpeed());
   chainStatusProto->set_progresspct(chainStatus.getProgressPct());
   chainStatusProto->set_eta(chainStatus.getETA());
   chainStatusProto->set_blocksleft(chainStatus.getBlocksLeft());
}

////////////////////////////////////////////////////////////////////////////////
void CppToProto::signatureState(
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
