////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ProtobufConversions.h"
#include "../Wallets/WalletIdTypes.h"
#include "../Wallets/AssetEncryption.h"

#include "DBClientClasses.h"
#include "TxEvalState.h"
#include "Wallets.h"

using namespace std;
using namespace Armory::Bridge;
using namespace Armory::Accounts;
using namespace Armory::Wallets;

using namespace BridgeProto;

/***
TODO: use the same protobuf as the DB for all things regarding wallet balance
      instead of rolling dedicated protobuf formas for the bridge
***/

////////////////////////////////////////////////////////////////////////////////
void CppToProto::ledger(Ledger* ledgerProto,
   const DBClientClasses::LedgerEntry& ledgerCpp)
{
   ledgerProto->set_value(ledgerCpp.getValue());

   auto hash = ledgerCpp.getTxHash();
   ledgerProto->set_hash(hash.toCharPtr(), hash.getSize());
   ledgerProto->set_id(ledgerCpp.getID());
   
   ledgerProto->set_height(ledgerCpp.getBlockNum());
   ledgerProto->set_tx_index(ledgerCpp.getIndex());
   ledgerProto->set_tx_time(ledgerCpp.getTxTime());
   ledgerProto->set_coinbase(ledgerCpp.isCoinbase());
   ledgerProto->set_sent_to_self(ledgerCpp.isSentToSelf());
   ledgerProto->set_change_back(ledgerCpp.isChangeBack());
   ledgerProto->set_chained_zc(ledgerCpp.isChainedZC());
   ledgerProto->set_witness(ledgerCpp.isWitness());
   ledgerProto->set_rbf(ledgerCpp.isOptInRBF());

   for (auto& scrAddr : ledgerCpp.getScrAddrList())
      ledgerProto->add_scraddr(scrAddr.getCharPtr(), scrAddr.getSize());
}

////////////////////////////////////////////////////////////////////////////////
bool CppToProto::addr(WalletReply::AddressData* assetPtr,
   shared_ptr<AddressEntry> addrPtr, shared_ptr<AddressAccount> accPtr,
   const EncryptionKeyId& defaultEncryptionKeyId)
{
   if (accPtr == nullptr)
      throw runtime_error("[CppToProto::addr] null acc ptr");

   auto assetID = addrPtr->getID();
   auto wltAsset = accPtr->getAssetForID(assetID);

   //address
   auto& addrHash = addrPtr->getPrefixedHash();
   assetPtr->set_prefixed_hash(addrHash.toCharPtr(), addrHash.getSize());

   //address type & pubkey
   BinaryDataRef pubKeyRef;
   std::shared_ptr<AddressEntry_WithAsset> addrWithAssetPtr = nullptr;
   uint32_t addrType = (uint32_t)addrPtr->getType();

   auto addrNested = dynamic_pointer_cast<AddressEntry_Nested>(addrPtr);
   if (addrNested != nullptr)
   {
      addrType |= (uint32_t)addrNested->getPredecessor()->getType();
      auto pred = addrNested->getPredecessor();
      pubKeyRef = pred->getPreimage().getRef();

      addrWithAssetPtr = dynamic_pointer_cast<AddressEntry_WithAsset>(pred);
   }
   else
   {
      pubKeyRef = addrPtr->getPreimage().getRef();
      addrWithAssetPtr = dynamic_pointer_cast<AddressEntry_WithAsset>(addrPtr);
   }

   assetPtr->set_addr_type(addrType);
   assetPtr->set_public_key(pubKeyRef.toCharPtr(), pubKeyRef.getSize());

   //index
   assetPtr->set_id(wltAsset->getIndex());
   const auto& serAssetId = assetID.getSerializedKey(PROTO_ASSETID_PREFIX);
   assetPtr->set_asset_id(serAssetId.getCharPtr(), serAssetId.getSize());

   //address string
   const auto& addrStr = addrPtr->getAddress();
   assetPtr->set_address_string(addrStr);

   auto isUsed = accPtr->isAssetInUse(addrPtr->getID());
   assetPtr->set_is_used(isUsed);

   //resolve change status
   bool isChange = accPtr->isAssetChange(addrPtr->getID());
   assetPtr->set_is_change(isChange);

   //priv key & encryption status
   bool isLocked = false;
   bool hasPrivKey = false;
   if (addrWithAssetPtr != nullptr)
   {
      auto theAsset = addrWithAssetPtr->getAsset();
      if (theAsset != nullptr)
      {
         if (theAsset->hasPrivateKey())
         {
            hasPrivKey = true;
            try
            {
               //the privkey is considered locked if it's encrypted by
               //something else than the default encryption key, which
               //lays in clear text in the wallet header
               auto encryptionKeyId = theAsset->getPrivateEncryptionKeyId();
               isLocked = (encryptionKeyId != defaultEncryptionKeyId);
            }
            catch (const runtime_error&)
            {
               //nothing to do, address has no encryption key
            }
         }
      }
   }
   assetPtr->set_has_priv_key(hasPrivKey);
   assetPtr->set_use_encryption(isLocked);

   //precursor, if any
   if (addrNested == nullptr)
      return isLocked;

   auto& precursor = addrNested->getPredecessor()->getScript();
   assetPtr->set_precursor_script(precursor.getCharPtr(), precursor.getSize());

   return isLocked;
}

////////////////////////////////////////////////////////////////////////////////
void CppToProto::wallet(WalletReply::WalletData* wltProto,
   shared_ptr<AssetWallet> wltPtr,
   const Armory::Wallets::AddressAccountId& accId,
   const map<BinaryData, string>& commentMap)
{
   string wltId = wltPtr->getID() + ":" + accId.toHexStr();
   wltProto->set_id(wltId);

   //wo status
   bool isWO = true;
   auto wltSingle = dynamic_pointer_cast<AssetWallet_Single>(wltPtr);
   if (wltSingle != nullptr)
      isWO = wltSingle->isWatchingOnly();
   wltProto->set_watching_only(isWO);

   //the address account
   auto accPtr = wltSingle->getAccountForID(accId);

   //address types
   const auto& addrTypes = accPtr->getAddressTypeSet();
   for (const auto& addrType : addrTypes)
      wltProto->add_address_type(addrType);
   wltProto->set_default_address_type((uint32_t)accPtr->getDefaultAddressType());

   //use index
   auto assetAccountPtr = accPtr->getOuterAccount();
   wltProto->set_lookup_count(assetAccountPtr->getLastComputedIndex());
   wltProto->set_use_count(assetAccountPtr->getHighestUsedIndex());

   //address map
   auto addrMap = accPtr->getUsedAddressMap();
   bool useEncryption = true;
   for (auto& addrPair : addrMap)
   {
      auto assetPtr = wltProto->add_address_data();
      useEncryption &= CppToProto::addr(assetPtr, addrPair.second, accPtr,
         wltPtr->getDefaultEncryptionKeyId());
   }

   //encryption info
   wltProto->set_use_encryption(useEncryption);

   uint32_t kdfMem = 0;
   auto kdfPtr = wltPtr->getDefaultKdf();
   auto kdfRomix = dynamic_pointer_cast<
      Encryption::KeyDerivationFunction_Romix>(kdfPtr);
   if (kdfRomix != nullptr)
      kdfMem = kdfRomix->memTarget();
   wltProto->set_kdf_mem_req(kdfMem);

   //labels
   wltProto->set_label(wltPtr->getLabel());
   wltProto->set_desc(wltPtr->getDescription());

   //comments
   for (const auto& commentIt : commentMap)
   {
      auto commentProto = wltProto->add_comments();
      commentProto->set_key(
         commentIt.first.getPtr(), commentIt.first.getSize());
      commentProto->set_val(commentIt.second);
   }
}

////////////////////////////////////////////////////////////////////////////////
void CppToProto::utxo(Utxo* utxoProto, const UTXO& utxo)
{
   auto& hash = utxo.getTxHash();
   utxoProto->set_tx_hash(hash.getCharPtr(), hash.getSize());
   utxoProto->set_txout_index(utxo.getTxOutIndex());

   utxoProto->set_value(utxo.getValue());
   utxoProto->set_tx_height(utxo.getHeight());
   utxoProto->set_tx_index(utxo.getTxIndex());

   auto& script = utxo.getScript();
   utxoProto->set_script(script.getCharPtr(), script.getSize());

   auto scrAddr = utxo.getRecipientScrAddr();
   utxoProto->set_scraddr(scrAddr.getCharPtr(), scrAddr.getSize());
}

////////////////////////////////////////////////////////////////////////////////
void CppToProto::nodeStatus(NodeStatus* nsProto,
   const DBClientClasses::NodeStatus& nsCpp)
{
   auto chainStatus = nsCpp.chainStatus();

   nsProto->set_is_valid(true);
   nsProto->set_node_state(nsCpp.state());
   nsProto->set_is_segwit_enabled(nsCpp.isSegWitEnabled());
   nsProto->set_rpc_state(nsCpp.rpcState());
   
   auto chainStatusProto = nsProto->mutable_chain_status();

   chainStatusProto->set_chain_state(chainStatus.state());
   chainStatusProto->set_block_speed(chainStatus.getBlockSpeed());
   chainStatusProto->set_progress_pct(chainStatus.getProgressPct());
   chainStatusProto->set_eta(chainStatus.getETA());
   chainStatusProto->set_blocks_left(chainStatus.getBlocksLeft());
}

////////////////////////////////////////////////////////////////////////////////
void CppToProto::signatureState(
   SignerReply::InputSignedState* ssProto,
   const Armory::Signer::TxInEvalState& ssCpp)
{
   ssProto->set_is_valid(ssCpp.isValid());
   ssProto->set_m(ssCpp.getM());
   ssProto->set_n(ssCpp.getN());
   ssProto->set_sig_count(ssCpp.getSigCount());
   
   const auto& pubKeyMap = ssCpp.getPubKeyMap();
   for (auto& pubKeyPair : pubKeyMap)
   {
      auto keyData = ssProto->add_sign_state();
      keyData->set_pub_key(
         pubKeyPair.first.getCharPtr(), pubKeyPair.first.getSize());
      keyData->set_has_sig(pubKeyPair.second);
   }
}
