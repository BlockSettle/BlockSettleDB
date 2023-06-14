////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _BRIDGE_PROTOBUF_CONVERSION_H
#define _BRIDGE_PROTOBUF_CONVERSION_H

#include <memory>

#include "../protobuf/BridgeProto.pb.h"

#define PROTO_ASSETID_PREFIX 0xAFu

//forward declarations
struct UTXO;
class AddressEntry;
class BinaryData;

namespace DBClientClasses
{
   class LedgerEntry;
   class NodeStatus;
};

namespace Armory
{
   namespace Accounts
   {
      class AddressAccount;
   }

   namespace Wallets
   {
      class AddressAccountId;
      class AssetWallet;
      class EncryptionKeyId;
   };

   namespace Signer
   {
      class TxInEvalState;
   };

   ////
   namespace Bridge
   {
      struct CppToProto
      {
         static void ledger(
            BridgeProto::Ledger*,
            const DBClientClasses::LedgerEntry&);

         static bool addr(
            BridgeProto::WalletReply::AddressData*,
            std::shared_ptr<AddressEntry>,
            std::shared_ptr<Accounts::AddressAccount>,
            const Wallets::EncryptionKeyId&);

         static void wallet(
            BridgeProto::WalletReply::WalletData*,
            std::shared_ptr<Wallets::AssetWallet>,
            const Wallets::AddressAccountId&,
            const std::map<BinaryData, std::string>&);

         static void utxo(
            BridgeProto::Utxo*,
            const UTXO& utxo);

         static void nodeStatus(
            BridgeProto::NodeStatus*,
            const DBClientClasses::NodeStatus&);

         static void signatureState(
            BridgeProto::SignerReply::InputSignedState*,
            const Signer::TxInEvalState&);
      };
   }; //namespace Bridge
}; //namespace Armory

#endif