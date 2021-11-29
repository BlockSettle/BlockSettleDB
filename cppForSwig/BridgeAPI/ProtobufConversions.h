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

#include "../protobuf/ClientProto.pb.h"

#define PROTO_ASSETID_PREFIX 0xAFu

//forward declarations
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
   };

   namespace Signer
   {
      class TxInEvalState;
   };
};

class UTXO;
class AddressEntry;

////
namespace ArmoryBridge
{
   struct CppToProto
   {
      static void ledger(
         Codec_ClientProto::BridgeLedger*,
         const DBClientClasses::LedgerEntry&);

      static void addr(
         Codec_ClientProto::WalletAsset*,
         std::shared_ptr<AddressEntry>,
         std::shared_ptr<Armory::Accounts::AddressAccount>);

      static void wallet(
         Codec_ClientProto::WalletData* wltProto,
         std::shared_ptr<Armory::Wallets::AssetWallet> wltPtr,
         const Armory::Wallets::AddressAccountId&);

      static void utxo(
         Codec_ClientProto::BridgeUtxo*,
         const UTXO& utxo);

      static void nodeStatus(
         Codec_ClientProto::BridgeNodeStatus*,
         const DBClientClasses::NodeStatus&);

      static void signatureState(
         Codec_ClientProto::BridgeInputSignedState*,
         const Armory::Signer::TxInEvalState&);
   };
}; //namespace ArmoryBridge

#endif