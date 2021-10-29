////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _BRIDGE_PROTOBUF_CONVERSION_H
#define _BRIDGE_PROTOBUF_CONVERSION_H

#include <memory>

#include "../protobuf/ClientProto.pb.h"

//forward declarations
namespace DBClientClasses
{
   class LedgerEntry;
   class NodeStatus;
};

namespace Armory
{
   namespace Wallets
   {
      class AddressAccountId;
   };
};

class UTXO;
class TxInEvalState;

class AssetWallet;
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
      std::shared_ptr<AssetWallet>);

   static void wallet(
      Codec_ClientProto::WalletData* wltProto,
      std::shared_ptr<AssetWallet> wltPtr,
      const Armory::Wallets::AddressAccountId&);

   static void utxo(
      Codec_ClientProto::BridgeUtxo*,
      const UTXO& utxo);

   static void nodeStatus(
      Codec_ClientProto::BridgeNodeStatus*,
      const DBClientClasses::NodeStatus&);

   static void signatureState(
      Codec_ClientProto::BridgeInputSignedState*,
      const TxInEvalState&);
};
}; //namespace ArmoryBridge

#endif