////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _CPPBRIDGE_H
#define _CPPBRIDGE_H

#include "../ArmoryConfig.h"
#include "WalletManager.h"
#include "btc/ecc.h"
#include "../protobuf/BridgeProto.pb.h"
#include "../AsyncClient.h"

namespace Armory
{
   namespace Bridge
   {
      struct WritePayload_Bridge;

      //////////////////////////////////////////////////////////////////////////
      typedef std::function<void(
         std::unique_ptr<BridgeProto::Payload>)> notifLbd;

      ////
      class BridgeCallback : public RemoteCallback
      {
      private:
         std::shared_ptr<WalletManager> wltManager_;

         //to push packets to the gui
         notifLbd pushNotifLbd_;

         //id members
         Armory::Threading::BlockingQueue<std::string> idQueue_;
         std::set<std::string> validIds_;
         std::mutex idMutex_;

      public:
         BridgeCallback(
            std::shared_ptr<WalletManager> mgr, const notifLbd& lbd) :
            RemoteCallback(), wltManager_(mgr), pushNotifLbd_(lbd)
         {}

         //virtuals
         void run(BdmNotification) override;

         void progress(
            BDMPhase phase,
            const std::vector<std::string> &walletIdVec,
            float progress, unsigned secondsRem,
            unsigned progressNumeric
         ) override;

         void disconnected(void) override;

         //local notifications
         void notify_SetupDone(void);
         void notify_RegistrationDone(const std::set<std::string>&);
         void notify_SetupRegistrationDone(const std::set<std::string>&);
         void notify_NewBlock(unsigned);
         void notify_Ready(unsigned);

         //
         void waitOnId(const std::string&);
      };

      //////////////////////////////////////////////////////////////////////////
      struct CppBridgeSignerStruct
      {
         Armory::Signer::Signer signer_;
         std::unique_ptr<Armory::Signer::TxEvalState> signState_;
      };

      //////////////////////////////////////////////////////////////////////////
      using CommandQueue = std::shared_ptr<Armory::Threading::BlockingQueue<
         ::BridgeProto::Request>>;

      ////
      class CppBridge;

      ////
      class MethodCallbacksHandler
      {
         friend class CppBridge;

      private:
         unsigned counter_ = 0;
         const BinaryData id_;
         std::thread methodThr_;
         std::map<unsigned, std::function<void(BinaryData)>> callbacks_;

         CommandQueue parentCommandQueue_;

      public:
         MethodCallbacksHandler(const BinaryData& id, CommandQueue queue) :
            id_(id), parentCommandQueue_(queue)
         {}

         ~MethodCallbacksHandler(void)
         {
            flagForCleanup();
            if (methodThr_.joinable())
               methodThr_.join();
         }

         const BinaryData& id(void) const { return id_; }
         unsigned addCallback(const std::function<void(BinaryData)>&);

         //startThread
         void flagForCleanup(void);
         void processCallbackReply(unsigned, BinaryDataRef&);
      };

      //////////////////////////////////////////////////////////////////////////
      struct ProtobufCommandParser;
      using BridgePayload = std::unique_ptr<BridgeProto::Payload>;

      class CppBridge
      {
         friend struct ProtobufCommandParser;

      private:
         const std::string path_;

         const std::string dbAddr_;
         const std::string dbPort_;

         std::shared_ptr<WalletManager> wltManager_;
         std::shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;

         std::shared_ptr<BridgeCallback> callbackPtr_;

         std::map<std::string, AsyncClient::LedgerDelegate> delegateMap_;
         std::map<std::string,
            std::shared_ptr<CoinSelection::CoinSelectionInstance>> csMap_;
         std::map<std::string,
            std::shared_ptr<CppBridgeSignerStruct>> signerMap_;

         PRNG_Fortuna fortuna_;

         std::mutex passPromptMutex_;
         std::map<std::string,
            std::shared_ptr<BridgePassphrasePrompt>> promptMap_;

         std::function<void(
            std::unique_ptr<WritePayload_Bridge>)> writeLambda_;

         const bool dbOneWayAuth_;
         const bool dbOffline_;

         std::map<BinaryData, std::shared_ptr<MethodCallbacksHandler>>
            callbackHandlerMap_;
         CommandQueue commandWithCallbackQueue_;

         std::thread commandWithCallbackProcessThread_;

      private:
         //commands with callback
         void queueCommandWithCallback(BridgeProto::Request);
         void processCommandWithCallbackThread(void);

         //wallet setup
         void loadWallets(unsigned id);
         BridgePayload createWalletsPacket(void);
         bool deleteWallet(const std::string&);
         BridgePayload getWalletPacket(const std::string&) const;

         //AsyncClient::BlockDataViewer setup
         void setupDB(void);
         void registerWallets(void);
         void registerWallet(const std::string&, bool isNew);

         BridgePayload getNodeStatus(void);

         //balance and counts
         BridgePayload getBalanceAndCount(const std::string&);
         BridgePayload getAddrCombinedList(const std::string&);
         BridgePayload getHighestUsedIndex(const std::string&);

         //wallet & addresses
         void extendAddressPool(const std::string&, unsigned,
            const std::string&, unsigned);
         BridgePayload getNewAddress(const std::string&, unsigned);
         BridgePayload getChangeAddress(const std::string&, unsigned);
         BridgePayload peekChangeAddress(const std::string&, unsigned);
         std::string createWallet(const BridgeProto::Utils::CreateWallet&);
         void createBackupStringForWallet(const std::string&, unsigned);
         void restoreWallet(const BinaryDataRef&,
            std::shared_ptr<MethodCallbacksHandler>);

         //ledgers
         const std::string& getLedgerDelegateIdForWallets(void);
         const std::string& getLedgerDelegateIdForScrAddr(
            const std::string&, const BinaryDataRef&);
         void getHistoryPageForDelegate(const std::string&, unsigned, unsigned);
         void getHistoryForWalletSelection(const std::string&,
            std::vector<std::string>, unsigned);
         void createAddressBook(const std::string&, unsigned);
         void setComment(const std::string&,
            const BridgeProto::Wallet::SetComment&);
         void setWalletLabels(const std::string&,
            const BridgeProto::Wallet::SetLabels&);

         //txs & headers
         void getTxByHash(const BinaryData&, unsigned);
         void getHeaderByHeight(unsigned, unsigned);

         //utxos
         void getUtxosForValue(const std::string&, uint64_t, unsigned);
         void getSpendableZCList(const std::string&, unsigned);
         void getRBFTxOutList(const std::string&, unsigned);

         //coin selection
         void setupNewCoinSelectionInstance(
            const std::string&, unsigned, unsigned);
         void destroyCoinSelectionInstance(const std::string&);
         std::shared_ptr<CoinSelection::CoinSelectionInstance>
            coinSelectionInstance(const std::string&) const;

         //signer
         BridgePayload initNewSigner(void);
         void destroySigner(const std::string&);
         std::shared_ptr<CppBridgeSignerStruct>
            signerInstance(const std::string&) const;

         void signer_signTx(const std::string&, const std::string&, unsigned);
         BridgePayload getSignedStateForInput(
            const std::string&, unsigned);
         bool signer_resolve(const std::string&, const std::string&) const;

         //utils
         BridgePayload getTxInScriptType(
            const BinaryData&, const BinaryData&) const;
         BridgePayload getTxOutScriptType(const BinaryData&) const;
         BridgePayload getScrAddrForScript(const BinaryData&) const;
         BridgePayload getScrAddrForAddrStr(const std::string&) const;
         BridgePayload getLastPushDataInScript(const BinaryData&) const;
         BridgePayload getHash160(const BinaryDataRef&) const;
         void broadcastTx(const std::vector<BinaryData>&);
         BridgePayload getTxOutScriptForScrAddr(const BinaryData&) const;
         BridgePayload getAddrStrForScrAddr(const BinaryData&) const;
         std::string getNameForAddrType(int) const;
         BridgePayload setAddressTypeFor(
            const std::string&, const std::string&, uint32_t) const;
         void getBlockTimeByHeight(uint32_t, uint32_t) const;
         void estimateFee(uint32_t, const std::string&, uint32_t) const;

         //passphrase prompt
         PassphraseLambda createPassphrasePrompt(
            ::BridgeProto::UnlockPromptType);
         bool returnPassphrase(const std::string&, const std::string&);

      public:
         CppBridge(const std::string&, const std::string&,
            const std::string&, bool, bool);

         bool processData(BinaryDataRef socketData);
         void writeToClient(BridgePayload msgPtr) const;

         void setWriteLambda(
            std::function<void(std::unique_ptr<WritePayload_Bridge>)> lbd)
         {
            writeLambda_ = lbd;
         }

         void startThreads(void);
         void stopThreads(void);
      };
   }; //namespace Bridge
}; //namespace Armory

#endif