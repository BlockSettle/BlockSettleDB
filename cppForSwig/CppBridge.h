////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _CPPBRIDGE_H
#define _CPPBRIDGE_H

#include "BlockDataManagerConfig.h"
#include "WalletManager.h"
#include "btc/ecc.h"
#include "protobuf/ClientProto.pb.h"
#include "AsyncClient.h"

///////////////////////////////////////////////////////////////////////////////
struct WritePayload_Bridge : public Socket_WritePayload
{
   std::unique_ptr<::google::protobuf::Message> message_;

   void serialize(std::vector<uint8_t>&);
   std::string serializeToText(void) 
   {
      throw std::runtime_error("not implemented"); 
   }

   size_t getSerializedSize(void) const 
   {
      return message_->ByteSize() + 8;
   }
};

///////////////////////////////////////////////////////////////////////////////
struct BridgePassphrasePrompt
{
private:
   std::unique_ptr<std::promise<SecureBinaryData>> promPtr_;
   std::unique_ptr<std::shared_future<SecureBinaryData>> futPtr_;

   const std::string id_;
   std::function<void(std::unique_ptr<WritePayload_Bridge>)> writeLambda_;

   std::set<BinaryData> ids_;

public:
   BridgePassphrasePrompt(const std::string id,
      std::function<void(std::unique_ptr<WritePayload_Bridge>)> lbd) :
      id_(id), writeLambda_(lbd)
   {}

   PassphraseLambda getLambda(::Codec_ClientProto::UnlockPromptType);
   void setReply(const std::string&);
};

///////////////////////////////////////////////////////////////////////////////
typedef std::function<void(
   std::unique_ptr<google::protobuf::Message>, unsigned)> notifLbd;

////
class BridgeCallback : public RemoteCallback
{
private:
   std::shared_ptr<WalletManager> wltManager_;

   //to push packets to the gui
   notifLbd pushNotifLbd_;
   
   //id members
   ArmoryThreading::BlockingQueue<std::string> idQueue_;
   std::set<std::string> validIds_;
   std::mutex idMutex_;

public:
   BridgeCallback(std::shared_ptr<WalletManager> mgr, const notifLbd& lbd) :
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

///////////////////////////////////////////////////////////////////////////////
struct CppBridgeSignerStruct
{
   ArmorySigner::Signer signer_;
   std::unique_ptr<TxEvalState> signState_;
};

///////////////////////////////////////////////////////////////////////////////
using CommandQueue = std::shared_ptr<ArmoryThreading::BlockingQueue<
   ::Codec_ClientProto::ClientCommand>>;

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

///////////////////////////////////////////////////////////////////////////////
using BridgeReply = std::unique_ptr<::google::protobuf::Message>;
class CppBridge
{
private:
   const std::string path_;

   const std::string dbAddr_;
   const std::string dbPort_;

   std::shared_ptr<WalletManager> wltManager_;
   std::shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;

   std::shared_ptr<BridgeCallback> callbackPtr_;

   std::map<std::string, AsyncClient::LedgerDelegate> delegateMap_;
   std::map<std::string, std::shared_ptr<CoinSelectionInstance>> csMap_;
   std::map<std::string, std::shared_ptr<CppBridgeSignerStruct>> signerMap_;

   PRNG_Fortuna fortuna_;

   std::mutex passPromptMutex_;
   std::map<std::string, std::shared_ptr<BridgePassphrasePrompt>> promptMap_;

   std::function<void(std::unique_ptr<WritePayload_Bridge>)> writeLambda_;

   const bool oneWayAuth_;
   const bool offline_;

   std::map<BinaryData, std::shared_ptr<MethodCallbacksHandler>> 
      callbackHandlerMap_;
   CommandQueue commandWithCallbackQueue_;

   std::thread commandWithCallbackProcessThread_;

private:
   //commands with callback
   void queueCommandWithCallback(::Codec_ClientProto::ClientCommand);
   void processCommandWithCallbackThread(void);

   //wallet setup
   void loadWallets(unsigned id);
   BridgeReply createWalletsPacket(void);
   bool deleteWallet(const std::string&);
   BridgeReply getWalletPacket(const std::string&) const;
   
   //AsyncClient::BlockDataViewer setup
   void setupDB(void);
   void registerWallets(void);
   void registerWallet(const std::string&, bool isNew);

   BridgeReply getNodeStatus(void);

   //balance and counts
   BridgeReply getBalanceAndCount(const std::string&);
   BridgeReply getAddrCombinedList(const std::string&);
   BridgeReply getHighestUsedIndex(const std::string&);

   //wallet & addresses
   BridgeReply getNewAddress(const std::string&, unsigned);
   BridgeReply getChangeAddress(const std::string&, unsigned);
   BridgeReply peekChangeAddress(const std::string&, unsigned);
   void extendAddressPool(const std::string&, unsigned, unsigned);
   std::string createWallet(const ::Codec_ClientProto::ClientCommand&);
   void createBackupStringForWallet(const std::string&, unsigned);
   void restoreWallet(const BinaryDataRef&, 
      std::shared_ptr<MethodCallbacksHandler>);

   //ledgers
   const std::string& getLedgerDelegateIdForWallets(void);
   void getHistoryPageForDelegate(const std::string&, unsigned, unsigned);
   void createAddressBook(const std::string&, unsigned);

   //txs & headers
   void getTxByHash(const BinaryData&, unsigned);
   void getHeaderByHeight(unsigned, unsigned);

   //utxos
   void getUtxosForValue(const std::string&, uint64_t, unsigned);
   void getSpendableZCList(const std::string&, unsigned);
   void getRBFTxOutList(const std::string&, unsigned);

   //coin selection
   void setupNewCoinSelectionInstance(const std::string&, unsigned, unsigned);
   void destroyCoinSelectionInstance(const std::string&);
   void resetCoinSelection(const std::string&);
   bool setCoinSelectionRecipient(
      const std::string&, const std::string&, uint64_t, unsigned);
   bool cs_SelectUTXOs(const std::string&, uint64_t, float, unsigned);
   BridgeReply cs_getUtxoSelection(const std::string&);
   BridgeReply cs_getFlatFee(const std::string&);   
   BridgeReply cs_getFeeByte(const std::string&);   
   bool cs_ProcessCustomUtxoList(const ::Codec_ClientProto::ClientCommand&);

   //signer
   BridgeReply initNewSigner(void);
   void destroySigner(const std::string&);
   bool signer_SetVersion(const std::string&, unsigned);
   bool signer_SetLockTime(const std::string&, unsigned);
   
   bool signer_addSpenderByOutpoint(
      const std::string&, const BinaryDataRef&, unsigned, unsigned);
   bool signer_populateUtxo(
      const std::string&, const BinaryDataRef&, unsigned, uint64_t, 
      const BinaryDataRef&);

   bool signer_addRecipient(
      const std::string&, const BinaryDataRef&, uint64_t);
   BridgeReply signer_getSerializedState(const std::string&) const;
   bool signer_unserializeState(const std::string&, const BinaryData&);
   void signer_signTx(const std::string&, const std::string&, unsigned);
   BridgeReply signer_getSignedTx(const std::string&) const;
   BridgeReply signer_getSignedStateForInput(const std::string&, unsigned);
   BridgeReply signer_resolve(const std::string&, const std::string&) const;

   //utils
   BridgeReply getTxInScriptType(const BinaryData&, const BinaryData&) const;
   BridgeReply getTxOutScriptType(const BinaryData&) const;
   BridgeReply getScrAddrForScript(const BinaryData&) const;  
   BridgeReply getLastPushDataInScript(const BinaryData&) const;
   BridgeReply getHash160(const BinaryDataRef&) const;
   void broadcastTx(const std::vector<BinaryData>&);
   BridgeReply getTxOutScriptForScrAddr(const BinaryData&) const;  
   BridgeReply getAddrStrForScrAddr(const BinaryData&) const;  
   void getBlockTimeByHeight(uint32_t, uint32_t) const;
         
   //passphrase prompt
   PassphraseLambda createPassphrasePrompt(::Codec_ClientProto::UnlockPromptType);
   bool returnPassphrase(const std::string&, const std::string&);

public:
   CppBridge(const std::string&, const std::string&, 
      const std::string&, bool, bool);

   bool processData(std::vector<uint8_t> socketData);
   void writeToClient(BridgeReply msgPtr, unsigned id) const;
   
   void setWriteLambda(
      std::function<void(std::unique_ptr<WritePayload_Bridge>)> lbd)
   {
      writeLambda_ = lbd;
   }

   void startThreads(void);
   void stopThreads(void);
};

////
class CppBridgeSocket : public PersistentSocket
{
private:
   std::shared_ptr<CppBridge> bridgePtr_;

public:
   CppBridgeSocket(
      const std::string& addr, const std::string& port,
      std::shared_ptr<CppBridge> bridgePtr) :
      PersistentSocket(addr, port), bridgePtr_(bridgePtr)
   {}

   SocketType type(void) const override { return SocketBitcoinP2P; }
   void respond(std::vector<uint8_t>& data) override;
   void pushPayload(
      std::unique_ptr<Socket_WritePayload>,
      std::shared_ptr<Socket_ReadPayload>) override;
};

#endif