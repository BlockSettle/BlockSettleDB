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
   std::shared_ptr<ArmoryThreading::BlockingQueue<
      std::unique_ptr<WritePayload_Bridge>>> writeQueue_;

   std::set<BinaryData> ids_;

public:
   BridgePassphrasePrompt(const std::string id,
   std::shared_ptr<ArmoryThreading::BlockingQueue<
      std::unique_ptr<WritePayload_Bridge>>> queuePtr) :
      id_(id), writeQueue_(queuePtr)
   {}

   PassphraseLambda getLambda(::Codec_ClientProto::BridgePromptType);
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

   void disconnected(void) override
   {}

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
   Signer signer_;
   std::unique_ptr<TxEvalState> signState_;
};

////
class CppBridge
{
private:
   const std::string path_;
   const std::string port_;

   const std::string dbAddr_;
   const std::string dbPort_;

   std::unique_ptr<SimpleSocket> sockPtr_;
   std::shared_ptr<WalletManager> wltManager_;
   std::shared_ptr<AsyncClient::BlockDataViewer> bdvPtr_;

   std::shared_ptr<BridgeCallback> callbackPtr_;

   std::thread writeThr_;
   std::shared_ptr<ArmoryThreading::BlockingQueue<
      std::unique_ptr<WritePayload_Bridge>>> writeQueue_;

   std::map<std::string, AsyncClient::LedgerDelegate> delegateMap_;
   std::map<std::string, std::shared_ptr<CoinSelectionInstance>> csMap_;
   std::map<std::string, std::shared_ptr<CppBridgeSignerStruct>> signerMap_;

   PRNG_Fortuna fortuna_;

   std::mutex passPromptMutex_;
   std::map<std::string, std::shared_ptr<BridgePassphrasePrompt>> promptMap_;

private:
   //write to socket thread
   void writeThread(void);

   //wallet setup
   void loadWallets(unsigned id);
   std::unique_ptr<::google::protobuf::Message> createWalletPacket(void);
   
   //AsyncClient::BlockDataViewer setup
   void setupDB(void);
   void registerWallets(void);
   std::unique_ptr<::google::protobuf::Message> getNodeStatus(void);

   //balance and counts
   std::unique_ptr<::google::protobuf::Message> getBalanceAndCount(
      const std::string&);
   std::unique_ptr<::google::protobuf::Message> getAddrCombinedList(
      const std::string&);
   std::unique_ptr<::google::protobuf::Message> getHighestUsedIndex(
      const std::string&);

   //addresses
   std::unique_ptr<::google::protobuf::Message> getNewAddress(
      const std::string&, unsigned);
   std::unique_ptr<::google::protobuf::Message> getChangeAddress(
      const std::string&, unsigned);
   std::unique_ptr<::google::protobuf::Message> peekChangeAddress(
      const std::string&, unsigned);
   void extendAddressPool(const std::string&, unsigned, unsigned);


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
   std::unique_ptr<::google::protobuf::Message> cs_getUtxoSelection(
      const std::string&);
   std::unique_ptr<::google::protobuf::Message> cs_getFlatFee(
      const std::string&);   
   std::unique_ptr<::google::protobuf::Message> cs_getFeeByte(
      const std::string&);   
   bool cs_ProcessCustomUtxoList(const ::Codec_ClientProto::ClientCommand&);

   //signer
   std::unique_ptr<::google::protobuf::Message> initNewSigner(void);
   void destroySigner(const std::string&);
   bool signer_SetVersion(const std::string&, unsigned);
   bool signer_SetLockTime(const std::string&, unsigned);
   
   bool signer_addSpenderByOutpoint(
      const std::string&, const BinaryDataRef&, unsigned, unsigned, 
      uint64_t);
   bool signer_populateUtxo(
      const std::string&, const BinaryDataRef&, unsigned, uint64_t, 
      const BinaryDataRef&);

   bool signer_addRecipient(
      const std::string&, const BinaryDataRef&, uint64_t);
   std::unique_ptr<::google::protobuf::Message> 
      signer_getSerializedState(const std::string&) const;
   bool signer_unserializeState(const std::string&, const BinaryData&);
   void signer_signTx(const std::string&, const std::string&, unsigned);
   std::unique_ptr<::google::protobuf::Message>
      signer_getSignedTx(const std::string&) const;
   std::unique_ptr<::google::protobuf::Message>
      signer_getSignedStateForInput(const std::string&, unsigned);

   //utils
   std::unique_ptr<::google::protobuf::Message> getTxInScriptType(
      const BinaryData&, const BinaryData&) const;
   std::unique_ptr<::google::protobuf::Message> getTxOutScriptType(
      const BinaryData&) const;
   std::unique_ptr<::google::protobuf::Message> getScrAddrForScript(
      const BinaryData&) const;  
   std::unique_ptr<::google::protobuf::Message> getLastPushDataInScript(
      const BinaryData&) const;
   std::unique_ptr<::google::protobuf::Message> getHash160(
      const BinaryDataRef&) const;
   void broadcastTx(const BinaryDataRef&);
   std::unique_ptr<::google::protobuf::Message> getTxOutScriptForScrAddr(
      const BinaryData&) const;  

   //passphrase prompt
   PassphraseLambda createPassphrasePrompt(::Codec_ClientProto::BridgePromptType);
   bool returnPassphrase(const std::string&, const std::string&);

public:
   CppBridge(const std::string& path, const std::string& port,
      const std::string& dbAddr, const std::string& dbPort) :
      path_(path), port_(port), dbAddr_(dbAddr), dbPort_(dbPort)
   {}

   void commandLoop(void);
   void writeToClient(std::unique_ptr<::google::protobuf::Message> msgPtr, unsigned id);
};

#endif