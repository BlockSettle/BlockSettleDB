////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018-2021, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

/***
Handle codec and socketing for armory client
***/

#ifndef _ASYNCCLIENT_H
#define _ASYNCCLIENT_H

#include <thread>

#include "StringSockets.h"
#include "bdmenums.h"
#include "log.h"
#include "TxClasses.h"
#include "ArmoryConfig.h"
#include "WebSocketClient.h"
#include "DBClientClasses.h"
#include "SocketWritePayload.h"
#include "Wallets/PassphraseLambda.h"

class WalletManager;
class WalletContainer;

///////////////////////////////////////////////////////////////////////////////
struct OutpointData
{
   BinaryData txHash_;
   unsigned txOutIndex_;
   
   unsigned txHeight_ = UINT32_MAX;
   unsigned txIndex_ = UINT32_MAX;

   uint64_t value_;
   bool isSpent_;

   BinaryData spenderHash_;

   //debug
   void prettyPrint(std::ostream&) const;
};

////
struct OutpointBatch
{
   unsigned heightCutoff_;
   unsigned zcIndexCutoff_;

   std::map<BinaryData, std::vector<OutpointData>> outpoints_;

   //debug
   void prettyPrint(void) const;
};

///////////////////////////////////////////////////////////////////////////////
class ClientMessageError : public std::runtime_error
{
private:
   int errorCode_ = 0;

public:
   ClientMessageError(const std::string& err, unsigned errCode) :
      std::runtime_error(err), errorCode_(errCode)
   {}

   int errorCode(void) const { return errorCode_; }
};

///////////////////////////////////////////////////////////////////////////////
template<class U> class ReturnMessage
{
private:
   U value_;
   std::shared_ptr<ClientMessageError> error_;

public:
   ReturnMessage(void) :
      value_(U())
   {}

   ReturnMessage(U& val) :
      value_(std::move(val))
   {}

   ReturnMessage(const U& val) :
      value_(val)
   {}

   ReturnMessage(ClientMessageError& err)
   {
      error_ = std::make_shared<ClientMessageError>(err);
   }

   U get(void)
   { 
      if (error_ != nullptr)
         throw *error_;

      return std::move(value_);
   }
};

///////////////////////////////////////////////////////////////////////////////
struct CombinedBalances
{
   BinaryData walletId_;
      
   /*
   {
      fullBalance,
      spendableBalance,
      unconfirmedBalance,
      wltTxnCount
   }
   */
   std::vector<uint64_t> walletBalanceAndCount_;

   /*
   {
      scrAddr (prefixed):
         {
            fullBalance,
            spendableBalance,
            unconfirmedBalance
         }
   }
   */

   std::map<BinaryData, std::vector<uint64_t>> addressBalances_;

   bool operator<(const CombinedBalances& rhs) const
   {
      return walletId_ < rhs.walletId_;
   }

   bool operator<(const BinaryData& rhs) const
   {
      return walletId_ < rhs;
   }
};

///////////////////////////////////////////////////////////////////////////////
struct CombinedCounts
{
   BinaryData walletId_;
      
   /*
   {
      scrAddr (prefixed): txn count
   }
   */
      
   std::map<BinaryData, uint64_t> addressTxnCounts_;

   bool operator<(const CombinedCounts& rhs) const
   {
      return walletId_ < rhs.walletId_;
   }
};

///////////////////////////////////////////////////////////////////////////////
namespace AsyncClient
{
   ///////////////////////////////////////////////////////////////////////////////
   class ClientCache : public Lockable
   {
      friend struct CallbackReturn_Tx;
      friend struct CallbackReturn_TxBatch;
      
   private:
      std::map<BinaryData, std::shared_ptr<Tx>> txMap_;
      std::map<unsigned, BinaryData> rawHeaderMap_;
      std::map<BinaryData, unsigned> txHashToHeightMap_;

   private:
      std::shared_ptr<Tx> getTx_NoConst(const BinaryDataRef&);
      void insertTx(const BinaryData&, std::shared_ptr<Tx>);

   public:
      void insertTx(std::shared_ptr<Tx>);
      void insertRawHeader(unsigned&, BinaryDataRef);
      void insertHeightForTxHash(BinaryData&, unsigned&);

      std::shared_ptr<const Tx> getTx(const BinaryDataRef&) const;
      const BinaryData& getRawHeader(const unsigned&) const;
      const unsigned& getHeightForTxHash(const BinaryData&) const;

      //virtuals
      void initAfterLock(void) {}
      void cleanUpBeforeUnlock(void) {}
   };

   class NoMatch
   {};

   ///////////////////////////////////////////////////////////////////////////////
   typedef std::shared_ptr<const Tx> TxResult;
   typedef std::function<void(ReturnMessage<TxResult>)> TxCallback;

   typedef std::map<BinaryData, TxResult> TxBatchResult;
   typedef std::function<void(ReturnMessage<TxBatchResult>)> TxBatchCallback; 

   class BlockDataViewer;

   /////////////////////////////////////////////////////////////////////////////
   class LedgerDelegate
   {
   private:
      std::string delegateID_;
      std::string bdvID_;
      std::shared_ptr<SocketPrototype> sock_;

   public:
      LedgerDelegate(void) {}

      LedgerDelegate(std::shared_ptr<SocketPrototype>, 
         const std::string&, const std::string&);

      void getHistoryPage(uint32_t id, 
         std::function<void(ReturnMessage<std::vector<DBClientClasses::LedgerEntry>>)>);
      void getPageCount(std::function<void(ReturnMessage<uint64_t>)>) const;

      const std::string& getID(void) const { return delegateID_; }
   };

   class BtcWallet;

   /////////////////////////////////////////////////////////////////////////////
   class ScrAddrObj
   {
      friend class ::WalletContainer;

   private:
      const std::string bdvID_;
      const std::string walletID_;
      const BinaryData scrAddr_;
      const std::shared_ptr<SocketPrototype> sock_;

      const uint64_t fullBalance_;
      const uint64_t spendableBalance_;
      const uint64_t unconfirmedBalance_;
      const uint32_t count_;
      const int index_;

      std::string comment_;

   private:
      ScrAddrObj(const BinaryData& scrAddr, int index) :
         bdvID_(std::string()), walletID_(std::string()),
         scrAddr_(scrAddr),
         sock_(nullptr), 
         fullBalance_(0), spendableBalance_(0), unconfirmedBalance_(0),
         count_(0), index_(index)
      {}

   public:
      ScrAddrObj(BtcWallet*, const BinaryData&, int index,
         uint64_t, uint64_t, uint64_t, uint32_t);
      ScrAddrObj(std::shared_ptr<SocketPrototype>,
         const std::string&, const std::string&, const BinaryData&, int index,
         uint64_t, uint64_t, uint64_t, uint32_t);

      uint64_t getFullBalance(void) const { return fullBalance_; }
      uint64_t getSpendableBalance(void) const { return spendableBalance_; }
      uint64_t getUnconfirmedBalance(void) const { return unconfirmedBalance_; }

      uint64_t getTxioCount(void) const { return count_; }

      void getSpendableTxOutList(std::function<void(ReturnMessage<std::vector<UTXO>>)>);
      const BinaryData& getScrAddr(void) const { return scrAddr_; }

      void setComment(const std::string& comment) { comment_ = comment; }
      const std::string& getComment(void) const { return comment_; }
      int getIndex(void) const { return index_; }
   };

   /////////////////////////////////////////////////////////////////////////////
   class BtcWallet
   {
      friend class ScrAddrObj;

   protected:
      const std::string walletID_;
      const std::string bdvID_;
      const std::shared_ptr<SocketPrototype> sock_;

   public:
      BtcWallet(const BlockDataViewer&, const std::string&);
      
      void getBalancesAndCount(uint32_t topBlockHeight,
         std::function<void(ReturnMessage<std::vector<uint64_t>>)>);

      void getSpendableTxOutListForValue(uint64_t val, 
         std::function<void(ReturnMessage<std::vector<UTXO>>)>);
      void getSpendableZCList(std::function<void(ReturnMessage<std::vector<UTXO>>)>);
      void getRBFTxOutList(std::function<void(ReturnMessage<std::vector<UTXO>>)>);

      void getAddrTxnCountsFromDB(std::function<void(
         ReturnMessage<std::map<BinaryData, uint32_t>>)>);
      void getAddrBalancesFromDB(std::function<void(
         ReturnMessage<std::map<BinaryData, std::vector<uint64_t>>>)>);

      void getHistoryPage(uint32_t id, 
         std::function<void(ReturnMessage<std::vector<DBClientClasses::LedgerEntry>>)>);
      void getLedgerEntryForTxHash(
         const BinaryData& txhash, 
         std::function<void(ReturnMessage<std::shared_ptr<DBClientClasses::LedgerEntry>>)>);

      ScrAddrObj getScrAddrObjByKey(const BinaryData&,
         uint64_t, uint64_t, uint64_t, uint32_t);

      virtual std::string registerAddresses(
         const std::vector<BinaryData>& addrVec, bool isNew);
      std::string unregisterAddresses(const std::set<BinaryData>&);
      std::string unregister(void);

      void createAddressBook(
         std::function<void(ReturnMessage<std::vector<AddressBookEntry>>)>) const;

      std::string setUnconfirmedTarget(unsigned);
      std::string walletID(void) const { return walletID_; }
   };

   /////////////////////////////////////////////////////////////////////////////
   class Lockbox : public BtcWallet
   {
   private:
      uint64_t fullBalance_ = 0;
      uint64_t spendableBalance_ = 0;
      uint64_t unconfirmedBalance_ = 0;

      uint64_t txnCount_ = 0;

   public:

      Lockbox(const BlockDataViewer& bdv, const std::string& id) :
         BtcWallet(bdv, id)
      {}

      void getBalancesAndCountFromDB(uint32_t topBlockHeight);

      uint64_t getFullBalance(void) const { return fullBalance_; }
      uint64_t getSpendableBalance(void) const { return spendableBalance_; }
      uint64_t getUnconfirmedBalance(void) const { return unconfirmedBalance_; }
      uint64_t getWltTotalTxnCount(void) const { return txnCount_; }
 
      std::string registerAddresses(
         const std::vector<BinaryData>& addrVec, bool isNew);
   };

   /////////////////////////////////////////////////////////////////////////////
   class Blockchain
   {
   private:
      const std::shared_ptr<SocketPrototype> sock_;
      const std::string bdvID_;

   public:
      Blockchain(const BlockDataViewer&);
      void getHeaderByHash(const BinaryData& hash, 
         std::function<void(ReturnMessage<DBClientClasses::BlockHeader>)>);
      void getHeaderByHeight(
         unsigned height, 
         std::function<void(ReturnMessage<DBClientClasses::BlockHeader>)>);
   };

   /////////////////////////////////////////////////////////////////////////////
   class BlockDataViewer
   {
      friend class ScrAddrObj;
      friend class BtcWallet;
      friend class RemoteCallback;
      friend class LedgerDelegate;
      friend class Blockchain;
      friend class ::WalletManager;

   private:
      std::string bdvID_;
      std::shared_ptr<SocketPrototype> sock_;
      std::shared_ptr<ClientCache> cache_;

   private:
      BlockDataViewer(void);
      BlockDataViewer(std::shared_ptr<SocketPrototype> sock);
      bool isValid(void) const { return sock_ != nullptr; }

      const BlockDataViewer& operator=(const BlockDataViewer& rhs)
      {
         bdvID_ = rhs.bdvID_;
         sock_ = rhs.sock_;
         cache_ = rhs.cache_;

         return *this;
      }

   public:
      ~BlockDataViewer(void);

      //utility
      static std::unique_ptr<WritePayload_Protobuf> make_payload(
         ::Codec_BDVCommand::Methods);
      static std::unique_ptr<WritePayload_Protobuf> make_payload(
         ::Codec_BDVCommand::StaticMethods);
      
      BtcWallet instantiateWallet(const std::string& id);
      Lockbox instantiateLockbox(const std::string& id);

      //BIP15x
      std::pair<unsigned, unsigned> getRekeyCount(void) const;
      void setCheckServerKeyPromptLambda(
         std::function<bool(const BinaryData&, const std::string&)>);
      void addPublicKey(const SecureBinaryData&);

      //connectivity
      bool connectToRemote(void);
      std::shared_ptr<SocketPrototype> getSocketObject(void) const { return sock_; }
      void goOnline(void);
      bool hasRemoteDB(void);

      //setup
      const std::string& getID(void) const { return bdvID_; }
      static std::shared_ptr<BlockDataViewer> getNewBDV(
         const std::string& addr, const std::string& port,
         const std::string& datadir, const PassphraseLambda&,
         const bool& ephemeralPeers, bool oneWayAuth,
         std::shared_ptr<RemoteCallback> callbackPtr);

      void registerWithDB(BinaryData magic_word);
      void unregisterFromDB(void);
      void shutdown(const std::string&);
      void shutdownNode(const std::string&);

      //ledgers
      void getLedgerDelegateForWallets(
         std::function<void(ReturnMessage<LedgerDelegate>)>);
      void getLedgerDelegateForLockboxes(
         std::function<void(ReturnMessage<LedgerDelegate>)>);
      void getLedgerDelegateForScrAddr(
         const std::string&, BinaryDataRef,
         std::function<void(ReturnMessage<LedgerDelegate>)>);

      void getHistoryForWalletSelection(
         const std::vector<std::string>&, const std::string& orderingStr,
         std::function<void(ReturnMessage<std::vector<DBClientClasses::LedgerEntry>>)>);

      void updateWalletsLedgerFilter(const std::vector<BinaryData>& wltIdVec);

      //header data
      Blockchain blockchain(void);

      void getRawHeaderForTxHash(
         const BinaryData& txHash, 
         std::function<void(ReturnMessage<BinaryData>)>);
      void getHeaderByHeight(
         unsigned height, 
         std::function<void(ReturnMessage<BinaryData>)>);

      //node & fee
      void getNodeStatus(
         std::function<void(ReturnMessage<std::shared_ptr<DBClientClasses::NodeStatus>>)>);
      void estimateFee(unsigned, const std::string&,
         std::function<void(ReturnMessage<DBClientClasses::FeeEstimateStruct>)>);
      void getFeeSchedule(const std::string&, std::function<void(ReturnMessage<
            std::map<unsigned, DBClientClasses::FeeEstimateStruct>>)>);

      //combined methods
      void getCombinedBalances(
         const std::vector<std::string>&,
         std::function<void(
            ReturnMessage<std::map<std::string, CombinedBalances>>)>);
      
      void getCombinedAddrTxnCounts(
         const std::vector<std::string>&,
         std::function<void(
            ReturnMessage<std::map<std::string, CombinedCounts>>)>);

      void getCombinedSpendableTxOutListForValue(
         const std::vector<std::string>&, uint64_t value,
         std::function<void(ReturnMessage<std::vector<UTXO>>)>);
   
      void getCombinedSpendableZcOutputs(const std::vector<std::string>&, 
         std::function<void(ReturnMessage<std::vector<UTXO>>)>);

      void getCombinedRBFTxOuts(const std::vector<std::string>&, 
         std::function<void(ReturnMessage<std::vector<UTXO>>)>);

      //outputs
      void getOutpointsForAddresses(const std::set<BinaryData>&, 
         unsigned startHeight, unsigned zcIndexCutoff,
         std::function<void(ReturnMessage<OutpointBatch>)>);

      void getUTXOsForAddress(const BinaryData&, bool,
         std::function<void(ReturnMessage<std::vector<UTXO>>)>);

      void getSpentnessForOutputs(const std::map<BinaryData, std::set<unsigned>>&,
         std::function<void(ReturnMessage<std::map<BinaryData, std::map<
         unsigned, SpentnessResult>>>)>);
      void getSpentnessForZcOutputs(const std::map<BinaryData, std::set<unsigned>>&,
         std::function<void(ReturnMessage<std::map<BinaryData, std::map<
         unsigned, SpentnessResult>>>)>);

      void getOutputsForOutpoints(
         const std::map<BinaryData, std::set<unsigned>>&, bool,
         std::function<void(ReturnMessage<std::vector<UTXO>>)>);

      /*
      Broadcast methods:
        All broadcast methods generate and return a random BROADCAST_ID_LENGTH 
        bytes long ID. This ID will be attached to the broadcast notification 
        for the relevant transactions. Notifications for these transaction may
        come with no ID attached, in which case these notifications are not the
        result of your broadcast.
      */
      std::string broadcastZC(const BinaryData& rawTx);
      std::string broadcastZC(const std::vector<BinaryData>& rawTxVec);
      std::string broadcastThroughRPC(const BinaryData& rawTx);

      void getTxByHash(const BinaryData& txHash, const TxCallback&);
      void getTxBatchByHash(
         const std::set<BinaryData>&, const TxBatchCallback&);
   };

   ////////////////////////////////////////////////////////////////////////////
   void deserialize(::google::protobuf::Message*, 
      const WebSocketMessagePartial&);

   ///////////////////////////////////////////////////////////////////////////////
   ///////////////////////////////////////////////////////////////////////////////
   //// callback structs for async networking
   ///////////////////////////////////////////////////////////////////////////////
   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_BinaryDataRef : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(BinaryDataRef)> userCallbackLambda_;

   public:
      CallbackReturn_BinaryDataRef(std::function<void(BinaryDataRef)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_String : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::string>)> userCallbackLambda_;

   public:
      CallbackReturn_String(std::function<void(ReturnMessage<std::string>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_LedgerDelegate : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<AsyncClient::LedgerDelegate>)> userCallbackLambda_;
      std::shared_ptr<SocketPrototype> sockPtr_;
      const std::string& bdvID_;

   public:
      CallbackReturn_LedgerDelegate(
         std::shared_ptr<SocketPrototype> sock, const std::string& bdvid,
         std::function<void(ReturnMessage<AsyncClient::LedgerDelegate>)> lbd) :
         userCallbackLambda_(lbd), sockPtr_(sock), bdvID_(bdvid)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_Tx : public CallbackReturn_WebSocket
   {
   private:
      std::shared_ptr<ClientCache> cache_;
      BinaryData txHash_;
      TxCallback userCallbackLambda_;

   public:
      CallbackReturn_Tx(std::shared_ptr<ClientCache> cache,
         const BinaryData& txHash, const TxCallback& lbd) :
         cache_(cache), txHash_(txHash), userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };


   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_TxBatch : public CallbackReturn_WebSocket
   {
   private:
      std::shared_ptr<ClientCache> cache_;
      TxBatchResult cachedTx_;
      std::map<BinaryData, bool> callMap_;
      TxBatchCallback userCallbackLambda_;

   public:
      CallbackReturn_TxBatch(
         std::shared_ptr<ClientCache> cache, TxBatchResult& cachedTx, 
         std::map<BinaryData, bool>& callMap, const TxBatchCallback& lbd) :
         cache_(cache), cachedTx_(std::move(cachedTx)),
         callMap_(std::move(callMap)),
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_RawHeader : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<BinaryData>)> userCallbackLambda_;
      std::shared_ptr<ClientCache> cache_;
      BinaryData txHash_;
      unsigned height_;

   public:
      CallbackReturn_RawHeader(
         std::shared_ptr<ClientCache> cache,
         unsigned height, const BinaryData& txHash, 
         std::function<void(ReturnMessage<BinaryData>)> lbd) :
         userCallbackLambda_(lbd),
         cache_(cache),txHash_(txHash), height_(height)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   class CallbackReturn_NodeStatus : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::shared_ptr<DBClientClasses::NodeStatus>>)>
         userCallbackLambda_;

   public:
      CallbackReturn_NodeStatus(std::function<void(
         ReturnMessage<std::shared_ptr<DBClientClasses::NodeStatus>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_FeeEstimateStruct : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<DBClientClasses::FeeEstimateStruct>)>
         userCallbackLambda_;

   public:
      CallbackReturn_FeeEstimateStruct(
         std::function<void(ReturnMessage<DBClientClasses::FeeEstimateStruct>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_FeeSchedule : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::map<unsigned, DBClientClasses::FeeEstimateStruct>>)>
         userCallbackLambda_;

   public:
      CallbackReturn_FeeSchedule(std::function<void(ReturnMessage<
         std::map<unsigned, DBClientClasses::FeeEstimateStruct>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_VectorLedgerEntry : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::vector<DBClientClasses::LedgerEntry>>)>
         userCallbackLambda_;

   public:
      CallbackReturn_VectorLedgerEntry(
         std::function<void(ReturnMessage<std::vector<DBClientClasses::LedgerEntry>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_UINT64 : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<uint64_t>)> userCallbackLambda_;

   public:
      CallbackReturn_UINT64(
         std::function<void(ReturnMessage<uint64_t>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_VectorUTXO : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::vector<UTXO>>)> userCallbackLambda_;

   public:
      CallbackReturn_VectorUTXO(
         std::function<void(ReturnMessage<std::vector<UTXO>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_VectorUINT64 : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::vector<uint64_t>>)> userCallbackLambda_;

   public:
      CallbackReturn_VectorUINT64(
         std::function<void(ReturnMessage<std::vector<uint64_t>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_Map_BD_U32 : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::map<BinaryData, uint32_t>>)> userCallbackLambda_;

   public:
      CallbackReturn_Map_BD_U32(
         std::function<void(ReturnMessage<std::map<BinaryData, uint32_t>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_Map_BD_VecU64 : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::map<BinaryData, std::vector<uint64_t>>>)>
         userCallbackLambda_;

   public:
      CallbackReturn_Map_BD_VecU64(
         std::function<void(ReturnMessage<std::map<BinaryData, std::vector<uint64_t>>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_LedgerEntry : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::shared_ptr<DBClientClasses::LedgerEntry>>)>
         userCallbackLambda_;

   public:
      CallbackReturn_LedgerEntry(
         std::function<void(ReturnMessage<std::shared_ptr<DBClientClasses::LedgerEntry>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_VectorAddressBookEntry : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::vector<AddressBookEntry>>)> userCallbackLambda_;

   public:
      CallbackReturn_VectorAddressBookEntry(
         std::function<void(ReturnMessage<std::vector<AddressBookEntry>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_Bool : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<bool>)> userCallbackLambda_;

   public:
      CallbackReturn_Bool(std::function<void(ReturnMessage<bool>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_BlockHeader : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<DBClientClasses::BlockHeader>)> userCallbackLambda_;
      const unsigned height_;

   public:
      CallbackReturn_BlockHeader(unsigned height, 
         std::function<void(ReturnMessage<DBClientClasses::BlockHeader>)> lbd) :
         userCallbackLambda_(lbd), height_(height)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_BDVCallback : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(std::shared_ptr<::Codec_BDVCommand::BDVCallback>)>
         userCallbackLambda_;

   public:
      CallbackReturn_BDVCallback(
         std::function<void(std::shared_ptr<::Codec_BDVCommand::BDVCallback>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_CombinedBalances : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::map<std::string, CombinedBalances>>)> 
         userCallbackLambda_;

   public:
      CallbackReturn_CombinedBalances(
         std::function<void(
            ReturnMessage<std::map<std::string, CombinedBalances>>)> lbd) :
         userCallbackLambda_(lbd)
      {}
      
      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_CombinedCounts : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<std::map<std::string, CombinedCounts>>)> 
         userCallbackLambda_;

   public:
      CallbackReturn_CombinedCounts(
         std::function<void(
            ReturnMessage<std::map<std::string, CombinedCounts>>)> lbd) :
         userCallbackLambda_(lbd)
      {}
      
      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_AddrOutpoints : public CallbackReturn_WebSocket
   {
   private:
      std::function<void(ReturnMessage<OutpointBatch>)>
         userCallbackLambda_;

   public:
      CallbackReturn_AddrOutpoints(
         std::function<void(
            ReturnMessage<OutpointBatch>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };

   ///////////////////////////////////////////////////////////////////////////////
   struct CallbackReturn_SpentnessData : public CallbackReturn_WebSocket
   {
   private:

      std::function<void(
      ReturnMessage<std::map<BinaryData, std::map<
         unsigned, SpentnessResult>>>)>
         userCallbackLambda_;

   public:
      CallbackReturn_SpentnessData(
         std::function<void(ReturnMessage<std::map<BinaryData, std::map<
            unsigned, SpentnessResult>>>)> lbd) :
         userCallbackLambda_(lbd)
      {}

      //virtual
      void callback(const WebSocketMessagePartial&);
   };
};
#endif
