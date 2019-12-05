////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                                                                            //
//  Copyright (C) 2016-17, goatpig                                            //            
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                   
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <limits.h>
#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <thread>
#include "gtest.h"
#include "btc/ecc.h"

#include "../log.h"
#include "../BinaryData.h"
#include "../BtcUtils.h"
#include "../BlockObj.h"
#include "../StoredBlockObj.h"
#include "../PartialMerkle.h"
#include "../EncryptionUtils.h"
#include "../lmdb_wrapper.h"
#include "../BlockUtils.h"
#include "../ScrAddrObj.h"
#include "../BtcWallet.h"
#include "../BlockDataViewer.h"

#ifndef LIBBTC_ONLY
#include "../cryptopp/DetSign.h"
#include "../cryptopp/integer.h"
#endif

#include "../Progress.h"
#include "../reorgTest/blkdata.h"
#include "../BDM_Server.h"
#include "../TxClasses.h"
#include "../txio.h"
#include "../bdmenums.h"
#include "../SwigClient.h"
#include "../Script.h"
#include "../Signer.h"
#include "../Wallets.h"
#include "../WalletManager.h"
#include "../BIP32_Node.h"
#include "../BitcoinP2p.h"
#include "btc/ecc.h"

#include "NodeUnitTest.h"

#ifdef _MSC_VER
#ifdef mlock
#undef mlock
#undef munlock
#endif
#include "win32_posix.h"
#undef close

#ifdef _DEBUG
//#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#ifndef DBG_NEW
#define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
#define new DBG_NEW
#endif
#endif
#endif

#define READHEX BinaryData::CreateFromHex

#if ! defined(_MSC_VER) && ! defined(__MINGW32__)
   void mkdir(std::string newdir);
#endif

namespace TestUtils
{
   // This function assumes src to be a zero terminated sanitized string with
   // an even number of [0-9a-f] characters, and target to be sufficiently large
   void hex2bin(const char* src, unsigned char* target);

   int char2int(char input);

   bool searchFile(const std::string& filename, BinaryData& data);
   uint32_t getTopBlockHeightInDB(BlockDataManager &bdm, DB_SELECT db);
   uint64_t getDBBalanceForHash160(
      BlockDataManager &bdm, BinaryDataRef addr160);

   void concatFile(const std::string &from, const std::string &to);
   void appendBlocks(const std::vector<std::string> &files, const std::string &to);
   void setBlocks(const std::vector<std::string> &files, const std::string &to);
   void nullProgress(unsigned, double, unsigned, unsigned);
   BinaryData getTx(unsigned height, unsigned id);
}

namespace DBTestUtils
{
   unsigned getTopBlockHeight(LMDBBlockDatabase*, DB_SELECT);
   BinaryData getTopBlockHash(LMDBBlockDatabase*, DB_SELECT);

   std::string registerBDV(Clients* clients, const BinaryData& magic_word);
   void goOnline(Clients* clients, const std::string& id);
   const std::shared_ptr<BDV_Server_Object> getBDV(Clients* clients, const std::string& id);
   
   void registerWallet(Clients* clients, const std::string& bdvId,
      const std::vector<BinaryData>& scrAddrs, const std::string& wltName);
   void regLockbox(Clients* clients, const std::string& bdvId,
      const std::vector<BinaryData>& scrAddrs, const std::string& wltName);

   std::vector<uint64_t> getBalanceAndCount(Clients* clients,
      const std::string& bdvId, const std::string& walletId, unsigned blockheight);
   std::string getLedgerDelegate(Clients* clients, const std::string& bdvId);
   std::vector<::ClientClasses::LedgerEntry> getHistoryPage(
      Clients* clients, const std::string& bdvId,
      const std::string& delegateId, uint32_t pageId);

   std::tuple<std::shared_ptr<::Codec_BDVCommand::BDVCallback>, unsigned> waitOnSignal(
      Clients* clients, const std::string& bdvId,
      ::Codec_BDVCommand::NotificationType signal);
   void waitOnBDMReady(Clients* clients, const std::string& bdvId);

   std::tuple<std::shared_ptr<::Codec_BDVCommand::BDVCallback>, unsigned> 
      waitOnNewBlockSignal(Clients* clients, const std::string& bdvId);
   std::pair<std::vector<::ClientClasses::LedgerEntry>, std::set<BinaryData>>
      waitOnNewZcSignal(Clients* clients, const std::string& bdvId);
   void waitOnWalletRefresh(Clients* clients, const std::string& bdvId,
      const BinaryData& wltId);
   void triggerNewBlockNotification(BlockDataManagerThread* bdmt);
   void mineNewBlock(BlockDataManagerThread* bdmt, const BinaryData& h160,
      unsigned count);

   struct ZcVector
   {
      std::vector<std::pair<Tx, unsigned>> zcVec_;

      void push_back(BinaryData rawZc, unsigned zcTime, unsigned blocksToMine = 0)
      {
         Tx zctx(rawZc);
         zctx.setTxTime(zcTime);

         zcVec_.push_back(std::move(std::make_pair(zctx, blocksToMine)));
      }
   };

   void pushNewZc(BlockDataManagerThread* bdmt, const ZcVector& zcVec, bool stage = false);
   std::pair<BinaryData, BinaryData> getAddrAndPubKeyFromPrivKey(BinaryData privKey);

   Tx getTxByHash(Clients* clients, const std::string bdvId,
      const BinaryData& txHash);
   std::vector<UTXO> getUtxoForAddress(Clients* clients, const std::string bdvId, 
      const BinaryData& addr, bool withZc);

   void addTxioToSsh(StoredScriptHistory&, const std::map<BinaryData, std::shared_ptr<TxIOPair>>&);
   void prettyPrintSsh(StoredScriptHistory& ssh);
   LedgerEntry getLedgerEntryFromWallet(std::shared_ptr<BtcWallet>, const BinaryData&);
   LedgerEntry getLedgerEntryFromAddr(ScrAddrObj*, const BinaryData&);

   void updateWalletsLedgerFilter(
      Clients*, const std::string&, const std::vector<BinaryData>&);

   std::shared_ptr<::google::protobuf::Message> processCommand(
      Clients* clients, std::shared_ptr<::google::protobuf::Message>);

   /////////////////////////////////////////////////////////////////////////////
   std::vector<UnitTestBlock> getMinedBlocks(BlockDataManagerThread*);
   void setReorgBranchingPoint(BlockDataManagerThread*, const BinaryData&);

   /////////////////////////////////////////////////////////////////////////////
   class UTCallback : public RemoteCallback
   {
      struct BdmNotif
      {
         BDMAction action_;
         std::vector<BinaryData> idVec_;
         std::set<BinaryData> addrSet_;
         unsigned reorgHeight_ = UINT32_MAX;
      };

   private:
      BlockingQueue<std::unique_ptr<BdmNotif>> actionStack_;

   public:
      UTCallback() : RemoteCallback()
      {}

      void run(BdmNotification bdmNotif)
      {
         auto notif = make_unique<BdmNotif>();
         notif->action_ = bdmNotif.action_;

         if (bdmNotif.action_ == BDMAction_Refresh)
         {
            notif->idVec_ = bdmNotif.ids_;
         }
         else if (bdmNotif.action_ == BDMAction_ZC)
         {
            for (auto& le : bdmNotif.ledgers_)
            {
               notif->idVec_.push_back(le->getTxHash());

               auto addrVec = le->getScrAddrList();
               for (auto& addrRef : addrVec)
                  notif->addrSet_.insert(addrRef);
            }
         }
         else if (bdmNotif.action_ == BDMAction_NewBlock)
         {
            notif->reorgHeight_ = bdmNotif.branchHeight_;
         }

         actionStack_.push_back(move(notif));
      }

      void progress(BDMPhase, const std::vector<std::string> &,
         float ,unsigned , unsigned)
      {}

      void disconnected()
      {}

      unsigned waitOnReorg(void)
      {
         while (1)
         {
            auto&& action = actionStack_.pop_front();
            if (action->action_ == BDMAction_NewBlock)
            {
               if (action->reorgHeight_ != UINT32_MAX)
                  return action->reorgHeight_;
            }
         }
      }

      void waitOnSignal(BDMAction signal, std::string id = "")
      {
         BinaryDataRef idRef; idRef.setRef(id);
         while (1)
         {
            auto&& action = actionStack_.pop_front();
            if (action->action_ == signal)
            {
               if (id.size() > 0)
               {
                  for (auto& id : action->idVec_)
                  {
                     if (id == idRef)
                        return;
                  }
               }
               else
               {
                  return;
               }
            }
         }
      }

      void waitOnManySignals(BDMAction signal, std::vector<std::string> ids)
      {
         unsigned count = 0;
         std::set<BinaryDataRef> bdrVec;
         for (auto& id : ids)
         {
            BinaryDataRef bdr; bdr.setRef(id);
            bdrVec.insert(bdr);
         }

         while (1)
         {
            if (count >= ids.size())
               break;

            auto&& action = actionStack_.pop_front();
            if (action->action_ == signal)
            {
               for (auto& id : action->idVec_)
               {
                  if (bdrVec.find(id) != bdrVec.end())
                     ++count;
               }
            }         
         }
      }

      void waitOnZc(
         const std::set<BinaryData>& hashes, 
         std::set<BinaryData> scrAddrSet)
      {
         while (1)
         {
            auto&& action = actionStack_.pop_front();
            if (action->action_ != BDMAction_ZC)
               continue;

            bool hasHashes = true;
            for (auto& txHash : action->idVec_)
            {
               if (hashes.find(txHash) == hashes.end())
               {
                  hasHashes = false;
                  break;
               }
            }

            if (!hasHashes)
               continue;

            if (action->addrSet_ == scrAddrSet)
               break;
         }
      }
   };
}

namespace ResolverUtils
{
   ////////////////////////////////////////////////////////////////////////////////
   struct TestResolverFeed : public ResolverFeed
   {
      std::map<BinaryData, BinaryData> h160ToPubKey_;
      std::map<BinaryData, SecureBinaryData> pubKeyToPrivKey_;

      BinaryData getByVal(const BinaryData& val)
      {
         auto iter = h160ToPubKey_.find(val);
         if (iter == h160ToPubKey_.end())
            throw std::runtime_error("invalid value");

         return iter->second;
      }

      const SecureBinaryData& getPrivKeyForPubkey(const BinaryData& pubkey)
      {
         auto iter = pubKeyToPrivKey_.find(pubkey);
         if (iter == pubKeyToPrivKey_.end())
            throw std::runtime_error("invalid pubkey");

         return iter->second;
      }
   };

   ////////////////////////////////////////////////////////////////////////////////
   class HybridFeed : public ResolverFeed
   {
   private:
      std::shared_ptr<ResolverFeed_AssetWalletSingle> feedPtr_;

   public:
      TestResolverFeed testFeed_;

   public:
      HybridFeed(std::shared_ptr<AssetWallet_Single> wltPtr)
      {
         feedPtr_ = std::make_shared<ResolverFeed_AssetWalletSingle>(wltPtr);
      }

      BinaryData getByVal(const BinaryData& val)
      {
         try
         {
            return testFeed_.getByVal(val);
         }
         catch (std::runtime_error&)
         {
         }

         return feedPtr_->getByVal(val);
      }

      const SecureBinaryData& getPrivKeyForPubkey(const BinaryData& pubkey)
      {
         try
         {
            return testFeed_.getPrivKeyForPubkey(pubkey);
         }
         catch (std::runtime_error&)
         {
         }

         return feedPtr_->getPrivKeyForPubkey(pubkey);
      }
   };

   /////////////////////////////////////////////////////////////////////////////
   struct CustomFeed : public ResolverFeed
   {
      std::map<BinaryDataRef, BinaryDataRef> hash_to_preimage_;
      std::shared_ptr<ResolverFeed> wltFeed_;

   private:
      void addAddressEntry(std::shared_ptr<AddressEntry> addrPtr)
      {
         try
         {
            BinaryDataRef hash(addrPtr->getHash());
            BinaryDataRef preimage(addrPtr->getPreimage());
            hash_to_preimage_.insert(std::make_pair(hash, preimage));
         }
         catch (std::exception)
         {
            return;
         }

         auto addr_nested = std::dynamic_pointer_cast<AddressEntry_Nested>(addrPtr);
         if (addr_nested != nullptr)
            addAddressEntry(addr_nested->getPredecessor());
      }

   public:
      CustomFeed(std::shared_ptr<AddressEntry> addrPtr,
         std::shared_ptr<AssetWallet_Single> wlt) :
         wltFeed_(std::make_shared<ResolverFeed_AssetWalletSingle>(wlt))
      {
         addAddressEntry(addrPtr);
      }

      CustomFeed(std::shared_ptr<AddressEntry> addrPtr,
         std::shared_ptr<ResolverFeed> feed) :
         wltFeed_(feed)
      {
         addAddressEntry(addrPtr);
      }

      BinaryData getByVal(const BinaryData& key)
      {
         auto keyRef = BinaryDataRef(key);
         auto iter = hash_to_preimage_.find(keyRef);
         if (iter == hash_to_preimage_.end())
            throw std::runtime_error("invalid value");

         return iter->second;
      }

      const SecureBinaryData& getPrivKeyForPubkey(const BinaryData& pubkey)
      {
         return wltFeed_->getPrivKeyForPubkey(pubkey);
      }
   };
}

#endif
