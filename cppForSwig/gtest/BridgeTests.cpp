////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <cstdlib>
#include <queue>

#include "TestUtils.h"
#include <reorgTest/blkdata.h>
#include <Utils/ArmoryConfig.h>
#include <Utils/DBUtils.h>

#include <Wallets/Accounts/AddressAccounts.h>
#include <Wallets/WalletFileInterface.h>
#include <Wallets/Seeds/Seeds.h>
#include <Wallets/AuthorizedPeers.h>

#include <BridgeAPI/CppBridge.h>
#include <BridgeAPI/BridgeSocket.h>
#include <BridgeAPI/ProtoCommandParser.h>
#include <BridgeAPI/Wallets/Manager.h>
#include <BridgeAPI/BlockchainDbClient.h>

#include "BDM_mainthread.h"
#include "Server.h"
#include "WebSocketClient.h"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include "capnp/Bridge.capnp.h"
#include "capnp/Types.capnp.h"

using namespace Armory;

using namespace std::chrono_literals;
using namespace std::string_view_literals;

using MsgPtr = std::unique_ptr<Armory::Bridge::WritePayload_Bridge>;

////////////////////////////////////////////////////////////////////////////////
namespace {
   int CapnWalletState_Legacy = 1;
   int CapnWalletState_Encrypted = 2;
   int CapnWalletState_Ready = 3;

   BinaryData serializeCapnp(capnp::MallocMessageBuilder& msg)
   {
      auto flat = capnp::messageToFlatArray(msg);
      auto bytes = flat.asBytes();
      return BinaryData(bytes.begin(), bytes.end());
   }

   struct WltListEntry
   {
      std::string walletId;
      int loadState;
      bool staged;
      bool isWO;
   };

   struct AddressData
   {
      const int32_t index;
      const BinaryData hash;

      bool operator<(const AddressData& rhs) const
      {
         return hash < rhs.hash;
      }
   };

   struct WalletData
   {
      const std::string walletId;
      const std::string accountId;
      const std::string masterId;
      const std::string dbId;

      const std::string label;
      const std::string desc;

      const bool encrypted;
      const bool watchingOnly;
      const std::set<AddressData> addresses;
      const int64_t lookup;
      const int64_t useCount;

      const std::filesystem::path path;
      const uint32_t kdfMemReq;
   };

   std::filesystem::path fullBinPath;

   AddressData capnToAddressData(const Codec::Bridge::WalletData::AddressData::Reader& capnAddr)
   {
      auto capnHash = capnAddr.getPrefixedHash();
      BinaryData addrHash{capnHash.begin(), capnHash.end()};
      return AddressData{capnAddr.getIndex(), std::move(addrHash)};
   }

   WalletData capnToWalletData(const Codec::Bridge::WalletData::Reader& capnWlt)
   {
      auto capnAddrs = capnWlt.getAddressData();
      std::set<AddressData> addresses;
      for (const auto& capnAddr : capnAddrs) {
         addresses.emplace(capnToAddressData(capnAddr));
      }

      std::string walletId = capnWlt.getWalletId();
      return WalletData{
         walletId, capnWlt.getAccountId(), capnWlt.getMasterId(), capnWlt.getDbId(),
         capnWlt.getLabel(), capnWlt.getDesc(),
         capnWlt.getUsesEncryption(), capnWlt.getWatchingOnly(),
         std::move(addresses), capnWlt.getLookupCount(), capnWlt.getUseCount(),
         std::filesystem::path(std::string{capnWlt.getPath()}), capnWlt.getKdfMemReq()
      };
   }

   std::vector<std::vector<LedgerEntry>> capnToLedgers(
      const capnp::List<Codec::Types::TxLedger, capnp::Kind::STRUCT>::Reader& capnLedgers)
   {
      std::vector<std::vector<LedgerEntry>> result(capnLedgers.size());

      unsigned i=0;
      for (auto txLedgers : capnLedgers) {
         auto& ledgerVec = result[i++];
         for (auto capnLedger : txLedgers.getLedgers()) {
            auto capnHash = capnLedger.getTxHash();
            BinaryData txHash{capnHash.begin(), capnHash.end()};

            LedgerEntry le{std::string{capnLedger.getWalletId()},
               capnLedger.getBalance(), capnLedger.getTxHeight(), txHash,
               capnLedger.getTxOutIndex(), capnLedger.getTxTime(),
               capnLedger.getIsCoinbase(), capnLedger.getIsSTS(), capnLedger.getIsChangeBack(),
               capnLedger.getIsOptInRBF(), capnLedger.getIsWitness(), capnLedger.getIsChainedZC()
            };

            auto capnAddrList = capnLedger.getScrAddrs();
            std::set<BinaryData> addrSet;
            for (auto capnAddr : capnAddrList) {
               addrSet.emplace(BinaryData{capnAddr.begin(), capnAddr.end()});
            }
            if (!addrSet.empty()) {
               le.setScrAddrList(addrSet);
            }
            ledgerVec.emplace_back(std::move(le));
         }
      }
      return result;
   }

   struct NotifQueue
   {
      std::queue<BinaryData> queue;
      std::mutex mu;
      std::condition_variable cv;

      void push_back(BinaryData& data)
      {
         std::unique_lock<std::mutex> lock(mu);
         queue.emplace(std::move(data));
         cv.notify_all();
      }

      BinaryData pop()
      {
         std::unique_lock<std::mutex> lock(mu);
         while (queue.empty()) {
            cv.wait(lock);
         }

         auto data = std::move(queue.front());
         queue.pop();
         return data;
      }
   };

   /////////////////////////////////////////////////////////////////////////////
   std::mutex commsMutex;
   std::deque<MsgPtr> replyQueue;
   std::condition_variable commsCV;

   MsgPtr waitOnReply()
   {
      std::unique_lock<std::mutex> lock(commsMutex);
      while (replyQueue.empty()) {
         commsCV.wait(lock);
      }
      auto result = std::move(replyQueue.front());
      replyQueue.pop_front();
      return result;
   }

   /////////////////////////////////////////////////////////////////////////////
   std::string initWOWallet(const std::filesystem::path& homedir)
   {
      Wallets::IO::CreateWalletParams params{
         homedir, {}, {},
         nullptr, 0
      };

      auto walletId = std::string{"walletWO_" +
         Cryptography::PRNG::fortuna.generateRandom(3).toHexStr()};

      //create empty WO wallet
      auto wltWO = Wallets::AssetWallet_Single::createBlank(
         {std::string_view{walletId}}, params);
      wltWO->setupImportAccount();

      auto pubKeyB = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrB);
      wltWO->importPublicKey(pubKeyB, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));

      auto pubKeyC = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrC);
      wltWO->importPublicKey(pubKeyC, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));

      auto pubKeyD = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrD);
      wltWO->importPublicKey(pubKeyD, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));

      auto pubKeyE = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrE);
      wltWO->importPublicKey(pubKeyE, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));

      return walletId;
   }

   std::string createWallet(const std::filesystem::path& homedir)
   {
      Wallets::IO::CreateWalletParams params{
         homedir,
         {1ms, 0, SecureBinaryData::fromString("privpass1")},
         {},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      return assetWlt->getID();
   }

   /////////////////////////////////////////////////////////////////////////////
   void pushRequest(std::shared_ptr<Bridge::CppBridge> bridge,
      const BinaryData& rawRequest)
   {
      Bridge::ProtoCommandParser::processData(bridge, rawRequest);
   }

   std::map<std::string, WalletData> loadWallets(
      std::shared_ptr<Bridge::CppBridge> bridge)
   {
      auto refId = rand();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWalletManager();
      request.setLoadWallets();

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess() || reply.getReferenceId() != refId) {
         throw std::runtime_error({});
      }

      auto replyMgr = reply.getWalletManager();
      auto replyLoadWlts = replyMgr.getLoadWallets();

      std::map<std::string, WalletData> wltsData;
      for (const auto& capnWlt : replyLoadWlts) {
         wltsData.emplace(capnWlt.getWalletId(), capnToWalletData(capnWlt));
      }
      return wltsData;
   }

   std::map<std::string, WltListEntry> listWallets(
      std::shared_ptr<Bridge::CppBridge> bridge)
   {
      auto refId = rand();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWalletManager();
      request.setListWallets();

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess() || reply.getReferenceId() != refId) {
         throw std::runtime_error({});
      }

      auto replyMgr = reply.getWalletManager();
      auto replyListWlts = replyMgr.getListWallets();

      std::map<std::string, WltListEntry> wltMap;
      for (auto capnEntry : replyListWlts) {
         wltMap.emplace(std::string(capnEntry.getPath()),
            WltListEntry{
               capnEntry.getWalletId(),
               (int)capnEntry.getState(),
               capnEntry.getStaged(),
               capnEntry.getWatchingOnly()}
            );
      }
      return wltMap;
   }

   WalletData getWalletData(
      std::shared_ptr<Bridge::CppBridge> bridge,
      const std::string& walletId)
   {
      auto refId = rand();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(walletId);
      request.setGetData();

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess() || reply.getReferenceId() != refId) {
         throw std::runtime_error({});
      }

      auto replyMgr = reply.getWallet();
      return capnToWalletData(replyMgr.getGetData());
   }

   bool changeWalletPassphrase(
      std::shared_ptr<Bridge::CppBridge> bridge,
      const std::string& walletId,
      const std::string& currentPass, const std::string& newPass)
   {
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();
      auto refId = rand();

      //start passphrase change sequence
      {
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         toBridge.setReferenceId(refId);
         auto request = toBridge.initWallet();
         request.setWalletId(walletId);

         auto passReq = request.initChangePassphrase();
         passReq.setCallbackId(callbackId);
         passReq.setPrivate();

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge, rawReq);
      }

      //wait on passphrase prompt
      {
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            return false;
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            return false;
         }
         if (notif.which() != Codec::Bridge::Notification::UNLOCK_REQUEST) {
            return false;
         }
         auto counter = notif.getCounter();

         //push passphrase
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         auto notifReply = toBridge.initNotification();
         notifReply.setSuccess(true);
         notifReply.setCounter(counter);
         notifReply.setUnlockRequest(currentPass);

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge, rawReq);
      }

      //wait on new passphrase prompt
      {
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            return false;
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            return false;
         }
         if (notif.which() != Codec::Bridge::Notification::SET_PASSPHRASE) {
            return false;
         }
         auto counter = notif.getCounter();

         //push passphrase
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         auto notifReply = toBridge.initNotification();
         notifReply.setSuccess(true);
         notifReply.setCounter(counter);
         auto capnSetPass = notifReply.initSetPassphrase();
         capnSetPass.setPassphrase(newPass);
         capnSetPass.setReuseKdf(true);

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge, rawReq);
      }

      //expect success reply
      {
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
            return false;
         }

         auto reply = fromBridge.getReply();
         if (reply.getReferenceId() != refId || !reply.getSuccess()) {
            return false;
         }
      }

      //expect cleanup notif
      {
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            return false;
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            return false;
         }
         if (notif.which() != Codec::Bridge::Notification::CLEANUP) {
            return false;
         }
      }

      return true;
   }

   WalletData extendAddressPool(
      std::shared_ptr<Bridge::CppBridge> bridge,
      const std::string& walletId, const std::string& accountId,
      const std::string& dbId, unsigned count, bool isNew)
   {
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();
      auto refId = rand();

      //start chain extension sequence
      {
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         toBridge.setReferenceId(refId);
         auto request = toBridge.initWallet();
         request.setWalletId(walletId);
         request.setAccountId(accountId);

         auto extendReq = request.initExtendAddressPool();
         extendReq.setCallbackId(callbackId);
         extendReq.setCount(count);
         extendReq.setIsNew(isNew);

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge, rawReq);
      }
      bool run = true;
      MsgPtr rawReply;
      int notifCount = 0;
      int lastKnownCount = 0;
      std::string refreshId;
      while (run) {
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();

         switch (fromBridge.which())
         {
            case Codec::Bridge::FromBridge::NOTIFICATION:
            {
               auto notif = fromBridge.getNotification();
               switch (notif.which())
               {
                  case Codec::Bridge::Notification::WALLET_PROGRESS:
                  {
                     auto wltNotif = notif.getWalletProgress();
                     switch (wltNotif.which())
                     {
                        case Codec::Bridge::Notification::WalletProgress::EXTEND_CHAIN:
                        {
                           auto extNotif = wltNotif.getExtendChain();
                           if (extNotif.getTotal() != count) {
                              throw std::runtime_error("invalid total count");
                           }
                           ++notifCount;
                           lastKnownCount = extNotif.getCurrent();
                           break;
                        }

                        default:
                           throw std::runtime_error("invalid wallet progress which");
                     }
                     break;
                  }

                  case Codec::Bridge::Notification::REFRESH:
                  {
                     if (notif.getCallbackId() != "bdm_callback") {
                        throw std::runtime_error("invalid callbackId for refresh");
                     }
                     if (!refreshId.empty()) {
                        throw std::runtime_error("refresh already seen!");
                     }

                     auto refreshIds = notif.getRefresh();
                     if (refreshIds.size() != 1) {
                        throw std::runtime_error("unexpected refreshId count");
                     }
                     refreshId = refreshIds[0];
                     break;
                  }

                  default:
                     throw std::runtime_error("invalid notif which");
               }
               break;
            }

            case Codec::Bridge::FromBridge::REPLY:
            {
               auto reply = fromBridge.getReply();
               if (!reply.getSuccess() || reply.getReferenceId() != refId) {
                  throw std::runtime_error("request failed");
               }
               run = false;
               break;
            }

            default:
               throw std::runtime_error("invalid bridge which");
         }
      }

      if (notifCount < 3) {
         throw std::runtime_error("too few notifs");
      }
      if (lastKnownCount != count) {
         throw std::runtime_error("invalid count in final notif");
      }

      //expect cleanup notif
      {
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            throw std::runtime_error("expected notif");
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            throw std::runtime_error("unexpected callbackId");
         }
         if (notif.which() != Codec::Bridge::Notification::CLEANUP) {
            throw std::runtime_error("expected cleanup notif");
         }
      }

      //expect refresh notif
      while (refreshId.empty()) {
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            throw std::runtime_error("expected notif");
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() == "progress") {
            continue;
         } else if (notif.getCallbackId() != "bdm_callback") {
            throw std::runtime_error("expected bdm notif");
         }
         if (notif.which() != Codec::Bridge::Notification::REFRESH) {
            throw std::runtime_error("expected refresh notif");
         }

         auto refreshIds = notif.getRefresh();
         if (refreshIds.size() != 1) {
            throw std::runtime_error("unexpected refreshId");
         }
         refreshId = refreshIds[0];
         break;
      }

      if (refreshId != dbId) {
         throw std::runtime_error("dbId mismatch");
      }

      //lastly, grab updated wallet data
      return getWalletData(bridge, walletId);
   }

   AddressData getAddress(
      std::shared_ptr<Bridge::CppBridge> bridge,
      const std::string& walletId,
      const std::string& accountId)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(walletId);
      request.setAccountId(accountId);
      auto reqAddr = request.initGetAddress();
      reqAddr.setNew();
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      if (reply.getSuccess() == false) {
         throw std::runtime_error("failure: " + std::string{reply.getError()});
      }
      if (reply.getReferenceId() != refId) {
         throw std::runtime_error("refId mismatch");
      }

      if (reply.which() != Codec::Bridge::RpcReply::WALLET) {
         throw std::runtime_error("which mismatch");
      }
      auto walletReply = reply.getWallet();

      if (walletReply.which() != Codec::Bridge::WalletReply::GET_ADDRESS) {
         throw std::runtime_error("which mismatch");
      }

      return capnToAddressData(walletReply.getGetAddress());
   }

   /////////////////////////////////////////////////////////////////////////////
   bool connectToDb(std::shared_ptr<Bridge::CppBridge> bridge)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initService();
      request.setSetupDb();

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      /* TODO: check we have a 2-way handshake with db */

      //expecting setup done notif
      auto reply = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(reply->data.getPtr()),
         reply->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);

      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
         std::cout << "..1" << std::endl;
         return false;
      }

      auto notif = fromBridge.getNotification();
      if (notif.which() != Codec::Bridge::Notification::SETUP_DONE) {
         std::cout << "..2" << std::endl;
         return false;
      }

      //grab reply to setupDb as well
      auto reply2 = waitOnReply();
      words = kj::ArrayPtr<const capnp::word>{
         reinterpret_cast<const capnp::word*>(reply2->data.getPtr()),
         reply2->data.getSize() / sizeof(capnp::word)
      };
      reader = capnp::FlatArrayMessageReader{words};
      fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();

      if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
         std::cout << "..3" << std::endl;
         return false;
      }

      auto repCapnp = fromBridge.getReply();
      if (!repCapnp.getSuccess()) {
         std::cout << "..4" << std::endl;
         return false;
      }
      return true;
   }

   bool registerWallets(std::shared_ptr<Bridge::CppBridge> bridge)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initService();
      request.setRegisterWallets();

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      //expecting setup done notif
      auto reply = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(reply->data.getPtr()),
         reply->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);

      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
         return false;
      }

      auto notif = fromBridge.getNotification();
      return notif.which() == Codec::Bridge::Notification::REGISTER_DONE;
   }

   int goOnline(std::shared_ptr<Bridge::CppBridge> bridge)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initService();
      request.setGoOnline();
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      bool run = true;
      int newBlock = -1;
      while (run) {
         auto reply = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(reply->data.getPtr()),
            reply->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);

         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            return -2;
         }

         auto notif = fromBridge.getNotification();
         switch (notif.which()) {
            case Codec::Bridge::Notification::SCAN_PROGRESS:
               break;

            case Codec::Bridge::Notification::READY:
            {
               newBlock = notif.getReady();
               return newBlock;
            }

            case Codec::Bridge::Notification::NODE_STATUS:
            {
               //ignore
               break;
            }

            default:
               std::cout << "unexpected db init notif: " << notif.which() << std::endl;
               return -3;
         }
      }
      return 0;
   }

   std::map<BinaryData, std::vector<uint64_t>> getBalances(
      std::shared_ptr<Bridge::CppBridge> bridge,
      const std::string& wltId, const std::string& accId)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto req = toBridge.initWallet();
      req.setWalletId(wltId);
      req.setAccountId(accId);
      req.setGetAddrCombinedList();
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      //process reply
      auto resp = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(resp->data.getPtr()),
         resp->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);

      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
         return {};
      }
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess()) {
         return {};
      }
      if (reply.which() != Codec::Bridge::RpcReply::WALLET) {
         return {};
      }

      auto walletReply = reply.getWallet();
      if (walletReply.which() != Codec::Bridge::WalletReply::GET_ADDR_COMBINED_LIST) {
         return {};
      }
      auto capnCombList = walletReply.getGetAddrCombinedList();
      auto capnBalances = capnCombList.getBalances();

      std::map<BinaryData, std::vector<uint64_t>> result;
      for (const auto& capnBal : capnBalances) {
         auto scrAddrCapn = capnBal.getScrAddr();
         BinaryData scrAddrRef{scrAddrCapn.begin(), scrAddrCapn.end()};
         auto iter = result.emplace(scrAddrRef, std::vector<uint64_t>{}).first;

         auto balCapn = capnBal.getBalances();
         iter->second.emplace_back(balCapn.getFull());
         iter->second.emplace_back(balCapn.getSpendable());
         iter->second.emplace_back(balCapn.getUnconfirmed());
      }
      return result;
   }

   /////////////////////////////////////////////////////////////////////////////
   // ledger stuff
   struct LedgerEntryValues
   {
      const int64_t balance;
      const uint32_t height;
      const uint32_t txTime;
   };
   std::vector<LedgerEntryValues> ledgersAt5Blocks{
      { 5 * COIN           , 5, 1231009513},
      { 30 * COIN          , 5, 1231009513},
      { 50 * COIN          , 5, 1231009513},
      { -45 * (int64_t)COIN, 4, 1231008909},
      { 5 * COIN           , 4, 1231008909},
      { 50 * COIN          , 4, 1231008909},
      { 55 * COIN          , 3, 1231008309},
      { 5 * COIN           , 3, 1231008309},
      { 5 * COIN           , 3, 1231008309},
      { 5 * COIN           , 3, 1231008309},
      { 50 * COIN          , 3, 1231008309},
      { -20 * (int64_t)COIN, 2, 1231007708},
      { -25 * (int64_t)COIN, 2, 1231007708},
      { 50 * COIN          , 2, 1231007708},
      { 50 * COIN          , 1, 1231007105},
   };

   std::string getLedgerDelegateId(std::shared_ptr<Bridge::CppBridge> bridge)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto req = toBridge.initService();
      req.setGetLedgerDelegateId();
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      //process reply
      auto resp = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(resp->data.getPtr()),
         resp->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);

      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
         return {};
      }
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess()) {
         return {};
      }
      if (reply.which() != Codec::Bridge::RpcReply::SERVICE) {
         return {};
      }
      auto serviceReply = reply.getService();
      return serviceReply.getGetLedgerDelegateId();
   }

   size_t getLedgersPageCount(std::shared_ptr<Bridge::CppBridge> bridge,
      const std::string& delegateId)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto req = toBridge.initDelegate();
      req.setId(delegateId);
      req.setGetPageCount();
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      //process reply
      auto resp = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(resp->data.getPtr()),
         resp->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);

      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
         return SIZE_MAX;
      }
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess()) {
         return SIZE_MAX;
      }
      if (reply.which() != Codec::Bridge::RpcReply::DELEGATE) {
         return SIZE_MAX;
      }
      auto delegateReply = reply.getDelegate();
      return delegateReply.getGetPageCount();
   }

   std::vector<LedgerEntry> getLedgersPage(std::shared_ptr<Bridge::CppBridge> bridge,
      const std::string& delegateId, uint32_t pageId)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto req = toBridge.initDelegate();
      req.setId(delegateId);
      auto pageReq = req.initGetPages();
      pageReq.setFirst(pageId);
      pageReq.setLast(pageId);
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge, rawReq);

      //process reply
      auto resp = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(resp->data.getPtr()),
         resp->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);

      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
         return {};
      }
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess()) {
         return {};
      }
      if (reply.which() != Codec::Bridge::RpcReply::DELEGATE) {
         return {};
      }

      auto delegateReply = reply.getDelegate();
      auto result = capnToLedgers(delegateReply.getGetPages());
      if (result.size() != 1) {
         throw std::runtime_error("unexpected ledger size");
      }
      return result[0];
   }

   /////////////////////////////////////////////////////////////////////////////
   std::map<BinaryData, std::vector<uint64_t>> testAddrBalances {
      { TestChain::scrAddrB, { 70 * COIN, 20 * COIN, 70 * COIN } },
      { TestChain::scrAddrC, { 20 * COIN, 20 * COIN, 20 * COIN } },
      { TestChain::scrAddrD, { 65 * COIN, 15 * COIN, 65 * COIN } },
      { TestChain::scrAddrE, { 30 * COIN, 30 * COIN, 30 * COIN } }
   };
}

////////////////////////////////////////////////////////////////////////////////
// WalletManagerTests
////////////////////////////////////////////////////////////////////////////////
class WalletManagerTests : public ::testing::Test
{
protected:
   virtual void SetUp(void)
   {
      homedir_ = std::filesystem::path("./fakehomedir");
      FileUtils::removeDirectory(homedir_);
      std::filesystem::create_directory(homedir_);

      Config::parseArgs({
         "--offline",
         "--datadir=./fakehomedir" },
         Config::ProcessType::DB);
   }

   virtual void TearDown(void)
   {
      Config::reset();
      FileUtils::removeDirectory(homedir_);
   }

   std::filesystem::path homedir_;
};

////////////////////////////////////////////////////////////////////////////////
TEST_F(WalletManagerTests, ListStageLoad)
{
   /*
   covers the following scenarios:
      1: wallet without control passphrase
      2: with control passphrase, keep encrypted
      3: with control passphrase, decrypted
      4: with control passphrase, decrypted but unstaged
   */
   std::vector<std::filesystem::path> walletFiles;

   //wallet 1
   {
      Wallets::IO::CreateWalletParams params{
         homedir_,
         {1ms, 0, SecureBinaryData::fromString("privpass1")},
         {},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletFiles.emplace_back(assetWlt->getDbFilename());
   }

   //wallet 2, 3, 4
   for (unsigned i=2; i<5; i++) {
      Wallets::IO::CreateWalletParams params{
         homedir_,
         {1ms, 0, SecureBinaryData::fromString("privpass" + std::to_string(i))},
         {1ms, 0, SecureBinaryData::fromString("controlpass" + std::to_string(i))},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletFiles.emplace_back(assetWlt->getDbFilename());
   }

   //list wallets
   Bridge::WalletManager mgr{homedir_};
   auto theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 4);
   for (const auto& path : walletFiles) {
      ASSERT_NE(theList.find(path.filename().string()), theList.end());
   }

   auto checkState = [&walletFiles](
      const std::map<std::string, std::shared_ptr<Bridge::WalletFileInfo>>& theList,
      unsigned intId, Bridge::WalletLoadState expLoadState, bool expectedStaged)->bool
   {
      auto listEntry = theList.at(walletFiles[intId].filename().string());
      if (listEntry->state() != expLoadState) {
         return false;
      }
      if (listEntry->state() == Bridge::WalletLoadState::Ready &&
         listEntry->walletId().empty()) {
         return false;
      }
      return listEntry->staged() == expectedStaged;
   };

   EXPECT_TRUE(checkState(theList, 0, Bridge::WalletLoadState::Ready, true));
   EXPECT_TRUE(checkState(theList, 1, Bridge::WalletLoadState::Encrypted, false));
   EXPECT_TRUE(checkState(theList, 2, Bridge::WalletLoadState::Encrypted, false));
   EXPECT_TRUE(checkState(theList, 3, Bridge::WalletLoadState::Encrypted, false));

   //unlock wallets 3 & 4, fail for wtl2
   {
      try {
         mgr.unlockControlHeader(walletFiles[2].filename().string(), [](
            const std::set<Wallets::EncryptionKeyId>&)->Passphrase::Result {
               return { SecureBinaryData::fromString("controlpass3"), true };
            }
         );

         mgr.unlockControlHeader(walletFiles[3].filename().string(), [](
            const std::set<Wallets::EncryptionKeyId>&)->Passphrase::Result {
               return { SecureBinaryData::fromString("controlpass4"), true };
            }
         );
      } catch (const std::exception& e) {
         ASSERT_TRUE(false) << e.what();
      }

      unsigned count = 0;
      auto failUnlockLbd = [&count](
         const std::set<Wallets::EncryptionKeyId>&)->Passphrase::Result {
         if (count++ < 2) {
            return { Cryptography::PRNG::fortuna.generateRandom(10), true };
         }
         //give up after 2 tries
         return { {}, false };
      };
      try {
         mgr.unlockControlHeader(walletFiles[1].filename().string(), failUnlockLbd);
         ASSERT_TRUE(false);
      } catch (const Wallets::Encryption::DecryptedDataContainerException& e) {
         ASSERT_EQ(e.what(), std::string{"unlock request rejected"}) << e.what();
      }
   }

   //recheck the list
   theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 4);
   for (const auto& path : walletFiles) {
      ASSERT_NE(theList.find(path.filename().string()), theList.end());
   }
   EXPECT_TRUE(checkState(theList, 0, Bridge::WalletLoadState::Ready, true));
   EXPECT_TRUE(checkState(theList, 1, Bridge::WalletLoadState::Encrypted, false));
   EXPECT_TRUE(checkState(theList, 2, Bridge::WalletLoadState::Ready, true));
   EXPECT_TRUE(checkState(theList, 3, Bridge::WalletLoadState::Ready, true));

   //unstage wlt4
   {
      auto wlt4Info = theList.at(walletFiles[3].filename().string());
      ASSERT_TRUE(mgr.stageWallet(wlt4Info->walletId(), false));
   }

   //recheck the list
   theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 4);
   for (const auto& path : walletFiles) {
      ASSERT_NE(theList.find(path.filename().string()), theList.end());
   }
   EXPECT_TRUE(checkState(theList, 0, Bridge::WalletLoadState::Ready, true));
   EXPECT_TRUE(checkState(theList, 1, Bridge::WalletLoadState::Encrypted, false));
   EXPECT_TRUE(checkState(theList, 2, Bridge::WalletLoadState::Ready, true));
   EXPECT_TRUE(checkState(theList, 3, Bridge::WalletLoadState::Ready, false));

   //load wallets
   mgr.loadWallets();

   //check loaded wallets
   auto checkHasWallet = [&theList, &walletFiles, &mgr](unsigned intId)->bool
   {
      auto entry = theList.at(walletFiles[intId].filename().string());
      try {
         return mgr.hasWallet(entry->walletId());
      } catch (const std::exception&) {
         return false;
      }
      
   };

   EXPECT_TRUE(checkHasWallet(0));
   EXPECT_FALSE(checkHasWallet(1));
   EXPECT_TRUE(checkHasWallet(2));
   EXPECT_FALSE(checkHasWallet(3));

   //check list only has wlt1
   theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 2);

   ASSERT_EQ(theList.find(walletFiles[0].filename().string()), theList.end());
   ASSERT_NE(theList.find(walletFiles[1].filename().string()), theList.end());
   ASSERT_EQ(theList.find(walletFiles[2].filename().string()), theList.end());
   ASSERT_NE(theList.find(walletFiles[3].filename().string()), theList.end());
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(WalletManagerTests, ListWO)
{
   std::vector<std::filesystem::path> wltPaths;

   //wallet 1
   {
      Wallets::IO::CreateWalletParams params{
         homedir_,
         {1ms, 0, SecureBinaryData::fromString("privpass1")},
         {1ms, 0, SecureBinaryData::fromString("ctrlPass")},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      wltPaths.emplace_back(assetWlt->getDbFilename());
   }

   {
      auto woWltPath = Wallets::AssetWallet::forkWatchingOnly({wltPaths[0],
         [](const std::set<Wallets::EncryptionKeyId>&)->Passphrase::Result
         {
            return { SecureBinaryData::fromString("ctrlPass"), true };
         }},
         {1ms, 0, SecureBinaryData::fromString("woPass")}
      );
      ASSERT_FALSE(woWltPath.empty());
      ASSERT_TRUE(FileUtils::fileExists(woWltPath, 0));
      ASSERT_NE(woWltPath, wltPaths[0]);
      wltPaths.emplace_back(woWltPath);
   }

   //list wallets
   Bridge::WalletManager mgr{homedir_};
   auto theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 2);
   for (const auto& path : wltPaths) {
      ASSERT_NE(theList.find(path.filename().string()), theList.end());
   }

   auto checkState = [&wltPaths](
      const std::map<std::string, std::shared_ptr<Bridge::WalletFileInfo>>& theList,
      unsigned intId, Bridge::WalletLoadState expLoadState,
      bool expectedStaged, bool isWO=false)->bool
   {
      auto listEntry = theList.at(wltPaths[intId].filename().string());
      if (listEntry->state() != expLoadState) {
         return false;
      }
      if (listEntry->state() == Bridge::WalletLoadState::Ready &&
         listEntry->walletId().empty()) {
         return false;
      }
      if (isWO != listEntry->isWatchingOnly()) {
         return false;
      }
      return listEntry->staged() == expectedStaged;
   };

   EXPECT_TRUE(checkState(theList, 0,
      Bridge::WalletLoadState::Encrypted, false));
   EXPECT_TRUE(checkState(theList, 1,
      Bridge::WalletLoadState::Encrypted, false));

   //unlock the wallets
   {
      try {
         mgr.unlockControlHeader(wltPaths[0].filename().string(), [](
            const std::set<Wallets::EncryptionKeyId>&)->Passphrase::Result {
               return { SecureBinaryData::fromString("ctrlPass"), true };
            }
         );

         mgr.unlockControlHeader(wltPaths[1].filename().string(), [](
            const std::set<Wallets::EncryptionKeyId>&)->Passphrase::Result {
               return { SecureBinaryData::fromString("woPass"), true };
            }
         );
      } catch (const std::exception& e) {
         ASSERT_TRUE(false) << e.what();
      }
   }

   //recheck the list
   theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 2);
   for (const auto& path : wltPaths) {
      ASSERT_NE(theList.find(path.filename().string()), theList.end());
   }

   std::vector<std::string> wltIds;
   for (const auto& entry : theList) {
      wltIds.emplace_back(entry.second->walletId());
   }
   ASSERT_EQ(wltIds.size(), 2);
   ASSERT_EQ(wltIds[0], wltIds[1]);

   EXPECT_TRUE(checkState(theList, 0,
      Bridge::WalletLoadState::Ready, true, false));
   EXPECT_TRUE(checkState(theList, 1,
      Bridge::WalletLoadState::Ready, true, true));
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(WalletManagerTests, Migrate_Legacy)
{
   //copy test legacy wallet to datadir
   const auto& wltId = "28m472Xbm"sv;
   std::string fileName = std::string{"armory_"sv} +
      std::string{wltId} +
      std::string{"_.wallet"sv};
   const std::filesystem::path wltPath{fileName};
   std::filesystem::copy(
      "input_files/legacy.wallet"sv,
      homedir_ / wltPath
   );

   //list wallets
   Bridge::WalletManager mgr{homedir_};
   auto theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 1);

   //sanity check
   {
      auto iter = theList.find(wltPath.filename().string());
      ASSERT_NE(iter, theList.end());
      EXPECT_EQ(iter->second->state(), Bridge::WalletLoadState::Legacy);
      EXPECT_EQ(iter->second->walletId(), wltId);
      EXPECT_FALSE(iter->second->staged());
   }

   //migrate the wallet
   auto passFunc = [](const std::set<Wallets::EncryptionKeyId>&)
   ->Passphrase::Result
   {
      return { SecureBinaryData::fromString("testnet"), true };
   };
   mgr.migrateWallet(wltPath.filename().string(), passFunc,
      Wallets::IO::CreateWalletParams{
         homedir_,
         {1ms, 0, {}},
         {1ms, 0, {}},
         nullptr, 0
      });

   theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 2);

   //check legacy wallet
   {
      auto iter = theList.find(wltPath.filename().string());
      ASSERT_NE(iter, theList.end());
      EXPECT_EQ(iter->second->state(), Bridge::WalletLoadState::Legacy);
      EXPECT_EQ(iter->second->walletId(), wltId);
      EXPECT_FALSE(iter->second->staged());
   }

   //check migrated wallet
   {
      auto iter = theList.begin();
      while (iter != theList.end()) {
         if (iter->first != wltPath.filename().string()) {
            break;
         }
         ++iter;
      }
      ASSERT_NE(iter, theList.end());
      EXPECT_EQ(iter->second->state(), Bridge::WalletLoadState::Ready);
      EXPECT_EQ(iter->second->walletId(), wltId);
      EXPECT_TRUE(iter->second->staged());
   }

   //load wallets
   mgr.loadWallets();

   //check migrated wallet
   try {
      auto wltContainer = mgr.getWalletContainer(wltId);
      ASSERT_NE(wltContainer, nullptr);
      EXPECT_EQ(wltContainer->getHighestUsedIndex(), 2);
      EXPECT_EQ(wltContainer->getAccountId().toHexStr(), "f6e10000");

      auto wltPtr = wltContainer->getWalletPtr();
      EXPECT_EQ(wltPtr->getLabel(), "legacy1");
      EXPECT_EQ(wltPtr->getDescription(), "migration test");

      auto addrAccPtr = wltContainer->getAddressAccount();
      auto addrMap = addrAccPtr->getAddressHashMap();
      EXPECT_EQ(addrMap.size(), 104 * 3);

      //TODO: check addresses
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //TODO: check backup string, with version (should be 1.35c)
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(WalletManagerTests, Migrate_Reject)
{
   //copy test legacy wallet to datadir
   const auto& wltId = "28m472Xbm"sv;
   std::string fileName = std::string{"armory_"sv} +
      std::string{wltId} +
      std::string{"_.wallet"sv};
   const std::filesystem::path wltPath{fileName};
   std::filesystem::copy(
      "input_files/legacy.wallet"sv,
      homedir_ / wltPath
   );

   //list wallets
   Bridge::WalletManager mgr{homedir_};
   auto theList = mgr.listWallets();
   ASSERT_EQ(theList.size(), 1);

   //sanity check
   {
      auto iter = theList.find(wltPath.filename().string());
      ASSERT_NE(iter, theList.end());
      EXPECT_EQ(iter->second->state(), Bridge::WalletLoadState::Legacy);
      EXPECT_EQ(iter->second->walletId(), wltId);
      EXPECT_FALSE(iter->second->staged());
   }

   //reject the unlock
   auto passFunc = [](const std::set<Wallets::EncryptionKeyId>&)
   ->Passphrase::Result
   {
      return { SecureBinaryData::fromString("testnet"), false };
   };

   try {
      mgr.migrateWallet(wltPath.filename().string(), passFunc,
         Wallets::IO::CreateWalletParams{
            homedir_,
            {1ms, 0, {}},
            {1ms, 0, {}},
            nullptr, 0
         });
      ASSERT_TRUE(false);
   } catch (const std::exception& e) {
      EXPECT_EQ(e.what(), std::string{"rejected migration"});
   }
}

////////////////////////////////////////////////////////////////////////////////
// WalletManagerWebsocketsTests
////////////////////////////////////////////////////////////////////////////////
class WalletManagerWebsocketsTests : public ::testing::Test
{
protected:
   void initBDM()
   {
      theBDMt_ = new BlockDataManagerThread();
      iface_ = theBDMt_->bdm()->getIFace();
   }

   void createWallet()
   {
      Wallets::IO::CreateWalletParams params{
         homedir_,
         Passphrase::SetNew{1ms, 0, {}},
         Passphrase::SetNew{1ms, 0, {}},
         nullptr, 0
      };

      //create empty WO wallet
      auto wltWO = Wallets::AssetWallet_Single::createBlank("walletWO1"sv, params);
      wltWO->setupImportAccount();

      auto pubKeyB = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrB);
      wltWO->importPublicKey(pubKeyB, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));

      auto pubKeyC = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrC);
      wltWO->importPublicKey(pubKeyC, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));

      auto pubKeyD = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrD);
      wltWO->importPublicKey(pubKeyD, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));

      auto pubKeyE = Cryptography::ECDSA::computePublicKey(TestChain::privKeyAddrE);
      wltWO->importPublicKey(pubKeyE, AddressEntryType(
         AddressEntryType::P2PKH | AddressEntryType::Uncompressed));
   }

   virtual void SetUp()
   {
      FileUtils::removeDirectory(blkdir_);
      FileUtils::removeDirectory(homedir_);
      FileUtils::removeDirectory(ldbdir_);

      FileUtils::createDirectory(blkdir_ / "blocks");
      FileUtils::createDirectory(homedir_);
      FileUtils::createDirectory(ldbdir_);

      Config::DBSettings::setServiceType(SERVICE_UNITTEST_WITHWS);

      // Put the first 5 blocks into the blkdir
      blk0dat_ = FileUtils::getBlkFilename(blkdir_ / "blocks", 0);
      TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);

      Config::parseArgs({
         "--datadir=./fakehomedir",
         "--dbdir=./ldbtestdir",
         "--satoshi-datadir=./blkfiletest",
         "--db-type=DB_FULL",
         "--thread-count=3",
         "--public"},
         Config::ProcessType::DB);

      startupBIP151CTX();
      startupBIP150CTX(4);

      //setup auth peers for server and client
      authPeersPassLbd_ = [](const std::set<Wallets::EncryptionKeyId>&)
      ->Passphrase::Result
      {
         return { {}, true };
      };

      auto createWltLbd = []()->std::unique_ptr<Passphrase::Params>
      {
         return std::make_unique<Passphrase::Params>(
            1ms, 0, SecureBinaryData{});
      };

      Wallets::AuthorizedPeers::createWallet({
         homedir_ / SERVER_AUTH_PEER_FILENAME, {createWltLbd}});
      Wallets::AuthorizedPeers serverPeers(
         {homedir_ / SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_});

      Wallets::AuthorizedPeers::createWallet({
         homedir_ / CLIENT_AUTH_PEER_FILENAME, {createWltLbd}});
      Wallets::AuthorizedPeers clientPeers(
         {homedir_ / CLIENT_AUTH_PEER_FILENAME, authPeersPassLbd_});

      //share public keys between client and server
      auto& serverPubkey = serverPeers.getOwnPublicKey();

      std::stringstream serverAddr;
      serverAddr << "127.0.0.1:" << Config::NetworkSettings::dbPort();
      clientPeers.addPeer(serverPubkey, serverAddr.str());

      serverPubkey_ = BinaryData(serverPubkey.pubkey, 33);
      serverAddr_ = serverAddr.str();

      createWallet();
      initBDM();
      auto nodePtr = std::dynamic_pointer_cast<NodeUnitTest>(
         Config::NetworkSettings::bitcoinNodes().first);
      nodePtr->setIface(theBDMt_->bdm()->getIFace());
      hexMagicBytes = Config::BitcoinSettings::getMagicBytes().toHexStr();
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void TearDown()
   {
      WebSocketServer::shutdown();
      WebSocketServer::waitOnShutdown();
      theBDMt_->shutdown();

      delete theBDMt_;
      theBDMt_ = nullptr;

      FileUtils::removeDirectory(blkdir_);
      FileUtils::removeDirectory(homedir_);
      FileUtils::removeDirectory(ldbdir_);
      Config::reset();
   }

   /////////////////////////////////////////////////////////////////////////////
   BlockDataManagerThread *theBDMt_;
   Passphrase::UnlockFunc authPeersPassLbd_;
   LMDBBlockDatabase* iface_;

   std::filesystem::path blkdir_{"./blkfiletest"sv};
   std::filesystem::path homedir_{"./fakehomedir"sv};
   std::filesystem::path ldbdir_{"./ldbtestdir"sv};
   std::filesystem::path blk0dat_;

   BinaryData serverPubkey_;
   std::string serverAddr_;
   std::string hexMagicBytes;
};

////
TEST_F(WalletManagerWebsocketsTests, Connect)
{
   NotifQueue queue;
   auto notifFunc = [&queue](BinaryData notifData)
   {
      queue.push_back(notifData);
   };
   auto mgr = std::make_shared<Bridge::WalletManager>(homedir_);
   mgr->setupBdvCallback(notifFunc);

   //list wallets
   auto theList = mgr->listWallets();
   ASSERT_EQ(theList.size(), 1);
   auto wltId = theList.begin()->second->walletId();
   mgr->loadWallets();

   WebSocketServer::initAuthPeers({
      homedir_ / SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_});
   WebSocketServer::start(theBDMt_->bdm(), true);

   //create bdv ptr, connect to db
   auto clientPeers = std::make_shared<Wallets::AuthorizedPeers>(
      Wallets::IO::ReadOnlyFileParams{
         homedir_ / CLIENT_AUTH_PEER_FILENAME, authPeersPassLbd_});
   auto bdvPtr = Bridge::setupClientConnection(
      clientPeers, mgr);

   //expecting setupDone notif
   {
      auto notifBd = queue.pop();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(notifBd.getPtr()),
         notifBd.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto notif = fromBridge.getNotification();
      ASSERT_EQ(notif.which(), Codec::Bridge::Notification::SETUP_DONE);
   }

   //register wallet
   mgr->registerWallets();

   //expecting registerDone notif
   {
      auto notifBd = queue.pop();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(notifBd.getPtr()),
         notifBd.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto notif = fromBridge.getNotification();
      ASSERT_EQ(notif.which(), Codec::Bridge::Notification::REGISTER_DONE);
   }

   //start blockchain db & go online
   theBDMt_->start(Config::DBSettings::initMode());
   bdvPtr->goOnline();

   //expecting ready notif
   int newBlockVal = 0;
   bool run = true;
   while (run) {
      auto notifBd = queue.pop();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(notifBd.getPtr()),
         notifBd.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto notif = fromBridge.getNotification();

      switch (notif.which()) {
         case Codec::Bridge::Notification::READY:
         {
            newBlockVal = notif.getReady();
            run = false;
            break;
         }

         case Codec::Bridge::Notification::SCAN_PROGRESS:
            break;

         default:
            EXPECT_TRUE(false) << (int)notif.which();
      }
   }
   ASSERT_EQ(newBlockVal, 5);

   //check wallet balances
   try {
      auto wltCont = mgr->getWalletContainer(wltId);
      ASSERT_NE(wltCont, nullptr);

      auto addrBalances = wltCont->getAddrBalanceMap();
      ASSERT_EQ(addrBalances.size(), 4);

      for (const auto& addrBal : testAddrBalances) {
         auto mgrBal = addrBalances.at(addrBal.first);
         for (unsigned i=0; i<3; i++) {
            EXPECT_EQ(addrBal.second[i], mgrBal[i]);
         }
      }
   } catch (const std::exception&) {
      ASSERT_TRUE(false);
   }

   //cleanup
   bdvPtr->unregisterFromDB();
}

////////////////////////////////////////////////////////////////////////////////
// BridgeTests
////////////////////////////////////////////////////////////////////////////////
class BridgeTests : public ::testing::Test
{
protected:
   //setup
   virtual void SetUp(void)
   {
      std::srand(std::time({}));
      homedir = std::filesystem::path("./fakehomedir");
      FileUtils::removeDirectory(homedir);
      std::filesystem::create_directory(homedir);

      Config::parseArgs({
         "--offline",
         "--datadir=./fakehomedir" },
         Config::ProcessType::Bridge);

      replyQueue.clear();
      bridge_ = std::make_shared<Bridge::CppBridge>();
      bridge_->setWriteLambda([](MsgPtr payload) {
         std::unique_lock<std::mutex> lock(commsMutex);
         replyQueue.emplace_back(std::move(payload));
         commsCV.notify_all();
      });
   }

   virtual void TearDown(void)
   {
      bridge_.reset();
      Config::reset();
      FileUtils::removeDirectory(homedir);
   }

   //helpers
   bool unlockWallet(const std::string& path, const std::string& passphrase)
   {
      auto refId = rand();
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

      //request unlock
      {
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         toBridge.setReferenceId(refId);
         auto request = toBridge.initWalletManager();
         auto unlockReq = request.initUnlockControlHeader();

         unlockReq.setCallbackId(callbackId);
         unlockReq.setWalletPath(path);

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge_, rawReq);
      }

      //wait on passphrase prompt
      auto rawPrompt = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
         rawPrompt->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
         return false;
      }

      auto notif = fromBridge.getNotification();
      if (notif.getCallbackId() != callbackId) {
         return false;
      }
      if (notif.which() != Codec::Bridge::Notification::UNLOCK_REQUEST) {
         return false;
      }
      auto counter = notif.getCounter();

      //push passphrase
      {
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         auto notifReply = toBridge.initNotification();
         notifReply.setSuccess(true);
         notifReply.setCounter(counter);
         notifReply.setUnlockRequest(passphrase);

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge_, rawReq);
      }

      //expect success reply
      bool success = false;
      {
         auto rawReply = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawReply->data.getPtr()),
            rawReply->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
            return false;
         }

         auto rpcReply = fromBridge.getReply();
         if (rpcReply.getReferenceId() != refId) {
            success = false;
         } else {
            success = rpcReply.getSuccess();
         }
      }

      //expect prompt cleanup
      {
         auto rawReply = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawReply->data.getPtr()),
            rawReply->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            return false;
         }
   
         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            return false;
         }
         if (notif.which() != Codec::Bridge::Notification::CLEANUP) {
            return false;
         }
      }

      return success;
   }

   int failToUnlockWallet(const std::string& path, unsigned count)
   {
      auto refId = rand();
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

      //request unlock
      {
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         toBridge.setReferenceId(refId);
         auto request = toBridge.initWalletManager();
         auto unlockReq = request.initUnlockControlHeader();

         unlockReq.setCallbackId(callbackId);
         unlockReq.setWalletPath(path);

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge_, rawReq);
      }

      unsigned attempts = 0;
      while (attempts <= count) {
         //wait on passphrase prompt
         auto rawPrompt = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawPrompt->data.getPtr()),
            rawPrompt->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            return -1;
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            return -2;
         }
         if (notif.which() != Codec::Bridge::Notification::UNLOCK_REQUEST) {
            return -3;
         }
         auto counter = notif.getCounter();

         //push passphrase
         {
            capnp::MallocMessageBuilder message;
            auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
            auto notifReply = toBridge.initNotification();
            notifReply.setCounter(counter);

            if (attempts != count) {
               notifReply.setSuccess(true);
               auto badPass = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();
               notifReply.setUnlockRequest(badPass);
            } else {
               notifReply.setSuccess(false);
            }

            auto rawReq = serializeCapnp(message);
            pushRequest(bridge_, rawReq);
         }
         ++attempts;
      }

      //expect failure notif
      {
         auto rawReply = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawReply->data.getPtr()),
            rawReply->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
            return -4;
         }

         auto rpcReply = fromBridge.getReply();
         if (rpcReply.getReferenceId() != refId) {
            return -5;
         }
         if (rpcReply.getSuccess() != false) {
            return -6;
         }

         std::string errorStr = rpcReply.getError();
         if (errorStr != std::string{"unlock request rejected"}) {
            return -7;
         }
      }

      //expect prompt cleanup
      {
         auto rawReply = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(rawReply->data.getPtr()),
            rawReply->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            return -8;
         }
   
         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            return -9;
         }
         if (notif.which() != Codec::Bridge::Notification::CLEANUP) {
            return -10;
         }
      }
      return attempts;
   }

   bool stageWallet(const std::string& walletId, bool stage)
   {
      auto refId = rand();

      //request staging change
      {
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         toBridge.setReferenceId(refId);
         auto request = toBridge.initWalletManager();
         auto stageReq = request.initStageWallet();

         stageReq.setWalletId(walletId);
         stageReq.setStage(stage);

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge_, rawReq);
      }

      //expect success
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      if (reply.getReferenceId() != refId) {
         return false;
      }
      return reply.getSuccess();
   }

   std::chrono::milliseconds testKDFUnlock(const std::string& walletId)
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(walletId);
      request.setGetUnlockTime();

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      if (!reply.getSuccess() || reply.getReferenceId() != refId) {
         return {};
      }
      return std::chrono::milliseconds(reply.getWallet().getGetUnlockTime());
   }

   WalletData progressWalletCreation(const std::string& callbackId,
      const std::string& passphrase, std::chrono::milliseconds targetMs,
      uint32_t targetMB, int lookup, bool WO=false)
   {
      std::string masterId;
      std::filesystem::path path;
      int notifCount=0;
      bool run = true;
      while (run) {
         auto result = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(result->data.getPtr()),
            result->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            throw std::runtime_error("invalid FromBridge which");
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            throw std::runtime_error("invalid callbackId");
         }
         auto counter = notif.getCounter();

         switch (notif.which())
         {
            case Codec::Bridge::Notification::SET_PASSPHRASE:
            {
               auto wltNotif = notif.getSetPassphrase();
               switch (wltNotif.which())
               {
                  case Codec::Bridge::Notification::SetPassphraseRequest::CONTROL_PASS:
                  {
                     if (notifCount++ != 1) {
                        throw std::runtime_error("count != 1");
                     }
                     capnp::MallocMessageBuilder message;
                     auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
                     auto notifReply = toBridge.initNotification();
                     notifReply.setSuccess(false);
                     notifReply.setCounter(counter);
                     auto rawReq = serializeCapnp(message);
                     pushRequest(bridge_, rawReq);
                     break;
                  }

                  case Codec::Bridge::Notification::SetPassphraseRequest::PRIVATE_PASS:
                  {
                     if (notifCount++ != 3) {
                        throw std::runtime_error("count != 3");
                     }
                     capnp::MallocMessageBuilder message;
                     auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
                     auto notifReply = toBridge.initNotification();
                     notifReply.setCounter(counter);

                     if (passphrase.empty()) {
                        notifReply.setSuccess(false);
                     } else {
                        notifReply.setSuccess(true);
                        auto capnSetPass = notifReply.initSetPassphrase();
                        capnSetPass.setPassphrase(passphrase);
                        capnSetPass.setKdfTargetMs(targetMs.count());
                        capnSetPass.setKdfTargetMB(targetMB);
                     }

                     auto rawReq = serializeCapnp(message);
                     pushRequest(bridge_, rawReq);
                     break;
                  }

                  default:
                     throw std::runtime_error("unexpected wallet creation notif");
               }
               break;
            }

            case Codec::Bridge::Notification::WALLET_PROGRESS:
            {
               auto wltNotif = notif.getWalletProgress();
               switch (wltNotif.which())
               {
                  case Codec::Bridge::Notification::WalletProgress::CREATE_FILE:
                  {
                     if (notifCount++ != 0) {
                        throw std::runtime_error("count != 0");
                     }
                     path = std::filesystem::path(std::string{wltNotif.getCreateFile()});
                     break;
                  }

                  case Codec::Bridge::Notification::WalletProgress::INIT_FILE:
                  {
                     if (notifCount++ != 2) {
                        throw std::runtime_error("count != 2");
                     }
                     if (WO) {
                        ++notifCount;
                     }

                     auto fullPath = std::filesystem::path{"./fakehomedir"} / path;
                     if (!FileUtils::fileExists(fullPath, 0)) {
                        fullPath = std::filesystem::path{"./fakehomedir/temp"} / path;
                        if (!FileUtils::fileExists(fullPath, 0)) {
                           throw std::runtime_error("wallet path is invalid!");
                        }
                     }
                     masterId = wltNotif.getInitFile();
                     break;
                  }

                  case Codec::Bridge::Notification::WalletProgress::READ_FILE:
                  {
                     if (notifCount++ != 4) {
                        throw std::runtime_error("count != 4");
                     }
                     if (wltNotif.getReadFile() != masterId) {
                        throw std::runtime_error("masterId mismatch");
                     }
                     break;
                  }

                  case Codec::Bridge::Notification::WalletProgress::CREATE_ACCOUNT:
                  {
                     if (notifCount++ != 5) {
                        throw std::runtime_error("count != 5");
                     }
                     EXPECT_EQ(wltNotif.getCreateAccount(), "Armory Legacy");
                     break;
                  }

                  case Codec::Bridge::Notification::WalletProgress::EXTEND_CHAIN:
                  {
                     if (notifCount++ != 6) {
                        throw std::runtime_error("count != 6");
                     }
                     auto extendNotif = wltNotif.getExtendChain();
                     EXPECT_EQ(extendNotif.getTotal(), lookup);
                     EXPECT_EQ(extendNotif.getCurrent(), 0);
                     break;
                  }

                  default:
                     throw std::runtime_error("unexpected wallet progress notif");
               }
               break;
            }

            case Codec::Bridge::Notification::CLEANUP:
            {
               run = false;
               break;
            }

            case Codec::Bridge::Notification::RESTORE:
            {
               auto restoreNotif = notif.getRestore();
               std::cout << "fail notif: " << std::string{restoreNotif.getFailure()} << std::endl;
               throw std::runtime_error("got a restore notif in wallet creation progress!");
            }

            default:
               throw std::runtime_error(std::string{
                  "unexpected wallet notif: " + std::to_string(notif.which())});
         }
      }

      if (!passphrase.empty() && notifCount != 7) {
         throw std::runtime_error("unexpected notif count");
      }

      return WalletData{
         {}, {}, masterId, {},
         {}, {},
         true, false, {}, 0, 0,
         path
      };
   }

   std::vector<std::string> getBackup(const std::string& walletId,
      const std::string& passphrase, Codec::Bridge::WalletBackup::Type backupType)
   {
      auto refId = rand();
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(walletId);
      auto reqBackup = request.initCreateBackupString();
      reqBackup.setPrivate(callbackId);
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      //handle unlock and cleanup
      int count = 0;
      bool run = true;
      while (run) {
         auto result = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(result->data.getPtr()),
            result->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);

         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            throw std::runtime_error("expected a notif");
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            throw std::runtime_error("unexpected callback id");
         }

         switch (notif.which()) {
            case Codec::Bridge::Notification::UNLOCK_REQUEST:
            {
               capnp::MallocMessageBuilder notifMsg;
               auto notifBridge = notifMsg.initRoot<Codec::Bridge::ToBridge>();
               auto notifReply = notifBridge.initNotification();
               notifReply.setCounter(notif.getCounter());
               if (count == 0) {
                  notifReply.setSuccess(true);
                  notifReply.setUnlockRequest(passphrase);
               } else {
                  notifReply.setSuccess(false);
                  run = false;
               }

               auto rawNotif = serializeCapnp(notifMsg);
               pushRequest(bridge_, rawNotif);
               ++count;
               break;
            }

            case Codec::Bridge::Notification::CLEANUP:
            {
               run = false;
               break;
            }

            default:
               throw std::runtime_error("unexpected notif type");
         }
      }

      //grab the reply
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      if (reply.getSuccess() == false) {
         throw std::runtime_error(reply.getError());
      }
      if (reply.getReferenceId() != refId) {
         throw std::runtime_error("refId mismatch");
      }

      if (reply.which() != Codec::Bridge::RpcReply::WALLET) {
         throw std::runtime_error("which mismatch");
      }
      auto walletReply = reply.getWallet();

      if (walletReply.which() != Codec::Bridge::WalletReply::CREATE_BACKUP_STRING) {
         throw std::runtime_error("which mismatch");
      }
      auto capnBackup = walletReply.getCreateBackupString();

      //backup type
      if (capnBackup.getBackupType() != backupType) {
         throw std::runtime_error("backup type mismatch");
      }

      //root
      std::vector<std::string> lines;
      for (const auto& line : capnBackup.getRootClear()) {
         lines.emplace_back(line);
      }

      //chaincode
      if (capnBackup.hasChainClear()) {
         for (const auto& line : capnBackup.getChainClear()) {
            lines.emplace_back(line);
         }
      }
      return lines;
   }

   WalletData restoreWallet(const std::vector<std::string>& lines,
      const std::string& expectedWltId, Codec::Bridge::WalletBackup::Type backupType,
      const std::string& passphrase, std::chrono::milliseconds targetMs, uint32_t targetMB,
      bool merge, unsigned expectedLookup)
   {
      if (lines.size() < 2) {
         throw std::runtime_error("1");
      }

      //restore the wallet
      auto refId = rand();
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

      {
         capnp::MallocMessageBuilder message;
         auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
         toBridge.setReferenceId(refId);
         auto request = toBridge.initUtils();
         auto restoreWltReq = request.initRestoreWallet();

         restoreWltReq.setCallbackId(callbackId);

         size_t lineIndex = 0;
         if (lines.size() == 5) {
            restoreWltReq.setBackupId(lines[lineIndex++]);
         }

         auto rootLines = restoreWltReq.initRoot(2);
         rootLines.set(0, lines[lineIndex++]);
         rootLines.set(1, lines[lineIndex++]);

         if (lineIndex < lines.size()) {
            auto ccLines = restoreWltReq.initChaincode(2);
            ccLines.set(0, lines[lineIndex++]);
            ccLines.set(1, lines[lineIndex++]);
         }

         auto rawReq = serializeCapnp(message);
         pushRequest(bridge_, rawReq);
      }

      //backup deser notifs
      unsigned notifCount = 0;
      bool restoringBackup = true;
      while (restoringBackup) {
         auto result = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(result->data.getPtr()),
            result->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
         if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
            throw std::runtime_error("2");
         }

         auto notif = fromBridge.getNotification();
         if (notif.getCallbackId() != callbackId) {
            throw std::runtime_error("3");
         }

         switch (notif.which())
         {
            case Codec::Bridge::Notification::RESTORE:
            {
               auto restoreNotif = notif.getRestore();
               switch (restoreNotif.which())
               {
                  case Codec::Bridge::Notification::RestorePrompt::CHECK_WALLET_ID:
                  {
                     //return merge decision
                     auto meta = restoreNotif.getCheckWalletId();
                     if (meta.getWalletId() != expectedWltId ||
                        meta.getBackupType() != backupType) {
                        throw std::runtime_error("4");
                     }

                     auto counter = notif.getCounter();
                     capnp::MallocMessageBuilder notifMsg;
                     auto toBridge = notifMsg.initRoot<Codec::Bridge::ToBridge>();
                     toBridge.setReferenceId(rand());

                     auto notifReply = toBridge.initNotification();
                     notifReply.setSuccess(true);
                     notifReply.setCounter(counter);
                     notifReply.setRestore(merge ?
                        Codec::Bridge::NotificationReply::RestoreMode::MERGE :
                        Codec::Bridge::NotificationReply::RestoreMode::OVERWRITE
                     );

                     auto rawReq = serializeCapnp(notifMsg);
                     pushRequest(bridge_, rawReq);
                     restoringBackup = false;
                     break;
                  }

                  default:
                     throw std::runtime_error("5");
               }

               break;
            }

            default:
               throw std::runtime_error("6");
         }
      }

      //create wallet notifs
      auto wltData = progressWalletCreation(callbackId,
         passphrase, targetMs, targetMB,
         expectedLookup, lines.size() == 5);

      //validate reply
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
         throw std::runtime_error("7");
      }

      auto reply = fromBridge.getReply();
      if (!reply.getSuccess() || reply.getReferenceId() != refId) {
         throw std::runtime_error("8");
      }
      return wltData;
   }

public:
   std::filesystem::path homedir;
   std::shared_ptr<Bridge::CppBridge> bridge_;
};

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, ListStageLoad)
{
   /*
   This test covers the same scenario as WalletManagerTests.ListStageLoad,
   but through CppBridge rather than WalletManager directly
   */
   std::vector<std::pair<std::filesystem::path, std::string>> walletFiles;

   //wallet 1
   {
      Wallets::IO::CreateWalletParams params{
         homedir,
         {1ms, 0, SecureBinaryData::fromString("privpass1")},
         {},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletFiles.emplace_back(
         std::make_pair(assetWlt->getDbFilename(), assetWlt->getID()));
   }

   //wallet 2, 3, 4
   for (unsigned i=2; i<5; i++) {
      Wallets::IO::CreateWalletParams params{
         homedir,
         {1ms, 0, SecureBinaryData::fromString("privpass" + std::to_string(i))},
         {1ms, 0, SecureBinaryData::fromString("controlpass" + std::to_string(i))},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletFiles.emplace_back(
         std::make_pair(assetWlt->getDbFilename(), assetWlt->getID()));
   }

   //list wallets
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 4);
      auto checkWltList = [&wltList, &walletFiles](
         unsigned intId, int expectedState, bool expectedStaged)->bool
      {
         auto entry = walletFiles[intId];
         auto path = entry.first.filename().string();
         auto capnEntry = wltList.at(path);

         if (capnEntry.loadState != expectedState) {
            return false;
         }

         if (expectedState == CapnWalletState_Ready) {
            if (capnEntry.walletId != entry.second) {
               return false;
            }
         }
         return capnEntry.staged == expectedStaged;
      };
      EXPECT_TRUE(checkWltList(0, CapnWalletState_Ready, true));
      EXPECT_TRUE(checkWltList(1, CapnWalletState_Encrypted, false));
      EXPECT_TRUE(checkWltList(2, CapnWalletState_Encrypted, false));
      EXPECT_TRUE(checkWltList(3, CapnWalletState_Encrypted, false));
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //unlock wallets 3 & 4
   ASSERT_TRUE(unlockWallet(walletFiles[2].first.filename().string(), "controlpass3"));
   ASSERT_TRUE(unlockWallet(walletFiles[3].first.filename().string(), "controlpass4"));

   //list wallets again, check for unlocks
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 4);
      auto checkWltList = [&wltList, &walletFiles](
         unsigned intId, int expectedState, bool expectedStaged)->bool
      {
         auto entry = walletFiles[intId];
         auto path = entry.first.filename().string();
         auto capnEntry = wltList.at(path);

         if (capnEntry.loadState != expectedState) {
            return false;
         }

         if (expectedState == CapnWalletState_Ready) {
            if (capnEntry.walletId != entry.second) {
               return false;
            }
         }
         return capnEntry.staged == expectedStaged;
      };
      EXPECT_TRUE(checkWltList(0, CapnWalletState_Ready, true));
      EXPECT_TRUE(checkWltList(1, CapnWalletState_Encrypted, false));
      EXPECT_TRUE(checkWltList(2, CapnWalletState_Ready, true));
      EXPECT_TRUE(checkWltList(3, CapnWalletState_Ready, true));
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //fail to unlock wallet 2
   ASSERT_EQ(failToUnlockWallet(walletFiles[1].first.filename().string(), 2), 3);

   //unstage wallet 4
   stageWallet(walletFiles[3].second, false);

   //list wallets again, check for staging
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 4);
      auto checkWltList = [&wltList, &walletFiles](
         unsigned intId, int expectedState, bool expectedStaged)->bool
      {
         auto entry = walletFiles[intId];
         auto path = entry.first.filename().string();
         auto capnEntry = wltList.at(path);

         if (capnEntry.loadState != expectedState) {
            return false;
         }

         if (expectedState == CapnWalletState_Ready) {
            if (capnEntry.walletId != entry.second) {
               return false;
            }
         }
         return capnEntry.staged == expectedStaged;
      };
      EXPECT_TRUE(checkWltList(0, CapnWalletState_Ready, true));
      EXPECT_TRUE(checkWltList(1, CapnWalletState_Encrypted, false));
      EXPECT_TRUE(checkWltList(2, CapnWalletState_Ready, true));
      EXPECT_TRUE(checkWltList(3, CapnWalletState_Ready, false));
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //load wallets
   auto wallets = loadWallets(bridge_);
   ASSERT_EQ(wallets.size(), 2);
   EXPECT_NE(wallets.find(walletFiles[0].second), wallets.end());
   EXPECT_NE(wallets.find(walletFiles[2].second), wallets.end());

   //list wallets one last time
   //list wallets again, check for staging
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 2);
      auto checkWltList = [&wltList, &walletFiles](
         unsigned intId, int expectedState, bool expectedStaged)->bool
      {
         auto entry = walletFiles[intId];
         auto path = entry.first.filename().string();
         auto capnEntry = wltList.at(path);

         if (capnEntry.loadState != expectedState) {
            return false;
         }

         if (expectedState == CapnWalletState_Ready) {
            if (capnEntry.walletId != entry.second) {
               return false;
            }
         }
         return capnEntry.staged == expectedStaged;
      };
      EXPECT_TRUE(checkWltList(1, CapnWalletState_Encrypted, false));
      EXPECT_TRUE(checkWltList(3, CapnWalletState_Ready, false));
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, ListWO)
{
   std::vector<std::pair<std::filesystem::path, std::string>> wltPaths;
   std::string walletId;

   //wallet 1
   {
      Wallets::IO::CreateWalletParams params{
         homedir,
         {1ms, 0, SecureBinaryData::fromString("privpass1")},
         {1ms, 0, SecureBinaryData::fromString("ctrlPass")},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletId = assetWlt->getID();
      wltPaths.emplace_back(std::make_pair(
         assetWlt->getDbFilename(), walletId));
   }

   {
      const auto& fullWltPath = wltPaths.begin()->first;
      auto woWltPath = Wallets::AssetWallet::forkWatchingOnly({fullWltPath,
         [](const std::set<Wallets::EncryptionKeyId>&)->Passphrase::Result
         {
            return { SecureBinaryData::fromString("ctrlPass"), true };
         }},
         {1ms, 0, SecureBinaryData::fromString("woPass")}
      );
      ASSERT_FALSE(woWltPath.empty());
      ASSERT_TRUE(FileUtils::fileExists(woWltPath, 0));
      ASSERT_NE(woWltPath, fullWltPath);
      wltPaths.emplace_back(std::make_pair(
         woWltPath, walletId));
   }

   //list wallets
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 2);
      auto checkWltList = [&wltList, &wltPaths](
         unsigned intId, int expectedState, bool expectedStaged)->bool
      {
         auto entry = wltPaths[intId];
         auto path = entry.first.filename().string();
         auto capnEntry = wltList.at(path);

         if (capnEntry.loadState != expectedState) {
            return false;
         }

         if (expectedState == CapnWalletState_Ready) {
            if (capnEntry.walletId != entry.second) {
               return false;
            }
         }

         //encrypted wallets show up as not WO (can't be determined yet)
         if (capnEntry.isWO) {
            return false;
         }
         return capnEntry.staged == expectedStaged;
      };
      EXPECT_TRUE(checkWltList(0, CapnWalletState_Encrypted, false));
      EXPECT_TRUE(checkWltList(1, CapnWalletState_Encrypted, false));
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //unlock them
   ASSERT_TRUE(unlockWallet(wltPaths[0].first.filename().string(), "ctrlPass"));
   ASSERT_TRUE(unlockWallet(wltPaths[1].first.filename().string(), "woPass"));

   //list again
   try {
      std::vector<std::string> wltIds;
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 2);
      auto checkWltList = [&wltList, &wltPaths, &wltIds](
         unsigned intId, int expectedState,
         bool expectedStaged, bool isWO)->bool
      {
         auto entry = wltPaths[intId];
         auto path = entry.first.filename().string();
         auto capnEntry = wltList.at(path);

         if (capnEntry.loadState != expectedState) {
            return false;
         }

         if (expectedState == CapnWalletState_Ready) {
            if (capnEntry.walletId != entry.second) {
               return false;
            }
            wltIds.emplace_back(capnEntry.walletId);
         }

         if (isWO != capnEntry.isWO) {
            return false;
         }
         return capnEntry.staged == expectedStaged;
      };
      EXPECT_TRUE(checkWltList(0, CapnWalletState_Ready, true, false));
      EXPECT_TRUE(checkWltList(1, CapnWalletState_Ready, true, true));

      ASSERT_EQ(wltIds.size(), 2);
      ASSERT_EQ(wltIds[0], wltIds[1]);
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, CreateWallet)
{
   //create the wallet
   auto refId = rand();
   auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

   capnp::MallocMessageBuilder message;
   auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
   toBridge.setReferenceId(refId);
   auto request = toBridge.initUtils();
   auto createWltReq = request.initCreateWallet();

   createWltReq.setCallbackId(callbackId);
   createWltReq.setLookup(100);
   createWltReq.setLabel("labl");
   createWltReq.setDescription("desc");

   auto rawReq = serializeCapnp(message);
   pushRequest(bridge_, rawReq);

   //handle progress notifs
   std::string masterId;
   std::filesystem::path path;
   try {
      auto walletData = progressWalletCreation(callbackId,
         "pass1", 500ms, 128, 100);
      masterId = walletData.masterId;
      path = walletData.path;
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //validate reply
   auto result = waitOnReply();
   kj::ArrayPtr<const capnp::word> words(
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word));
   capnp::FlatArrayMessageReader reader(words);
   auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   auto reply = fromBridge.getReply();
   ASSERT_TRUE(reply.getSuccess());
   ASSERT_EQ(reply.getReferenceId(), refId);

   ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::UTILS);
   auto utilsReply = reply.getUtils();
   ASSERT_EQ(utilsReply.which(), Codec::Bridge::UtilsReply::CREATE_WALLET);
   std::string wltId = utilsReply.getCreateWallet();
   ASSERT_FALSE(wltId.empty());

   //get the wallet data & validate it
   auto wltData = getWalletData(bridge_, wltId);
   EXPECT_EQ(wltData.walletId, wltId);
   EXPECT_FALSE(wltData.accountId.empty());
   EXPECT_EQ(wltData.path.filename().string(), path);
   EXPECT_EQ(wltData.masterId, masterId);

   EXPECT_EQ(wltData.label, "labl");
   EXPECT_EQ(wltData.desc, "desc");

   EXPECT_TRUE(wltData.encrypted);
   EXPECT_FALSE(wltData.watchingOnly);
   EXPECT_EQ(wltData.addresses.size(), 1);
   EXPECT_EQ(wltData.kdfMemReq, 128);

   /* extras
      1. KDF unlock time
      2. change passphrase
      3. change KDF
      4. remove passphrase
   */

   //1 request KDF unlock time
   auto unlockTime = testKDFUnlock(wltId);
   EXPECT_GE(unlockTime, 500ms) << unlockTime.count();
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, DeleteWallet)
{
   std::string masterId;
   std::filesystem::path path;
   std::string wltId;

   {
      //create the wallet
      auto refId = rand();
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initUtils();
      auto createWltReq = request.initCreateWallet();

      createWltReq.setCallbackId(callbackId);
      createWltReq.setLookup(100);
      createWltReq.setLabel("labl");
      createWltReq.setDescription("desc");

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      //handle progress notifs
      try {
         auto walletData = progressWalletCreation(callbackId,
            "pass1", 500ms, 0, 100);
         masterId = walletData.masterId;
         path = walletData.path;
      } catch (const std::exception& e) {
         ASSERT_TRUE(false) << e.what();
      }

      //validate reply
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      ASSERT_TRUE(reply.getSuccess());
      ASSERT_EQ(reply.getReferenceId(), refId);

      ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::UTILS);
      auto utilsReply = reply.getUtils();
      ASSERT_EQ(utilsReply.which(), Codec::Bridge::UtilsReply::CREATE_WALLET);
      wltId = utilsReply.getCreateWallet();
   }

   //get the wallet data & validate it
   ASSERT_FALSE(wltId.empty());
   auto wltData = getWalletData(bridge_, wltId);
   EXPECT_EQ(wltData.walletId, wltId);
   EXPECT_FALSE(wltData.accountId.empty());
   ASSERT_FALSE(path.empty());
   EXPECT_EQ(wltData.path.filename().string(), path);
   EXPECT_EQ(wltData.masterId, masterId);

   EXPECT_EQ(wltData.label, "labl");
   EXPECT_EQ(wltData.desc, "desc");

   EXPECT_TRUE(wltData.encrypted);
   EXPECT_FALSE(wltData.watchingOnly);
   EXPECT_EQ(wltData.addresses.size(), 1);
   EXPECT_EQ(wltData.kdfMemReq, 8);

   //check wallet path
   auto fullWltPath = homedir / path;
   ASSERT_TRUE(FileUtils::fileExists(fullWltPath, 0));

   //delete said wallet
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWalletManager();
      request.setDeleteWallet(wltId);
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      //validate reply
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto reply = fromBridge.getReply();
      ASSERT_TRUE(reply.getSuccess());
      ASSERT_EQ(reply.getReferenceId(), refId);
      ASSERT_FALSE(FileUtils::fileExists(fullWltPath, 0));
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, CreateWallet_Reject)
{
   //create the wallet
   auto refId = rand();
   auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

   capnp::MallocMessageBuilder message;
   auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
   toBridge.setReferenceId(refId);
   auto request = toBridge.initUtils();
   auto createWltReq = request.initCreateWallet();

   createWltReq.setCallbackId(callbackId);
   createWltReq.setLookup(100);
   createWltReq.setLabel("labl");
   createWltReq.setDescription("desc");

   auto rawReq = serializeCapnp(message);
   pushRequest(bridge_, rawReq);

   //handle progress notifs
   try {
      auto walletData = progressWalletCreation(callbackId,
         std::string{}, 500ms, 128, 100);
      ASSERT_FALSE(walletData.masterId.empty());
      ASSERT_FALSE(walletData.path.empty());

      //check file is cleaned up
      EXPECT_FALSE(FileUtils::fileExists(
         std::filesystem::path{"./fakehomedir"} / walletData.path, 0));
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //validate reply
   auto result = waitOnReply();
   kj::ArrayPtr<const capnp::word> words(
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word));
   capnp::FlatArrayMessageReader reader(words);
   auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   auto reply = fromBridge.getReply();
   ASSERT_FALSE(reply.getSuccess());
   ASSERT_EQ(reply.getReferenceId(), refId);
   std::string errorStr = reply.getError();
   EXPECT_EQ(errorStr, std::string{"passphrase request was rejected"});
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, RestoreWallet_Legacy)
{
   const std::string walletId{"292AxMD9H"};
   const std::vector<std::string> lines {
      "oiow rfta wueg hewo  wuaj jawj rddi uufu  tusi",
      "idnt enrd sjgo tgfi  esni eutw ktna ustg  arfe",
      "jdtf fink jshs ewda  kkor daet kgtr eiha  ejgd",
      "uaew ggod ngjk ejuu  rugf kufg awnn ofas  rhtf"
   };
   const std::string passphrase{"privPassTest"};

   //restore the wallet
   auto restoreData = restoreWallet(lines, walletId,
      Codec::Bridge::WalletBackup::Type::LEGACY135_A,
      passphrase, 300ms, 32, false, 500);

   //get the wallet data & validate it
   auto wltData = getWalletData(bridge_, walletId);
   EXPECT_EQ(wltData.walletId, walletId);
   EXPECT_FALSE(wltData.accountId.empty());
   EXPECT_EQ(wltData.path.filename(), restoreData.path);
   EXPECT_EQ(wltData.masterId, restoreData.masterId);

   EXPECT_TRUE(wltData.encrypted);
   EXPECT_FALSE(wltData.watchingOnly);
   EXPECT_EQ(wltData.addresses.size(), 1);
   EXPECT_EQ(wltData.lookup, 500);
   EXPECT_EQ(wltData.kdfMemReq, 32);

   //request KDF unlock time
   auto unlockTime = testKDFUnlock(walletId);
   EXPECT_GE(unlockTime, 300ms) << unlockTime.count();

   //grab backup strings via callback
   {
      auto refId = rand();
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(walletId);
      auto reqBackup = request.initCreateBackupString();
      reqBackup.setPrivate(callbackId);
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      //wait for unlock request
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      auto notif = fromBridge.getNotification();
      ASSERT_EQ(notif.getCallbackId(), callbackId);
      ASSERT_EQ(notif.which(), Codec::Bridge::Notification::UNLOCK_REQUEST);

      //reply with passphrase
      capnp::MallocMessageBuilder notifMsg;
      auto notifBridge = notifMsg.initRoot<Codec::Bridge::ToBridge>();
      auto notifReply = notifBridge.initNotification();
      notifReply.setSuccess(true);
      notifReply.setCounter(notif.getCounter());
      notifReply.setUnlockRequest(passphrase);

      auto rawNotif = serializeCapnp(notifMsg);
      pushRequest(bridge_, rawNotif);

      //cleanup notif
      result = waitOnReply();
      words = kj::ArrayPtr<const capnp::word>(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      reader = capnp::FlatArrayMessageReader(words);
      fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      notif = fromBridge.getNotification();
      ASSERT_EQ(notif.which(), Codec::Bridge::Notification::CLEANUP);

      //check the backup
      auto backup = waitOnReply();
      words = kj::ArrayPtr<const capnp::word>(
         reinterpret_cast<const capnp::word*>(backup->data.getPtr()),
         backup->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader replyReader(words);
      fromBridge = replyReader.getRoot<Codec::Bridge::FromBridge>();
      ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::REPLY);
      auto reply = fromBridge.getReply();
      ASSERT_TRUE(reply.getSuccess());
      ASSERT_EQ(reply.getReferenceId(), refId);

      ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::WALLET);
      auto walletReply = reply.getWallet();
      ASSERT_EQ(walletReply.which(), Codec::Bridge::WalletReply::CREATE_BACKUP_STRING);

      auto capnBackup = walletReply.getCreateBackupString();
      auto rootLines = capnBackup.getRootClear();
      ASSERT_EQ(rootLines.size(), 2);
      ASSERT_EQ(rootLines[0], lines[0]);
      ASSERT_EQ(rootLines[1], lines[1]);

      auto chainLines = capnBackup.getChainClear();
      ASSERT_EQ(chainLines.size(), 2);
      ASSERT_EQ(chainLines[0], lines[2]);
      ASSERT_EQ(chainLines[1], lines[3]);
   }

   //grab backup strings via passphrase
   try {
      auto capnLines = getBackup(walletId, passphrase,
         Codec::Bridge::WalletBackup::Type::LEGACY135_A);
      ASSERT_EQ(capnLines.size(), 4);

      for (unsigned i=0; i<4; i++) {
         ASSERT_EQ(lines[i], capnLines[i]);
      }
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, RestoreWallet_LegacyWO)
{
   const std::string walletId{"292AxMD9H"};
   const std::vector<std::string> lines {
      "wswg egsh oghk aaaj eu",
      "kdrk ouid agee jttn tfaa ruun twsu jfgu nasj",
      "otrr egjh farw dfuo gddh ugki fhrt dgeh geth",
      "jdtf fink jshs ewda kkor daet kgtr eiha ejgd",
      "uaew ggod ngjk ejuu rugf kufg awnn ofas rhtf",
   };
   const std::string passphrase{"privPassTest"};

   //restore the wallet
   auto restoreData = restoreWallet(lines, walletId,
      Codec::Bridge::WalletBackup::Type::LEGACY135_A,
      passphrase, 300ms, 32, false, 500);

   //get the wallet data & validate it
   auto wltData = getWalletData(bridge_, walletId);
   EXPECT_EQ(wltData.walletId, walletId);
   EXPECT_FALSE(wltData.accountId.empty());
   EXPECT_EQ(wltData.path.filename(), restoreData.path);
   EXPECT_EQ(wltData.masterId, restoreData.masterId);

   EXPECT_FALSE(wltData.encrypted);
   EXPECT_TRUE(wltData.watchingOnly);
   EXPECT_EQ(wltData.addresses.size(), 1);
   EXPECT_EQ(wltData.lookup, 500);
   EXPECT_EQ(wltData.kdfMemReq, 0);

   //grab backup strings
   {
      auto refId = rand();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(walletId);
      auto reqBackup = request.initCreateBackupString();
      reqBackup.setPublic();
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      //check the backup
      auto backup = waitOnReply();
      auto words = kj::ArrayPtr<const capnp::word>(
         reinterpret_cast<const capnp::word*>(backup->data.getPtr()),
         backup->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader replyReader(words);
      auto fromBridge = replyReader.getRoot<Codec::Bridge::FromBridge>();
      ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::REPLY);
      auto reply = fromBridge.getReply();
      ASSERT_TRUE(reply.getSuccess());
      ASSERT_EQ(reply.getReferenceId(), refId);

      ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::WALLET);
      auto walletReply = reply.getWallet();
      ASSERT_EQ(walletReply.which(), Codec::Bridge::WalletReply::CREATE_BACKUP_STRING);

      auto capnBackup = walletReply.getCreateBackupString();
      auto rootLines = capnBackup.getRootClear();
      ASSERT_EQ(rootLines.size(), 2);
      ASSERT_EQ(rootLines[0], lines[1]);
      ASSERT_EQ(rootLines[1], lines[2]);

      auto chainLines = capnBackup.getChainClear();
      ASSERT_EQ(chainLines.size(), 2);
      ASSERT_EQ(chainLines[0], lines[3]);
      ASSERT_EQ(chainLines[1], lines[4]);

      //backupid
      auto backupId = capnBackup.getBackupId();
      ASSERT_EQ(backupId, lines[0]);
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, RestoreMerge)
{
   //create the wallet
   auto refId = rand();
   auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();
   std::string passphrase{"pass2"};
   std::string passphrase2{"pass3"};
   unsigned lookup = 46;

   capnp::MallocMessageBuilder message;
   auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
   toBridge.setReferenceId(refId);
   auto request = toBridge.initUtils();
   auto createWltReq = request.initCreateWallet();

   createWltReq.setCallbackId(callbackId);
   createWltReq.setLookup(lookup);
   createWltReq.setLabel("labl2");
   createWltReq.setDescription("desc2");

   auto rawReq = serializeCapnp(message);
   pushRequest(bridge_, rawReq);

   //handle progress notifs
   std::string masterId;
   std::filesystem::path path;
   try {
      auto walletData = progressWalletCreation(callbackId,
         passphrase, 500ms, 128, lookup);
      masterId = walletData.masterId;
      path = walletData.path;
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //validate reply
   auto result = waitOnReply();
   kj::ArrayPtr<const capnp::word> words(
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word));
   capnp::FlatArrayMessageReader reader(words);
   auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   auto reply = fromBridge.getReply();
   ASSERT_TRUE(reply.getSuccess());
   ASSERT_EQ(reply.getReferenceId(), refId);

   ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::UTILS);
   auto utilsReply = reply.getUtils();
   ASSERT_EQ(utilsReply.which(), Codec::Bridge::UtilsReply::CREATE_WALLET);
   std::string wltId = utilsReply.getCreateWallet();
   ASSERT_FALSE(wltId.empty());

   //get the wallet data & validate it
   auto wltData = getWalletData(bridge_, wltId);
   EXPECT_EQ(wltData.walletId, wltId);
   EXPECT_FALSE(wltData.accountId.empty());
   EXPECT_EQ(wltData.path.filename().string(), path);
   EXPECT_EQ(wltData.masterId, masterId);

   EXPECT_EQ(wltData.label, "labl2");
   EXPECT_EQ(wltData.desc, "desc2");

   EXPECT_TRUE(wltData.encrypted);
   EXPECT_FALSE(wltData.watchingOnly);
   EXPECT_EQ(wltData.addresses.size(), 1);
   EXPECT_EQ(wltData.lookup, lookup);
   EXPECT_EQ(wltData.kdfMemReq, 128);

   //grab 3 addresses
   std::vector<AddressData> addresses;
   addresses.emplace_back(*wltData.addresses.begin());
   for (unsigned i=0; i<3; i++) {
      addresses.emplace_back(getAddress(bridge_, wltId, wltData.accountId));
   }

   for (unsigned i=0; i<4; i++) {
      const auto& addr = addresses[i];
      ASSERT_EQ(addr.index, i);
      ASSERT_FALSE(addr.hash.empty());
   }

   //grab the backup strings
   std::vector<std::string> lines;
   try {
      lines = getBackup(wltId, passphrase,
         Codec::Bridge::WalletBackup::Type::LEGACY200_A);
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //restore merge the wallet
   ASSERT_EQ(lines.size(), 2);
   for (const auto& line : lines) {
      ASSERT_FALSE(line.empty());
   }
   auto restoreData = restoreWallet(lines, wltId,
      Codec::Bridge::WalletBackup::Type::LEGACY200_A,
      passphrase2, 1ms, 0, true,
      //the legacy armory account always starts with asset 0
      lookup - 1
   );
   ASSERT_EQ(restoreData.masterId, masterId);
   ASSERT_EQ(restoreData.path, path);

   //validate restored wallet state
   auto wltData2 = getWalletData(bridge_, wltId);
   EXPECT_EQ(wltData2.walletId, wltId);
   EXPECT_EQ(wltData2.accountId, wltData.accountId);
   EXPECT_EQ(wltData2.path.filename().string(), path);
   EXPECT_EQ(wltData2.masterId, masterId);

   EXPECT_EQ(wltData2.label, "labl2");
   EXPECT_EQ(wltData2.desc, "desc2");

   EXPECT_TRUE(wltData2.encrypted);
   EXPECT_FALSE(wltData2.watchingOnly);
   EXPECT_EQ(wltData2.addresses.size(), 4);
   EXPECT_EQ(wltData2.lookup, lookup);

   for (const auto& addr : wltData2.addresses) {
      ASSERT_LT(addr.index, 4);
      const auto& addrI = addresses[addr.index];
      ASSERT_EQ(addr.hash, addrI.hash);
   }

   //check it unlocks with passphrase2
   std::vector<std::string> lines2;
   try {
      lines2 = getBackup(wltId, passphrase2,
         Codec::Bridge::WalletBackup::Type::LEGACY200_A);
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }
   EXPECT_EQ(lines, lines2);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, Migrate_Legacy)
{
   //copy test legacy wallet to datadir
   const std::string wltId{"28m472Xbm"sv};
   const std::string fileName = std::string{"armory_"sv} +
      std::string{wltId} +
      std::string{"_.wallet"sv};
   const std::filesystem::path wltPath{fileName};
   std::filesystem::copy(
      "input_files/legacy.wallet"sv,
      homedir / wltPath
   );

   //list the wallet
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 1);

      auto wltInfoLegacy = wltList.at(fileName);
      ASSERT_EQ(wltInfoLegacy.walletId, wltId);
      ASSERT_FALSE(wltInfoLegacy.staged);
      ASSERT_EQ(wltInfoLegacy.loadState, 1);
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   //migrate it
   auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();
   auto refId = rand();
   {
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto mgrRequest = toBridge.initWalletManager();
      auto migrationRequest = mgrRequest.initMigrateWallet();
      migrationRequest.setWalletPath(fileName);
      migrationRequest.setCallbackId(callbackId);
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);
   }

   /* handle migration callbacks */

   //unlock notif
   {
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::NOTIFICATION);

      auto notif = fromBridge.getNotification();
      ASSERT_EQ (notif.getCallbackId(), callbackId);
      auto counter = notif.getCounter();

      ASSERT_EQ(notif.which(), Codec::Bridge::Notification::UNLOCK_REQUEST);

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      auto notifReply = toBridge.initNotification();
      notifReply.setSuccess(true);
      notifReply.setCounter(counter);
      notifReply.setUnlockRequest("testnet");
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);
   }

   //progress new wallet creation
   auto wltData = progressWalletCreation(callbackId, "newpass", 250ms, 32, 104);

   //validate success
   auto result = waitOnReply();
   kj::ArrayPtr<const capnp::word> words(
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word));
   capnp::FlatArrayMessageReader reader(words);
   auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::REPLY);
   auto reply = fromBridge.getReply();
   ASSERT_EQ(reply.getReferenceId(), refId);
   ASSERT_TRUE(reply.getSuccess());

   ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::WALLET_MANAGER);
   auto mgrReply = reply.getWalletManager();
   ASSERT_EQ(mgrReply.which(), Codec::Bridge::WalletManagerReply::MIGRATE_WALLET);
   std::string migratedId(mgrReply.getMigrateWallet());

   /* list wallets again, migrated wallet should be staged */
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 2);
      for (const auto& wltInfo : wltList) {
         ASSERT_EQ(wltInfo.second.walletId, wltId);
         if (wltInfo.first == fileName) {
            ASSERT_FALSE(wltInfo.second.staged);
            ASSERT_EQ(wltInfo.second.loadState, CapnWalletState_Legacy);
         } else {
            ASSERT_TRUE(wltInfo.second.staged);
            ASSERT_EQ(wltInfo.second.loadState, CapnWalletState_Ready);
         }
      }
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   {
      auto wallets = loadWallets(bridge_);
      ASSERT_EQ(wallets.size(), 1);
      auto iter = wallets.find(wltId);
      ASSERT_NE(iter, wallets.end());

      ASSERT_TRUE(iter->second.encrypted);
      ASSERT_FALSE(iter->second.watchingOnly);
      EXPECT_EQ(iter->second.kdfMemReq, 32);
      EXPECT_EQ(iter->second.lookup, 104);
      EXPECT_EQ(iter->second.addresses.size(), 3);
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, ImportWallet_Legacy)
{
   std::filesystem::path legacyWalletFile{"input_files/legacy.wallet"sv};
   const std::string walletId{"28m472Xbm"sv};

   /* import the wallet file */
   auto refId = rand();
   capnp::MallocMessageBuilder message;
   auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
   toBridge.setReferenceId(refId);
   auto request = toBridge.initUtils();
   request.setImportWallet(legacyWalletFile.string());
   auto rawReq = serializeCapnp(message);
   pushRequest(bridge_, rawReq);

   auto result = waitOnReply();
   kj::ArrayPtr<const capnp::word> words(
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word));
   capnp::FlatArrayMessageReader reader(words);
   auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   auto reply = fromBridge.getReply();
   ASSERT_TRUE(reply.getSuccess());
   ASSERT_EQ(reply.getReferenceId(), refId);

   /* validate the reply */
   auto utilsReply = reply.getUtils();
   auto wltReply = utilsReply.getImportWallet();

   //type
   EXPECT_EQ(wltReply.which(),
      Codec::Bridge::WalletImportPreview::LEGACY);

   //id
   std::string capnWltId(wltReply.getWalletId());
   EXPECT_EQ(capnWltId, walletId);

   //label
   std::string capnLabel(wltReply.getLabel());
   EXPECT_EQ(capnLabel, "legacy1");

   //description
   std::string capnDesc(wltReply.getDescription());
   EXPECT_EQ(capnDesc, "migration test");

   //address count & index
   EXPECT_EQ(wltReply.getHighestUsedIndex(), 2);
   EXPECT_EQ(wltReply.getAddressCount(), 104);

   //priv keys
   EXPECT_FALSE(wltReply.getWatchingOnly());
   EXPECT_TRUE(wltReply.getEncrypted());
   EXPECT_EQ(wltReply.getKdfMem(), 32 * 1024 * 1024);

   //version
   EXPECT_EQ(wltReply.getSeedVersion(), "1.35");

   /* check wallet was imported to the manager */
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 1);

      auto wltInfoLegacy = wltList.at(legacyWalletFile.filename().string());
      ASSERT_EQ(wltInfoLegacy.walletId, walletId);
      ASSERT_FALSE(wltInfoLegacy.staged);
      ASSERT_EQ(wltInfoLegacy.loadState, 1);
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   /* migrate the wallet */
   auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();
   refId = rand();
   {
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto mgrRequest = toBridge.initWalletManager();
      auto migrationRequest = mgrRequest.initMigrateWallet();
      migrationRequest.setWalletPath(legacyWalletFile.filename().string());
      migrationRequest.setCallbackId(callbackId);
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);
   }

   /* handle migration callbacks */

   //unlock notif
   {
      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
      ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::NOTIFICATION);

      auto notif = fromBridge.getNotification();
      ASSERT_EQ (notif.getCallbackId(), callbackId);
      auto counter = notif.getCounter();

      ASSERT_EQ(notif.which(), Codec::Bridge::Notification::UNLOCK_REQUEST);

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      auto notifReply = toBridge.initNotification();
      notifReply.setSuccess(true);
      notifReply.setCounter(counter);
      notifReply.setUnlockRequest("testnet");
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);
   }

   //progress new wallet creation
   auto wltData = progressWalletCreation(callbackId, "newpass", 250ms, 32, 104);

   //validate success
   result = waitOnReply();
   words = kj::ArrayPtr<const capnp::word>{
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word)};
   reader = capnp::FlatArrayMessageReader{words};
   fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::REPLY);
   reply = fromBridge.getReply();
   ASSERT_EQ(reply.getReferenceId(), refId);
   ASSERT_TRUE(reply.getSuccess());

   ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::WALLET_MANAGER);
   auto mgrReply = reply.getWalletManager();
   ASSERT_EQ(mgrReply.which(), Codec::Bridge::WalletManagerReply::MIGRATE_WALLET);
   std::string migratedId(mgrReply.getMigrateWallet());

   /* list wallets again, migrated wallet should be staged */
   try {
      auto wltList = listWallets(bridge_);
      ASSERT_EQ(wltList.size(), 2);
      for (const auto& wltInfo : wltList) {
         ASSERT_EQ(wltInfo.second.walletId, walletId);
         if (wltInfo.first == legacyWalletFile.filename()) {
            ASSERT_FALSE(wltInfo.second.staged);
            ASSERT_EQ(wltInfo.second.loadState, CapnWalletState_Legacy);
         } else {
            ASSERT_TRUE(wltInfo.second.staged);
            ASSERT_EQ(wltInfo.second.loadState, CapnWalletState_Ready);
         }
      }
   } catch (const std::exception& e) {
      ASSERT_TRUE(false) << e.what();
   }

   {
      auto wallets = loadWallets(bridge_);
      ASSERT_EQ(wallets.size(), 1);
      auto iter = wallets.find(walletId);
      ASSERT_NE(iter, wallets.end());

      ASSERT_TRUE(iter->second.encrypted);
      ASSERT_FALSE(iter->second.watchingOnly);
      EXPECT_EQ(iter->second.kdfMemReq, 32);
      EXPECT_EQ(iter->second.lookup, 104);
      EXPECT_EQ(iter->second.addresses.size(), 3);
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, ChangeWalletPassphrase)
{
   /* 1. create an encrypted wallet */
   std::filesystem::path walletPath;
   std::string walletId;

   std::string currentPass{"privPass1"};
   std::string newPass{"newPrivPass2"};

   //wallet 1
   {
      Wallets::IO::CreateWalletParams params{
         homedir,
         {500ms, 0, SecureBinaryData::fromString(currentPass)},
         {1ms, 0, {}},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletPath = assetWlt->getDbFilename();
      walletId = assetWlt->getID();
   }
   ASSERT_FALSE(walletId.empty());

   /* 2. load it into bridge */
   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 1);
   ASSERT_EQ(wltList.begin()->first, walletPath.filename().string());

   {
      const auto& wltEntry = wltList.begin()->second;
      ASSERT_EQ(wltEntry.loadState, (int)Bridge::WalletLoadState::Ready);
      ASSERT_TRUE(wltEntry.staged);
      EXPECT_EQ(wltEntry.walletId, walletId);
   }

   auto wallets = loadWallets(bridge_);
   ASSERT_EQ(wallets.size(), 1);
   ASSERT_EQ(wallets.begin()->first, walletId);

   /* 3. check current passphrase, grab backup */
   auto now = std::chrono::system_clock::now();
   auto wltBackupLines = getBackup(walletId, currentPass,
      Codec::Bridge::WalletBackup::Type::LEGACY200_A);
   auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now() - now);
   EXPECT_GE(elapsed, 500ms);
   ASSERT_EQ(wltBackupLines.size(), 2);
   ASSERT_EQ(wltBackupLines[0].size(), 46);
   ASSERT_EQ(wltBackupLines[1].size(), 46);
   ASSERT_NE(wltBackupLines[0], wltBackupLines[1]);

   /* 4. change its passphrase */
   EXPECT_TRUE(changeWalletPassphrase(bridge_, walletId,
      currentPass, newPass));

   /* 5. check current passphrase fails to unlock wallet */
   try {
      auto newLines = getBackup(walletId, currentPass,
         Codec::Bridge::WalletBackup::Type::LEGACY200_A);
      ASSERT_TRUE(false);
   } catch (const std::exception& e) {
      EXPECT_EQ(e.what(), std::string{"unlock request rejected"});
   }

   /* 6. check new passphrase unlocks wallet */
   try {
      auto now = std::chrono::system_clock::now();
      auto newLines = getBackup(walletId, newPass,
         Codec::Bridge::WalletBackup::Type::LEGACY200_A);
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
         std::chrono::system_clock::now() - now);
      EXPECT_GE(elapsed, 500ms);
      ASSERT_EQ(newLines.size(), 2);
      ASSERT_EQ(newLines[0], wltBackupLines[0]);
      ASSERT_EQ(newLines[1], wltBackupLines[1]);
   } catch (const std::exception& e) {
      ASSERT_TRUE(false);
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, ExtendAddressChain)
{
   /*
   NOTE: bridge is offline in this test. It covers the graceful handling of
   attempted wallet registration after generating a batch of fresh addresses
   */
   /* 1. create a wallet */
   std::filesystem::path walletPath;
   std::string walletId;
   std::string accountId;
   std::string dbId;

   //wallet 1
   {
      Wallets::IO::CreateWalletParams params{
         homedir,
         {1ms, 0, SecureBinaryData::fromString("pass1")},
         {1ms, 0, {}},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletPath = assetWlt->getDbFilename();
      walletId = assetWlt->getID();
   }
   ASSERT_FALSE(walletId.empty());

   /* 2. load it into bridge */
   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 1);
   ASSERT_EQ(wltList.begin()->first, walletPath.filename().string());

   {
      const auto& wltEntry = wltList.begin()->second;
      ASSERT_EQ(
         wltEntry.loadState,
         (int)Bridge::WalletLoadState::Ready
      );
      ASSERT_TRUE(wltEntry.staged);
      EXPECT_EQ(wltEntry.walletId, walletId);
   }

   {
      auto wallets = loadWallets(bridge_);
      ASSERT_EQ(wallets.size(), 1);
      auto wltIter = wallets.begin();
      ASSERT_EQ(wltIter->first, walletId);
      ASSERT_EQ(wltIter->second.lookup, 4);
      ASSERT_EQ(wltIter->second.useCount, -1);
      accountId = wltIter->second.accountId;
      dbId = wltIter->second.dbId;
   }

   /* 3. extend its address chain */
   try {
      auto wltData = extendAddressPool(bridge_,
         walletId, accountId, dbId, 10000, false);
      ASSERT_EQ(wltData.walletId, walletId);
      ASSERT_EQ(wltData.accountId, accountId);
      EXPECT_EQ(wltData.useCount, -1);
      EXPECT_EQ(wltData.lookup, 10004);
   } catch (const std::runtime_error& e) {
      ASSERT_TRUE(false) << e.what();
   }

   /* grab wallet data explicitly, check chain again */
   auto walletData = getWalletData(bridge_, walletId);
   ASSERT_EQ(walletData.walletId, walletId);
   ASSERT_EQ(walletData.accountId, accountId);
   EXPECT_EQ(walletData.useCount, -1);
   EXPECT_EQ(walletData.lookup, 10004);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeTests, ForkWO)
{
   std::filesystem::path walletPath;
   std::string walletId;
   std::string accountId;
   std::string dbId;

   //wallet 1
   {
      Wallets::IO::CreateWalletParams params{
         homedir,
         {1ms, 0, SecureBinaryData::fromString("pass1")},
         {1ms, 0, {}},
         nullptr, 4
      };

      std::unique_ptr<Seeds::ClearTextSeed> seed(
         new Seeds::ClearTextSeed_Armory());
      auto assetWlt = Wallets::AssetWallet_Single::createFromSeed(
         std::move(seed), params);
      walletPath = assetWlt->getDbFilename();
      walletId = assetWlt->getID();
   }
   ASSERT_FALSE(walletId.empty());

   /* 2. load it into bridge */
   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 1);
   ASSERT_EQ(wltList.begin()->first, walletPath.filename().string());

   {
      const auto& wltEntry = wltList.begin()->second;
      ASSERT_EQ(
         wltEntry.loadState,
         (int)Bridge::WalletLoadState::Ready
      );
      ASSERT_TRUE(wltEntry.staged);
      EXPECT_EQ(wltEntry.walletId, walletId);
   }

   {
      auto wallets = loadWallets(bridge_);
      ASSERT_EQ(wallets.size(), 1);
      auto wltIter = wallets.begin();
      ASSERT_EQ(wltIter->first, walletId);
      ASSERT_EQ(wltIter->second.lookup, 4);
      ASSERT_EQ(wltIter->second.useCount, -1);
      accountId = wltIter->second.accountId;
      dbId = wltIter->second.dbId;
   }

   /* 3. fork it */
   auto refId = rand();
   {
      auto callbackId = Cryptography::PRNG::fortuna.generateRandom(10).toHexStr();

      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(walletId);
      request.setForkWatchingOnly(callbackId);

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      //deal with notifications
      bool run = true;
      while (run) {
         auto result = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(result->data.getPtr()),
            result->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();

         ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::NOTIFICATION);
         auto notif = fromBridge.getNotification();
         ASSERT_EQ(notif.getCallbackId(), callbackId);
         switch (notif.which())
         {
            case Codec::Bridge::Notification::SET_PASSPHRASE:
            {
               auto counter = notif.getCounter();

               //push passphrase
               capnp::MallocMessageBuilder message;
               auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
               auto notifReply = toBridge.initNotification();
               notifReply.setSuccess(true);
               notifReply.setCounter(counter);
               auto capnSetPass = notifReply.initSetPassphrase();
               capnSetPass.setPassphrase("woCtrlPass");
               capnSetPass.setReuseKdf(true);

               auto rawReq = serializeCapnp(message);
               pushRequest(bridge_, rawReq);
               break;
            }

            case Codec::Bridge::Notification::CLEANUP:
            {
               run = false;
               break;
            }

            /*case Bridge::Notification::WALLET_PROGRESS:
            {
               auto prog = notif.getWalletProgress();
               switch (prog.which())
               {
               }
               break;
            }*/

            default:
               ASSERT_TRUE(false);
         }
      }
   }

   //handle reply
   auto result = waitOnReply();
   kj::ArrayPtr<const capnp::word> words(
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word));
   capnp::FlatArrayMessageReader reader(words);
   auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   ASSERT_EQ(fromBridge.which(), Codec::Bridge::FromBridge::REPLY);

   auto reply = fromBridge.getReply();
   ASSERT_EQ(reply.getReferenceId(), refId);
   ASSERT_TRUE(reply.getSuccess());
   std::filesystem::path woWltPath{
      std::string{reply.getWallet().getForkWatchingOnly()}};
   ASSERT_NE(woWltPath.filename(), walletPath.filename());

   /* unload full wallet */
   {
      auto msgId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(msgId);
      auto request = toBridge.initWalletManager();
      request.setUnloadWallet(walletId);

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      auto result = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(result->data.getPtr()),
         result->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();

      auto reply = fromBridge.getReply();
      ASSERT_EQ(reply.getReferenceId(), msgId);
      ASSERT_TRUE(reply.getSuccess());
   }

   /* load WO wallet */
   wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 1);
   ASSERT_EQ(wltList.begin()->first, woWltPath.filename().string());
   ASSERT_EQ(wltList.begin()->second.loadState, CapnWalletState_Encrypted);

   ASSERT_TRUE(unlockWallet(woWltPath.filename().string(), "woCtrlPass"));
   wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 1);
   ASSERT_EQ(wltList.begin()->first, woWltPath.filename().string());
   ASSERT_EQ(wltList.begin()->second.loadState, CapnWalletState_Ready);

   {
      auto wallets = loadWallets(bridge_);
      ASSERT_EQ(wallets.size(), 1);
      auto wltIter = wallets.begin();
      ASSERT_EQ(wltIter->first, walletId);
      ASSERT_EQ(wltIter->second.lookup, 4);
      ASSERT_EQ(wltIter->second.useCount, -1);
      ASSERT_EQ(wltIter->second.path, woWltPath);
      ASSERT_EQ(wltIter->second.accountId, accountId);
      ASSERT_NE(dbId, wltIter->second.dbId);
   }
}

////////////////////////////////////////////////////////////////////////////////
// BridgeWebsocketsTests
////////////////////////////////////////////////////////////////////////////////
class BridgeWebsocketsTests : public ::testing::Test
{
protected:
   void initBDM()
   {
      theBDMt_ = new BlockDataManagerThread();
      iface_ = theBDMt_->bdm()->getIFace();
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void SetUp()
   {
      FileUtils::removeDirectory(blkdir_);
      FileUtils::removeDirectory(homedir_);
      FileUtils::removeDirectory(ldbdir_);

      FileUtils::createDirectory(blkdir_ / "blocks");
      FileUtils::createDirectory(homedir_);
      FileUtils::createDirectory(ldbdir_);

      Config::DBSettings::setServiceType(SERVICE_UNITTEST_WITHWS);

      // Put the first 5 blocks into the blkdir
      blk0dat_ = FileUtils::getBlkFilename(blkdir_ / "blocks", 0);
      TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);

      Config::parseArgs({
         "--datadir=./fakehomedir",
         "--dbdir=./ldbtestdir",
         "--satoshi-datadir=./blkfiletest",
         "--db-type=DB_FULL",
         "--thread-count=3",
         "--public"},
         Config::ProcessType::DB);

      startupBIP151CTX();
      startupBIP150CTX(4);

      //setup auth peers for server and client
      authPeersPassLbd_ = [](const std::set<Wallets::EncryptionKeyId>&)
      ->Passphrase::Result
      {
         return { {}, true };
      };

      auto createWltLbd = []()->std::unique_ptr<Passphrase::Params>
      {
         return std::make_unique<Passphrase::Params>(
            1ms, 0, SecureBinaryData{});
      };

      Wallets::AuthorizedPeers::createWallet({
         homedir_ / SERVER_AUTH_PEER_FILENAME, {createWltLbd}});
      Wallets::AuthorizedPeers serverPeers(
         {homedir_ / SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_});

      Wallets::AuthorizedPeers::createWallet({
         homedir_ / CLIENT_AUTH_PEER_FILENAME, {createWltLbd}});
      Wallets::AuthorizedPeers clientPeers(
         {homedir_ / CLIENT_AUTH_PEER_FILENAME, authPeersPassLbd_});

      //share public keys between client and server
      auto& serverPubkey = serverPeers.getOwnPublicKey();

      std::stringstream serverAddr;
      serverAddr << "127.0.0.1:" << Config::NetworkSettings::dbPort();
      clientPeers.addPeer(serverPubkey, serverAddr.str());

      serverPubkey_ = BinaryData(serverPubkey.pubkey, 33);
      serverAddr_ = serverAddr.str();

      replyQueue.clear();
      bridge_ = std::make_shared<Bridge::CppBridge>();
      bridge_->setWriteLambda([](MsgPtr payload) {
         std::unique_lock<std::mutex> lock(commsMutex);
         replyQueue.emplace_back(std::move(payload));
         commsCV.notify_all();
      });

      walletId_ = initWOWallet(homedir_);
      initBDM();
      auto nodePtr = std::dynamic_pointer_cast<NodeUnitTest>(
         Config::NetworkSettings::bitcoinNodes().first);
      nodePtr->setIface(theBDMt_->bdm()->getIFace());
      hexMagicBytes = Config::BitcoinSettings::getMagicBytes().toHexStr();
   }

   /////////////////////////////////////////////////////////////////////////////
   virtual void TearDown()
   {
      bridge_.reset();
      WebSocketServer::shutdown();
      WebSocketServer::waitOnShutdown();
      theBDMt_->shutdown();

      delete theBDMt_;
      theBDMt_ = nullptr;

      FileUtils::removeDirectory(blkdir_);
      FileUtils::removeDirectory(homedir_);
      FileUtils::removeDirectory(ldbdir_);
      Config::reset();
   }

protected:
   BlockDataManagerThread *theBDMt_;
   Passphrase::UnlockFunc authPeersPassLbd_;
   LMDBBlockDatabase* iface_;

   std::filesystem::path blkdir_{"./blkfiletest"sv};
   std::filesystem::path homedir_{"./fakehomedir"sv};
   std::filesystem::path ldbdir_{"./ldbtestdir"sv};
   std::filesystem::path blk0dat_;

   BinaryData serverPubkey_;
   std::string serverAddr_;
   std::string hexMagicBytes;
   std::shared_ptr<Bridge::CppBridge> bridge_;
   std::string walletId_;
};

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeWebsocketsTests, Connect)
{
   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 1);
   auto wltId = wltList.begin()->second.walletId;
   ASSERT_FALSE(wltId.empty());
   ASSERT_EQ(wltId, walletId_);
   auto wallets = loadWallets(bridge_);
   ASSERT_EQ(wallets.size(), 1);

   ASSERT_EQ(wallets.begin()->second.walletId, wltId);
   auto accountId = wallets.begin()->second.accountId;
   ASSERT_FALSE(accountId.empty());

   WebSocketServer::initAuthPeers({
      homedir_ / SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_});
   WebSocketServer::start(theBDMt_->bdm(), true);

   ASSERT_TRUE(connectToDb(bridge_));
   ASSERT_TRUE(registerWallets(bridge_));

   //start db, go online and wait on ready notif
   theBDMt_->start(Config::DBSettings::initMode());
   ASSERT_EQ(goOnline(bridge_), 5);

   //check balances
   auto balances = getBalances(bridge_, wltId, accountId);
   ASSERT_EQ(balances.size(), 4);

   try {
      for (const auto& balPair : balances) {
         const auto& addrBal = testAddrBalances.at(balPair.first);
         EXPECT_EQ(addrBal[0], balPair.second[0]);
         EXPECT_EQ(addrBal[1], balPair.second[1]);
         EXPECT_EQ(addrBal[2], balPair.second[2]);
      }
   } catch (const std::exception&) {
      ASSERT_TRUE(false);
   }

   //check ledgers
   auto delegateId = getLedgerDelegateId(bridge_);
   ASSERT_FALSE(delegateId.empty());

   auto pageCount = getLedgersPageCount(bridge_, delegateId);
   ASSERT_EQ(pageCount, 1);

   auto ledgers = getLedgersPage(bridge_, delegateId, 0);
   ASSERT_EQ(ledgers.size(), 15);

   auto leAt5BlocksIter = ledgersAt5Blocks.begin();
   for (const auto& le : ledgers) {
      EXPECT_EQ(le.getValue(), leAt5BlocksIter->balance);
      EXPECT_EQ(le.getBlockNum(), leAt5BlocksIter->height);
      EXPECT_EQ(le.getTxTime(), leAt5BlocksIter->txTime);
      ++leAt5BlocksIter;
   }
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeWebsocketsTests, DeleteWallet)
{
   //create a fresh wallet
   auto wltId = createWallet(homedir_);

   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 2);
   auto wallets = loadWallets(bridge_);
   ASSERT_EQ(wallets.size(), 2);

   std::string accountId, importAccId, dbId;
   for (const auto& wltData : wallets) {
      if (wltData.first != wltId) {
         ASSERT_EQ(wltData.first, walletId_);
         importAccId = wltData.second.accountId;
         ASSERT_FALSE(importAccId.empty());
      } else {
         ASSERT_EQ(wltData.first, wltId);
         accountId = wltData.second.accountId;
         dbId = wltData.second.dbId;
         ASSERT_FALSE(accountId.empty());
      }
   }

   WebSocketServer::initAuthPeers({
      homedir_ / SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_});
   WebSocketServer::start(theBDMt_->bdm(), true);

   ASSERT_TRUE(connectToDb(bridge_));
   ASSERT_TRUE(registerWallets(bridge_));

   //start db, go online and wait on ready notif
   theBDMt_->start(Config::DBSettings::initMode());
   ASSERT_EQ(goOnline(bridge_), 5);

   //check balances
   auto balances = getBalances(bridge_, walletId_, importAccId);
   ASSERT_EQ(balances.size(), 4);
   try {
      for (const auto& balPair : balances) {
         const auto& addrBal = testAddrBalances.at(balPair.first);
         EXPECT_EQ(addrBal[0], balPair.second[0]);
         EXPECT_EQ(addrBal[1], balPair.second[1]);
         EXPECT_EQ(addrBal[2], balPair.second[2]);
      }
   } catch (const std::exception&) {
      ASSERT_TRUE(false);
   }

   balances = getBalances(bridge_, wltId, accountId);
   ASSERT_EQ(balances.size(), 0);

   //get the wallet path, check it
   std::filesystem::path wltPath;
   for (const auto& entry : wltList) {
      if (entry.second.walletId == wltId) {
         wltPath = homedir_ / entry.first;
         break;
      }
   }
   ASSERT_FALSE(wltPath.empty());
   ASSERT_TRUE(FileUtils::fileExists(wltPath, 0));

   //delete said wallet
   auto refId = rand();
   capnp::MallocMessageBuilder message;
   auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
   toBridge.setReferenceId(refId);
   auto request = toBridge.initWalletManager();
   request.setDeleteWallet(wltId);
   auto rawReq = serializeCapnp(message);
   pushRequest(bridge_, rawReq);

   //validate reply
   auto result = waitOnReply();
   kj::ArrayPtr<const capnp::word> words(
      reinterpret_cast<const capnp::word*>(result->data.getPtr()),
      result->data.getSize() / sizeof(capnp::word));
   capnp::FlatArrayMessageReader reader(words);
   auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();
   auto reply = fromBridge.getReply();
   ASSERT_TRUE(reply.getSuccess());
   ASSERT_EQ(reply.getReferenceId(), refId);
   ASSERT_FALSE(FileUtils::fileExists(wltPath, 0));
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeWebsocketsTests, ExtendAddressChain)
{
   //create a fresh wallet
   auto wltId = createWallet(homedir_);

   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 2);
   auto wallets = loadWallets(bridge_);
   ASSERT_EQ(wallets.size(), 2);

   std::string accountId, importAccId, dbId;
   for (const auto& wltData : wallets) {
      if (wltData.first != wltId) {
         ASSERT_EQ(wltData.first, walletId_);
         importAccId = wltData.second.accountId;
         ASSERT_FALSE(importAccId.empty());
      } else {
         ASSERT_EQ(wltData.first, wltId);
         accountId = wltData.second.accountId;
         dbId = wltData.second.dbId;
         ASSERT_FALSE(accountId.empty());
      }
   }

   WebSocketServer::initAuthPeers({
      homedir_ / SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_});
   WebSocketServer::start(theBDMt_->bdm(), true);

   ASSERT_TRUE(connectToDb(bridge_));
   ASSERT_TRUE(registerWallets(bridge_));

   //start db, go online and wait on ready notif
   theBDMt_->start(Config::DBSettings::initMode());
   ASSERT_EQ(goOnline(bridge_), 5);

   //check balances
   auto balances = getBalances(bridge_, walletId_, importAccId);
   ASSERT_EQ(balances.size(), 4);
   try {
      for (const auto& balPair : balances) {
         const auto& addrBal = testAddrBalances.at(balPair.first);
         EXPECT_EQ(addrBal[0], balPair.second[0]);
         EXPECT_EQ(addrBal[1], balPair.second[1]);
         EXPECT_EQ(addrBal[2], balPair.second[2]);
      }
   } catch (const std::exception&) {
      ASSERT_TRUE(false);
   }

   balances = getBalances(bridge_, wltId, accountId);
   ASSERT_EQ(balances.size(), 0);

   /* extend address chain */
   try {
      auto wltData = extendAddressPool(bridge_,
         wltId, accountId, dbId, 10000, false);
      ASSERT_EQ(wltData.walletId, wltId);
      ASSERT_EQ(wltData.accountId, accountId);
      EXPECT_EQ(wltData.useCount, -1);
      EXPECT_EQ(wltData.lookup, 10004);
   } catch (const std::runtime_error& e) {
      ASSERT_TRUE(false) << e.what();
   }

   /* grab wallet data explicitly, check chain again */
   auto walletData = getWalletData(bridge_, wltId);
   ASSERT_EQ(walletData.walletId, wltId);
   ASSERT_EQ(walletData.accountId, accountId);
   EXPECT_EQ(walletData.useCount, -1);
   EXPECT_EQ(walletData.lookup, 10004);
}

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeWebsocketsTests, AddNewAddress)
{
   /*
   This test covers the edge case where a wallet does not have enough
   computed addresses to serve a getAddress request, in which event it
   needs to trigger the address generation flow first
   */

   //create a fresh wallet
   auto wltId = createWallet(homedir_);

   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 2);
   auto wallets = loadWallets(bridge_);
   ASSERT_EQ(wallets.size(), 2);

   std::string accountId, importAccId, dbId;
   for (const auto& wltData : wallets) {
      if (wltData.first != wltId) {
         ASSERT_EQ(wltData.first, walletId_);
         importAccId = wltData.second.accountId;
         ASSERT_FALSE(importAccId.empty());
      } else {
         ASSERT_EQ(wltData.first, wltId);
         accountId = wltData.second.accountId;
         dbId = wltData.second.dbId;
         ASSERT_FALSE(accountId.empty());
      }
   }

   WebSocketServer::initAuthPeers({
      homedir_ / SERVER_AUTH_PEER_FILENAME, authPeersPassLbd_});
   WebSocketServer::start(theBDMt_->bdm(), true);

   ASSERT_TRUE(connectToDb(bridge_));
   ASSERT_TRUE(registerWallets(bridge_));

   //start db, go online and wait on ready notif
   theBDMt_->start(Config::DBSettings::initMode());
   ASSERT_EQ(goOnline(bridge_), 5);

   //check balances
   auto balances = getBalances(bridge_, walletId_, importAccId);
   ASSERT_EQ(balances.size(), 4);
   try {
      for (const auto& balPair : balances) {
         const auto& addrBal = testAddrBalances.at(balPair.first);
         EXPECT_EQ(addrBal[0], balPair.second[0]);
         EXPECT_EQ(addrBal[1], balPair.second[1]);
         EXPECT_EQ(addrBal[2], balPair.second[2]);
      }
   } catch (const std::exception&) {
      ASSERT_TRUE(false);
   }

   balances = getBalances(bridge_, wltId, accountId);
   ASSERT_EQ(balances.size(), 0);

   /* get 4 addresses, wallet should have the data for that */
   {
      auto walletData = getWalletData(bridge_, wltId);
      ASSERT_EQ(walletData.walletId, wltId);
      ASSERT_EQ(walletData.accountId, accountId);
      EXPECT_EQ(walletData.useCount, -1);
      EXPECT_EQ(walletData.lookup, 4);
   }

   for (unsigned i=0; i<4; i++) {
      getAddress(bridge_, wltId, accountId);
   }

   {
      auto walletData = getWalletData(bridge_, wltId);
      ASSERT_EQ(walletData.walletId, wltId);
      ASSERT_EQ(walletData.accountId, accountId);
      EXPECT_EQ(walletData.useCount, 3);
      EXPECT_EQ(walletData.lookup, 4);
   }

   /* request a new address, it should trigger address creation */
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initWallet();
      request.setWalletId(wltId);
      request.setAccountId(accountId);
      auto reqAddr = request.initGetAddress();
      reqAddr.setNew();
      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      bool refreshSeen = false;
      bool done = false;
      while (!done || !refreshSeen) {
         auto result = waitOnReply();
         kj::ArrayPtr<const capnp::word> words(
            reinterpret_cast<const capnp::word*>(result->data.getPtr()),
            result->data.getSize() / sizeof(capnp::word));
         capnp::FlatArrayMessageReader reader(words);
         auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();

         switch (fromBridge.which())
         {
            case Codec::Bridge::FromBridge::REPLY:
            {
               auto reply = fromBridge.getReply();
               ASSERT_TRUE(reply.getSuccess());
               ASSERT_EQ(reply.getReferenceId(), refId);
               ASSERT_EQ(reply.which(), Codec::Bridge::RpcReply::WALLET);

               auto walletReply = reply.getWallet();
               ASSERT_EQ(walletReply.which(), Codec::Bridge::WalletReply::GET_ADDRESS);
               done = true;
               break;
            }

            case Codec::Bridge::FromBridge::NOTIFICATION:
            {
               auto notif = fromBridge.getNotification();
               std::cout << "notif which(): " << notif.which() << std::endl;

               if (notif.which() == Codec::Bridge::Notification::REFRESH) {
                  ASSERT_FALSE(refreshSeen);
                  auto refreshNotif = notif.getRefresh();
                  ASSERT_EQ(refreshNotif.size(), 1);
                  ASSERT_EQ(refreshNotif[0], dbId);
                  refreshSeen = true;
               }
               break;
            }
         }
      }
   }

   {
      //grab wallet data explicitly, check chain again
      auto walletData = getWalletData(bridge_, wltId);
      ASSERT_EQ(walletData.walletId, wltId);
      ASSERT_EQ(walletData.accountId, accountId);
      EXPECT_EQ(walletData.useCount, 4);
      EXPECT_EQ(walletData.lookup, 104);
   }
}

////////////////////////////////////////////////////////////////////////////////
// BridgeWebsocketsAutoDB
////////////////////////////////////////////////////////////////////////////////
class BridgeWebsocketsAutoDB : public ::testing::Test
{
protected:
   virtual void SetUp()
   {
      FileUtils::removeDirectory(blkdir_);
      FileUtils::removeDirectory(homedir_);
      FileUtils::removeDirectory(ldbdir_);

      FileUtils::createDirectory(blkdir_ / "blocks");
      FileUtils::createDirectory(homedir_);
      FileUtils::createDirectory(ldbdir_);

      Config::DBSettings::setServiceType(SERVICE_UNITTEST_WITHWS);

      // Put the first 5 blocks into the blkdir
      blk0dat_ = FileUtils::getBlkFilename(blkdir_ / "blocks", 0);
      TestUtils::setBlocks({ "0", "1", "2", "3", "4", "5" }, blk0dat_);

      #ifdef _WIN32
         auto buildPath = fullBinPath.string();
      #else
         auto buildPath = fullBinPath.parent_path().parent_path().string();
      #endif
      char* argv[] = {
         buildPath.data(),
         (char*)"--datadir=./fakehomedir"sv.data(),
         (char*)"--dbdir=./ldbtestdir"sv.data(),
         (char*)"--satoshi-datadir=./blkfiletest"sv.data(),
         (char*)"--db-type=DB_FULL"sv.data(),
         (char*)"--automateDb"sv.data(),
         (char*)"--thread-count=3"sv.data()
      };
      Config::parseArgs(7, argv, Config::ProcessType::Bridge);

      startupBIP151CTX();
      startupBIP150CTX(4);

      replyQueue.clear();
      bridge_ = std::make_shared<Bridge::CppBridge>();
      bridge_->setWriteLambda([](MsgPtr payload) {
         std::unique_lock<std::mutex> lock(commsMutex);
         replyQueue.emplace_back(std::move(payload));
         commsCV.notify_all();
      });

      walletId_ = initWOWallet(homedir_);
   }

   virtual void TearDown()
   {
      bridge_.reset();
      FileUtils::removeDirectory(blkdir_);
      FileUtils::removeDirectory(homedir_);
      FileUtils::removeDirectory(ldbdir_);
      Config::reset();
   }

   bool disconnectFromDb()
   {
      auto refId = rand();
      capnp::MallocMessageBuilder message;
      auto toBridge = message.initRoot<Codec::Bridge::ToBridge>();
      toBridge.setReferenceId(refId);
      auto request = toBridge.initService();
      request.setCleanupDb();

      auto rawReq = serializeCapnp(message);
      pushRequest(bridge_, rawReq);

      //grab reply to cleanupDb as well
      auto reply = waitOnReply();
      kj::ArrayPtr<const capnp::word> words(
         reinterpret_cast<const capnp::word*>(reply->data.getPtr()),
         reply->data.getSize() / sizeof(capnp::word));
      capnp::FlatArrayMessageReader reader(words);
      auto fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();

      if (fromBridge.which() != Codec::Bridge::FromBridge::REPLY) {
         return false;
      }
      auto repCapnp = fromBridge.getReply();
      if (!repCapnp.getSuccess()) {
         return false;
      }

      //expecting disconnected notif
      auto reply2 = waitOnReply();
      words = kj::ArrayPtr<const capnp::word>{
         reinterpret_cast<const capnp::word*>(reply2->data.getPtr()),
         reply2->data.getSize() / sizeof(capnp::word)
      };
      reader = capnp::FlatArrayMessageReader{words};
      fromBridge = reader.getRoot<Codec::Bridge::FromBridge>();

      if (fromBridge.which() != Codec::Bridge::FromBridge::NOTIFICATION) {
         return false;
      }
      auto notif = fromBridge.getNotification();
      return notif.which() == Codec::Bridge::Notification::DISCONNECTED;
   }

protected:
   std::filesystem::path blkdir_{"./blkfiletest"sv};
   std::filesystem::path homedir_{"./fakehomedir"sv};
   std::filesystem::path ldbdir_{"./ldbtestdir"sv};
   std::filesystem::path blk0dat_;

   std::shared_ptr<Bridge::CppBridge> bridge_;
   std::string walletId_;
};

////////////////////////////////////////////////////////////////////////////////
TEST_F(BridgeWebsocketsAutoDB, Connect)
{
   auto wltList = listWallets(bridge_);
   ASSERT_EQ(wltList.size(), 1);
   auto wltId = wltList.begin()->second.walletId;
   ASSERT_FALSE(wltId.empty());
   ASSERT_EQ(wltId, walletId_);
   auto wallets = loadWallets(bridge_);
   ASSERT_EQ(wallets.size(), 1);

   ASSERT_EQ(wallets.begin()->second.walletId, wltId);
   auto accountId = wallets.begin()->second.accountId;
   ASSERT_FALSE(accountId.empty());

   //setup connection to db
   ASSERT_TRUE(connectToDb(bridge_));
   ASSERT_TRUE(Bridge::isDbRunning());
   ASSERT_TRUE(registerWallets(bridge_));
   ASSERT_EQ(goOnline(bridge_), 5);

   //check balances
   auto balances = getBalances(bridge_, wltId, accountId);
   ASSERT_EQ(balances.size(), 4);

   try {
      for (const auto& balPair : balances) {
         const auto& addrBal = testAddrBalances.at(balPair.first);
         EXPECT_EQ(addrBal[0], balPair.second[0]);
         EXPECT_EQ(addrBal[1], balPair.second[1]);
         EXPECT_EQ(addrBal[2], balPair.second[2]);
      }
   } catch (const std::exception&) {
      ASSERT_TRUE(false);
   }

   //cleanup
   ASSERT_TRUE(disconnectFromDb());

   //confirm db is down
   while (Bridge::isDbRunning()) {
      std::this_thread::sleep_for(100ms);
   }
}

////////////////////////////////////////////////////////////////////////////////
GTEST_API_ int main(int argc, char **argv)
{
   Cryptography::ECDSA::setupContext();

   srand(time(0));
   std::cout << "Running main() from gtest_main.cc\n";

   SETLOGLEVEL(LogLvlDebug);
   LOGENABLESTDOUT();
   LOGDISABLESTDOUT();

   fullBinPath = std::filesystem::absolute(std::filesystem::path{argv[0]});
   testing::InitGoogleTest(&argc, argv);
   int exitCode = RUN_ALL_TESTS();

   FLUSHLOG();
   CLEANUPLOG();

   Cryptography::ECDSA::shutdown();
   return exitCode;
}
