////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <cstring>

#include "AuthorizedPeers.h"
#include <Utils/BIP150_151.h>
#include <Utils/DBUtils.h>

#include "Accounts/AccountTypes.h"
#include "Accounts/AddressAccounts.h"
#include "Accounts/MetaAccounts.h"
#include "Wallets.h"
#include "WalletFileInterface.h"
#include "Seeds/Seeds.h"
#include "TerminalPassphrasePrompt.h"
#include "BIP32_Node.h"

using namespace Armory::Assets;
using namespace Armory::Accounts;
using namespace Armory::Wallets;
using namespace Armory::Seeds;

using namespace std::chrono_literals;
using namespace std::string_view_literals;

////////////////////////////////////////////////////////////////////////////////
AuthorizedPeers::AuthorizedPeers(std::shared_ptr<AssetWallet> wltPtr) :
   wallet_(wltPtr)
{
   initFromWallet();
}

////
AuthorizedPeers::AuthorizedPeers(const IO::ReadOnlyFileParams& params)
{
   loadWallet(params);
   initFromWallet();
}

////
AuthorizedPeers::AuthorizedPeers()
{
   //No filename was passed, create an ephemral peer db instead
   auto privateKey = Cryptography::PRNG::generateRandomStrong(32);

   //compute the public key
   auto ownPubKey = Cryptography::ECDSA::computePublicKey(privateKey);
   auto ownPubKey_compressed = Cryptography::ECDSA::compressPoint(ownPubKey);

   //add to private keys map
   privateKeys_.emplace(ownPubKey_compressed, privateKey);

   //add to public key map as own
   btc_pubkey btc_own;
   btc_pubkey_init(&btc_own);
   std::memcpy(btc_own.pubkey, ownPubKey_compressed.getPtr(), BIP151PUBKEYSIZE);
   btc_own.compressed = true;
   nameToKeyMap_.emplace("own", btc_own);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::loadWallet(const IO::ReadOnlyFileParams& params)
{
   if (!FileUtils::fileExists(params.filePath, 6)) {
      throw PeerFileMissing();
   }
   wallet_ = AssetWallet::loadMainWalletFromFile(params);
}

////
void AuthorizedPeers::initFromWallet()
{
   if (wallet_ == nullptr) {
      throw AuthorizedPeersException("failed to initialize peer wallet");
   }
   //grab all meta entries, populate public key map
   auto peerAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
   auto peerAssets = AuthPeerAssetConversion::getAssetMap(peerAccount.get());

   //root signature
   rootSignature_ = std::move(peerAssets.rootSignature);

   //name key pairs
   for (auto& pubkey : peerAssets.nameKeyPair) {
      btc_pubkey btckey;
      btc_pubkey_init(&btckey);

      SecureBinaryData pubkey_cmp;
      if (pubkey.second->getSize() != BIP151PUBKEYSIZE) {
         pubkey_cmp = Cryptography::ECDSA::compressPoint(*pubkey.second);
      } else {
         pubkey_cmp = *pubkey.second;
      }

      std::memcpy(btckey.pubkey, pubkey_cmp.getPtr(), BIP151PUBKEYSIZE);
      btckey.compressed = true;
      keySet_.emplace(pubkey_cmp);
      nameToKeyMap_.emplace(pubkey.first, btckey);
   }

   //peer root public keys
   peerRootKeys_ = std::move(peerAssets.peerRootKeys);

   //get the private key
   BinaryData ownPubKey_compressed;
   {
      //create & set password lambda
      auto passphrasePrompt = [](const std::set<EncryptionKeyId>&)
      ->Passphrase::Result
      {
         return {
            SecureBinaryData::fromString(PEERS_WALLET_PASSWORD),
            true
         };
      };
      wallet_->setPassphrasePromptLambda(passphrasePrompt);

      //grab decryption container lock
      auto lock = wallet_->lockDecryptedContainer();

      auto walletSingle = std::dynamic_pointer_cast<AssetWallet_Single>(wallet_);
      if (walletSingle == nullptr) {
         throw AuthorizedPeersException("unexpected wallet type");
      }

      //grab asset #1 on main peers chain (m'/PEERS_WALLET_BIP32_ACCOUNT'/0')
      auto mainAcc = walletSingle->getAccountForID(
         walletSingle->getMainAccountID());
      auto outerAccount = mainAcc->getOuterAccount();
      auto assetPtr = outerAccount->getAssetForKey(1);
      auto assetSingle = std::dynamic_pointer_cast<AssetEntry_Single>(assetPtr);

      const auto& privateKey = wallet_->getDecryptedValue(
         assetSingle->getPrivKey());

      //compute the public key
      auto ownPubKey = Cryptography::ECDSA::computePublicKey(privateKey);
      ownPubKey_compressed = Cryptography::ECDSA::compressPoint(ownPubKey);

      //add to private keys map
      privateKeys_.emplace(ownPubKey_compressed, privateKey);
   }

   //add to public key map as own
   btc_pubkey btc_own;
   btc_pubkey_init(&btc_own);
   std::memcpy(btc_own.pubkey, ownPubKey_compressed.getPtr(), BIP151PUBKEYSIZE);
   btc_own.compressed = true;
   nameToKeyMap_.emplace("own", btc_own);

   //grab public key to index map
   keyToAssetIndexMap_ =
      std::move(AuthPeerAssetConversion::getKeyIndexMap(peerAccount.get()));

   //set master key
   if (peerAssets.masterKey.empty()) {
      return;
   }
   masterKey_ = std::move(peerAssets.masterKey);
}

////////////////////////////////////////////////////////////////////////////////
std::shared_ptr<AuthorizedPeers> AuthorizedPeers::createWallet(
   const IO::CreateFileParams& params)
{
   //Default peers wallet private keys password. Asset wallets always
   //encrypt private keys, we have to provide a password at creation.
   auto privPass = SecureBinaryData::fromString(PEERS_WALLET_PASSWORD);

   //wrap around the provided CreateFileParams to create the AssetWallet
   //the peers db will run off of
   IO::CreateWalletParams walletParams{
      params.filePath.parent_path(),
      Passphrase::SetNew{1ms, 0, privPass},
      params.setCtrlPassObj.copy(), nullptr,
      0, {}, {}
   };

   std::shared_ptr<AssetWallet_Single> wallet;
   {
      //Default peers wallet derivation path. Using m/'account/'0.
      std::vector<uint32_t> derPath;
      derPath.push_back(PEERS_WALLET_BIP32_ACCOUNT);
      derPath.push_back(0xF0000000);

      //generate bip32 node from random seed
      wallet = AssetWallet_Single::createFromSeed(
         std::make_unique<ClearTextSeed_BIP32>(
            Cryptography::PRNG::generateRandomStrong(32),
            SeedType::BIP32_Virgin),
         walletParams);
      auto wltSingle = std::dynamic_pointer_cast<AssetWallet_Single>(wallet);

      auto rootBip32 = std::dynamic_pointer_cast<AssetEntry_BIP32Root>(
         wltSingle->getRoot());
      if (rootBip32 == nullptr) {
         throw AuthorizedPeersException("[createWallet] invalid root");
      }
      auto account = AccountType_BIP32::makeFromDerPaths(
         rootBip32->getSeedFingerprint(false), {derPath});
      account->setMain(true);
      account->setAddressLookup(2);

      wallet->setPassphrasePromptLambda(
         walletParams.setPrivPassObj.getUnlockFunc());
      wltSingle->createBIP32Account(account, nullptr);
   }

   //add the peers meta account
   wallet->addMetaAccount(MetaAccountType::AuthPeers);

   //grab wallet filename
   auto currentname = wallet->getDbFilename();

   //destroying the wallet will shutdown the underlying db object
   wallet.reset();

   //rename peers wallet to desired name
   try {
      std::filesystem::rename(currentname, params.filePath);
   } catch (const std::filesystem::filesystem_error&) {
      throw AuthorizedPeersException("failed to setup peers wallet");
   }
   currentname.append("-lock");
   std::filesystem::remove(currentname);

   IO::ReadOnlyFileParams roFileParams{params.filePath,
      walletParams.setCtrlPassObj.getUnlockFunc()};
   return std::make_shared<AuthorizedPeers>(roFileParams);
}

////////////////////////////////////////////////////////////////////////////////
const std::map<std::string, btc_pubkey>& AuthorizedPeers::getPeerNameMap() const
{
   return nameToKeyMap_;
}

////////////////////////////////////////////////////////////////////////////////
const std::set<SecureBinaryData>& AuthorizedPeers::getPublicKeySet() const
{
   return keySet_;
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AuthorizedPeers::getPrivateKey(
   const BinaryDataRef& pubkey) const
{
   auto iter = privateKeys_.find(pubkey);
   if (iter == privateKeys_.end()) {
      throw AuthorizedPeersException("unknown private key");
   }
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::addPeer(const SecureBinaryData& pubkey,
   const std::initializer_list<std::string>& names)
{
   std::vector<std::string> namesVec(names);
   addPeer(pubkey, namesVec);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::addPeer(const btc_pubkey& pubkey,
   const std::initializer_list<std::string>& names)
{
   std::vector<std::string> namesVec(names);
   SecureBinaryData keySbd(pubkey.pubkey, pubkey.compressed ? 33 : 65);
   addPeer(keySbd, namesVec);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::addPeer(const SecureBinaryData& pubkey,
   const std::vector<std::string>& names)
{
   //convert sbd pubkey to libbtc pubkey
   SecureBinaryData pubkey_cmp;
   if (pubkey.getSize() == 65) {
      pubkey_cmp = Cryptography::ECDSA::compressPoint(pubkey);
   } else if (pubkey.getSize() == BIP151PUBKEYSIZE) {
      pubkey_cmp = pubkey;
   } else {
      throw AuthorizedPeersException("unexpected public key size");
   }

   btc_pubkey btckey;
   btc_pubkey_init(&btckey);
   std::memcpy(btckey.pubkey, pubkey_cmp.getPtr(), pubkey_cmp.getSize());
   btckey.compressed = true;

   //add all names to key list; using insert means existing names are
   //not overwritten
   for (auto& name : names) {
      nameToKeyMap_.emplace(name, btckey);
   }
   keySet_.insert(pubkey_cmp);

   //if we dont have a wallet attached, we're done
   if (wallet_ == nullptr) {
      return;
   }

   //get a dbtx for the wallet & add the pubkey with its names
   auto peerAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
   auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
      wallet_->getDbName());
   std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
   auto index = AuthPeerAssetConversion::addAsset(
      peerAccount.get(), pubkey_cmp, names, sharedTx);

   //track the asset index for the pubkey
   auto iter = keyToAssetIndexMap_.find(pubkey_cmp);
   if (iter == keyToAssetIndexMap_.end()) {
      iter = keyToAssetIndexMap_.emplace(
         pubkey_cmp, std::set<unsigned>{}).first;
   }
   iter->second.insert(index);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::eraseName(const std::string& name)
{
   if (name == "own") {
      throw AuthorizedPeersException("invalid name");
   }

   //find pubkey
   auto keyIter = nameToKeyMap_.find(name);
   if (keyIter == nameToKeyMap_.end()) {
      return;
   }
   auto pubkey = keyIter->second;

   //convert libbtc key to binarydataref
   BinaryDataRef bdrKey(pubkey.pubkey, BIP151PUBKEYSIZE);

   //get the list wallet assets this pub key appears in
   auto indexIter = keyToAssetIndexMap_.find(bdrKey);

   //erase name from map
   nameToKeyMap_.erase(keyIter);

   if (wallet_ == nullptr) {
      /*
      We need to know if the name to erase is the last one refering to its
      relevant pubkey. If so, we need to delete the pubkey from the keySet
      as well, as it doesn't represent an valid peer anymore.

      In the absence of a wallet, we can't rely on it to sort public keys
      by name. Instead, parse nameToKeyMap linearly for other instances of
      the key
      */

      bool hasKey = false;
      for (auto& namePair : nameToKeyMap_) {
         if (std::memcmp(
            namePair.second.pubkey, pubkey.pubkey, BIP151PUBKEYSIZE) == 0) {
            hasKey = true;
            break;
         }
      }

      if (!hasKey) {
         //erase from key set
         BinaryDataRef bdr(pubkey.pubkey, BIP151PUBKEYSIZE);
         keySet_.erase(bdr);
      }
      return;
   }

   if (indexIter == keyToAssetIndexMap_.end()) {
      return;
   }

   //grab metadata account from wallet, cycle through assets, clean up
   //indexMap as we go
   auto metaAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
   auto setIter = indexIter->second.begin();
   while (setIter != indexIter->second.end()) {
      const auto& index = *setIter;
      std::shared_ptr<MetaData> metaPtr;
      try {
         metaPtr = metaAccount->getMetaDataByIndex(index);
      } catch (const std::exception&) {
         indexIter->second.erase(setIter++);
         continue;
      }

      auto peerPtr = std::dynamic_pointer_cast<PeerPublicData>(metaPtr);
      if (peerPtr == nullptr) {
         indexIter->second.erase(setIter++);
         continue;
      }

      if (peerPtr->eraseName(name)) {
         if (peerPtr->getNames().empty()) {
            indexIter->second.erase(setIter++);
            continue;
         }
      }
      ++setIter;
   }

   //remove public key from index map if it isn't related to any assets
   if (indexIter->second.empty()) {
      keySet_.erase(indexIter->first);
      keyToAssetIndexMap_.erase(indexIter);
   }

   auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
      wallet_->getDbName());
   std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
   metaAccount->updateOnDisk(sharedTx);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::eraseKey(const btc_pubkey& pubkey)
{
   size_t size = 65;
   if (pubkey.compressed) {
      size = 33;
   }
   SecureBinaryData keySbd(size);
   std::memcpy(keySbd.getPtr(), pubkey.pubkey, size);
   eraseKey(keySbd);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::eraseKey(const SecureBinaryData& pubkey)
{
   //make sure we're working with compressed keys only
   SecureBinaryData pubkey_cmp;
   if (pubkey.getSize() == 65) {
      pubkey_cmp = Cryptography::ECDSA::compressPoint(pubkey);
   } else {
      pubkey_cmp = pubkey;
   }

   btc_pubkey btckey;
   btc_pubkey_init(&btckey);
   std::memcpy(btckey.pubkey, pubkey_cmp.getPtr(), BIP151PUBKEYSIZE);
   btckey.compressed = true;

   bool cleanupMasterKey = false;
   if (pubkey_cmp == masterKey_) {
      masterKey_.clear();
      cleanupMasterKey = true;
   }

   //erase from public key set
   if (keySet_.erase(pubkey_cmp) == 0) {
      erasePeerRootKey(pubkey);
      return;
   }

   if (wallet_ == nullptr) {
      //lacking a wallet to build a set of names for this pubkey, scoure the
      //name-key map linearly, clear it and we're done

      auto keyIter = nameToKeyMap_.begin();
      while (keyIter != nameToKeyMap_.end()) {
         if (std::memcmp(keyIter->second.pubkey, btckey.pubkey, BIP151PUBKEYSIZE) == 0) {
            nameToKeyMap_.erase(keyIter++);
            continue;
         }
         ++keyIter;
      }
      return;
   }

   //we have a wallet, need to clear entries on disk and compile name list for
   //the public key
   auto iter = keyToAssetIndexMap_.find(pubkey_cmp);
   if (iter == keyToAssetIndexMap_.end()) {
      return;
   }
   auto metaAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
   std::set<std::string> namesToDelete;

   for (auto& index : iter->second) {
      std::shared_ptr<MetaData> metaPtr;
      try {
         metaPtr = metaAccount->getMetaDataByIndex(index);
      } catch (const std::exception&) {
         continue;
      }

      auto peerPtr = std::dynamic_pointer_cast<PeerPublicData>(metaPtr);
      if (peerPtr == nullptr) {
         continue;
      }
      auto& assetNames = peerPtr->getNames();
      namesToDelete.insert(assetNames.begin(), assetNames.end());
      metaAccount->eraseMetaDataByIndex(index);
   }

   //update on disk
   auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
      wallet_->getDbName());
   std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
   if (cleanupMasterKey) {
      AuthPeerAssetConversion::clearMasterKeyAssets(metaAccount.get());
   }
   metaAccount->updateOnDisk(sharedTx);

   //erase from index map
   keyToAssetIndexMap_.erase(iter);

   //erase names
   for (const auto& name : namesToDelete) {
      nameToKeyMap_.erase(name);
   }
}

////////////////////////////////////////////////////////////////////////////////
const btc_pubkey& AuthorizedPeers::getOwnPublicKey() const
{
   auto iter = nameToKeyMap_.find("own");
   if (iter == nameToKeyMap_.end()) {
      throw AuthorizedPeersException("malformed authpeer object");
   }
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::addRootSignature(
   const SecureBinaryData& key, const SecureBinaryData& sig)
{
   //check key is valid
   if (!Cryptography::ECDSA::verifyPublicKeyValid(key)) {
      throw AuthorizedPeersException("invalid root pubkey");
   }

   //check sig is valid
   auto ownKey = getOwnPublicKey();
   BinaryDataRef ownKeyBdr(ownKey.pubkey, 33);
   if (!Cryptography::ECDSA::verifyData(ownKeyBdr, sig, key)) {
      throw AuthorizedPeersException("invalid root signature");
   }
   rootSignature_ = std::make_pair(key, sig);

   if (wallet_ == nullptr) {
      return;
   }

   auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
      wallet_->getDbName());
   std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
   auto peerAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
   AuthPeerAssetConversion::addRootSignature(
      peerAccount.get(), key, sig, sharedTx);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::addPeerRootKey(
   const SecureBinaryData& key, std::string description)
{
   //check key is valid
   if (!Cryptography::ECDSA::verifyPublicKeyValid(key)) {
      throw AuthorizedPeersException("invalid root pubkey");
   }
   if (wallet_ == nullptr) {
      peerRootKeys_.emplace(key, std::make_pair(description, 0));
      return;
   }

   auto peerAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
   auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
      wallet_->getDbName());
   std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
   auto index = AuthPeerAssetConversion::addRootPeer(
      peerAccount.get(), key, description, sharedTx);
   peerRootKeys_.emplace(key, std::make_pair(description, index));
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::erasePeerRootKey(const SecureBinaryData& key)
{
   auto iter = peerRootKeys_.find(key);
   if (iter == peerRootKeys_.end()) {
      return;
   }
   if (wallet_ != nullptr) {
      //update wallet to reflect erasure
      auto metaAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
      metaAccount->eraseMetaDataByIndex(iter->second.second);

      //update on disk
      auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
         wallet_->getDbName());
      std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
      metaAccount->updateOnDisk(sharedTx);
   }
   peerRootKeys_.erase(iter);
}

////////////////////////////////////////////////////////////////////////////////
void AuthorizedPeers::changeControlPassphrase(const std::filesystem::path& path)
{
   //get a terminal prompt lambda
   auto promptPtr = TerminalPassphrasePrompt::getLambda("peers db");

   //load the wallet
   auto wlt = AssetWallet::loadMainWalletFromFile(
      IO::ReadOnlyFileParams{path, promptPtr});

   //change passphrase lambda
   auto changeLbd = [&promptPtr](void)->std::unique_ptr<Passphrase::Params>
   {
      auto result = promptPtr({ BinaryData::fromString("change-pass"sv) });
      if (!result.success) {
         throw std::runtime_error("authdb passphrase change was rejected");
      }
      return std::make_unique<Passphrase::Params>(
         250ms, 0, std::move(result.passphrase));
   };
   Passphrase::SetNew changePassObj{changeLbd};

   //change the passphrase
   wlt->changeControlPassphrase(changePassObj, promptPtr);
}

////////////////////////////////////////////////////////////////////////////////
AuthPeersLambdas AuthorizedPeers::getAuthPeersLambdas(
   std::shared_ptr<AuthorizedPeers> authPeers)
{
   auto getMap = [authPeers]()->const std::map<std::string, btc_pubkey>&
   {
      return authPeers->getPeerNameMap();
   };

   auto getPrivKey = [authPeers](const BinaryDataRef& pubkey)
   ->const SecureBinaryData&
   {
      return authPeers->getPrivateKey(pubkey);
   };

   auto getAuthSet = [authPeers]()->const std::set<SecureBinaryData>&
   {
      return authPeers->getPublicKeySet();
   };

   return AuthPeersLambdas(getMap, getPrivKey, getAuthSet);
}

////////////////////////////////////////////////////////////////////////////////
bool AuthorizedPeers::setMasterKey(const btc_pubkey& pubkey)
{
   SecureBinaryData keySbd{pubkey.pubkey, pubkey.compressed ? 33u : 65u};
   return setMasterKey(keySbd);
}

////
bool AuthorizedPeers::setMasterKey(const SecureBinaryData& pubkey)
{
   //blindly add the master key, the youngest asset takes precedence
   if (masterKey_ == pubkey) {
      return true;
   }

   if (!Cryptography::ECDSA::verifyPublicKeyValid(pubkey)) {
      //not a valid pubkey
      return false;
   }

   if (keySet_.find(pubkey) == keySet_.end()) {
      //master key isn't known to peers store, ignore
      return false;
   }

   //set in wallet
   if (wallet_ != nullptr) {
      auto metaAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
      auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
         wallet_->getDbName());
      std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
      AuthPeerAssetConversion::addMasterKey(metaAccount.get(), pubkey, sharedTx);
   }

   //set locally
   masterKey_ = pubkey;
   return true;
}

////
void AuthorizedPeers::eraseMasterKey()
{
   if (masterKey_.empty()) {
      return;
   }
   masterKey_.clear();

   if (wallet_ == nullptr) {
      return;
   }

   auto metaAccount = wallet_->getMetaAccount(MetaAccountType::AuthPeers);
   auto uniqueTx = wallet_->getIface()->beginWriteTransaction(
      wallet_->getDbName());
   std::shared_ptr<IO::DBIfaceTransaction> sharedTx(std::move(uniqueTx));
   AuthPeerAssetConversion::clearMasterKeyAssets(metaAccount.get());
   metaAccount->updateOnDisk(sharedTx);
}

////////////////////////////////////////////////////////////////////////////////
bool AuthorizedPeers::isMasterKey(const btc_pubkey& pubkey) const
{
   if (masterKey_.empty()) {
      return false;
   }

   BinaryDataRef keyRef{pubkey.pubkey, pubkey.compressed ? 33u : 65u};
   return masterKey_.getRef() == keyRef;
}

////
bool AuthorizedPeers::isMasterKey(const SecureBinaryData& pubkey) const
{
   if (masterKey_.empty()) {
      return false;
   }
   return masterKey_.getRef() == pubkey;
}
