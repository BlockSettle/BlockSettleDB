////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2019, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Wallets.h"
#include "BlockDataManagerConfig.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// WalletMeta
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
WalletMeta::~WalletMeta()
{}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletMeta::getDbKey()
{
   if (walletID_.getSize() == 0)
      throw WalletException("empty master ID");

   BinaryWriter bw;
   bw.put_uint8_t(WALLETMETA_PREFIX);
   bw.put_BinaryData(walletID_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletMeta::serializeVersion() const
{
   BinaryWriter bw;
   bw.put_uint8_t(versionMajor_);
   bw.put_uint16_t(versionMinor_);
   bw.put_uint16_t(revision_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
void WalletMeta::unseralizeVersion(BinaryRefReader& brr)
{
   versionMajor_ = brr.get_uint8_t();
   versionMinor_ = brr.get_uint16_t();
   revision_ = brr.get_uint16_t();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletMeta::serializeEncryptionKey() const
{
   BinaryWriter bw;
   bw.put_var_int(defaultEncryptionKeyId_.getSize());
   bw.put_BinaryData(defaultEncryptionKeyId_);
   bw.put_var_int(defaultEncryptionKey_.getSize());
   bw.put_BinaryData(defaultEncryptionKey_);

   bw.put_var_int(defaultKdfId_.getSize());
   bw.put_BinaryData(defaultKdfId_);
   bw.put_var_int(masterEncryptionKeyId_.getSize());
   bw.put_BinaryData(masterEncryptionKeyId_);


   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
void WalletMeta::unserializeEncryptionKey(BinaryRefReader& brr)
{
   auto len = brr.get_var_int();
   defaultEncryptionKeyId_ = move(brr.get_BinaryData(len));
   
   len = brr.get_var_int();
   defaultEncryptionKey_ = move(brr.get_BinaryData(len));

   len = brr.get_var_int();
   defaultKdfId_ = move(brr.get_BinaryData(len));

   len = brr.get_var_int();
   masterEncryptionKeyId_ = move(brr.get_BinaryData(len));
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletMeta_Single::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(type_);
   bw.put_BinaryData(serializeVersion());
   bw.put_BinaryData(serializeEncryptionKey());

   BinaryWriter final_bw;
   final_bw.put_var_int(bw.getSize());
   final_bw.put_BinaryDataRef(bw.getDataRef());

   return final_bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletMeta_Single::shouldLoad() const
{
   return true;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletMeta_Multisig::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(type_);
   bw.put_BinaryData(serializeVersion());
   bw.put_BinaryData(serializeEncryptionKey());

   BinaryWriter final_bw;
   final_bw.put_var_int(bw.getSize());
   final_bw.put_BinaryDataRef(bw.getDataRef());

   return final_bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletMeta_Multisig::shouldLoad() const
{
   return true;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletMeta_Subwallet::serialize() const
{
   BinaryWriter bw;
   bw.put_var_int(4);
   bw.put_uint32_t(type_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletMeta_Subwallet::shouldLoad() const
{
   return false;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WalletMeta> WalletMeta::deserialize(
   shared_ptr<WalletDBInterface> iface, BinaryDataRef key, BinaryDataRef val)
{
   if (key.getSize() < 2)
      throw WalletException("invalid meta key");

   BinaryRefReader brrKey(key);
   auto prefix = brrKey.get_uint8_t();
   if (prefix != WALLETMETA_PREFIX)
      throw WalletException("invalid wallet meta prefix");

   string dbname((char*)brrKey.getCurrPtr(), brrKey.getSizeRemaining());

   BinaryRefReader brrVal(val);
   auto wltType = (WalletMetaType)brrVal.get_uint32_t();

   shared_ptr<WalletMeta> wltMetaPtr;

   switch (wltType)
   {
   case WalletMetaType_Single:
   {
      wltMetaPtr = make_shared<WalletMeta_Single>(iface);
      wltMetaPtr->unseralizeVersion(brrVal);
      wltMetaPtr->unserializeEncryptionKey(brrVal);
      break;
   }

   case WalletMetaType_Subwallet:
   {
      wltMetaPtr = make_shared<WalletMeta_Subwallet>(iface);
      break;
   }

   case WalletMetaType_Multisig:
   {
      wltMetaPtr = make_shared<WalletMeta_Multisig>(iface);
      wltMetaPtr->unseralizeVersion(brrVal);
      wltMetaPtr->unserializeEncryptionKey(brrVal);
      break;
   }

   default:
      throw WalletException("invalid wallet type");
   }

   wltMetaPtr->dbName_ = move(dbname);
   wltMetaPtr->walletID_ = brrKey.get_BinaryData(brrKey.getSizeRemaining());
   return wltMetaPtr;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AssetWallet
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AssetWallet::~AssetWallet()
{
   accounts_.clear();
   iface_.reset();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressAccount> AssetWallet::createAccount(
   shared_ptr<AccountType> accountType)
{
   auto cipher = make_unique<Cipher_AES>(
      decryptedData_->getDefaultKdfId(),
      decryptedData_->getMasterEncryptionKeyId());

   //instantiate AddressAccount object from AccountType
   auto account_ptr = make_shared<AddressAccount>(iface_, dbName_);
   account_ptr->make_new(accountType, decryptedData_, move(cipher));
   auto accID = account_ptr->getID();
   if (accounts_.find(accID) != accounts_.end())
      throw WalletException("already have an address account with this path");

   //commit to disk
   account_ptr->commit();

   if (accountType->isMain())
   {
      mainAccount_ = account_ptr->getID();

      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

      BinaryWriter bwData;
      bwData.put_var_int(mainAccount_.getSize());
      bwData.put_BinaryData(mainAccount_);

      auto&& tx = iface_->beginWriteTransaction(dbName_);
      tx.insert(bwKey.getData(), bwData.getData());
   }

   accounts_.insert(make_pair(accID, account_ptr));
   return account_ptr;
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetWallet_Single::createBIP32Account(
   shared_ptr<AssetEntry_BIP32Root> parentNode, 
   vector<unsigned> derPath, bool isMain)
{
   shared_ptr<AssetEntry_BIP32Root> root = parentNode;
   if (parentNode == nullptr)
      root = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);

   if (root == nullptr)
      throw AccountException("no valid root to create BIP32 account from");

   shared_ptr<AccountType_BIP32_Legacy> accountTypePtr = nullptr;
   if(root->getPrivKey() != nullptr)
   {
      //try to decrypt the root's private key to get full derivation
      try
      {
         //lock for decryption
         auto lock = lockDecryptedContainer();

         //decrypt root
         auto privKey = decryptedData_->getDecryptedPrivateData(root->getPrivKey());
         auto chaincode = root->getChaincode();

         SecureBinaryData dummy;
         accountTypePtr = make_shared<AccountType_BIP32_Legacy>(
            privKey, dummy, chaincode, derPath,
            root->getDepth(), root->getLeafID());
      }
      catch(exception&)
      {}
   }

   if (accountTypePtr == nullptr)
   {
      //can't get the private key, if we can derive this only from 
      //the pubkey then do it, otherwise throw
      auto pubkey = root->getPubKey()->getCompressedKey();
      auto chaincode = root->getChaincode();

      SecureBinaryData dummy1;
      accountTypePtr = make_shared<AccountType_BIP32_Legacy>(
         dummy1, pubkey, chaincode, derPath,
         root->getDepth(), root->getLeafID());
   }

   if (isMain || accounts_.size() == 0)
      accountTypePtr->setMain(true);

   auto&& tx = iface_->beginWriteTransaction(dbName_);
   auto accountPtr = createAccount(accountTypePtr);
   accountPtr->extendPrivateChain(decryptedData_, DERIVATION_LOOKUP);
   return accountPtr->getID();
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& AssetWallet_Single::createBIP32Account(
   std::shared_ptr<AssetEntry_BIP32Root> parentNode,
   std::vector<unsigned> derPath,
   std::shared_ptr<AccountType_BIP32_Custom> accTypePtr)
{
   shared_ptr<AssetEntry_BIP32Root> root = parentNode;
   if (parentNode == nullptr)
      root = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);

   if (root == nullptr)
      throw AccountException("no valid root to create BIP32 account from");

   bool isDerived = false;
   if (root->getPrivKey() != nullptr)
   {
      //try to decrypt the root's private to get full derivation
      try
      {
         //lock for decryption
         auto lock = lockDecryptedContainer();

         //decrypt root
         auto privKey = decryptedData_->getDecryptedPrivateData(
            root->getPrivKey());
         auto chaincode = root->getChaincode();

         //derive account root
         BIP32_Node bip32Node;
         bip32Node.initFromPrivateKey(
            root->getDepth(), root->getLeafID(), root->getFingerPrint(),
            privKey, chaincode);
         for (auto& path : derPath)
            bip32Node.derivePrivate(path);

         auto derivedKey = bip32Node.movePrivateKey();
         auto derivedCode = bip32Node.moveChaincode();
         auto pubkey = CryptoECDSA().ComputePublicKey(derivedKey, true);

         accTypePtr->setChaincode(derivedCode);
         accTypePtr->setPrivateKey(derivedKey);
         accTypePtr->setPublicKey(pubkey);

         isDerived = true;
      }
      catch (exception&)
      {
         isDerived = false;
      }
   }

   if (!isDerived)
   {
      //can't get the private key, if we can derive this only from 
      //the pubkey then do it, otherwise throw

      auto pubkey = root->getPubKey()->getCompressedKey();
      auto chaincode = root->getChaincode();

      BIP32_Node bip32Node;
      bip32Node.initFromPublicKey(
         root->getDepth(), root->getLeafID(), root->getFingerPrint(),
         pubkey, chaincode);
      for (auto& path : derPath)
         bip32Node.derivePublic(path);

      auto derivedKey = bip32Node.movePublicKey();
      auto derivedCode = bip32Node.moveChaincode();

      accTypePtr->setChaincode(derivedCode);
      accTypePtr->setPublicKey(derivedKey);
   }

   auto accountPtr = createAccount(accTypePtr);
   accountPtr->extendPrivateChain(decryptedData_, accTypePtr->getAddressLookup());
   return accountPtr->getID();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::
   createFromPrivateRoot_Armory135(
   const string& folder,
   const SecureBinaryData& privateRoot,
   const SecureBinaryData& passphrase,
   unsigned lookup)
{
   if (privateRoot.getSize() != 32)
      throw WalletException("empty root");

   //compute wallet ID
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privateRoot);
   
   //compute master ID as hmac256(root pubkey, "MetaEntry")
   string hmacMasterMsg("MetaEntry");
   auto&& masterID_long = BtcUtils::getHMAC256(
      pubkey, SecureBinaryData(hmacMasterMsg));
   auto&& masterID = BtcUtils::computeID(masterID_long);
   string masterIDStr(masterID.getCharPtr());

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterIDStr << "_wallet.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), 2);

   initWalletMetaDB(iface, masterIDStr);

   auto wltMetaPtr = make_shared<WalletMeta_Single>(iface);
   wltMetaPtr->parentID_ = masterID;

   {
      //walletID
      auto&& chaincode = BtcUtils::computeChainCode_Armory135(privateRoot);
      auto derScheme = make_shared<DerivationScheme_ArmoryLegacy>(
         chaincode);

      auto asset_single = make_shared<AssetEntry_Single>(
         ROOT_ASSETENTRY_ID, BinaryData(), 
         pubkey, nullptr);

      wltMetaPtr->walletID_ = move(computeWalletID(derScheme, asset_single));
   }
   
   //create kdf and master encryption key
   auto kdfPtr = make_shared<KeyDerivationFunction_Romix>();
   auto&& masterKeySBD = CryptoPRNG::generateRandom(32);
   DecryptedEncryptionKey masterEncryptionKey(masterKeySBD);
   masterEncryptionKey.deriveKey(kdfPtr);
   auto&& masterEncryptionKeyId = masterEncryptionKey.getId(kdfPtr->getId());

   auto cipher = make_unique<Cipher_AES>(kdfPtr->getId(), 
      masterEncryptionKeyId);

   SecureBinaryData dummy1, dummy2;
   auto&& privateRootCopy = privateRoot.copy();

   //address accounts
   set<shared_ptr<AccountType>> accountTypes;
   accountTypes.insert(
      make_shared<AccountType_ArmoryLegacy>(
      privateRootCopy, 
      dummy1, dummy2));
   (*accountTypes.begin())->setMain(true);
   
   SecureBinaryData dummy;
   auto walletPtr = initWalletDb(
      wltMetaPtr,
      kdfPtr,
      masterEncryptionKey,
      move(cipher),
      passphrase, 
      privateRoot, 
      dummy,
      move(accountTypes),
      lookup - 1);

   //set as main
   setMainWallet(iface, wltMetaPtr);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::
createFromPublicRoot_Armory135(
   const string& folder,
   SecureBinaryData& pubRoot,
   SecureBinaryData& chainCode,
   unsigned lookup)
{
   //compute master ID as hmac256(root pubkey, "MetaEntry")
   string hmacMasterMsg("MetaEntry");
   auto&& masterID_long = BtcUtils::getHMAC256(
      pubRoot, SecureBinaryData(hmacMasterMsg));
   auto&& masterID = BtcUtils::computeID(masterID_long);
   string masterIDStr(masterID.getCharPtr());

   //create wallet file and dbenv
   stringstream pathSS;
   pathSS << folder << "/armory_" << masterIDStr << "_WatchingOnly.lmdb";
   auto iface = getIfaceFromFile(pathSS.str(), 2);

   initWalletMetaDB(iface, masterIDStr);

   auto wltMetaPtr = make_shared<WalletMeta_Single>(iface);
   wltMetaPtr->parentID_ = masterID;

   {
      //walletID
      auto chainCode_copy = chainCode;
      auto derScheme = make_shared<DerivationScheme_ArmoryLegacy>(
         chainCode_copy);

      auto asset_single = make_shared<AssetEntry_Single>(
         ROOT_ASSETENTRY_ID, BinaryData(),
         pubRoot, nullptr);

      wltMetaPtr->walletID_ = move(computeWalletID(derScheme, asset_single));
   }

   //address accounts
   SecureBinaryData dummy;
   auto&& pubRootCopy = pubRoot.copy();
   auto&& chainCodeCopy = chainCode.copy();

   set<shared_ptr<AccountType>> accountTypes;
   accountTypes.insert(
      make_shared<AccountType_ArmoryLegacy>(
      dummy, pubRootCopy, chainCodeCopy));
   (*accountTypes.begin())->setMain(true);

   auto walletPtr = initWalletDbFromPubRoot(
      wltMetaPtr,
      pubRoot, 
      accountTypes,
      lookup - 1);

   //set as main
   setMainWallet(iface, wltMetaPtr);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromSeed_BIP32(
   const string& folder,
   const SecureBinaryData& seed,
   const vector<unsigned>& derivationPath,
   const SecureBinaryData& passphrase,
   unsigned lookup)
{
   if (seed.getSize() == 0)
      throw WalletException("empty seed");

   BIP32_Node rootNode;
   rootNode.initFromSeed(seed);

   //address accounts
   set<shared_ptr<AccountType>> accountTypes;

   /*
   Derive 2 hardcoded paths on top of the main derivatrionPath for
   this wallet, to support the default address chains for Armory operations
   */

   SecureBinaryData dummy1, dummy2;
   auto privateRootCopy_1 = rootNode.getPrivateKey();
   auto privateRootCopy_2 = rootNode.getPrivateKey();
   auto chaincode1 = rootNode.getChaincode();
   auto chaincode2 = rootNode.getChaincode();

   accountTypes.insert(
      make_shared<AccountType_BIP32_Legacy>(
         privateRootCopy_1,
         dummy1, chaincode1,
         derivationPath, 0, 0));
   (*accountTypes.begin())->setMain(true);

   accountTypes.insert(
      make_shared<AccountType_BIP32_SegWit>(
         privateRootCopy_2,
         dummy2, chaincode2,
         derivationPath, 0, 0));

   auto walletPtr = createFromBIP32Node(
      rootNode, 
      accountTypes, 
      passphrase, 
      folder, 
      lookup);

   //save the seed
   walletPtr->setSeed(seed, passphrase);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromBase58_BIP32(
   const string& folder,
   const SecureBinaryData& base58,
   const vector<unsigned>& derivationPath,
   const SecureBinaryData& passphrase,
   unsigned lookup)
{
   //setup node
   BIP32_Node node;
   node.initFromBase58(base58);

   bool isPublic = false;
   if (node.isPublic())
      isPublic = true;

   //address accounts
   set<shared_ptr<AccountType>> accountTypes;

   /*
   Unlike wallets setup from seeds, we do not make any assumption with those setup from
   a xpriv/xpub and only use what's provided in derivationPath. It is the caller's
   responsibility to run sanity checks.
   */

   if (!isPublic)
   {
      auto privateRootCopy = node.getPrivateKey();
      SecureBinaryData dummy;
      auto chainCodeCopy = node.getChaincode();

      accountTypes.insert(make_shared<AccountType_BIP32_Custom>(
         privateRootCopy, dummy, chainCodeCopy, derivationPath,
         node.getDepth(), node.getLeafID()));
      (*accountTypes.begin())->setMain(true);
   }
   else
   {
      //ctors move the arguments in, gotta create copies first
      auto pubkey_copy = node.getPublicKey();
      auto chaincode_copy = node.getChaincode();
      SecureBinaryData dummy1;

      accountTypes.insert(make_shared<AccountType_BIP32_Custom>(
         dummy1, pubkey_copy, chaincode_copy, derivationPath,
         node.getDepth(), node.getLeafID()));
      (*accountTypes.begin())->setMain(true);
   }

   auto walletPtr = createFromBIP32Node(
      node,
      accountTypes,
      passphrase,
      folder, 
      lookup);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromSeed_BIP32_Blank(
   const string& folder,
   const SecureBinaryData& seed,
   const SecureBinaryData& passphrase)
{
   if (seed.getSize() == 0)
      throw WalletException("empty seed");

   BIP32_Node rootNode;
   rootNode.initFromSeed(seed);

   //address accounts
   set<shared_ptr<AccountType>> accountTypes;

   /*
   no accounts are setup for a blank wallet
   */

   auto walletPtr = createFromBIP32Node(
      rootNode,
      accountTypes,
      passphrase,
      folder,
      0);

   //save the seed
   walletPtr->setSeed(seed, passphrase);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::createFromBIP32Node(
   const BIP32_Node& node,
   set<shared_ptr<AccountType>> accountTypes,
   const SecureBinaryData& passphrase,
   const string& folder,
   unsigned lookup)
{
   bool isPublic = false;
   if (node.isPublic())
      isPublic = true;

   //compute wallet ID
   auto pubkey = node.getPublicKey();

   //compute master ID as hmac256(root pubkey, "MetaEntry")
   string hmacMasterMsg("MetaEntry");
   auto&& masterID_long = BtcUtils::getHMAC256(
      pubkey, SecureBinaryData(hmacMasterMsg));
   auto&& masterID = BtcUtils::computeID(masterID_long);
   string masterIDStr(masterID.getCharPtr());

   //create wallet file and dbenv
   stringstream pathSS;
   if (!isPublic)
      pathSS << folder << "/armory_" << masterIDStr << "_wallet.lmdb";
   else
      pathSS << folder << "/armory_" << masterIDStr << "_WatchingOnly.lmdb";

   auto iface = getIfaceFromFile(pathSS.str(), 2);
   initWalletMetaDB(iface, masterIDStr);

   auto wltMetaPtr = make_shared<WalletMeta_Single>(iface);
   wltMetaPtr->parentID_ = masterID;

   {
      //walletID
      auto chaincode_copy = node.getChaincode();
      auto derScheme =
         make_shared<DerivationScheme_ArmoryLegacy>(chaincode_copy);

      auto asset_single = make_shared<AssetEntry_Single>(
         ROOT_ASSETENTRY_ID, BinaryData(),
         pubkey, nullptr);

      wltMetaPtr->walletID_ = move(computeWalletID(derScheme, asset_single));
   }

   //create kdf and master encryption key
   auto kdfPtr = make_shared<KeyDerivationFunction_Romix>();
   auto&& masterKeySBD = CryptoPRNG::generateRandom(32);
   DecryptedEncryptionKey masterEncryptionKey(masterKeySBD);
   masterEncryptionKey.deriveKey(kdfPtr);
   auto&& masterEncryptionKeyId = masterEncryptionKey.getId(kdfPtr->getId());

   auto cipher = make_unique<Cipher_AES>(kdfPtr->getId(),
      masterEncryptionKeyId);

   //address accounts
   shared_ptr<AssetWallet_Single> walletPtr = nullptr;

   if (!isPublic)
   {
      walletPtr = initWalletDb(
         wltMetaPtr,
         kdfPtr,
         masterEncryptionKey,
         move(cipher),
         passphrase,
         node.getPrivateKey(),
         node.getChaincode(),
         move(accountTypes),
         lookup);
   }
   else
   {
      //ctors move the arguments in, gotta create copies first
      auto pubkey_copy = node.getPublicKey();
      walletPtr = initWalletDbFromPubRoot(
         wltMetaPtr,
         pubkey_copy,
         move(accountTypes),
         lookup);
   }

   //set as main
   setMainWallet(iface, wltMetaPtr);

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet> AssetWallet::loadMainWalletFromFile(const string& path)
{
   auto iface = getIfaceFromFile(path.c_str(), 1);

   unsigned count;
   map<BinaryData, shared_ptr<WalletMeta>> metaMap;
   BinaryData masterID;
   BinaryData mainWalletID;

   //db count and names
   count = getDbCountAndNames(
      iface, metaMap, masterID, mainWalletID);

   //close env, reopen env with proper count
   iface.reset();

   auto metaIter = metaMap.find(mainWalletID);
   if (metaIter == metaMap.end())
      throw WalletException("invalid main wallet id");

   auto mainWltMeta = metaIter->second;
   metaMap.clear();

   mainWltMeta->iface_ = getIfaceFromFile(path.c_str(), count + 1);

   shared_ptr<AssetWallet> wltPtr;

   switch (mainWltMeta->type_)
   {
   case WalletMetaType_Single:
   {
      auto wltSingle = make_shared<AssetWallet_Single>(mainWltMeta);
      wltSingle->readFromFile();

      wltPtr = wltSingle;
      break;
   }

   case WalletMetaType_Multisig:
   {
      auto wltMS = make_shared<AssetWallet_Multisig>(mainWltMeta);
      wltMS->readFromFile();

      wltPtr = wltMS;
      break;
   }

   default:
      throw WalletException("unexpected main wallet type");
   }

   return wltPtr;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::putDbName(shared_ptr<WalletDBInterface> iface, 
   shared_ptr<WalletMeta> wltMetaPtr)
{
   iface->openDB(WALLETMETA_DBNAME);

   auto&& key = wltMetaPtr->getDbKey();
   auto&& val = wltMetaPtr->serialize();
   auto&& tx = iface->beginWriteTransaction(WALLETMETA_DBNAME);
   tx.insert(key, val);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::setMainWallet(
   shared_ptr<WalletDBInterface> iface, shared_ptr<WalletMeta> wltMetaPtr)
{
   iface->openDB(WALLETMETA_DBNAME);

   BinaryWriter bwKey;
   bwKey.put_uint32_t(MAINWALLET_KEY);

   BinaryWriter bwData;
   bwData.put_var_int(wltMetaPtr->walletID_.getSize());
   bwData.put_BinaryData(wltMetaPtr->walletID_);

   auto&& tx = iface->beginWriteTransaction(WALLETMETA_DBNAME);
   tx.insert(bwKey.getData(), bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::initWalletMetaDB(
   shared_ptr<WalletDBInterface> iface, const string& masterID)
{
   iface->openDB(WALLETMETA_DBNAME);

   BinaryWriter bwKey;
   bwKey.put_uint32_t(MASTERID_KEY);

   auto val = iface->getDataRef(WALLETMETA_DBNAME, bwKey.getData());
   if (val.getSize() != 0)
   {
      //the master key is already set, this is an existing wallet, abort
      throw WalletException("trying to init an already existing wallet");
   }

   BinaryWriter bwData;
   bwData.put_var_int(masterID.size());

   BinaryDataRef idRef;
   idRef.setRef(masterID);
   bwData.put_BinaryDataRef(idRef);

   auto&& tx = iface->beginWriteTransaction(WALLETMETA_DBNAME);
   tx.insert(bwKey.getData(), bwData.getData());
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetWallet::getDbCountAndNames(
   std::shared_ptr<WalletDBInterface> iface,
   map<BinaryData, shared_ptr<WalletMeta>>& metaMap,
   BinaryData& masterID, BinaryData& mainWalletID)
{
   if (iface == nullptr)
      throw WalletException("invalid dbenv");

   unsigned dbcount = 0;

   iface->openDB(WALLETMETA_DBNAME);

   {
      auto&& tx = iface->beginReadTransaction(WALLETMETA_DBNAME);

      {
         //masterID
         BinaryWriter bwKey;
         bwKey.put_uint32_t(MASTERID_KEY);

         try
         {
            masterID = getDataRefForKey(
               bwKey.getData(), iface, WALLETMETA_DBNAME);
         }
         catch (NoEntryInWalletException&)
         {
            throw runtime_error("missing masterID entry");
         }
      }

      {
         //mainWalletID
         BinaryWriter bwKey;
         bwKey.put_uint32_t(MAINWALLET_KEY);

         try
         {
            mainWalletID = getDataRefForKey(
               bwKey.getData(), iface, WALLETMETA_DBNAME);
         }
         catch (NoEntryInWalletException&)
         {
            throw runtime_error("missing main wallet entry");
         }
      }

      //meta map
      auto dbIter = iface->getIterator(WALLETMETA_DBNAME);

      BinaryWriter bwKey;
      bwKey.put_uint8_t(WALLETMETA_PREFIX);
      dbIter.seek(bwKey.getDataRef());

      while (dbIter.isValid())
      {
         auto iterkey = dbIter.key();
         auto itervalue = dbIter.value();

         //check value's advertized size is packet size and strip it
         BinaryRefReader brrVal(itervalue);
         auto valsize = brrVal.get_var_int();
         if (valsize != brrVal.getSizeRemaining())
            throw WalletException("entry val size mismatch");

         try
         {
            auto metaPtr = WalletMeta::deserialize(
               iface,
               iterkey,
               brrVal.get_BinaryDataRef(brrVal.getSizeRemaining()));

            dbcount++;
            if (metaPtr->shouldLoad())
               metaMap.insert(make_pair(
               metaPtr->getWalletID(), metaPtr));
         }
         catch (exception& e)
         {
            LOGERR << e.what();
            break;
         }

         dbIter.advance();
      }
   }

   return dbcount + 1;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData AssetWallet_Single::computeWalletID(
   shared_ptr<DerivationScheme> derScheme,
   shared_ptr<AssetEntry> rootEntry)
{
   auto&& addrVec = derScheme->extendPublicChain(rootEntry, 1, 1);
   if (addrVec.size() != 1)
      throw WalletException("unexpected chain derivation output");

   auto firstEntry = dynamic_pointer_cast<AssetEntry_Single>(addrVec[0]);
   if (firstEntry == nullptr)
      throw WalletException("unexpected asset entry type");

   return BtcUtils::computeID(firstEntry->getPubKey()->getUncompressedKey());
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::initWalletDb(
   shared_ptr<WalletMeta> metaPtr,
   shared_ptr<KeyDerivationFunction> masterKdf,
   DecryptedEncryptionKey& masterEncryptionKey,
   unique_ptr<Cipher> cipher,
   const SecureBinaryData& passphrase,
   const SecureBinaryData& privateRoot,
   const SecureBinaryData& chaincode,
   set<shared_ptr<AccountType>> accountTypes,
   unsigned lookup)
{
   //create root AssetEntry
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privateRoot);

   //copy cipher to cycle the IV then encrypt the private root
   masterEncryptionKey.deriveKey(masterKdf);
   auto&& masterEncryptionKeyId = masterEncryptionKey.getId(masterKdf->getId());
   auto&& rootCipher = cipher->getCopy(masterEncryptionKeyId);
   auto&& encryptedRoot = rootCipher->encrypt(
      &masterEncryptionKey, masterKdf->getId(), privateRoot);

   //create encrypted object
   auto rootAsset = make_shared<Asset_PrivateKey>(
      WRITE_UINT32_BE(UINT32_MAX), encryptedRoot, move(rootCipher));

   bool isBip32 = false;
   unsigned armory135AccCount = 0;
   for (auto& account : accountTypes)
   {
      switch (account->type())
      {
      case AccountTypeEnum_ArmoryLegacy:
      {  
         ++armory135AccCount;
         break;
      }

      default:
         continue;
      }
   }

   if (armory135AccCount > 0 && isBip32)
      throw AccountException("account type mismatch");

   //default to bip32 root if there are no account types specified
   if (armory135AccCount == 0 && !isBip32)
      isBip32 = true;

   shared_ptr<AssetEntry_Single> rootAssetEntry;
   if(isBip32)
   { 
      if (chaincode.getSize() == 0)
         throw WalletException("emtpy chaincode for bip32 root");

      rootAssetEntry = make_shared<AssetEntry_BIP32Root>(
         -1, BinaryData(),
         pubkey, rootAsset,
         chaincode, 0, 0, 0);
   }
   else
   {
      rootAssetEntry = make_shared<AssetEntry_Single>(
         -1, BinaryData(),
         pubkey, rootAsset);
   }

   if (metaPtr->dbName_.size() == 0)
   {
      string walletIDStr(metaPtr->getWalletIDStr());
      metaPtr->dbName_ = walletIDStr;
   }

   //encrypt master key, create object and set it
   metaPtr->defaultEncryptionKey_ = move(CryptoPRNG::generateRandom(32));
   auto defaultKey = metaPtr->getDefaultEncryptionKey();
   auto defaultEncryptionKeyPtr = make_unique<DecryptedEncryptionKey>(defaultKey);
   defaultEncryptionKeyPtr->deriveKey(masterKdf);
   metaPtr->defaultEncryptionKeyId_ =
      defaultEncryptionKeyPtr->getId(masterKdf->getId());

   //encrypt master encryption key with passphrase if present, otherwise use default
   unique_ptr<DecryptedEncryptionKey> topEncryptionKey;
   if (passphrase.getSize() > 0)
   {
      //copy passphrase
      auto&& passphraseCopy = passphrase.copy();
      topEncryptionKey = make_unique<DecryptedEncryptionKey>(passphraseCopy);
   }
   else
   {
      LOGWARN << "Wallet created without password, using default encryption key";
      topEncryptionKey = move(defaultEncryptionKeyPtr);
   }

   topEncryptionKey->deriveKey(masterKdf);
   auto&& topEncryptionKeyId = topEncryptionKey->getId(masterKdf->getId());
   auto&& masterKeyCipher = cipher->getCopy(topEncryptionKeyId);
   auto&& encrMasterKey = masterKeyCipher->encrypt(
      topEncryptionKey.get(),
      masterKdf->getId(),
      masterEncryptionKey.getData());

   auto masterKeyPtr = make_shared<Asset_EncryptionKey>(masterEncryptionKeyId,
      encrMasterKey, move(masterKeyCipher));

   metaPtr->masterEncryptionKeyId_ = masterKeyPtr->getId();
   metaPtr->defaultKdfId_ = masterKdf->getId();

   auto walletPtr = make_shared<AssetWallet_Single>(metaPtr);

   //add kdf & master key
   walletPtr->decryptedData_->addKdf(masterKdf);
   walletPtr->decryptedData_->addEncryptionKey(masterKeyPtr);

   //set passphrase lambda if necessary
   if (passphrase.getSize() > 0)
   {
      //custom passphrase, set prompt lambda for the chain extention
      auto passphraseLambda =
         [&passphrase](const set<BinaryData>&)->SecureBinaryData
      {
         return passphrase;
      };

      walletPtr->decryptedData_->setPassphrasePromptLambda(passphraseLambda);
   }

   //put wallet db name in meta db
   putDbName(metaPtr->iface(), metaPtr);

   //insert the original entries
   {
      auto&& tx = metaPtr->iface()->beginWriteTransaction(walletPtr->dbName_);
      walletPtr->putHeaderData(
         metaPtr->parentID_, metaPtr->walletID_);

      {
         //decrypted data container
         walletPtr->decryptedData_->updateOnDisk();
      }

      {
         //root asset
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);

         auto&& data = rootAssetEntry->serialize();
         tx.insert(bwKey.getData(), data);
      }

      {
         //accounts
         for (auto& accountType : accountTypes)
         {
            //instantiate AddressAccount object from AccountType
            auto account_ptr = make_shared<AddressAccount>(
               metaPtr->iface(), metaPtr->dbName_);

            auto&& cipher_copy = cipher->getCopy();
            account_ptr->make_new(accountType,
               walletPtr->decryptedData_,
               move(cipher_copy));

            //commit to disk
            account_ptr->commit();

            if (accountType->isMain())
               walletPtr->mainAccount_ = account_ptr->getID();
         }

         //main account
         if (walletPtr->mainAccount_.getSize() > 0)
         {
            BinaryWriter bwKey;
            bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

            BinaryWriter bwData;
            bwData.put_var_int(walletPtr->mainAccount_.getSize());
            bwData.put_BinaryData(walletPtr->mainAccount_);
            tx.insert(bwKey.getData(), bwData.getData());
         }
      }
   }

   //init walletptr from file
   walletPtr->readFromFile();

   {
      //asset lookup
      if (lookup == UINT32_MAX)
         lookup = DERIVATION_LOOKUP;

      if(lookup != 0)
         walletPtr->extendPrivateChain(lookup);
   }

   walletPtr->decryptedData_->resetPassphraseLambda();
   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet_Single> AssetWallet_Single::initWalletDbFromPubRoot(
   shared_ptr<WalletMeta> metaPtr,
   SecureBinaryData& pubRoot,
   set<shared_ptr<AccountType>> accountTypes,
   unsigned lookup)
{
   //create root AssetEntry
   auto rootAssetEntry = make_shared<AssetEntry_Single>(
      -1, BinaryData(),
      pubRoot, nullptr);

   if (metaPtr->dbName_.size() == 0)
   {
      string walletIDStr(metaPtr->getWalletIDStr());
      metaPtr->dbName_ = walletIDStr;
   }

   auto walletPtr = make_shared<AssetWallet_Single>(metaPtr);
   putDbName(metaPtr->iface(), metaPtr);

   /**insert the original entries**/
   {
      auto&& tx = metaPtr->iface()->beginWriteTransaction(walletPtr->dbName_);

      walletPtr->putHeaderData(
         metaPtr->parentID_, metaPtr->walletID_);

      {
         //root asset
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);

         auto&& data = rootAssetEntry->serialize();

         tx.insert(bwKey.getData(), data);
      }

      {
         //accounts
         for (auto& accountType : accountTypes)
         {
            //instantiate AddressAccount object from AccountType
            auto account_ptr = make_shared<AddressAccount>(
               metaPtr->iface(), metaPtr->dbName_);
            account_ptr->make_new(accountType, nullptr, nullptr);

            //commit to disk
            account_ptr->commit();

            if (accountType->isMain())
               walletPtr->mainAccount_ = account_ptr->getID();
         }

         //main account
         if (walletPtr->mainAccount_.getSize() > 0)
         {
            BinaryWriter bwKey;
            bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

            BinaryWriter bwData;
            bwData.put_var_int(walletPtr->mainAccount_.getSize());
            bwData.put_BinaryData(walletPtr->mainAccount_);
            tx.insert(bwKey.getData(), bwData.getData());
         }
      }
   }

   //init walletptr from file
   walletPtr->readFromFile();

   {
      //asset lookup
      auto topEntryPtr = rootAssetEntry;

      if (lookup == UINT32_MAX)
         lookup = DERIVATION_LOOKUP;

      walletPtr->extendPublicChain(lookup);
   }

   return walletPtr;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::putHeaderData(
   const BinaryData& parentID,
   const BinaryData& walletID)
{
   auto&& tx = iface_->beginWriteTransaction(dbName_);

   {

      //wallet type
      BinaryWriter bwKey;
      bwKey.put_uint32_t(WALLETTYPE_KEY);

      BinaryWriter bwData;
      bwData.put_var_int(4);
      bwData.put_uint32_t(WalletMetaType_Single);

      tx.insert(bwKey.getData(), bwData.getData());
   }

   AssetWallet::putHeaderData(parentID, walletID);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::putHeaderData(
   const BinaryData& parentID,
   const BinaryData& walletID)
{
   auto&& tx = iface_->beginWriteTransaction(dbName_);

   {
      //parent ID
      BinaryWriter bwKey;
      bwKey.put_uint32_t(PARENTID_KEY);

      BinaryWriter bwData;
      bwData.put_var_int(parentID.getSize());
      bwData.put_BinaryData(parentID);

      tx.insert(bwKey.getData(), bwData.getData());
   }

   {
      //wallet ID
      BinaryWriter bwKey;
      bwKey.put_uint32_t(WALLETID_KEY);

      BinaryWriter bwData;
      bwData.put_var_int(walletID.getSize());
      bwData.put_BinaryData(walletID);

      tx.insert(bwKey.getData(), bwData.getData());
   }
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef AssetWallet::getDataRefForKey(const BinaryData& key) const
{
   /** The reference lifetime is tied to the db tx lifetime. The caller has to
   maintain the tx for as long as the data ref needs to be valid **/

   return getDataRefForKey(key, iface_, dbName_);
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef AssetWallet::getDataRefForKey(const BinaryData& key, 
   std::shared_ptr<WalletDBInterface> iface, const std::string& dbName)
{
   auto ref = iface->getDataRef(dbName, key);

   if (ref.getSize() == 0)
      throw NoEntryInWalletException();

   return DBUtils::getDataRefForPacket(ref);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::readFromFile()
{
   //sanity check
   if (iface_ == nullptr)
      throw WalletException("uninitialized wallet object");

   auto&& tx = iface_->beginReadTransaction(dbName_);

   {
      //parentId
      BinaryWriter bwKey;
      bwKey.put_uint32_t(PARENTID_KEY);

      auto parentIdRef = getDataRefForKey(bwKey.getData());
      parentID_ = parentIdRef;
   }

   {
      //walletId
      BinaryWriter bwKey;
      bwKey.put_uint32_t(WALLETID_KEY);
      auto walletIdRef = getDataRefForKey(bwKey.getData());

      walletID_ = walletIdRef;
   }

   {
      //main account
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

      try
      {
         auto account_id = getDataRefForKey(bwKey.getData());

         mainAccount_ = account_id;
      }
      catch (NoEntryInWalletException&)
      { }
   }

   {
      //root asset
      BinaryWriter bwKey;
      bwKey.put_uint32_t(ROOTASSET_KEY);
      auto rootAssetRef = getDataRefForKey(bwKey.getData());

      auto asset_root = AssetEntry::deserDBValue(-1, BinaryData(), rootAssetRef);
      root_ = dynamic_pointer_cast<AssetEntry_Single>(asset_root);
   }

   {
      //seed
      seed_ = nullptr;

      try
      {
         BinaryWriter bwKey;
         bwKey.put_uint32_t(WALLET_SEED_KEY);
         auto rootAssetRef = getDataRefForKey(bwKey.getData());

         auto seedPtr = Asset_EncryptedData::deserialize(
            rootAssetRef.getSize(), rootAssetRef);
         auto seedObj = dynamic_pointer_cast<EncryptedSeed>(seedPtr);
         if (seedObj == nullptr)
            throw WalletException("failed to deser wallet seed");

         seed_ = seedObj;
      }
      catch(NoEntryInWalletException&)
      {}
   }

   //encryption keys and kdfs
   decryptedData_->readFromDisk();

   {
      //accounts
      BinaryWriter bwPrefix;
      bwPrefix.put_uint8_t(ADDRESS_ACCOUNT_PREFIX);
      auto dbIter = iface_->getIterator(dbName_);
      dbIter.seek(bwPrefix.getDataRef());

      while (dbIter.isValid())
      {
         //iterate through account keys
         auto&& key = dbIter.key();

         try
         {
            //instantiate account object and read data on disk
            auto addressAccount = make_shared<AddressAccount>(iface_, dbName_);
            addressAccount->readFromDisk(key);

            //insert
            accounts_.insert(make_pair(addressAccount->getID(), addressAccount));
         }
         catch (exception&)
         {
            //in case of exception, the value for this key is not for an
            //account. Assume we ran out of accounts and break out.
            break;
         }

         dbIter.advance();
      }

      loadMetaAccounts();
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Multisig::readFromFile()
{
   //sanity check
   if (iface_ == nullptr)
      throw WalletException("uninitialized wallet object");

   {
      {
         //parentId
         BinaryWriter bwKey;
         bwKey.put_uint32_t(PARENTID_KEY);

         auto parentIdRef = getDataRefForKey(bwKey.getData());
         parentID_ = parentIdRef;
      }

      {
         //walletId
         BinaryWriter bwKey;
         bwKey.put_uint32_t(WALLETID_KEY);
         auto walletIdRef = getDataRefForKey(bwKey.getData());

         walletID_ = walletIdRef;
      }

      {
         //lookup
         {
            BinaryWriter bwKey;
            bwKey.put_uint8_t(ASSETENTRY_PREFIX);
            auto lookupRef = getDataRefForKey(bwKey.getData());

            BinaryRefReader brr(lookupRef);
            chainLength_ = brr.get_uint32_t();
         }
      }
   }

   {
      unsigned n = 0;

      map<BinaryData, shared_ptr<AssetWallet_Single>> walletPtrs;
      for (unsigned i = 0; i < n; i++)
      {
         stringstream ss;
         ss << "Subwallet-" << i;

         auto subWltMeta = make_shared<WalletMeta_Subwallet>(iface_);
         subWltMeta->dbName_ = ss.str();

         auto subwalletPtr = make_shared<AssetWallet_Single>(subWltMeta);
         subwalletPtr->readFromFile();
         walletPtrs[subwalletPtr->getID()] = subwalletPtr;

      }

      loadMetaAccounts();
   }
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewAddress(
   AddressEntryType aeType)
{
   /***
   The wallet will always try to deliver an address with the requested type if 
   any of its accounts supports it. It will prioritize the main account, then
   try through all accounts in binary order.
   ***/

   //lock
   ReentrantLock lock(this);

   if (mainAccount_.getSize() == 0)
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->getNewAddress(aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->getNewAddress(aeType);
   }

   throw WalletException("unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewChangeAddress(
   AddressEntryType aeType)
{
   ReentrantLock lock(this);

   if (mainAccount_.getSize() == 0)
      throw WalletException("no main account for wallet");

   auto mainAccount = getAccountForID(mainAccount_);
   if (mainAccount->hasAddressType(aeType))
      return mainAccount->getNewChangeAddress(aeType);

   for (auto& account : accounts_)
   {
      if (account.second->hasAddressType(aeType))
         return account.second->getNewChangeAddress(aeType);
   }

   throw WalletException("unexpected address entry type");
   return nullptr;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getNewAddress(
   const BinaryData& accountID, AddressEntryType aeType)
{
   ReentrantLock lock(this);

   auto account = getAccountForID(accountID);
   auto newAddress = account->getNewAddress(aeType);

   return newAddress;
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet::hasScrAddr(const BinaryData& scrAddr)
{
   try
   {
      getAssetIDForAddr(scrAddr);
   }
   catch (runtime_error&)
   {
      return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
const pair<BinaryData, AddressEntryType>& 
   AssetWallet::getAssetIDForAddr(const BinaryData& scrAddr)
{
   //this takes prefixed hashes or a b58 address

   ReentrantLock lock(this);
   
   BinaryData scrHash;

   try
   {
      scrHash = move(BtcUtils::base58toScrAddr(scrAddr));
   }
   catch(runtime_error&)
   {
      scrHash = scrAddr;
   }

   for (auto acc : accounts_)
   {
      try
      {
         return acc.second->getAssetIDPairForAddr(scrHash);
      }
      catch (runtime_error&)
      {
         continue;
      }
   }

   throw runtime_error("unknown scrAddr");
}

////////////////////////////////////////////////////////////////////////////////
AddressEntryType AssetWallet::getAddrTypeForID(const BinaryData& ID)
{
   ReentrantLock lock(this);
   
   auto addrPtr = getAddressEntryForID(ID);
   return addrPtr->getType();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressAccount> AssetWallet::getAccountForID(
   const BinaryData& ID) const
{
   if (ID.getSize() < 4)
      throw WalletException("invalid account id");

   auto idRef = ID.getSliceRef(0, 4);
   auto iter = accounts_.find(idRef);
   if (iter == accounts_.end())
      throw WalletException("unknown account ID");

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
const string& AssetWallet::getDbFilename(void) const
{ 
   if (iface_ == nullptr)
      throw WalletException("uninitialized db environment");
   return iface_->getFilename(); 
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::shutdown()
{
   if (iface_ == nullptr)
      return;

   iface_.reset();
}

////////////////////////////////////////////////////////////////////////////////
AddressEntryType AssetWallet::getAddrTypeForAccount(const BinaryData& ID)
{
   auto acc = getAccountForID(ID);
   return acc->getAddressType();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AddressEntry> AssetWallet::getAddressEntryForID(
   const BinaryData& ID) const
{
   ReentrantLock lock(this);

   if (ID.getSize() != 12)
      throw WalletException("invalid asset id");

   auto accPtr = getAccountForID(ID);
   return accPtr->getAddressEntryForID(ID.getRef());
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::updateHashMap()
{
   ReentrantLock lock(this);

   for (auto account : accounts_)
      account.second->updateAddressHashMap();
}

////////////////////////////////////////////////////////////////////////////////
set<BinaryData> AssetWallet::getAddrHashSet()
{
   ReentrantLock lock(this);

   set<BinaryData> addrHashSet;
   for (auto account : accounts_)
   {
      auto& hashes = account.second->getAddressHashMap();

      for (auto& hashPair : hashes)
         addrHashSet.insert(hashPair.first);
   }

   return addrHashSet;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetWallet::getAssetForID(const BinaryData& ID) const
{
   if (ID.getSize() < 8)
      throw WalletException("invalid asset ID");

   ReentrantLock lock(this);

   auto acc = getAccountForID(ID);
   return acc->getAssetForID(ID.getSliceRef(4, ID.getSize() - 4));
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet::getID(void) const
{
   return string(walletID_.getCharPtr());
}

////////////////////////////////////////////////////////////////////////////////
ReentrantLock AssetWallet::lockDecryptedContainer(void)
{
   return move(ReentrantLock(decryptedData_.get()));
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet::isDecryptedContainerLocked() const
{
   try
   {
      auto lock = SingleLock(decryptedData_.get());
      return false;
   }
   catch (AlreadyLocked&)
   {}

   return true;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPublicChain(unsigned count)
{
   for (auto& account : accounts_)
   {
      account.second->extendPublicChain(count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPrivateChain(unsigned count)
{
   for (auto& account : accounts_)
   {
      account.second->extendPrivateChain(decryptedData_, count);
   }
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPublicChainToIndex(
   const BinaryData& account_id, unsigned count)
{
   auto account = getAccountForID(account_id);
   account->extendPublicChainToIndex(
      account->getOuterAccount()->getID(), count);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::extendPrivateChainToIndex(
   const BinaryData& account_id, unsigned count)
{
   auto account = getAccountForID(account_id);
   account->extendPrivateChainToIndex(
      decryptedData_,
      account->getOuterAccount()->getID(), count);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getDecryptedValue(
   shared_ptr<Asset_EncryptedData> assetPtr)
{
   //have to lock the decryptedData object before calling this method
   return decryptedData_->getDecryptedPrivateData(assetPtr);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getDecryptedPrivateKeyForAsset(
   std::shared_ptr<AssetEntry_Single> assetPtr)
{
   auto assetPrivKey = assetPtr->getPrivKey();

   if (assetPrivKey == nullptr)
   {
      auto account = getAccountForID(assetPtr->getAccountID());
      assetPrivKey = account->fillPrivateKey(
         decryptedData_, assetPtr->getID());
   }
   
   return getDecryptedValue(assetPrivKey);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Multisig::getDecryptedValue(
   shared_ptr<Asset_EncryptedData> assetPtr)
{
   return decryptedData_->getDecryptedPrivateData(assetPtr);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::changeMasterPassphrase(
   const SecureBinaryData& newPassphrase)
{
   auto&& masterKeyId = root_->getPrivateEncryptionKeyId();
   auto&& kdfId = root_->getKdfId();

   decryptedData_->encryptEncryptionKey(
      masterKeyId, kdfId, newPassphrase, true);
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::addPassphrase(const SecureBinaryData& passphrase)
{
   auto&& masterKeyId = root_->getPrivateEncryptionKeyId();
   auto&& masterKdfId = root_->getKdfId();

   decryptedData_->encryptEncryptionKey(
      masterKeyId, masterKdfId, passphrase, false);
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getPublicRoot() const
{
   if (root_ == nullptr)
      throw WalletException("null root");

   auto pubkey = root_->getPubKey();
   if (pubkey == nullptr)
      throw WalletException("null pubkey");

   return pubkey->getUncompressedKey();
}

////////////////////////////////////////////////////////////////////////////////
const SecureBinaryData& AssetWallet_Single::getArmory135Chaincode() const
{
   BinaryWriter bw;
   bw.put_uint32_t(ARMORY_LEGACY_ACCOUNTID, BE);

   auto account = getAccountForID(bw.getData());
   auto assetAccount = account->getOuterAccount();
   return assetAccount->getChaincode();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> 
   AssetWallet_Single::getMainAccountAssetForIndex(unsigned id) const
{
   auto account = getAccountForID(mainAccount_);
   if (account == nullptr)
      throw WalletException("failed to grab main account");

   return account->getOutterAssetForIndex(id);
}

////////////////////////////////////////////////////////////////////////////////
unsigned AssetWallet_Single::getMainAccountAssetCount(void) const
{
   auto account = getAccountForID(mainAccount_);
   if (account == nullptr)
      throw WalletException("failed to grab main account");

   auto asset_account = account->getOuterAccount();
   return asset_account->getAssetCount();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetEntry> AssetWallet_Single::getAccountRoot(
   const BinaryData& id) const
{
   auto account = getAccountForID(id);
   if (account == nullptr)
      throw WalletException("failed to grab main account");

   return account->getOutterAssetRoot();
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void AssetWallet::addMetaAccount(MetaAccountType type)
{
   auto account_ptr = make_shared<MetaDataAccount>(iface_, dbName_);
   account_ptr->make_new(type);

   //do not overwrite existing account of the same type
   if (metaDataAccounts_.find(type) != metaDataAccounts_.end())
      return;

   account_ptr->commit();
   metaDataAccounts_.insert(make_pair(type, account_ptr));
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet::loadMetaAccounts()
{
   //accounts
   BinaryWriter bwPrefix;
   bwPrefix.put_uint8_t(META_ACCOUNT_PREFIX);
   auto dbIter = iface_->getIterator(dbName_);
   dbIter.seek(bwPrefix.getDataRef());

   while (dbIter.isValid())
   {
      //iterate through account keys
      auto&& key = dbIter.key();

      try
      {
         //instantiate account object and read data on disk
         auto metaAccount = make_shared<MetaDataAccount>(iface_, dbName_);
         metaAccount->readFromDisk(key);

         //insert
         metaDataAccounts_.insert(
            make_pair(metaAccount->getType(), metaAccount));
      }
      catch (exception&)
      {
         //in case of exception, the value for this key is not for an
         //account. Assume we ran out of accounts and break out.
         break;
      }

      dbIter.advance();
   }
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<MetaDataAccount> AssetWallet::getMetaAccount(MetaAccountType type)
{
   auto iter = metaDataAccounts_.find(type);

   if (iter == metaDataAccounts_.end())
      throw WalletException("no meta account for this type");
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
bool AssetWallet_Single::isWatchingOnly() const
{
   return !root_->hasPrivateKey();
}

////////////////////////////////////////////////////////////////////////////////
string AssetWallet::forkWathcingOnly(const string& filename)
{
   //strip '_wallet' extention
   auto underscoreIndex = filename.find_last_of("_");
   auto newname = filename.substr(0, underscoreIndex);

   //set WO suffix
   newname.append("_WatchingOnly.lmdb");

   //check file does not exist
   if (DBUtils::fileExists(newname, 0))
      throw WalletException("WO wallet filename already exists");

   //read meta data header
   map<BinaryData, shared_ptr<WalletMeta>> metaMap;
   BinaryData masterID;
   BinaryData mainWalletID;

   auto originIface = getIfaceFromFile(filename, 1);
   auto count = getDbCountAndNames(
      originIface, metaMap, masterID, mainWalletID);
   originIface = getIfaceFromFile(filename, count + 1);

   //create WO dbEnv
   auto woIface = getIfaceFromFile(newname, count + 1);

   //set master id
   string masterIdStr(masterID.getCharPtr(), masterID.getSize());
   initWalletMetaDB(woIface, masterIdStr);

   //open meta db
   woIface->openDB(WALLETMETA_DBNAME);

   //cycle through wallet metas, copy wallet structure and assets
   for (auto& metaPtr : metaMap)
   {
      switch (metaPtr.second->type_)
      {
      case WalletMetaType_Single:
      {
         {
            //copy wallet meta
            auto&& key = metaPtr.second->getDbKey();
            auto&& val = metaPtr.second->serialize();

            auto&& tx = woIface->beginWriteTransaction(WALLETMETA_DBNAME);
            tx.insert(key, val);
         }

         //load wallet
         metaPtr.second->iface_ = originIface;
         auto wltSingle = make_shared<AssetWallet_Single>(metaPtr.second);
         wltSingle->readFromFile();

         //copy content
         AssetWallet_Single::copyPublicData(wltSingle, woIface);

         //close the wallet
         wltSingle.reset();
         break;
      }

      default:
         throw WalletException(
            "WO forking for this kind of wallet not yet implemented");
      }
   }

   {
      //set main wallet
      BinaryWriter bwKey;
      bwKey.put_uint32_t(MAINWALLET_KEY);

      BinaryWriter bwData;
      bwData.put_var_int(mainWalletID.getSize());
      bwData.put_BinaryData(mainWalletID);

      auto&& tx = woIface->beginWriteTransaction(WALLETMETA_DBNAME);
      tx.insert(bwKey.getData(), bwData.getData());
   }

   //close dbs
   originIface.reset();
   woIface.reset();

   //return the file name of the wo wallet
   return newname;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::copyPublicData(
   shared_ptr<AssetWallet_Single> wlt,
   std::shared_ptr<WalletDBInterface> iface)
{
   {
      //open the relevant db name
      iface->openDB(wlt->dbName_);
      auto&& tx = iface->beginWriteTransaction(wlt->dbName_);

      {
         //copy root
         auto rootCopy = wlt->root_->getPublicCopy();

         //commit root
         BinaryWriter bwKey;
         bwKey.put_uint32_t(ROOTASSET_KEY);

         auto&& data = rootCopy->serialize();

         tx.insert(bwKey.getData(), data);
      }

      {
         //address accounts
         for (auto& addrAccPtr : wlt->accounts_)
         {
            auto woAcc = addrAccPtr.second->getWatchingOnlyCopy(iface, wlt->dbName_);
            woAcc->commit();
         }
      }

      {
         //meta accounts
         for (auto& metaAccPtr : wlt->metaDataAccounts_)
         {
            auto accCopy = metaAccPtr.second->copy(iface, wlt->dbName_);
            accCopy->commit();
         }
      }
   }

   //header data
   {
      auto metaPtr = make_shared<WalletMeta_Single>(iface);
      metaPtr->dbName_ = wlt->dbName_;
      AssetWallet_Single wltWO(metaPtr);

      auto&& tx = wltWO.iface_->beginWriteTransaction(wltWO.dbName_);
      wltWO.putHeaderData(wlt->parentID_, wlt->walletID_);

      if (wlt->mainAccount_.getSize() > 0)
      {
         //main account
         BinaryWriter bwKey;
         bwKey.put_uint32_t(MAIN_ACCOUNT_KEY);

         BinaryWriter bwData;
         bwData.put_var_int(wlt->mainAccount_.getSize());
         bwData.put_BinaryData(wlt->mainAccount_);
         tx.insert(bwKey.getData(), bwData.getData());
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
set<BinaryData> AssetWallet::getAccountIDs(void) const
{
   set<BinaryData> result;
   for (auto& accPtr : accounts_)
      result.insert(accPtr.second->getID());

   return result;
}

////////////////////////////////////////////////////////////////////////////////
map<BinaryData, shared_ptr<AddressEntry>> AssetWallet::getUsedAddressMap() const
{
   /***
   This is an expensive call, do not spam it.
   ***/

   map<BinaryData, shared_ptr<AddressEntry>> result;
   for (auto& account : accounts_)
   {
      auto&& addrMap = account.second->getUsedAddressMap();
      result.insert(addrMap.begin(), addrMap.end());
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
void AssetWallet_Single::setSeed(
   const SecureBinaryData& seed,
   const SecureBinaryData& passphrase)
{
   //copy root node cipher
   auto rootPtr = dynamic_pointer_cast<AssetEntry_BIP32Root>(root_);
   if (rootPtr == nullptr)
      throw WalletException("expected BIP32 root object");
   auto cipherCopy = 
      rootPtr->getPrivKey()->getCipherDataPtr()->cipher_->getCopy();

   //if custom passphrase, set prompt lambda prior to encryption
   if (passphrase.getSize() > 0)
   {
      auto passphraseLambda =
         [&passphrase](const set<BinaryData>&)->SecureBinaryData
      {
         return passphrase;
      };

      decryptedData_->setPassphrasePromptLambda(passphraseLambda);
   }

   //create encrypted seed object
   {
      auto lock = lockDecryptedContainer();

      auto&& cipherText = decryptedData_->encryptData(cipherCopy.get(), seed);
      seed_ = make_shared<EncryptedSeed>(cipherText, move(cipherCopy));
   }

   //write to disk
   {
      auto&& tx = iface_->beginWriteTransaction(dbName_);

      BinaryWriter bwKey;
      bwKey.put_uint32_t(WALLET_SEED_KEY);
      auto&& serData = seed_->serialize();

      tx.insert(bwKey.getData(), serData);
   }

   //reset prompt lambda
   resetPassphrasePromptLambda();
}
