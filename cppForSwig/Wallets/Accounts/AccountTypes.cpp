////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "AccountTypes.h"
#include "../Assets.h"
#include "../DecryptedDataContainer.h"

using namespace std;
using namespace Armory::Assets;
using namespace Armory::Accounts;
using namespace Armory::Wallets;

#define ARMORY135_PRIVKEY_PREFIX    1
#define ARMORY135_PRIVKEY_SIZE      32

#define ARMORY135_PUBKEY_PREFIX     2
#define ARMORY135_PUBKEY_SIZE       65

#define ARMORY135_CHAINCODE_PREFIX  3
#define ARMORY135_CHAINCODE_SIZE    32

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AccountType::~AccountType()
{}


////////////////////////////////////////////////////////////////////////////////
void AccountType::addAddressType(AddressEntryType addrType)
{
   addressTypes_.insert(addrType);
}

////////////////////////////////////////////////////////////////////////////////
void AccountType::setDefaultAddressType(AddressEntryType addrType)
{
   defaultAddressEntryType_ = addrType;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_ArmoryLegacy
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
const Armory::Wallets::AddressAccountId
   AccountType_ArmoryLegacy::addrAccountId(ARMORY_LEGACY_ACCOUNTID);

AccountType_ArmoryLegacy::AccountType_ArmoryLegacy() :
   AccountType()
{
   //uncompressed p2pkh
   addressTypes_.insert(AddressEntryType(
      AddressEntryType_P2PKH | AddressEntryType_Uncompressed));

   //nested compressed p2pk
   addressTypes_.insert(AddressEntryType(
      AddressEntryType_P2PK | AddressEntryType_P2SH));

   //nested p2wpkh
   addressTypes_.insert(AddressEntryType(
      AddressEntryType_P2WPKH | AddressEntryType_P2SH));

   //default type
   defaultAddressEntryType_ = AddressEntryType(
      AddressEntryType_P2PKH | AddressEntryType_Uncompressed);
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountId AccountType_ArmoryLegacy::getOuterAccountID(void) const
{
   return AssetAccountId(getAccountID(), ARMORY_LEGACY_ASSET_ACCOUNTID);
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountId AccountType_ArmoryLegacy::getInnerAccountID(void) const
{
   return {};
}

////////////////////////////////////////////////////////////////////////////////
AddressAccountId AccountType_ArmoryLegacy::getAccountID() const
{
   return addrAccountId;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_BIP32
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
AccountType_BIP32::AccountType_BIP32(DerivationTree& tree) :
   AccountType(), derTree_(move(tree))
{}

////////////////////////////////////////////////////////////////////////////////
AddressAccountId AccountType_BIP32::getAccountID() const
{
   //this ensures address accounts of different types based on the same
   //bip32 root do not end up with the same id

   auto seedFingerprint = derTree_.getSeedFingerprint();
   if (seedFingerprint == UINT32_MAX)
      cout << "[getAccountID] uninitialized seed fingerprint" << endl;

   BinaryWriter bw;
   bw.put_uint32_t(seedFingerprint);

   /* add in unique data identifying this account */

   //account soft derivation paths
   auto paths = derTree_.getPaths();
   for (const auto& path : paths)
   {
      auto path32 = DerivationTree::toPath32(path);
      for (auto& node : path32)
         bw.put_uint32_t(node, BE);
   }

   //address types
   for (auto& addressType : addressTypes_)
      bw.put_uint32_t(addressType, BE);

   //default address
   bw.put_uint32_t(defaultAddressEntryType_);

   //main flag
   bw.put_uint8_t(isMain_);

   //hash, use first 4 bytes
   auto pub_hash160 = BtcUtils::getHash160(bw.getData());
   BinaryRefReader brr(pub_hash160.getRef());
   AccountKeyType addressAccountKey = brr.get_int32_t(BE);

   auto legacyAddressAccountId = ARMORY_LEGACY_ACCOUNTID;
   AccountKeyType legacyAccountKey;
   memcpy(&legacyAccountKey, &legacyAddressAccountId, sizeof(AccountKeyType));

   if (addressAccountKey == legacyAccountKey ||
      addressAccountKey == IMPORTS_ACCOUNTID)
   {
      throw AccountException("BIP32 account ID collision");
   }

   return AddressAccountId(addressAccountKey);
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setNodes(const set<unsigned>& nodes)
{
   for (auto& node : nodes)
   {
      auto& branch = derTree_.forkFromBranch(0);
      branch.appendNode(node);
   }
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountId AccountType_BIP32::getOuterAccountID(void) const
{
   if (!haveOuterAccId_)
      return {};

   return AssetAccountId(getAccountID(), outerAccountKey_);
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountId AccountType_BIP32::getInnerAccountID(void) const
{
   if (!haveInnerAccId_)
      return {};

   return AssetAccountId(getAccountID(), innerAccountKey_);
}

////////////////////////////////////////////////////////////////////////////////
unsigned AccountType_BIP32::getAddressLookup() const
{
   if (addressLookup_ == UINT32_MAX)
      throw AccountException("[AccountType_BIP32] uninitialized address lookup");
   return addressLookup_;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setOuterAccountID(const AccountKeyType& outerAccountKey)
{
   outerAccountKey_ = outerAccountKey;
   haveOuterAccId_ = true;
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setInnerAccountID(const AccountKeyType& innerAccountKey)
{
   innerAccountKey_ = innerAccountKey;
   haveInnerAccId_ = true;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AccountType_BIP32> AccountType_BIP32::makeFromDerPaths(
   uint32_t seedFingerprint, const vector<vector<unsigned>>& derPaths)
{
   auto tree = DerivationTree::fromDerivationPaths(seedFingerprint, derPaths);
   return make_shared<AccountType_BIP32>(tree);
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setRoots(const vector<PathAndRoot>& pathsAndRoots)
{
   auto paths = derTree_.getPaths();

   auto getNodeForRoot = [](const vector<uint32_t>& rootPath,
      const DerivationBranch::Path& path, const NodeData** nodeData)->bool
   {
      if (rootPath.empty() || rootPath.size() > path.size())
         return false;

      auto pathIt = path.begin();
      auto rootPathIt = rootPath.begin();

      while (rootPathIt != rootPath.end())
      {
         if (pathIt->value != *rootPathIt)
            return false;

         ++rootPathIt;
         ++pathIt;
      }

      pathIt = prev(pathIt);
      *nodeData = &(*pathIt);
      return true;
   };

   auto matchRootToNode = [this, &paths, getNodeForRoot](
      const PathAndRoot& pathAndRoot)->bool
   {
      const NodeData* theNode = nullptr;
      for (const auto& path : paths)
      {
         if (getNodeForRoot(pathAndRoot.getPath(), path, &theNode))
         {
            derTree_.addB58Root(*theNode, pathAndRoot.getRootSbd());
            return true;
         }
      }

      return false;
   };

   for (const auto& pathAndRootIt : pathsAndRoots)
   {
      if (!matchRootToNode(pathAndRootIt))
         throw AccountException("[setRoots] could not fine node for root");
   }
}

////////////////////////////////////////////////////////////////////////////////
void AccountType_BIP32::setSeedRoot(const SecureBinaryData& b58Root)
{
   const auto& seedNode = derTree_.getSeedNode();
   derTree_.addB58Root(seedNode, b58Root);
}

////////////////////////////////////////////////////////////////////////////////
const DerivationTree& AccountType_BIP32::getDerivationTree() const
{
   return derTree_;
}

////////////////////////////////////////////////////////////////////////////////
uint32_t AccountType_BIP32::getSeedFingerprint() const
{
   return derTree_.getSeedFingerprint();
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_Salted
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
shared_ptr<AccountType_BIP32_Salted> AccountType_BIP32_Salted::makeFromDerPaths(
   uint32_t seedFingerprint, const vector<vector<unsigned>>& derPaths,
   const SecureBinaryData& salt)
{
   auto tree = DerivationTree::fromDerivationPaths(seedFingerprint, derPaths);
   return make_shared<AccountType_BIP32_Salted>(tree, salt);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// AccountType_ECDH
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
bool AccountType_ECDH::isWatchingOnly(void) const
{
   return privateKey_.empty();
}

////////////////////////////////////////////////////////////////////////////////
AddressAccountId AccountType_ECDH::getAccountID() const
{
   AccountKeyType accountKey;
   if (isWatchingOnly())
   {
      //this ensures address accounts of different types based on the same
      //bip32 root do not end up with the same id
      auto rootCopy = publicKey_;
      rootCopy.getPtr()[0] ^= (uint8_t)type();

      auto pub_hash160 = BtcUtils::getHash160(rootCopy);
      BinaryRefReader brr(pub_hash160.getRef());
      accountKey = brr.get_int32_t(BE);
   }
   else
   {
      auto&& root_pub = CryptoECDSA().ComputePublicKey(privateKey_, true);
      root_pub.getPtr()[0] ^= (uint8_t)type();

      auto&& pub_hash160 = BtcUtils::getHash160(root_pub);
      BinaryRefReader brr(pub_hash160.getRef());
      accountKey = brr.get_int32_t(BE);
   }

   auto legacyAddressAccountId = ARMORY_LEGACY_ACCOUNTID;
   AccountKeyType legacyAccountKey;
   memcpy(&legacyAccountKey, &legacyAddressAccountId, sizeof(AccountKeyType));

   if (accountKey == legacyAccountKey || accountKey == IMPORTS_ACCOUNTID)
      throw AccountException("BIP32 account ID collision");

   return AddressAccountId(accountKey);
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountId AccountType_ECDH::getOuterAccountID() const
{
   return AssetAccountId(getAccountID(), ECDH_ASSET_ACCOUNTID);
}

////////////////////////////////////////////////////////////////////////////////
AssetAccountId AccountType_ECDH::getInnerAccountID() const
{
   return {};
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DerivationBranch
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
DerivationBranch::DerivationBranch(const NodeData& parent, uint16_t id) :
   parent_(parent), id_(id)
{
   //private ctor
}

////////////////////////////////////////////////////////////////////////////////
const NodeData& DerivationBranch::appendNode(NodeData::NodeVal newNode)
{
   uint16_t depth = parent_.depth + (uint16_t)nodes_.size() + 1;
   auto insertIt = nodes_.emplace(NodeData(depth, id_, newNode));

   return *insertIt.first;
}

////////////////////////////////////////////////////////////////////////////////
const NodeData& DerivationBranch::getNodeByRelativeDepth(NodeData::Depth depth)
{
   //0 for branch id and value, not relevant for a depth search
   //true to enable depth search
   NodeData findNode(parent_.depth + depth + 1, 0, 0 , true);
   auto it = nodes_.find(findNode);
   if (it == nodes_.end())
      throw runtime_error("[getNodeByRelativeDepth] no node for this depth");

   return *it;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// DerivationTree
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
DerivationTree::DerivationTree(uint32_t fingerprint)
{
   //setup branch id
   auto branchId = branchCounter_++;

   //create origin parent node
   NodeData parentNode(SEED_DEPTH, branchId, fingerprint);
   branches_.emplace(branchId, DerivationBranch(parentNode, branchId));
}

////////////////////////////////////////////////////////////////////////////////
void DerivationTree::mergeDerPaths(
   DerivationBranch& branch, HeadsMap& heads)
{
   //iterate over the heads map until it is exhausted
   while (true)
   {
      //heads map cleanup
      auto headIt = heads.begin();
      while (headIt != heads.end())
      {
         if (!headIt->second.isValid())
         {
            heads.erase(headIt++);
            continue;
         }

         ++headIt;
      }

      if (heads.empty())
         break;

      //<node value, map of path iterators that match the node>
      map<uint32_t, HeadsMap> theNodes;
      for (auto& headIt : heads)
      {
         auto& mapIt = theNodes[*(headIt.second.it++)];
         mapIt.emplace(headIt);
      }

      if (theNodes.size() == 1)
      {
         branch.appendNode(theNodes.begin()->first);
         continue;
      }

      /*
      If we got this far we got at least 2 nodes that differ amoung our
      paths. Find the branch point with the most paths on it and grow the
      current branch from it. Fork out the other branch points.
      */

      auto branchIt = theNodes.begin();
      auto largestIt = branchIt;
      while (branchIt != theNodes.end())
      {
         if (branchIt->second.size() > largestIt->second.size())
            largestIt = branchIt;
         ++branchIt;
      }

      branchIt = theNodes.begin();
      while (branchIt != theNodes.end())
      {
         //if this is the branchpoint with the most paths, do not
         //fork these, they will continue growing the current branch
         if (branchIt == largestIt)
         {
            ++branchIt;
            continue;
         }

         //fork the current branch from this branchpoint and grow
         //the related paths from the new fork
         auto& fork = forkFromBranch(branch);

         //use the heads map of this branchpoint with the forked paths,
         //but first remove them current from heads map
         for (auto& branchpoint : branchIt->second)
         {
            heads.erase(branchpoint.first);

            //rollback the branched off iterator so that its first
            //value is added to the fork
            branchpoint.second.it = prev(branchpoint.second.it);
         }

         //build out the new fork
         mergeDerPaths(fork, branchIt->second);

         ++branchIt;
      }

      branch.appendNode(largestIt->first);
   }
}

////////////////////////////////////////////////////////////////////////////////
DerivationTree DerivationTree::fromDerivationPaths(
   uint32_t seedFingerprint, const vector<vector<uint32_t>>& derPaths)
{
   /*
   Merge the individual paths into a unified tree. We assume all paths
   originate from the wallet's seed.
   */
   DerivationTree tree(seedFingerprint);

   //seed the heads map
   HeadsMap heads;
   for (size_t i=0; i<derPaths.size(); i++)
   {
      auto& path = derPaths[i];
      if (path.empty())
         continue;
      heads.emplace(i, PathIt{&path});
   }

   //start merging from the main branch, recursive call will take care
   //of the rest
   auto& mainBranch = tree.getBranch(0);
   tree.mergeDerPaths(mainBranch, heads);

   return tree;
}

////////////////////////////////////////////////////////////////////////////////
DerivationBranch& DerivationTree::getBranch(const NodeData& node)
{
   return getBranch(node.branchId);
}

////////////////////////////////////////////////////////////////////////////////
DerivationBranch& DerivationTree::getBranch(NodeData::BranchId id)
{
   const DerivationTree* const_this = const_cast<DerivationTree*>(this);
   return const_cast<DerivationBranch&>(const_this->getBranch(id));
}

////////////////////////////////////////////////////////////////////////////////
const DerivationBranch& DerivationTree::getBranch(NodeData::BranchId id) const
{
   /*
   Returns a branch by its id. Throws if nothing is found.
   */

   if (branches_.empty())
      throw runtime_error("[getBranch] empty branches");

   //get node level
   return branches_.at(id);
}

////////////////////////////////////////////////////////////////////////////////
DerivationBranch& DerivationTree::forkFromBranch(const NodeData& node)
{
   return forkFromBranch(node.branchId);
}

DerivationBranch& DerivationTree::forkFromBranch(const DerivationBranch& branch)
{
   return forkFromBranch(branch.id_);
}

////////////////////////////////////////////////////////////////////////////////
DerivationBranch& DerivationTree::forkFromBranch(NodeData::BranchId id)
{
   /*
   Create a new branch, forking from the last node in the branch
   designated by nodeId. Throw on failure.
   */

   //sanity check: does this branch exist?
   const auto& branch = getBranch(id);
   if (branch.nodes_.empty())
      throw runtime_error("[forkFromBranch] empty branch");

   const auto& lastNode = *prev(branch.nodes_.end());
   auto newBranchId = branchCounter_++;
   auto insertIt = branches_.emplace(
      newBranchId, DerivationBranch(lastNode, newBranchId));

   return insertIt.first->second;
}

////////////////////////////////////////////////////////////////////////////////
uint32_t DerivationTree::getSeedFingerprint() const
{
   const auto& branch = getBranch(0);
   return branch.parent_.value;
}

////////////////////////////////////////////////////////////////////////////////
vector<DerivationBranch::Path> DerivationTree::getPaths() const
{
   //find open ended branches
   std::map<NodeData, DerivationBranch const*> endPoints;
   for (const auto& branch : branches_)
   {
      //dont track forks with no nodes
      if (branch.second.nodes_.empty())
         continue;

      const auto& endPoint = *std::prev(branch.second.nodes_.end());
      endPoints.emplace(endPoint, &branch.second);
   }

   for (const auto& branch : branches_)
   {
      if (branch.second.nodes_.empty())
         continue;

      auto endPointsIter = endPoints.find(branch.second.parent_);
      if (endPointsIter == endPoints.end())
         continue;

      endPoints.erase(endPointsIter);
   }

   if (endPoints.empty())
      throw runtime_error("[getPaths] no valid end point");

   //run through the branches, find out the leaves
   vector<DerivationBranch::Path> results;
   for (const auto& endPoint : endPoints)
   {
      DerivationBranch::Path path;

      DerivationBranch const* currentBranch = nullptr;
      DerivationBranch const* parentBranch = endPoint.second;

      NodeData const *parent = nullptr;
      while (currentBranch != parentBranch)
      {
         if (currentBranch != nullptr)
            parent = &currentBranch->parent_;

         currentBranch = parentBranch;
         for (const auto& node : currentBranch->nodes_)
         {
            path.emplace(node);
            if (parent != nullptr && node == *parent)
               break;
         }

         parentBranch = &getBranch(currentBranch->parent_.branchId);
      }

      results.emplace_back(move(path));
   }

   return results;
}

////////////////////////////////////////////////////////////////////////////////
vector<NodeRoot> DerivationTree::resolveNodeRoots(
   shared_ptr<Encryption::DecryptedDataContainer> decrData,
   shared_ptr<AssetEntry_BIP32Root> walletRoot) const
{
   vector<NodeRoot> result;
   auto skipNode = [&result](DerivationBranch::Path& path)->void
   {
      NodeRoot skipped{ move(path), {} };
      result.emplace_back(move(skipped));
   };

   auto paths = getPaths();

   //look for potential seed root
   const auto& seedNode = getSeedNode();
   auto seedRootIt = b58Roots_.find(seedNode);

   //look for a root on the path
   for (auto& path : paths)
   {
      if (path.empty())
         throw runtime_error("[getNodeRoots] empty path");

      BIP32_Node bip32Node;
      bool haveRoot = false;
      auto firstNodeIt = path.begin();

      auto pathIt = path.rbegin();
      while (pathIt != path.rend())
      {
         auto b58It = b58Roots_.find(*pathIt);
         if (b58It != b58Roots_.end())
         {
            BIP32_Node node;
            firstNodeIt = ++path.find(*pathIt);
            node.initFromBase58(b58It->second);
            if (node.isPublic())
            {
               //public root, check the next node isn't hard
               //derived.
               if (firstNodeIt != path.end() &&
                  firstNodeIt->isHardDerviation())
               {
                  ++pathIt;
                  continue;
               }
            }

            //setup first node
            bip32Node = move(node);
            haveRoot = true;
            break;
         }

         ++pathIt;
      }

      if (!haveRoot)
      {
         if (seedRootIt != b58Roots_.end())
         {
            bip32Node.initFromBase58(seedRootIt->second);
         }
         else
         {
            /* setup bip32 node from wallet root */

            //sanitychecks
            if (walletRoot == nullptr || decrData == nullptr)
            {
               skipNode(path);
               continue;
            }

            if (walletRoot->getSeedFingerprint(true) != getSeedFingerprint())
            {
               skipNode(path);
               continue;
            }

            //grab cleartext wallet root private key
            const auto& privateRoot = decrData->getClearTextAssetData(
               walletRoot->getPrivKey());

            //setup bip32node from private key
            bip32Node.initFromPrivateKey(
               walletRoot->getDepth(), walletRoot->getLeafID(),
               walletRoot->getParentFingerprint(),
               privateRoot, walletRoot->getChaincode());
         }

         //set first node to begining of path
         firstNodeIt = path.begin();
      }

      //derive
      while (firstNodeIt != path.end())
      {
         const auto& node = *(firstNodeIt++);
         if (!bip32Node.isPublic())
            bip32Node.derivePrivate(node.value);
         else
            bip32Node.derivePublic(node.value);
      }

      //grab base58 string
      SecureBinaryData rootB58(bip32Node.getBase58());
      NodeRoot nodeRoot{ move(path), move(rootB58) };
      result.emplace_back(move(nodeRoot));
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
vector<uint32_t> DerivationTree::toPath32(const DerivationBranch::Path& path)
{
   vector<uint32_t> path32;
   for (const auto& node : path)
      path32.push_back(node.value);
   return path32;
}

////////////////////////////////////////////////////////////////////////////////
const NodeData& DerivationTree::getSeedNode() const
{
   return branches_.at(0).parent_;
}

////////////////////////////////////////////////////////////////////////////////
void DerivationTree::addB58Root(const NodeData& node,
   const SecureBinaryData& rootB58)
{
   b58Roots_.emplace(node, rootB58);
}
