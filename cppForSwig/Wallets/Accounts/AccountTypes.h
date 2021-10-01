////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_ACCOUNT_TYPES
#define _H_ACCOUNT_TYPES

#include "../Addresses.h"

#define ARMORY_LEGACY_ACCOUNTID        0xF6E10000
#define IMPORTS_ACCOUNTID              0x00000000
#define ARMORY_LEGACY_ASSET_ACCOUNTID  0x00000001
#define ECDH_ASSET_ACCOUNTID           0x20000000
#define SEED_DEPTH                     0xFFFF

class AccountException : public std::runtime_error
{
public:
   AccountException(const std::string& err) : std::runtime_error(err)
   {}
};

enum AssetAccountTypeEnum
{
   AssetAccountTypeEnum_Plain = 0,
   AssetAccountTypeEnum_ECDH
};

enum AccountTypeEnum
{
   /*
   armory derivation scheme 
   outer and inner account are the same
   uncompressed P2PKH, compresed P2SH-P2PK, P2SH-P2WPKH
   */
   AccountTypeEnum_ArmoryLegacy = 0,

   /*
   BIP32 derivation scheme, derPath is used as is.
   no address type is assumed, this has to be provided at creation
   */
   AccountTypeEnum_BIP32,

   /*
   Derives from BIP32_Custom, ECDH all keys pairs with salt, 
   carried by derScheme object.
   */
   AccountTypeEnum_BIP32_Salted,

   /*
   Stealth address account. Has a single key pair, ECDH it with custom
   salts per asset.
   */
   AccountTypeEnum_ECDH,

   AccountTypeEnum_Custom
};

enum MetaAccountType
{
   MetaAccount_Unset = 0,
   MetaAccount_Comments,
   MetaAccount_AuthPeers
};

namespace ArmorySigner
{
   class BIP32_AssetPath;
};

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
class AccountType
{
protected:
   std::set<AddressEntryType> addressTypes_;
   AddressEntryType defaultAddressEntryType_;
   bool isMain_ = false;

public:
   //tors
   AccountType()
   {}

   virtual ~AccountType() = 0;

   //locals
   void setMain(bool ismain) { isMain_ = ismain; }
   const bool isMain(void) const { return isMain_; }

   const std::set<AddressEntryType>& getAddressTypes(void) const 
   { return addressTypes_; }

   AddressEntryType getDefaultAddressEntryType(void) const 
   { return defaultAddressEntryType_; }

   void addAddressType(AddressEntryType);
   void setDefaultAddressType(AddressEntryType);

   //virtuals
   virtual AccountTypeEnum type(void) const = 0;
   virtual BinaryData getAccountID(void) const = 0;
   virtual BinaryData getOuterAccountID(void) const = 0;
   virtual BinaryData getInnerAccountID(void) const = 0;
   virtual bool isWatchingOnly(void) const = 0;
};

////////////////////
class AccountType_ArmoryLegacy : public AccountType
{
public:
   AccountType_ArmoryLegacy(void);

   AccountTypeEnum type(void) const override
   { return AccountTypeEnum_ArmoryLegacy; }

   bool isWatchingOnly(void) const override {return false;}

   BinaryData getAccountID(void) const override;
   BinaryData getOuterAccountID(void) const override;
   BinaryData getInnerAccountID(void) const override;
};

struct NodeData
{
   using Depth    = uint16_t;
   using BranchId = uint16_t;
   using NodeVal  = uint32_t;

   //depth of the node relative to the seed, always unique within a
   //branch or a path, can have duplicates within a tree
   const Depth depth;

   //id of the branch carrying the node, depths can duplicate
   //so we have to differentiate by branch too
   const BranchId branchId;

   //value of the node, this value is used as is to derive with
   const NodeVal value;

   //false for depth + branch id indexing (default behavior), true
   //for searching exclusively by depth (depth is unique within a
   //given branch)
   const bool depthOnly;

   NodeData(Depth d, BranchId b, NodeVal nv, bool dOnly = false) :
      depth(d), branchId(b), value(nv), depthOnly(dOnly)
   {}

   bool operator<(const NodeData& rhs) const
   {
      //for depth based searches
      if (depthOnly || rhs.depthOnly)
         return depth < rhs.depth;

      //otherwise, order by depth if possible, differentiate by
      //branch if necessary
      if (depth == rhs.depth)
         return branchId < rhs.branchId;

      return depth < rhs.depth;
   }

   bool operator==(const NodeData& rhs) const
   {
      return
         depth == rhs.depth &&
         branchId == rhs.branchId &&
         value == value;
   }

   bool isHardDerviation(void) const
   {
      return (value & 0x80000000);
   }
};

////////////////////
class DerivationBranch
{
   friend class DerivationTree;

public:
   using Path = std::set<NodeData>;

private:
   const NodeData parent_;
   const NodeData::BranchId id_;
   Path nodes_;

private:
   DerivationBranch(const NodeData&, uint16_t);

public:
   const NodeData& appendNode(uint32_t);
   const NodeData& getNodeByRelativeDepth(uint16_t);
   const Path& getNodes(void) const { return nodes_; }
};

////////////////////
struct NodeRoot
{
   const DerivationBranch::Path path;
   const SecureBinaryData b58Root;

   bool isInitialized(void) const
   {
      return !b58Root.empty();
   }
};

////////////////////
class AssetEntry_BIP32Root;
class DecryptedDataContainer;

class DerivationTree
{
private:
   std::map<NodeData::BranchId, DerivationBranch> branches_;
   std::map<NodeData, SecureBinaryData> b58Roots_;
   NodeData::BranchId branchCounter_{0};

private:
   struct PathIt
   {
      std::vector<uint32_t>::const_iterator it;
      const std::vector<uint32_t>* theVector;

      PathIt(const std::vector<uint32_t>* theV) :
         theVector(theV)
      {
         it = theVector->begin();
      }

      bool isValid(void) const
      {
         return (it != theVector->end());
      }

   };
   using HeadsMap = std::map<int, PathIt>;
   void mergeDerPaths(DerivationBranch&, HeadsMap&);

public:
   DerivationTree(uint32_t);

   DerivationBranch& getBranch(const NodeData&);
   DerivationBranch& getBranch(NodeData::BranchId);
   const DerivationBranch& getBranch(NodeData::BranchId) const;

   DerivationBranch& forkFromBranch(const NodeData&);
   DerivationBranch& forkFromBranch(const DerivationBranch&);
   DerivationBranch& forkFromBranch(NodeData::BranchId);

   const NodeData& getSeedNode(void) const;
   void addB58Root(const NodeData&, const SecureBinaryData&);

   static DerivationTree fromDerivationPaths(
      uint32_t, const std::vector<std::vector<uint32_t>>&);

   uint32_t getSeedFingerprint(void) const;

   std::vector<DerivationBranch::Path> getPaths(void) const;
   std::vector<NodeRoot> resolveNodeRoots(
      std::shared_ptr<DecryptedDataContainer>,
      std::shared_ptr<AssetEntry_BIP32Root>) const;

   static std::vector<uint32_t> toPath32(const DerivationBranch::Path&);
};

////////////////////
class PathAndRoot
{
private:
   const std::vector<uint32_t> path_;
   mutable std::string b58RootStr_;
   mutable SecureBinaryData b58RootSbd_;

public:
   PathAndRoot(const std::vector<uint32_t> p, const std::string& root) :
      path_(p), b58RootStr_(root), b58RootSbd_({})
   {
      if (root.empty())
         throw std::runtime_error("[PathAndRoot] empty root");
   }

   PathAndRoot(const std::vector<uint32_t> p, const SecureBinaryData& root) :
      path_(p), b58RootStr_({}), b58RootSbd_(root)
   {
      if (root.empty())
         throw std::runtime_error("[PathAndRoot] empty root");
   }

   const std::vector<uint32_t>& getPath(void) const
   {
      return path_;
   }

   const SecureBinaryData& getRootSbd(void) const
   {
      if (b58RootSbd_.empty())
         b58RootSbd_ = SecureBinaryData::fromString(b58RootStr_);

      return b58RootSbd_;
   }

   const std::string& getRootStr(void) const
   {
      if (b58RootStr_.empty())
      {
         b58RootStr_ = std::string(
            b58RootSbd_.toCharPtr(), b58RootSbd_.getSize());
      }

      return b58RootStr_;
   }
};

////
class AccountType_BIP32 : public AccountType
{   
   friend struct AccountType_BIP32_Custom;

private:
   DerivationTree derTree_;

   BinaryData outerAccount_;
   BinaryData innerAccount_;

protected:
   unsigned addressLookup_ = UINT32_MAX;

private:

public:
   AccountType_BIP32(DerivationTree&);

   static std::shared_ptr<AccountType_BIP32> makeFromDerPaths(
      uint32_t, const std::vector<std::vector<uint32_t>>&);

   //AccountType virtuals
   BinaryData getAccountID(void) const override;
   BinaryData getOuterAccountID(void) const override;
   BinaryData getInnerAccountID(void) const override;
   bool isWatchingOnly(void) const override {return false;}

   //bip32 locals
   unsigned getSeedFingerprint(void) const;
   unsigned getAddressLookup(void) const;
   void setAddressLookup(unsigned count) 
   { 
      addressLookup_ = count; 
   }

   void setNodes(const std::set<unsigned>& nodes);
   void setOuterAccountID(const BinaryData&);
   void setInnerAccountID(const BinaryData&);
   void setRoots(const std::vector<PathAndRoot>&);
   void setSeedRoot(const SecureBinaryData&);

   virtual AccountTypeEnum type(void) const override
   { return AccountTypeEnum_BIP32; }

   const DerivationTree& getDerivationTree(void) const;
};

////////////////////////////////////////////////////////////////////////////////
class AccountType_BIP32_Salted : public AccountType_BIP32
{
private:
   const SecureBinaryData salt_;

public:
   AccountType_BIP32_Salted(
      DerivationTree& tree,
      const SecureBinaryData& salt) :
      AccountType_BIP32(tree), salt_(salt)
   {}

   static std::shared_ptr<AccountType_BIP32_Salted> makeFromDerPaths(uint32_t,
      const std::vector<std::vector<unsigned>>&, const SecureBinaryData&);

   AccountTypeEnum type(void) const 
   { return AccountTypeEnum_BIP32_Salted; }

   const SecureBinaryData& getSalt(void) const 
   { return salt_; }
};

////////////////////////////////////////////////////////////////////////////////
class AccountType_ECDH : public AccountType
{
private:
   const SecureBinaryData privateKey_;
   const SecureBinaryData publicKey_;

   //ECDH accounts are always single
   const BinaryData accountID_;

public:
   //tor
   AccountType_ECDH(
      const SecureBinaryData& privKey,
      const SecureBinaryData& pubKey) :
      privateKey_(privKey), publicKey_(pubKey),
      accountID_(WRITE_UINT32_BE(ECDH_ASSET_ACCOUNTID))
   {
      //run checks
      if (privateKey_.getSize() == 0 && publicKey_.getSize() == 0)
         throw AccountException("invalid key length");
   }

   //local
   const SecureBinaryData& getPrivKey(void) const { return privateKey_; }
   const SecureBinaryData& getPubKey(void) const { return publicKey_; }

   //virtual
   AccountTypeEnum type(void) const override { return AccountTypeEnum_ECDH; }
   BinaryData getAccountID(void) const override;
   BinaryData getOuterAccountID(void) const override { return accountID_; }
   BinaryData getInnerAccountID(void) const override { return accountID_; }
   virtual bool isWatchingOnly(void) const override;
};

#endif