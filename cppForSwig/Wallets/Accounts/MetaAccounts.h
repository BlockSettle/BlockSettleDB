////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <memory>
#include <map>

#include "../../BinaryData.h"
#include "../../SecureBinaryData.h"
#include "../../ReentrantLock.h"

#include "AccountTypes.h"

#ifndef _H_META_ACCOUNTS
#define _H_META_ACCOUNTS

#define META_ACCOUNT_COMMENTS    0x000000C0
#define META_ACCOUNT_AUTHPEER    0x000000C1
#define META_ACCOUNT_PREFIX      0xF1

////
class DBIfaceTransaction;
class WalletDBInterface;

////////////////////////////////////////////////////////////////////////////////
class MetaDataAccount : public Lockable
{
   friend struct AuthPeerAssetConversion;
   friend struct CommentAssetConversion;

private:
   MetaAccountType type_ = MetaAccount_Unset;
   BinaryData ID_;

   const std::string dbName_;

   std::map<unsigned, std::shared_ptr<MetaData>> assets_;

private:
   bool writeAssetToDisk(
      std::shared_ptr<DBIfaceTransaction>, std::shared_ptr<MetaData>) const;

public:
   MetaDataAccount(const std::string& dbName) :
      dbName_(dbName)
   {}

   //Lockable virtuals
   void initAfterLock(void) {}
   void cleanUpBeforeUnlock(void) {}

   //storage methods
   void readFromDisk(std::shared_ptr<WalletDBInterface>, const BinaryData&);
   void commit(std::unique_ptr<DBIfaceTransaction>) const;
   void updateOnDisk(std::shared_ptr<DBIfaceTransaction>);
   std::shared_ptr<MetaDataAccount> copy(const std::string&) const;

   //setup methods
   void reset(void);
   void make_new(MetaAccountType);

   //
   std::shared_ptr<MetaData> getMetaDataByIndex(unsigned) const;
   void eraseMetaDataByIndex(unsigned);
   MetaAccountType getType(void) const { return type_; }
};

struct AuthPeerAssetMap
{
   //<name, authorized pubkey>
   std::map<std::string, const SecureBinaryData*> nameKeyPair_;
   
   //<pubkey, sig>
   std::pair<SecureBinaryData, SecureBinaryData> rootSignature_;

   //<pubkey, description>
   std::map<SecureBinaryData, std::pair<std::string, unsigned>> peerRootKeys_;
};

////////////////////////////////////////////////////////////////////////////////
struct AuthPeerAssetConversion
{
   static AuthPeerAssetMap getAssetMap(
      const MetaDataAccount*);
   static std::map<SecureBinaryData, std::set<unsigned>> getKeyIndexMap(
      const MetaDataAccount*);

   static int addAsset(MetaDataAccount*, const SecureBinaryData&,
      const std::vector<std::string>&,
      std::shared_ptr<DBIfaceTransaction>);

   static void addRootSignature(MetaDataAccount*, 
      const SecureBinaryData&, const SecureBinaryData&,
      std::shared_ptr<DBIfaceTransaction>);

   static unsigned addRootPeer(MetaDataAccount*,
      const SecureBinaryData&, const std::string&,
      std::shared_ptr<DBIfaceTransaction>);
};

////////////////////////////////////////////////////////////////////////////////
struct CommentAssetConversion
{
   static std::shared_ptr<CommentData> getByKey(MetaDataAccount*,
      const BinaryData&);

   static int setAsset(
      MetaDataAccount*, const BinaryData&,
      const std::string&,
      std::shared_ptr<DBIfaceTransaction>);

   static int deleteAsset(
      MetaDataAccount*, const BinaryData&,
      std::shared_ptr<DBIfaceTransaction>);

   static std::map<BinaryData, std::string> getCommentMap(MetaDataAccount*);
};

#endif
