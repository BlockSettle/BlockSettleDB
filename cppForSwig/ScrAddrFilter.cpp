////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2015, Armory Technologies, Inc.                        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE-ATI or http://www.gnu.org/licenses/agpl.html                  //
//                                                                            //
//                                                                            //
//  Copyright (C) 2016-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ScrAddrFilter.h"
#include "BlockUtils.h"
#include "txio.h"
#include "TxOutScrRef.h"

#include <thread>
#include <google/protobuf/message.h>


using namespace std;

///////////////////////////////////////////////////////////////////////////////
//
// ScrAddrFilter
//
///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::cleanUpPreviousChildren(LMDBBlockDatabase* lmdb)
{
   //get rid of sdbi entries created by side scans that have not been 
   //cleaned up during the previous run

   set<BinaryData> sdbiKeys;

   //clean up SUBSSH SDBIs
   {
      auto&& tx = lmdb->beginTransaction(SSH, LMDB::ReadWrite);
      auto dbIter = lmdb->getIterator(SSH);

      while (dbIter->advanceAndRead(DB_PREFIX_DBINFO))
      {
         auto&& keyRef = dbIter->getKeyRef();
         if (keyRef.getSize() != 3)
            throw runtime_error("invalid sdbi key in SSH db");

         auto id = (uint16_t*)(keyRef.getPtr() + 1);
         if (*id == 0)
            continue;

         sdbiKeys.insert(keyRef);
      }

      for (auto& keyRef : sdbiKeys)
         lmdb->deleteValue(SSH, keyRef);
   }

   //clean up SSH SDBIs
   sdbiKeys.clear();
   {
      auto&& tx = lmdb->beginTransaction(SUBSSH, LMDB::ReadWrite);
      auto dbIter = lmdb->getIterator(SUBSSH);

      while (dbIter->advanceAndRead(DB_PREFIX_DBINFO))
      {
         auto&& keyRef = dbIter->getKeyRef();
         if (keyRef.getSize() != 3)
            throw runtime_error("invalid sdbi key in SSH db");

         auto id = (uint16_t*)(keyRef.getPtr() + 1);
         if (*id == 0)
            continue;

         sdbiKeys.insert(keyRef);
      }

      for (auto& keyRef : sdbiKeys)
         lmdb->deleteValue(SUBSSH, keyRef);
   }

   //clean up missing hashes entries in TXFILTERS
   set<BinaryData> missingHashKeys;
   {
      auto&& tx = lmdb->beginTransaction(TXFILTERS, LMDB::ReadWrite);
      auto dbIter = lmdb->getIterator(TXFILTERS);

      while (dbIter->advanceAndRead(DB_PREFIX_MISSING_HASHES))
      {
         auto&& keyRef = dbIter->getKeyRef();
         if (keyRef.getSize() != 4)
            throw runtime_error("invalid missing hashes key");

         auto id = (uint32_t*)(keyRef.getPtr());
         if ((*id & 0x00FFFFFF) == 0)
            continue;

         sdbiKeys.insert(keyRef);
      }

      for (auto& keyRef : sdbiKeys)
         lmdb->deleteValue(TXFILTERS, keyRef);
   }
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::updateAddressMerkleInDB()
{
   auto&& addrMerkle = getAddressMapMerkle();

   StoredDBInfo sshSdbi;
   auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadWrite);

   try
   {
      sshSdbi = move(lmdb_->getStoredDBInfo(SSH, sdbiKey_));
   }
   catch (runtime_error&)
   {
      sshSdbi.magic_ = Armory::Config::BitcoinSettings::getMagicBytes();
      sshSdbi.metaHash_ = BtcUtils::EmptyHash_;
      sshSdbi.topBlkHgt_ = 0;
      sshSdbi.armoryType_ = ARMORY_DB_BARE;
   }

   sshSdbi.metaHash_ = addrMerkle;
   lmdb_->putStoredDBInfo(SSH, sshSdbi, sdbiKey_);
}

///////////////////////////////////////////////////////////////////////////////
StoredDBInfo ScrAddrFilter::getSubSshSDBI(void) const
{
   StoredDBInfo sdbi;
   auto&& tx = lmdb_->beginTransaction(SUBSSH, LMDB::ReadOnly);

   sdbi = move(lmdb_->getStoredDBInfo(SUBSSH, sdbiKey_));
   return sdbi;
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::putSubSshSDBI(const StoredDBInfo& sdbi)
{
   auto&& tx = lmdb_->beginTransaction(SUBSSH, LMDB::ReadWrite);
   lmdb_->putStoredDBInfo(SUBSSH, sdbi, sdbiKey_);
}

///////////////////////////////////////////////////////////////////////////////
StoredDBInfo ScrAddrFilter::getSshSDBI(void) const
{
   auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadOnly);
   return lmdb_->getStoredDBInfo(SSH, sdbiKey_);
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::putSshSDBI(const StoredDBInfo& sdbi)
{
   auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadWrite);
   lmdb_->putStoredDBInfo(SSH, sdbi, sdbiKey_);
}

///////////////////////////////////////////////////////////////////////////////
set<BinaryData> ScrAddrFilter::getMissingHashes(void) const
{
   return lmdb_->getMissingHashes(sdbiKey_);
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::putMissingHashes(const set<BinaryData>& hashSet)
{
   auto&& tx = lmdb_->beginTransaction(TXFILTERS, LMDB::ReadWrite);
   lmdb_->putMissingHashes(hashSet, sdbiKey_);
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::getScrAddrCurrentSyncState()
{
   {
      auto scraddrmap = scanFilterAddrMap_->get();
      auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadOnly);

      for (auto& scrAddr : *scraddrmap)
      {
         StoredScriptHistory ssh;
         lmdb_->getStoredScriptHistorySummary(ssh, scrAddr.first);

         scrAddr.second->scannedHeight_ = ssh.scanHeight_;
      }
   }
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::setSSHLastScanned(set<BinaryDataRef>& addrSet, 
   unsigned height)
{
   auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadWrite);
   for (auto& scrAddr : addrSet)
   {
      StoredScriptHistory ssh;
      lmdb_->getStoredScriptHistorySummary(ssh, scrAddr);
      if (!ssh.isInitialized())
         ssh.uniqueKey_ = scrAddr;

      ssh.scanHeight_ = height;
      lmdb_->putStoredScriptHistorySummary(ssh);
   }
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::setSSHLastScanned(unsigned height)
{
   set<BinaryDataRef> addrSet;
   auto addrMap = scanFilterAddrMap_->get();
   for (auto& addr : *addrMap)
      addrSet.insert(addr.first);

   setSSHLastScanned(addrSet, height);
}

///////////////////////////////////////////////////////////////////////////////
set<BinaryDataRef> ScrAddrFilter::updateAddrMap(
   const set<BinaryDataRef>& addrSet, unsigned height, bool remove)
{
   if (addrSet.empty())
      return {};

   switch (remove)
   {
   case false: 
   {
      //add addresses to both scan and zc filter maps
      set<BinaryDataRef> addrRefSet;
      auto scraddrmap = scanFilterAddrMap_->get();
      map<BinaryDataRef, shared_ptr<AddrAndHash>> updateMap;

      for (auto& sa : addrSet)
      {
         auto iter = scraddrmap->find(sa);
         if (iter != scraddrmap->end())
         {
            addrRefSet.insert(iter->first);
            continue;
         }

         auto aah = make_shared<AddrAndHash>(sa);
         aah->scannedHeight_ = height;
         pair<BinaryDataRef, shared_ptr<AddrAndHash>> addrPair = { 
            aah->scrAddr_.getRef(), aah };
         
         updateMap.insert(move(addrPair));
         addrRefSet.insert(aah->scrAddr_.getRef());
      }

      scanFilterAddrMap_->update(updateMap);
      return addrRefSet;
   }

   case true:
      return {};
   }

   //this is to mute the msvc eroneous warning about return values
   return {};
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::pushAddressBatch(shared_ptr<AddressBatch> batch)
{
   registrationStack_.push_back(move(batch));
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::registrationThread()
{
   while (1)
   {
      shared_ptr<AddressBatch> batch;
      try
      {
         batch = move(registrationStack_.pop_front());
      }
      catch (Armory::Threading::StopBlockingLoop&)
      {
         //end loop condition
         break;
      }

      switch (batch->type_)
      {
      case AddressBatch_register:
      {
         auto batchPtr = dynamic_pointer_cast<RegistrationBatch>(batch);
         if (batchPtr == nullptr)
            throw runtime_error("unexpected batch ptr type");

         if (Armory::Config::DBSettings::getDbType() == ARMORY_DB_SUPER)
         {
            //no scanning required in supernode, just update the address map
            auto&& scaSet = updateAddrMap(batchPtr->scrAddrSet_, 0, false);
            batchPtr->callback_(scaSet);
            continue;
         }

         //filter out collisions
         set<BinaryDataRef> addrSet;
         {
            auto scraddrmap = scanFilterAddrMap_->get();
            for (auto& sa : batchPtr->scrAddrSet_)
            {
               BinaryData sabd(sa);
               auto iter = scraddrmap->find(sa);
               if (iter != scraddrmap->end())
                  continue;

               addrSet.insert(sa);
            }
         }

         if (addrSet.size() == 0 || !bdmIsRunning())
         {
            //all addresses are already registered
            //or db isn't running yet
            auto&& scaSet = updateAddrMap(batchPtr->scrAddrSet_, 0, false);
            batchPtr->callback_(scaSet);
            continue;
         }

         LOGINFO << "Starting address registration process";

         //BDM is initialized and maintenance thread is running, scan batch
         uint32_t topBlockHeight = blockchain()->top()->getBlockHeight();
         
         if (batchPtr->isNew_)
         {
            //batch is flagged as new, all addresses within it are assumed
            //clean of history. Update the map and continue
            auto&& scaSet = updateAddrMap(batchPtr->scrAddrSet_, 0, false);
            setSSHLastScanned(addrSet, topBlockHeight);
            batchPtr->callback_(scaSet);
            continue;
         }

         //scan the batch
         vector<string> walletIDs;
         walletIDs.push_back(batchPtr->walletID_);
         auto saf = getNew(SIDESCAN_ID);
         saf->updateAddrMap(addrSet, 0, false);
         saf->applyBlockRangeToDB(0, walletIDs, true);

         //merge with main address filter
         set<BinaryDataRef> newAddrSet;
         auto newMap = saf->scanFilterAddrMap_->get();
         for (auto& saPair : *newMap)
            newAddrSet.insert(saPair.first);
         scanFilterAddrMap_->update(*newMap);
         updateAddressMerkleInDB();

         //final scan to sync all addresses to same height
         applyBlockRangeToDB(topBlockHeight + 1, walletIDs, false);
         
         //cleanup
         saf->cleanUpSdbis();

         //notify
         for (const auto& wID : walletIDs)
            LOGINFO << "Completed scan of wallet " << wID;

         auto&& scaSet = updateAddrMap(batchPtr->scrAddrSet_, 0, false);
         batchPtr->callback_(scaSet);
         
         break;
      }

      case AddressBatch_unregister:
      {
         auto batchPtr = dynamic_pointer_cast<UnregistrationBatch>(batch);
         if (batchPtr == nullptr)
            throw runtime_error("unexpected batch ptr type");
        
         set<BinaryDataRef> scrAddrSet;
         scrAddrSet.insert(
            batchPtr->scrAddrSet_.begin(), batchPtr->scrAddrSet_.end());
         updateAddrMap(scrAddrSet, 0, true);
         if (batchPtr->callback_)
            batchPtr->callback_();
         
         break;
      }
      }
   }
}

///////////////////////////////////////////////////////////////////////////////
int32_t ScrAddrFilter::scanFrom() const
{
   int32_t lowestBlock = -1;

   if (scanFilterAddrMap_->size() > 0)
   {
      auto scraddrmap = scanFilterAddrMap_->get();
      lowestBlock = scraddrmap->begin()->second->scannedHeight_;

      for (auto scrAddr : *scraddrmap)
      {
         if (lowestBlock != (int32_t)scrAddr.second->scannedHeight_)
         {
            lowestBlock = -1;
            break;
         }
      }
   }

   if (lowestBlock != -1)
      lowestBlock++;

   return lowestBlock;
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::resetSshDB()
{
   auto tx = lmdb_->beginTransaction(SSH, LMDB::ReadWrite);
   auto scraddrmap = scanFilterAddrMap_->get();
   
   for (const auto& regScrAddr : *scraddrmap)
   {
      regScrAddr.second->scannedHeight_ = 0;
      StoredScriptHistory ssh;
      ssh.uniqueKey_ = regScrAddr.first;
      ssh.scanHeight_ = -1;
      lmdb_->putStoredScriptHistorySummary(ssh);
   }
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::getAllScrAddrInDB()
{
   auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadOnly);
   auto dbIter = lmdb_->getIterator(SSH);   

   map<BinaryDataRef, shared_ptr<AddrAndHash>> scrAddrMap;

   //iterate over ssh DB
   while(dbIter->advanceAndRead(DB_PREFIX_SCRIPT))
   {
      StoredScriptHistory ssh;
      ssh.unserializeDBKey(dbIter->getKeyRef());
      ssh.unserializeDBValue(dbIter->getValueReader());

      auto aah = make_shared<AddrAndHash>(ssh.uniqueKey_.getRef());
      aah->scannedHeight_ = ssh.scanHeight_;
      
      scrAddrMap.insert(
         move(make_pair(aah->scrAddr_.getRef(), aah)));
   } 

   //the zc filter map is only update once when users register address explictly
   scanFilterAddrMap_->update(scrAddrMap);
}

///////////////////////////////////////////////////////////////////////////////
BinaryData ScrAddrFilter::getAddressMapMerkle(void) const
{
   vector<BinaryData> addrVec;
   addrVec.reserve(scanFilterAddrMap_->size());

   auto scraddrmap = scanFilterAddrMap_->get();
   for (const auto& addr : *scraddrmap)
      addrVec.push_back(addr.second->getHash());

   if (addrVec.size() > 0)
      return BtcUtils::calculateMerkleRoot(addrVec);

   return BinaryData();
}

///////////////////////////////////////////////////////////////////////////////
bool ScrAddrFilter::hasNewAddresses(void) const
{
   if (scanFilterAddrMap_->size() == 0)
      return false;

   //do not run before getAllScrAddrInDB
   auto&& currentmerkle = getAddressMapMerkle();
   BinaryData dbMerkle;

   {
      auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadOnly);
      auto&& sdbi = getSshSDBI();
      dbMerkle = sdbi.metaHash_;
   }

   if (dbMerkle == currentmerkle)
      return false;

   //merkles don't match, check height in each address
   auto scraddrmap = scanFilterAddrMap_->get();
   auto scanfrom = scraddrmap->begin()->second;
   for (const auto& scrAddr : *scraddrmap)
   {
      if (scanfrom != scrAddr.second)
         return true;
   }

   return false;
}

///////////////////////////////////////////////////////////////////////////////
shared_ptr<unordered_map<TxOutScriptRef, int>> ScrAddrFilter::getOutScrRefMap()
{
   getScrAddrCurrentSyncState();
   auto outset = make_shared<unordered_map<TxOutScriptRef, int>>();

   auto scrAddrMap = scanFilterAddrMap_->get();

   for (auto& scrAddr : *scrAddrMap)
   {
      if (scrAddr.first.empty())
         continue;

      TxOutScriptRef scrRef;
      scrRef.setRef(scrAddr.first);
      outset->emplace(move(scrRef), scrAddr.second->scannedHeight_);
   }

   return outset;
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::cleanUpSdbis()
{
   //SSH
   {
      auto&& tx = lmdb_->beginTransaction(SSH, LMDB::ReadWrite);
      lmdb_->deleteValue(SSH,
         StoredDBInfo::getDBKey(sdbiKey_));
   }

   //SUBSSH
   {
      auto&& tx = lmdb_->beginTransaction(SUBSSH, LMDB::ReadWrite);
      lmdb_->deleteValue(SUBSSH,
         StoredDBInfo::getDBKey(sdbiKey_));
   }

   //TXFILTERS
   {
      auto&& tx = lmdb_->beginTransaction(TXFILTERS, LMDB::ReadWrite);
      lmdb_->deleteValue(TXFILTERS,
         DBUtils::getMissingHashesKey(sdbiKey_));
   }
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::shutdown()
{
   registrationStack_.terminate();
   if (thr_.joinable())
      thr_.join();
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::init()
{
   auto thrLambda = [this](void)->void
   {
      this->registrationThread();
   };

   thr_ = thread(thrLambda);
}

///////////////////////////////////////////////////////////////////////////////
void ScrAddrFilter::unregisterAddresses(const set<BinaryDataRef>& scrAddrSet, 
   const function<void(void)>& callback)
{
   /*
   Remove addresses from the ScrAddrFilter zcFilter map
   */

   auto batch = make_shared<UnregistrationBatch>();
   batch->scrAddrSet_.insert(scrAddrSet.begin(), scrAddrSet.end());
   batch->callback_ = callback;

   pushAddressBatch(move(batch));
}

///////////////////////////////////////////////////////////////////////////////
////
//// AddressBatch
////
///////////////////////////////////////////////////////////////////////////////
AddressBatch::~AddressBatch()
{}