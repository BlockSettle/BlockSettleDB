////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "NodeUnitTest.h"
#include "../BlockUtils.h"

using namespace std;

BlockingQueue<BinaryData> NodeUnitTest::watcherInvQueue_;

////////////////////////////////////////////////////////////////////////////////
NodeUnitTest::NodeUnitTest(uint32_t magic_word, bool watcher) :
   BitcoinNodeInterface(magic_word, watcher)
{
   //0 is reserved for coinbase tx ordering in spoofed blocks
   counter_.store(1, memory_order_relaxed);

   if (!watcher)
      return;

   auto watcherLbd = [this](void)->void
   {
      this->watcherProcess();
   };

   watcherThread_ = thread(watcherLbd);
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::shutdown()
{
   if (watcherThread_.joinable())
   {
      watcherInvQueue_.terminate();
      watcherThread_.join();
   }

   BitcoinNodeInterface::shutdown();
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::connectToNode(bool)
{
   run_.store(true, memory_order_relaxed);
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::notifyNewBlock(void)
{
   InvEntry ie;
   ie.invtype_ = Inv_Msg_Block;

   vector<InvEntry> vecIE;
   vecIE.push_back(ie);

   processInvBlock(move(vecIE));
}

////////////////////////////////////////////////////////////////////////////////
map<unsigned, BinaryData> NodeUnitTest::mineNewBlock(BlockDataManager* bdm,
   unsigned count, const BinaryData& h160)
{
   Recipient_P2PKH recipient(h160, 50 * COIN);
   return mineNewBlock(bdm, count, &recipient);
}

////////////////////////////////////////////////////////////////////////////////
map<unsigned, BinaryData> NodeUnitTest::mineNewBlock(BlockDataManager* bdm,
   unsigned count, ScriptRecipient* recipient)
{

   if(header_.prevHash_.getSize() == 0)
   {
      auto top = blockchain_->top();
      header_.prevHash_ = top->getThisHash();
      header_.timestamp_ = top->getTimestamp();
      header_.diffBits_  = top->getDiffBits();
      header_.blockHeight_ = top->getBlockHeight() + 1;
   }

   std::map<unsigned, BinaryData> result;
   bool stagedZc = false;

   for (unsigned i = 0; i < count; i++)
   {
      UnitTestBlock block;

      //create coinbase tx
      BinaryWriter bwCoinbase;
      {
         //version
         bwCoinbase.put_uint32_t(1);

         //input count
         bwCoinbase.put_var_int(1);

         //outpoint
         BinaryData outpoint(36);
         memset(outpoint.getPtr(), 0, outpoint.getSize());
         bwCoinbase.put_BinaryData(outpoint);

         //txin script
         bwCoinbase.put_var_int(4);
         bwCoinbase.put_uint32_t(counter_.fetch_add(1, memory_order_relaxed));

         //sequence
         bwCoinbase.put_uint32_t(UINT32_MAX);

         //output count
         bwCoinbase.put_var_int(1);

         //output script
         auto& outputScript = recipient->getSerializedScript();
         bwCoinbase.put_BinaryData(outputScript);

         //locktime
         bwCoinbase.put_uint32_t(0);
      }

      auto coinbaseObj = make_shared<MempoolObject>();
      coinbaseObj->rawTx_ = bwCoinbase.getData();
      coinbaseObj->hash_ = BtcUtils::getHash256(coinbaseObj->rawTx_);
      coinbaseObj->order_ = 0;
      block.coinbase_ = Tx(coinbaseObj->rawTx_);
      block.height_ = header_.blockHeight_++;

      result.insert(make_pair(block.height_, coinbaseObj->hash_));

      //grab all tx in the mempool, respect ordering
      vector<shared_ptr<MempoolObject>> mempoolV;
      map<BinaryDataRef, shared_ptr<MempoolObject>> purgedMempool;
      mempoolV.push_back(coinbaseObj);
      for (auto& obj : mempool_)
      {
         if (obj.second->staged_)
            stagedZc = true;

         if (obj.second->blocksUntilMined_ == 0)
         {
            mempoolV.push_back(obj.second);
         }
         else
         {
            --obj.second->blocksUntilMined_;
            auto objPair = make_pair(obj.second->hash_.getRef(), move(obj.second));
            purgedMempool.emplace(objPair);
         }
      }

      struct SortStruct
      {
         bool operator()(const shared_ptr<MempoolObject>& lhs,
            const shared_ptr<MempoolObject>& rhs) const
         {
            return *lhs < *rhs;
         }
      };

      sort(mempoolV.begin(), mempoolV.end(), SortStruct());

      //compute merkle
      vector<BinaryData> txHashes;
      for (auto& obj : mempoolV)
         txHashes.push_back(obj->hash_);
      auto merkleRoot = BtcUtils::calculateMerkleRoot(txHashes);

      //clear mempool
      mempool_ = move(purgedMempool);

      //build block
      BinaryWriter bwBlock;

      {
         /* build header */

         //version
         bwBlock.put_uint32_t(1);

         //previous hash
         bwBlock.put_BinaryData(header_.prevHash_);

         //merkle root
         bwBlock.put_BinaryData(merkleRoot);

         //timestamp
         bwBlock.put_uint32_t(header_.timestamp_ + 600);

         //diff bits
         bwBlock.put_BinaryData(header_.diffBits_);

         //nonce
         bwBlock.put_uint32_t(0);

         //update prev hash and timestamp for the next block
         header_.prevHash_ = BtcUtils::getHash256(bwBlock.getDataRef());

         block.headerHash_ = header_.prevHash_;
         block.rawHeader_ = bwBlock.getDataRef();
         
         block.diffBits_ = header_.diffBits_;
         block.timestamp_ = header_.timestamp_;
         header_.timestamp_ += 600;
      }

      {
         /* serialize block */

         //tx count
         bwBlock.put_var_int(mempoolV.size());

         //tx
         for (auto& txObj : mempoolV)
         {
            bwBlock.put_BinaryData(txObj->rawTx_);
            block.transactions_.push_back(Tx(txObj->rawTx_));
         }
      }

      blocks_.push_back(block);

      {
         /* append to blocks data file */

         //get file stream
         auto lastFileName = filesPtr_->getLastFileName();
         auto fStream = ofstream(lastFileName, ios::binary | ios::app);

         BinaryWriter bwHeader;

         //magic byte
         bwHeader.put_uint32_t(getMagicWord());

         //block size
         bwHeader.put_uint32_t(bwBlock.getSize());

         fStream.write(
            (const char*)bwHeader.getDataRef().getPtr(), bwHeader.getSize());

         //block data
         fStream.write(
            (const char*)bwBlock.getDataRef().getPtr(), bwBlock.getSize());

         fStream.close();
      }
   }

   if (stagedZc && mempool_.size() > 0)
   {
      /*
      We have staged zc, need to push them. Have to wait for the mining to 
      complete first however, or the staged zc will most likely be rejected
      as invalid.
      */

      //create hook
      auto promPtr = make_shared<promise<bool>>();
      auto fut = promPtr->get_future();
      auto waitOnNotif = [promPtr](BDV_Notification* notifPtr)->void
      {
         auto blockNotif = dynamic_cast<BDV_Notification_NewBlock*>(notifPtr);
         if (blockNotif == nullptr)
            promPtr->set_value(false);
         else
            promPtr->set_value(true);
      };

      auto hookPtr = make_shared<BDVNotificationHook>();
      hookPtr->lambda_ = waitOnNotif;

      //set hook
      bdm->registerOneTimeHook(hookPtr);

      //push db block notification
      notifyNewBlock();

      //wait on hook
      if (!fut.get())
         throw runtime_error("unexpected bdm notificaiton");

      //push the staged transactions
      vector<InvEntry> invVec;
      for (auto& tx : mempool_)
      {
         InvEntry ie;
         ie.invtype_ = Inv_Msg_Witness_Tx;
         memcpy(ie.hash, tx.first.getPtr(), 32);
         invVec.emplace_back(ie);
      }
      
      processInvTx(invVec);
   }
   else
   {
      //push db block notification
      notifyNewBlock();
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::setReorgBranchPoint(shared_ptr<BlockHeader> header)
{
   if (header == nullptr)
      throw runtime_error("null header");

   header_.prevHash_ = header->getThisHash();
   header_.blockHeight_ = header->getBlockHeight();
   header_.timestamp_ = header->getTimestamp();
   header_.diffBits_ = header->getDiffBits();

   //purge mempool
   mempool_.clear();
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::pushZC(const vector<pair<BinaryData, unsigned>>& txVec, 
   bool stage)
{
   vector<InvEntry> invVec;
   map<BinaryData, BinaryData> rawTxMap;

   //save tx to fake mempool
   for (auto& tx : txVec)
   {
      auto obj = make_shared<MempoolObject>();
      Tx txNew(tx.first);
      obj->rawTx_ = tx.first;
      obj->hash_ = txNew.getThisHash();
      obj->order_ = counter_.fetch_add(1, memory_order_relaxed);
      obj->blocksUntilMined_ = tx.second;
      obj->staged_ = stage;

      /***
      cheap zc replacement code: check for outpoint reuse, assume unit
      tests will not push conflicting transactions that aren't legit RBF
      ***/

      auto poolIter = mempool_.begin();
      while(poolIter != mempool_.end())
      {
         Tx txMempool(poolIter->second->rawTx_);
         if (txNew.getThisHash() == txMempool.getThisHash())
            return;

         bool hasCollision = false;
         for (unsigned i = 0; i < txMempool.getNumTxIn(); i++)
         {
            auto txinMempool = txMempool.getTxInCopy(i);

            for (unsigned y = 0; y < txNew.getNumTxIn(); y++)
            {
               auto txinNew = txNew.getTxInCopy(y);

               if (txinMempool.getOutPoint() == txinNew.getOutPoint())
               {
                  hasCollision = true;
                  break;
               }
            }
            
            if (hasCollision)
               break;
         }

         if (hasCollision)
         {
            mempool_.erase(poolIter++);
            continue;
         }

         ++poolIter;
      }

      auto objPair = make_pair(obj->hash_.getRef(), move(obj));
      auto insertIter = mempool_.insert(move(objPair));

      //add to inv vector
      InvEntry ie;
      ie.invtype_ = Inv_Msg_Witness_Tx;
      memcpy(ie.hash, insertIter.first->second->hash_.getPtr(), 32);
      invVec.emplace_back(ie);

      //save tx to reply to getdata request
      rawTxMap.insert(make_pair(
         insertIter.first->second->hash_, 
         insertIter.first->second->rawTx_));
   }

   /*
   Do not push the tx to the db if it is flagged for staging. It will get
   pushed after the next mining call. This is mostly useful for reorgs 
   (where you can't push zc that conflicts with the still valid branch)
   */
   if (stage)
      return;

   rawTxMap_.update(rawTxMap);
   processInvTx(invVec);
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::setBlockchain(std::shared_ptr<Blockchain> bcPtr)
{
   blockchain_ = bcPtr;
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::setBlockFiles(std::shared_ptr<BlockFiles> filesPtr)
{
   filesPtr_ = filesPtr;
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::sendMessage(unique_ptr<Payload> payload)
{
   //mock the node
   switch (payload->type())
   {
   case Payload_inv:
   {
      shared_ptr<Payload> payloadSPtr(move(payload));
      auto payloadInv = dynamic_pointer_cast<Payload_Inv>(payloadSPtr);
      if (payloadInv == nullptr)
         throw runtime_error("unexpected payload type");

      for (auto& entry : payloadInv->invVector_)
      {
         switch (entry.invtype_)
         {
         case Inv_Msg_Tx:
         {
            //consume getDataMap entry, set promise value
            auto gdpMap = getDataPayloadMap_.get();
            BinaryData hashBd(&entry.hash[0], sizeof(entry.hash));
            auto iter = gdpMap->find(hashBd);
            if (iter == gdpMap->end())
               break;

            shared_ptr<Payload> payloadTxSPtr(move(iter->second->payload_));
            auto payloadTx = dynamic_pointer_cast<Payload_Tx>(payloadTxSPtr);
            
            auto obj = make_shared<MempoolObject>();
            auto rawTx = payloadTx->getRawTx();       
            obj->rawTx_ = BinaryData(&rawTx[0], rawTx.size());
            obj->hash_ = hashBd;
            obj->order_ = counter_.fetch_add(1, memory_order_relaxed);
            
            //TODO: tie this with zc delay and stashing
            obj->blocksUntilMined_ = 0;
            obj->staged_ = false;

            mempool_.insert(make_pair(obj->hash_.getRef(), obj));

            try
            {
               iter->second->promise_->set_value(true);
            }
            catch(...)
            {}

            //send out the inventry through the watcher
            watcherInvQueue_.push_back(move(hashBd));

            break;
         }

         default:
            throw runtime_error("inventry type support not implemented yet");
         }
      }

      break;
   }

   case Payload_getdata:
   {
      //looking to get data for a previous inv tx message
      auto payloadSPtr = shared_ptr<Payload>(move(payload));
      auto payloadGetData = 
         dynamic_pointer_cast<Payload_GetData>(payloadSPtr);
      if (payloadGetData == nullptr)
         throw runtime_error("invalid payload type");

      for (auto& inv : payloadGetData->getInvVector())
      {
         auto txMap = rawTxMap_.get();
         BinaryData hash(&inv.hash[0], sizeof(inv.hash));
         auto iter = txMap->find(hash);
         if (iter == txMap->end())
            continue;

         auto payloadTx = make_unique<Payload_Tx>();

         vector<uint8_t> rawTx(iter->second.getSize());
         memcpy(&rawTx[0], iter->second.getPtr(), iter->second.getSize());
         payloadTx->setRawTx(rawTx);
         
         getTxDataLambda_(move(payloadTx));
      }

      break;
   }

   default:
      throw runtime_error("payload type support not implemented yet");
   }
}

////////////////////////////////////////////////////////////////////////////////
void NodeUnitTest::watcherProcess()
{
   while(true)
   {
      BinaryData hash;
      try
      {
         hash = move(watcherInvQueue_.pop_front());
      }
      catch(StopBlockingLoop&)
      {
         break;
      }
      
      vector<InvEntry> invVec;
      InvEntry inv;
      inv.invtype_ = Inv_Msg_Witness_Tx;
      memcpy(inv.hash, hash.getPtr(), 32);
      invVec.push_back(move(inv));

      processInvTx(invVec);
   }

   watcherInvQueue_.clear();
}