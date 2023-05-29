////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <memory>
#include <functional>
#include "TxHashFilters.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
//
//// Helpers
//
////////////////////////////////////////////////////////////////////////////////
uint32_t getSizeFromPtr(const uint8_t* ptr)
{
   uint32_t size;
   memcpy(&size, ptr, sizeof(uint32_t));
   return size;
}

////
uint32_t getBlockKeyFromPtr(const uint8_t* ptr)
{
   uint32_t blockKey;
   memcpy(&blockKey, ptr + 4, sizeof(uint32_t));
   return blockKey;
}

////
uint32_t getLenFromPtr(const uint8_t* ptr)
{
   uint32_t len;
   memcpy(&len, ptr + 8, sizeof(uint32_t));
   return len;
}

////
bool checkPtrLen(const uint8_t* ptr)
{
   if (ptr == nullptr)
      throw runtime_error("invalid txfilter ptr");

   uint32_t size;
   memcpy(&size, ptr, sizeof(uint32_t));
   if (size < 12)
      throw runtime_error("invalid txfilter ptr");

   uint32_t len;
   memcpy(&len, ptr + 8, sizeof(uint32_t));
   auto total = len * sizeof(uint32_t) + 12;
   if (total != size)
      throw runtime_error("invalid txfilter ptr");

   return true;
}

////////////////////////////////////////////////////////////////////////////////
//
//// BlockHashVector
//
////////////////////////////////////////////////////////////////////////////////
BlockHashVector::BlockHashVector(uint32_t blockKey) :
   blockKey_(blockKey)
{}

BlockHashVector::BlockHashVector(const BlockHashVector& other) :
   blockKey_(other.blockKey_)
{
   isValid_ = other.isValid_;
   len_ = other.len_;

   filterVector_ = other.filterVector_;
   filterPtr_ = other.filterPtr_;
}

////
BlockHashVector::BlockHashVector(BlockHashVector&& mv) :
   isValid_(mv.isValid_),
   blockKey_(mv.blockKey_), len_(mv.len_),
   filterPtr_(mv.filterPtr_)
{
   filterVector_ = move(mv.filterVector_);
}

////////////////////////////////////////////////////////////////////////////////
void BlockHashVector::update(const BinaryData& hash)
{
   if (hash.getSize() != 32)
      throw std::range_error("unexpected hash length");

   uint32_t hashHead;
   memcpy(&hashHead, hash.getPtr(), sizeof(uint32_t));
   filterVector_.push_back(hashHead);
}

////
void BlockHashVector::update(const vector<BinaryData>& hashVec)
{
   if (!isValid())
      throw runtime_error("txfilter needs initialized first");

   reserve(filterVector_.size() + hashVec.size());
   for (auto& hash : hashVec)
      update(hash);
   len_ = filterVector_.size();
}

////
void BlockHashVector::reserve(size_t len)
{
   filterVector_.reserve(len);
}

////////////////////////////////////////////////////////////////////////////////
set<uint32_t> BlockHashVector::compare(const BinaryData& hash) const
{
   uint32_t key;
   memcpy(&key, hash.getPtr(), sizeof(uint32_t));
   return compare(key);
}

////
set<uint32_t> BlockHashVector::compare(uint32_t key) const
{
   set<uint32_t> resultSet;
   if (!filterVector_.empty())
   {
      for (unsigned i = 0; i < filterVector_.size(); i++)
      {
         if (filterVector_[i] == key)
            resultSet.insert(i);
      }
   }
   else if (filterPtr_ != nullptr)
   {
      auto ptr = (uint32_t*)(filterPtr_ + 12);
      for (unsigned i = 0; i < len_; i++)
      {
         if (ptr[i] == key)
            resultSet.insert(i);
      }
   }
   else
      throw runtime_error("invalid filter");

   return resultSet;
}

////////////////////////////////////////////////////////////////////////////////
void BlockHashVector::serialize(BinaryWriter& bw) const
{
   if (blockKey_ == UINT32_MAX)
      throw runtime_error("[BlockHashVector::serialize] invalid block key");

   uint32_t size = 12 + filterVector_.size() * sizeof(uint32_t);
   bw.put_uint32_t(size);
   bw.put_uint32_t(blockKey_);
   bw.put_uint32_t(filterVector_.size());

   BinaryDataRef bdr(
      (uint8_t*)&filterVector_[0], filterVector_.size() * sizeof(uint32_t));
   bw.put_BinaryData(bdr);
}

////
BlockHashVector BlockHashVector::deserialize(const uint8_t* ptr)
{
   auto size = getSizeFromPtr(ptr);
   if (size < 12)
      throw runtime_error("[BlockHashVector::deserialize] invalid size");

   auto blockkey = getBlockKeyFromPtr(ptr);
   BlockHashVector bucket(blockkey);
   bucket.len_ = getLenFromPtr(ptr);

   if (size != bucket.len_ * sizeof(uint32_t) + 12)
      throw runtime_error("[BlockHashVector::deserialize] deser error");

   bucket.filterPtr_ = ptr;
   bucket.isValid_ = true;
   return bucket;
}

////////////////////////////////////////////////////////////////////////////////
//
//// BlockHashMap
//
////////////////////////////////////////////////////////////////////////////////
BlockHashMap::BlockHashMap(uint32_t blockKey) :
   blockKey_(blockKey)
{}

BlockHashMap::BlockHashMap(const BlockHashMap& other) :
   blockKey_(other.blockKey_)
{
   isValid_ = other.isValid_;
   len_ = other.len_;

   filterMap_ = other.filterMap_;
}

////
BlockHashMap::BlockHashMap(BlockHashMap&& mv) :
   isValid_(mv.isValid_),
   blockKey_(mv.blockKey_), len_(mv.len_)
{
   filterMap_ = move(mv.filterMap_);
}

////////////////////////////////////////////////////////////////////////////////
void BlockHashMap::update(const BinaryData& hash)
{
   if (hash.getSize() != 32)
      throw range_error("unexpected hash length");

   uint32_t hashHead;
   memcpy(&hashHead, hash.getPtr(), sizeof(uint32_t));
   auto id = len_++;
   auto insertIter = filterMap_.emplace(
      hashHead, set<uint32_t>{(uint32_t)id});

   if (insertIter.second)
      return;

   insertIter.first->second.emplace(id);
}

////
void BlockHashMap::update(const vector<BinaryData>& hashVec)
{
   if (!isValid())
      throw runtime_error("txfilter needs initialized first");

   for (auto& hash : hashVec)
      update(hash);
}

////////////////////////////////////////////////////////////////////////////////
set<uint32_t> BlockHashMap::compare(const BinaryData& hash) const
{
   uint32_t key;
   memcpy(&key, hash.getPtr(), sizeof(uint32_t));
   return compare(key);
}

////
set<uint32_t> BlockHashMap::compare(uint32_t key) const
{
   auto iter = filterMap_.find(key);
   if (iter == filterMap_.end())
      return {};

   return iter->second;
}

////
BlockHashMap BlockHashMap::deserialize(const uint8_t* ptr)
{
   auto size = getSizeFromPtr(ptr);
   if (size < 12)
      throw runtime_error("[BlockHashVector::deserialize] invalid size");

   auto blockkey = getBlockKeyFromPtr(ptr);
   BlockHashMap bucket(blockkey);
   bucket.len_ = getLenFromPtr(ptr);

   if (size != bucket.len_ * sizeof(uint32_t) + 12)
      throw runtime_error("[BlockHashVector::deserialize] deser error");

   for (uint32_t i=0; i<bucket.len_; i++)
   {
      uint32_t hash;
      memcpy(&hash, ptr + 12 + i*4, sizeof(uint32_t));
      auto insertIter = bucket.filterMap_.emplace(hash, set<uint32_t>{i});
      if (insertIter.second)
         continue;

      insertIter.first->second.emplace(i);
   }

   bucket.isValid_ = true;
   return bucket;
}

////////////////////////////////////////////////////////////////////////////////
//
//// TxFilterPoolWriter
//
////////////////////////////////////////////////////////////////////////////////
TxFilterPoolWriter::TxFilterPoolWriter(void) :
   dataRef_()
{}

////
TxFilterPoolWriter::TxFilterPoolWriter(map<uint32_t, BlockHashVector>& pool) :
   dataRef_(), pool_(move(pool))
{}

////
TxFilterPoolWriter::TxFilterPoolWriter(const TxFilterPoolWriter& filter) :
   dataRef_(), pool_(filter.pool_)
{}

////
TxFilterPoolWriter::TxFilterPoolWriter(TxFilterPoolWriter&& filter) :
   dataRef_(filter.dataRef_), pool_(move(filter.pool_))
{}

////
TxFilterPoolWriter::TxFilterPoolWriter(BinaryDataRef bdr) :
   dataRef_(bdr)
{}

////////////////////////////////////////////////////////////////////////////////
bool TxFilterPoolWriter::isValid() const
{
   return !(dataRef_.empty() && pool_.empty());
}

////////////////////////////////////////////////////////////////////////////////
void TxFilterPoolWriter::update(const map<uint32_t, BlockHashVector>& bucketMap)
{
   pool_.insert(bucketMap.begin(), bucketMap.end());
}

////////////////////////////////////////////////////////////////////////////////
void TxFilterPoolWriter::update(
   const map<uint32_t, shared_ptr<BlockHashVector>>& bucketMap)
{
   for (const auto& it : bucketMap)
      pool_.emplace(it.first, *(it.second));
}

////////////////////////////////////////////////////////////////////////////////
void TxFilterPoolWriter::serialize(BinaryWriter& bw) const
{
   if (!isValid())
   {
      //these maps are populated for read only operations, we shouldn't
      //try to serialize this pool
      throw TxFilterException("[serialize] invalid state");
   }

   //get total count
   uint32_t len = 0;

   if (!dataRef_.empty())
      len = getSizeFromPtr(dataRef_.getPtr());
   len += pool_.size();

   //write count header as a 32bit integer
   bw.put_uint32_t(len);

   //if we have serialized data, write it without the header
   if (!dataRef_.empty())
   {
      bw.put_BinaryDataRef(dataRef_.getSliceRef(
         4, dataRef_.getSize() - 4));
   }

   //serialize the pool objects
   for (auto& filter : pool_)
      filter.second.serialize(bw);
}

////////////////////////////////////////////////////////////////////////////////
//
//// TxFilterPoolReader
//
////////////////////////////////////////////////////////////////////////////////
TxFilterPoolReader::TxFilterPoolReader(const TxFilterPoolReader& filter) :
   dataRef_(), poolMap_(filter.poolMap_), fullMap_(filter.fullMap_)
{}

////
TxFilterPoolReader::TxFilterPoolReader(TxFilterPoolReader&& filter) :
   dataRef_(filter.dataRef_), poolMap_(move(filter.poolMap_)),
   fullMap_(move(filter.fullMap_))
{}

////
TxFilterPoolReader::TxFilterPoolReader(
   BinaryDataRef bdr, TxFilterPoolMode mode) :
   dataRef_(bdr)
{
   if (bdr.empty())
      throw TxFilterException("[TxFilterPool] empty dataref");

   switch (mode)
   {
   case TxFilterPoolMode::Bucket_Vector:
      return;

   case TxFilterPoolMode::Bucket_Map:
   {
      auto thisPtr = dataRef_.getPtr();
      auto size = getSizeFromPtr(thisPtr);
      uint32_t filterSize;
      size_t pos = 4;

      for (uint32_t i = 0; i < size; i++)
      {
         if (pos >= dataRef_.getSize())
            throw TxFilterException("[TxFilterPool] overflow");

         //iterate through entries
         filterSize = getSizeFromPtr(thisPtr + pos);

         auto filterObj = BlockHashMap::deserialize(thisPtr + pos);
         poolMap_.emplace(filterObj.blockKey_, move(filterObj));
         pos += filterSize;
      }

      break;
   }

   case TxFilterPoolMode::Pool_Map:
   {
      auto size = getSizeFromPtr(dataRef_.getPtr());
      uint32_t filterSize;
      size_t pos = 4;

      for (uint32_t i = 0; i < size; i++)
      {
         if (pos >= dataRef_.getSize())
            throw TxFilterException("[TxFilterPool] overflow");

         //iterate through entries
         auto thisPtr = dataRef_.getPtr() + pos;
         filterSize = getSizeFromPtr(thisPtr);

         auto blockkey = getBlockKeyFromPtr(thisPtr);
         auto len = getLenFromPtr(thisPtr);

         for (uint32_t i=0; i<len; i++)
         {
            uint32_t hash;
            memcpy(&hash, thisPtr + 12 + i*4, sizeof(uint32_t));

            auto insertIter = fullMap_.emplace(hash,
               map<uint32_t, set<uint32_t>>());

            auto keyInsertIter = insertIter.first->second.emplace(
               blockkey, set<uint32_t>());
            keyInsertIter.first->second.emplace(i);
         }

         pos += filterSize;
      }

      break;
   }

   default:
      throw TxFilterException("[TxFilterPool] unexpected filter mode");
   }
}

////////////////////////////////////////////////////////////////////////////////
bool TxFilterPoolReader::isValid() const
{
   return !(dataRef_.empty() && poolMap_.empty() && fullMap_.empty());
}

////////////////////////////////////////////////////////////////////////////////
map<uint32_t, set<uint32_t>> TxFilterPoolReader::compare(
   const BinaryData& hash) const
{
   if (hash.getSize() != 32)
      throw TxFilterException("hash is 32 bytes long");

   if (!isValid())
      throw TxFilterException("[compare] invalid pool");

   map<uint32_t, set<uint32_t>> returnMap;

   if (!fullMap_.empty())
   {
      uint32_t shortHand;
      memcpy(&shortHand, hash.getPtr(), 4);
      auto iter = fullMap_.find(shortHand);
      if (iter != fullMap_.end())
         returnMap = iter->second;
   }
   else if (!poolMap_.empty())
   {
      for (const auto& filterIt : poolMap_)
      {
         auto resultSet = filterIt.second.compare(hash);
         if (!resultSet.empty())
            returnMap.emplace(filterIt.second.getBlockKey(), move(resultSet));
      }
   }
   else if (!dataRef_.empty()) //running against a pointer
   {
      //get count
      auto thisPtr = dataRef_.getPtr();
      auto size = getSizeFromPtr(thisPtr);
      uint32_t filterSize;
      size_t pos = 4;

      for (uint32_t i = 0; i < size; i++)
      {
         if (pos >= dataRef_.getSize())
            throw TxFilterException("overflow while reading pool ptr");

         //iterate through entries
         filterSize = getSizeFromPtr(thisPtr + pos);

         auto filterObj = BlockHashVector::deserialize(thisPtr + pos);
         auto resultSet = filterObj.compare(hash);
         if (!resultSet.empty())
            returnMap.emplace(filterObj.getBlockKey(), move(resultSet));

         pos += filterSize;
      }
   }

   return returnMap;
}

////////////////////////////////////////////////////////////////////////////////
map<uint32_t, TxHashHintsSet> TxFilterPoolReader::scanHashes(
   uint32_t blockFileCount,
   const function<BinaryDataRef(uint32_t)>& fetch,
   const set<BinaryData>& hashes,
   TxFilterPoolMode mode)
{
   auto parseBlockFile = [&fetch, &hashes, &mode](uint32_t id)->TxHashHintsSet
   {
      auto filterRawData = fetch(id);
      if (filterRawData.empty())
         return {};

      TxFilterPoolMode thisMode = mode;
      if (thisMode == TxFilterPoolMode::Auto)
      {
         thisMode = TxFilterPoolMode::Pool_Map;
         if (hashes.size() <= 200)
            thisMode = TxFilterPoolMode::Bucket_Vector;
         else if (hashes.size() <= 2300)
            thisMode = TxFilterPoolMode::Bucket_Map;
      }

      TxFilterPoolReader pool(filterRawData, thisMode);
      TxHashHintsSet result;

      for (auto& hash : hashes)
      {
         auto hits = pool.compare(hash);
         if (hits.empty())
            continue;

         TxHashHints hint{hash};
         hint.filterHits_ = move(hits);

         result.emplace(move(hint));
      }

      return result;
   };

   map<uint32_t, TxHashHintsSet> finalResult;
   auto counterPtr = make_shared<atomic<uint32_t>>();
   counterPtr->store(0, memory_order_relaxed);
   auto mutexPtr = make_shared<mutex>();

   auto workerThread =
      [&parseBlockFile, &finalResult, &blockFileCount,
      counterPtr, mutexPtr](void)
   {
      map<uint32_t, TxHashHintsSet> result;
      while (true)
      {
         auto fileID = counterPtr->fetch_add(1, memory_order_relaxed);
         if (fileID >= blockFileCount)
            break;

         auto hits = parseBlockFile(fileID);
         result.emplace(fileID, move(hits));
      }

      auto lock = unique_lock<mutex>(*mutexPtr);
      for (auto& it : result)
         finalResult.emplace(it.first, move(it.second));
   };

   vector<thread> workers;
   for (unsigned i=1; i<thread::hardware_concurrency(); i++)
      workers.emplace_back(thread(workerThread));
   workerThread();

   for (auto& thr : workers)
      thr.join();

   return finalResult;
}