////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2021, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BlockDataMap.h"
#include "BtcUtils.h"
#include "TxHashFilters.h"

#ifndef _WIN32
#include <sys/mman.h>
#endif

using namespace std;

////////////////////////////////////////////////////////////////////////////////
BlockData::BlockData(uint32_t blockid)
   : uniqueID_(blockid)
{}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<BlockData> BlockData::deserialize(const uint8_t* data, size_t size,
   const shared_ptr<BlockHeader> blockHeader,
   function<unsigned int(const BinaryData&)> getID,
   BlockData::CheckHashes mode)
{
   //deser header from raw block and run a quick sanity check
   if (size < HEADER_SIZE)
   {
      throw BlockDeserializingException(
      "raw data is smaller than HEADER_SIZE");
   }

   BinaryDataRef bdr(data, HEADER_SIZE);
   BlockHeader bh(bdr);

   auto uniqueID = UINT32_MAX;
   if (getID)
      uniqueID = getID(bh.getThisHash());

   auto result = make_shared<BlockData>(uniqueID);
   result->headerPtr_ = blockHeader;
   result->blockHash_ = bh.thisHash_;

   BinaryRefReader brr(data + HEADER_SIZE, size - HEADER_SIZE);
   auto numTx = (unsigned)brr.get_var_int();

   if (blockHeader != nullptr)
   {
      if (bh.getThisHashRef() != blockHeader->getThisHashRef())
         throw BlockDeserializingException(
         "raw data does not match expected block hash");

      if (numTx != blockHeader->getNumTx())
         throw BlockDeserializingException(
         "tx count mismatch in deser header");
   }

   for (unsigned i = 0; i < numTx; i++)
   {
      //light tx deserialization, just figure out the offset and size of
      //txins and txouts
      auto tx = BCTX::parse(brr);
      brr.advance(tx->size_);

      //move it to BlockData object vector
      result->txns_.push_back(move(tx));
   }

   result->data_ = data;
   result->size_ = size;

   vector<BinaryData> allHashes;
   switch (mode)
   {
      case CheckHashes::NoChecks:
         return result;

      case CheckHashes::MerkleOnly:
      case CheckHashes::TxFilters:
      {
         allHashes.reserve(result->txns_.size());
         for (auto& txn : result->txns_)
         {
            auto txhash = txn->moveHash();
            allHashes.emplace_back(move(txhash));
         }
         break;
      }

      case CheckHashes::FullHints:
      {
         allHashes.reserve(result->txns_.size());
         for (auto& txn : result->txns_)
         {
            const auto& txhash = txn->getHash();
            allHashes.emplace_back(txhash);
         }
         break;
      }
   }

   //any form of later txhash filtering implies we check the merkle
   //root, otherwise we would have no guarantees the hashes are valid
   auto&& merkleroot = BtcUtils::calculateMerkleRoot(allHashes);
   if (merkleroot != bh.getMerkleRoot())
   {
      LOGERR << "merkle root mismatch!";
      LOGERR << "   header has: " << bh.getMerkleRoot().toHexStr();
      LOGERR << "   block yields: " << merkleroot.toHexStr();
      throw BlockDeserializingException("invalid merkle root");
   }

   if (mode == CheckHashes::TxFilters)
      result->computeTxFilter(allHashes);
   return result;
}

/////////////////////////////////////////////////////////////////////////////
void BlockData::computeTxFilter(const vector<BinaryData>& allHashes)
{
   if (txFilter_ == nullptr)
   {
      txFilter_ = make_shared<BlockHashVector>(uniqueID_);
      txFilter_->isValid_ = true;
   }
   txFilter_->update(allHashes);
}

////
shared_ptr<BlockHashVector> BlockData::getTxFilter() const
{
   return txFilter_;
}

/////////////////////////////////////////////////////////////////////////////
shared_ptr<BlockHeader> BlockData::createBlockHeader() const
{
   if (headerPtr_ != nullptr)
      return headerPtr_;

   auto bhPtr = make_shared<BlockHeader>();
   auto& bh = *bhPtr;

   bh.dataCopy_ = move(BinaryData(data_, HEADER_SIZE));

   bh.difficultyDbl_ = BtcUtils::convertDiffBitsToDouble(
      BinaryDataRef(data_ + 72, 4));

   bh.isInitialized_ = true;
   bh.nextHash_ = BinaryData(0);
   bh.blockHeight_ = UINT32_MAX;
   bh.difficultySum_ = -1;
   bh.isMainBranch_ = false;
   bh.isOrphan_ = true;
   
   bh.numBlockBytes_ = size_;
   bh.numTx_ = txns_.size();

   bh.blkFileNum_ = fileID_;
   bh.blkFileOffset_ = offset_;
   bh.thisHash_ = blockHash_;
   bh.uniqueID_ = uniqueID_;

   return bhPtr;
}

/////////////////////////////////////////////////////////////////////////////
void BlockFiles::detectAllBlockFiles()
{
   if (folderPath_.size() == 0)
      throw runtime_error("empty block files folder path");

   unsigned numBlkFiles = filePaths_.size();

   while (numBlkFiles < UINT16_MAX)
   {
      string path = BtcUtils::getBlkFilename(folderPath_, numBlkFiles);
      uint64_t filesize = BtcUtils::GetFileSize(path);
      if (filesize == FILE_DOES_NOT_EXIST)
         break;

      filePaths_.insert(make_pair(numBlkFiles, path));

      totalBlockchainBytes_ += filesize;
      numBlkFiles++;
   }
}

/////////////////////////////////////////////////////////////////////////////
const string& BlockFiles::getLastFileName(void) const
{
   if (filePaths_.size() == 0)
      throw runtime_error("empty path map");

   return filePaths_.rbegin()->second;
}

/////////////////////////////////////////////////////////////////////////////
BlockDataLoader::BlockDataLoader(const string& path) :
   path_(path), prefix_("blk")
{}

/////////////////////////////////////////////////////////////////////////////
shared_ptr<BlockDataFileMap> BlockDataLoader::get(const string& filename)
{
   //convert to int ID
   auto intID = nameToIntID(filename);

   //get with int ID
   return get(intID);
}

/////////////////////////////////////////////////////////////////////////////
shared_ptr<BlockDataFileMap> BlockDataLoader::get(uint32_t fileid)
{
   //don't have this fileid yet, create it
   return getNewBlockDataMap(fileid);
}

/////////////////////////////////////////////////////////////////////////////
uint32_t BlockDataLoader::nameToIntID(const string& filename)
{
   if (filename.size() < 3 ||
      strncmp(prefix_.c_str(), filename.c_str(), 3))
      throw runtime_error("invalid filename");

   auto&& substr = filename.substr(3);
   return stoi(substr);
}

/////////////////////////////////////////////////////////////////////////////
string BlockDataLoader::intIDToName(uint32_t fileid)
{
   stringstream filename;

   filename << path_ << "/blk";
   filename << setw(5) << setfill('0') << fileid;
   filename << ".dat";

   return filename.str();
}

/////////////////////////////////////////////////////////////////////////////
shared_ptr<BlockDataFileMap>
   BlockDataLoader::getNewBlockDataMap(uint32_t fileid)
{
   string filename = move(intIDToName(fileid));

   return make_shared<BlockDataFileMap>(filename);
}

/////////////////////////////////////////////////////////////////////////////
BlockDataFileMap::BlockDataFileMap(const string& filename)
{
   //relaxed memory order for loads and stores, we only care about 
   //atomicity in these operations
   useCounter_.store(0, memory_order_relaxed);

   try
   {
      auto filemap = DBUtils::getMmapOfFile(filename);
      fileMap_ = filemap.filePtr_;
      size_ = filemap.size_;
   }
   catch (exception&)
   {
      //LOGERR << "Failed to create BlockDataMap with error: " << e.what();
   }
}

/////////////////////////////////////////////////////////////////////////////
BlockDataFileMap::~BlockDataFileMap()
{
   //close file mmap
   if (fileMap_ != nullptr)
   {
#ifdef _WIN32
      UnmapViewOfFile(fileMap_);
#else
      munmap(fileMap_, size_);
#endif
      fileMap_ = nullptr;
   }
}
