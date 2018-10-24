////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _SSH_PARSER_H
#define _SSH_PARSER_H

#include <atomic>
#include <condition_variable>

#include "lmdb_wrapper.h"
#include "Blockchain.h"
#include "ScrAddrFilter.h"

#ifndef UNIT_TESTS
#define SSH_BOUNDS_BATCH_SIZE 100000
#else
#define SSH_BOUNDS_BATCH_SIZE 2
#endif

////////////////////////////////////////////////////////////////////////////////
struct SshBatch
{
   unique_ptr<promise<bool>> waitOnWriter_ = nullptr;
   const unsigned shardId_;
   map<BinaryData, BinaryWriter> serializedSsh_;

   SshBatch(unsigned shardId) :
      shardId_(shardId)
   {}
};

////////////////////////////////////////////////////////////////////////////////
struct SshBounds
{
   pair<BinaryData, BinaryData> bounds_;
   map<BinaryData, BinaryWriter> serializedSsh_;
   chrono::duration<double> time_;
   uint64_t count_ = 0;

   unique_ptr<promise<bool>> completed_;
   shared_future<bool> fut_;

   SshBounds(void)
   {
      completed_ = make_unique<promise<bool>>();
      fut_ = completed_->get_future();
   }

   void serializeResult(map<BinaryDataRef, StoredScriptHistory>&);
};

struct SshMapping
{
   map<uint8_t, shared_ptr<SshMapping>> map_;
   uint64_t count_ = 0;

   shared_ptr<SshMapping> getMappingForKey(uint8_t);
   void prettyPrint(stringstream&, unsigned);
   void merge(SshMapping&);
};


////////////////////////////////////////////////////////////////////////////////
class ShardedSshParser
{
private:
   LMDBBlockDatabase* db_;
   atomic<unsigned> counter_;
   const unsigned firstHeight_;
   unsigned firstShard_;
   const unsigned threadCount_;
   bool init_;
   bool undo_ = false;

   vector<unique_ptr<SshBounds>> boundsVector_;

   atomic<unsigned> commitedBoundsCounter_;
   atomic<unsigned> fetchBoundsCounter_;
   condition_variable writeThreadCV_;
   mutex cvMutex_;

   atomic<unsigned> mapCount_;
   vector<SshMapping> mappingResults_;

private:
   void putSSH(void);
   SshBounds* getNext();
   
private:
   void setupBounds();
   SshMapping mapSubSshDB();
   void mapSubSshDBThread(unsigned);
   void parseSshThread(void);

public:
   ShardedSshParser(
      LMDBBlockDatabase* db,
      unsigned firstHeight, 
      unsigned threadCount, bool init)
      : db_(db),
      firstHeight_(firstHeight),
      threadCount_(threadCount), init_(init)
   {
      counter_.store(0, memory_order_relaxed);
   }

   void updateSsh(void);
   void undo(void);
};

typedef pair<set<BinaryData>, map<BinaryData, StoredScriptHistory>> subSshParserResult;
subSshParserResult parseSubSsh(
   unique_ptr<LDBIter>, int32_t scanFrom, bool,
   function<uint8_t(unsigned)>,
   shared_ptr<map<BinaryDataRef, shared_ptr<AddrAndHash>>>,
   BinaryData upperBound);

#endif