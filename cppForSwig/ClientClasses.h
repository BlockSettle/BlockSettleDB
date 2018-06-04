////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_CLIENTCLASSES
#define _H_CLIENTCLASSES

#include <exception>
#include <string>
#include <functional>

#include "BinaryData.h"
#include "SocketObject.h"

namespace AsyncClient
{
   class BlockDataViewer;
};
   
///////////////////////////////////////////////////////////////////////////////
struct NoArmoryDBExcept : public std::runtime_error
{
   NoArmoryDBExcept(void) : runtime_error("")
   {}
};

struct BDVAlreadyRegistered : public std::runtime_error
{
   BDVAlreadyRegistered(void) : std::runtime_error("")
   {}
};

///////////////////////////////////////////////////////////////////////////////
struct RemoteCallbackSetupStruct
{
private:
   friend class AsyncClient::BlockDataViewer;
   friend class RemoteCallback;

   shared_ptr<SocketPrototype> sockPtr_;
   string bdvId_;
   function<void(unsigned)> setHeightLambda_;
   
private:
   RemoteCallbackSetupStruct(shared_ptr<SocketPrototype> sockptr,
      const string& id, function<void(unsigned)> lbd) :
      sockPtr_(sockptr), bdvId_(id), setHeightLambda_(lbd)
   {}

public:
   RemoteCallbackSetupStruct(void)
   {}
};

///////////////////////////////////////////////////////////////////////////////
namespace ClientClasses
{

   ///////////////////////////////////////////////////////////////////////////////
   struct FeeEstimateStruct
   {
      std::string error_;
      float val_ = 0;
      bool isSmart_ = false;

      FeeEstimateStruct(float val, bool isSmart, const std::string& error) :
         val_(val), isSmart_(isSmart), error_(error)
      {}

      FeeEstimateStruct(void) 
      {}
   };

   ///////////////////////////////////////////////////////////////////////////////
   class BlockHeader
   {
      friend class Blockchain;
      friend class testBlockHeader;
      friend class BlockData;

   private:

      void unserialize(uint8_t const * ptr, uint32_t size);
      void unserialize(BinaryDataRef const & str)
      {
         unserialize(str.getPtr(), str.getSize());
      }

   public:

      BlockHeader(void) {}
      BlockHeader(const BinaryData&, unsigned);

      uint32_t           getVersion(void) const { return READ_UINT32_LE(getPtr()); }
      BinaryData const & getThisHash(void) const { return thisHash_; }
      BinaryData         getPrevHash(void) const { return BinaryData(getPtr() + 4, 32); }
      BinaryData         getMerkleRoot(void) const { return BinaryData(getPtr() + 36, 32); }
      BinaryData         getDiffBits(void) const { return BinaryData(getPtr() + 72, 4); }
      uint32_t           getTimestamp(void) const { return READ_UINT32_LE(getPtr() + 68); }
      uint32_t           getNonce(void) const { return READ_UINT32_LE(getPtr() + 76); }
      uint32_t           getBlockHeight(void) const { return blockHeight_; }

      /////////////////////////////////////////////////////////////////////////////
      BinaryDataRef  getThisHashRef(void) const { return thisHash_.getRef(); }
      BinaryDataRef  getPrevHashRef(void) const { return BinaryDataRef(getPtr() + 4, 32); }
      BinaryDataRef  getMerkleRootRef(void) const { return BinaryDataRef(getPtr() + 36, 32); }
      BinaryDataRef  getDiffBitsRef(void) const { return BinaryDataRef(getPtr() + 72, 4); }

      /////////////////////////////////////////////////////////////////////////////
      uint8_t const * getPtr(void) const {
         if (!isInitialized_)
            throw runtime_error("uninitialized BlockHeader");
         return dataCopy_.getPtr();
      }
      size_t        getSize(void) const {
         if (!isInitialized_)
            throw runtime_error("uninitialized BlockHeader");
         return dataCopy_.getSize();
      }
      bool            isInitialized(void) const { return isInitialized_; }

      void clearDataCopy() { dataCopy_.resize(0); }

   private:
      BinaryData     dataCopy_;
      bool           isInitialized_ = false;
      // Specific to the DB storage
      uint32_t       blockHeight_ = UINT32_MAX;

      // Derived properties - we expect these to be set after construct/copy
      BinaryData     thisHash_;
      double         difficultyDbl_ = 0.0;
   };
};

///////////////////////////////////////////////////////////////////////////////
class RemoteCallback
{
private:

   enum CallbackOrder
   {
      CBO_continue,
      CBO_NewBlock,
      CBO_ZC,
      CBO_BDV_Refresh,
      CBO_BDM_Ready,
      CBO_progress,
      CBO_terminate,
      CBO_NodeStatus,
      CBO_BDV_Error
   };

   bool run_ = true;

   const shared_ptr<SocketPrototype> sock_;
   const string bdvID_;
   SOCKET sockfd_;

   map<string, CallbackOrder> orderMap_;
   function<void(unsigned)> setHeightLbd_;

private:
   void pushCallbackRequest(void);

public:
   RemoteCallback(RemoteCallbackSetupStruct);
   virtual ~RemoteCallback(void) = 0;

   virtual void run(BDMAction action, void* ptr, int block = 0) = 0;
   virtual void progress(
      BDMPhase phase,
      const vector<string> &walletIdVec,
      float progress, unsigned secondsRem,
      unsigned progressNumeric
   ) = 0;

   void start(void);
   void shutdown(void);
   bool processArguments(BinaryDataRef&);
};

#endif