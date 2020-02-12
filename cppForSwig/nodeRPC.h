////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_NODERPC_
#define _H_NODERPC_

#include <mutex>
#include <memory>
#include <string>
#include <functional>

#include "SocketObject.h"
#include "StringSockets.h"
#include "BtcUtils.h"

#include "JSON_codec.h"

#include "ReentrantLock.h"
#include "BlockDataManagerConfig.h"

////
enum NodeStatus
{
   NodeStatus_Offline,
   NodeStatus_Online,
   NodeStatus_OffSync
};

////
enum RpcStatus
{
   RpcStatus_Disabled,
   RpcStatus_BadAuth,
   RpcStatus_Online,
   RpcStatus_Error_28
};

////
enum ChainStatus
{
   ChainStatus_Unknown,
   ChainStatus_Syncing,
   ChainStatus_Ready
};

////
class RpcError : public std::runtime_error
{
public:
   RpcError(void) : 
      std::runtime_error("RpcError")
   {}

   RpcError(const std::string& err) :
      std::runtime_error(err)
   {}
};

class ConfMismatch
{
   const unsigned expected_;
   const unsigned actual_;

public:
   ConfMismatch(unsigned expected, unsigned actual) :
      expected_(expected), actual_(actual)
   {}

   unsigned expected(void) const { return expected_; }
   unsigned actual(void) const { return actual_; }
};

////////////////////////////////////////////////////////////////////////////////
struct FeeEstimateResult
{
   bool smartFee_ = false;
   float feeByte_ = 0;

   std::string error_;
};

typedef std::map<std::string, std::map<unsigned, FeeEstimateResult>> EstimateCache;

////////////////////////////////////////////////////////////////////////////////
class NodeChainState
{
   friend class CallbackReturn_NodeStatusStruct;
   friend class NodeRPC;

private:
   std::list<std::tuple<unsigned, uint64_t, uint64_t> > heightTimeVec_;
   ChainStatus state_ = ChainStatus_Unknown;
   float blockSpeed_ = 0.0f;
   uint64_t eta_ = 0;
   float pct_ = 0.0f;
   unsigned blocksLeft_ = 0;

   unsigned prev_pct_int_ = 0;

private:
   bool processState(std::shared_ptr<JSON_object> const getblockchaininfo_obj);

public:
   void appendHeightAndTime(unsigned, uint64_t);
   unsigned getTopBlock(void) const;
   ChainStatus state(void) const { return state_; }
   float getBlockSpeed(void) const { return blockSpeed_; }

   void reset();

   float getProgressPct(void) const { return pct_; }
   uint64_t getETA(void) const { return eta_; }
   unsigned getBlocksLeft(void) const { return blocksLeft_; }
};

////////////////////////////////////////////////////////////////////////////////
struct NodeStatusStruct
{
   NodeStatus status_ = NodeStatus_Offline;
   bool SegWitEnabled_ = false;
   RpcStatus rpcStatus_ = RpcStatus_Disabled;
   ::NodeChainState chainState_;
};

////////////////////////////////////////////////////////////////////////////////
class NodeRPCInterface : public Lockable
{
protected:
   std::function<void(void)> nodeStatusLambda_;
   ::NodeChainState nodeChainState_;
   std::shared_ptr<EstimateCache> currentEstimateCache_ = nullptr;

private:
   void initAfterLock(void) override {}
   void cleanUpBeforeUnlock(void) override {}

protected:
   void callback(void)
   {
      if (nodeStatusLambda_)
         nodeStatusLambda_();
   }

public:
   virtual ~NodeRPCInterface(void) = 0;
   virtual void shutdown(void) = 0;

   virtual int broadcastTx(const BinaryDataRef&) = 0;
   virtual bool canPoll(void) const = 0;
   virtual RpcStatus testConnection() = 0;
   virtual void waitOnChainSync(std::function<void(void)>) = 0;

   virtual FeeEstimateResult getFeeByte(
      unsigned confTarget, const std::string& strategy) = 0;

   //locals
   const ::NodeChainState& getChainStatus(void) const;
   void registerNodeStatusLambda(std::function<void(void)> lbd) 
   { nodeStatusLambda_ = lbd; }

   std::map<unsigned, FeeEstimateResult> getFeeSchedule(
      const std::string& strategy); 
};

////////////////////////////////////////////////////////////////////////////////
class NodeRPC : public NodeRPCInterface
{
private:
   const BlockDataManagerConfig& bdmConfig_;
   std::string basicAuthString64_;

   RpcStatus previousState_ = RpcStatus_Disabled;
   std::condition_variable pollCondVar_;


   std::vector<std::thread> thrVec_;
   std::atomic<bool> run_ = { true };

private:
   std::string getAuthString(void);
   std::string getDatadir(void);

   std::string queryRPC(JSON_object&);
   std::string queryRPC(HttpSocket&, JSON_object&);
   void pollThread(void);
   
   float queryFeeByte(HttpSocket&, unsigned);
   FeeEstimateResult queryFeeByteSmart(HttpSocket&,
      unsigned& confTarget, std::string& strategy);
   void aggregateFeeEstimates(void);
   void resetAuthString(void);
   bool updateChainStatus(void);

public:
   NodeRPC(BlockDataManagerConfig&);
   ~NodeRPC(void);
   
   bool setupConnection(HttpSocket&);

   //virtuals
   void shutdown(void) override;
   RpcStatus testConnection() override;
   bool canPoll(void) const override { return true; }

   FeeEstimateResult getFeeByte(
      unsigned confTarget, const std::string& strategy) override;

   int broadcastTx(const BinaryDataRef&) override;
   void waitOnChainSync(std::function<void(void)>) override;
};

#endif