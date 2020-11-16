////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "CppBridge.h"

////////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
   btc_ecc_start();
   startupBIP151CTX();
   startupBIP150CTX(4);

   //init static configuration variables
   BlockDataManagerConfig bdmConfig;
   bdmConfig.parseArgs(argc, argv);

   //enable logs
   STARTLOGGING(bdmConfig.logFilePath_, LogLvlDebug);
   LOGENABLESTDOUT();

   //setup the bridge
   auto bridge = std::make_shared<ArmoryBridge::CppBridge>(
      bdmConfig.dataDir_,
      "127.0.0.1", bdmConfig.listenPort_,
      bdmConfig.oneWayAuth_, bdmConfig.offline_);

   bridge->startThreads();
   
   //setup the socket
   auto sockPtr = std::make_shared<ArmoryBridge::CppBridgeSocket>(
       "127.0.0.1", "46122", bridge);

   //set bridge write lambda
   auto pushPayloadLbd = [sockPtr](
      std::unique_ptr<ArmoryBridge::WritePayload_Bridge> payload)->void
   {
      sockPtr->pushPayload(move(payload), nullptr);
   };
   bridge->setWriteLambda(pushPayloadLbd);

   //connect
   if (!sockPtr->connectToRemote())
   {
      LOGERR << "cannot find ArmoryQt client, shutting down";
      return -1;
   }

   //block main thread till socket dies
   sockPtr->blockUntilClosed();

   bridge->stopThreads();

   //done
   LOGINFO << "exiting";

   shutdownBIP151CTX();
   btc_ecc_stop();

   return 0;
}
