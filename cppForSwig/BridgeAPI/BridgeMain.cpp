////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-20, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BridgeSocket.h"
#include "CppBridge.h"

////////////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
   btc_ecc_start();
   startupBIP151CTX();
   startupBIP150CTX(4);

   //init static configuration variables
   Armory::Config::parseArgs(
      argc, argv, Armory::Config::ProcessType::Bridge);

   //enable logs
   STARTLOGGING(
      Armory::Config::Pathing::logFilePath("bridgeLog"), LogLvlDebug);
   LOGDISABLESTDOUT();

   //setup the bridge
   auto bridge = std::make_shared<ArmoryBridge::CppBridge>(
      Armory::Config::getDataDir(),
      "127.0.0.1", Armory::Config::NetworkSettings::listenPort(),
      Armory::Config::NetworkSettings::oneWayAuth(),
      Armory::Config::NetworkSettings::isOffline());

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
