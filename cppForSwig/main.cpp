////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-19, goatpig.                                           //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <string>
#include <iostream>
#include <sstream>
#include "btc/ecc.h"

#include "ArmoryConfig.h"
#include "BDM_mainthread.h"
#include "BDM_Server.h"
#include "TerminalPassphrasePrompt.h"

using namespace std;
using namespace ArmoryConfig;

#define LOG_FILE_NAME "dbLog"

int main(int argc, char* argv[])
{
   btc_ecc_start();
   startupBIP151CTX();
   startupBIP150CTX(4);

   GOOGLE_PROTOBUF_VERIFY_VERSION;

#ifdef _WIN32
   WSADATA wsaData;
   WORD wVersion = MAKEWORD(2, 0);
   WSAStartup(wVersion, &wsaData);
#endif

   ArmoryConfig::parseArgs(argc, argv);
   
      LOGENABLESTDOUT();
   else
      LOGDISABLESTDOUT();

   LOGINFO << "Running on " << DBSettings::threadCount() << " threads";
   LOGINFO << "Ram usage level: " << DBSettings::ramUsage();

   //init state
   DBSettings::setServiceType(SERVICE_WEBSOCKET);
   BlockDataManagerThread bdmThread;

   if (!DBSettings::checkChain())
   {
      //check we can listen on this ip:port
      if (SimpleSocket::checkSocket("127.0.0.1", NetworkSettings::listenPort()))
      {
         LOGERR << "There is already a process listening on port " << 
            NetworkSettings::listenPort();
         LOGERR << "ArmoryDB cannot start under these conditions. Shutting down!";
         LOGERR << "Make sure to shutdown the conflicting process" <<
            "before trying again (most likely another ArmoryDB instance)";

         exit(1);
      }
   }

   {
      //setup remote peers db, this will block the init process until 
      //peers db is unlocked if --encrypt-wallet is passed
      PassphraseLambda passLbd;

      if (bdmConfig.encryptWallet_)
      {
         passLbd = TerminalPassphrasePrompt::getLambda("peers db");
      }
      else
      {
         passLbd = [](const std::set<BinaryData>&) {
            return SecureBinaryData{};
         };
      }

      WebSocketServer::initAuthPeers(passLbd);
   }
    
   //start up blockchain service
   bdmThread.start(DBSettings::initMode());

   if (!DBSettings::checkChain())
   {
      WebSocketServer::start(&bdmThread, false);
   }
   else
   {
      bdmThread.join();
   }

   //stop all threads and clean up
   WebSocketServer::shutdown();
   google::protobuf::ShutdownProtobufLibrary();

   shutdownBIP151CTX();
   btc_ecc_stop();

   return 0;
}
