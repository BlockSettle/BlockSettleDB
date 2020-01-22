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

using namespace std;

#include "BlockDataManagerConfig.h"
#include "BDM_mainthread.h"
#include "BDM_Server.h"
#include "TerminalPassphrasePrompt.h"

int main(int argc, char* argv[])
{
   btc_ecc_start();
   startupBIP151CTX();
   startupBIP150CTX(4, false);

   GOOGLE_PROTOBUF_VERIFY_VERSION;

#ifdef _WIN32
   WSADATA wsaData;
   WORD wVersion = MAKEWORD(2, 0);
   WSAStartup(wVersion, &wsaData);
#endif

   BlockDataManagerConfig bdmConfig;
   bdmConfig.parseArgs(argc, argv);
   
   cout << "logging in " << bdmConfig.logFilePath_ << endl;
   STARTLOGGING(bdmConfig.logFilePath_, LogLvlDebug);
   if (!bdmConfig.useCookie_)
      LOGENABLESTDOUT();
   else
      LOGDISABLESTDOUT();

   LOGINFO << "Running on " << bdmConfig.threadCount_ << " threads";
   LOGINFO << "Ram usage level: " << bdmConfig.ramUsage_;

   //init state
   BlockDataManagerConfig::setServiceType(SERVICE_WEBSOCKET);
   BlockDataManagerThread bdmThread(bdmConfig);

   if (!bdmConfig.checkChain_)
   {
      //check we can listen on this ip:port
      if (SimpleSocket::checkSocket("127.0.0.1", bdmConfig.listenPort_))
      {
         LOGERR << "There is already a process listening on port " << 
            bdmConfig.listenPort_;
         LOGERR << "ArmoryDB cannot start under these conditions. Shutting down!";
         LOGERR << "Make sure to shutdown the conflicting process" <<
            "before trying again (most likely another ArmoryDB instance)";

         exit(1);
      }
   }

   {
      //setup remote peers db, this will block the init process until 
      //peers db is unlocked
      auto&& passLbd = TerminalPassphrasePrompt::getLambda("peers db");
      WebSocketServer::initAuthPeers(passLbd);
   }
    
   //create cookie file if applicable
   bdmConfig.createCookie();

   //start up blockchain service
   bdmThread.start(bdmConfig.initMode_);

   if (!bdmConfig.checkChain_)
   {
      //start websocket server
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
