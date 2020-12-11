////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2015, Armory Technologies, Inc.                        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE-ATI or http://www.gnu.org/licenses/agpl.html                  //
//                                                                            //
//                                                                            //
//  Copyright (C) 2016-2018, goatpig                                          //            
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                   
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

/*general config for all things client and server*/

#ifndef BLOCKDATAMANAGERCONFIG_H
#define BLOCKDATAMANAGERCONFIG_H

#include <exception>
#include <thread>
#include <tuple>
#include <list>

#include "bdmenums.h"
#include "BinaryData.h"
#include "BitcoinSettings.h"

#define DEFAULT_ZCTHREAD_COUNT 100
#define WEBSOCKET_PORT 7681

#define BROADCAST_ID_LENGTH 6
#define REGISTER_ID_LENGH 5

class BitcoinNodeInterface;

namespace CoreRPC
{
   class NodeRPCInterface;
};

namespace ArmoryConfig
{
   
////////////////////////////////////////////////////////////////////////////////
namespace SettingsUtils
{
   std::vector<std::string> getLines(const std::string& path);
   std::map<std::string, std::string> getKeyValsFromLines(
      const std::vector<std::string>&, char delim);
   std::pair<std::string, std::string> getKeyValFromLine(
      const std::string&, char delim);
      
   std::string stripQuotes(const std::string& input);
   std::vector<std::string> keyValToArgv(
      const std::map<std::string, std::string>&);
   std::vector<std::string> tokenizeLine(
      const std::string&, const std::string&);
      
   bool fileExists(const std::string&, int);
   std::string portToString(unsigned);

   bool testConnection(const std::string& ip, const std::string& port);
   std::string getPortFromCookie(const std::string& datadir);
   std::string hasLocalDB(const std::string& datadir, const std::string& port);
};

////////////////////////////////////////////////////////////////////////////////
void printHelp(void);
void parseArgs(int, char**);
void parseArgs(const std::vector<std::string>&);
const std::string& getDataDir(void);
void reset(void);

////////////////////////////////////////////////////////////////////////////////
class BaseSettings
{
   friend void ArmoryConfig::parseArgs(const std::vector<std::string>&);
   friend void ArmoryConfig::reset(void);
   friend const std::string& ArmoryConfig::getDataDir(void);

private:
   static std::mutex configMutex_;
   static std::string dataDir_;
   static unsigned initCount_;

private:
   static void detectDataDir(std::map<std::string, std::string>&);
   static void reset(void);
};

////////////////////////////////////////////////////////////////////////////////
class DBSettings
{
   friend void ArmoryConfig::parseArgs(const std::vector<std::string>&);
   friend void ArmoryConfig::reset(void);

private:
   static ARMORY_DB_TYPE armoryDbType_;
   static SOCKET_SERVICE service_;

   static BDM_INIT_MODE initMode_;

   static unsigned ramUsage_;
   static unsigned threadCount_;
   static unsigned zcThreadCount_;

   static bool reportProgress_;
   static bool checkChain_;
   static bool clearMempool_;

private:
   static void processArgs(const std::map<std::string, std::string>&);
   static void reset(void);

public:
   static std::string getCookie(const std::string& datadir);

   static ARMORY_DB_TYPE getDbType(void)
   {
      return armoryDbType_;
   }

   static void setServiceType(SOCKET_SERVICE _type)
   {
      service_ = _type;
   }

   static SOCKET_SERVICE getServiceType(void)
   {
      return service_;
   }

   static std::string getDbModeStr(void);
   static unsigned threadCount(void) { return threadCount_; }
   static unsigned ramUsage(void) { return ramUsage_; }
   static unsigned zcThreadCount(void) { return zcThreadCount_; }

   static bool checkChain(void) { return checkChain_; }
   static BDM_INIT_MODE initMode(void) { return initMode_; }
   static bool clearMempool(void) { return clearMempool_; }
   static bool reportProgress(void) { return reportProgress_; }
};

////////////////////////////////////////////////////////////////////////////////
class NetworkSettings
{
   using RpcPtr = std::shared_ptr<CoreRPC::NodeRPCInterface>;
   using NodePair = std::pair<
      std::shared_ptr<BitcoinNodeInterface>, 
      std::shared_ptr<BitcoinNodeInterface>>;

   friend void ArmoryConfig::parseArgs(const std::vector<std::string>&);
   friend void ArmoryConfig::reset(void);

private:
   static NodePair bitcoinNodes_;
   static RpcPtr rpcNode_;

   static std::string btcPort_;
   static std::string listenPort_;
   static std::string rpcPort_;

   static bool customListenPort_;
   static bool customBtcPort_;

   static bool useCookie_;
   static bool ephemeralPeers_;
   static bool oneWayAuth_;

   static bool offline_;
   static std::string cookie_;

private:
   static void createNodes(void);
   static void createCookie(void);

   static void processArgs(const std::map<std::string, std::string>&);
   static void reset(void);

public:
   static void selectNetwork(NETWORK_MODE);
   
   static const std::string& btcPort(void);
   static const std::string& listenPort(void);
   static const std::string& rpcPort(void);

   static void randomizeListenPort(void);

   static const NodePair& bitcoinNodes(void);
   static RpcPtr rpcNode(void);

   static bool useCookie(void) { return useCookie_; }
   static const std::string& cookie(void) { return cookie_; }
   
   static bool ephemeralPeers(void) { return ephemeralPeers_; }
   static bool oneWayAuth(void) { return oneWayAuth_; }
   static bool offline(void) { return offline_; }
};

////////////////////////////////////////////////////////////////////////////////
class Pathing
{
   friend void ArmoryConfig::parseArgs(const std::vector<std::string>&);
   friend void ArmoryConfig::reset(void);

private:
   static std::string blkFilePath_;
   static std::string dbDir_;
   static std::string logFilePath_;

private:
   static void processArgs(const std::map<std::string, std::string>&);
   static void reset(void);

public:

   static const std::string& logFilePath(void) { return logFilePath_; }
   static const std::string& blkFilePath(void) { return blkFilePath_; }
   static const std::string& dbDir(void) { return dbDir_; }
};

////////////////////////////////////////////////////////////////////////////////
struct ConfigFile
{
   std::map<std::string, std::string> keyvalMap_;

   ConfigFile(const std::string& path);

   static std::vector<BinaryData> fleshOutArgs(
      const std::string& path, const std::vector<BinaryData>& argv);
};
}; //namespace ArmoryConfig

////////////////////////////////////////////////////////////////////////////////
struct BDV_Error_Struct
{
   std::string errorStr_;
   BinaryData errData_;
   int errCode_;

   BinaryData serialize(void) const;
   void deserialize(const BinaryData&);
};
#endif

