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
#include "NetworkConfig.h"

#define DEFAULT_ZCTHREAD_COUNT 100
#define WEBSOCKET_PORT 7681

size_t MAX_THREADS();
#define BROADCAST_ID_LENGTH 6
#define REGISTER_ID_LENGH 5

class BitcoinP2P;
class BitcoinNodeInterface;
class NodeRPCInterface;

////////////////////////////////////////////////////////////////////////////////
struct BlockDataManagerConfig
{
private:
   static ARMORY_DB_TYPE armoryDbType_;
   static SOCKET_SERVICE service_;
   static ARMORY_OPERATION_MODE operationMode_;


public:
   BDM_INIT_MODE initMode_ = INIT_RESUME;

   static const std::string dbDirExtention_;
   static const std::string defaultDataDir_;
   static const std::string defaultBlkFileLocation_;
   static const std::string defaultTestnetDataDir_;
   static const std::string defaultTestnetBlkFileLocation_;
   static const std::string defaultRegtestDataDir_;
   static const std::string defaultRegtestBlkFileLocation_;

   static std::string dataDir_;

   static bool ephemeralPeers_;
   bool oneWayAuth_ = true; //BlockSettleDB modification: default to public db

   std::string blkFileLocation_;
   std::string dbDir_;
   std::string logFilePath_;

   std::pair<
      std::shared_ptr<BitcoinNodeInterface>, 
      std::shared_ptr<BitcoinNodeInterface>> bitcoinNodes_;
   std::shared_ptr<NodeRPCInterface> rpcNode_;

   std::string btcPort_;
   std::string listenPort_;
   std::string rpcPort_;

   bool customListenPort_ = false;
   bool customBtcPort_ = false;

   unsigned ramUsage_ = 4;
   unsigned threadCount_ = MAX_THREADS();
   unsigned zcThreadCount_ = DEFAULT_ZCTHREAD_COUNT;

   std::exception_ptr exceptionPtr_ = nullptr;

   bool reportProgress_ = true;

   bool checkChain_ = false;
   bool clearMempool_ = false;

   const std::string cookie_;
   bool useCookie_ = false;
   bool encryptWallet_ = false;

   bool offline_ = false;

private:
   static bool fileExists(const std::string&, int);

public:
   BlockDataManagerConfig();

   void selectNetwork(NETWORK_MODE);

   void processArgs(const std::map<std::string, std::string>&, bool);
   void parseArgs(int argc, char* argv[]);
   void createCookie(void) const;
   void printHelp(void);
   static std::string portToString(unsigned);

   static std::vector<std::string> getLines(const std::string& path);
   static std::map<std::string, std::string> getKeyValsFromLines(
      const std::vector<std::string>&, char delim);
   static std::pair<std::string, std::string> getKeyValFromLine(const std::string&, char delim);
   static std::string stripQuotes(const std::string& input);
   static std::vector<std::string> keyValToArgv(const std::map<std::string, std::string>&);
   static std::vector<std::string> tokenizeLine(
      const std::string&, const std::string&);

   static bool testConnection(const std::string& ip, const std::string& port);
   static std::string hasLocalDB(const std::string& datadir, const std::string& port);
   static std::string getPortFromCookie(const std::string& datadir);
   static std::string getCookie(const std::string& datadir);
   static std::string getDataDir(void) { return dataDir_; }

   static void setDbType(ARMORY_DB_TYPE dbType)
   {
      armoryDbType_ = dbType;
   }

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

   static void setOperationMode(ARMORY_OPERATION_MODE _mode)
   {
      operationMode_ = _mode;
   }

   static ARMORY_OPERATION_MODE getOperationMode(void)
   {
      return operationMode_;
   }
};

////////////////////////////////////////////////////////////////////////////////
struct ConfigFile
{
   std::map<std::string, std::string> keyvalMap_;

   ConfigFile(const std::string& path);

   static std::vector<BinaryData> fleshOutArgs(
      const std::string& path, const std::vector<BinaryData>& argv);
};

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
// kate: indent-width 3; replace-tabs on;
