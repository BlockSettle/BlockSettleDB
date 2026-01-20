////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <functional>
#include <memory>
#include <filesystem>

namespace AsyncClient
{
   class BlockDataViewer;
}

class BinaryData;

namespace Armory
{
   namespace Wallets
   {
      class AuthorizedPeers;
   }

   namespace Bridge
   {
      class WalletManager;
      using BdvPtr = std::shared_ptr<AsyncClient::BlockDataViewer>;
   #ifdef _WIN32
      extern void* autoDbHandle;
   #else
      extern int autoDbPid;
   #endif

      ////////
      std::shared_ptr<Wallets::AuthorizedPeers> spawnDb(void);
      bool isDbRunning(void);

      BdvPtr setupClientConnection(
         std::shared_ptr<Wallets::AuthorizedPeers>,
         std::shared_ptr<WalletManager>
      );
   }
}
