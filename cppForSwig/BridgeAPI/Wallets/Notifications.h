////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <mutex>
#include <functional>
#include <map>
#include <set>
#include <string>

#include "../DBClientClasses.h"

namespace Armory
{
   namespace Bridge
   {
      enum class NotifType : int
      {
         PUSH,
         UPDATE
      };

      struct NotifStruct
      {
         const NotifType type;

         //set when type is PUSH
         BinaryData packet;

         //set when type is UPDATE
         std::function<void(void)> lbd;
      };
      typedef std::function<void(NotifStruct)> NotifFunc;

      ////////
      class Callback : public RemoteCallback
      {
      private:
         //to push packets to the gui
         NotifFunc notifFunc_;

         //id members
         std::mutex idMutex_;
         std::unordered_map<std::string, std::function<void(void)>> idCallbacks_;

      private:
         void processRefreshCallbacks(std::set<std::string>&);

      public:
         Callback(const NotifFunc&);

         //virtuals
         void run(BdmNotification) override;
         void progress(
            BDMPhase phase,
            const std::vector<std::string> &walletIdVec,
            float progress, unsigned secondsRem,
            unsigned progressNumeric
         ) override;
         void disconnected(void) override;

         void notifySetupDone(void);
         void notifySetupRegistrationDone(void);
         void notifyRefresh(const std::set<std::string>&);
         void registerRefreshCallback(const std::string&,
            const std::function<void(void)>&);
         void unregisterCallback(const std::string&);
      };
   }
}
