////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _PASSPHRASE_PROMPT_H
#define _PASSPHRASE_PROMPT_H

#include <future>

#include "../Wallets/WalletIdTypes.h"
#include "../Wallets/GetPassphrase.h"

namespace Armory
{
   namespace Seeds
   {
      struct PromptReply;
   }

   namespace Bridge
   {
      using CallbackHandler = std::function<bool(const Seeds::PromptReply&)>;

      //////////////////////////////////////////////////////////////////////////
      struct ServerPushWrapper
      {
         const uint32_t referenceId;
         CallbackHandler handler = nullptr;
         BinaryData payload;
      };

      //////////////////////////////////////////////////////////////////////////
      class BridgePassphrasePrompt
      {
         static uint32_t referenceCounter_;

      private:
         const std::string promptId_;
         std::function<void(ServerPushWrapper)> writeFunc_;

      private:
         Seeds::PromptReply processFeedRequest(
            const std::set<Armory::Wallets::EncryptionKeyId>&);

      public:
         BridgePassphrasePrompt(const std::string&,
            std::function<void(ServerPushWrapper)>);

         Passphrase::UnlockFunc getLambda(void);
         void cleanup(void);
      };
   }; //namespace Bridge
}; //namespace Armory

#endif