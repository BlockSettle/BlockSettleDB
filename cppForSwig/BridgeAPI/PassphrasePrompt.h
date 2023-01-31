////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _PASSPHRASE_PROMPT_H
#define _PASSPHRASE_PROMPT_H

#include <future>

#include "../protobuf/BridgeProto.pb.h"
#include "../Wallets/WalletIdTypes.h"
#include "../Wallets/PassphraseLambda.h"

#define BRIDGE_CALLBACK_PROMPTUSER "prompt"

namespace Armory
{
   namespace Bridge
   {
      struct WritePayload_Bridge;

      //////////////////////////////////////////////////////////////////////////
      class BridgePassphrasePrompt
      {
      private:
         std::unique_ptr<std::promise<SecureBinaryData>> promPtr_;
         std::unique_ptr<std::shared_future<SecureBinaryData>> futPtr_;

         const std::string promptId_;
         std::function<void(std::unique_ptr<WritePayload_Bridge>)> writeLambda_;

         std::set<Wallets::EncryptionKeyId> encryptionKeyIds_;

      public:
         static const Wallets::EncryptionKeyId concludeKey;

      public:
         BridgePassphrasePrompt(const std::string& id,
            std::function<void(std::unique_ptr<WritePayload_Bridge>)> lbd) :
            promptId_(id), writeLambda_(lbd)
         {}

         PassphraseLambda getLambda(::BridgeProto::UnlockPromptType);
         void setReply(const std::string&);
      };
   }; //namespace Bridge
}; //namespace Armory

#endif