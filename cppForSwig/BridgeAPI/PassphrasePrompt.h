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

#include "../protobuf/ClientProto.pb.h"
#include "../Wallets/WalletIdTypes.h"
#include "../Wallets/PassphraseLambda.h"

#define BRIDGE_CALLBACK_PROMPTUSER  UINT32_MAX - 2

namespace ArmoryBridge
{
   struct WritePayload_Bridge;

   ////////////////////////////////////////////////////////////////////////////
   class BridgePassphrasePrompt
   {
   private:
      std::unique_ptr<std::promise<SecureBinaryData>> promPtr_;
      std::unique_ptr<std::shared_future<SecureBinaryData>> futPtr_;

      const std::string promptId_;
      std::function<void(std::unique_ptr<WritePayload_Bridge>)> writeLambda_;

      std::set<Armory::Wallets::EncryptionKeyId> encryptionKeyIds_;

   public:
      static const Armory::Wallets::EncryptionKeyId concludeKey;

   public:
      BridgePassphrasePrompt(const std::string& id,
         std::function<void(std::unique_ptr<WritePayload_Bridge>)> lbd) :
         promptId_(id), writeLambda_(lbd)
      {}

      PassphraseLambda getLambda(::Codec_ClientProto::UnlockPromptType);
      void setReply(const std::string&);
   };
};

#endif