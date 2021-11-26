////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "PassphrasePrompt.h"
#include "BridgeSocket.h"

using namespace ArmoryBridge;
using namespace std;
using namespace Codec_ClientProto;

////////////////////////////////////////////////////////////////////////////////
////
////  BridgePassphrasePrompt
////
////////////////////////////////////////////////////////////////////////////////
const Armory::Wallets::EncryptionKeyId
   BridgePassphrasePrompt::concludeKey("concludePrompt");

PassphraseLambda BridgePassphrasePrompt::getLambda(UnlockPromptType type)
{
   auto lbd = [this, type]
      (const set<Armory::Wallets::EncryptionKeyId>& ids)
      ->SecureBinaryData
   {
      UnlockPromptState promptState = UnlockPromptState::cycle;
      if (encryptionKeyIds_.empty())
      {
         if (ids.empty()) 
            throw runtime_error("malformed command");

         encryptionKeyIds_ = ids;
         promptState = UnlockPromptState::start;
      }

      //cycle the promise & future
      promPtr_ = make_unique<promise<SecureBinaryData>>();
      futPtr_ = make_unique<shared_future<SecureBinaryData>>(
         promPtr_->get_future());

      //create protobuf payload
      UnlockPromptCallback opaque;
      opaque.set_promptid(promptId_);
      opaque.set_prompttype(type);

      switch (type)
      {
         case UnlockPromptType::decrypt:
         {
            opaque.set_verbose("Unlock Wallet");
            break;
         }

         case UnlockPromptType::migrate:
         {
            opaque.set_verbose("Migrate Wallet");
            break;
         }

         default:
            opaque.set_verbose("undefined prompt type");
      }

      bool exit = false;
      if (!ids.empty())
      {
         auto iter = ids.begin();
         if (*iter == concludeKey)
         {
            promptState = UnlockPromptState::stop;
            exit = true;
         }

         opaque.set_walletid(iter->toHexStr());
      }

      opaque.set_state(promptState);

      auto msg = make_unique<OpaquePayload>();
      msg->set_payloadtype(OpaquePayloadType::prompt);

      string serializedOpaqueData;
      opaque.SerializeToString(&serializedOpaqueData);
      msg->set_payload(serializedOpaqueData);

      //push over socket
      auto payload = make_unique<WritePayload_Bridge>();
      payload->message_ = move(msg);
      payload->id_ = BRIDGE_CALLBACK_PROMPTUSER;
      writeLambda_(move(payload));

      if (exit)
         return {};

      //wait on future
      return futPtr_->get();
   };

   return lbd;
}

////////////////////////////////////////////////////////////////////////////////
void BridgePassphrasePrompt::setReply(const string& passphrase)
{
   auto&& passSBD = SecureBinaryData::fromString(passphrase);
   promPtr_->set_value(passSBD);
}
