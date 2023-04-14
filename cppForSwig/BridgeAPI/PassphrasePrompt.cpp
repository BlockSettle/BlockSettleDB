////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2021, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "log.h"
#include "../protobuf/BridgeProto.pb.h"
#include "PassphrasePrompt.h"

using namespace Armory::Bridge;
using namespace std;
using namespace BridgeProto;

uint32_t BridgePassphrasePrompt::referenceCounter_ = 1;

////////////////////////////////////////////////////////////////////////////////
////
////  BridgePassphrasePrompt
////
////////////////////////////////////////////////////////////////////////////////
BridgePassphrasePrompt::BridgePassphrasePrompt(const std::string& id,
   std::function<void(ServerPushWrapper)> func) :
   promptId_(id), writeFunc_(move(func))
{}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData BridgePassphrasePrompt::processFeedRequest(
   const set<Armory::Wallets::EncryptionKeyId>& ids)
{
   if (ids.empty())
   {
      //exit condition
      cleanup();
      return {};
   }

   //cycle the promise & future
   auto promPtr = make_shared<promise<SecureBinaryData>>();
   auto fut = promPtr->get_future();

   auto refId = referenceCounter_++;

   //create protobuf payload
   auto protoPtr = make_unique<Payload>();
   auto pushPtr = protoPtr->mutable_callback();
   pushPtr->set_callback_id(promptId_);
   pushPtr->set_reference_id(refId);

   auto unlockPtr = pushPtr->mutable_unlock_request();
   for (const auto& id : ids)
      unlockPtr->add_encryption_key_ids(id.toHexStr());

   //reply handler
   auto replyHandler = [promPtr](const CallbackReply& reply)->bool
   {
      if (!reply.success() ||
         reply.reply_payload_case() != CallbackReply::kPassphrase)
      {
         promPtr->set_exception(make_exception_ptr(runtime_error("")));
      }
      else
      {
         promPtr->set_value(SecureBinaryData::fromString(reply.passphrase()));
      }

      return true;
   };

   //push over socket
   ServerPushWrapper wrapper{ refId, replyHandler, move(protoPtr) };
   writeFunc_(move(wrapper));

   //wait on future
   try
   {
      return fut.get();
   }
   catch (const exception&)
   {
      LOGINFO << "cancelled wallet unlock";
      return {};
   }
}

////////////////////////////////////////////////////////////////////////////////
void BridgePassphrasePrompt::cleanup()
{
   auto protoPtr = make_unique<Payload>();
   auto pushPtr = protoPtr->mutable_callback();
   pushPtr->set_callback_id(promptId_);
   pushPtr->set_cleanup(true);
   writeFunc_(ServerPushWrapper{0, nullptr, move(protoPtr)});
}

////////////////////////////////////////////////////////////////////////////////
PassphraseLambda BridgePassphrasePrompt::getLambda()
{
   return [this](const set<Armory::Wallets::EncryptionKeyId>& ids)->SecureBinaryData
   {
      return processFeedRequest(ids);
   };
}
