////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-18, goatpig                                            //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "Signer.h"
#include "Script.h"
#include "Transactions.h"
#include "make_unique.h"

using namespace std;

StackItem::~StackItem()
{}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// ScriptSpender
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BinaryDataRef ScriptSpender::getOutputScript() const
{
   if (!utxo_.isInitialized())
      throw runtime_error("missing utxo");

   return utxo_.getScript();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef ScriptSpender::getOutputHash() const
{
   if (utxo_.isInitialized())
      return utxo_.getTxHash();

   if (outpoint_.getSize() != 36)
      throw runtime_error("missing utxo");

   BinaryRefReader brr(outpoint_);
   return brr.get_BinaryDataRef(32);
}

////////////////////////////////////////////////////////////////////////////////
unsigned ScriptSpender::getOutputIndex() const
{
   if (utxo_.isInitialized())
      return utxo_.getTxOutIndex();
   
   if (outpoint_.getSize() != 36)
      throw runtime_error("missing utxo");

   BinaryRefReader brr(outpoint_);
   brr.advance(32);

   return brr.get_uint32_t();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef ScriptSpender::getOutpoint() const
{
   if (outpoint_.getSize() == 0)
   {
      BinaryWriter bw;
      bw.put_BinaryDataRef(getOutputHash());
      bw.put_uint32_t(getOutputIndex());

      outpoint_ = bw.getData();
   }

   return outpoint_.getRef();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::serializeScript(
   const vector<shared_ptr<StackItem>>& stack, bool no_throw)
{
   BinaryWriter bwStack;

   for (auto& stackItem : stack)
   {
      switch (stackItem->type_)
      {
      case StackItemType_PushData:
      {
         auto stackItem_pushdata = 
            dynamic_pointer_cast<StackItem_PushData>(stackItem);
         if (stackItem_pushdata == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");

            bwStack.put_uint8_t(0);
            break;
         }

         bwStack.put_BinaryData(
            BtcUtils::getPushDataHeader(stackItem_pushdata->data_));
         bwStack.put_BinaryData(stackItem_pushdata->data_);
         break;
      }

      case StackItemType_SerializedScript:
      {
         auto stackItem_ss =
            dynamic_pointer_cast<StackItem_SerializedScript>(stackItem);
         if (stackItem_ss == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");
            
            break;
         }

         bwStack.put_BinaryData(stackItem_ss->data_);
         break;
      }

      case StackItemType_Sig:
      {
         auto stackItem_sig =
            dynamic_pointer_cast<StackItem_Sig>(stackItem);
         if (stackItem_sig == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");

            bwStack.put_uint8_t(0);
            break;
         }

         bwStack.put_BinaryData(
            BtcUtils::getPushDataHeader(stackItem_sig->data_));
         bwStack.put_BinaryData(stackItem_sig->data_);
         break;
      }

      case StackItemType_MultiSig:
      {
         auto stackItem_sig =
            dynamic_pointer_cast<StackItem_MultiSig>(stackItem);
         if (stackItem_sig == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");
            
            bwStack.put_uint8_t(0);
            break;
         }

         if (stackItem_sig->sigs_.size() < stackItem_sig->m_)
         {
            if (!no_throw)
               throw ScriptException("missing sigs for ms script");
         }

         for (auto& sigpair : stackItem_sig->sigs_)
         {
            bwStack.put_BinaryData(
               BtcUtils::getPushDataHeader(sigpair.second));
            bwStack.put_BinaryData(sigpair.second);
         }
         break;
      }

      case StackItemType_OpCode:
      {
         auto stackItem_opcode =
            dynamic_pointer_cast<StackItem_OpCode>(stackItem);
         if (stackItem_opcode == nullptr)
         {
            if (no_throw)
               throw ScriptException("unexpected StackItem type");
            
            bwStack.put_uint8_t(0);
            break;
         }

         bwStack.put_uint8_t(stackItem_opcode->opcode_);
         break;
      }

      default:
         if (!no_throw)
            throw ScriptException("unexpected StackItem type");
      }
   }

   return bwStack.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::serializeWitnessData(
   const vector<shared_ptr<StackItem>>& stack, 
   unsigned &itemCount, bool no_throw)
{
   itemCount = 0;

   BinaryWriter bwStack;
   for (auto& stackItem : stack)
   {
      switch (stackItem->type_)
      {
      case StackItemType_PushData:
      {
         ++itemCount;

         auto stackItem_pushdata =
            dynamic_pointer_cast<StackItem_PushData>(stackItem);
         if (stackItem_pushdata == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");

            bwStack.put_uint8_t(0);
            break;
         }

         bwStack.put_var_int(stackItem_pushdata->data_.getSize());
         bwStack.put_BinaryData(stackItem_pushdata->data_);
         break;
      }

      case StackItemType_SerializedScript:
      {

         auto stackItem_ss =
            dynamic_pointer_cast<StackItem_SerializedScript>(stackItem);
         if (stackItem_ss == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");

            break;
         }

         bwStack.put_BinaryData(stackItem_ss->data_);
         ++itemCount;
         break;
      }

      case StackItemType_Sig:
      {
         ++itemCount;
         auto stackItem_sig =
            dynamic_pointer_cast<StackItem_Sig>(stackItem);
         if (stackItem_sig == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");

            bwStack.put_uint8_t(0);
            break;
         }

         bwStack.put_var_int(stackItem_sig->data_.getSize());
         bwStack.put_BinaryData(stackItem_sig->data_);
         break;
      }

      case StackItemType_MultiSig:
      {
         auto stackItem_sig =
            dynamic_pointer_cast<StackItem_MultiSig>(stackItem);
         if (stackItem_sig == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");

            bwStack.put_uint8_t(0);
            break;
         }

         if (stackItem_sig->sigs_.size() < stackItem_sig->m_)
         {
            if (!no_throw)
               throw ScriptException("missing sigs for ms script");
         }

         for (auto& sigpair : stackItem_sig->sigs_)
         {
            bwStack.put_BinaryData(
               BtcUtils::getPushDataHeader(sigpair.second));
            bwStack.put_BinaryData(sigpair.second);
            ++itemCount;
         }
         break;
      }

      case StackItemType_OpCode:
      {
         ++itemCount;
         auto stackItem_opcode =
            dynamic_pointer_cast<StackItem_OpCode>(stackItem);
         if (stackItem_opcode == nullptr)
         {
            if (!no_throw)
               throw ScriptException("unexpected StackItem type");

            bwStack.put_uint8_t(0);
            break;
         }

         bwStack.put_uint8_t(stackItem_opcode->opcode_);
         break;
      }

      default:
         if (!no_throw)
            throw ScriptException("unexpected StackItem type");
      }
   }

   return bwStack.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::isResolved() const
{
   if (!utxo_.isInitialized())
      return false;

   if (!isSegWit())
   {
      if (legacyStatus_ >= SpenderStatus_Resolved)
         return true;
   }
   else
   {
      //If this spender is SW, only emtpy (native sw) and resolved (nested sw) 
      //states are valid. The SW stack should not be empty for a SW input
      if ((legacyStatus_ == SpenderStatus_Empty ||
         legacyStatus_ == SpenderStatus_Resolved) &&
         segwitStatus_ >= SpenderStatus_Resolved)
      {
         return true;
      }

   }
   return false;
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::isSigned() const
{
   /*
   Valid combos are:
   legacy: Signed, SW: empty
   legacy: empty, SW: signed
   legacy: resolved, SW: signed
   */
   if (!utxo_.isInitialized())
      return false;

   if (!isSegWit())
   {
      if (legacyStatus_ == SpenderStatus_Signed &&
         segwitStatus_ == SpenderStatus_Empty)
      {
         return true;
      }
   }
   else
   {
      if (segwitStatus_ == SpenderStatus_Signed)
      {
         if (legacyStatus_ == SpenderStatus_Empty ||
            legacyStatus_ == SpenderStatus_Resolved)
         {
            return true;
         }
      }
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::getSerializedOutpoint() const
{
   if (utxo_.isInitialized())
   {
      BinaryWriter bw;

      bw.put_BinaryData(utxo_.getTxHash());
      bw.put_uint32_t(utxo_.getTxOutIndex());

      return bw.getData();
   }

   if (outpoint_.getSize() != 36)
      throw ScriptException("missing outpoint");

   return outpoint_;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::getSerializedInputScript() const
{
   //if we have a serialized script already, return that
   if (!inputScript_.empty())
      return inputScript_;
      
   //otherwise, serialize it from the stack
   vector<shared_ptr<StackItem>> stack;
   for (auto& stack_item : legacyStack_)
      stack.push_back(stack_item.second);
   return serializeScript(stack, true);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::getSerializedInput(bool withSig) const
{
   if (legacyStatus_ == SpenderStatus_Unknown)
   {
      throw ScriptException("unresolved spender");
   }

   if (withSig)
   {
      if (!isSegWit())
      {
         if (legacyStatus_ != SpenderStatus_Signed)
            throw ScriptException("spender is missing sigs");        
      }
      else
      {
         if (legacyStatus_ != SpenderStatus_Empty && 
            legacyStatus_ != SpenderStatus_Resolved)
         {
            throw ScriptException("invalid legacy state for sw spender");                   
         }
      }
   }
   
   auto serializedScript = getSerializedInputScript();

   BinaryWriter bw;
   bw.put_BinaryData(getSerializedOutpoint());

   bw.put_var_int(serializedScript.getSize());
   bw.put_BinaryData(serializedScript);
   bw.put_uint32_t(sequence_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::serializeAvailableStack() const
{
   try
   {
      return getSerializedInput(false);
   }
   catch (exception&)
   {}

   vector<shared_ptr<StackItem>> stack;
   for (auto& stack_item : legacyStack_)
      stack.push_back(stack_item.second);

   auto&& serialized_script = serializeScript(stack, true);

   BinaryWriter bw;
   bw.put_BinaryData(getSerializedOutpoint());

   bw.put_var_int(serialized_script.getSize());
   bw.put_BinaryData(serialized_script);
   bw.put_uint32_t(sequence_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef ScriptSpender::getWitnessData(void) const
{
   if (isSegWit())
   {
      if(segwitStatus_ != SpenderStatus_Signed)
         throw runtime_error("witness data missing signature");
   }
   else if (segwitStatus_ != SpenderStatus_Empty)
   {
      throw runtime_error("unresolved witness");
   }

   return witnessData_.getRef();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::serializeAvailableWitnessData(void) const
{
   try
   {
      return getWitnessData();
   }
   catch (exception&)
   {}

   vector<shared_ptr<StackItem>> stack;
   for (auto& stack_item : witnessStack_)
      stack.push_back(stack_item.second);

   //serialize and get item count
   unsigned itemCount = 0;
   auto&& data = serializeWitnessData(stack, itemCount, true);

   //put stack item count
   BinaryWriter bw;
   bw.put_var_int(itemCount);

   //put serialized stack
   bw.put_BinaryData(data);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::setWitnessData(const vector<shared_ptr<StackItem>>& stack)
{  
   //serialize to get item count
   unsigned itemCount = 0;
   auto&& data = serializeWitnessData(stack, itemCount);

   //put stack item count
   BinaryWriter bw;
   bw.put_var_int(itemCount);

   //put serialized stack
   bw.put_BinaryData(data);

   witnessData_ = bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::updateStack(map<unsigned, shared_ptr<StackItem>>& stackMap,
   const vector<shared_ptr<StackItem>>& stackVec)
{
   for (auto& stack_item : stackVec)
   {
      auto iter_pair = stackMap.insert(
         make_pair(stack_item->getId(), stack_item));

      if (iter_pair.second == true)
         continue;

      //already have a stack item for this id, let's compare them
      if (iter_pair.first->second->isSame(stack_item.get()))
         continue;

      //stack items differ, are they multisig items?

      switch (iter_pair.first->second->type_)
      {
      case StackItemType_MultiSig:
      {
         auto stack_item_ms = 
            dynamic_pointer_cast<StackItem_MultiSig>(iter_pair.first->second);

         stack_item_ms->merge(stack_item.get());
         break;
      }

      case StackItemType_Sig:
      {
         if (iter_pair.first->second->isValid())
            break;

         if (stack_item->type_ == StackItemType_Sig && stack_item->isValid())
         {
            iter_pair.first->second = stack_item;
            break;
         }

      }

      default:
         throw ScriptException("unexpected StackItem type inequality");
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::processStacks()
{
   /*
   Process the respective stacks, set the serialized input scripts if the 
   stacks carry enough data and clear the stacks. Otherwise, leave the 
   input/witness script empty and preserve the stack as is.
   */

   auto parseStack = [](
      const map<unsigned, shared_ptr<StackItem>>& stack)
      ->SpenderStatus
   {
      SpenderStatus stackState = SpenderStatus_Resolved;
      for (auto& item_pair : stack)
      {
         auto& stack_item = item_pair.second;
         switch (stack_item->type_)
         {
            case StackItemType_MultiSig:
            {
               if (stack_item->isValid())
               {
                  stackState = SpenderStatus_Signed;
                  break;
               }

               auto stack_item_ms = dynamic_pointer_cast<StackItem_MultiSig>(
                  stack_item);

               if (stack_item_ms == nullptr)
                  throw runtime_error("unexpected stack item type");

               if (stack_item_ms->m_ > 0)
                  stackState = SpenderStatus_PartiallySigned;
                  
               break;
            }

            case StackItemType_Sig:
            {
               if (stack_item->isValid())
                  stackState = SpenderStatus_Signed;
               break;
            }

            default:
            {
               if (!stack_item->isValid())
                  return SpenderStatus_Unknown;
            }
         }
      }
      
      return stackState;
   };

   auto updateState = [parseStack](
      map<unsigned, shared_ptr<StackItem>>& stack,
      SpenderStatus& spenderState,
      const function<void(const vector<shared_ptr<StackItem>>&)>& setScript)
      ->void
   {
      auto stackState = parseStack(stack);

      if (stackState >= spenderState)
      {
         switch (stackState)
         {
            case SpenderStatus_Resolved:
            case SpenderStatus_PartiallySigned:
            {
               //do not set the script, keep the stack
               break;
            }

            case SpenderStatus_Signed:
            {
               //set the script, clear the stack

               vector<shared_ptr<StackItem>> stack_vec;
               for (auto& item_pair : stack)
                  stack_vec.push_back(item_pair.second);
            
               setScript(stack_vec);
               stack.clear();
               break;
            }

            default:
               //do not set the script, keep the stack
               break;
         }

         spenderState = stackState;
      }
   };

   if (legacyStack_.size() > 0)
   {
      updateState(legacyStack_, legacyStatus_, [this](
         const vector<shared_ptr<StackItem>>& stackVec) 
         { inputScript_ = move(serializeScript(stackVec)); }
      );
   }
   
   if (witnessStack_.size() > 0)
   {
      updateState(witnessStack_, segwitStatus_, [this](
         const vector<shared_ptr<StackItem>>& stackVec) 
         { this->setWitnessData(stackVec); }
      );
   }
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::serializeStateHeader(
   Codec_SignerState::ScriptSpenderState& protoMsg) const
{
   protoMsg.set_version_max(SCRIPT_SPENDER_VERSION_MAX);
   protoMsg.set_version_min(SCRIPT_SPENDER_VERSION_MIN);

   protoMsg.set_legacy_status((uint8_t)legacyStatus_);
   protoMsg.set_segwit_status((uint8_t)segwitStatus_);

   protoMsg.set_sighash_type((uint8_t)sigHashType_);
   protoMsg.set_sequence(sequence_);

   protoMsg.set_is_p2sh(isP2SH_);
   protoMsg.set_is_csv(isCSV_);
   protoMsg.set_is_cltv(isCLTV_);
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::serializeStateUtxo(
   Codec_SignerState::ScriptSpenderState& protoMsg) const
{
   if (hasUTXO())
   {
      auto utxoEntry = protoMsg.mutable_utxo();
      utxo_.toProtobuf(*utxoEntry);
   }
   else
   {
      auto outpoint = protoMsg.mutable_outpoint();
      
      auto outputHashRef = getOutputHash();
      outpoint->set_txhash(outputHashRef.getPtr(), outputHashRef.getSize());
      outpoint->set_txoutindex(getOutputIndex());
      outpoint->set_value(getValue());
      outpoint->set_isspent(false);
   }
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::serializeLegacyState(
   Codec_SignerState::ScriptSpenderState& protoMsg) const
{
   if (legacyStatus_ == SpenderStatus_Signed)
   {
      //put resolved script
      protoMsg.set_sig_script(
         inputScript_.getPtr(), inputScript_.getSize());
   }
   else if (legacyStatus_ >= SpenderStatus_Resolved)
   {
      //put legacy stack
      for (auto stackItem : legacyStack_)
      {
         auto stackEntry = protoMsg.add_legacy_stack();
         stackItem.second->serialize(*stackEntry);
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::serializeSegwitState(
   Codec_SignerState::ScriptSpenderState& protoMsg) const
{
   if (segwitStatus_ == SpenderStatus_Signed)
   {
      //put resolved witness data
      protoMsg.set_witness_data(
         witnessData_.getPtr(), witnessData_.getSize());
   }
   else if (segwitStatus_ >= SpenderStatus_Resolved)
   {
      //put witness stack
      for (auto stackItem : witnessStack_)
      {
         auto stackEntry = protoMsg.add_witness_stack();
         stackItem.second->serialize(*stackEntry);
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::serializeState(
   Codec_SignerState::ScriptSpenderState& protoMsg) const
{
   serializeStateHeader(protoMsg);
   serializeStateUtxo(protoMsg);
   serializeLegacyState(protoMsg);
   serializeSegwitState(protoMsg);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<ScriptSpender> ScriptSpender::deserializeState(
   const Codec_SignerState::ScriptSpenderState& protoMsg)
{
   auto maxVer = protoMsg.version_max();
   auto minVer = protoMsg.version_min();
   if (maxVer != SCRIPT_SPENDER_VERSION_MAX || 
      minVer != SCRIPT_SPENDER_VERSION_MIN)
   {
      throw SignerDeserializationError("serialized spender version mismatch");
   }

   shared_ptr<ScriptSpender> resultPtr;

   if (protoMsg.has_utxo())
   {
      auto&& utxo = UTXO::fromProtobuf(protoMsg.utxo());
      resultPtr = make_shared<ScriptSpender>(utxo);
   }
   else if (protoMsg.has_outpoint())
   {
      const auto& outpoint = protoMsg.outpoint();
      auto outpointHash = BinaryDataRef::fromString(outpoint.txhash());
      if (outpointHash.getSize() != 32)
         throw SignerDeserializationError("invalid outpoint hash");

      resultPtr = make_shared<ScriptSpender>(
         outpointHash, outpoint.txoutindex(), outpoint.value());
   }
   else
   {
      throw SignerDeserializationError("missing utxo/outpoint");
   }

   resultPtr->legacyStatus_ = (SpenderStatus)protoMsg.legacy_status();
   resultPtr->segwitStatus_ = (SpenderStatus)protoMsg.segwit_status();

   resultPtr->isP2SH_ = protoMsg.is_p2sh();
   resultPtr->isCSV_  = protoMsg.is_csv();
   resultPtr->isCLTV_ = protoMsg.is_cltv();

   resultPtr->sequence_ = protoMsg.sequence();
   resultPtr->sigHashType_ = (SIGHASH_TYPE)protoMsg.sighash_type();

   if (protoMsg.has_sig_script())
   {
      resultPtr->inputScript_ = BinaryData::fromString(protoMsg.sig_script());
   }

   for (unsigned i=0; i<protoMsg.legacy_stack_size(); i++)
   {
      const auto& stackItem = protoMsg.legacy_stack(i);
      auto stackObjPtr = StackItem::deserialize(stackItem);
      resultPtr->legacyStack_.emplace(stackObjPtr->getId(), stackObjPtr);
   }

   if (protoMsg.has_witness_data())
   {
      resultPtr->witnessData_ = BinaryData::fromString(protoMsg.witness_data());
   }

   for (unsigned i=0; i<protoMsg.witness_stack_size(); i++)
   {
      const auto& stackItem = protoMsg.witness_stack(i);
      auto stackObjPtr = StackItem::deserialize(stackItem);
      resultPtr->witnessStack_.emplace(stackObjPtr->getId(), stackObjPtr);
   }

   return resultPtr;
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::merge(const ScriptSpender& obj)
{
   if (isSigned())
      return;

   if (!utxo_.isInitialized() && obj.utxo_.isInitialized())
      utxo_ = obj.utxo_;

   if (utxo_.value_ != obj.value_)
      throw runtime_error("spender merge value mismatch");

   isP2SH_ |= obj.isP2SH_;
   isCLTV_ |= obj.isCLTV_;
   isCSV_  |= obj.isCSV_;

   if (legacyStatus_ != SpenderStatus_Signed)
   {
      switch (obj.legacyStatus_)
      {
      case SpenderStatus_Resolved:
      case SpenderStatus_PartiallySigned:
      {
         legacyStack_.insert(
            obj.legacyStack_.begin(), obj.legacyStack_.end());
         processStacks();
         
         /*
         processStacks will set the relevant legacy status, 
         therefor we break out of the switch scope so as to not overwrite
         the status unnecessarely
         */
         break;
      }

      case SpenderStatus_Signed:
      {
         inputScript_ = obj.inputScript_;
         //fallthrough
      }
      
      default:
         //set the legacy status
         if (obj.legacyStatus_ > legacyStatus_)
            legacyStatus_ = obj.legacyStatus_;
      }
   }

   if (segwitStatus_ != SpenderStatus_Signed)
   {
      switch (obj.segwitStatus_)
      {
      case SpenderStatus_Resolved:
      case SpenderStatus_PartiallySigned:
      {
         witnessStack_.insert(
            obj.witnessStack_.begin(), obj.witnessStack_.end());
         processStacks();
         break;
      }      

      case SpenderStatus_Signed:
      {
         witnessData_ = obj.witnessData_;
         //fallthrough
      }

      default:
         if (obj.segwitStatus_ > segwitStatus_)
            segwitStatus_ = obj.segwitStatus_;
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::compareEvalState(const ScriptSpender& rhs) const
{
   /*
   This is meant to compare the publicly resolved data between 2 spenders for 
   the same utxo. It cannot compare sigs in a stateful fashion because it
   cannot generate the sighash data without the rest of the transaction.

   Use signer::verify to check sigs
   */

   //lambdas
   auto getResolvedItems = [](const BinaryData& script, 
      bool isWitnessData)->
      vector<BinaryDataRef>
   {
      vector<BinaryDataRef> resolvedScriptItems;
      BinaryRefReader brr(script);

      try
      {
         if (isWitnessData)
            brr.get_var_int(); //drop witness item count

         while (brr.getSizeRemaining() > 0)
         {
            auto len = brr.get_var_int();
            if (len == 0)
            {
               resolvedScriptItems.push_back(BinaryDataRef());
               continue;
            }

            auto dataRef = brr.get_BinaryDataRef(len);

            if (dataRef.getSize() > 68 && 
               dataRef.getPtr()[0] == 0x30 &&
               dataRef.getPtr()[2] == 0x02)
            {
               //this is a sig, set an empty place holder instead
               resolvedScriptItems.push_back(BinaryDataRef());
               continue;
            }

            resolvedScriptItems.push_back(dataRef);
         }
      }
      catch (exception&) 
      {}

      return resolvedScriptItems;
   };

   auto serializeStack = [](
      const ScriptSpender& scriptSpender)->BinaryData
   {
      vector<shared_ptr<StackItem>> stack;
      for (auto& stack_item : scriptSpender.legacyStack_)
         stack.push_back(stack_item.second);

      return ScriptSpender::serializeScript(stack, true);
   };

   auto isStackMultiSig = [](
      const map<unsigned, shared_ptr<StackItem>>& stack)->bool
   {
      for (auto& stack_item : stack)
      {
         if (stack_item.second->type_ == StackItemType_MultiSig)
            return true;
      }

      return false;
   };

   auto compareScriptItems = [](
      const vector<BinaryDataRef>& ours, 
      const vector<BinaryDataRef>& theirs, 
      bool isMultiSig)->bool
   {
      if (ours == theirs)
         return true;

      if (theirs.size() == 0)
      {
         //if ours isn't empty, theirs cannot be empty (it needs the 
         //resolved data at least)
         return false;
      }

      if (isMultiSig)
      {
         //multisig script, tally 0s and compare
         vector<BinaryDataRef> oursStripped;
         unsigned ourZeroCount = 0;
         for (auto& ourItem : ours)
         {
            if (ourItem.empty())
               ++ourZeroCount;
            else
               oursStripped.push_back(ourItem);
         }

         vector<BinaryDataRef> theirsStripped;
         unsigned theirZeroCount = 0;
         for (auto& theirItem : theirs)
         {
            if (theirItem.empty())
               ++theirZeroCount;
            else
               theirsStripped.push_back(theirItem);
         }
            
         if (oursStripped == theirsStripped)
         {
            if (ourZeroCount > 1 && theirZeroCount >= 1)
               return true;
         }
      }

      return false;
   };

   //value checks
   if (value_ != rhs.value_ || utxo_ != rhs.utxo_)
      return false;
   
   //legacy status
   if (legacyStatus_ != rhs.legacyStatus_)
   {
      if (legacyStatus_ >= SpenderStatus_Resolved && 
         rhs.legacyStatus_ != SpenderStatus_Resolved)
      {
         /*
         This checks resolved state. Signed spenders are resolved.
         */
         return false;
      }
   }

   //legacy stack
   {
      //grab our resolved items from the script
      BinaryData ourSigScript;
      if (legacyStatus_ == SpenderStatus_Signed)
      {
         //signed spenders have a serialized sigScript and no stack items
         ourSigScript = inputScript_;
      }
      else
      {
         //everything else only has a stack
         ourSigScript = serializeStack(*this);
      }

      auto ourScriptItems = getResolvedItems(ourSigScript, false);

      //theirs cannot have a serialized script because theirs cannot be signed
      //grab the resolved data from the partial stack instead
      auto isMultiSig = isStackMultiSig(rhs.legacyStack_);
      auto theirSigScript = serializeStack(rhs);
      auto theirScriptItems = getResolvedItems(theirSigScript, false);

      //compare
      if (!compareScriptItems(ourScriptItems, theirScriptItems, isMultiSig))
         return false;
   }

   //segwit status
   if (segwitStatus_ != rhs.segwitStatus_)
   {
      if (segwitStatus_ >= SpenderStatus_Resolved &&
         rhs.segwitStatus_ != SpenderStatus_Resolved)
      {
         /*
         This checks resolved state. Signed spenders are resolved.
         */
         return false;
      }
   }

   //witness stack
   {
      //grab our resolved items from the witness data
      BinaryData ourWitnessData;
      if (segwitStatus_ == SpenderStatus_Signed)
      {
         //signed spenders have a serialized sigScript and no stack items
         ourWitnessData = witnessData_;
      }
      else
      {
         //everything else only has a stack
         ourWitnessData = serializeAvailableWitnessData();
      }

      auto ourScriptItems = getResolvedItems(ourWitnessData, true);

      //grab theirs
      auto isMultiSig = isStackMultiSig(rhs.witnessStack_);
      auto theirWitnessData = rhs.serializeAvailableWitnessData();
      auto theirScriptItems = getResolvedItems(theirWitnessData, true);

      //compare
      if (!compareScriptItems(ourScriptItems, theirScriptItems, isMultiSig))
         return false;
   }

   if (isP2SH_ != rhs.isP2SH_)
      return false;

   if (isCSV_ != rhs.isCSV_ || isCLTV_ != rhs.isCLTV_)
      return false;

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::isInitialized() const 
{
   if (legacyStatus_ == SpenderStatus_Unknown &&
      segwitStatus_ == SpenderStatus_Unknown &&
      isP2SH_ == false && 
      legacyStack_.empty() && witnessStack_.empty() &&
      inputScript_.empty() && witnessData_.empty())
   {
      return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::verifyEvalState(unsigned flags)
{
   /*
   check resolution state from public data is consistent with the serialized
   script
   */

   //uninitialized spender, nothing to check
   if (!isInitialized())
   {
      return true;
   }

   //sanity check: needs a utxo set to be resolved
   if (!utxo_.isInitialized())
   {
      return false;
   }

   ScriptSpender spenderVerify(utxo_);
   spenderVerify.sequence_ = sequence_;

   /*construct public resolver from the serialized script*/

   struct ResolverFeedLocal : public ResolverFeed
   {
      map<BinaryData, BinaryData> hashMap;

      BinaryData getByVal(const BinaryData& val) override
      {
         auto iter = hashMap.find(val);
         if (iter == hashMap.end())
            throw std::runtime_error("invalid value");

         return iter->second;
      }
      
      const SecureBinaryData& getPrivKeyForPubkey(const BinaryData&) override
      {
         throw std::runtime_error("invalid value");
      }
   };

   auto feed = make_shared<ResolverFeedLocal>();

   //look for push data in the sigScript
   auto&& legacyScript = getSerializedInputScript();

   try
   {
      auto pushDataVec = BtcUtils::splitPushOnlyScriptRefs(legacyScript);
      for (auto& pushData : pushDataVec)
      {
         //hash it and add to the feed's hash map
         auto hash = BtcUtils::getHash160(pushData);
         feed->hashMap.emplace(hash, pushData);
      }
   }
   catch (const runtime_error&)
   {
      //just exit the loop on deser error
   }
   
   //same with the witness data

   BinaryReader brSW;
   if (witnessData_.empty())
   {
      vector<shared_ptr<StackItem>> stack;
      for (auto& stack_item : witnessStack_)
         stack.push_back(stack_item.second);

      //serialize and get item count
      unsigned itemCount = 0;
      auto&& data = serializeWitnessData(stack, itemCount, true);

      //put stack item count
      BinaryWriter bw;
      bw.put_var_int(itemCount);

      //put serialized stack
      bw.put_BinaryData(data);

      brSW.setNewData(bw.getData());
   }
   else
   {
      brSW.setNewData(witnessData_);
   }

   try
   {
      auto itemCount = brSW.get_var_int();

      for (unsigned i=0; i<itemCount; i++)
      {
         //grab next data from the script as if it's push data
         auto len = brSW.get_var_int();
         auto val = brSW.get_BinaryDataRef(len);

         //hash it and add to the feed's hash map
         auto hash160 = BtcUtils::getHash160(val);
         feed->hashMap.emplace(hash160, val);

         //sha256 in case it's a p2wsh preimage
         auto hash256 = BtcUtils::getSha256(val);
         feed->hashMap.emplace(hash256, val);
      }

      if (brSW.getSizeRemaining() > 0)
      {
         //unparsed data remains in the witness data script, 
         //this shouldn't happen
         return false;
      }
   }
   catch (const runtime_error&)
   {
      //just exit the loop on deser error
   }

   //create resolver with mock feed and process it

   try
   {
      StackResolver resolver(getOutputScript(), feed, nullptr);
      resolver.setFlags(flags);
      spenderVerify.parseScripts(resolver);
   }
   catch (exception&)
   {}

   if (!compareEvalState(spenderVerify))
      return false;

   return true;
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::updateLegacyStack(
   const vector<shared_ptr<StackItem>>& stack, unsigned sigCount)
{
   if (legacyStatus_ == SpenderStatus_Signed)
      return;

   if (legacyStatus_ == SpenderStatus_Resolved && sigCount == 0)
      return;

   if (stack.size() != 0)
   {
      updateStack(legacyStack_, stack);

      if (sigCount > 0)
         legacyStatus_ = SpenderStatus_PartiallySigned;
   }
   else
   {
      legacyStatus_ = SpenderStatus_Empty;
   }
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::updateWitnessStack(
   const vector<shared_ptr<StackItem>>& stack, unsigned sigCount)
{
   if (segwitStatus_ == SpenderStatus_Signed)
      return;

   if (segwitStatus_ >= SpenderStatus_Resolved && sigCount == 0)
      return;

   updateStack(witnessStack_, stack);
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::parseScripts(StackResolver& resolver)
{
   //parse the utxo scripts, fill the relevant stacks

   auto resolvedStack = resolver.getResolvedStack();
   if (resolvedStack == nullptr)
      throw runtime_error("null resolved stack");

   flagP2SH(resolvedStack->isP2SH());
   updateLegacyStack(
      resolvedStack->getStack(), 
      resolvedStack->getSigCount());
   processStacks();

   auto resolvedStackWitness = resolvedStack->getWitnessStack();
   if (resolvedStackWitness == nullptr)
   {
      if (legacyStatus_ != SpenderStatus_Empty &&
         segwitStatus_ < SpenderStatus_Resolved)
      {
         segwitStatus_ = SpenderStatus_Empty; 
      }
      return;
   }

   updateWitnessStack(
      resolvedStackWitness->getStack(), 
      resolvedStackWitness->getSigCount());
   processStacks();
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::isSegWit() const
{
   switch (legacyStatus_)
   {
   case SpenderStatus_Empty:
      return true; //empty legacy input means sw

   case SpenderStatus_Resolved:
   {
      //resolved legacy status could mean nested sw
      if (segwitStatus_ >= SpenderStatus_Resolved)
         return true;
   }

   default:
      break;
   }
   
   return false;
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::injectSignature(SecureBinaryData& sig, unsigned sigId)
{
   //sanity checks
   if (!isResolved())
      throw runtime_error("cannot inject sig into unresolved spender");

   if (isSigned())
      throw runtime_error("spender is alreayd signed!");

   map<unsigned, shared_ptr<StackItem>>* stackPtr = nullptr;
   
   //grab the stack carrying the sig(s)
   if (isSegWit())
      stackPtr = &witnessStack_;
   else
      stackPtr = &legacyStack_;

   //find the stack sig object
   bool injected = false;
   for (auto& stackEntry : *stackPtr)
   {
      switch (stackEntry.second->type_)
      {
      case StackItemType_Sig:
      {
         if (stackEntry.second->isValid())
            throw runtime_error("stack sig entry already filled");

         auto newSigEntry = make_shared<StackItem_Sig>(
            stackEntry.second->getId(), move(sig));
         stackEntry.second = newSigEntry;
         injected = true;

         break;
      }

      case StackItemType_MultiSig:
      {
         if (sigId == UINT32_MAX)
            throw runtime_error("unset sig id");
         
         auto msEntryPtr = 
            dynamic_pointer_cast<StackItem_MultiSig>(stackEntry.second);
         if (msEntryPtr == nullptr)
            throw runtime_error("invalid ms stack entry");

         msEntryPtr->setSig(sigId, sig);
         injected = true;

         break;
      }

      default:
         break;
      }
   }

   if (!injected)
      throw runtime_error("failed to find sig entry in stack");

   processStacks();
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// Signer
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
Signer::Signer(const Codec_SignerState::SignerState& protoMsg) :
   TransactionStub()
{
   deserializeState(protoMsg);
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef Signer::getSerializedOutputScripts(void) const
{
   if (serializedOutputs_.getSize() == 0)
   {
      BinaryWriter bw;
      for (auto& recipient : recipients_)
      {
         auto&& serializedOutput = recipient->getSerializedScript();
         bw.put_BinaryData(serializedOutput);
      }

      serializedOutputs_ = move(bw.getData());
   }

   return serializedOutputs_.getRef();
}

////////////////////////////////////////////////////////////////////////////////
vector<TxInData> Signer::getTxInsData(void) const
{
   vector<TxInData> tidVec;

   for (auto& spender : spenders_)
   {
      TxInData tid;
      tid.outputHash_ = spender->getOutputHash();
      tid.outputIndex_ = spender->getOutputIndex();
      tid.sequence_ = spender->getSequence();

      tidVec.push_back(move(tid));
   }

   return tidVec;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::getSubScript(unsigned index) const
{
   auto spender = getSpender(index);
   return spender->getOutputScript();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef Signer::getWitnessData(unsigned index) const
{
   auto spender = getSpender(index);
   return spender->getWitnessData();
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::isInputSW(unsigned index) const
{
   auto spender = getSpender(index);
   return spender->isSegWit();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::serializeAllOutpoints(void) const
{
   BinaryWriter bw;
   for (auto& spender : spenders_)
   {
      bw.put_BinaryDataRef(spender->getOutpoint());
   }

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::serializeAllSequences(void) const
{
   BinaryWriter bw;
   for (auto& spender : spenders_)
   {
      bw.put_uint32_t(spender->getSequence());
   }

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef Signer::getOutpoint(unsigned index) const
{
   return spenders_[index]->getOutpoint();
}

////////////////////////////////////////////////////////////////////////////////
uint64_t Signer::getOutpointValue(unsigned index) const
{
   return spenders_[index]->getValue();
}

////////////////////////////////////////////////////////////////////////////////
unsigned Signer::getTxInSequence(unsigned index) const
{
   return spenders_[index]->getSequence();
}

////////////////////////////////////////////////////////////////////////////////
void Signer::sign(void)
{ 
   /***
   About the SegWit perma flagging:
   Armory SegWit support was implemented prior to the soft fork activation 
   (April 2016). At the time it was uncertain whether SegWit would be activated. 
   
   The chain was also getting hardforked to a ruleset specifically blocking 
   SegWit (Bcash).

   As a result, Armory had a responsibility to allow users to spend the 
   airdropped coins. Since Bcash does not support SegWit and such scripts are 
   otherwise anyone-can-spend, there had to be a toggle for this feature, 
   which applies to script resolution rules as well.

   Since SegWit is a done deal and Armory has no pretention to support Bcash, 
   SW can now be on by default, which reduces potential client side or unit 
   test snafus.
   ***/

   //perma flag for segwit verification
   flags_ |= SCRIPT_VERIFY_SEGWIT;

   /* sanity checks begin */

   {
      //sizes
      if (spenders_.size() == 0)
         throw runtime_error("tx has no spenders");

      if (recipients_.size() == 0)
         throw runtime_error("tx has no recipients");
   }

   {
      //spendVal
      uint64_t inputVal = 0;
      for (unsigned i=0; i < spenders_.size(); i++)
         inputVal += spenders_[i]->getValue();

      uint64_t spendVal = 0;
      for (unsigned i=0; i<recipients_.size(); i++)
         spendVal += recipients_[i]->getValue();

      if (inputVal < spendVal)
         throw runtime_error("invalid spendVal");
   }

   /* sanity checks end */

   //run through each spenders
   for (unsigned i = 0; i < spenders_.size(); i++)
   {
      auto& spender = spenders_[i];

      if (spender->isSigned())
         continue;

      if (!spender->hasUTXO())
         continue;

      if (!spender->hasFeed())
      {
         if (resolverPtr_ == nullptr)
            continue;

         spender->setFeed(resolverPtr_);
      }

      //resolve spender script
      auto proxy = make_shared<SignerProxyFromSigner>(this, i);
      
      StackResolver resolver(
         spender->getOutputScript(),
         spender->getFeed(),
         proxy);

      //check Script.h for signer flags
      resolver.setFlags(flags_);

      try
      {
         spender->parseScripts(resolver);
      }
      catch (...)
      {
         continue;
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
void Signer::resolveSpenders()
{
   //run through each spenders
   for (unsigned i = 0; i < spenders_.size(); i++)
   {
      auto& spender = spenders_[i];
      
      if (spender->isResolved())
         continue;
      
      if (!spender->hasUTXO())
         continue;

      auto publicResolver = make_shared<ResolverFeedPublic>(resolverPtr_.get());
      if (spender->hasFeed())
         publicResolver = make_shared<ResolverFeedPublic>(spender->getFeed().get());

      //resolve spender script
      StackResolver resolver(
         spender->getOutputScript(),
         publicResolver,
         nullptr);

      resolver.setFlags(flags_);

      try
      {
         spender->parseScripts(resolver);
      }
      catch (exception&)
      {
         //nothing to do here, just trying to evaluate signing status
         continue;
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData Signer::sign(
   BinaryDataRef script,
   const SecureBinaryData& privKey,
   shared_ptr<SigHashData> SHD, unsigned index)
{
   auto spender = spenders_[index];

   auto&& dataToHash = SHD->getDataForSigHash(
      spender->getSigHashType(), *this,
      script, index);
   
#ifdef SIGNER_DEBUG   
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privKey);
   LOGWARN << "signing for: ";
   LOGWARN << "   pubkey: " << pubkey.toHexStr();

   auto&& msghash = BtcUtils::getHash256(dataToHash);
   LOGWARN << "   message: " << dataToHash.toHexStr();
#endif

   SecureBinaryData dataSBD(dataToHash);
   auto&& sig = CryptoECDSA().SignData(dataSBD, privKey, false);


   return sig;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<ScriptSpender> Signer::getSpender(unsigned index) const
{
   if (index > spenders_.size())
      throw ScriptException("invalid spender index");

   return spenders_[index];
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef Signer::serializeSignedTx(void) const
{
   if (serializedSignedTx_.getSize() != 0)
      return serializedSignedTx_.getRef();

   BinaryWriter bw;

   //version
   bw.put_uint32_t(version_);

   bool isSW = isSegWit();
   if (isSW)
   {
      //marker and flag
      bw.put_uint8_t(0);
      bw.put_uint8_t(1);
   }

   //txin count
   if (spenders_.size() == 0)
      throw runtime_error("no spenders");
   bw.put_var_int(spenders_.size());

   //txins
   for (auto& spender : spenders_)
      bw.put_BinaryDataRef(spender->getSerializedInput(true));

   //txout count
   if (recipients_.size() == 0)
      throw runtime_error("no recipients");
   bw.put_var_int(recipients_.size());

   //txouts
   for (auto& recipient : recipients_)
      bw.put_BinaryDataRef(recipient->getSerializedScript());

   if (isSW)
   {
      //witness data
      for (auto& spender : spenders_)
      {
         BinaryDataRef witnessRef = spender->getWitnessData();
         
         //account for empty witness data
         if (witnessRef.getSize() == 0)
            bw.put_uint8_t(0);
         else
            bw.put_BinaryDataRef(witnessRef);
      }
   }

   //lock time
   bw.put_uint32_t(lockTime_);

   serializedSignedTx_ = move(bw.getData());

   return serializedSignedTx_.getRef();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef Signer::serializeUnsignedTx(bool loose)
{
   if (serializedUnsignedTx_.getSize() != 0)
      return serializedUnsignedTx_.getRef();

   resolveSpenders();

   BinaryWriter bw;

   //version
   bw.put_uint32_t(version_);

   bool isSW = isSegWit();
   if (isSW)
   {
      //marker and flag
      bw.put_uint8_t(0);
      bw.put_uint8_t(1);
   }

   //txin count
   if (spenders_.size() == 0)
   {
      if (!loose)
         throw runtime_error("no spenders");
   }

   bw.put_var_int(spenders_.size());

   //txins
   for (auto& spender : spenders_)
      bw.put_BinaryDataRef(spender->getSerializedInput(false));

   //txout count
   if (recipients_.size() == 0)
   {
      if (!loose)
         throw runtime_error("no recipients");
   }

   bw.put_var_int(recipients_.size());

   //txouts
   for (auto& recipient : recipients_)
      bw.put_BinaryDataRef(recipient->getSerializedScript());

   //no witness data for unsigned transactions
   for (auto& spender : spenders_)
      bw.put_uint8_t(0);

   //lock time
   bw.put_uint32_t(lockTime_);

   serializedUnsignedTx_ = move(bw.getData());

   return serializedUnsignedTx_.getRef();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::serializeAvailableResolvedData(void) const
{
   try
   {
      auto&& serTx = serializeSignedTx();
      return serTx;
   }
   catch (exception&)
   {}
   
   BinaryWriter bw;

   //version
   bw.put_uint32_t(version_);

   bool isSW = isSegWit();
   if (isSW)
   {
      //marker and flag
      bw.put_uint8_t(0);
      bw.put_uint8_t(1);
   }

   //txin count
   bw.put_var_int(spenders_.size());

   //txins
   for (auto& spender : spenders_)
      bw.put_BinaryDataRef(spender->serializeAvailableStack());

   //txout count
   bw.put_var_int(recipients_.size());

   //txouts
   for (auto& recipient : recipients_)
      bw.put_BinaryDataRef(recipient->getSerializedScript());

   if (isSW)
   {
      //witness data
      for (auto& spender : spenders_)
      {
         BinaryData witnessData = spender->serializeAvailableWitnessData();

         //account for empty witness data
         if (witnessData.getSize() == 0)
            bw.put_uint8_t(0);
         else
            bw.put_BinaryData(witnessData);
      }
   }

   //lock time
   bw.put_uint32_t(lockTime_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<SigHashData> Signer::getSigHashDataForSpender(bool sw) const
{
   shared_ptr<SigHashData> SHD;
   if (sw)
   {
      if (sigHashDataObject_ == nullptr)
         sigHashDataObject_ = make_shared<SigHashDataSegWit>();

      SHD = sigHashDataObject_;
   }
   else
   {
      SHD = make_shared<SigHashDataLegacy>();
   }

   return SHD;
}

////////////////////////////////////////////////////////////////////////////////
unique_ptr<TransactionVerifier> Signer::getVerifier(shared_ptr<BCTX> bctx,
   map<BinaryData, map<unsigned, UTXO>>& utxoMap)
{
   return move(make_unique<TransactionVerifier>(*bctx, utxoMap));
}

////////////////////////////////////////////////////////////////////////////////
TxEvalState Signer::verify(const BinaryData& rawTx,
   map<BinaryData, map<unsigned, UTXO>>& utxoMap, 
   unsigned flags, bool strict)
{
   auto bctx = BCTX::parse(rawTx);

   //setup verifier
   auto tsv = getVerifier(bctx, utxoMap);
   auto tsvFlags = tsv->getFlags();
   tsvFlags |= flags;
   tsv->setFlags(tsvFlags);

   return tsv->evaluateState(strict);
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::verify(void) 
{
   //serialize signed tx
   BinaryData txdata;
   try
   {
      txdata = move(serializeSignedTx());
   }
   catch(const exception&)
   {
      return false;
   }

   map<BinaryData, map<unsigned, UTXO>> utxoMap;

   //gather utxos and spender flags
   unsigned flags = 0;
   for (auto& spender : spenders_)
   {
      auto& indexMap = utxoMap[spender->getOutputHash()];
      indexMap[spender->getOutputIndex()] = spender->getUtxo();
      
      flags |= spender->getFlags();
   }

   auto evalState = verify(txdata, utxoMap, flags);
   return evalState.isValid();
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::verifyRawTx(const BinaryData& rawTx, 
   const map<BinaryData, map<unsigned, BinaryData>>& rawUTXOs)
{
   map<BinaryData, map<unsigned, UTXO>> utxoMap;

   //deser utxos
   for (auto& utxoPair : rawUTXOs)
   {
      map<unsigned, UTXO> idMap;
      for (auto& rawUtxoPair : utxoPair.second)
      {
         UTXO utxo;
         utxo.unserializeRaw(rawUtxoPair.second);
         idMap.insert(move(make_pair(rawUtxoPair.first, move(utxo))));
      }

      utxoMap.insert(move(make_pair(utxoPair.first, move(idMap))));
   }

   auto&& evalState = 
      verify(rawTx, utxoMap, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SEGWIT);

   return evalState.isValid();
}

////////////////////////////////////////////////////////////////////////////////
Codec_SignerState::SignerState Signer::serializeState() const
{
   Codec_SignerState::SignerState protoMsg;
   
   protoMsg.set_flags(flags_);
   protoMsg.set_tx_version(version_);
   protoMsg.set_locktime(lockTime_);

   for (auto& spender : spenders_)
   {
      auto spenderProto = protoMsg.add_spenders();
      spender->serializeState(*spenderProto);
   }

   for (auto& recipient : recipients_)
   {
      auto& data = recipient->getSerializedScript();
      protoMsg.add_recipients(data.getPtr(), data.getSize());
   }

   return protoMsg;
}

////////////////////////////////////////////////////////////////////////////////
Signer Signer::createFromState(const string& protoStr)
{
   Codec_SignerState::SignerState protoMsg;
   protoMsg.ParseFromString(protoStr);

   return createFromState(protoMsg);
}

////////////////////////////////////////////////////////////////////////////////
Signer Signer::createFromState(const Codec_SignerState::SignerState& protoMsg)
{
   Signer signer;
   signer.resetFlags();

   signer.version_ = protoMsg.tx_version();
   signer.lockTime_ = protoMsg.locktime();
   signer.flags_ = protoMsg.flags();

   for (unsigned i = 0; i < protoMsg.spenders_size(); i++)
   {

      auto spenderPtr = ScriptSpender::deserializeState(protoMsg.spenders(i));
      signer.spenders_.push_back(spenderPtr);
   }

   for (unsigned i = 0; i < protoMsg.recipients_size(); i++)
   {
      auto&& recipientData = BinaryDataRef::fromString(protoMsg.recipients(i));
      auto recipientPtr = ScriptRecipient::deserialize(recipientData);
      signer.recipients_.push_back(recipientPtr);
   }

   return signer;
}

////////////////////////////////////////////////////////////////////////////////
void Signer::deserializeState(
   const Codec_SignerState::SignerState& protoMsg)
{
   //deser into a new object
   auto&& new_signer = createFromState(protoMsg);

   version_ = new_signer.version_;
   lockTime_ = new_signer.lockTime_;
   flags_ |= new_signer.flags_;

   auto find_spender = [this](shared_ptr<ScriptSpender> obj)->
      shared_ptr<ScriptSpender>
   {
      for (auto spd : this->spenders_)
      {
         if (*spd == *obj)
            return spd;
      }

      return nullptr;
   };

   auto find_recipient = [this](shared_ptr<ScriptRecipient> obj)->
      shared_ptr<ScriptRecipient>
   {
      auto& scriptHash = obj->getSerializedScript();
      for (auto rec : this->recipients_)
      {
         if (scriptHash == rec->getSerializedScript())
            return rec;
      }

      return nullptr;
   };

   //Merge new signer with this. As a general rule, the added entries are all 
   //pushed back.

   //merge spender
   for (auto& spender : new_signer.spenders_)
   {
      auto local_spender = find_spender(spender);
      if (local_spender != nullptr)
      {
         local_spender->merge(*spender);
         if (!local_spender->verifyEvalState(flags_))
            throw SignerDeserializationError("merged spender has inconsistent state");
      }
      else
      {
         spenders_.push_back(spender);
         if (!spenders_.back()->verifyEvalState(flags_))
            throw SignerDeserializationError("unserialized spender has inconsistent state");
      }
   }


   /*Recipients are told apart by their script hash. Several recipients with
   the same script hash will be aggregated into a single one.

   Note that in case the local signer has several recipient with the same
   hash scripts, these won't be aggregated. Only those from the new_signer will.

   As a general rule, do not create several outputs with the same script hash.

   NOTE: adding recipients or triggering an aggregation will render prior signatures 
   invalid. This code does NOT check for that. It's the caller's responsibility 
   to check for this condition.

   As with spenders, new recipients are pushed back.
   */

   for (auto& recipient : new_signer.recipients_)
   {
      auto local_recipient = find_recipient(recipient);

      if (local_recipient == nullptr)
         recipients_.push_back(recipient);
      else
         local_recipient->setValue(
            local_recipient->getValue() + recipient->getValue());
   }
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::isResolved() const
{
   /*
   Returns true if all spenders carry all relevant public data referenced by 
   the utxo's script
   */
   for (auto& spender : spenders_)
   {
      if (!spender->isResolved())
         return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::isSigned() const
{
   /*
   Return true is all spenders carry enough signatures. Does not check sigs,
   use ::verify() to check those.
   */
   for (auto& spender : spenders_)
   {
      if (!spender->isSigned())
         return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
void Signer::resetFeeds(void)
{
   for (auto& spender : spenders_)
      spender->setFeed(nullptr);
}

////////////////////////////////////////////////////////////////////////////////
void Signer::populateUtxo(const UTXO& utxo)
{
   for (auto& spender : spenders_)
   {
      if (spender->hasUTXO())
      {
         auto& spender_utxo = spender->getUtxo();
         if (spender_utxo == utxo)
            return;
      }
      else
      {
         auto outpoint = spender->getOutpoint();
         BinaryRefReader brr(outpoint);
         
         auto&& hash = brr.get_BinaryDataRef(32);
         if (hash != utxo.getTxHash())
            continue;

         auto txoutid = brr.get_uint32_t();
         if (txoutid != utxo.getTxOutIndex())
            continue;

         spender->setUtxo(utxo);
         return;
      }
   }

   throw runtime_error("could not match utxo to any spender");
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::getTxId()
{
   try
   {
      auto txdataref = serializeSignedTx();
      Tx tx(txdataref);
      return tx.getThisHash();
   }
   catch (exception&)
   {}

   //tx isn't signed, let's check for SW inputs
   resolveSpenders();
   
   //serialize the tx
   BinaryWriter bw;

   //version
   bw.put_uint32_t(version_);
   
   //inputs
   bw.put_var_int(spenders_.size());
   for (auto spender : spenders_)
   {
      if (!spender->isSegWit() && !spender->isSigned())
         throw runtime_error("cannot get hash for unsigned legacy tx");

      bw.put_BinaryDataRef(spender->getSerializedInput(false));
   }

   //outputs
   bw.put_var_int(recipients_.size());
   for (auto recipient : recipients_)
      bw.put_BinaryDataRef(recipient->getSerializedScript());

   //locktime
   bw.put_uint32_t(lockTime_);

   //hash and return
   return BtcUtils::getHash256(bw.getDataRef());
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addSpender_ByOutpoint(
   const BinaryData& hash, unsigned index, unsigned sequence, uint64_t value)
{
   auto spender = make_shared<ScriptSpender>(hash, index, value);
   spender->setSequence(sequence);

   addSpender(spender);
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::verifySpenderEvalState() const
{
   /*
   Checks the integrity of spenders evaluation state. This is meant as a 
   sanity check for signers restored from a serialized state.
   */

   for (unsigned i = 0; i < spenders_.size(); i++)
   {
      auto& spender = spenders_[i];

      if (!spender->verifyEvalState(flags_))
         return false;
   }

   return true;
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::isSegWit() const
{
   for (auto& spender : spenders_)
   {
      if (spender->isSegWit())
         return true;
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::hasLegacyInputs() const
{
   for (auto& spender : spenders_)
   {
      if (!spender->isSegWit())
         return true;
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////
void Signer::injectSignature(
   unsigned inputIndex, SecureBinaryData& sig, unsigned sigId)
{
   if (spenders_.size() < inputIndex)
      throw runtime_error("invalid spender index");

   auto& spender = spenders_[inputIndex];
   spender->injectSignature(sig, sigId);
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// SignerProxy
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
SignerProxy::~SignerProxy(void)
{}

////////////////////////////////////////////////////////////////////////////////
void SignerProxyFromSigner::setLambda(
   Signer* signer, shared_ptr<ScriptSpender> spender, unsigned index,
   shared_ptr<ResolverFeed> feedPtr)
{
   auto signerLBD = [signer, spender, index, feedPtr]
      (BinaryDataRef script, const BinaryData& pubkey, bool sw)->SecureBinaryData
   {
      auto SHD = signer->getSigHashDataForSpender(sw);

      //get priv key for pubkey
      auto&& privKey = feedPtr->getPrivKeyForPubkey(pubkey);

      //sign
      auto&& sig = signer->sign(script, privKey, SHD, index);

      //convert to DER
#ifndef LIBBTC_ONLY
      auto&& derSig = BtcUtils::rsToDerSig(sig.getRef());

      //append sighash byte
      derSig.append(spender->getSigHashByte());
      return SecureBinaryData(derSig);
#else
      //append sighash byte
      SecureBinaryData sbd_hashbyte(1);
      *sbd_hashbyte.getPtr() = spender->getSigHashByte();
      sig.append(sbd_hashbyte);
      return sig;
#endif
   };

   signerLambda_ = signerLBD;
}
