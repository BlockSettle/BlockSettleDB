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

#include "BIP32_Node.h"
#include "Assets.h"

using namespace std;
using namespace ArmorySigner;

StackItem::~StackItem()
{}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// ScriptSpender
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
const UTXO& ScriptSpender::getUtxo() const
{
   if (!utxo_.isInitialized())
   {
      if (!haveSupportingTx())
         throw SpenderException("missing both utxo & supporting tx");
      
      utxo_.txHash_ = getOutputHash();
      utxo_.txOutIndex_ = getOutputIndex();

      const auto& supportingTx = getSupportingTx();
      auto opId = getOutputIndex();
      auto txOutCopy = supportingTx.getTxOutCopy(opId);
      utxo_.unserializeRaw(txOutCopy.serializeRef());
   }

   return utxo_;
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef ScriptSpender::getOutputScript() const
{
   const auto& utxo = getUtxo();
   return utxo.getScript();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef ScriptSpender::getOutputHash() const
{
   if (utxo_.isInitialized())
      return utxo_.getTxHash();

   if (outpoint_.getSize() != 36)
      throw SpenderException("missing utxo");

   BinaryRefReader brr(outpoint_);
   return brr.get_BinaryDataRef(32);
}

////////////////////////////////////////////////////////////////////////////////
unsigned ScriptSpender::getOutputIndex() const
{
   if (utxo_.isInitialized())
      return utxo_.getTxOutIndex();
   
   if (outpoint_.getSize() != 36)
      throw SpenderException("missing utxo");

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
            BtcUtils::getPushDataHeader(stackItem_sig->sig_));
         bwStack.put_BinaryData(stackItem_sig->sig_);
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

         bwStack.put_var_int(stackItem_sig->sig_.getSize());
         bwStack.put_BinaryData(stackItem_sig->sig_);
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
   if (!canBeResolved())
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
   if (!canBeResolved())
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
      throw SpenderException("missing outpoint");

   return outpoint_;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::getAvailableInputScript() const
{
   //if we have a serialized script already, return that
   if (!finalInputScript_.empty())
      return finalInputScript_;
      
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
      throw SpenderException("unresolved spender");
   }

   if (withSig)
   {
      if (!isSegWit())
      {
         if (legacyStatus_ != SpenderStatus_Signed)
            throw SpenderException("spender is missing sigs");        
      }
      else
      {
         if (legacyStatus_ != SpenderStatus_Empty && 
            legacyStatus_ != SpenderStatus_Resolved)
         {
            throw SpenderException("invalid legacy state for sw spender");                   
         }
      }
   }
   
   auto serializedScript = getAvailableInputScript();

   BinaryWriter bw;
   bw.put_BinaryData(getSerializedOutpoint());

   bw.put_var_int(serializedScript.getSize());
   bw.put_BinaryData(serializedScript);
   bw.put_uint32_t(sequence_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::serializeEmptyInput() const
{
   BinaryWriter bw;
   bw.put_BinaryData(getSerializedOutpoint());
   bw.put_uint8_t(0);
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
BinaryDataRef ScriptSpender::getFinalizedWitnessData(void) const
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

   return finalWitnessData_.getRef();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData ScriptSpender::serializeAvailableWitnessData(void) const
{
   try
   {
      return getFinalizedWitnessData();
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

   finalWitnessData_ = bw.getData();
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
      case StackItemType_PushData:
      {
         if (!iter_pair.first->second->isValid())
            iter_pair.first->second = stack_item;
         else if (stack_item->isValid())
            throw ScriptException("invalid push_data");            

         break;
      }

      case StackItemType_MultiSig:
      {
         auto stack_item_ms = 
            dynamic_pointer_cast<StackItem_MultiSig>(iter_pair.first->second);

         stack_item_ms->merge(stack_item.get());
         break;
      }

      case StackItemType_Sig:
      {
         auto stack_item_sig = 
            dynamic_pointer_cast<StackItem_Sig>(iter_pair.first->second);

         stack_item_sig->merge(stack_item.get());
         break;
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

               if (stack_item_ms->sigs_.size() > 0)
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
         { finalInputScript_ = move(serializeScript(stackVec)); }
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
   if (utxo_.isInitialized())
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
      outpoint->set_value(UINT64_MAX);
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
         finalInputScript_.getPtr(), finalInputScript_.getSize());
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
         finalWitnessData_.getPtr(), finalWitnessData_.getSize());
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
void ScriptSpender::serializePathData(
   Codec_SignerState::ScriptSpenderState& protoMsg) const
{
   for (auto bip32Path : bip32Paths_)
   {
      auto pathEntry = protoMsg.add_bip32paths();
      bip32Path.second.toProtobuf(*pathEntry);
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
   serializePathData(protoMsg);
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
         outpointHash, outpoint.txoutindex());
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
      resultPtr->finalInputScript_ = BinaryData::fromString(protoMsg.sig_script());
   }

   for (unsigned i=0; i<protoMsg.legacy_stack_size(); i++)
   {
      const auto& stackItem = protoMsg.legacy_stack(i);
      auto stackObjPtr = StackItem::deserialize(stackItem);
      resultPtr->legacyStack_.emplace(stackObjPtr->getId(), stackObjPtr);
   }

   if (protoMsg.has_witness_data())
   {
      resultPtr->finalWitnessData_ = BinaryData::fromString(protoMsg.witness_data());
   }

   for (unsigned i=0; i<protoMsg.witness_stack_size(); i++)
   {
      const auto& stackItem = protoMsg.witness_stack(i);
      auto stackObjPtr = StackItem::deserialize(stackItem);
      resultPtr->witnessStack_.emplace(stackObjPtr->getId(), stackObjPtr);
   }

   for (unsigned i=0; i<protoMsg.bip32paths_size(); i++)
   {
      auto pathObj = BIP32_AssetPath::fromProtobuf(protoMsg.bip32paths(i));
      resultPtr->bip32Paths_.emplace(pathObj.getPublicKey(), move(pathObj));
   }

   return resultPtr;
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::merge(const ScriptSpender& obj)
{
   if (isSigned())
      return;

   //do we have supporting data?
   {
      //sanity check on obj
      BinaryDataRef objOpHash;
      uint64_t objOpVal;
      try
      {
         objOpHash = obj.getOutputHash();
         objOpVal = obj.getValue();
      }
      catch (const exception&)
      {
         //obj has no supporting data, it doesn't carry anything to merge
         return;
      }

      try
      {
         if (getOutputHash() != objOpHash)
            throw runtime_error("spender output hash mismatch");

         if (getOutputIndex() != obj.getOutputIndex())
            throw runtime_error("spender output index mismatch");

         if (getValue() != objOpVal)
            throw runtime_error("spender output value mismatch");           
      }
      catch (const SpenderException&)
      {
         //missing supporting data, get it from obj
         if (obj.utxo_.isInitialized())
            utxo_ = obj.utxo_;
         else if (!obj.outpoint_.empty())
            outpoint_ = obj.outpoint_;
         else
            throw runtime_error("impossible condition, how did we get here??");
      }
   }

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
         //merge the stacks
         vector<shared_ptr<StackItem>> objStackVec;
         for (auto& stackItemPtr : obj.legacyStack_)
            objStackVec.emplace_back(stackItemPtr.second);

         updateStack(legacyStack_, objStackVec);
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
         finalInputScript_ = obj.finalInputScript_;
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
         //merge the stacks
         vector<shared_ptr<StackItem>> objStackVec;
         for (auto& stackItemPtr : obj.witnessStack_)
            objStackVec.emplace_back(stackItemPtr.second);

         updateStack(witnessStack_, objStackVec);
         processStacks();
         break;
      }      

      case SpenderStatus_Signed:
      {
         finalWitnessData_ = obj.finalWitnessData_;
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

   //check utxos
   {
      if (getOutputHash() != rhs.getOutputHash() ||
         getOutputIndex() != rhs.getOutputIndex() ||
         getValue() != getValue())
         return false;
   }
   
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
      BinaryData ourSigScript = getAvailableInputScript();
      auto ourScriptItems = getResolvedItems(ourSigScript, false);

      //theirs cannot have a serialized script because theirs cannot be signed
      //grab the resolved data from the partial stack instead
      auto isMultiSig = isStackMultiSig(rhs.legacyStack_);
      auto theirSigScript = rhs.getAvailableInputScript();
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
      BinaryData ourWitnessData = serializeAvailableWitnessData();
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
      finalInputScript_.empty() && finalWitnessData_.empty())
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
   if (!canBeResolved())
   {
      return false;
   }

   ScriptSpender spenderVerify;
   spenderVerify.sequence_ = sequence_;

   if (utxo_.isInitialized())
      spenderVerify.utxo_ = utxo_;
   else
      spenderVerify.outpoint_ = outpoint_;

   spenderVerify.txMap_ = txMap_;

   /*construct public resolver from the serialized script*/
   auto feed = make_shared<ResolverFeed_SpenderResolutionChecks>();

   //look for push data in the sigScript
   auto&& legacyScript = getAvailableInputScript();

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
   if (finalWitnessData_.empty())
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
      brSW.setNewData(finalWitnessData_);
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
      StackResolver resolver(getOutputScript(), feed);
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
   const vector<shared_ptr<StackItem>>& stack)
{
   if (legacyStatus_ >= SpenderStatus_Resolved)
      return;

   if (stack.size() != 0)
   {
      updateStack(legacyStack_, stack);
   }
   else
   {
      legacyStatus_ = SpenderStatus_Empty;
   }
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::updateWitnessStack(
   const vector<shared_ptr<StackItem>>& stack)
{
   if (segwitStatus_ >= SpenderStatus_Resolved)
      return;

   updateStack(witnessStack_, stack);
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::parseScripts(StackResolver& resolver)
{
   /*parse the utxo scripts, fill the relevant stacks*/

   auto resolvedStack = resolver.getResolvedStack();
   if (resolvedStack == nullptr)
      throw runtime_error("null resolved stack");

   flagP2SH(resolvedStack->isP2SH());

   //push the legacy resolved data into the local legacy stack
   updateLegacyStack(resolvedStack->getStack());
   
   //parse the legacy stack, will set the legacy status
   processStacks();

   //same with the witness stack
   auto resolvedStackWitness = resolvedStack->getWitnessStack();
   if (resolvedStackWitness == nullptr)
   {
      if (legacyStatus_ >= SpenderStatus_Resolved &&
         segwitStatus_ < SpenderStatus_Resolved)
      {
         //this is a pure legacy redeem script
         segwitStatus_ = SpenderStatus_Empty; 
      }
   }
   else
   {
      updateWitnessStack(resolvedStackWitness->getStack());
      processStacks();
   }

   //resolve pubkeys
   auto feed = resolver.getFeed();
   if (feed == nullptr)
      return;

   auto pubKeys = getRelevantPubkeys();
   for (auto& pubKeyPair : pubKeys)
   {
      try
      {
         auto bip32path = feed->resolveBip32PathForPubkey(pubKeyPair.second);
         if (!bip32path.isValid())
            continue;

         bip32Paths_.emplace(pubKeyPair.second, bip32path);
      }
      catch (const exception&)
      {
         continue;
      }
   }  
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::sign(shared_ptr<SignerProxy> proxy)
{
   auto signStack = [proxy](
      map<unsigned, shared_ptr<StackItem>>& stackMap, bool isSW)->void
   {
      for (auto& stackEntryPair : stackMap)
      {
         auto stackItem = stackEntryPair.second;
         switch (stackItem->type_)
         {
         case StackItemType_Sig:
         {
            if (stackItem->isValid())
               throw SpenderException("stack sig entry already filled");

            auto sigItem =  dynamic_pointer_cast<StackItem_Sig>(stackItem);
            if (sigItem == nullptr)
               throw runtime_error("unexpected stack item type");

            sigItem->sig_ = 
               move(proxy->sign(sigItem->script_, sigItem->pubkey_, isSW));
            break;
         }

         case StackItemType_MultiSig:
         {
            auto msEntryPtr = 
               dynamic_pointer_cast<StackItem_MultiSig>(stackItem);
            if (msEntryPtr == nullptr)
               throw SpenderException("invalid ms stack entry");

            for (unsigned i=0; i < msEntryPtr->pubkeyVec_.size(); i++)
            {
               if (msEntryPtr->sigs_.find(i) != msEntryPtr->sigs_.end())
                  continue;
               
               const auto& pubkey = msEntryPtr->pubkeyVec_[i];
               try
               {
                  auto&& sig = proxy->sign(msEntryPtr->script_, pubkey, isSW);
                  msEntryPtr->sigs_.emplace(i, move(sig));
                  if (msEntryPtr->sigs_.size() >= msEntryPtr->m_)
                     break;
               }
               catch (runtime_error&)
               {
                  //feed is missing private key, nothing to do
               }
            }

            break;
         }

         default:
            break;
         }
      }
   };

   try
   {
      
      signStack(legacyStack_, false);
      signStack(witnessStack_, true);

      processStacks();
   }
   catch (const exception&)
   {}
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
      throw runtime_error("spender is already signed!");

   map<unsigned, shared_ptr<StackItem>>* stackPtr = nullptr;
   
   //grab the stack carrying the sig(s)
   if (isSegWit())
      stackPtr = &witnessStack_;
   else
      stackPtr = &legacyStack_;

   //find the stack sig object
   bool injected = false;
   for (auto& stackItemPair : *stackPtr)
   {
      auto& stackItem = stackItemPair.second;
      switch (stackItem->type_)
      {
      case StackItemType_Sig:
      {
         if (stackItem->isValid())
            throw SpenderException("stack sig entry already filled");

         auto stackItemSig = dynamic_pointer_cast<StackItem_Sig>(stackItem);
         if (stackItemSig == nullptr)
            throw SpenderException("unexpected stack item type");

         stackItemSig->injectSig(sig);
         injected = true;

         break;
      }

      case StackItemType_MultiSig:
      {
         if (sigId == UINT32_MAX)
            throw SpenderException("unset sig id");
         
         auto msEntryPtr = 
            dynamic_pointer_cast<StackItem_MultiSig>(stackItem);
         if (msEntryPtr == nullptr)
            throw SpenderException("invalid ms stack entry");

         msEntryPtr->setSig(sigId, sig);
         injected = true;

         break;
      }

      default:
         break;
      }
   }

   if (!injected)
      throw SpenderException("failed to find sig entry in stack");

   processStacks();
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef ScriptSpender::getRedeemScriptFromStack(
   const map<unsigned, shared_ptr<StackItem>>* stackPtr) const
{
   if (stackPtr == nullptr)   
      return BinaryDataRef();

   shared_ptr<StackItem> firstPushData;
   
   //look for redeem script from sig stack items
   for (auto stackPair : *stackPtr)
   {
      auto stackItem = stackPair.second;
      switch (stackItem->type_)
      {
      case StackItemType_PushData:
      {
         //grab first push data entry in stack
         if (firstPushData == nullptr)
            firstPushData = stackItem;
         break;
      }

      case StackItemType_Sig:
      {
         auto sig = dynamic_pointer_cast<StackItem_Sig>(stackItem);
         if (sig == nullptr)
            break;

         return sig->script_.getRef();
      }

      case StackItemType_MultiSig:
      {
         auto msig = dynamic_pointer_cast<StackItem_MultiSig>(stackItem);
         if (msig == nullptr)
            break;

         return msig->script_.getRef();
      }

      default:
         break;
      }
   }

   //if we couldn't find sig entries, let's try the first push data entry
   if (firstPushData == nullptr || !firstPushData->isValid())
      return BinaryDataRef();

   auto pushdata = dynamic_pointer_cast<StackItem_PushData>(firstPushData);
   if (pushdata == nullptr)
      return BinaryDataRef();

   return pushdata->data_;
}

////////////////////////////////////////////////////////////////////////////////
map<BinaryData, BinaryData> ScriptSpender::getPartialSigs() const
{
   const map<unsigned, shared_ptr<StackItem>>* stackPtr = nullptr;
   if (!isSegWit())
      stackPtr = &legacyStack_;
   else
      stackPtr = &witnessStack_;

   //look for multsig stack entry
   shared_ptr<StackItem_MultiSig> stackItemMultisig = nullptr;
   for (const auto& stackObj : *stackPtr)
   {
      auto stackItem = stackObj.second;
      if (stackItem->type_ == StackItemType_MultiSig)
      {
         stackItemMultisig = 
            dynamic_pointer_cast<StackItem_MultiSig>(stackItem);
         break;
      }
   }

   if (stackItemMultisig == nullptr)
      return {};

   map<BinaryData, BinaryData> sigMap;
   for (const auto& sigPair : stackItemMultisig->sigs_)
   {
      if (sigPair.first > stackItemMultisig->pubkeyVec_.size())
      {
         LOGWARN << "sig index out of bounds";
         break;
      }

      const auto& pubkey = stackItemMultisig->pubkeyVec_[sigPair.first];
      sigMap.emplace(pubkey, sigPair.second);
   }

   return sigMap;
}

////////////////////////////////////////////////////////////////////////////////
map<unsigned, BinaryData> ScriptSpender::getRelevantPubkeys() const
{
   if (!isResolved())
      return {};

   if (isSigned())
   {
      /*spender is signed, redeem script is finalized*/
      throw runtime_error("need implemented");
   }
   else
   {
      auto stack = &legacyStack_;
      if (isSegWit())
         stack = &witnessStack_;

      for (auto& stackEntryPair : *stack)
      {
         const auto& stackItem = stackEntryPair.second;
         switch (stackItem->type_)
         {
         case StackItemType_Sig:
         {
            auto sig = dynamic_pointer_cast<StackItem_Sig>(stackItem);
            if (stackItem == nullptr)
               break;

            map<unsigned, BinaryData> pubkeyMap;
            pubkeyMap.emplace(0, sig->pubkey_);
            return pubkeyMap;
         }

         case StackItemType_MultiSig:
         {
            auto msig = dynamic_pointer_cast<StackItem_MultiSig>(stackItem);
            if (stackItem == nullptr)
               break;

            map<unsigned, BinaryData> pubkeyMap;
            for (unsigned i=0; i<msig->pubkeyVec_.size(); i++)
            {
               auto& pubkey = msig->pubkeyVec_[i];
               pubkeyMap.emplace(i, pubkey);
            }
            return pubkeyMap;
         }

         default:
            break;
         }
      }
   }

   return {};
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::toPSBT(BinaryWriter& bw) const
{
   //supporting tx or utxo
   bool hasSupportingOutput = false;
   if (haveSupportingTx())
   {
      //key length
      bw.put_uint8_t(1);
      
      //supporting tx key
      bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_NON_WITNESS_UTXO);

      //tx
      const auto& supportingTx = getSupportingTx();
      bw.put_var_int(supportingTx.getSize());
      bw.put_BinaryData(supportingTx.getPtr(), supportingTx.getSize());
      
      hasSupportingOutput = true;
   }
   else if (isSegWit() && utxo_.isInitialized())
   {
      //utxo
      bw.put_uint8_t(1);
      bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_WITNESS_UTXO);

      auto rawUtxo = utxo_.serializeTxOut();
      bw.put_var_int(rawUtxo.getSize());
      bw.put_BinaryData(rawUtxo);

      hasSupportingOutput = true;
   }

   //partial sigs
   {
      /*
      This section only applies to MS or exotic scripts that can be 
      partially signed. Single sig scripts go to the finalized
      section right away.
      */

      auto partialSigs = getPartialSigs();
      for (auto& sigPair : partialSigs)
      {
         bw.put_var_int(sigPair.first.getSize() + 1);
         bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_PARTIAL_SIG);
         bw.put_BinaryData(sigPair.first);

         bw.put_var_int(sigPair.second.getSize());
         bw.put_BinaryData(sigPair.second);
      }
   }

   //sig hash, conditional on utxo/prevTx presence
   if (hasSupportingOutput && !isSigned())
   {
      bw.put_uint8_t(1);
      bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_SIGHASH_TYPE);

      bw.put_uint8_t(4);
      bw.put_uint32_t((uint32_t)sigHashType_);
   }

   //redeem script
   if (!isSigned())
   {
      auto redeemScript = getRedeemScriptFromStack(&legacyStack_);
      if (!redeemScript.empty())
      {
         bw.put_uint8_t(1);
         bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_REDEEM_SCRIPT);
         
         bw.put_var_int(redeemScript.getSize());
         bw.put_BinaryDataRef(redeemScript);
      }
   }

   //witness script
   if (isSegWit())
   {
      auto witnessScript = getRedeemScriptFromStack(&witnessStack_);
      if (!witnessScript.empty())
      {
         bw.put_uint8_t(1);
         bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_WITNESS_SCRIPT);
         
         bw.put_var_int(witnessScript.getSize());
         bw.put_BinaryDataRef(witnessScript);
      }
   }

   if (!isSigned())
   {
      //pubkeys
      for (auto& bip32Path : bip32Paths_)
      {
         if (!bip32Path.second.isValid())
            continue;

         bw.put_uint8_t(34);
         bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_BIP32_DERIVATION);
         bw.put_BinaryData(bip32Path.first);

         //path
         bip32Path.second.toPSBT(bw);
      }
   }
   else
   {
      //scriptSig
      auto finalizedInputScript = getAvailableInputScript();
      if (!finalizedInputScript.empty())
      {
         bw.put_uint8_t(1);
         bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_FINAL_SCRIPTSIG);

         bw.put_var_int(finalizedInputScript.getSize());
         bw.put_BinaryData(finalizedInputScript);
      }

      auto finalizedWitnessData = getFinalizedWitnessData();
      if (!finalizedWitnessData.empty())
      {
         bw.put_uint8_t(1);
         bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_FINAL_SCRIPTWITNESS);

         bw.put_var_int(finalizedWitnessData.getSize());
         bw.put_BinaryData(finalizedWitnessData);
      }
   }

   //proprietary data
   for (auto& data : prioprietaryPSBTData_)
   {
      //key
      bw.put_var_int(data.first.getSize() + 1);
      bw.put_uint8_t(PSBT::ENUM_INPUT::PSBT_IN_PROPRIETARY);
      bw.put_BinaryData(data.first);

      //val
      bw.put_var_int(data.second.getSize());
      bw.put_BinaryData(data.second);
   }

   //terminate
   bw.put_uint8_t(0);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<ScriptSpender> ScriptSpender::fromPSBT(
   BinaryRefReader& brr, 
   const TxIn& txin, 
   shared_ptr<map<BinaryData, Tx>> txMap)
{
   UTXO utxo;
   bool haveSupportingTx = false;

   map<BinaryDataRef, BinaryDataRef> partialSigs;
   map<BinaryData, BIP32_AssetPath> bip32paths;
   map<BinaryData, BinaryData> prioprietaryPSBTData;
         
   BinaryDataRef redeemScript;
   BinaryDataRef witnessScript;
   BinaryDataRef finalRedeemScript;
   BinaryDataRef finalWitnessScript;

   uint32_t sigHash = (uint32_t)SIGHASH_ALL;

   auto inputDataPairs = BtcUtils::getPSBTDataPairs(brr);
   for (const auto& dataPair : inputDataPairs)
   {
      const auto& key = dataPair.first;
      const auto& val = dataPair.second;

      //key type
      auto typePtr = key.getPtr();
      switch (*typePtr)
      {
      case PSBT::ENUM_INPUT::PSBT_IN_NON_WITNESS_UTXO:
      {
         if (txMap == nullptr)
            throw PSBTDeserializationError("null txmap");

         //supporting tx, key has to be 1 byte long
         if (key.getSize() != 1)
            throw PSBTDeserializationError("unvalid supporting tx key len");

         Tx tx(val);
         txMap->emplace(tx.getThisHash(), move(tx));
         haveSupportingTx = true;
         break;
      }
         
      case PSBT::ENUM_INPUT::PSBT_IN_WITNESS_UTXO:
      {
         //utxo, key has to be 1 byte long
         if (key.getSize() != 1)
            throw PSBTDeserializationError("unvalid utxo key len");

         utxo.unserializeRaw(val);
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_PARTIAL_SIG:
      {
         partialSigs.emplace(key.getSliceRef(1, key.getSize() - 1), val);
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_SIGHASH_TYPE:
      {
         if (key.getSize() != 1)
            throw PSBTDeserializationError("unvalid sighash key len");
            
         if (val.getSize() != 4)
            throw PSBTDeserializationError("invalid sighash val length");

         sigHash = *(uint32_t*)val.getPtr();
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_REDEEM_SCRIPT:
      {
         if (key.getSize() != 1)
            throw PSBTDeserializationError("unvalid redeem script key len");
            
         redeemScript = val;
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_WITNESS_SCRIPT:
      {
         if (key.getSize() != 1)
            throw PSBTDeserializationError("unvalid witness script key len");

         witnessScript = val;
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_BIP32_DERIVATION:
      {
         auto assetPath = BIP32_AssetPath::fromPSBT(key, val);
         auto insertIter = bip32paths.emplace(
            assetPath.getPublicKey(), assetPath);

         if (!insertIter.second)
            throw PSBTDeserializationError("bip32 path collision");
         
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_FINAL_SCRIPTSIG:
      {
         if (key.getSize() != 1)
            throw PSBTDeserializationError("unvalid finalized input script key len");

         finalRedeemScript = val;  
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_FINAL_SCRIPTWITNESS:
      {
         if (key.getSize() != 1)
            throw PSBTDeserializationError("unvalid finalized witness script key len");

         finalWitnessScript = val;  
         break;
      }

      case PSBT::ENUM_INPUT::PSBT_IN_PROPRIETARY:
      {
         //proprietary data doesn't have to be interpreted but
         //it needs carried over
         prioprietaryPSBTData.emplace(
            key.getSliceRef(1, key.getSize() - 1), val);
         break;
      }

      default:
         throw PSBTDeserializationError("unexpected txin key");
      }
   }

   //create spender
   shared_ptr<ScriptSpender> spender;
   auto outpoint = txin.getOutPoint();

   if (!haveSupportingTx && utxo.isInitialized())
   {
      utxo.txHash_ = outpoint.getTxHash();
      utxo.txOutIndex_ = outpoint.getTxOutIndex();
      spender = make_shared<ScriptSpender>(utxo);
   }
   else
   {
      spender = make_shared<ScriptSpender>(
         outpoint.getTxHash(), outpoint.getTxOutIndex());
   }

   spender->setTxMap(txMap);
   auto feed = make_shared<ResolverFeed_SpenderResolutionChecks>();

   bool isSigned = false;
   if (!finalRedeemScript.empty())
   {
      spender->finalInputScript_ = finalRedeemScript;
      spender->legacyStatus_ = SpenderStatus_Signed;
      spender->segwitStatus_ = SpenderStatus_Empty;
      isSigned = true;
   }
   
   if (!finalWitnessScript.empty())
   {
      spender->finalWitnessData_ = finalWitnessScript;
      spender->segwitStatus_ = SpenderStatus_Signed;
      if (isSigned)
         spender->legacyStatus_ = SpenderStatus_Resolved;
      else
         spender->legacyStatus_ = SpenderStatus_Empty;
      isSigned = true;
   }

   if (!isSigned)
   {
      //redeem scripts
      if (!redeemScript.empty())
      {
         //add to custom feed
         auto hash = BtcUtils::getHash160(redeemScript);
         feed->hashMap.emplace(hash, redeemScript);
      }

      if (!witnessScript.empty())
      {
         //add to custom feed
         auto hash = BtcUtils::getHash160(witnessScript);
         feed->hashMap.emplace(hash, witnessScript);

         hash = BtcUtils::getSha256(witnessScript);
         feed->hashMap.emplace(hash, witnessScript);
      }

      //resolve
      try
      {
         StackResolver resolver(spender->getOutputScript(), feed);
         resolver.setFlags(         
            SCRIPT_VERIFY_P2SH | 
            SCRIPT_VERIFY_SEGWIT | 
            SCRIPT_VERIFY_P2SH_SHA256);

         spender->parseScripts(resolver);
      }
      catch (const exception&)
      {}

      //get pubkeys
      auto pubkeys = spender->getRelevantPubkeys();

      //check pubkeys are relevant
      {
         set<BinaryDataRef> pubkeyRefs;
         for (auto& pubkey : pubkeys)
            pubkeyRefs.emplace(pubkey.second.getRef());

         for (auto& bip32path : bip32paths)
         {
            auto iter = pubkeyRefs.find(bip32path.first);
            if (iter == pubkeyRefs.end())
            {
               throw PSBTDeserializationError(
                  "have bip32path for unrelated pubkey");
            }

            spender->bip32Paths_.emplace(bip32path);
         }
      }

      //inject partial sigs
      if (!partialSigs.empty())
      {
         for (auto& pubkey : pubkeys)
         {
            auto iter = partialSigs.find(pubkey.second);
            if (iter == partialSigs.end())
               continue;

            SecureBinaryData sig(iter->second);
            spender->injectSignature(sig, pubkey.first);
            partialSigs.erase(iter);
         }

         if (!partialSigs.empty())
            throw PSBTDeserializationError("couldn't inject sigs");
      }

      spender->setSigHashType((SIGHASH_TYPE)sigHash);
   }

   spender->prioprietaryPSBTData_ = move(prioprietaryPSBTData);

   return spender;
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::setTxMap(shared_ptr<map<BinaryData, Tx>> txMap)
{
   txMap_ = txMap;
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::setSupportingTx(BinaryDataRef rawTx)
{
   if (rawTx.empty())
      return false;

   try
   {
      Tx tx(rawTx);
      return setSupportingTx(move(tx));
   }
   catch (const exception&)
   {}

   return false;
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::setSupportingTx(Tx supportingTx)
{
   /*
   Returns true if the supporting tx is relevant to this spender, false 
   otherwise
   */
   if (supportingTx.getThisHash() != getOutputHash())
      return false;

   auto insertIter = txMap_->emplace(
      supportingTx.getThisHash(), move(supportingTx));
   
   return insertIter.second;
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::haveSupportingTx() const
{
   if (txMap_ == nullptr)
      return false;

   try
   {        
      auto hash = getOutputHash();
      auto iter = txMap_->find(hash);
      return (iter != txMap_->end());
   }
   catch (const exception&)
   {}

   return false;
}

////////////////////////////////////////////////////////////////////////////////
const Tx& ScriptSpender::getSupportingTx() const
{
   if (txMap_ == nullptr)
      throw SpenderException("missing tx map");;

   auto hash = getOutputHash();
   auto iter = txMap_->find(hash);
   if (iter == txMap_->end())
      throw SpenderException("missing supporting tx");

   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
bool ScriptSpender::canBeResolved() const
{
   if (utxo_.isInitialized())
      return true;

   if (outpoint_.getSize() != 36)
      return false;

   return haveSupportingTx();
}

////////////////////////////////////////////////////////////////////////////////
uint64_t ScriptSpender::getValue() const
{
   if (utxo_.isInitialized())
      return utxo_.getValue();

   if (!haveSupportingTx())
      throw SpenderException("missing both supporting tx and utxo");

   auto index = getOutputIndex();
   const auto& supportingTx = getSupportingTx();
   auto txOutCopy = supportingTx.getTxOutCopy(index);

   return txOutCopy.getValue();
}

////////////////////////////////////////////////////////////////////////////////
void ScriptSpender::seedResolver(shared_ptr<ResolverFeed> ptr) const
{
   for (auto& bip32Path : bip32Paths_)
      ptr->setBip32PathForPubkey(bip32Path.first, bip32Path.second);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// Signer
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
Signer::Signer(const Codec_SignerState::SignerState& protoMsg) :
   TransactionStub()
{
   supportingTxMap_ = std::make_shared<std::map<BinaryData, Tx>>();
   deserializeState(protoMsg);
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef Signer::getSerializedOutputScripts(void) const
{
   if (serializedOutputs_.empty())
   {
      BinaryWriter bw;
      for (auto& recipient : getRecipientVector())
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
   return spender->getFinalizedWitnessData();
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
   if (index >= spenders_.size())  
      throw runtime_error("invalid spender index");
   return spenders_[index]->getOutpoint();
}

////////////////////////////////////////////////////////////////////////////////
uint64_t Signer::getOutpointValue(unsigned index) const
{
   if (index >= spenders_.size())  
      throw runtime_error("invalid spender index");
   return spenders_[index]->getValue();
}

////////////////////////////////////////////////////////////////////////////////
unsigned Signer::getTxInSequence(unsigned index) const
{
   if (index >= spenders_.size())  
      throw runtime_error("invalid spender index");
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

   //sizes
   if (spenders_.size() == 0)
      throw runtime_error("tx has no spenders");

   auto recVector = getRecipientVector();
   if (recVector.size() == 0)
      throw runtime_error("tx has no recipients");

   /*
   Try to check input value vs output value. We're not guaranteed to 
   have this information, since we may be partially signing this 
   transaction. In that case, skip this step
   */
   try
   {
      uint64_t inputVal = 0;
      for (unsigned i=0; i < spenders_.size(); i++)
         inputVal += spenders_[i]->getValue();

      uint64_t spendVal = 0;
      for (auto& recipient : recVector)
         spendVal += recipient->getValue();

      if (inputVal < spendVal)
         throw runtime_error("invalid spendVal");
   }
   catch (const SpenderException&)
   {
      //missing input value data, skip the spendVal check
   }

   /* sanity checks end */

   //resolve
   resolvePublicData();

   //sign sig stack entries in each spender
   for (unsigned i=0; i < spenders_.size(); i++)
   {
      auto& spender = spenders_[i];
      if (!spender->isResolved() || spender->isSigned())
         continue;
      
      spender->seedResolver(resolverPtr_);
      auto proxy = make_shared<SignerProxyFromSigner>(this, i, resolverPtr_);
      spender->sign(proxy);
   }
}

////////////////////////////////////////////////////////////////////////////////
void Signer::resolvePublicData()
{
   //run through each spenders
   for (auto& spender : spenders_)
   {
      if (isResolved())
         continue;

      if (!spender->canBeResolved())
         continue;

      //resolve spender script    
      StackResolver resolver(
         spender->getOutputScript(),
         resolverPtr_);

      //check Script.h for signer flags
      resolver.setFlags(flags_);

      try
      {
         spender->parseScripts(resolver);
      }
      catch (const exception&)
      {}

      auto spenderBip32Paths = spender->getBip32Paths();
      for (const auto& pathPair : spenderBip32Paths)
      {
         const auto& assetPath = pathPair.second;
         if (assetPath.hasRoot())
            addBip32Root(assetPath.getRoot());
      }
   }

   if (resolverPtr_ == nullptr)
      return;

   for (auto& recipient : getRecipientVector())
   {
      const auto& serializedOutput = recipient->getSerializedScript();
      BinaryRefReader brr(serializedOutput);
      brr.advance(8);
      auto len = brr.get_var_int();
      auto scriptRef = brr.get_BinaryDataRef(len);

      auto pubKeys = Signer::getPubkeysForScript(scriptRef, resolverPtr_);
      for (const auto& pubKeyPair : pubKeys)
      {
         try
         {
            auto bip32path = 
               resolverPtr_->resolveBip32PathForPubkey(pubKeyPair.second);
            if (!bip32path.isValid())
               continue;

            recipient->addBip32Path(bip32path);
         }
         catch (const exception&)
         {
            continue;
         }
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData Signer::signScript(
   BinaryDataRef script,
   const SecureBinaryData& privKey,
   shared_ptr<SigHashData> SHD, unsigned index)
{
   auto spender = spenders_[index];

   auto hashToSign = SHD->getDataForSigHash(
      spender->getSigHashType(), *this,
      script, index);
   
#ifdef SIGNER_DEBUG   
   auto&& pubkey = CryptoECDSA().ComputePublicKey(privKey);
   LOGWARN << "signing for: ";
   LOGWARN << "   pubkey: " << pubkey.toHexStr();

   auto&& msghash = BtcUtils::getHash256(dataToHash);
   LOGWARN << "   message: " << dataToHash.toHexStr();
#endif

   return CryptoECDSA().SignData(hashToSign, privKey, false);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<ScriptSpender> Signer::getSpender(unsigned index) const
{
   if (index > spenders_.size())
      throw ScriptException("invalid spender index");

   return spenders_[index];
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<ScriptRecipient> Signer::getRecipient(unsigned index) const
{
   auto recVector = getRecipientVector();
   if (index > recVector.size())
      throw ScriptException("invalid spender index");

   return recVector[index];
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
      bw.put_BinaryData(spender->getSerializedInput(true));

   //txout count
   auto recVector = getRecipientVector();
   if (recVector.size() == 0)
      throw runtime_error("no recipients");
   bw.put_var_int(recVector.size());

   //txouts
   for (auto& recipient : recVector)
      bw.put_BinaryData(recipient->getSerializedScript());

   if (isSW)
   {
      //witness data
      for (auto& spender : spenders_)
      {
         BinaryDataRef witnessRef = spender->getFinalizedWitnessData();
         
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

   resolvePublicData();

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
      bw.put_BinaryData(spender->getSerializedInput(false));

   //txout count
   auto recVector = getRecipientVector();
   if (recVector.size() == 0)
   {
      if (!loose)
         throw runtime_error("no recipients");
   }

   bw.put_var_int(recVector.size());

   //txouts
   for (auto& recipient : recVector)
      bw.put_BinaryData(recipient->getSerializedScript());

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
      bw.put_BinaryData(spender->serializeAvailableStack());

   //txout count
   auto recVector = getRecipientVector();
   bw.put_var_int(recVector.size());

   //txouts
   for (auto& recipient : recVector)
      bw.put_BinaryData(recipient->getSerializedScript());

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
TxEvalState Signer::evaluateSignedState(void) const
{
   auto&& txdata = serializeAvailableResolvedData();

   std::map<BinaryData, std::map<unsigned, UTXO>> utxoMap;
   unsigned flags = 0;
   for (auto& spender : spenders_)
   {
      auto& indexMap = utxoMap[spender->getOutputHash()];
      indexMap[spender->getOutputIndex()] = spender->getUtxo();

      flags |= spender->getFlags();
   }

   return verify(txdata, utxoMap, flags, true);
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::verify(void) const
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

   for (auto& group : recipients_)
   {
      for (auto& recipient : group.second)
      {
         auto recMsgPtr = protoMsg.add_recipients();
         recipient->toProtobuf(*recMsgPtr, group.first);
      }
   }

   if (supportingTxMap_ != nullptr)
   {
      for (auto& supportingTx : *supportingTxMap_)
      {
         protoMsg.add_supportingtx(
            supportingTx.second.getPtr(), supportingTx.second.getSize());
      }
   }

   for (auto& bip32PublicRoot : bip32PublicRoots_)
   {
      auto& rootPtr = bip32PublicRoot.second;
      auto pubRoot = protoMsg.add_bip32roots();
      
      pubRoot->set_xpub(rootPtr->getXPub());
      pubRoot->set_fingerprint(rootPtr->getSeedFingerprint());
      
      for (auto& step : rootPtr->getPath())
         pubRoot->add_path(step);
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
void Signer::deserializeSupportingTxMap(
   const Codec_SignerState::SignerState& protoMsg)
{
   for (unsigned i = 0; i < protoMsg.supportingtx_size(); i++)
   {
      BinaryDataRef rawTxRef;
      rawTxRef.setRef(protoMsg.supportingtx(i));

      Tx tx(rawTxRef);
      supportingTxMap_->emplace(tx.getThisHash(), move(tx));
   }   
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
      signer.addSpender(spenderPtr);
   }

   for (unsigned i = 0; i < protoMsg.recipients_size(); i++)
   {
      const auto& recipientMsg = protoMsg.recipients(i);
      auto recipientPtr = ScriptRecipient::fromProtobuf(protoMsg.recipients(i));
      signer.addRecipient(recipientPtr, recipientMsg.groupid());
   }

   signer.deserializeSupportingTxMap(protoMsg);
   
   for (unsigned i=0; i<protoMsg.bip32roots_size(); i++)
   {
      auto& root = protoMsg.bip32roots(i);

      vector<unsigned> path;
      for (unsigned y=0; y<root.path_size(); y++)
         path.push_back(root.path(y));

      auto bip32root = make_shared<BIP32_PublicDerivedRoot>(
         root.xpub(), path, root.fingerprint());

      signer.bip32PublicRoots_.emplace(
         bip32root->getThisFingerprint(), bip32root);
   }

   signer.matchAssetPathsWithRoots();

   return signer;
}

////////////////////////////////////////////////////////////////////////////////
void Signer::deserializeState(
   const Codec_SignerState::SignerState& protoMsg)
{
   //deser into a new object
   auto&& new_signer = createFromState(protoMsg);
   new_signer.deserializeSupportingTxMap(protoMsg);

   merge(new_signer);
}

////////////////////////////////////////////////////////////////////////////////
void Signer::merge(const Signer& rhs)
{
   version_ = rhs.version_;
   lockTime_ = rhs.lockTime_;
   flags_ |= rhs.flags_;

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

   auto find_recipient = [this](
      shared_ptr<ScriptRecipient> obj, unsigned groupid)->
      shared_ptr<ScriptRecipient>
   {
      auto groupIter = this->recipients_.find(groupid);
      if (groupIter == this->recipients_.end())
         return nullptr;

      auto& scriptHash = obj->getSerializedScript();
      for (auto& rec : groupIter->second)
      {
         if (scriptHash == rec->getSerializedScript())
            return rec;
      }

      return nullptr;
   };

   //Merge new signer with this. As a general rule, the added entries are all 
   //pushed back.
   supportingTxMap_->insert(
      rhs.supportingTxMap_->begin(), rhs.supportingTxMap_->end());

   //merge spender
   for (auto& spender : rhs.spenders_)
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
         spender->txMap_ = supportingTxMap_;
         spenders_.push_back(spender);
         if (!spenders_.back()->verifyEvalState(flags_))
            throw SignerDeserializationError("unserialized spender has inconsistent state");
      }
   }


   /*
   Recipients are told apart by their script hash. Several recipients with
   the same script hash will be merged.

   Note that in case the local signer has several recipient with the same
   hash scripts, these won't be aggregated. Only those from the rhs will.

   As a general rule, do not create several outputs with the same script hash.

   NOTE: adding recipients or triggering an aggregation will render prior signatures 
   invalid. This code does NOT check for that. It's the caller's responsibility 
   to check for this condition.

   As with spenders, new recipients are pushed back.
   */

   for (auto& group : rhs.recipients_)
   {
      for (auto& recipient : group.second)
      {
         auto local_recipient = find_recipient(recipient, group.first);

         if (local_recipient == nullptr)
            addRecipient(recipient, group.first);
         else
            local_recipient->merge(recipient);
      }
   }

   //merge bip32 roots
   bip32PublicRoots_.insert(
      rhs.bip32PublicRoots_.begin(), rhs.bip32PublicRoots_.end());
   matchAssetPathsWithRoots();
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
void Signer::resetFeed(void)
{
   resolverPtr_ = nullptr;
}

////////////////////////////////////////////////////////////////////////////////
void Signer::populateUtxo(const UTXO& utxo)
{
   for (auto& spender : spenders_)
   {
      try
      {
         const auto& spenderUtxo = spender->getUtxo();
         if (spenderUtxo.isInitialized())
         {
            if (spenderUtxo == utxo)
               return;
         }
      }
      catch (const exception&)
      {}

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

   throw runtime_error("could not match utxo to any spender");
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::getTxId_const() const
{
   try
   {
      auto txdataref = serializeSignedTx();
      Tx tx(txdataref);
      return tx.getThisHash();
   }
   catch (exception&)
   {}

   BinaryWriter bw;

   //version
   bw.put_uint32_t(version_);
   
   //inputs
   bw.put_var_int(spenders_.size());
   for (auto spender : spenders_)
   {
      if (!spender->isSegWit() && !spender->isSigned())
         throw runtime_error("cannot get hash for unsigned legacy tx");

      bw.put_BinaryData(spender->getSerializedInput(false));
   }

   //outputs
   auto recipientVec = getRecipientVector();
   bw.put_var_int(recipientVec.size());
   for (auto recipient : recipientVec)
      bw.put_BinaryData(recipient->getSerializedScript());

   //locktime
   bw.put_uint32_t(lockTime_);

   //hash and return
   return BtcUtils::getHash256(bw.getDataRef());
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::getTxId()
{
   if (!isResolved())
      resolvePublicData();

   return getTxId_const();
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addSpender_ByOutpoint(
   const BinaryData& hash, unsigned index, unsigned sequence)
{
   auto spender = make_shared<ScriptSpender>(hash, index);
   spender->setSequence(sequence);

   addSpender(spender);
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addSpender(std::shared_ptr<ScriptSpender> ptr)
{
   for (const auto& spender : spenders_)
   {
      if (*ptr == *spender)
      {
         throw ScriptException("already carrying this spender");
      }
   }

   ptr->setTxMap(supportingTxMap_);
   spenders_.emplace_back(ptr);
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addRecipient(shared_ptr<ScriptRecipient> rec)
{
   addRecipient(rec, DEFAULT_RECIPIENT_GROUP);
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addRecipient(shared_ptr<ScriptRecipient> rec, unsigned groupId)
{
   //do not tolerate recipient duplication within a same group
   auto iter = recipients_.find(groupId);
   if (iter == recipients_.end())
   {
      auto insertIter = recipients_.emplace(
         groupId, vector<shared_ptr<ScriptRecipient>>());

      iter = insertIter.first;
   }

   auto& recVector = iter->second;

   for (const auto& recFromVector : recVector)
   {
      if (recFromVector->isSame(*rec))
      {
         throw runtime_error(
            "recipient duplication is not tolerated within groups");
      }
   }

   recVector.emplace_back(rec);
}

////////////////////////////////////////////////////////////////////////////////
vector<shared_ptr<ScriptRecipient>> Signer::getRecipientVector() const
{
   vector<shared_ptr<ScriptRecipient>> result;
   for (auto& group : recipients_)
   {
      for (auto& rec : group.second)
         result.emplace_back(rec);
   }

   return result;
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
BinaryData Signer::toPSBT() const
{
   //init
   BinaryWriter bw;
   PSBT::init(bw);

   /*
   Serialize the unsigned tx. PSBT requires non SW formating for this field
   and preimages are carried in dedicated input fields so we'll be using 
   dedicated serialization instead of relying on the existing unsigned tx
   code (which is used to yield hashes from unsigned SW transactions).
   */
   BinaryData unsignedTx;
   {
      BinaryWriter bw;

      //version
      bw.put_uint32_t(version_);

      //txin count
      bw.put_var_int(spenders_.size());

      //txins
      for (auto& spender : spenders_)
         bw.put_BinaryData(spender->serializeEmptyInput());

      //txout count
      auto recVector = getRecipientVector();
      bw.put_var_int(recVector.size());

      //txouts
      for (auto& recipient : recVector)
         bw.put_BinaryData(recipient->getSerializedScript());

      //lock time
      bw.put_uint32_t(lockTime_);

      unsignedTx = move(bw.getData());
   }

   //unsigned tx
   PSBT::setUnsignedTx(bw, unsignedTx);

   //proprietary data
   for (auto& data : prioprietaryPSBTData_)
   {
      //key
      bw.put_var_int(data.first.getSize() + 1);
      bw.put_uint8_t(PSBT::ENUM_GLOBAL::PSBT_GLOBAL_PROPRIETARY);
      bw.put_BinaryData(data.first);

      //val
      bw.put_var_int(data.second.getSize());
      bw.put_BinaryData(data.second);
   }

   PSBT::setSeparator(bw);

   /*inputs*/
   for (auto& spender : spenders_)
      spender->toPSBT(bw);

   /*outputs*/
   for (auto recipient : getRecipientVector())
      recipient->toPSBT(bw);

   //return
   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
Signer Signer::fromPSBT(const string& psbtString)
{
   BinaryDataRef psbtRef;
   psbtRef.setRef(psbtString);

   return Signer::fromPSBT(psbtRef);
}

////////////////////////////////////////////////////////////////////////////////
Signer Signer::fromPSBT(BinaryDataRef psbtRef)
{
   Signer signer;
   BinaryRefReader brr(psbtRef);

   /** header section **/

   //magic word
   auto magic = brr.get_uint32_t(BE);

   //separator
   auto separator = brr.get_uint8_t();

   if (magic != PSBT::ENUM_GLOBAL::PSBT_GLOBAL_MAGICWORD || 
      separator != PSBT::ENUM_GLOBAL::PSBT_GLOBAL_SEPARATOR)
   {
      throw PSBTDeserializationError("invalid header");
   }

   /** global section **/
   uint32_t psbtVersion = 0;
   BinaryDataRef unsignedTxRef;

   //getPSBTDataPairs guarantees keys aren't empty
   auto globalDataPairs = BtcUtils::getPSBTDataPairs(brr);

   for (const auto& dataPair : globalDataPairs)
   {
      const auto& key = dataPair.first;
      const auto& val = dataPair.second;
      
      //key type
      auto typePtr = key.getPtr();

      switch (*typePtr)
      {
      case PSBT::ENUM_GLOBAL::PSBT_GLOBAL_UNSIGNED_TX:
      {
         //key has to be 1 byte long
         if (key.getSize() != 1)
            throw PSBTDeserializationError("invalid unsigned tx key length");

         unsignedTxRef = val;
         break;
      }

      case PSBT::ENUM_GLOBAL::PSBT_GLOBAL_XPUB:
      {
         //skip for now

         break;
      }

      case PSBT::ENUM_GLOBAL::PSBT_GLOBAL_VERSION:
      {
         //sanity checks
         if (key.getSize() != 1)
            throw PSBTDeserializationError("invalid version key length");
         
         if (val.getSize() != 4)
            throw PSBTDeserializationError("invalid version val length");

         psbtVersion = *(uint32_t*)val.getPtr();
         break;
      }

      case PSBT::ENUM_GLOBAL::PSBT_GLOBAL_PROPRIETARY:
      {
         //skip for now

         break;
      }

      default:
         throw PSBTDeserializationError("unexpected global key");
      }
   }

   //sanity check
   if (unsignedTxRef.empty())
      throw PSBTDeserializationError("missing unsigned tx");

   Tx unsignedTx(unsignedTxRef);
   signer.setVersion(unsignedTx.getVersion());

   /** txin section **/
   for (unsigned i=0; i<unsignedTx.getNumTxIn(); i++)
   {
      auto txinCopy = unsignedTx.getTxInCopy(i);
      auto spender = ScriptSpender::fromPSBT(
         brr, txinCopy, signer.supportingTxMap_);

      signer.addSpender(spender);
   }

   /** txout section **/
   for (unsigned i=0; i<unsignedTx.getNumTxOut(); i++)
   {
      auto txoutCopy = unsignedTx.getTxOutCopy(i);
      auto recipient = ScriptRecipient::fromPSBT(brr, txoutCopy);
      signer.addRecipient(recipient);
   }

   return signer;
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addSupportingTx(BinaryDataRef rawTxRef)
{
   if (rawTxRef.empty())
      return;

   try
   {
      Tx tx(rawTxRef);
      addSupportingTx(move(tx));
   }
   catch (const exception&)
   {}
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addSupportingTx(Tx tx)
{
   if (!tx.isInitialized())
      return;

   supportingTxMap_->emplace(tx.getThisHash(), move(tx));
}

////////////////////////////////////////////////////////////////////////////////
const Tx& Signer::getSupportingTx(const BinaryData& hash) const
{
   auto iter = supportingTxMap_->find(hash);
   if (iter == supportingTxMap_->end())
      throw runtime_error("unknown supporting tx hash");
   
   return iter->second;
}

////////////////////////////////////////////////////////////////////////////////
map<unsigned, BinaryData> Signer::getPubkeysForScript(
   BinaryDataRef& scriptRef, shared_ptr<ResolverFeed> feedPtr)
{
   auto scriptType = BtcUtils::getTxOutScriptType(scriptRef);
   map<unsigned, BinaryData> pubkeyMap;

   switch (scriptType)
   {
   case TXOUT_SCRIPT_P2WPKH:
   {
      auto hash = scriptRef.getSliceRef(2, 20);
      if (feedPtr != nullptr)
      {
         try
         {
            pubkeyMap.emplace(0, feedPtr->getByVal(hash));
         }
         catch (const exception&)
         {}
      }
      break;
   }

   case TXOUT_SCRIPT_STDHASH160:
   {
      auto hash = scriptRef.getSliceRef(3, 20);
      if (feedPtr != nullptr)
      {
         try
         {
            pubkeyMap.emplace(0, feedPtr->getByVal(hash));
         }
         catch (const exception&)
         {}
      }
      break;
   }

   case TXOUT_SCRIPT_STDPUBKEY33:
   {
      pubkeyMap.emplace(0, scriptRef.getSliceRef(1, 33));
      break;
   }

   case TXOUT_SCRIPT_MULTISIG:
   {
      vector<BinaryData> pubKeys;
      BtcUtils::getMultisigPubKeyList(scriptRef, pubKeys);

      for (unsigned i=0; i<pubKeys.size(); i++)
         pubkeyMap.emplace(i, move(pubKeys[i]));
      break;
   }

   default:
      break;
   }

   return pubkeyMap;
}

////////////////////////////////////////////////////////////////////////////////
uint64_t Signer::getTotalInputsValue(void) const
{
   uint64_t val = 0;
   for (auto& spender : spenders_)
      val += spender->getValue();

   return val;
}

////////////////////////////////////////////////////////////////////////////////
uint64_t Signer::getTotalOutputsValue(void) const
{
   uint64_t val = 0;
   for (const auto& group : recipients_)
   {
      for (const auto& recipient : group.second)
         val += recipient->getValue();
   }

   return val;
}

////////////////////////////////////////////////////////////////////////////////
uint32_t Signer::getTxOutCount() const
{
   uint32_t count = 0;
   for (const auto& group : recipients_)
      count += group.second.size();

   return count;   
}

////////////////////////////////////////////////////////////////////////////////
void Signer::addBip32Root(shared_ptr<BIP32_PublicDerivedRoot> rootPtr)
{
   if (rootPtr == nullptr)
      return;
   
   bip32PublicRoots_.emplace(rootPtr->getThisFingerprint(), rootPtr);
}

////////////////////////////////////////////////////////////////////////////////
void Signer::matchAssetPathsWithRoots()
{
   for (auto& spender : spenders_)
   {
      auto& paths = spender->getBip32Paths();

      for (auto& pathPair : paths)
      {
         auto fingerprint = pathPair.second.getThisFingerprint();
      
         auto iter = bip32PublicRoots_.find(fingerprint);
         if (iter == bip32PublicRoots_.end())
            continue;

         pathPair.second.setRoot(iter->second);
      }
   }
}

////////////////////////////////////////////////////////////////////////////////
BinaryData Signer::signMessage(
   const BinaryData&,
   const BinaryData&,
   std::shared_ptr<ResolverFeed>)
{
   throw runtime_error("TODO: implement me");
}

////////////////////////////////////////////////////////////////////////////////
bool Signer::verifyMessageSignature(
   const BinaryData&, const BinaryData&)
{
   throw runtime_error("TODO: implement me");
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
      if (signer == nullptr || feedPtr == nullptr || spender == nullptr)
         throw runtime_error("proxy carries null pointers");

      auto SHD = signer->getSigHashDataForSpender(sw);

      //get priv key for pubkey
      const auto& privKey = feedPtr->getPrivKeyForPubkey(pubkey);

      //sign
      auto&& sig = signer->signScript(script, privKey, SHD, index);

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

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// ResolverFeed_SpenderResolutionChecks
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
BIP32_AssetPath ResolverFeed_SpenderResolutionChecks::resolveBip32PathForPubkey(
   const BinaryData&)
{
   throw std::runtime_error("invalid pubkey");
}

////////////////////////////////////////////////////////////////////////////////
void ResolverFeed_SpenderResolutionChecks::setBip32PathForPubkey(
   const BinaryData&, const BIP32_AssetPath&)
{}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// PSBT
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
void PSBT::init(BinaryWriter& bw)
{
   bw.put_uint32_t(PSBT::ENUM_GLOBAL::PSBT_GLOBAL_MAGICWORD, BE);
   bw.put_uint8_t(PSBT::ENUM_GLOBAL::PSBT_GLOBAL_SEPARATOR);
}

////////////////////////////////////////////////////////////////////////////////
void PSBT::setUnsignedTx(BinaryWriter& bw, const BinaryData& unsignedTx)
{
   bw.put_uint8_t(1);
   bw.put_uint8_t(PSBT::ENUM_GLOBAL::PSBT_GLOBAL_UNSIGNED_TX);

   bw.put_var_int(unsignedTx.getSize());
   bw.put_BinaryData(unsignedTx);
}

////////////////////////////////////////////////////////////////////////////////
void PSBT::setSeparator(BinaryWriter& bw)
{
   bw.put_uint8_t(0);
}