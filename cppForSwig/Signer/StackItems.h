////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <map>
#include <Utils/SecureBinaryData.h>

namespace Armory
{
   namespace Signing
   {
      class ScriptException : public std::runtime_error
      {
      public:
         ScriptException(const std::string&);
      };

      //////////////////////////////////////////////////////////////////////////
      // enums
      enum class StackItemType : int
      {
         PushData = 1,
         OpCode,
         Sig,
         MultiSig,
         SerializedScript
      };

      enum class StackValueType : int
      {
         Static,
         FromFeed,
         Sig,
         Multisig,
         Reference
      };

      //////////////////////////////////////////////////////////////////////////
      // StackItem
      class StackItem
      {
      protected:
         const StackItemType type_;
         const unsigned id_;

      public:
         StackItem(StackItemType, unsigned);

         virtual ~StackItem(void) = 0;
         virtual bool isValid(void) const;
         virtual bool isSame(const StackItem*) const = 0;
         unsigned getId(void) const;
         StackItemType type(void) const;
      };

      ////
      struct StackItem_PushData : public StackItem
      {
         const BinaryData data;

         StackItem_PushData(unsigned, BinaryData&&);
         bool isValid(void) const override;
         bool isSame(const StackItem*) const override;
      };

      ////
      struct StackItem_Sig : public StackItem
      {
         BinaryData pubkey;
         BinaryData script;
         SecureBinaryData sig;

         StackItem_Sig(unsigned, BinaryData&, BinaryData&);
         bool isValid(void) const override;
         bool isSame(const StackItem*) const override;
         void merge(const StackItem*);
         void injectSig(SecureBinaryData&);
      };

      ////
      struct StackItem_MultiSig : public StackItem
      {
         const BinaryData script;

         std::map<unsigned, SecureBinaryData> sigs;
         std::vector<BinaryData> pubkeyVec;
         unsigned m;

         StackItem_MultiSig(unsigned, BinaryData&);
         void setSig(unsigned, SecureBinaryData&);
         bool isSame(const StackItem*) const override;
         void merge(const StackItem*);
         bool isValid(void) const override;
      };

      ////
      struct StackItem_OpCode : public StackItem
      {
         const uint8_t opcode;

         StackItem_OpCode(unsigned, uint8_t);
         bool isSame(const StackItem*) const override;
      };

      ////
      struct StackItem_SerializedScript : public StackItem
      {
         const BinaryData data;

         StackItem_SerializedScript(unsigned, BinaryData&&);
         bool isSame(const StackItem*) const;
      };

      //////////////////////////////////////////////////////////////////////////
      // OpCode
      struct ReversedStackEntry;

      struct OpCode
      {
         size_t offset;
         uint8_t opcode;
         BinaryDataRef dataRef;

         virtual ~OpCode(void);
      };

      struct ExtendedOpCode : public OpCode
      {
         unsigned itemIndex;
         BinaryData data;
         std::vector<std::shared_ptr<ReversedStackEntry>> referenceStackItemVec;

         ExtendedOpCode(const OpCode&);
      };

      //////////////////////////////////////////////////////////////////////////
      // StackValue
      struct StackValue
      {
      private:
         const StackValueType type_;

      public:
         StackValue(StackValueType);
         virtual ~StackValue(void) = 0;

         StackValueType type(void) const;
      };

      ////
      struct StackValue_Static : public StackValue
      {
         BinaryData value_;

         StackValue_Static(BinaryData);
      };

      ////
      struct StackValue_Reference : public StackValue
      {
         std::shared_ptr<ReversedStackEntry> valueReference_;
         BinaryData value_;

         StackValue_Reference(std::shared_ptr<ReversedStackEntry>);
      };

      ////
      struct StackValue_FromFeed : public StackValue
      {
         BinaryData requestString_;
         BinaryData value_;

         StackValue_FromFeed(const BinaryData&);
      };

      ////
      struct StackValue_Sig : public StackValue
      {
         std::shared_ptr<ReversedStackEntry> pubkeyRef_;
         BinaryData script_;

         StackValue_Sig(std::shared_ptr<ReversedStackEntry>);
      };

      ////
      struct StackValue_Multisig : public StackValue
      {
         BinaryData script_;

         StackValue_Multisig(const BinaryData&);
      };

      //////////////////////////////////////////////////////////////////////////
      // ReversedStackEntry
      struct ReversedStackEntry
      {
         //static data is usually result of a pushdata opcode
         bool static_ = false;
         BinaryData staticData_;

         //ptr to parent for op_dup style entries
         std::shared_ptr<ReversedStackEntry> parent_ = nullptr;

         //effective opcodes on this item
         std::vector<std::shared_ptr<OpCode>> opcodes_;

         //original value prior to opcode effect
         std::shared_ptr<StackValue> resolvedValue_;

      public:
         ReversedStackEntry(void);
         ReversedStackEntry(const BinaryData&);
         bool push_opcode(std::shared_ptr<OpCode>);
      };

   } //namespace Signing
} //namespace Armory
