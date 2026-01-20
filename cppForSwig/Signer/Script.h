////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

//signer flags
#define SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY 0x00000001
#define SCRIPT_VERIFY_CHECKSEQUENCEVERIFY 0x00000002
#define SCRIPT_VERIFY_P2SH                0x00000004
#define SCRIPT_VERIFY_P2SH_SHA256         0x00000008
#define SCRIPT_VERIFY_SEGWIT              0x00000010
#define P2SH_TIMESTAMP                    1333238400

#define STACKITEM_OPCODE_PREFIX           0x10
#define STACKITEM_PUSHDATA_PREFIX         0x11
#define STACKITEM_SERSCRIPT_PREFIX        0x12
#define STACKITEM_SIG_PREFIX              0x13
#define STACKITEM_MULTISIG_PREFIX         0x14

#include <deque>
#include <Utils/OpCodes.h>
#include "SigHashEnum.h"
#include "StackItems.h"
#include "TxEvalState.h"

namespace Armory
{
   namespace Signing
   {
      class ResolverFeed;
      class TransactionStub;
      class SigHashData;
      class SigHashDataSegWit;

      //////////////////////////////////////////////////////////////////////////
      class ScriptParser
      {
      protected:
         virtual void processOpCode(const OpCode&) = 0;

      public:
         void parseScript(BinaryRefReader&);
         size_t seekToOpCode(BinaryRefReader&, OPCODETYPE) const;
      };

      //////////////////////////////////////////////////////////////////////////
      class StackInterpreter : public ScriptParser
      {
      private:
         std::vector<BinaryData> stack_;
         std::vector<BinaryData> altstack_;
         bool onlyPushDataInInput_ = true;

         const TransactionStub* txStubPtr_;
         const unsigned inputIndex_;

         bool isValid_ = false;
         unsigned opcount_ = 0;

         unsigned flags_;

         BinaryDataRef outputScriptRef_;
         BinaryData p2shScript_;

         std::shared_ptr<SigHashDataSegWit> SHD_SW_ = nullptr;

         TxInEvalState txInEvalState_;

      protected:
         std::shared_ptr<SigHashData> sigHashDataObject_ = nullptr;
         virtual SIGHASH_TYPE getSigHashSingleByte(uint8_t) const;

      private:
         void processOpCode(const OpCode&) override;
         void op_if(BinaryRefReader&, bool);
         void op_0(void);
         void op_true(void);
         void op_1negate(void);
         void op_depth(void);
         void op_dup(void);
         void op_nip(void);
         void op_over(void);
         void op_2dup(void);
         void op_3dup(void);
         void op_2over(void);
         void op_toaltstack(void);
         void op_fromaltstack(void);
         void op_ifdup(void);
         void op_pick(void);
         void op_roll(void);
         void op_rot(void);
         void op_swap(void);
         void op_tuck(void);
         void op_ripemd160(void);
         void op_sha256(void);
         void op_hash160(void);
         void op_hash256(void);
         void op_size(void);
         void op_equal(void);
         void op_1add(void);
         void op_1sub(void);
         void op_negate(void);
         void op_abs(void);
         void op_not(void);
         void op_0notequal(void);
         void op_numequal(void);
         void op_numnotequal(void);
         void op_lessthan(void);
         void op_lessthanorequal(void);
         void op_greaterthan(void);
         void op_greaterthanorequal(void);
         void op_min(void);
         void op_max(void);
         void op_within(void);
         void op_booland(void);
         void op_boolor(void);
         void op_add(void);
         void op_sub(void);
         void op_checksig(void);
         void op_checkmultisig(void);
         void op_verify(void);
         void process_p2wpkh(const BinaryData&);
         void process_p2wsh(const BinaryData&);

      public:
         StackInterpreter(void);
         StackInterpreter(const TransactionStub*, unsigned);

         void push_back(const BinaryData&);
         BinaryData pop_back(void);
         const BinaryData& stack_back(void) const;

         void checkState(void);
         void processSW(BinaryDataRef);
         void setSegWitSigHashDataObject(std::shared_ptr<SigHashDataSegWit>);

         unsigned getFlags(void) const;
         void setFlags(unsigned);

         void processScript(const BinaryDataRef&, bool);
         void processScript(BinaryRefReader&, bool);
         const TxInEvalState& getTxInEvalState(void) const;
      };

      //////////////////////////////////////////////////////////////////////////
      class ResolvedStack
      {
         friend class StackResolver;

      private:
         bool isP2SH_ = false;

         std::vector<std::shared_ptr<StackItem>> stack_;
         std::shared_ptr<ResolvedStack> witnessStack_ = nullptr;

      public:
         bool isP2SH(void) const;
         void flagP2SH(bool);
         size_t stackSize(void) const;

         std::shared_ptr<ResolvedStack> getWitnessStack(void) const;
         void setWitnessStack(std::shared_ptr<ResolvedStack>);
         void setStackData(std::vector<std::shared_ptr<StackItem>>);
         const std::vector<std::shared_ptr<StackItem>>& getStack(void) const;
      };

      //////////////////////////////////////////////////////////////////////////
      class StackResolver : ScriptParser
      {
      private:
         std::deque<std::shared_ptr<ReversedStackEntry>> stack_;
         unsigned flags_ = 0;

         std::shared_ptr<ResolvedStack> resolvedStack_ = nullptr;
         unsigned opCodeCount_ = 0;
         bool opHash_ = false;
         bool isP2SH_ = false;
         bool isSW_ = false;

         const BinaryDataRef script_;
         std::shared_ptr<ResolverFeed> feed_;

      private:
         std::shared_ptr<ReversedStackEntry> pop_back(void);
         std::shared_ptr<ReversedStackEntry> getTopStackEntryPtr(void);

         void processOpCode(const OpCode&);
         void push_int(unsigned);
         void pushdata(const BinaryData&);
         void op_dup(void);
         void push_op_code(const OpCode&);
         void op_1item(const OpCode&);
         void op_1item_verify(const OpCode&);
         void op_2items(const OpCode&);
         void op_2items_verify(const OpCode&);

         void processScript(BinaryRefReader&);
         void resolveStack(void);

      public:
         StackResolver(BinaryDataRef, std::shared_ptr<ResolverFeed>);
         ~StackResolver(void);

         std::shared_ptr<ResolvedStack> getResolvedStack(void);
         unsigned getFlags(void) const;
         void setFlags(unsigned);
         std::shared_ptr<ResolverFeed> getFeed(void) const;
      };
   } //namespace Signing
} //namespace Armory
