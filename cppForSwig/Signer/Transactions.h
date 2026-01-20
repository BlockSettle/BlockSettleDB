////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <map>
#include <vector>
#include <string>

#include "Utils/BinaryData.h"
#include "Utils/BCTX.h"
#include "TxEvalState.h"
#include "SigHashEnum.h"

struct UTXO;
class UnspentTxOut;

namespace Armory
{
   namespace Signing
   {
      class StackInterpreter;
      using UtxoMap = std::map<BinaryData, std::map<unsigned, UTXO>>;

      class UnsupportedSigHashTypeException : public std::runtime_error
      {
      public:
         UnsupportedSigHashTypeException(const std::string&);
      };

      //////////////////////////////////////////////////////////////////////////
      struct TxInData
      {
         BinaryDataRef outputHash;
         uint32_t outputIndex;
         uint32_t sequence;
      };

      //////////////////////////////////////////////////////////////////////////
      class SigHashDataSegWit;

      class TransactionStub
      {
      protected:
         unsigned flags_ = 0;
         mutable std::shared_ptr<SigHashDataSegWit> sigHashDataObject_ = nullptr;

      public:
         mutable std::map<unsigned, size_t> lastCodeSeparatorMap_;

      public:
         TransactionStub(void);
         TransactionStub(unsigned);
         virtual ~TransactionStub(void) = 0;

         virtual BinaryDataRef getSerializedOutputScripts(void) const = 0;
         virtual std::vector<TxInData> getTxInsData(void) const = 0;
         virtual BinaryData getSubScript(unsigned) const = 0;
         virtual BinaryDataRef getWitnessData(unsigned) const = 0;

         virtual uint32_t getVersion(void) const = 0;
         virtual uint32_t getTxOutCount(void) const = 0;
         virtual uint32_t getLockTime(void) const = 0;

         //sw methods
         virtual BinaryData serializeAllOutpoints(void) const = 0;
         virtual BinaryData serializeAllSequences(void) const = 0;
         virtual BinaryDataRef getOutpoint(unsigned) const = 0;
         virtual uint64_t getOutpointValue(unsigned) const = 0;
         virtual unsigned getTxInSequence(unsigned) const = 0;

         //flags
         unsigned getFlags(void) const;
         void setFlags(unsigned);

         //op_cs
         void setLastOpCodeSeparator(unsigned, size_t) const;
         unsigned getLastCodeSeparatorOffset(unsigned) const;
      };

      //////////////////////////////////////////////////////////////////////////
      class SigHashData
      {
         //this class and its children do not return the sighash,
         //rather the data that will yield the hash
      private:
         virtual BinaryData getDataForSigHashAll(const TransactionStub&,
            BinaryDataRef, unsigned) = 0;

      public:
         BinaryData getDataForSigHash(
            SIGHASH_TYPE, const TransactionStub&,
            BinaryDataRef, unsigned);
         std::vector<BinaryDataRef> tokenize(const BinaryData&, uint8_t);
      };

      //////////////////////////////////////////////////////////////////////////
      class SigHashDataLegacy : public SigHashData
      {
      private:
         BinaryData getDataForSigHashAll(
            const TransactionStub&,
            BinaryDataRef, unsigned);
      };

      //////////////////////////////////////////////////////////////////////////
      class SigHashDataSegWit : public SigHashData
      {
      private:
         bool initialized_ = false;
         BinaryData hashPrevouts_;
         BinaryData hashSequence_;
         BinaryData hashOutputs_;

      private:
         virtual uint32_t getSigHashAll_4Bytes(void) const;

      private:
         BinaryData getDataForSigHashAll(const TransactionStub&,
            BinaryDataRef, unsigned);
         void computePreState(const TransactionStub&);
      };

      //////////////////////////////////////////////////////////////////////////
      class TransactionVerifier : public TransactionStub
      {
      private:
         UtxoMap utxos_;
         const BCTX theTx_;
         mutable TxEvalState txEvalState_;

         uint64_t checkOutputs(void) const;
         void checkSigs(void) const;
         void checkSigs_NoCatch(void) const;
         TxInEvalState checkSig(unsigned, StackInterpreter* = nullptr) const;

      protected:
         virtual std::unique_ptr<StackInterpreter>
            getStackInterpreter(unsigned) const;

      public:
         TransactionVerifier(const BCTX&, const UtxoMap&);
         TransactionVerifier(const BCTX&, const std::vector<UnspentTxOut>&);
         TransactionVerifier(const BCTX&, const std::vector<UTXO>&);

         bool verify(bool=true, bool=true) const;
         TxEvalState evaluateState(bool=true) const;

         BinaryDataRef getSerializedOutputScripts(void) const;
         std::vector<TxInData> getTxInsData(void) const;
         BinaryData getSubScript(unsigned) const;
         BinaryDataRef getWitnessData(unsigned) const;

         uint32_t getVersion(void) const;
         uint32_t getTxOutCount(void) const;
         uint32_t getLockTime(void) const;

         //sw
         BinaryData serializeAllOutpoints(void) const;
         BinaryData serializeAllSequences(void) const;
         BinaryDataRef getOutpoint(unsigned) const;
         uint64_t getOutpointValue(unsigned) const;
         unsigned getTxInSequence(unsigned) const;
      };
   } //namespace Signing
} //namespace Armory
