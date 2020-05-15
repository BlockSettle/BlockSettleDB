////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_SIGNER
#define _H_SIGNER

#include <set>

#include "EncryptionUtils.h"
#include "TxClasses.h"
#include "Transactions.h"
#include "ScriptRecipient.h"
#include "TxEvalState.h"

enum SpenderStatus
{
   //Not parsed yet/failed to parse entirely. This is 
   //an invalid state
   SpenderStatus_Unknown,

   //As the name suggests. This is a valid state
   SpenderStatus_Empty,

   //All public data has been resolved. This is a valid state
   SpenderStatus_Resolved,

   //Resolved & partially signed (only applies to multisig scripts)
   //This is an invalid state
   SpenderStatus_PartiallySigned,

   //Resolved & signed. This is a valid state
   SpenderStatus_Signed
};

#define SERIALIZED_SCRIPT_PREFIX 0x01
#define WITNESS_SCRIPT_PREFIX    0x02

#define LEGACY_STACK_PARTIAL    0x03
#define WITNESS_STACK_PARTIAL   0x04

#define PREFIX_UTXO        0x05
#define PREFIX_OUTPOINT    0x06

////////////////////////////////////////////////////////////////////////////////
class ScriptSpender
{
protected:
   SpenderStatus segwitStatus_ = SpenderStatus_Unknown;
   BinaryData witnessData_;
   mutable BinaryData serializedInput_;

private:
   SpenderStatus legacyStatus_ = SpenderStatus_Unknown;
   bool isP2SH_ = false;
   bool isSegWit_ = false;

   bool isCSV_ = false;
   bool isCLTV_ = false;

   UTXO utxo_;
   const uint64_t value_ = UINT64_MAX;
   unsigned sequence_ = UINT32_MAX;
   mutable BinaryData outpoint_;

   //
   std::shared_ptr<ResolverFeed> resolverFeed_;
   BinaryData serializedScript_;

   std::map<unsigned, std::shared_ptr<StackItem>> partialStack_;
   std::map<unsigned, std::shared_ptr<StackItem>> partialWitnessStack_;

protected:
   SIGHASH_TYPE sigHashType_ = SIGHASH_ALL;

   BinaryData getSerializedOutpoint(void) const;

private:
   static BinaryData serializeScript(
      const std::vector<std::shared_ptr<StackItem>>& stack, bool no_throw=false);
   static BinaryData serializeWitnessData(
      const std::vector<std::shared_ptr<StackItem>>& stack,
      unsigned& itemCount, bool no_throw=false);

   void updateStack(std::map<unsigned, std::shared_ptr<StackItem>>&,
      const std::vector<std::shared_ptr<StackItem>>&);

   bool compareEvalState(const ScriptSpender&) const;
   BinaryData getSerializedInputScript(void) const;

public:
   ScriptSpender(
      const BinaryDataRef txHash, unsigned index, uint64_t value) :
      value_(value)
   {
      BinaryWriter bw;
      bw.put_BinaryDataRef(txHash);
      bw.put_uint32_t(index);

      outpoint_ = bw.getData();
   }

   ScriptSpender(const UTXO& utxo) :
      utxo_(utxo), value_(utxo.getValue())
   {}

   ScriptSpender(const UTXO& utxo, std::shared_ptr<ResolverFeed> feed) :
      utxo_(utxo), value_(utxo.getValue()), resolverFeed_(feed)
   {}

   virtual ~ScriptSpender() = default;

   bool isSegWit(void) const { return isSegWit_; }
   bool isP2SH(void) const { return isP2SH_; }

   //set
   void setSigHashType(SIGHASH_TYPE sht) { sigHashType_ = sht; }
   void setSequence(unsigned s) { sequence_ = s; }
   void setWitnessData(const std::vector<std::shared_ptr<StackItem>>&);
   void flagP2SH(bool flag) { isP2SH_ = flag; }

   //get
   SIGHASH_TYPE getSigHashType(void) const { return sigHashType_; }
   unsigned getSequence(void) const { return sequence_; }
   BinaryDataRef getOutputScript(void) const;
   BinaryDataRef getOutputHash(void) const;
   unsigned getOutputIndex(void) const;
   BinaryData getSerializedInput(bool) const;
   BinaryData serializeAvailableStack(void) const;
   BinaryDataRef getWitnessData(void) const;
   BinaryData serializeAvailableWitnessData(void) const;
   BinaryDataRef getOutpoint(void) const;
   uint64_t getValue(void) const { return value_; }
   std::shared_ptr<ResolverFeed> getFeed(void) const { return resolverFeed_; }
   const UTXO& getUtxo(void) const { return utxo_; }
   void setUtxo(const UTXO& utxo) { utxo_ = utxo; }

   unsigned getFlags(void) const
   {
      unsigned flags = 0;
      if (isP2SH_)
         flags |= SCRIPT_VERIFY_P2SH;

      if (isSegWit())
         flags |= SCRIPT_VERIFY_SEGWIT | SCRIPT_VERIFY_P2SH_SHA256;

      if (isCSV_)
         flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;

      if (isCLTV_)
         flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;

      return flags;
   }

   virtual uint8_t getSigHashByte(void) const
   {
      uint8_t hashbyte;
      switch (sigHashType_)
      {
      case SIGHASH_ALL:
         hashbyte = 1;
         break;

      default:
         throw ScriptException("unsupported sighash type");
      }

      return hashbyte;
   }

   void updatePartialStack(
      const std::vector<std::shared_ptr<StackItem>>& stack, unsigned sigCount)
   {
      if (legacyStatus_ == SpenderStatus_Signed)
         return;

      if (legacyStatus_ == SpenderStatus_Resolved && sigCount == 0)
         return;

      if (stack.size() != 0)
      {
         updateStack(partialStack_, stack);

         if (sigCount > 0)
            legacyStatus_ = SpenderStatus_PartiallySigned;
      }
      else
      {
         legacyStatus_ = SpenderStatus_Empty;
      }
   }

   void updatePartialWitnessStack(
      const std::vector<std::shared_ptr<StackItem>>& stack, unsigned sigCount)
   {
      if (segwitStatus_ == SpenderStatus_Signed)
         return;

      if (segwitStatus_ >= SpenderStatus_Resolved && sigCount == 0)
         return;

      updateStack(partialWitnessStack_, stack);
   }
   
   void evaluatePartialStacks();
   bool isResolved(void) const;
   bool isSigned(void) const;

   BinaryData serializeState(void) const;
   static std::shared_ptr<ScriptSpender> deserializeState(
      const BinaryDataRef&);

   void merge(const ScriptSpender&);
   bool hasUTXO(void) const { return utxo_.isInitialized(); }

   bool hasFeed(void) const { return resolverFeed_ != nullptr; }
   void setFeed(std::shared_ptr<ResolverFeed> feedPtr) { resolverFeed_ = feedPtr; }

   bool operator==(const ScriptSpender& rhs)
   {
      return this->getOutpoint() == rhs.getOutpoint();
   }

   void evaluateStack(StackResolver&, bool&);
   bool verifyEvalState(unsigned);
};

////////////////////////////////////////////////////////////////////////////////
class Signer : public TransactionStub
{
   friend class SignerProxyFromSigner;

protected:
   unsigned version_ = 1;
   unsigned lockTime_ = 0;

   mutable BinaryData serializedSignedTx_;
   mutable BinaryData serializedUnsignedTx_;
   mutable BinaryData serializedOutputs_;

   std::vector<std::shared_ptr<ScriptSpender>> spenders_;
   std::vector<std::shared_ptr<ScriptRecipient>> recipients_;

   std::shared_ptr<ResolverFeed> resolverPtr_;

   mutable bool isSegWit_ = false;

protected:
   virtual std::shared_ptr<SigHashData> getSigHashDataForSpender(bool) const;
   SecureBinaryData sign(
      BinaryDataRef script,
      const SecureBinaryData& privKey, 
      std::shared_ptr<SigHashData>,
      unsigned index);

   static std::unique_ptr<TransactionVerifier> getVerifier(std::shared_ptr<BCTX>,
      std::map<BinaryData, std::map<unsigned, UTXO>>&);

   BinaryData serializeAvailableResolvedData(void) const;

public:
   Signer(void) :
      TransactionStub(
         SCRIPT_VERIFY_P2SH | 
         SCRIPT_VERIFY_SEGWIT | 
         SCRIPT_VERIFY_P2SH_SHA256)
   {}

   //static
   static TxEvalState verify(
      const BinaryData&, //raw tx
      std::map<BinaryData, std::map<unsigned, UTXO>>&, //supporting outputs
      unsigned, //flags
      bool strict = true //strict verification (check balances)
      );

   //locals
   void addSpender(std::shared_ptr<ScriptSpender> spender)
   { spenders_.push_back(spender); }

   virtual void addSpender_ByOutpoint(
      const BinaryData& hash, unsigned index, unsigned sequence, uint64_t value);
   
   void addRecipient(std::shared_ptr<ScriptRecipient> recipient)
   { recipients_.push_back(recipient); }

   //resolve output scripts, fill public data when applicable
   void resolveSpenders(void);

   //resolve spenders & sign them
   void sign(void);

   BinaryDataRef serializeSignedTx(void) const;
   BinaryDataRef serializeUnsignedTx(bool loose = false);
   
   //verify tx signatures
   bool verify(void);
   bool verifyRawTx(const BinaryData& rawTx,
      const std::map<BinaryData, std::map<unsigned, BinaryData> >& rawUTXOs);

   ////
   BinaryDataRef getSerializedOutputScripts(void) const override;
   std::vector<TxInData> getTxInsData(void) const override;   
   BinaryData getSubScript(unsigned index) const override;
   BinaryDataRef getWitnessData(unsigned inputId) const override;
   bool isInputSW(unsigned inputId) const;

   uint32_t getVersion(void) const override { return version_; }
   uint32_t getTxOutCount(void) const override { return recipients_.size(); }
   std::shared_ptr<ScriptSpender> getSpender(unsigned) const;

   uint32_t getLockTime(void) const override { return lockTime_; }
   void setLockTime(unsigned locktime) { lockTime_ = locktime; }
   void setVersion(unsigned version) { version_ = version; }

   //sw methods
   BinaryData serializeAllOutpoints(void) const override;
   BinaryData serializeAllSequences(void) const override;
   BinaryDataRef getOutpoint(unsigned) const override;
   uint64_t getOutpointValue(unsigned) const override;
   unsigned getTxInSequence(unsigned) const override;

   BinaryData serializeState(void) const;
   void deserializeState(const BinaryData&);
   bool isResolved(void) const;
   bool isSigned(void) const;
   
   void setFeed(std::shared_ptr<ResolverFeed> feedPtr) { resolverPtr_ = feedPtr; }
   void resetFeeds(void);
   void populateUtxo(const UTXO& utxo);

   static Signer createFromState(const BinaryData&);

   BinaryData getTxId(void);

   TxEvalState evaluateSignedState(void)
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

   bool verifySpenderEvalState(void) const;
};

////////////////////////////////////////////////////////////////////////////////
class SignerProxy
{
protected:
   std::function<SecureBinaryData(
      BinaryDataRef, const BinaryData&, bool)> signerLambda_;

public:
   virtual ~SignerProxy(void) = 0;

   SecureBinaryData sign(
      BinaryDataRef script,
      const BinaryData& pubkey,
      bool sw)
   {
      return std::move(signerLambda_(script, pubkey, sw));
   }
};

////
class SignerProxyFromSigner : public SignerProxy
{
private:
   void setLambda(Signer*, std::shared_ptr<ScriptSpender>, unsigned index,
      std::shared_ptr<ResolverFeed>);

public:
   SignerProxyFromSigner(Signer* signer,
      unsigned index)
   {
      auto spender = signer->getSpender(index);
      setLambda(signer, spender, index, spender->getFeed());
   }

   SignerProxyFromSigner(Signer* signer,
      unsigned index, std::shared_ptr<ResolverFeed> feedPtr)
   {
      auto spender = signer->getSpender(index);
      setLambda(signer, spender, index, feedPtr);
   }
};

#endif

