////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2017-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "TxEvalState.h"
#include "Utils/Cryptography.h"

using namespace Armory;
using namespace Armory::Signing;

////////////////////////////////////////////////////////////////////////////////
// TxInEvalState
bool TxInEvalState::isValid() const
{
   if (!validStack_) {
      return false;
   }

   unsigned count = 0;
   for (const auto& state : pubKeyState_) {
      if (state.second == true) {
         ++count;
      }
   }
   return count >= m_;
}

////////
unsigned TxInEvalState::getM() const
{
   return m_;
}

unsigned TxInEvalState::getN() const
{
   return n_;
}

unsigned TxInEvalState::getSigCount() const
{
   unsigned count = 0;
   for (auto& state : pubKeyState_) {
      if (state.second == true) {
         ++count;
      }
   }
   return count;
}

////////
const std::map<BinaryData, bool>& TxInEvalState::getPubKeyMap() const
{
   return pubKeyState_;
}

bool TxInEvalState::isSignedForPubKey(BinaryDataRef pubkey) const
{
   if (pubKeyState_.empty()) {
      return false;
   }

   auto type = getType();
   if (type == PubKeyType::Unkonwn) {
      throw std::runtime_error("can't establish pub key type");
   }

   if ((pubkey.getSize() == 65 && type == PubKeyType::Uncompressed) ||
      (pubkey.getSize() == 33 && type == PubKeyType::Compressed)) {
      auto iter = pubKeyState_.find(pubkey);
      if (iter == pubKeyState_.end()) {
         return false;
      }
      return iter->second;
   } else if (type != PubKeyType::Mixed) {
      BinaryData modifiedKey;
      if (type == PubKeyType::Compressed) {
         modifiedKey = Cryptography::ECDSA::compressPoint(pubkey);
      } else if (type == PubKeyType::Uncompressed) {
         modifiedKey = Cryptography::ECDSA::uncompressPoint(pubkey);
      }

      auto iter = pubKeyState_.find(modifiedKey);
      if (iter == pubKeyState_.end()) {
         return false;
      }
      return iter->second;
   } else {
      BinaryData modifiedKey;
      if (type == PubKeyType::Compressed) {
         modifiedKey = Cryptography::ECDSA::compressPoint(pubkey);
      } else if (type == PubKeyType::Uncompressed) {
         modifiedKey = Cryptography::ECDSA::uncompressPoint(pubkey);
      }

      auto iter = pubKeyState_.find(pubkey);
      if (iter == pubKeyState_.end()) {
         auto iter2 = pubKeyState_.find(modifiedKey);
         if (iter2 == pubKeyState_.end()) {
            return false;
         }
         return iter2->second;
      }
      return iter->second;
   }
   return false;
}

////////
PubKeyType TxInEvalState::getType() const
{
   if (keyType_ != PubKeyType::Unkonwn) {
      return keyType_;
   }

   bool isCompressed = false;
   bool isUncompressed = false;

   for (const auto& key : pubKeyState_) {
      if (key.first.getSize() == 65) {
         isUncompressed = true;
      } else if (key.first.getSize() == 33) {
         isCompressed = true;
      }
   }

   if (isCompressed && isUncompressed) {
      keyType_ = PubKeyType::Mixed;
   } else if (isCompressed) {
      keyType_ = PubKeyType::Compressed;
   } else if (isUncompressed) {
      keyType_ = PubKeyType::Uncompressed;
   }
   return keyType_;
}

////////
void Signing::TxEvalState::updateState(unsigned id, TxInEvalState state)
{
   evalMap_.emplace(id, state);
}

////////////////////////////////////////////////////////////////////////////////
// TxEvalState
bool TxEvalState::isValid() const
{
   for (const auto& state : evalMap_) {
      if (!state.second.isValid()) {
         return false;
      }
   }
   return true;
}

void TxEvalState::reset()
{
   evalMap_.clear();
}

size_t TxEvalState::getEvalMapSize() const
{
   return evalMap_.size();
}

////////
const TxInEvalState& TxEvalState::getSignedStateForInput(unsigned i) const
{
   auto iter = evalMap_.find(i);
   if (iter == evalMap_.end()) {
      throw std::range_error("invalid input index");
   }
   return iter->second;
}
