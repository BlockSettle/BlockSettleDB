////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018-2025, goatpig                                          //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BitcoinSettings.h"
#include <btc/chainparams.h>

using namespace Armory::Config;

uint8_t BitcoinSettings::pubkeyHashPrefix_;
uint8_t BitcoinSettings::scriptHashPrefix_;
uint8_t BitcoinSettings::privKeyPrefix_;

BinaryData BitcoinSettings::genesisBlockHash_;
BinaryData BitcoinSettings::genesisTxHash_;
BinaryData BitcoinSettings::magicBytes_;

NETWORK_MODE BitcoinSettings::mode_;
const btc_chainparams* BitcoinSettings::chainParams_ = nullptr;
std::string BitcoinSettings::bech32Prefix_;
uint32_t BitcoinSettings::BIP32_CoinType_ = UINT32_MAX;

////////////////////////////////////////////////////////////////////////////////
void BitcoinSettings::selectNetwork(NETWORK_MODE mode)
{
   switch (mode)
   {
      case NETWORK_MODE_MAINNET:
      {
         genesisBlockHash_ = READHEX(MAINNET_GENESIS_HASH_HEX);
         genesisTxHash_ = READHEX(MAINNET_GENESIS_TX_HASH_HEX);
         magicBytes_ = READHEX(MAINNET_MAGIC_BYTES);
         pubkeyHashPrefix_ = (uint8_t)ScriptPrefix::HASH160;
         scriptHashPrefix_ = (uint8_t)ScriptPrefix::P2SH;
         privKeyPrefix_ = (uint8_t)ScriptPrefix::PRIVKEY;
         bech32Prefix_ = "bc";

         chainParams_ = &btc_chainparams_main;
         BIP32_CoinType_ = 0x80000000;
         break;
      }

      case NETWORK_MODE_TESTNET:
      {
         genesisBlockHash_ = READHEX(TESTNET_GENESIS_HASH_HEX);
         genesisTxHash_ = READHEX(TESTNET_GENESIS_TX_HASH_HEX);
         magicBytes_ = READHEX(TESTNET_MAGIC_BYTES);
         pubkeyHashPrefix_ = (uint8_t)ScriptPrefix::HASH160_TESTNET;
         scriptHashPrefix_ = (uint8_t)ScriptPrefix::P2SH_TESTNET;
         privKeyPrefix_ = (uint8_t)ScriptPrefix::PRIVKEY_TESTNET;
         bech32Prefix_ = "tb";

         chainParams_ = &btc_chainparams_test;
         BIP32_CoinType_ = 0x80000001;
         break;
      }

      case NETWORK_MODE_REGTEST:
      {
         genesisBlockHash_ = READHEX(REGTEST_GENESIS_HASH_HEX);
         genesisTxHash_ = READHEX(REGTEST_GENESIS_TX_HASH_HEX);
         magicBytes_ = READHEX(REGTEST_MAGIC_BYTES);
         pubkeyHashPrefix_ = (uint8_t)ScriptPrefix::HASH160_TESTNET;
         scriptHashPrefix_ = (uint8_t)ScriptPrefix::P2SH_TESTNET;
         privKeyPrefix_ = (uint8_t)ScriptPrefix::PRIVKEY_TESTNET;
         bech32Prefix_ = "tb";

         chainParams_ = &btc_chainparams_regtest;
         BIP32_CoinType_ = 0x80000001;
         break;
      }

      default:
         mode_ = NETWORK_MODE_NA;
         LOGERR << "invalid network mode selection";
         throw std::runtime_error("invalid network mode selection");
   }
   mode_ = mode;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData BitcoinSettings::getMainnetMagicBytes()
{
   return READHEX(MAINNET_MAGIC_BYTES);
}

////////////////////////////////////////////////////////////////////////////////
bool BitcoinSettings::isInitialized()
{
   return mode_ != NETWORK_MODE_NA;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t BitcoinSettings::getPubkeyHashPrefix()
{ 
   if (!isInitialized()) {
      LOGERR << "BitcoinSettings is uninitialized!";
      throw std::runtime_error("BitcoinSettings is uninitialized!");
   }
   return pubkeyHashPrefix_;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t BitcoinSettings::getScriptHashPrefix()
{
   if (!isInitialized()) {
      LOGERR << "BitcoinSettings is uninitialized!";
      throw std::runtime_error("BitcoinSettings is uninitialized!");
   }
   return scriptHashPrefix_;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t BitcoinSettings::getPrivKeyPrefix()
{
   if (!isInitialized()) {
      LOGERR << "BitcoinSettings is uninitialized!";
      throw std::runtime_error("BitcoinSettings is uninitialized!");
   }
   return privKeyPrefix_;
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& BitcoinSettings::getGenesisBlockHash()
{
   if (!isInitialized()) {
      LOGERR << "BitcoinSettings is uninitialized!";
      throw std::runtime_error("BitcoinSettings is uninitialized!");
   }
   return genesisBlockHash_;
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& BitcoinSettings::getGenesisTxHash()
{
   if (!isInitialized()) {
      LOGERR << "BitcoinSettings is uninitialized!";
      throw std::runtime_error("BitcoinSettings is uninitialized!");
   }
   return genesisTxHash_;
}

////////////////////////////////////////////////////////////////////////////////
const BinaryData& BitcoinSettings::getMagicBytes()
{
   if (!isInitialized()) {
      LOGERR << "BitcoinSettings is uninitialized!";
      throw std::runtime_error("BitcoinSettings is uninitialized!");
   }
   return magicBytes_;
}

////////////////////////////////////////////////////////////////////////////////
uint32_t BitcoinSettings::getCoinType()
{
   if (BIP32_CoinType_ == UINT32_MAX) {
      LOGERR << "coin type is not set";
      throw std::runtime_error("coin type is not set");
   }
   return BIP32_CoinType_;
}

////////////////////////////////////////////////////////////////////////////////
void BitcoinSettings::processArgs(
   const std::map<std::string, std::string>& argMap)
{
   //is it testnet?
   auto iter = argMap.find("testnet");
   if (iter != argMap.end()) {
      selectNetwork(NETWORK_MODE_TESTNET);
      return;
   }

   //or regtest?
   iter = argMap.find("regtest");
   if (iter != argMap.end()) {
      selectNetwork(NETWORK_MODE_REGTEST);
      return;
   }

   //or finally, mainnet
   selectNetwork(NETWORK_MODE_MAINNET);
}

////////
const btc_chainparams* BitcoinSettings::getChainParams()
{
   return chainParams_;
}

NETWORK_MODE BitcoinSettings::getMode()
{
   return mode_;
}
