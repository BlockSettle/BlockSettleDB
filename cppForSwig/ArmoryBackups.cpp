////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "ArmoryBackups.h"
#include "EncryptionUtils.h"
#include "BtcUtils.h"
#include "Wallets/WalletIdTypes.h"

#define EASY16_CHECKSUM_LEN 2
#define EASY16_INDEX_MAX   15
#define EASY16_LINE_LENGTH 16

#define WALLET_RESTORE_LOOKUP 1000

using namespace std;
using namespace ArmoryBackups;

////////////////////////////////////////////////////////////////////////////////
const vector<char> BackupEasy16::e16chars_ = 
{
   'a', 's', 'd', 'f',
   'g', 'h', 'j', 'k',
   'w', 'e', 'r', 't',
   'u', 'i', 'o', 'n'
};

////////////////////////////////////////////////////////////////////////////////
const set<uint8_t> BackupEasy16::eligibleIndexes_ =
{
   (uint8_t)BackupType::Armory135,
   (uint8_t)BackupType::BIP32_Seed_Structured,
   (uint8_t)BackupType::BIP32_Root,
   (uint8_t)BackupType::BIP32_Seed_Virgin,
};


////////////////////////////////////////////////////////////////////////////////

/*
Nothing up my sleeve!  Need some hardcoded random numbers to use for
encryption IV and salt.  Using the first 256 digits of Pi for the
the IV, and first 256 digits of e for the salt (hashed)
*/

const string SecurePrint::digits_pi_ = 
{
   "ARMORY_ENCRYPTION_INITIALIZATION_VECTOR_"
   "1415926535897932384626433832795028841971693993751058209749445923"
   "0781640628620899862803482534211706798214808651328230664709384460"
   "9550582231725359408128481117450284102701938521105559644622948954"
   "9303819644288109756659334461284756482337867831652712019091456485"
};
   
const string SecurePrint::digits_e_ = 
{
   "ARMORY_KEY_DERIVATION_FUNCTION_SALT_"
   "7182818284590452353602874713526624977572470936999595749669676277"
   "2407663035354759457138217852516642742746639193200305992181741359"
   "6629043572900334295260595630738132328627943490763233829880753195"
   "2510190115738341879307021540891499348841675092447614606680822648"
};

const uint32_t SecurePrint::kdfBytes_ = 16 * 1024 * 1024;

////////////////////////////////////////////////////////////////////////////////
////
//// BackupEasy16
////
////////////////////////////////////////////////////////////////////////////////
BinaryData BackupEasy16::getHash(const BinaryDataRef& data, uint8_t hint)
{
   if (hint == 0)
   {
      return BtcUtils::getHash256(data);
   }
   else
   {
      SecureBinaryData dataCopy(data.getSize() + 1);
      memcpy(dataCopy.getPtr(), data.getPtr(), data.getSize());
      dataCopy.getPtr()[data.getSize()] = hint;

      return BtcUtils::getHash256(dataCopy);
   }
}

////////////////////////////////////////////////////////////////////////////////
uint8_t BackupEasy16::verifyChecksum(
   const BinaryDataRef& data, const BinaryDataRef& checksum)
{
   for (const auto& indexCandidate : eligibleIndexes_)
   {
      auto hash = getHash(data, indexCandidate);
      if (hash.getSliceRef(0, EASY16_CHECKSUM_LEN) == checksum)
         return indexCandidate;
   }

   return EASY16_INVALID_CHECKSUM_INDEX;
}

////////////////////////////////////////////////////////////////////////////////
vector<string> BackupEasy16::encode(const BinaryDataRef data, uint8_t index)
{
   if (index > EASY16_INDEX_MAX)
   {
      LOGERR << "index is too large";
      throw runtime_error("index is too large");
   }

   auto encodeByte = [](stringstream& ss, uint8_t c)->void
   {
      uint8_t val1 = c >> 4;
      uint8_t val2 = c & 0x0F;
      ss << e16chars_[val1] << e16chars_[val2];
   };

   auto encodeValue = [&encodeByte, &index](
      const BinaryDataRef& chunk16)->string
   {
      //get hash
      auto h256 = getHash(chunk16, index);
      
      //encode the chunk
      stringstream ss;
      unsigned charCount = 0;
      auto ptr = chunk16.getPtr();
      for (unsigned i=0; i<chunk16.getSize(); i++)
      {
         encodeByte(ss, ptr[i]);
         ++charCount;
         if (charCount % 2 == 0)
            ss << " ";

         if (charCount % 8 == 0)
            ss << " ";
      }

      //append first 2 bytes of the hash as its checksum
      auto hashPtr = h256.getPtr();
      for (unsigned i = 0; i < EASY16_CHECKSUM_LEN; i++)
         encodeByte(ss, hashPtr[i]);

      return ss.str();
   };

   vector<string> result;
   BinaryRefReader brr(data);

   uint32_t count = 
      (data.getSize() + EASY16_LINE_LENGTH - 1) / EASY16_LINE_LENGTH;
   for (unsigned i=0; i<count; i++)
   {
      size_t len = 
         std::min(size_t(EASY16_LINE_LENGTH), brr.getSizeRemaining());
      auto chunk = brr.get_BinaryDataRef(len);
      result.emplace_back(encodeValue(chunk));
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
BackupEasy16DecodeResult BackupEasy16::decode(const vector<string>& lines)
{
   vector<BinaryDataRef> refVec;
   for (const auto& line : lines)
      refVec.emplace_back((const uint8_t*)line.c_str(), line.size());

   return decode(refVec);
}

////////////////////////////////////////////////////////////////////////////////
BackupEasy16DecodeResult BackupEasy16::decode(const vector<BinaryDataRef>& lines)
{
   if (lines.size() == 0)
      throw runtime_error("empty easy16 code");

   //setup character to value lookup map
   map<char, uint8_t> easy16Vals;
   for (unsigned i=0; i<e16chars_.size(); i++)
      easy16Vals.emplace(e16chars_[i], i);

   auto checkSpace = [](const char* str)->bool
   {
      if (str[0] == ' ')
         return false;
      
      return true;
   };

   auto decodeCharacters = [&easy16Vals](
      uint8_t& result, const char* str)->void
   {
      //convert characters to value, ignore effect of invalid ones
      result = 0;
      auto iter1 = easy16Vals.find(str[0]);
      if (iter1 != easy16Vals.end())
         result = iter1->second << 4;

      auto iter2 = easy16Vals.find(str[1]);
      if (iter2 != easy16Vals.end())
         result += iter2->second;      
   };

   /*
   Converts line to binary, appends into result.
   Returns the hash index matching the checksum.
   
   Error values:
    . -1: checksum mismatch
    . -2: invalid checksum data
    . -3: not enough room in  the result buffer
   */
   auto decodeLine = [&checkSpace, &decodeCharacters](
      uint8_t* result, size_t& len, 
      const BinaryDataRef& line, BinaryData& checksum)->int
   {
      auto maxlen = len;
      len = 0;
      auto ptr = line.toCharPtr();

      unsigned i=0;
      for (; i<line.getSize() - (EASY16_CHECKSUM_LEN * 2); i++)
      {
         //skip spaces
         if (!checkSpace(ptr + i))
            continue;

         if (len >= maxlen)
            return -3;
         
         decodeCharacters(result[len], ptr + i);

         //increment result length
         ++len;

         //increment i to skip 2 characters
         ++i;
      }

      //grab checksum
      checksum.resize(EASY16_CHECKSUM_LEN);
      uint8_t* checksumPtr = checksum.getPtr();
      size_t checksumLen = 0;
      for (; i<line.getSize(); i++)
      {
         //skip spaces
         if (!checkSpace(ptr + i))
            continue;

         if (checksumLen >= EASY16_CHECKSUM_LEN)
            return -2;
         
         decodeCharacters(*(checksumPtr + checksumLen), ptr + i);
         ++checksumLen;
         ++i;
      }

      if (checksumLen != EASY16_CHECKSUM_LEN)
         return -2;

      //hash data
      BinaryDataRef decodedChunk(result, len);
      return verifyChecksum(decodedChunk, checksum);
   };

   size_t fullSize = lines.size() * EASY16_LINE_LENGTH;
   SecureBinaryData data(fullSize);
   vector<int> checksumIndexes;
   vector<BinaryData> checksums(lines.size());

   auto dataPtr = data.getPtr();
   size_t pos = 0;
   for (unsigned i=0; i<lines.size(); i++)
   {
      const auto& line = lines[i];
      size_t len = fullSize - pos;
      auto result = decodeLine(dataPtr + pos, len, line, checksums[i]);

      pos += len;

      switch (result)
      {
      case -1: //could not match checksum
      case -2: //invalid checksum length
      {
         checksumIndexes.push_back(result);
         break;
      }

      case -3:
      {
         //ran out of space in result buffer
         throw runtime_error("easy16 decode buffer is too short");
      }

      default:
         //valid checksum
         checksumIndexes.push_back(result);
      }

      if (len > EASY16_LINE_LENGTH)
      {
         throw runtime_error("easy16 line is too long");
      }
      else if (len < EASY16_LINE_LENGTH)
      {
         if (i != lines.size() - 1)
            throw runtime_error("easy16 line is too short");

         //last line doesn't have to be EASY16_LINE_LENGTH bytes long
         data.resize(pos);
      }
   }

   BackupEasy16DecodeResult result;
   result.checksumIndexes_ = move(checksumIndexes);
   result.checksums_ = move(checksums);
   result.data_ = move(data);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
bool BackupEasy16::repair(BackupEasy16DecodeResult& faultyBackup)
{
   //sanity check
   if (faultyBackup.data_.empty() || faultyBackup.checksums_.empty() ||
      faultyBackup.checksums_.size() != faultyBackup.checksumIndexes_.size())
   {
      throw Easy16RepairError("invalid arugments");
   }

   //is there an error?
   bool hasError = false;
   set<int> validIndexes;
   for (auto index : faultyBackup.checksumIndexes_)
   {
      auto indexIter = eligibleIndexes_.find(index);
      if (indexIter == eligibleIndexes_.end())
      {
         if (index == EASY16_INVALID_CHECKSUM_INDEX)
         {
            hasError = true;
            continue;
         }
         else
         {
            //these errors cannot be repaired
            throw Easy16RepairError("fatal checksum error");
         }
      }

      validIndexes.insert(index);
   }

   if (!hasError && validIndexes.size() == 1)
      return true;

   /* checksum search function */
   auto searchChecksum = [](
      const BinaryDataRef& data, const BinaryData& checksum, uint8_t hint)
      ->map<unsigned, map<unsigned, set<uint8_t>>>
   {
      map<unsigned, map<unsigned, set<uint8_t>>> result;

      //copy the data
      SecureBinaryData copied(data);

      //run through each byte of data
      for (unsigned i=0; i<data.getSize(); i++)
      {
         auto& valRef = copied.getPtr()[i];
         auto originalValue = valRef;

         for (unsigned y=0; y<256; y++)
         {
            if (y == originalValue)
               continue;

            //set new value
            valRef = y;

            //check it
            if (hint != EASY16_INVALID_CHECKSUM_INDEX)
            {
               auto hash = getHash(copied, hint);
               if (hash.getSliceRef(0, 2) == checksum)
               {
                  auto& chkVal = result[hint];
                  auto& pos = chkVal[i];
                  pos.insert(y);
               }
            }
            else
            {
               //check all eligible indexes
               for (const auto& indexCandidate : eligibleIndexes_)
               {
                  auto hash = getHash(copied, indexCandidate);
                  if (hash.getSliceRef(0, 2) == checksum)
                  {
                     auto& chkVal = result[indexCandidate];
                     auto& pos = chkVal[i];
                     pos.insert(y);
                  }
               }
            }
         }

         //reset value
         valRef = originalValue;
      }

      return result;
   };


   //what kind of error? can it be repaired?
   if (validIndexes.size() > 1)
   {
      //there's more than one checksum index, cannot proceed
      throw Easy16RepairError("checksum results mismatch");
   }
   else if (validIndexes.size() == 1)
   {
      /*
      Some lines are invalid but we have at least one that is valid. This 
      allows us to search for the expected checksum index in the invalid 
      lines (they should all match)
      */
      unsigned hint = *validIndexes.begin();

      BinaryRefReader brr(faultyBackup.data_);
      for (unsigned i=0; i<faultyBackup.checksumIndexes_.size(); i++)
      {
         if (faultyBackup.checksumIndexes_[i] != EASY16_INVALID_CHECKSUM_INDEX)
         {
            brr.advance(
               std::min(size_t(EASY16_LINE_LENGTH), brr.getSizeRemaining()));
            faultyBackup.repairedIndexes_.push_back(hint);

            continue;
         }

         auto dataRef = brr.get_BinaryDataRef(
            std::min(size_t(EASY16_LINE_LENGTH), brr.getSizeRemaining()));

         auto repairResults = 
            searchChecksum(dataRef, faultyBackup.checksums_[i], hint);

         if (repairResults.size() != 1)
            return false;

         auto repairIter = repairResults.begin();
         if (repairIter->second.size() != 1)
            return false;

         const auto& repairPair = *repairIter->second.begin();
         if (repairPair.second.size() != 1)
            return false;

         //apply repair on the fly
         auto ptr = (uint8_t*)(dataRef.getPtr() + repairPair.first);
         *ptr = *repairPair.second.begin();

         //update the repaired line checksum result
         faultyBackup.repairedIndexes_.push_back(hint);
      }
   }
   else
   {
      /*
      All lines are invalid. There is no indication of what the checksum index 
      ought to be. We have to search all lines for a matching index.
      */
      vector<map<unsigned, map<unsigned, set<uint8_t>>>> resultMap;

      BinaryRefReader brr(faultyBackup.data_);
      for (unsigned i=0; i<faultyBackup.checksumIndexes_.size(); i++)
      {
         auto dataRef = brr.get_BinaryDataRef(
            std::min(size_t(EASY16_LINE_LENGTH), brr.getSizeRemaining()));

         auto repairResults = 
            searchChecksum(dataRef, faultyBackup.checksums_[i], -1);

         if (repairResults.empty())
            return false;

         resultMap.emplace_back(move(repairResults));
      }

      //compare results for index matches
      map<unsigned, set<unsigned>> chksumIndexes;
      for (unsigned i=0; i<resultMap.size(); i++)
      {
         const auto& lineResult = resultMap[i];
         for (const auto& lineData : lineResult)
         {
            //skip on multiple solutions
            if (lineData.second.size() != 1)
               continue;

            if (lineData.second.begin()->second.size() != 1)
               continue;
            
            auto& chkValueSet = chksumIndexes[lineData.first];
            chkValueSet.insert(i);
         }
      }

      //only those indexes represented across all lines are eligible
      auto iter = chksumIndexes.begin();
      while (iter != chksumIndexes.end())
      {
         if (iter->second.size() != faultyBackup.checksumIndexes_.size())
         {
            chksumIndexes.erase(iter++);
            continue;
         }

         ++iter;
      }

      //fail if we have several repair candidates
      if (chksumIndexes.size() != 1)
         return false;

      //repair the data
      brr.resetPosition();
      auto repairIndex = chksumIndexes.begin()->first;
      for (unsigned i=0; i<faultyBackup.checksumIndexes_.size(); i++)
      {
         const auto& lineResult = resultMap[i];
         auto lineIter = lineResult.find(repairIndex);
         if (lineIter == lineResult.end())
            return false;

         //do not tolerate multiple solutions
         if (lineIter->second.size() != 1)
            return false;
         
         auto valIter = lineIter->second.begin();
         if (valIter->second.size() != 1)
            return false;

         auto dataRef = brr.get_BinaryDataRef(
            std::min(size_t(EASY16_LINE_LENGTH), brr.getSizeRemaining()));
         
         auto ptr = (uint8_t*)(dataRef.getPtr() + valIter->first);
         *ptr = *valIter->second.begin();

         //update the repaired line checksum result
         faultyBackup.repairedIndexes_.push_back(repairIndex);
      }
   }

   return true;
}  

////////////////////////////////////////////////////////////////////////////////
////
//// SecurePrint
////
////////////////////////////////////////////////////////////////////////////////
SecurePrint::SecurePrint()
{
   //setup aes IV and kdf
   auto iv32 = BtcUtils::getHash256(
      (const uint8_t*)digits_pi_.c_str(), digits_pi_.size());
   iv16_ = move(iv32.getSliceCopy(0, AES_BLOCK_SIZE));

   salt_ = move(BtcUtils::getHash256(
      (const uint8_t*)digits_e_.c_str(), digits_e_.size()));
   kdf_.usePrecomputedKdfParams(kdfBytes_, 1, salt_);
}

////////////////////////////////////////////////////////////////////////////////
pair<SecureBinaryData, SecureBinaryData> SecurePrint::encrypt(
   const SecureBinaryData& root, const SecureBinaryData& chaincode)
{
   /*
   1. generate passphrase from root and chaincode
   */

   //sanity check
   if (root.getSize() != 32)
   {
      LOGERR << "invalid root size for secureprint";
      throw runtime_error("invalid root size for secureprint");
   }

   SecureBinaryData hmacPhrase(64);
   if (chaincode.empty())
   {
      /*
      The passphrase is the hmac of the root and the chaincode. If the 
      chaincode is empty, we only hmac the root.
      */

      auto rootHash = BtcUtils::getHash256(root);
      BtcUtils::getHMAC512(
         rootHash.getPtr(), rootHash.getSize(),
         salt_.getPtr(), salt_.getSize(),
         hmacPhrase.getPtr());
   }
   else
   {
      /*
      Concatenate root and chaincode then hmac
      */

      SecureBinaryData rootCopy = root;
      rootCopy.append(chaincode);

      auto rootHash = BtcUtils::getHash256(rootCopy);
      BtcUtils::getHMAC512(
         rootHash.getPtr(), rootHash.getSize(),
         salt_.getPtr(), salt_.getSize(),
         hmacPhrase.getPtr());
   }

   //passphrase is first 7 bytes of the hmac
   BinaryWriter bw;
   bw.put_BinaryDataRef(hmacPhrase.getSliceRef(0, 7));
   auto passChecksum = BtcUtils::getHash256(bw.getData());
   bw.put_uint8_t(passChecksum[0]);

   passphrase_ = SecureBinaryData::fromString(
      BtcUtils::base58_encode(bw.getData()));

   /*
   2. extend the passphrase
   */

   auto encryptionKey = kdf_.DeriveKey(passphrase_);

   /*
   3. Encrypt the data. We use the libbtc call directly because
      we do not want padding
   */

   auto encrypt = [this, &encryptionKey](
      const SecureBinaryData& cleartext, SecureBinaryData& result)->bool
   {
      //this exclusively encrypt 32 bytes of data
      if (cleartext.getSize() != 32)
         return false;

      //make sure result buffer is large enough
      result.resize(32);

      //encrypt with CBC
      auto encrLen = aes256_cbc_encrypt(
         encryptionKey.getPtr(), iv16_.getPtr(),
         cleartext.getPtr(), cleartext.getSize(),
         0, //no padding
         result.getPtr());

      if (encrLen != 32)
         return false;

      return true;
   };

   pair<SecureBinaryData, SecureBinaryData> result;
   if (!encrypt(root, result.first))
   {
      LOGERR << "SecurePrint encryption failure";
      throw runtime_error("SecurePrint encryption failure");
   }

   if (!chaincode.empty())
   {
      if (!encrypt(chaincode, result.second))      
      {
         LOGERR << "SecurePrint encryption failure";
         throw runtime_error("SecurePrint encryption failure");
      }
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData SecurePrint::decrypt(
   const SecureBinaryData& ciphertext, const BinaryDataRef passphrase) const
{
   //check passphrase checksum
   string passStr(passphrase.toCharPtr(), passphrase.getSize());
   BinaryData passBin;
   try
   {
      passBin = move(BtcUtils::base58_decode(passStr));
   }
   catch (const exception&)
   {
      LOGERR << "invalid SecurePrint passphrase";
      throw runtime_error("invalid SecurePrint passphrase");
   }

   if (passBin.getSize() != 8)
   {
      LOGERR << "invalid SecurePrint passphrase";
      throw runtime_error("invalid SecurePrint passphrase");
   }

   BinaryRefReader brr(passBin);
   auto passBase = brr.get_BinaryDataRef(7);
   auto checksum = brr.get_uint8_t();

   auto passHash = BtcUtils::getHash256(passBase);
   if (passHash[0] != checksum)
   {
      LOGERR << "invalid SecurePrint passphrase";
      throw runtime_error("invalid SecurePrint passphrase");
   }

   if (ciphertext.getSize() < 32)
   {
      LOGERR << "invalid ciphertext size for SecurePrint";
      throw runtime_error("invalid ciphertext size for SecurePrint");
   }
   
   //kdf the passphrase
   auto encryptionKey = kdf_.DeriveKey(passphrase);

   //
   auto decrypt = [this, &encryptionKey](
      const BinaryDataRef& ciphertext, SecureBinaryData& result)->bool
   {
      //works exclusively on 32 byte packets
      if (ciphertext.getSize() != 32)
         return false;

      result.resize(32);

      auto size = aes256_cbc_decrypt(
         encryptionKey.getPtr(), iv16_.getPtr(),
         ciphertext.getPtr(), ciphertext.getSize(),
         0, //no padding
         result.getPtr());

      if (size != 32)
         return false;

      return true;
   };

   //decrypt the root
   SecureBinaryData result;
   if (!decrypt(ciphertext, result))
   {
      LOGERR << "failed to decrypt SecurePrint string";
      throw runtime_error("failed to decrypt SecurePrint string");
   }

   return result;
}

////////////////////////////////////////////////////////////////////////////////
////
//// Helpers
////
////////////////////////////////////////////////////////////////////////////////
WalletRootData Helpers::getRootData(
   shared_ptr<AssetWallet_Single> wltSingle)
{
   WalletRootData rootData;
   rootData.wltId_ = wltSingle->getID();
   auto root = dynamic_pointer_cast<AssetEntry_Single>(
      wltSingle->getRoot());

   //lock wallet
   auto lock = wltSingle->lockDecryptedContainer();

   //check root
   auto rootBip32 = dynamic_pointer_cast<AssetEntry_BIP32Root>(root);
   if (rootBip32 == nullptr)
   {
      /*
      This isn't a bip32 root, therefor it's an Armory root. It may carry a
      dedicated chaincode, let's check for that.
      */

      auto root135 = dynamic_pointer_cast<AssetEntry_ArmoryLegacyRoot>(root);
      if (root135 == nullptr)
      {
         LOGERR << "unexpected wallet root type";
         throw runtime_error("unexpected wallet root type");
      }

      rootData.root_ = wltSingle->getDecryptedPrivateKeyForAsset(root);
      rootData.type_ = BackupType::Armory135;

      const auto& wltChaincode = root135->getChaincode();
      if (!wltChaincode.empty())
      {
         /*
         If the root carries a chaincode, it may be non deterministic. Let's 
         check.
         */

         auto computedChaincode = 
            BtcUtils::computeChainCode_Armory135(rootData.root_);
         
         if (computedChaincode != wltChaincode)
            rootData.secondaryData_ = wltChaincode;
      }
   }
   else
   {
      //bip32 wallet, grab the seed instead
      auto seedPtr = wltSingle->getEncryptedSeed();
      if (seedPtr == nullptr)
      {
         /*
         For now, abort if bip32 wallet is missing its seed. May implement
         root backups for bip32 wallets (privkey + chaincode) in the future.
         */
         rootData.type_ = BackupType::BIP32_Root;
         return rootData;
      }

      rootData.type_ = BackupType::BIP32_Seed_Structured;

      //decrypt the seed
      rootData.root_ = wltSingle->getDecryptedValue(seedPtr);
   }

   return rootData;
}

////////////////////////////////////////////////////////////////////////////////
WalletRootData Helpers::getRootData_Multisig(
   shared_ptr<AssetWallet_Multisig>)
{
   throw runtime_error("TODO: needs implementation");
}

////////////////////////////////////////////////////////////////////////////////
WalletBackup Helpers::getWalletBackup(
   std::shared_ptr<AssetWallet_Single> wltPtr, BackupType type)
{
   auto rootData = getRootData(wltPtr);
   return getWalletBackup(rootData, type);
}

////////////////////////////////////////////////////////////////////////////////
WalletBackup Helpers::getWalletBackup(WalletRootData& rootData, 
   BackupType forceBackupType)
{
   //apply secureprint
   SecurePrint sp;
   auto encrRoot = sp.encrypt(rootData.root_, rootData.secondaryData_);
      
   WalletBackup backup;

   if (forceBackupType != BackupType::Invalid)
      rootData.type_ = forceBackupType;

   unsigned mode = UINT32_MAX;
   switch (rootData.type_)
   {
   case BackupType::Armory135:
   case BackupType::BIP32_Seed_Structured:
   case BackupType::BIP32_Root:
   case BackupType::BIP32_Seed_Virgin:
   {
      mode = unsigned(rootData.type_);
      break;
   }

   default:
      break;
   }

   if (mode == UINT32_MAX)
   {
      LOGERR << "cannot create backup for unknown wallet type";
      throw runtime_error("cannot create backup for unknown wallet type");
   }

   //cleartext root easy16
   backup.rootClear_ = move(BackupEasy16::encode(rootData.root_, mode));

   //encrypted root easy16
   backup.rootEncr_ = move(BackupEasy16::encode(encrRoot.first,mode));

   if (!rootData.secondaryData_.empty())
   {
      //cleartext chaincode easy16
      backup.chaincodeClear_ = move(BackupEasy16::encode(
         rootData.secondaryData_, mode));

      //encrypted chaincode easy16
      backup.chaincodeEncr_ = move(BackupEasy16::encode(
         encrRoot.second, mode));
   }

   backup.spPass_ = sp.getPassphrase();
   backup.wltId_ = rootData.wltId_;

   return backup;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet> Helpers::restoreFromBackup(
   const vector<string>& data, const BinaryDataRef passphrase,
   const string& homedir, const UserPrompt& callerPrompt)
{
   vector<BinaryDataRef> bdrVec;
   for (const auto& str : data)
      bdrVec.emplace_back((const uint8_t*)str.c_str(), str.size());

   return restoreFromBackup(bdrVec, passphrase, homedir, callerPrompt);
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<AssetWallet> Helpers::restoreFromBackup(
   const vector<BinaryDataRef>& data, const BinaryDataRef passphrase,
   const string& homedir, const UserPrompt& callerPrompt)
{
   SecureBinaryData promptDummy;
   bool hasSecondaryData = false;

   //decode the data
   BackupEasy16DecodeResult primaryData, secondaryData;
   if (data.size() == 2)
   {
      primaryData = BackupEasy16::decode(data);
   }
   else if (data.size() > 2)
   {
      vector<BinaryDataRef> primarySlice;
      primarySlice.insert(primarySlice.end(), data.begin(), data.begin() + 2);
      primaryData = BackupEasy16::decode(primarySlice);

      vector<BinaryDataRef> secondarySlice;
      secondarySlice.insert(secondarySlice.end(), data.begin() + 2, data.end());
      secondaryData = BackupEasy16::decode(secondarySlice);

      hasSecondaryData = true;
   }
   else
   {
      callerPrompt(RestorePromptType::FormatError, {}, promptDummy);
      return nullptr;
   }
   
   if (primaryData.checksumIndexes_.empty() || 
      (hasSecondaryData && secondaryData.checksumIndexes_.empty()))
   {
      callerPrompt(RestorePromptType::Failure, {}, promptDummy);
      return nullptr;
   }

   //sanity check
   auto checksumIndexes = primaryData.checksumIndexes_;
   if (hasSecondaryData)
   {
      checksumIndexes.insert(checksumIndexes.end(), 
         secondaryData.checksumIndexes_.begin(), 
         secondaryData.checksumIndexes_.end());
   }

   bool checksumErrors;
   int firstIndex;

   auto processChecksumIndexes = [&checksumErrors, &firstIndex](
      const vector<int>& checksumValues)
   {
      /*
      Set the common checksum result value and make sure all lines
      carry the same value.
      */

      checksumErrors = false;
      firstIndex = checksumValues[0];
      for (const auto& result : checksumValues)
      {
         if (result < 0 || result != firstIndex)
         {
            checksumErrors = true;
            break;
         }
      }
   };
   processChecksumIndexes(checksumIndexes);

   if (checksumErrors)
   {
      auto reportError = [&callerPrompt, &checksumIndexes](void)
      {
         //prompt caller if we can't repair the error and throw
         SecureBinaryData dummy;
         callerPrompt(
            RestorePromptType::ChecksumError, checksumIndexes, dummy);
         throw RestoreUserException("checksum error");             
      };

      vector<int> repairedIndexes;

      auto repairData = [&reportError, &repairedIndexes](
         BackupEasy16DecodeResult& data)
      {
         //attempt to repair the data
         auto result = BackupEasy16::repair(data);
         if (!result)
            reportError();
         
         if (data.repairedIndexes_.size() !=
            data.checksumIndexes_.size())
            reportError();

         repairedIndexes.insert(repairedIndexes.end(), 
            data.repairedIndexes_.begin(),
            data.repairedIndexes_.end());
      };

      //found some checksum errors, attempt to auto repair
      repairData(primaryData);
      if (hasSecondaryData)
         repairData(secondaryData);

      //check the repaired checksum result values
      processChecksumIndexes(repairedIndexes);

      if (checksumErrors)
         reportError();
   }

   //check for encryption
   if (!passphrase.empty())
   {
      try
      {
         SecurePrint sp;
         auto decryptedData = sp.decrypt(primaryData.data_, passphrase);
         primaryData.data_ = move(decryptedData);

         if (hasSecondaryData)
         {
            auto decryptedData = sp.decrypt(secondaryData.data_, passphrase);
            secondaryData.data_ = move(decryptedData);
         }
      }
      catch (const exception&)
      {
         //prompt caller on decrypt error and return
         callerPrompt(RestorePromptType::DecryptError, {}, promptDummy);
         throw RestoreUserException("invalid SP pass");       
      }
   }

   auto computeWalletId = [](
      const SecureBinaryData& root, const SecureBinaryData& chaincode)
      ->string
   {
      auto chaincodeCopy = chaincode;
      if (chaincodeCopy.empty())
         chaincodeCopy = BtcUtils::computeChainCode_Armory135(root);

      auto derScheme = 
         make_shared<DerivationScheme_ArmoryLegacy>(chaincodeCopy);

      auto pubkey = CryptoECDSA().ComputePublicKey(root);
      auto asset_single = make_shared<AssetEntry_Single>(
         Armory::Wallets::AssetId::getRootAssetId(), pubkey, nullptr);

      return AssetWallet_Single::computeWalletID(derScheme, asset_single);
   };

   auto promptForPassphrase = [&callerPrompt](
      SecureBinaryData& passphrase, SecureBinaryData& control)->bool
   {
      //prompt for wallet passphrase
      if (!callerPrompt(RestorePromptType::Passphrase, {}, passphrase))
         return false;

      //prompt for control passphrase
      if (!callerPrompt(RestorePromptType::Control, {}, control))
         return false;

      return true;
   };

   //generate wallet
   shared_ptr<AssetWallet> wallet;
   switch (firstIndex)
   {
   case BackupType::Armory135:
   {
      /*legacy armory wallet*/
      
      auto id = SecureBinaryData::fromString(
         computeWalletId(primaryData.data_, secondaryData.data_));
      if (!callerPrompt(RestorePromptType::Id, checksumIndexes, id))
         throw RestoreUserException("user rejected id");

      //prompt for passwords
      SecureBinaryData pass, control;
      if (!promptForPassphrase(pass, control))
         throw RestoreUserException("user did not provide passphrase");

      //create wallet
      wallet = AssetWallet_Single::createFromPrivateRoot_Armory135(
         homedir,
         primaryData.data_,
         secondaryData.data_,
         pass, control,
         WALLET_RESTORE_LOOKUP);

      break;
   }

   //bip32 wallets
   case BackupType::BIP32_Seed_Structured:
   {
      /*BIP32 wallet with BIP44/49/84 accounts*/

      //create root node from seed
      BIP32_Node rootNode;
      rootNode.initFromSeed(primaryData.data_);

      //compute id and present to caller
      auto id = SecureBinaryData::fromString(
         computeWalletId(rootNode.getPrivateKey(), rootNode.getChaincode()));
      if (!callerPrompt(RestorePromptType::Id, checksumIndexes, id))
         throw RestoreUserException("user rejected id");

      //prompt for passwords
      SecureBinaryData pass, control;
      if (!promptForPassphrase(pass, control))
         throw RestoreUserException("user did not provide passphrase");

      //create wallet
      wallet = AssetWallet_Single::createFromSeed_BIP32(
         homedir,
         primaryData.data_,
         pass, control,
         WALLET_RESTORE_LOOKUP);

      break;
   }

   case BIP32_Seed_Virgin:
   {
      /*empty BIP32 wallet*/
      
      //create root node from seed
      BIP32_Node rootNode;
      rootNode.initFromSeed(primaryData.data_);

      //compute id and present to caller
      auto id = SecureBinaryData::fromString(
         computeWalletId(rootNode.getPrivateKey(), rootNode.getChaincode()));
      if (!callerPrompt(RestorePromptType::Id, checksumIndexes, id))
         throw RestoreUserException("user rejected id");

      //prompt for passwords
      SecureBinaryData pass, control;
      if (!promptForPassphrase(pass, control))
         throw RestoreUserException("user did not provide passphrase");

      //create wallet
      wallet = AssetWallet_Single::createFromSeed_BIP32_Blank(
         homedir,
         primaryData.data_,
         pass, control);

      break;
   }

   //case BackupType::BIP32_Root:

   default:
      callerPrompt(RestorePromptType::TypeError, {}, promptDummy);
   }

   return wallet;
}