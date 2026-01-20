////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019-2025, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <mutex>
#include <map>

#include "Utils/SecureBinaryData.h"
#include "Wallets/WalletIdTypes.h"
#include "Wallets/GetPassphrase.h"

class TerminalPassphrasePrompt
{
private:
   std::mutex mu_;
   std::map<Armory::Wallets::EncryptionKeyId, unsigned> countMap_;
   const std::string verbose_;

private:
   TerminalPassphrasePrompt(const std::string& verbose) :
      verbose_(verbose)
   {
      if (verbose_.empty()) {
         throw std::runtime_error("empty verbose is not allowed");
      }
   }

   SecureBinaryData prompt(
      const std::set<Armory::Wallets::EncryptionKeyId>&);
   SecureBinaryData promptForPassphrase(
      const std::set<Armory::Wallets::EncryptionKeyId>&);
   SecureBinaryData promptNewPass(void);

   static void setEcho(bool);

public:
   static Armory::Passphrase::UnlockFunc getLambda(const std::string&);
};
