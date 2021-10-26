////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 20119, goatpig.                                             //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <mutex>
#include <map>

#include "SecureBinaryData.h"
#include "Wallets/WalletIdTypes.h"
#include "Wallets/PassphraseLambda.h"

#define CHANGE_PASS_FLAG BinaryData::fromString("change-pass     ")

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
        if (verbose_.size() == 0)
            throw std::runtime_error("empty verbose is not allowed");
    }
    
    SecureBinaryData prompt(
        const std::set<Armory::Wallets::EncryptionKeyId>& idSet);
    SecureBinaryData promptForPassphrase(
        const std::set<Armory::Wallets::EncryptionKeyId>& idSet);
    SecureBinaryData promptNewPass();

    static void setEcho(bool);

public:
    static PassphraseLambda getLambda(const std::string&);
};
