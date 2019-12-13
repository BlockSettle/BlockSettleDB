////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 20119, goatpig.                                             //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <mutex>
#include <map>

#include "BinaryData.h"
#include "EncryptionUtils.h"

#define CHANGE_PASS_FLAG BinaryData::fromString("change-pass")

class TerminalPassphrasePrompt
{
private:
    std::mutex mu_;
    std::map<BinaryData, unsigned> countMap_;

    const std::string verbose_;

private:  
    TerminalPassphrasePrompt(const std::string& verbose) :
        verbose_(verbose)
    {
        if (verbose_.size() == 0)
            throw std::runtime_error("empty verbose is not allowed");
    }
    
    SecureBinaryData prompt(const std::set<BinaryData>& idSet);
    SecureBinaryData promptForPassphrase(
        const std::set<BinaryData>& idSet);
    SecureBinaryData promptNewPass();

    static void setEcho(bool);

public:
    static PassphraseLambda getLambda(const std::string&);
};
