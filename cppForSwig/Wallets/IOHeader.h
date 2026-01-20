////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "Progress.h"
#include "GetPassphrase.h"
#include <set>
#include <filesystem>
#include <chrono>

namespace Armory
{
   namespace Wallets
   {
      namespace IO
      {
         using namespace std::chrono_literals;

         struct ReadOnlyFileParams
         {
            const std::filesystem::path filePath;
            const Passphrase::UnlockFunc unlockFunc;
         };

         struct CreateFileParams
         {
            const std::filesystem::path filePath;
            const Passphrase::SetNew& setCtrlPassObj;

            ReadOnlyFileParams getOpenFileParams(void) const
            {
               return ReadOnlyFileParams{filePath, setCtrlPassObj.getUnlockFunc()};
            }
         };

         struct CreateWalletParams
         {
            const std::filesystem::path folder{"./"};

            //encrypts/unlocks private keys
            //2sec default unlock duration for private keys
            const Passphrase::SetNew setPrivPassObj;

            //encrypts/unlocks all data in the wallet
            const Passphrase::SetNew setCtrlPassObj;

            //to report on creation progress
            Progress::Func progressFunc=nullptr;

            //misc
            const size_t lookup{100};
            const std::string label{};
            const std::string description{};

            ////////
            CreateWalletParams(const std::filesystem::path& p,
               Passphrase::SetNew s1, Passphrase::SetNew s2,
               Progress::Func f, size_t l,
               const std::string& lbl={}, const std::string& descr={}) :
               folder{p}, setPrivPassObj(std::move(s1)),
               setCtrlPassObj(std::move(s2)),
               progressFunc(std::move(f)), lookup(l),
               label(lbl), description(descr)
            {}

            ////////
            CreateFileParams getCreateFileParams(const std::string& masterId,
               const std::string& suffix={"wallet"}) const
            {
               auto path = folder / std::filesystem::path{
                  "armory_" + masterId + "_" + suffix + ".lmdb"};
               return CreateFileParams{path, setCtrlPassObj};
            }
         };
      };
   };
};