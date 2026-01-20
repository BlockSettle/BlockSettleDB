////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "Utils/BinaryData.h"

namespace Armory
{
   enum class ScriptPrefix : uint8_t;
}

class TxOutScriptRef
{
public:
   struct Comparator
   {
      using is_transparent = void;
      bool operator()(const TxOutScriptRef&, const TxOutScriptRef&) const;
   };

private:
   const Armory::ScriptPrefix type_;
   BinaryDataRef scriptRef_;
   BinaryData scriptCopy_;

private:
   TxOutScriptRef(Armory::ScriptPrefix, const BinaryDataRef&);

public:
   TxOutScriptRef(Armory::ScriptPrefix, BinaryData&);
   TxOutScriptRef(const TxOutScriptRef&);
   TxOutScriptRef(TxOutScriptRef&&);

   TxOutScriptRef& operator=(const TxOutScriptRef&);
   bool operator==(const TxOutScriptRef&) const;
   bool operator<(const TxOutScriptRef&) const;

   BinaryData getScrAddr(void) const;
   BinaryDataRef getScrRef(void) const;
   static TxOutScriptRef fromRef(Armory::ScriptPrefix, const BinaryDataRef&);
   static TxOutScriptRef fromScrAddr(BinaryDataRef);
};

namespace std
{
   template<> struct hash<TxOutScriptRef>
   {
      std::size_t operator()(const TxOutScriptRef&) const;
   };
};
