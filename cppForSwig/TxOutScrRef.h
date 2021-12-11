////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2021, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_TXOUTSCRIPTREF
#define _H_TXOUTSCRIPTREF

#include "BinaryData.h"
#include "BitcoinSettings.h"

struct TxOutScriptRef
{
public:
   SCRIPT_PREFIX type_ = SCRIPT_PREFIX_NONSTD;
   BinaryDataRef scriptRef_;
   BinaryData scriptCopy_;

public:
   TxOutScriptRef(void);
   TxOutScriptRef(const TxOutScriptRef&);
   TxOutScriptRef(TxOutScriptRef&&);

   TxOutScriptRef& operator=(const TxOutScriptRef&);
   bool operator==(const TxOutScriptRef&) const;
   bool operator<(const TxOutScriptRef&) const;

   void copyFrom(const TxOutScriptRef&);
   void setRef(const BinaryDataRef& bd);

   BinaryData getScrAddr(void) const;
};

namespace std
{
   template<> struct hash<TxOutScriptRef>
   {
      std::size_t operator()(const TxOutScriptRef&) const;
   };
};


#endif
