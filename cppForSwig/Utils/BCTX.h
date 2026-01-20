////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2025, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <vector>
#include "BinaryData.h"

class BCTX
{
   using OffsetAndSize = std::pair<size_t, size_t>;

private:
   mutable BinaryData txHash_;

public:
   const uint8_t* data_;
   const size_t size_;

   uint32_t version_;
   uint32_t lockTime_;

   bool usesWitness_ = false;

   std::vector<OffsetAndSize> txins_;
   std::vector<OffsetAndSize> txouts_;
   std::vector<OffsetAndSize> witnesses_;

   bool isCoinbase_ = false;

public:
   BCTX(const uint8_t*, size_t);
   BCTX(const BinaryDataRef&);

   const BinaryData& getHash(void) const;
   BinaryData&& moveHash(void);

   BinaryDataRef getTxInRef(unsigned) const;
   BinaryDataRef getTxOutRef(unsigned) const;

   static std::shared_ptr<BCTX> parse(
      BinaryRefReader, unsigned=UINT32_MAX);
   static std::shared_ptr<BCTX> parse(
      const uint8_t*, size_t, unsigned=UINT32_MAX);
};
