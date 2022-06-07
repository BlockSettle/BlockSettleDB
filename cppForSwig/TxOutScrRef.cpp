////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2016-2021, goatpig.                                         //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "TxOutScrRef.h"
#include "BinaryData.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
TxOutScriptRef::TxOutScriptRef()
{}

////////////////////////////////////////////////////////////////////////////////
TxOutScriptRef::TxOutScriptRef(const TxOutScriptRef& outscr)
{
   copyFrom(outscr);
}

////////////////////////////////////////////////////////////////////////////////
TxOutScriptRef::TxOutScriptRef(TxOutScriptRef&& outscr)
{
   type_ = std::move(outscr.type_);
   if (outscr.scriptCopy_.getSize() > 0)
   {
      scriptCopy_ = std::move(outscr.scriptCopy_);
      outscr.scriptRef_.setRef(scriptCopy_);
   }

   scriptRef_ = std::move(outscr.scriptRef_);
}

////////////////////////////////////////////////////////////////////////////////
void TxOutScriptRef::copyFrom(const TxOutScriptRef& outscr)
{
   type_ = outscr.type_;
   if(outscr.scriptCopy_.getSize())
   {
      scriptCopy_ = outscr.scriptCopy_;
      scriptRef_.setRef(scriptCopy_);
   }
   else
   {
      scriptRef_ = outscr.scriptRef_;
   }
}

////////////////////////////////////////////////////////////////////////////////
TxOutScriptRef& TxOutScriptRef::operator=(const TxOutScriptRef& rhs)
{
   if(this !=  &rhs)
      copyFrom(rhs);
   return *this;
}

////////////////////////////////////////////////////////////////////////////////
bool TxOutScriptRef::operator== (const TxOutScriptRef& rhs) const
{
   if (this->type_ != rhs.type_)
      return false;

   return this->scriptRef_ == rhs.scriptRef_;
}

////////////////////////////////////////////////////////////////////////////////
bool TxOutScriptRef::operator< (const TxOutScriptRef& rhs) const
{
   if (this->type_ == rhs.type_)
      return this->scriptRef_ < rhs.scriptRef_;
   else
      return this->type_ < rhs.type_;
}

////////////////////////////////////////////////////////////////////////////////
void TxOutScriptRef::setRef(const BinaryDataRef& bd)
{
   type_ = (SCRIPT_PREFIX)bd.getPtr()[0];
   scriptRef_ = bd.getSliceRef(1, bd.getSize() - 1);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData TxOutScriptRef::getScrAddr(void) const
{
   BinaryWriter bw(1 + scriptRef_.getSize());
   bw.put_uint8_t(type_);
   bw.put_BinaryData(scriptRef_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
std::size_t hash<TxOutScriptRef>::operator()(const TxOutScriptRef& key) const
{
   std::hash<BinaryDataRef> bdrHashObj;
   return bdrHashObj(key.scriptRef_);
}
