////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2011-2015, Armory Technologies, Inc.                        //
//  Distributed under the GNU Affero General Public License (AGPL v3)         //
//  See LICENSE-ATI or http://www.gnu.org/licenses/agpl.html                  //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BinaryData.h"
#include "BtcUtils.h"
#include "EncryptionUtils.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
BinaryData::BinaryData(BinaryDataRef const & bdRef) 
{ 
   copyFrom(bdRef.getPtr(), bdRef.getSize());
}

////////////////////////////////////////////////////////////////////////////////
void BinaryData::copyFrom(BinaryDataRef const & bdr)
{
   copyFrom( bdr.getPtr(), bdr.getSize() );
}

////////////////////////////////////////////////////////////////////////////////
BinaryDataRef BinaryData::getRef(void) const
{
   return BinaryDataRef(getPtr(), getSize());
}

////////////////////////////////////////////////////////////////////////////////
BinaryData & BinaryData::append(BinaryDataRef const & bd2)
{
   if(bd2.getSize()==0) 
      return (*this);
   
   if(getSize()==0) 
      copyFrom(bd2.getPtr(), bd2.getSize());
   else
      data_.insert(data_.end(), bd2.getPtr(), bd2.getPtr()+bd2.getSize());

   return (*this);
}

/////////////////////////////////////////////////////////////////////////////
BinaryData & BinaryData::append(uint8_t const * str, size_t sz)
{
   BinaryDataRef appStr(str, sz);
   return append(appStr);
}

////////////////////////////////////////////////////////////////////////////////
int32_t BinaryData::find(BinaryDataRef const & matchStr, uint32_t startPos)
{
   int32_t finalAnswer = -1;
   if(matchStr.getSize()==0)
      return startPos;

   for(int32_t i=startPos; i<=(int32_t)getSize()-(int32_t)matchStr.getSize(); i++)
   {
      if(matchStr[0] != data_[i])
         continue;

      for(uint32_t j=0; j<matchStr.getSize(); j++)
      {
         if(matchStr[j] != data_[i+j])
            break;

         // If we are at this instruction and is the last index, it's a match
         if(j==matchStr.getSize()-1)
            finalAnswer = i;
      }

      if(finalAnswer != -1)
         break;
   }

   return finalAnswer;
}

////////////////////////////////////////////////////////////////////////////////
int32_t BinaryData::find(BinaryData const & matchStr, uint32_t startPos)
{
   BinaryDataRef bdrmatch(matchStr);
   return find(bdrmatch, startPos);
}


////////////////////////////////////////////////////////////////////////////////
bool BinaryData::contains(BinaryData const & matchStr, uint32_t startPos)
{
   return (find(matchStr, startPos) != -1);
}

////////////////////////////////////////////////////////////////////////////////
bool BinaryData::contains(BinaryDataRef const & matchStr, uint32_t startPos)
{
   return (find(matchStr, startPos) != -1);
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::startsWith(BinaryDataRef const & matchStr) const
{
   if(matchStr.getSize() > getSize())
      return false;

   for(uint32_t i=0; i<matchStr.getSize(); i++)
      if(matchStr[i] != (*this)[i])
         return false;

   return true;
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::startsWith(BinaryData const & matchStr) const
{
   if(matchStr.getSize() > getSize())
      return false;

   for(uint32_t i=0; i<matchStr.getSize(); i++)
      if(matchStr[i] != (*this)[i])
         return false;

   return true;
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::endsWith(BinaryDataRef const & matchStr) const
{
   size_t sz = matchStr.getSize();
   if(sz > getSize())
      return false;
   
   for(uint32_t i=0; i<sz; i++)
      if(matchStr[sz-(i+1)] != (*this)[getSize()-(i+1)])
         return false;

   return true;
}
/////////////////////////////////////////////////////////////////////////////
bool BinaryData::endsWith(BinaryData const & matchStr) const
{
   size_t sz = matchStr.getSize();
   if(sz > getSize())
      return false;
   
   for(uint32_t i=0; i<sz; i++)
      if(matchStr[sz-(i+1)] != (*this)[getSize()-(i+1)])
         return false;

   return true;
}

/////////////////////////////////////////////////////////////////////////////
BinaryDataRef BinaryData::getSliceRef(ssize_t start_pos, size_t nChar) const
{
   if(start_pos < 0) 
      start_pos = getSize() + start_pos;

   if((size_t)start_pos + nChar > getSize())
   {
      cerr << "getSliceRef: Invalid BinaryData access" << endl;
      return BinaryDataRef();
   }
   return BinaryDataRef( getPtr()+start_pos, nChar);
}

/////////////////////////////////////////////////////////////////////////////
BinaryData BinaryData::getSliceCopy(ssize_t start_pos, size_t nChar) const
{
   if(start_pos < 0) 
      start_pos = getSize() + start_pos;

   if((size_t)start_pos + nChar > getSize())
   {
      cerr << "getSliceCopy: Invalid BinaryData access" << endl;
      return BinaryData();
   }
   return BinaryData(getPtr()+start_pos, nChar);
}

/////////////////////////////////////////////////////////////////////////////
void BinaryData::createFromHex(const string& str)
{
   BinaryDataRef bdr((uint8_t*)str.c_str(), str.size());
   createFromHex(bdr);
}

/////////////////////////////////////////////////////////////////////////////
void BinaryData::createFromHex(BinaryDataRef const & bdr)
{
   static const uint8_t binLookupTable[256] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0, 0, 0, 0, 0, 0,
      0, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

   if (bdr.getSize() % 2 != 0)
   {
      LOGERR << "odd hexit count";
      throw runtime_error("odd hexit count");
   }
   size_t newLen = bdr.getSize() / 2;
   alloc(newLen);

   auto ptr = bdr.getPtr();
   for (size_t i = 0; i<newLen; i++)
   {
      uint8_t char1 = binLookupTable[*(ptr + 2 * i)];
      uint8_t char2 = binLookupTable[*(ptr + 2 * i + 1)];
      data_[i] = (char1 << 4) | char2;
   }
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::isZero() const
{
   bool isZero = true;
   auto ptr = getPtr();
   for (size_t i = 0; i < getSize(); i++)
   {
      if (ptr[i] != 0)
      {
         isZero = false;
         break;
      }
   }

   return isZero;
}

/////////////////////////////////////////////////////////////////////////////
uint64_t BinaryReader::get_var_int(uint8_t* nRead)
{
   uint32_t nBytes;
   uint64_t varInt = BtcUtils::readVarInt( 
      bdStr_.getPtr() + pos_, bdStr_.getSize() - pos_, &nBytes);
   if(nRead != NULL)
      *nRead = nBytes;
   pos_ += nBytes;
   return varInt;
}

/////////////////////////////////////////////////////////////////////////////
uint64_t BinaryRefReader::get_var_int(uint8_t* nRead)
{
   uint32_t nBytes;
   uint64_t varInt = BtcUtils::readVarInt( bdRef_.getPtr() + pos_, getSizeRemaining(), &nBytes);
   if(nRead != NULL)
      *nRead = nBytes;
   pos_.fetch_add(nBytes, memory_order_relaxed);
   return varInt;
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::operator==(BinaryDataRef const & bd2) const
{
   if (!empty())
   {
      if(getSize() != bd2.getSize())
         return false;

      return (memcmp(getPtr(), bd2.getPtr(), getSize()) == 0);
   }

   return bd2.empty();
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::operator<(BinaryDataRef const & bd2) const
{
   size_t minLen = min(getSize(), bd2.getSize());
   auto ref_ptr = bd2.getPtr();
   for (size_t i = 0; i<minLen; i++)
   {
      if (data_[i] == ref_ptr[i])
         continue;
      return data_[i] < ref_ptr[i];
   }
   return (getSize() < bd2.getSize());
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::operator<(BinaryData const & bd2) const
{
   size_t minLen = std::min(getSize(), bd2.getSize());
   for (size_t i = 0; i < minLen; i++)
   {
      if (data_[i] == bd2.data_[i])
         continue;
      return data_[i] < bd2.data_[i];
   }
   return (getSize() < bd2.getSize());
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryData::operator>(BinaryData const & bd2) const
{
   size_t minLen = min(getSize(), bd2.getSize());
   for (size_t i = 0; i < minLen; i++)
   {
      if (data_[i] == bd2.data_[i])
         continue;
      return data_[i] > bd2.data_[i];
   }
   return (getSize() > bd2.getSize());
}

/////////////////////////////////////////////////////////////////////////////
//
////BinaryDataRef
//
/////////////////////////////////////////////////////////////////////////////
bool BinaryDataRef::operator<(BinaryDataRef const & bd2) const
{
   auto minsize = min(nBytes_, bd2.nBytes_);
   for (size_t i = 0; i < minsize; i++)
   {
      if (ptr_[i] == bd2.ptr_[i])
         continue;
      return ptr_[i] < bd2.ptr_[i];
   }

   return (nBytes_ < bd2.nBytes_);
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryDataRef::operator>(BinaryDataRef const & bd2) const
{
   size_t minLen = min(nBytes_, bd2.nBytes_);
   for (size_t i = 0; i < minLen; i++)
   {
      if (ptr_[i] == bd2.ptr_[i])
         continue;
      return ptr_[i] > bd2.ptr_[i];
   }
   return (nBytes_ > bd2.nBytes_);
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryDataRef::startsWith(BinaryDataRef const & matchStr) const
{
   if(matchStr.getSize() > nBytes_)
      return false;
   
   for(uint32_t i=0; i<matchStr.getSize(); i++)
      if(matchStr[i] != (*this)[i])
         return false;
   
   return true;
}

/////////////////////////////////////////////////////////////////////////////
bool BinaryDataRef::startsWith(BinaryData const & matchStr) const
{
   if(matchStr.getSize() > nBytes_)
      return false;
   
   for(uint32_t i=0; i<matchStr.getSize(); i++)
      if(matchStr[i] != (*this)[i])
         return false;
   
   return true;
}

/////////////////////////////////////////////////////////////////////////////
//
////BinaryReader
//
/////////////////////////////////////////////////////////////////////////////
void BinaryReader::advance(uint32_t nBytes)
{
   pos_ += nBytes;
   pos_ = min(pos_, getSize());
}

/////////////////////////////////////////////////////////////////////////////
void BinaryReader::rewind(size_t nBytes)
{
   pos_ -= nBytes;
   pos_ = max(pos_, (size_t)0);
}

/////////////////////////////////////////////////////////////////////////////
void BinaryReader::resize(size_t nBytes)
{
   bdStr_.resize(nBytes);
   pos_ = min(nBytes, pos_);
}

/////////////////////////////////////////////////////////////////////////////
//
////BinaryRefReader
//
/////////////////////////////////////////////////////////////////////////////
SecureBinaryData BinaryRefReader::get_SecureBinaryData(uint32_t nBytes)
{
   if (getSizeRemaining() < nBytes)
      throw runtime_error("buffer overflow");
   SecureBinaryData out(nBytes);
   bdRef_.copyTo(out.getPtr(), pos_, nBytes);
   pos_.fetch_add(nBytes, memory_order_relaxed);
   return out;
}

/////////////////////////////////////////////////////////////////////////////
void BinaryRefReader::advance(size_t nBytes)
{
   if (getSizeRemaining() < nBytes)
      throw runtime_error("buffer overflow");

   pos_.fetch_add(nBytes, memory_order_relaxed);
}
