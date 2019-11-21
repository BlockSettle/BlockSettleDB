////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2019, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "WalletHeader.h"
#include "Assets.h"
#include "AssetEncryption.h"
#include "DecryptedDataContainer.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//// WalletHeader
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
WalletHeader::~WalletHeader()
{}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader::getDbKey()
{
   if (walletID_.getSize() == 0)
      throw WalletException("empty master ID");

   BinaryWriter bw;
   bw.put_uint8_t(WALLETHEADER_PREFIX);
   bw.put_BinaryData(walletID_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader::serializeVersion() const
{
   BinaryWriter bw;
   bw.put_uint8_t(versionMajor_);
   bw.put_uint16_t(versionMinor_);
   bw.put_uint16_t(revision_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
void WalletHeader::unseralizeVersion(BinaryRefReader& brr)
{
   versionMajor_ = brr.get_uint8_t();
   versionMinor_ = brr.get_uint16_t();
   revision_ = brr.get_uint16_t();
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader::serializeEncryptionKey() const
{
   BinaryWriter bw;
   bw.put_var_int(defaultEncryptionKeyId_.getSize());
   bw.put_BinaryData(defaultEncryptionKeyId_);
   bw.put_var_int(defaultEncryptionKey_.getSize());
   bw.put_BinaryData(defaultEncryptionKey_);

   bw.put_var_int(defaultKdfId_.getSize());
   bw.put_BinaryData(defaultKdfId_);
   bw.put_var_int(masterEncryptionKeyId_.getSize());
   bw.put_BinaryData(masterEncryptionKeyId_);


   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
void WalletHeader::unserializeEncryptionKey(BinaryRefReader& brr)
{
   auto len = brr.get_var_int();
   defaultEncryptionKeyId_ = move(brr.get_BinaryData(len));

   len = brr.get_var_int();
   defaultEncryptionKey_ = move(brr.get_BinaryData(len));

   len = brr.get_var_int();
   defaultKdfId_ = move(brr.get_BinaryData(len));

   len = brr.get_var_int();
   masterEncryptionKeyId_ = move(brr.get_BinaryData(len));
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader::serializeControlSalt() const
{
   BinaryWriter bw;
   bw.put_var_int(controlSalt_.getSize());
   bw.put_BinaryData(controlSalt_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
void WalletHeader::unserializeControlSalt(BinaryRefReader& brr)
{
   auto len = brr.get_var_int();
   controlSalt_ = brr.get_SecureBinaryData(len);
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader_Single::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(type_);
   bw.put_BinaryData(serializeVersion());
   bw.put_BinaryData(serializeEncryptionKey());
   bw.put_BinaryData(serializeControlSalt());

   BinaryWriter final_bw;
   final_bw.put_var_int(bw.getSize());
   final_bw.put_BinaryDataRef(bw.getDataRef());

   return final_bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletHeader_Single::shouldLoad() const
{
   return true;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader_Multisig::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(type_);
   bw.put_BinaryData(serializeVersion());
   bw.put_BinaryData(serializeEncryptionKey());
   bw.put_BinaryData(serializeControlSalt());

   BinaryWriter final_bw;
   final_bw.put_var_int(bw.getSize());
   final_bw.put_BinaryDataRef(bw.getDataRef());

   return final_bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletHeader_Multisig::shouldLoad() const
{
   return true;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader_Subwallet::serialize() const
{
   BinaryWriter bw;
   bw.put_var_int(4);
   bw.put_uint32_t(type_);

   return bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletHeader_Subwallet::shouldLoad() const
{
   return false;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader_Control::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(type_);
   bw.put_BinaryData(serializeVersion());
   bw.put_BinaryData(serializeEncryptionKey());
   bw.put_BinaryData(serializeControlSalt());

   BinaryWriter final_bw;
   final_bw.put_var_int(bw.getSize());
   final_bw.put_BinaryDataRef(bw.getDataRef());

   return final_bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletHeader_Control::shouldLoad() const
{
   return true;
}

////////////////////////////////////////////////////////////////////////////////
BinaryData WalletHeader_Custom::serialize() const
{
   BinaryWriter bw;
   bw.put_uint32_t(type_);
   bw.put_BinaryData(serializeVersion());

   BinaryWriter final_bw;
   final_bw.put_var_int(bw.getSize());
   final_bw.put_BinaryDataRef(bw.getDataRef());

   return final_bw.getData();
}

////////////////////////////////////////////////////////////////////////////////
bool WalletHeader_Custom::shouldLoad() const
{
   return true;
}

////////////////////////////////////////////////////////////////////////////////
shared_ptr<WalletHeader> WalletHeader::deserialize(
   BinaryDataRef key, BinaryDataRef val)
{
   if (key.getSize() < 2)
      throw WalletException("invalid meta key");

   BinaryRefReader brrKey(key);
   auto prefix = brrKey.get_uint8_t();
   if (prefix != WALLETHEADER_PREFIX)
      throw WalletException("invalid wallet meta prefix");

   string dbname((char*)brrKey.getCurrPtr(), brrKey.getSizeRemaining());

   BinaryRefReader brrVal(val);
   auto wltType = (WalletHeaderType)brrVal.get_uint32_t();

   shared_ptr<WalletHeader> wltHeaderPtr;

   switch (wltType)
   {
   case WalletHeaderType_Single:
   {
      wltHeaderPtr = make_shared<WalletHeader_Single>();
      wltHeaderPtr->unseralizeVersion(brrVal);
      wltHeaderPtr->unserializeEncryptionKey(brrVal);
      wltHeaderPtr->unserializeControlSalt(brrVal);      
      break;
   }

   case WalletHeaderType_Subwallet:
   {
      wltHeaderPtr = make_shared<WalletHeader_Subwallet>();
      break;
   }

   case WalletHeaderType_Multisig:
   {
      wltHeaderPtr = make_shared<WalletHeader_Multisig>();
      wltHeaderPtr->unseralizeVersion(brrVal);
      wltHeaderPtr->unserializeEncryptionKey(brrVal);
      wltHeaderPtr->unserializeControlSalt(brrVal);
      break;
   }

   case WalletHeaderType_Control:
   {
      wltHeaderPtr = make_shared<WalletHeader_Control>();
      wltHeaderPtr->unseralizeVersion(brrVal);
      wltHeaderPtr->unserializeEncryptionKey(brrVal);
      wltHeaderPtr->unserializeControlSalt(brrVal);
      break;
   }

   case WalletHeaderType_Custom:
   {
      wltHeaderPtr = make_shared<WalletHeader_Custom>();
      wltHeaderPtr->unseralizeVersion(brrVal);
      break;
   }

   default:
      throw WalletException("invalid wallet type");
   }

   wltHeaderPtr->walletID_ = brrKey.get_BinaryData(brrKey.getSizeRemaining());
   return wltHeaderPtr;
}