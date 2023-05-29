////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2018, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_BDV_CODEC_
#define _H_BDV_CODEC_

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4100)  // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4996)  // function deprecated or _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4250)  // 'class1' : inherits 'class2::member' via dominance
#pragma warning(disable : 4251)  // 'identifier' : class 'type' needs to have dll-interface to be used by clients of class 'type2'
#pragma warning(disable : 4275)  // non - DLL-interface class 'class_1' used as base for DLL-interface class 'class_2'
#pragma warning(disable : 4267)  // conversion from 'x' to 'y', possible loss of data
#pragma warning(disable : 4101)  // unreferenced local variable
#endif

// It seems that gcc from 4.7 completly ignore GCC diagnostic pragmas
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53431
#if defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#endif // __GNUC__

#include "protobuf/AddressBook.pb.h"
#include "protobuf/AddressData.pb.h"
#include "protobuf/CommonTypes.pb.h"
#include "protobuf/FeeEstimate.pb.h"
#include "protobuf/LedgerEntry.pb.h"
#include "protobuf/Utxo.pb.h"
#include "protobuf/NodeStatus.pb.h"
#include "protobuf/BDVCommand.pb.h"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#if defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 2)
#pragma GCC diagnostic pop
#endif
#endif // __GNUC__

#endif
