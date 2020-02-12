////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_ARMORY_ERRORS
#define _H_ARMORY_ERRORS

enum class ArmoryErrorCodes : int
{
    //bitcoin node rpc
    ZcBroadcast_AlreadyInChain = -27,

    //common
    ErrorUnknown    = -1,
    Success         = 0,

    //p2p reject errors
    P2PReject_InsufficientFee = 66,

    //zc parser
    ZcBatch_Timeout                 = 30000,
    ZcBroadcast_AlreadyInMempool    = 30001
};

#endif