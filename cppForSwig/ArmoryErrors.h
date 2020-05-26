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
    //bitcoin node rpc errors
    ZcBroadcast_AlreadyInChain = -27, //Zc is already mined
    ZcBroadcast_VerifyRejected = -26, //failed verification
    ZcBroadcast_Error          = -25, //non specific error, most likely spent output

    //common
    ErrorUnknown    = -1,
    Success         = 0,

    //p2p reject errors
    P2PReject_Duplicate         = 18, //mempool double spend
    P2PReject_InsufficientFee   = 66,

    //zc parser
    ZcBatch_Timeout                 = 30000,
    ZcBroadcast_AlreadyInMempool    = 30001,

    //client already has a pending broadcast request for this zc
    ZcBroadcast_Pending             = 30002, 

    //rpc error codes
    RPCFailure_Unknown  = 40000,
    RPCFailure_JSON     = 40001, //bitcoin node return is not JSON 
    RPCFailure_Internal = 40002, //failed to setup the RPC connection

    //getTxBatchByHash
    GetTxBatchError_Invalid = 50001, //response isn't flagged as valid
    GetTxBatchError_CallMap = 50002, //mismatch between result and call map
};

#endif