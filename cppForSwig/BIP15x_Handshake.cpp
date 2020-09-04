////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2020, goatpig                                               //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "BIP15x_Handshake.h"
#include "BIP150_151.h"

using namespace std;
using namespace ArmoryAEAD;

////////////////////////////////////////////////////////////////////////////////
HandshakeState BIP15x_Handshake::serverSideHandshake(
   BIP151Connection* connPtr,
   uint8_t msgType, const BinaryDataRef& msg, 
   const WriteCallback& writeCb)
{
   switch (msgType)
   {
   case HandshakeSequence::Start:
   {
      //init bip151 handshake
      BinaryData encinitData(ENCINITMSGSIZE);
      if (connPtr->getEncinitData(
         encinitData.getPtr(), ENCINITMSGSIZE,
         BIP151SymCiphers::CHACHA20POLY1305_OPENSSH) != 0)
      {
         //failed to init handshake, kill connection
         return HandshakeState::Error_GetEncInit;
      }

      writeCb(encinitData.getRef(), HandshakeSequence::EncInit, false);
      break;
   }

   case HandshakeSequence::Rekey:
   {
      if (connPtr->getBIP150State() !=
         BIP150State::SUCCESS)
      {
         //can't rekey before auth, kill connection
         return HandshakeState::Error;
      }

      //process rekey
      if (connPtr->processEncack(
         msg.getPtr(), msg.getSize(), false) != 0)
      {
         //failed to init handshake, kill connection
         LOGWARN << "failed to process rekey";
         return HandshakeState::Error_ProcessEncAck;
      }

      break;
   }

   case HandshakeSequence::EncInit:
   {
      //process client encinit
      if (connPtr->processEncinit(
         msg.getPtr(), msg.getSize(), false) != 0)
      {
         //failed to init handshake, kill connection
         return HandshakeState::Error_ProcessEncInit;
      }

      //return encack
      BinaryData encackData(BIP151PUBKEYSIZE);
      if (connPtr->getEncackData(
         encackData.getPtr(), BIP151PUBKEYSIZE) != 0)
      {
         //failed to init handshake, kill connection
         return HandshakeState::Error_GetEncAck;
      }

      writeCb(encackData.getRef(), HandshakeSequence::EncAck, false);
      break;
   }

      //this is weird: no reply, investigate. Can AEAD sequence be stalled indefinitely because of this?
      case HandshakeSequence::EncAck:
      {
         //process client encack
         if (connPtr->processEncack(
            msg.getPtr(), msg.getSize(), true) != 0)
         {
            //failed to init handshake, kill connection
            return HandshakeState::Error_ProcessEncAck;
         }

         break;
      }

   case HandshakeSequence::Challenge:
   {
      bool goodChallenge = true;
      auto challengeResult = connPtr->processAuthchallenge(
         msg.getPtr(),
         msg.getSize(),
         true); //true: step #1 of 6

      if (challengeResult == -1)
      {
         //auth fail, kill connection
         return HandshakeState::Error_ProcessAuthChallenge;
      }
      else if (challengeResult == 1)
      {
         goodChallenge = false;
      }

      BinaryData authreplyBuf(BIP151PRVKEYSIZE * 2);
      if (connPtr->getAuthreplyData(
         authreplyBuf.getPtr(),
         authreplyBuf.getSize(),
         true, //true: step #2 of 6
         goodChallenge) == -1)
      {
         //auth setup failure, kill connection
         return HandshakeState::Error_GetAuthReply;
      }

      writeCb(authreplyBuf.getRef(), HandshakeSequence::Reply, true);

      break;
   }

   case HandshakeSequence::Propose:
   {
      bool goodPropose = true;
      auto proposeResult = connPtr->processAuthpropose(
         msg.getPtr(),
         msg.getSize());

      if (proposeResult == -1)
      {
         //auth setup failure, kill connection
         return HandshakeState::Error_ProcessAuthPropose;
      }
      else if (proposeResult == 1)
      {
         goodPropose = false;
      }
      else
      {
         //keep track of the propose check state
         connPtr->setGoodPropose();
      }

      BinaryData authchallengeBuf(BIP151PRVKEYSIZE);
      if (connPtr->getAuthchallengeData(
         authchallengeBuf.getPtr(),
         authchallengeBuf.getSize(),
         "", //empty string, use chosen key from processing auth propose
         false, //false: step #4 of 6
         goodPropose) == -1)
      {
         //auth setup failure, kill connection
         return HandshakeState::Error_GetAuthChallenge;
      }

      writeCb(authchallengeBuf.getRef(), HandshakeSequence::Challenge, true);

      break;
   }

   case HandshakeSequence::Reply:
   {
      if (connPtr->processAuthreply(
         msg.getPtr(),
         msg.getSize(),
         false,
         connPtr->getProposeFlag()) != 0)
      {
         //invalid auth setup, kill connection
         return HandshakeState::Error_ProcessAuthReply;
      }

      //rekey after succesful BIP150 handshake
      connPtr->bip150HandshakeRekey();

      //handshake successful
      return HandshakeState::Completed;
   }

   default:
      //unexpected msg id, kill connection
      return HandshakeState::Error;
   }

   return HandshakeState::StepSuccessful;
}

////////////////////////////////////////////////////////////////////////////////
HandshakeState BIP15x_Handshake::clientSideHandshake(
   BIP151Connection* connPtr, const string& servName,
   uint8_t msgType, const BinaryDataRef& msg, 
   const WriteCallback& writeCb)
{
   if (connPtr == nullptr)
      return HandshakeState::Error;
   
   switch (msgType)
   {
   case HandshakeSequence::EncInit:
   {
      if (connPtr->processEncinit(
         msg.getPtr(), msg.getSize(), false) != 0)
         return HandshakeState::Error_ProcessEncInit;

      //valid encinit, send client side encack
      BinaryData encackPayload(BIP151PUBKEYSIZE);
      if (connPtr->getEncackData(
         encackPayload.getPtr(), BIP151PUBKEYSIZE) != 0)
      {
         return HandshakeState::Error_GetEncAck;
      }
      
      writeCb(encackPayload, HandshakeSequence::EncAck, false);

      //start client side encinit
      BinaryData encinitPayload(ENCINITMSGSIZE);
      if (connPtr->getEncinitData(
         encinitPayload.getPtr(), ENCINITMSGSIZE,
         BIP151SymCiphers::CHACHA20POLY1305_OPENSSH) != 0)
      {
         return HandshakeState::Error_GetEncInit;
      }

      writeCb(encinitPayload, HandshakeSequence::EncInit, false);
      break;
   }

   case HandshakeSequence::EncAck:
   {
      if (connPtr->processEncack(
         msg.getPtr(), msg.getSize(), true) == -1)
      {
         return HandshakeState::Error_ProcessEncAck;
      }

      //bip151 handshake completed, time for bip150
      BinaryData authchallengeBuf(BIP151PRVKEYSIZE);
      if (connPtr->getAuthchallengeData(
         authchallengeBuf.getPtr(),
         authchallengeBuf.getSize(),
         servName,
         true, //true: auth challenge step #1 of 6
         false) != 0) //false: have not processed an auth propose yet
      {
         return HandshakeState::Error_GetAuthChallenge;
      }

      writeCb(authchallengeBuf, HandshakeSequence::Challenge, true);
      break;
   }

   case HandshakeSequence::Rekey:
   {
      //rekey requests before auth are invalid
      if (connPtr->getBIP150State() != BIP150State::SUCCESS)
         return HandshakeState::Error;

      //if connection is already setup, we only accept enack rekey messages
      if (connPtr->processEncack(
         msg.getPtr(), msg.getSize(), false) == -1)
         return HandshakeState::Error_ProcessEncAck;

      return HandshakeState::RekeySuccessful;
   }

   case HandshakeSequence::Reply:
   {
      if (connPtr->processAuthreply(
         msg.getPtr(),
         msg.getSize(),
         true, //true: step #2 out of 6
         false) != 0) //false: haven't seen an auth challenge yet
      {
         return HandshakeState::Error_ProcessAuthReply;
      }

      BinaryData authproposeBuf(BIP151PRVKEYSIZE);
      if (connPtr->getAuthproposeData(
         authproposeBuf.getPtr(),
         authproposeBuf.getSize()) != 0)
      {
         return HandshakeState::Error_GetAuthPropose;
      }

      writeCb(authproposeBuf, HandshakeSequence::Propose, true);
      break;
   }

   case HandshakeSequence::Challenge:
   {
      //should return a reply packet to the server even if this step fails

      bool goodChallenge = true;
      auto challengeResult =
         connPtr->processAuthchallenge(
            msg.getPtr(),
            msg.getSize(),
            false); //true: step #4 of 6

      if (challengeResult == 1)
      {
         goodChallenge = false;
      }

      BinaryData authreplyBuf(BIP151PRVKEYSIZE * 2);
      auto validReply = connPtr->getAuthreplyData(
         authreplyBuf.getPtr(),
         authreplyBuf.getSize(),
         false, //true: step #5 of 6
         goodChallenge);

      writeCb(authreplyBuf, HandshakeSequence::Reply, true);

      if (challengeResult == -1)
      {
         //auth fail, kill connection
         return HandshakeState::Error_ProcessAuthChallenge;
      }      
      else if (validReply != 0)
      {
         //auth setup failure, kill connection
         return HandshakeState::Error_GetAuthReply;
      }

      //rekey
      connPtr->bip150HandshakeRekey();

      //handshake done, connection is ready
      return HandshakeState::Completed;
   }

   default:
      return HandshakeState::Error;
   }

   return HandshakeState::StepSuccessful;
}
