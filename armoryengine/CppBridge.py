################################################################################
#                                                                              #
# Copyright (C) 2019-2020, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import errno
import socket
from armoryengine import ClientProto_pb2
from armoryengine.ArmoryUtils import LOGDEBUG, LOGERROR, hash256
from armoryengine.BDM import TheBDM
from armoryengine.BinaryPacker import BinaryPacker, \
   UINT32, UINT8, BINARY_CHUNK, VAR_INT
from struct import unpack
import atexit
import threading
import binascii
import subprocess

from concurrent.futures import ThreadPoolExecutor

from armoryengine.ArmoryUtils import PassphraseError
from armoryengine.BIP15x import \
    BIP15xConnection, AEAD_THRESHOLD_BEGIN, AEAD_Error, \
    CHACHA20POLY1305MAXPACKETSIZE

CPP_BDM_NOTIF_ID = 2**32 -1
CPP_PROGRESS_NOTIF_ID = 2**32 -2
CPP_PROMPT_USER_ID = 2**32 -3
BRIDGE_CLIENT_HEADER = 1

#################################################################################
class BridgeError(Exception):
   pass

#################################################################################
class BridgeSignerError(Exception):
   pass

#################################################################################
class PyPromFut(object):

   #############################################################################
   def __init__(self):

      self.data = None
      self.has = False
      self.cv = threading.Condition()

   #############################################################################
   def setVal(self, val):
      self.cv.acquire()
      self.data = val
      self.has = True
      self.cv.notify()
      self.cv.release()

   #############################################################################
   def getVal(self):
      self.cv.acquire()
      while self.has is False:
         self.cv.wait()
      self.cv.release()
      return self.data


################################################################################
class ArmoryBridge(object):

   #############################################################################
   def __init__(self):
      self.blockTimeByHeightCache = {}
      self.addrTypeStrByType = {}
      self.bip15xConnection = BIP15xConnection(\
         self.sendToBridgeRaw)

   #############################################################################
   def start(self, stringArgs, notifyReadyLbd):
      self.bip15xConnection.setNotifyReadyLbd(notifyReadyLbd)

      self.run = True
      self.rwLock = threading.Lock()

      self.idCounter = 0
      self.responseDict = {}

      self.executor = ThreadPoolExecutor(max_workers=2)
      listenFut = self.executor.submit(self.listenOnBridge)

      #append gui pubkey to arg list and spawn bridge
      stringArgs += " --uiPubKey=" + self.bip15xConnection.getPubkeyHex()
      self.processFut = self.executor.submit(self.spawnBridge, stringArgs)

      #block until listen socket receives bridge connection
      self.clientSocket = listenFut.result()

      #start socket read thread
      self.clientFut = self.executor.submit(self.readBridgeSocket)

      #initiate AEAD handshake (server has to start it)
      self.bip15xConnection.serverStartHandshake()

   #############################################################################
   def stop(self):
      self.listenSocket.close()
      self.clientSocket.close()

   #############################################################################
   def listenOnBridge(self):
      #setup listener

      portNumber = 46122
      self.listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.listenSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
      self.listenSocket.bind(("127.0.0.1", portNumber))
      self.listenSocket.listen()

      clientSocket, clientIP = self.listenSocket.accept()
      return clientSocket

   #############################################################################
   def spawnBridge(self, stringArgs):
      subprocess.run(["./CppBridge", stringArgs])

   #############################################################################
   def encryptPayload(self, clearText):
      if not self.bip15xConnection.encrypted():
         raise AEAD_Error("channel is not encrypted")

      cipherText = []
      if self.bip15xConnection.needsRekey(len(clearText)):
         cipherText.append(self.bip15xConnection.getRekeyPayload())
      cipherText.append(\
         self.bip15xConnection.encrypt(clearText, len(clearText)))

      return cipherText

   #############################################################################
   def sendToBridgeProto(self, msg, \
      needsReply=True, callback=None, cbArgs=[], \
      msgType = BRIDGE_CLIENT_HEADER):

      msg.payloadId = self.idCounter
      self.idCounter = self.idCounter + 1

      payload = msg.SerializeToString()
      result = self.sendToBridgeBinary(payload, msg.payloadId, \
         needsReply, callback, cbArgs, msgType)

      if needsReply:
         return result

   #############################################################################
   def sendToBridgeBinary(self, payload, payloadId, \
      needsReply=True, callback=None, cbArgs=[], \
      msgType = BRIDGE_CLIENT_HEADER):

      #grab id from msg counter
      if self.run == False:
         return

      #serialize payload
      bp = BinaryPacker()

      #payload type header
      bp.put(UINT8, msgType)

      #serialized protobuf message
      bp.put(BINARY_CHUNK, payload)

      #grab read write lock
      self.rwLock.acquire(True)

      #encrypt
      encryptedPayloads = self.encryptPayload(bp.getBinaryString())

      if needsReply:
         #instantiate prom/future object and set in response dict
         fut = PyPromFut()
         self.responseDict[payloadId] = fut

      elif callback != None:
         #set callable in response dict
         self.responseDict[payloadId] = [callback, cbArgs]

      #send over the wire, may have 2 payloads if we triggered a rekey
      for p in encryptedPayloads:
         self.clientSocket.sendall(p)

      #return future to caller
      self.rwLock.release()

      if needsReply:
         return fut

   #############################################################################
   def sendToBridgeRaw(self, msg):
      self.rwLock.acquire(True)
      self.clientSocket.sendall(msg)
      self.rwLock.release()

   #############################################################################
   def pollRecv(self, payloadSize):
      payload = bytearray()
      fullSize = payloadSize
      while len(payload) < fullSize:
         try:
            payload += self.clientSocket.recv(payloadSize)
            payloadSize = fullSize - len(payload)
         except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
               LOGDEBUG('No data available from socket.')
               continue
            else:
               LOGERROR("Socket error: %s" % str(e))
               break

      return payload

   #############################################################################
   def readBridgeSocket(self):
      recvLen = 4
      while self.run is True:
         #wait for data on the socket
         try:
            response = self.clientSocket.recv(recvLen)

            if len(response) < recvLen:
               break
         except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
               LOGDEBUG('No data available from socket.')
               continue
            else:
               LOGERROR("Socket error: %s" % str(e))
               self.run = False
               break

         #if channel is established, incoming data is encrypted
         if self.bip15xConnection.encrypted():
            payloadSize = self.bip15xConnection.decodeSize(response[:4])
            if payloadSize > CHACHA20POLY1305MAXPACKETSIZE:
               LOGERROR("Invalid encrypted packet size: " + str(payloadSize))
               self.run = False
               break

            #grab the payload
            payload = response
            payload += self.pollRecv(\
                payloadSize + self.bip15xConnection.getMacLen())

            #decrypt it
            response = self.bip15xConnection.decrypt(\
               payload, payloadSize)


         #check header
         header = unpack('<B', response[:1])[0]
         if header > AEAD_THRESHOLD_BEGIN[0]:
            #get expected packet size for this payload from the socket
            payloadSize = self.bip15xConnection.getAEADPacketSize(header)

            payload = response[1:]
            if len(payload) < payloadSize:
                payload += self.pollRecv(payloadSize - len(payload))

            try:
               self.bip15xConnection.serverHandshake(header, payload)
            except AEAD_Error as aeadError:
               print (aeadError)
               return

            #handshake packets are not to be processed as user data
            continue

         if not self.bip15xConnection.ready():
            #non AEAD data is only tolerated after channels are setup
            raise BridgeError("Received user data before AEAD is ready")

         #grab packet id
         fullPacket = response[5:]

         packetId = unpack('<I', response[1:5])[0]
         if packetId == CPP_BDM_NOTIF_ID:
            self.pushNotification(fullPacket)
            continue
         elif packetId == CPP_PROGRESS_NOTIF_ID:
            self.pushProgressNotification(fullPacket)
            continue
         elif packetId == CPP_PROMPT_USER_ID:
            self.promptUser(fullPacket)
            continue

         #lock and look for future object in response dict
         self.rwLock.acquire(True)
         if packetId not in self.responseDict:
            self.rwLock.release()
            continue

         #grab the future, delete it from dict
         replyObj = self.responseDict[packetId]
         del self.responseDict[packetId]

         self.clientSocket.setblocking(1)

         #fill the promise & release lock
         self.rwLock.release()

         if isinstance(replyObj, PyPromFut):
            replyObj.setVal(fullPacket)

         elif replyObj != None and replyObj[0] != None:
            replyObj[0](fullPacket, replyObj[1])

   #############################################################################
   def pushNotification(self, data):
      payload = ClientProto_pb2.CppBridgeCallback()
      payload.ParseFromString(data)

      notifThread = threading.Thread(\
         group=None, target=TheBDM.pushNotification, \
         name=None, args=[payload], kwargs={})
      notifThread.start()

   #############################################################################
   def pushProgressNotification(self, data):
      payload = ClientProto_pb2.CppProgressCallback()
      payload.ParseFromString(data)

      TheBDM.reportProgress(payload)

   #############################################################################
   def promptUser(self, data):
      payload = ClientProto_pb2.OpaquePayload()
      payload.ParseFromString(data)

      TheBDM.pushFromBridge(\
         payload.payloadType, payload.payload, payload.uniqueId, payload.intId)

   #############################################################################
   def returnPassphrase(self, id, passphrase):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.returnPassphrase

      packet.stringArgs.append(id)
      packet.stringArgs.append(passphrase)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def loadWallets(self, func):
      #create protobuf packet
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.loadWallets

      #send to the socket
      self.sendToBridgeProto(packet, False, self.walletsLoaded, [func])

   #############################################################################
   def walletsLoaded(self, socketResponse, args):
      #deser protobuf reply
      response = ClientProto_pb2.WalletPayload()
      response.ParseFromString(bytearray(socketResponse))

      #fire callback
      callbackThread = threading.Thread(\
         group=None, target=args[0], \
         name=None, args=[response], kwargs={})
      callbackThread.start()

   #############################################################################
   def shutdown(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.shutdown
      self.sendToBridgeProto(packet)

      self.rwLock.acquire(True)

      self.run = False
      self.clientSocket.close()
      self.listenSocket.close()

      self.rwLock.release()
      self.clientFut.result()

   #############################################################################
   def setupDB(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.setupDB

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def registerWallets(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.registerWallets

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def goOnline(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.goOnline

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def getLedgerDelegateIdForWallets(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getLedgerDelegateIdForWallets

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyStrings()
      response.ParseFromString(socketResponse)

      if len(response.reply) != 1:
         raise BridgeError("invalid reply")

      return response.reply[0]

   #############################################################################
   def getLedgerDelegateIdForScrAddr(self, walletId, addr160):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getLedgerDelegateIdForScrAddr
      packet.stringArgs.append(walletId)
      packet.byteArgs.append(addr160)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyStrings()
      response.ParseFromString(socketResponse)

      if len(response.reply) != 1:
         raise BridgeError("invalid reply")

      return response.reply[0]

   #############################################################################
   def updateWalletsLedgerFilter(self, ids):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.updateWalletsLedgerFilter

      for id in ids:
         packet.stringArgs.append(id)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def getHistoryPageForDelegate(self, delegateId, pageId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getHistoryPageForDelegate

      packet.stringArgs.append(delegateId)
      packet.intArgs.append(pageId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeLedgers()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def getNodeStatus(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getNodeStatus

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeNodeStatus()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def getBalanceAndCount(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getBalanceAndCount
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeBalanceAndCount()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def getAddrCombinedList(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getAddrCombinedList
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeMultipleBalanceAndCount()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def getHighestUsedIndex(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getHighestUsedIndex
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      return response.ints[0]

   #############################################################################
   def getTxByHash(self, hashVal):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getTxByHash
      packet.byteArgs.append(hashVal)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeTx()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def getTxOutScriptType(self, script):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getTxOutScriptType
      packet.byteArgs.append(script)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      return response.ints[0]

   #############################################################################
   def getTxInScriptType(self, script, hashVal):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getTxInScriptType
      packet.byteArgs.append(script)
      packet.byteArgs.append(hashVal)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      return response.ints[0]

   #############################################################################
   def getLastPushDataInScript(self, script):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getLastPushDataInScript
      packet.byteArgs.append(script)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      if len(response.reply) > 0:
         return response.reply[0]
      else:
         return ""

   #############################################################################
   def getTxOutScriptForScrAddr(self, script):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getTxOutScriptForScrAddr
      packet.byteArgs.append(script)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def getHeaderByHeight(self, height):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getHeaderByHeight
      packet.intArgs.append(height)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def getScrAddrForScript(self, script):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getScrAddrForScript
      packet.byteArgs.append(script)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def getScrAddrForAddrStr(self, addrStr):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getScrAddrForAddrStr
      packet.stringArgs.append(addrStr)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      errorResponse = ClientProto_pb2.ReplyError()
      errorResponse.ParseFromString(socketResponse)
      if errorResponse.isError == False:
         response = ClientProto_pb2.ReplyBinary()
         response.ParseFromString(socketResponse)
         return response.reply[0]
      raise BridgeError("error in getScrAddrForAddrStr: " + errorResponse.error)

   #############################################################################
   def getAddrStrForScrAddr(self, scrAddr):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getAddrStrForScrAddr
      packet.byteArgs.append(scrAddr)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      errorResponse = ClientProto_pb2.ReplyError()
      errorResponse.ParseFromString(socketResponse)
      if errorResponse.isError == False:
         response = ClientProto_pb2.ReplyStrings()
         response.ParseFromString(socketResponse)
         return response.reply[0]
      raise BridgeError("error in getAddrStrForScrAddr: " + errorResponse.error)

   #############################################################################
   def initCoinSelectionInstance(self, wltId, height):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.setupNewCoinSelectionInstance
      packet.stringArgs.append(wltId)
      packet.intArgs.append(height)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyStrings()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def destroyCoinSelectionInstance(self, csId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.destroyCoinSelectionInstance
      packet.stringArgs.append(csId)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def setCoinSelectionRecipient(self, csId, addrStr, value, recId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.setCoinSelectionRecipient
      packet.stringArgs.append(csId)
      packet.stringArgs.append(addrStr)
      packet.intArgs.append(recId)
      packet.longArgs.append(value)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeError("setCoinSelectionRecipient failed")

   #############################################################################
   def resetCoinSelection(self, csId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.resetCoinSelection
      packet.stringArgs.append(csId)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def cs_SelectUTXOs(self, csId, fee, feePerByte, processFlags):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.cs_SelectUTXOs
      packet.stringArgs.append(csId)
      packet.longArgs.append(fee)
      packet.floatArgs.append(feePerByte)
      packet.intArgs.append(processFlags)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeError("selectUTXOs failed")

   #############################################################################
   def cs_getUtxoSelection(self, csId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.cs_getUtxoSelection
      packet.stringArgs.append(csId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeUtxoList()
      response.ParseFromString(socketResponse)

      return response.data

   #############################################################################
   def cs_getFlatFee(self, csId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.cs_getFlatFee
      packet.stringArgs.append(csId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      return response.longs[0]

   #############################################################################
   def cs_getFeeByte(self, csId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.cs_getFeeByte
      packet.stringArgs.append(csId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      return response.floats[0]

   #############################################################################
   def cs_getSizeEstimate(self, csId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.cs_getSizeEstimate
      packet.stringArgs.append(csId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      return response.longs[0]

   #############################################################################
   def cs_ProcessCustomUtxoList(self, csId, \
      utxoList, fee, feePerByte, processFlags):

      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.cs_ProcessCustomUtxoList
      packet.stringArgs.append(csId)
      packet.longArgs.append(fee)
      packet.floatArgs.append(feePerByte)
      packet.intArgs.append(processFlags)

      for utxo in utxoList:
         bridgeUtxo = utxo.toBridgeUtxo()
         packet.byteArgs.append(bridgeUtxo.SerializeToString())

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeError("ProcessCustomUtxoList failed")

   #############################################################################
   def generateRandomHex(self, size):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.generateRandomHex
      packet.intArgs.append(size)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyStrings()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def createAddressBook(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.createAddressBook
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeAddressBook()
      response.ParseFromString(socketResponse)

      return response.data

   #############################################################################
   def getUtxosForValue(self, wltId, value):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getUtxosForValue
      packet.stringArgs.append(wltId)
      packet.longArgs.append(value)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeUtxoList()
      response.ParseFromString(socketResponse)

      return response.data

   #############################################################################
   def getSpendableZCList(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getSpendableZCList
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeUtxoList()
      response.ParseFromString(socketResponse)

      return response.data

   #############################################################################
   def getRBFTxOutList(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getRBFTxOutList
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeUtxoList()
      response.ParseFromString(socketResponse)

      return response.data

   #############################################################################
   def getNewAddress(self, wltId, addrType):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getNewAddress
      packet.stringArgs.append(wltId)
      packet.intArgs.append(addrType)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.WalletAsset()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def getNewChangeAddr(self, wltId, addrType):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getNewChangeAddr
      packet.stringArgs.append(wltId)
      packet.intArgs.append(addrType)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.WalletAsset()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def peekChangeAddress(self, wltId, addrType):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.peekChangeAddress
      packet.stringArgs.append(wltId)
      packet.intArgs.append(addrType)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.WalletAsset()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def getHash160(self, data):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getHash160
      packet.byteArgs.append(data)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def broadcastTx(self, rawTxList):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.broadcastTx
      packet.byteArgs.extend(rawTxList)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def extendAddressPool(self, wltId, progressId, count, callback):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.extendAddressPool
      packet.stringArgs.append(wltId)
      packet.stringArgs.append(progressId)
      packet.intArgs.append(count)

      self.sendToBridgeProto(packet, False,
         self.finishExtendAddressPool, [callback])

   #############################################################################
   def finishExtendAddressPool(self, socketResponse, args):
      response = ClientProto_pb2.WalletData()
      response.ParseFromString(socketResponse)

      #fire callback
      callbackThread = threading.Thread(\
         group=None, target=args[0], \
         name=None, args=[response], kwargs={})
      callbackThread.start()

   #############################################################################
   def createWallet(self, addrPoolSize, passphrase, controlPassphrase, \
      shortLabel, longLabel, extraEntropy):
      walletCreationStruct = ClientProto_pb2.BridgeCreateWalletStruct()
      walletCreationStruct.lookup = addrPoolSize
      walletCreationStruct.passphrase = passphrase
      walletCreationStruct.controlPassphrase = controlPassphrase
      walletCreationStruct.label = shortLabel
      walletCreationStruct.description = longLabel

      if extraEntropy is not None:
         walletCreationStruct.extraEntropy = extraEntropy

      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.createWallet
      packet.byteArgs.append(walletCreationStruct.SerializeToString())

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyStrings()
      response.ParseFromString(socketResponse)

      if len(response.reply) != 1:
         raise BridgeError("string reply count mismatch")

      return response.reply[0]

   #############################################################################
   def deleteWallet(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.deleteWallet
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      return response.ints[0]

   #############################################################################
   def getWalletData(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getWalletData
      packet.stringArgs.append(wltId)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.WalletData()
      response.ParseFromString(socketResponse)

      return response

   #############################################################################
   def registerWallet(self, walletId, isNew):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.registerWallet
      packet.stringArgs.append(walletId)
      packet.intArgs.append(isNew)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def getBlockTimeByHeight(self, height):
      if height in self.blockTimeByHeightCache:
         return self.blockTimeByHeightCache[height]

      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getBlockTimeByHeight
      packet.intArgs.append(height)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      blockTime = response.ints[0]

      if blockTime == 2**32 - 1:
         raise BridgeError("invalid block time")

      self.blockTimeByHeightCache[height] = blockTime
      return blockTime

   #############################################################################
   def createBackupStringForWalletCallback(self, socketResponse, args):
      rootData = ClientProto_pb2.BridgeBackupString()
      rootData.ParseFromString(socketResponse)

      callbackArgs = [rootData]
      callbackThread = threading.Thread(\
         group=None, target=args[0], \
         name=None, args=callbackArgs, kwargs={})
      callbackThread.start()

   #############################################################################
   def createBackupStringForWallet(self, wltId, callback):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.createBackupStringForWallet
      packet.stringArgs.append(wltId)

      callbackArgs = [callback]
      self.sendToBridgeProto(\
         packet, False, self.createBackupStringForWalletCallback, callbackArgs)

   #############################################################################
   def restoreWallet(self, root, chaincode, sppass, callbackId):
      opaquePayload = ClientProto_pb2.RestoreWalletPayload()
      opaquePayload.root.extend(root)
      opaquePayload.secondary.extend(chaincode)
      opaquePayload.spPass = sppass

      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.methodWithCallback
      packet.methodWithCallback = ClientProto_pb2.restoreWallet

      packet.byteArgs.append(callbackId)
      packet.byteArgs.append(opaquePayload.SerializeToString())

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def callbackFollowUp(self, payload, callbackId, callerId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.methodWithCallback
      packet.methodWithCallback = ClientProto_pb2.followUp

      packet.byteArgs.append(callbackId)
      packet.byteArgs.append(payload.SerializeToString())

      packet.intArgs.append(callerId)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def getNameForAddrType(self, addrType):
      if addrType in self.addrTypeStrByType:
         return self.addrTypeStrByType[addrType]

      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getNameForAddrType
      packet.intArgs.append(addrType)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyStrings()
      response.ParseFromString(socketResponse)

      addrTypeStr = response.reply[0]
      self.addrTypeStrByType[addrType] = addrTypeStr
      return addrTypeStr

   #############################################################################
   def setAddressTypeFor(self, walletId, assetId, addrType):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.getAddressStrFor

      packet.stringArgs.append(walletId)
      packet.byteArgs.append(assetId)
      packet.intArgs.append(addrType)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.WalletAsset()
      response.ParseFromString(socketResponse)
      return response

   #############################################################################
   def setComment(self, wltId, key, val):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.setComment

      packet.stringArgs.append(wltId)
      packet.byteArgs.append(key)
      packet.stringArgs.append(val)

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def estimateFee(self, blocks, strat):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.estimateFee
      packet.intArgs.append(blocks)
      packet.stringArgs.append(strat)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeFeeEstimate()
      response.ParseFromString(socketResponse)

      return response


################################################################################
class BridgeSigner(object):
   def __init__(self):
      self.signerId = None

   def __del__(self):
      self.cleanup()

   #############################################################################
   def initNew(self):
      if self.signerId != None:
         raise BridgeSignerError("initNew")

      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.initNewSigner

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyStrings()
      response.ParseFromString(socketResponse)

      self.signerId = response.reply[0]

   #############################################################################
   def cleanup(self):
      if self.signerId != None:
         return

      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.destroySigner
      packet.stringArgs.append(self.signerId)

      TheBridge.sendToBridgeProto(packet, False)
      self.signerId = None

   #############################################################################
   def setVersion(self, version):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_SetVersion
      packet.stringArgs.append(self.signerId)
      packet.intArgs.append(version)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeSignerError("setVersion")

   #############################################################################
   def setLockTime(self, locktime):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_SetLockTime
      packet.stringArgs.append(self.signerId)
      packet.intArgs.append(locktime)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeSignerError("setLockTime")

   #############################################################################
   def addSpenderByOutpoint(self, hashVal, txoutid, seq, value):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_addSpenderByOutpoint
      packet.stringArgs.append(self.signerId)
      packet.byteArgs.append(hashVal)
      packet.intArgs.append(txoutid)
      packet.intArgs.append(seq)
      packet.longArgs.append(value)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeSignerError("addSpenderByOutpoint")

   #############################################################################
   def populateUtxo(self, hashVal, txoutid, value, script):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_populateUtxo
      packet.stringArgs.append(self.signerId)
      packet.byteArgs.append(hashVal)
      packet.intArgs.append(txoutid)
      packet.longArgs.append(value)
      packet.byteArgs.append(script)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeSignerError("addSpenderByOutpoint")

   #############################################################################
   def addRecipient(self, value, script):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_addRecipient
      packet.stringArgs.append(self.signerId)
      packet.byteArgs.append(script)
      packet.longArgs.append(value)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeSignerError("addRecipient")

   #############################################################################
   def getSerializedState(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_getSerializedState
      packet.stringArgs.append(self.signerId)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def unserializeState(self, state):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_unserializeState
      packet.stringArgs.append(self.signerId)
      packet.byteArgs.append(state)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeSignerError("unserializeState")

   #############################################################################
   def resolve(self, wltId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_resolve
      packet.stringArgs.append(self.signerId)
      packet.stringArgs.append(wltId)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      if response.ints[0] == 0:
         raise BridgeSignerError("resolve")

   #############################################################################
   def signTx(self, wltId, callback, args):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_signTx
      packet.stringArgs.append(self.signerId)
      packet.stringArgs.append(wltId)

      callbackArgs = [callback]
      callbackArgs.extend(args)
      TheBridge.sendToBridgeProto(
         packet, False, self.signTxCallback, callbackArgs)

   #############################################################################
   def signTxCallback(self, socketResponse, args):
      response = ClientProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      callbackArgs = [response.ints[0]]
      callbackArgs.extend(args[1:])
      callbackThread = threading.Thread(\
         group=None, target=args[0], \
         name=None, args=callbackArgs, kwargs={})
      callbackThread.start()

   #############################################################################
   def getSignedTx(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_getSignedTx
      packet.stringArgs.append(self.signerId)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      return response.reply[0]

   #############################################################################
   def getUnsignedTx(self):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_getUnsignedTx
      packet.stringArgs.append(self.signerId)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.ReplyBinary()
      response.ParseFromString(socketResponse)

      return response.reply[0]


   #############################################################################
   def getSignedStateForInput(self, inputId):
      packet = ClientProto_pb2.ClientCommand()
      packet.method = ClientProto_pb2.signer_getSignedStateForInput
      packet.stringArgs.append(self.signerId)
      packet.intArgs.append(inputId)

      fut = TheBridge.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = ClientProto_pb2.BridgeInputSignedState()
      response.ParseFromString(socketResponse)

      return response

####
TheBridge = ArmoryBridge()
