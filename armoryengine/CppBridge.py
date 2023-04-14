################################################################################
#                                                                              #
# Copyright (C) 2019-2023, goatpig.                                            #
#  Distributed under the MIT license                                           #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                      #
#                                                                              #
################################################################################

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import os
import errno
import socket
from armoryengine import BridgeProto_pb2
from armoryengine.ArmoryUtils import LOGDEBUG, LOGERROR, hash256
from armoryengine.BinaryPacker import BinaryPacker, \
   UINT32, UINT8, BINARY_CHUNK, VAR_INT
from struct import unpack
import atexit
import threading
import base64
import subprocess

from concurrent.futures import ThreadPoolExecutor

from armoryengine.ArmoryUtils import PassphraseError
from armoryengine.BIP15x import \
    BIP15xConnection, AEAD_THRESHOLD_BEGIN, AEAD_Error, \
    CHACHA20POLY1305MAXPACKETSIZE
BRIDGE_CLIENT_HEADER = 1

################################################################################
##
#### Exceptions
##
################################################################################
class BridgeError(Exception):
   pass

################################################################################
class BridgeSignerError(Exception):
   pass

################################################################################
##
#### Tools
##
################################################################################
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
##
#### bridge socket
##
################################################################################
class BridgeSocket(object):
   recvLen = 4

   #############################################################################
   ## setup
   def __init__(self):
      self.idCounter = 0
      self.responseDict = {}
      self.callbackDict = {}
      self.bip15xConnection = BIP15xConnection(self.sendToBridgeRaw)
      self.run = False
      self.rwLock = None

   ####
   def setCallback(self, key, func):
      self.callbackDict[key] = func

   def unsetCallback(self, key):
      del self.callbackDict[key]

   #############################################################################
   ## listen socket setup
   def start(self, stringArgs, notifyReadyLbd):
      self.bip15xConnection.setNotifyReadyLbd(notifyReadyLbd)

      self.run = True
      self.rwLock = threading.Lock()

      self.executor = ThreadPoolExecutor(max_workers=2)
      listenFut = self.executor.submit(self.listenOnBridge)

      #append gui pubkey to arg list and spawn bridge
      os.environ['SERVER_PUBKEY'] = self.bip15xConnection.getPubkeyHex()
      self.processFut = self.executor.submit(self.spawnBridge, stringArgs)

      #block until listen socket receives bridge connection
      self.clientSocket = listenFut.result()

      #start socket read thread
      self.clientFut = self.executor.submit(self.readBridgeSocket)

      #initiate AEAD handshake (server has to start it)
      self.bip15xConnection.serverStartHandshake()

   ####
   def stop(self):
      self.rwLock.acquire(True)

      self.run = False
      self.clientSocket.close()
      self.listenSocket.close()

      self.rwLock.release()
      self.clientFut.result()

   #############################################################################
   ## bridge management
   def listenOnBridge(self):
      #setup listener

      portNumber = 46122
      self.listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.listenSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
      self.listenSocket.bind(("127.0.0.1", portNumber))
      self.listenSocket.listen()

      clientSocket, clientIP = self.listenSocket.accept()
      return clientSocket

   ####
   def spawnBridge(self, stringArgs):
      subprocess.run(["./build/CppBridge", stringArgs])

   #############################################################################
   ## socket write
   def encryptPayload(self, clearText):
      if not self.bip15xConnection.encrypted():
         raise AEAD_Error("channel is not encrypted")

      cipherText = []
      if self.bip15xConnection.needsRekey(len(clearText)):
         cipherText.append(self.bip15xConnection.getRekeyPayload())
      cipherText.append(\
         self.bip15xConnection.encrypt(clearText, len(clearText)))

      return cipherText

   ####
   def sendToBridgeProto(self, msg, needsReply,
      callbackFunc, callbackArgs, msgType):

      msg.reference_id = self.idCounter
      self.idCounter = self.idCounter + 1

      payload = msg.SerializeToString()
      result = self.sendToBridgeBinary(payload, msg.reference_id,
         needsReply, callbackFunc, callbackArgs, msgType)

      if needsReply:
         return result

   ####
   def sendToBridgeBinary(self, payload, payloadId,
      needsReply=True, callback=None, cbArgs=[],
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

      if callback != None:
         #set callable in response dict
         wrapper = CallbackWrapper(callback, cbArgs)
         self.responseDict[payloadId] = wrapper

      elif needsReply:
         #instantiate prom/future object and set in response dict
         fut = PyPromFut()
         self.responseDict[payloadId] = fut

      #send over the wire, may have 2 payloads if we triggered a rekey
      for p in encryptedPayloads:
         self.clientSocket.sendall(p)

      #return future to caller
      self.rwLock.release()

      if callback == None and needsReply:
         return fut

   ####
   def sendToBridgeRaw(self, msg):
      self.rwLock.acquire(True)
      self.clientSocket.sendall(msg)
      self.rwLock.release()

   #############################################################################
   ## socket read
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

   ####
   def readBridgeSocket(self):
      while self.run is True:
         #wait for data on the socket
         try:
            response = self.clientSocket.recv(self.recvLen)

            if len(response) < self.recvLen:
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
         fullPacket = response[1:]

         #deser protobuf reply
         protoPayload = BridgeProto_pb2.Payload()
         if not protoPayload.ParseFromString(fullPacket):
            raise BridgeError("failed to parse proto payload")

         #payloads are either replies or callbacks
         if protoPayload.HasField('reply'):
            reply = protoPayload.reply
            referenceId = reply.reference_id

            #lock and look for future object in response dict
            self.rwLock.acquire(True)
            if referenceId not in self.responseDict:
               LOGWARN(f"unknown reply referenceId: {referenceId}")
               self.rwLock.release()
               continue

            #TODO: general error handling on reply.success == False

            #grab the future, delete it from dict
            replyHandler = self.responseDict[referenceId]
            del self.responseDict[referenceId]

            #fill the promise & release lock
            self.rwLock.release()

            if isinstance(replyHandler, PyPromFut):
               replyHandler.setVal(reply)

            elif isinstance(replyHandler, CallbackWrapper):
               replyHandler.execute(reply)

         elif protoPayload.HasField('callback'):
            callbackData = protoPayload.callback
            callbackId = callbackData.callback_id

            #find the callback listener
            self.rwLock.acquire(True)
            if callbackId not in self.callbackDict:
               LOGWARN(f"ignoring callback id: {callbackId}")
               self.rwLock.release()
               continue

            #call it with the payload
            callbackFunc = self.callbackDict[callbackId]
            self.rwLock.release()
            callbackFunc.process(callbackData)

################################################################################
##
#### proto wrappers
##
################################################################################
class ProtoWrapper(object):
   ##
   def __init__(self, bridgeSocket):
      self.bridgeSocket = bridgeSocket

   ##
   def send(self, msg, needsReply=True, callback=None, cbArgs=[],
      msgType=BRIDGE_CLIENT_HEADER):
      return self.bridgeSocket.sendToBridgeProto(msg,
         needsReply, callback, cbArgs, msgType)

################################################################################
class BlockchainService(ProtoWrapper):
   #############################################################################
   ## setup ##
   def __init__(self, bridgeSocket):
      super().__init__(bridgeSocket)

   #############################################################################
   ## commands ##
   def loadWallets(self, callbackFunc, pushObj):
      #create protobuf packet
      packet = BridgeProto_pb2.Request()
      packet.service.load_wallets.callback_id = pushObj.callbackId

      #send to the socket
      self.send(packet, callback=callbackFunc)

   ####
   def shutdown(self):
      packet = BridgeProto_pb2.Request()
      packet.service.shutdown = True
      self.send(packet)
      self.bridgeSocket.stop()

   ####
   def setupDB(self):
      packet = BridgeProto_pb2.Request()
      packet.service.setup_db = True
      self.send(packet, needsReply=False)

   ####
   def registerWallets(self):
      packet = BridgeProto_pb2.Request()
      packet.service.register_wallets = True
      self.send(packet, needsReply=False)

   ####
   def goOnline(self):
      packet = BridgeProto_pb2.Request()
      packet.service.go_online = True
      self.send(packet, needsReply=False)

   ####
   def getLedgerDelegateIdForWallets(self):
      packet = BridgeProto_pb2.Request()
      packet.service.get_ledger_delegate_id_for_wallets = True

      fut = self.send(packet)
      response = fut.getVal()
      return response.service.ledger_delegate_id

   ####
   def updateWalletsLedgerFilter(self, ids):
      packet = BridgeProto_pb2.Request()
      method = packet.service.update_wallets_ledger_filter
      for id in ids:
         method.wallet_id.append(id)

      self.send(packet, needsReply=False)

   ####
   def getNodeStatus(self):
      packet = BridgeProto_pb2.Request()
      packet.service.get_node_status = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.service.node_status

   ####
   def registerWallet(self, walletId, isNew):
      packet = BridgeProto_pb2.Request()
      method = packet.service.register_wallet
      method.id = walletId
      method.is_new = isNew

      self.send(packet, needsReply=False)

   ####
   def getHistoryPageForDelegate(self, delegateId, pageId):
      packet = BridgeProto_pb2.Request()
      method = packet.service.get_history_page_for_delegate
      method.delegate_id = delegateId
      method.page_id = pageId

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.service.ledger_history

   ####
   def getTxByHash(self, hashVal):
      packet = BridgeProto_pb2.Request()
      packet.service.get_tx_by_hash.tx_hash = hashVal

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         return None
      return reply.service.tx

   ####
   def getHeaderByHeight(self, height):
      packet = BridgeProto_pb2.Request()
      method = packet.service.get_header_by_height.height = height

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.service.header_data

   ####
   def estimateFee(self, blocks, strat):
      packet = BridgeProto_pb2.Request()
      method = packet.service.estimate_fee
      method.blocks = blocks
      method.strat = strat

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise Exception(reply.error)
      return reply.service.fee_estimate

   ####
   def broadcastTx(self, rawTx):
      packet = BridgeProto_pb2.Request()
      method = packet.service.broadcast_tx
      method.raw_tx.append(rawTx)
      self.send(packet, needsReply=False)

################################################################################
class BlockchainUtils(ProtoWrapper):
   #############################################################################
   ## setup ##
   def __init__(self, bridgeSocket):
      super().__init__(bridgeSocket)
      self.addrTypeStrByType = {}

   #############################################################################
   ## commands ##
   def getNameForAddrType(self, addrType):
      if addrType in self.addrTypeStrByType:
         return self.addrTypeStrByType[addrType]

      packet = BridgeProto_pb2.Request()
      packet.utils.get_name_for_addr_type.address_type = addrType

      fut = self.send(packet)
      reply = fut.getVal()
      if not reply.success:
         raise BridgeError(
            f"[getNameForAddrType] failed with error: {reply.error}")

      addrTypeStr = reply.utils.address_type_name
      self.addrTypeStrByType[addrType] = addrTypeStr
      return addrTypeStr

   ####
   def getHash160(self, data):
      packet = BridgeProto_pb2.Request()
      packet.utils.get_hash_160.data = data

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.utils.hash

   ####
   def generateRandomHex(self, size):
      packet = BridgeProto_pb2.Request()
      packet.utils.generate_random_hex.length = size

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.utils.random_hex

   ####
   def getScrAddrForAddrStr(self, addrStr):
      packet = BridgeProto_pb2.Request()
      packet.utils.get_scraddr_for_addrstr.address = addrStr
      fut = self.send(packet)
      reply = fut.getVal()

      if reply.success == False:
         raise BridgeError(
            f"[getScrAddrForAddrStr] failed with error: {reply.error}")
      return reply.utils.scraddr

   ####
   def createWallet(self, addrPoolSize, passphrase, controlPassphrase,
      shortLabel, longLabel, extraEntropy):
      packet = BridgeProto_pb2.Request()
      method = packet.utils.create_wallet

      method.lookup = addrPoolSize
      method.passphrase = passphrase
      method.control_passphrase = controlPassphrase
      method.label = shortLabel
      method.description = longLabel

      if extraEntropy is not None:
         method.extra_entropy = extraEntropy

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeError(
            f"[createWallet] failed with error: {reply.error}")
      return reply.utils.wallet_id

################################################################################
class BridgeWalletWrapper(ProtoWrapper):
   #############################################################################
   ## setup ##
   def __init__(self, walletId):
      super().__init__(TheBridge.bridgeSocket)
      self.walletId = walletId

   ####
   def getPacket(self):
      packet = BridgeProto_pb2.Request()
      packet.wallet.id = self.walletId
      return packet

   #############################################################################
   ## commands ##
   def getBalanceAndCount(self):
      packet = self.getPacket()
      packet.wallet.get_balance_and_count = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.balance_and_count

   ####
   def getAddrCombinedList(self):
      packet = self.getPacket()
      packet.wallet.get_addr_combined_list = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.address_and_balance_data

   ####
   def getHighestUsedIndex(self):
      packet = self.getPacket()
      packet.wallet.get_highest_used_index = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.highest_used_index

   ####
   def extendAddressPool(self, progressId, count, callback):
      def finishExtension(reply, args):
         callbackThread = threading.Thread(
            group=None, target=args[0],
            name=None, args=[reply], kwargs={})
         callbackThread.start()

      packet = self.getPacket()
      method = packet.wallet.extend_address_pool
      method.count = count
      method.callback_id = progressId
      self.send(packet, False, finishExtension, [callback])

   ####
   def createBackupStringForWallet(self,
      serverPushObj, callbackFunc, callbackArgs=[]):
      packet = self.getPacket()
      method = packet.wallet.create_backup_string
      method.callback_id = serverPushObj.callbackId
      self.send(packet, callback=callbackFunc, cbArgs=callbackArgs)

   ####
   def setAddressTypeFor(self, assetId, addrType):
      packet = self.getPacket()
      method = packet.wallet.set_address_type_for
      method.asset_id = assetId
      method.address_type = addrType

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.address_data

   ####
   def setComment(self, key, val):
      packet = self.getPacket()
      method = packet.wallet.set_comment
      method.hash_key = key
      method.comment = val
      self.send(packet, False)

   ####
   def setLabels(self, title, desc):
      packet = self.getPacket()
      method = packet.wallet.set_labels
      method.title = title
      method.description = desc
      self.send(packet, False)

   ####
   def initCoinSelectionInstance(self, height):
      packet = self.getPacket()
      method = packet.wallet.setup_new_coin_selection_instance
      method.height = height

      fut = self.send(packet)
      reply = fut.getVal()
      return BridgeCoinSelectionWrapper(reply.wallet.coin_selection_id)

   ####
   def createAddressBook(self):
      packet = self.getPacket()
      packet.wallet.create_address_book = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.address_book

   ####
   def getUtxosForValue(self, value):
      packet = self.getPacket()
      method = packet.wallet.get_utxos_for_value
      method.value = value

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.utxo_list

   ####
   def getSpendableZCList(self):
      packet = self.getPacket()
      packet.wallet.get_spendable_zc_list = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.utxo_list

   ####
   def getRBFTxOutList(self):
      packet = self.getPacket()
      packet.wallet.get_rbf_txout_list = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.utxo_list

   ####
   def getNewAddress(self, addrType):
      packet = self.getPacket()
      packet.wallet.get_new_address.type = addrType

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.address_data

   ####
   def getNewChangeAddr(self, addrType):
      packet = self.getPacket()
      packet.wallet.get_change_address.type = addrType

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.address_data

   ####
   def peekChangeAddress(self, addrType):
      packet = self.getPacket()
      packet.wallet.peek_change_address.type = addrType

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.address_data

   ####
   def getData(self):
      packet = self.getPacket()
      packet.wallet.get_data = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.wallet_data

   ####
   def delete(self, wltId):
      packet = self.getPacket()
      packet.wallet.delete = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.success

   ####
   def getLedgerDelegateIdForScrAddr(self, scrAddr):
      packet = self.getPacket()
      packet.wallet.get_ledger_delegate_id_for_scraddr.hash = scrAddr

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.wallet.ledger_delegate_id

################################################################################
class BridgeCoinSelectionWrapper(ProtoWrapper):
   #############################################################################
   ## setup ##
   def __init__(self, csId):
      super().__init__(TheBridge.bridgeSocket)
      self.coinSelectionId = csId

   ####
   def getPacket(self):
      packet = BridgeProto_pb2.Request()
      packet.coin_selection.id = self.coinSelectionId
      return packet

   #############################################################################
   ## commands ##
   def destroyCoinSelectionInstance(self):
      packet = self.getPacket()
      packet.coin_selection.cleanup = True
      self.send(packet, False)

   #############################################################################
   def setCoinSelectionRecipient(self, addrStr, value, recId):
      packet = self.getPacket()
      method = packet.coin_selection.set_recipient
      method.address = addrStr
      method.value = value
      method.id = recId

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeError(
            f"[setCoinSelectionRecipient] failed with error: {reply.error}")

   #############################################################################
   def reset(self):
      packet = self.getPacket()
      packet.coin_selection.reset = True
      self.send(packet, False)

   #############################################################################
   def selectUTXOs(self, fee, feePerByte, processFlags):
      packet = self.getPacket()
      method = packet.coin_selection.select_utxos
      method.flags = processFlags

      if fee != 0:
         method.flat_fee = fee
      else:
         method.fee_byte = feePerByte

      fut = self.send(packet)
      relpy = fut.getVal()
      if relpy.success == False:
         raise BridgeError(f"[selectUTXOs] failed with error: {reply.error}")

   #############################################################################
   def getUtxoSelection(self):
      packet = self.getPacket()
      packet.coin_selection.get_utxo_selection = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.coin_selection.utxo_list

   #############################################################################
   def getFlatFee(self):
      packet = self.getPacket()
      packet.coin_selection.get_flat_fee = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.coin_selection.flat_fee

   #############################################################################
   def getFeeByte(self):
      packet = self.getPacket()
      packet.coin_selection.get_fee_byte = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.coin_selection.fee_byte

   #############################################################################
   def getSizeEstimate(self):
      packet = self.getPacket()
      packet.coin_selection.get_size_estimate = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.coin_selection.size_estimate

   #############################################################################
   def processCustomUtxoList(self, utxoList, fee, feePerByte, processFlags):
      packet = self.getPacket()
      method = packet.coin_selection.process_custom_utxo_list

      method.flags = processFlags
      for utxo in utxoList:
         method.utxos.append(utxo.toBridgeUtxo())

      if fee != 0:
         method.flat_fee = fee
      else:
         method.fee_byte = feePerByte

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeError("ProcessCustomUtxoList failed")

   #############################################################################
   def getFeeForMaxVal(self, feePerByte):
      packet = self.getPacket()
      method = packet.coin_selection.get_fee_for_max_val
      method.fee_byte = feePerByte

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.coin_selection.flat_fee

   #############################################################################
   def getFeeForMaxValUtxoVector(self, utxoList, feePerByte):
      packet = self.getPacket()
      method = packet.coin_selection.get_fee_for_max_val
      method.fee_byte = feePerByte

      for utxo in utxoList:
         method.utxos.append(utxo.toBridgeUtxo())

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.coin_selection.flat_fee

################################################################################
class ScriptUtils(ProtoWrapper):
   #############################################################################
   ## setup ##
   def __init__(self, bridgeSocket):
      super().__init__(bridgeSocket)

   ####
   def getPacket(self, script):
      packet = BridgeProto_pb2.Request()
      packet.script_utils.script = script
      return packet

   #############################################################################
   ## commands ##
   def getTxOutScriptType(self, script):
      packet = self.getPacket(script)
      packet.script_utils.get_txout_script_type = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.script_utils.txout_script_type

   ####
   def getTxInScriptType(self, script, hashVal):
      packet = self.getPacket(script)
      packet.script_utils.get_txin_script_type.hash = hashVal

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.script_utils.txin_script_type

   ####
   def getLastPushDataInScript(self, script):
      packet = self.getPacket(script)
      packet.script_utils.get_last_push_data_in_script = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.script_utils.push_data

   ####
   def getTxOutScriptForScrAddr(self, script):
      packet = self.getPacket(script)
      packet.script_utils.get_txout_script_for_scraddr = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.script_utils.script_data

   ####
   def getScrAddrForScript(self, script):
      packet = self.getPacket(script)
      packet.script_utils.get_scraddr_for_script = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.script_utils.scraddr

   ####
   def getAddrStrForScrAddr(self, scrAddr):
      packet = self.getPacket(scrAddr)
      packet.script_utils.get_addrstr_for_scraddr = True

      fut = self.send(packet)
      reply = fut.getVal()

      if reply.success == False:
         raise BridgeError(f"error in getAddrStrForScrAddr: {reply.error}")
      else:
         return reply.script_utils.address_string

################################################################################
class BridgeSigner(ProtoWrapper):
   #############################################################################
   ## setup ##
   def __init__(self):
      super().__init__(TheBridge.bridgeSocket)
      self.signerId = None

   ####
   def __del__(self):
      self.cleanup()

   ####
   def getPacket(self):
      if self.signerId == None or not self.signerId:
         raise BridgeSignerError("[BridgeSigner] missing signerId")

      packet = BridgeProto_pb2.Request()
      packet.signer.id = self.signerId
      return packet

   #############################################################################
   def initNew(self):
      if self.signerId != None:
         raise BridgeSignerError("[initNew] signer already has an id")

      packet = BridgeProto_pb2.Request()
      packet.signer.id = ""
      packet.signer.get_new = True

      fut = self.send(packet)
      reply = fut.getVal()
      self.signerId = reply.signer.signer_id

   #############################################################################
   def cleanup(self):
      packet = self.getPacket()
      packet.signer.cleanup = True

      self.send(packet, False)
      self.signerId = None

   #############################################################################
   def setVersion(self, version):
      packet = self.getPacket()
      packet.signer.set_version.version = version

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(
            f"[setVersion] failed with error: {reply.error}")

   #############################################################################
   def setLockTime(self, locktime):
      packet = self.getPacket()
      packet.signer.set_lock_time.lock_time = locktime

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(
            f"[setLockTime] failed with error: {reply.error}")

   #############################################################################
   def addSpenderByOutpoint(self, hashVal, txoutid, seq):
      packet = self.getPacket()
      method = packet.signer.add_spender_by_outpoint
      method.hash = hashVal
      method.tx_out_id = txoutid
      method.sequence = seq

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(
            f"[addSpenderByOutpoint] failed with error: {reply.error}")

   #############################################################################
   def populateUtxo(self, hashVal, txoutid, value, script):
      packet = self.getPacket()
      method = packet.signer.populate_utxo
      method.hash = hashVal
      method.tx_out_id = txoutid
      method.value = value
      method.script = script

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(
            f"[addSpenderByOutpoint] failed with error: {reply.error}")

   #############################################################################
   def addSupportingTx(self, rawTxData):
      packet = self.getPacket()
      packet.signer.add_supporting_tx.raw_tx = rawTxData

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(
            f"[addSupportingTx] failed with error: {reply.error}")

   #############################################################################
   def addRecipient(self, value, script):
      packet = self.getPacket()
      method = packet.signer.add_recipient
      method.value = value
      method.script = script

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(
            f"[addRecipient] failed with error: {reply.error}")

   #############################################################################
   def toTxSigCollect(self, ustxType):
      packet = self.getPacket()
      packet.signer.to_tx_sig_collect.ustx_type = ustxType

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.signer.tx_sig_collect

   #############################################################################
   def fromTxSigCollect(self, txSigCollect):
      packet = self.getPacket()
      packet.signer.from_tx_sig_collect.tx_sig_collect = txSigCollect

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(
            f"[fromTxSigCollect] failed with error: {reply.error}")

   #############################################################################
   def resolve(self, wltId):
      packet = self.getPacket()
      packet.signer.resolve.wallet_id = wltId

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         raise BridgeSignerError(f"[resolve] failed with error: {reply.error}")

   #############################################################################
   def signTx(self, wltId, serverPushObj, callbackFunc, callbackArgs=[]):
      packet = self.getPacket()
      packet.signer.sign_tx.wallet_id = wltId
      packet.signer.sign_tx.callback_id = serverPushObj.callbackId
      self.send(packet, callback=callbackFunc, cbArgs=callbackArgs)

   #############################################################################
   def getSignedTx(self):
      packet = self.getPacket()
      packet.signer.get_signed_tx = True

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         return None
      return reply.signer.tx_data

   #############################################################################
   def getUnsignedTx(self):
      packet = self.getPacket()
      packet.signer.get_unsigned_tx = True

      fut = self.send(packet)
      reply = fut.getVal()
      if reply.success == False:
         return None
      return reply.signer.tx_data

   #############################################################################
   def getSignedStateForInput(self, inputId):
      packet = self.getPacket()
      packet.signer.get_signed_state_for_input.input_id = inputId

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.signer.input_signed_state

   #############################################################################
   def fromType(self):
      packet = self.getPacket()
      packet.signer.get_unsigned_tx = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.signer.from_type

   #############################################################################
   def canLegacySerialize(self):
      packet = self.getPacket()
      packet.signer.can_legacy_serialize = True

      fut = self.send(packet)
      reply = fut.getVal()
      return reply.success

################################################################################
class ArmoryBridge(object):

   #############################################################################
   def __init__(self):
      self.blockTimeByHeightCache = {}
      self.bridgeSocket = BridgeSocket()

      self.service      = BlockchainService(self.bridgeSocket)
      self.utils        = BlockchainUtils(self.bridgeSocket)
      self.scriptUtils  = ScriptUtils(self.bridgeSocket)

   #############################################################################
   def start(self, stringArgs, notifyReadyLbd):
      self.bridgeSocket.start(stringArgs, notifyReadyLbd)

   #############################################################################
   def send(self, msg, needsReply=True, callback=None, cbArgs=[],
      msgType=BRIDGE_CLIENT_HEADER):
      self.bridgeSocket.sendToBridgeProto(msg,
         needsReply, callback, cbArgs, msgType)

   #############################################################################
   def pushNotification(self, callbackData):
      notifThread = threading.Thread(\
         group=None, target=TheBDM.pushNotification, \
         name=None, args=[callbackData], kwargs={})
      notifThread.start()

   #############################################################################
   def pushProgressNotification(self, data):
      payload = BridgeProto_pb2.CppProgressCallbackMsg()
      payload.ParseFromString(data)

      TheBDM.reportProgress(payload)

   #############################################################################
   def getBlockTimeByHeight(self, height):
      if height in self.blockTimeByHeightCache:
         return self.blockTimeByHeightCache[height]

      packet = BridgeProto_pb2.Request()
      packet.method = BridgeProto_pb2.getBlockTimeByHeight
      packet.intArgs.append(height)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = BridgeProto_pb2.ReplyNumbers()
      response.ParseFromString(socketResponse)

      blockTime = response.ints[0]

      if blockTime == 2**32 - 1:
         raise BridgeError("invalid block time")

      self.blockTimeByHeightCache[height] = blockTime
      return blockTime

   #############################################################################
   def restoreWallet(self, root, chaincode, sppass, callbackId):
      opaquePayload = BridgeProto_pb2.RestoreWalletPayload()
      opaquePayload.root.extend(root)
      opaquePayload.secondary.extend(chaincode)
      opaquePayload.spPass = sppass

      packet = BridgeProto_pb2.Request()
      packet.method = BridgeProto_pb2.methodWithCallback
      packet.methodWithCallback = BridgeProto_pb2.restoreWallet

      packet.byteArgs.append(callbackId)
      packet.byteArgs.append(opaquePayload.SerializeToString())

      self.sendToBridgeProto(packet, False)

   #############################################################################
   def getHistoryForWalletSelection(self, wltIDList, order):
      packet = BridgeProto_pb2.Request()
      packet.method = BridgeProto_pb2.getHistoryForWalletSelection
      packet.stringArgs.append(order)
      for wltID in wltIDList:
         packet.stringArgs.append(wltID)

      fut = self.sendToBridgeProto(packet)
      socketResponse = fut.getVal()

      response = BridgeProto_pb2.BridgeLedgers()
      response.ParseFromString(socketResponse)

      return response

################################################################################
class CallbackWrapper(object):
   def __init__(self, callbackFunc, callbackArgs=[]):
      self.callbackFunc = callbackFunc
      self.callbackArgs = callbackArgs

   def execute(self, replyObj):
      callbackThread = threading.Thread(
         group=None, target=self.callbackFunc,
         name=None, args=[*self.callbackArgs, replyObj], kwargs={})
      callbackThread.start()

################################################################################
class ServerPush(ProtoWrapper):
   def __init__(self, callbackId=""):
      super().__init__(TheBridge.bridgeSocket)

      if len(callbackId) == 0:
         self.callbackId = base64.b16encode(os.urandom(10)).decode('utf-8')
      else:
         self.callbackId = callbackId
      self.bridgeSocket.setCallback(self.callbackId, self)

      self.refId = 0
      self.packet = None

   def parseProtoPacket(self, protoPacket):
      raise Exception("override me")

   def process(self, protoPacket):
      if protoPacket.HasField('cleanup'):
         self.bridgeSocket.unsetCallback(self.callbackId)

      self.refId = protoPacket.reference_id
      self.parseProtoPacket(protoPacket)

   def getNewPacket(self):
      self.packet = BridgeProto_pb2.Request()
      self.packet.callback_reply.reference_id = self.refId
      self.refId = 0
      return self.packet.callback_reply

   def reply(self):
      self.send(self.packet, needsReply=False)
      self.packet = None



####
TheBridge = ArmoryBridge()
