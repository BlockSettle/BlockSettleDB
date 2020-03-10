from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
################################################################################
#                                                                              #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
import os.path
import random
import threading
import traceback

from armoryengine.ArmoryUtils import *
from armoryengine.Timer import TimeThisFunction
from armoryengine.BinaryPacker import UINT64
from armoryengine import ClientProto_pb2


BDMAction_Ready         = 1
BDMAction_NewBlock      = 2
BDMAction_ZC            = 3
BDMAction_InvalidatedZC = 4
BDMAction_Refresh       = 5
BDMAction_Exited        = 6
BDMAction_ErrorMsg      = 7
BDMAction_NodeStatus    = 8
BDMAction_BDV_Error     = 9

CppBridge_Ready         = 20
CppBridge_Registered    = 21

BDMPhase_DBHeaders = 1
BDMPhase_OrganizingChain = 2
BDMPhase_BlockHeaders = 3
BDMPhase_BlockData = 4
BDMPhase_Rescan = 5
BDMPhase_Balance = 6
BDMPhase_SearchHashes = 7
BDMPhase_ResolveHashes = 8


BDM_OFFLINE = 'Offline'
BDM_UNINITIALIZED = 'Uninitialized'
BDM_BLOCKCHAIN_READY = 'BlockChainReady'
BDM_SCANNING = 'Scanning'

FINISH_LOAD_BLOCKCHAIN_ACTION = 'FinishLoadBlockchain'   
NEW_ZC_ACTION = 'newZC'
NEW_BLOCK_ACTION = 'newBlock'
REFRESH_ACTION = 'refresh'
STOPPED_ACTION = 'stopped'
WARNING_ACTION = 'warning'
SCAN_ACTION = 'StartedWalletScan'
NODESTATUS_UPDATE = 'NodeStatusUpdate'
BDM_SCAN_PROGRESS = 'BDM_Progress'
BDV_ERROR = 'BDV_Error'

SETUP_STEP2 = 'setup_step1_done'
SETUP_STEP3 = 'setup_step2_done'

def newTheBDM(isOffline=False):
   global TheBDM
   if TheBDM:
      TheBDM.beginCleanShutdown()
   TheBDM = BlockDataManager(isOffline=isOffline)

def getCurrTimeAndBlock():
   time0 = long(RightNowUTC())
   return (time0, TheBDM.getTopBlockHeight())

# Make TheBDM act like it's a singleton. Always use the global singleton TheBDM
# instance that exists in this module regardless of the instance that passed as self
def ActLikeASingletonBDM(func):
   def inner(*args, **kwargs):
      if TheBDM and len(args) > 0:
         newArgs = (TheBDM,) + args[1:]
         return func(*newArgs, **kwargs)
      else:
         return func(*args, **kwargs)
   return inner



################################################################################
class BlockDataManager(object):

   #############################################################################
   def __init__(self, isOffline=False):
      super(BlockDataManager, self).__init__()

      #register callbacks
      self.armoryDBDir = ""
      self.bdv_ = None

      # Flags
      self.aboutToRescan = False
      self.errorOut      = 0

      self.currentActivity = 'None'
      self.walletsToRegister = []

      if isOffline == True: self.bdmState = BDM_OFFLINE
      else: self.bdmState = BDM_UNINITIALIZED

      self.btcdir = BTC_HOME_DIR
      self.armoryDBDir = ARMORY_DB_DIR
      self.datadir = ARMORY_HOME_DIR
      self.lastPctLoad = 0

      self.topBlockHeight = 0
      self.cppNotificationListenerList = []
      self.userPrompts = []

      self.progressComplete=0
      self.secondsRemaining=0
      self.progressPhase=0
      self.progressNumeric=0

      self.remoteDB = False
      if ARMORYDB_IP != ARMORYDB_DEFAULT_IP:
         self.remoteDB = True

      self.exception = ""
      self.cookie = None

      self.witness = False

   #############################################################################  
   def instantiateBDV(self, port):
      if self.bdmState == BDM_OFFLINE:
         return

      socketType = Cpp.SocketFcgi
      if self.remoteDB and not FORCE_FCGI:
         socketType = Cpp.SocketHttp 

      self.bdv_ = Cpp.BlockDataViewer_getNewBDV(\
                     str(ARMORYDB_IP), str(port), socketType)   

   #############################################################################
   def registerBDV(self):
      if self.bdmState == BDM_OFFLINE:
         return

      try:
         self.bdv_.registerWithDB(MAGIC_BYTES)
      except Cpp.DbErrorMsg as e:
         self.exception = e.what()
         LOGERROR('DB error: ' + e.what())
         raise e

   #############################################################################
   @ActLikeASingletonBDM
   def hasRemoteDB(self):
      return self.remoteDB

   #############################################################################
   @ActLikeASingletonBDM
   def getListenerList(self):
      return self.cppNotificationListenerList

   #############################################################################
   @ActLikeASingletonBDM
   def bdv(self):
      return self.bdv_

   #############################################################################
   @ActLikeASingletonBDM
   def getTxByHash(self, txHash):
      return self.bdv().getTxByHash(txHash)

   #############################################################################
   @ActLikeASingletonBDM
   def getSentValue(self, txIn):
      return self.bdv().getSentValue(txIn)

   #############################################################################
   @ActLikeASingletonBDM
   def getTopBlockHeight(self):
      return self.topBlockHeight

   #############################################################################
   @ActLikeASingletonBDM
   def registerCppNotification(self, cppNotificationListener):
      self.cppNotificationListenerList.append(cppNotificationListener)

   #############################################################################
   @ActLikeASingletonBDM
   def registerUserPrompt(self, prompt):
      self.userPrompts.append(prompt)

   #############################################################################
   @ActLikeASingletonBDM
   def unregisterCppNotification(self, cppNotificationListener):
      if cppNotificationListener in self.cppNotificationListenerList:
         self.cppNotificationListenerList.remove(cppNotificationListener)

   #############################################################################
   @ActLikeASingletonBDM
   def registerWallet(self, prefixedKeys, uniqueIDB58, isNew=False):
      #this returns a pointer to the BtcWallet C++ object. This object is
      #instantiated at registration and is unique for the BDV object, so we
      #should only ever set the cppWallet member here 
      return self.bdv().registerWallet(uniqueIDB58, prefixedKeys, isNew)

   #############################################################################
   @ActLikeASingletonBDM
   def registerLockbox(self, uniqueIDB58, addressList, isNew=False):
      #this returns a pointer to the BtcWallet C++ object. This object is
      #instantiated at registration and is unique for the BDV object, so we
      #should only ever set the cppWallet member here 
      return self.bdv().registerLockbox(uniqueIDB58, addressList, isNew)

   #############################################################################
   @ActLikeASingletonBDM
   def setSatoshiDir(self, newBtcDir):
      if not os.path.exists(newBtcDir):
         LOGERROR('setSatoshiDir: directory does not exist: %s', newBtcDir)
         return

      self.btcdir = newBtcDir
         
   #############################################################################
   @ActLikeASingletonBDM
   def predictLoadTime(self):
      return (self.progressPhase, self.progressComplete, self.secondsRemaining, self.progressNumeric)

   #############################################################################
   @TimeThisFunction
   @ActLikeASingletonBDM
   def createAddressBook(self, cppWlt):
      return cppWlt.createAddressBook()

   #############################################################################
   @ActLikeASingletonBDM
   def setState(self, state):
      self.bdmState = state

   #############################################################################
   @ActLikeASingletonBDM
   def getState(self):
      return self.bdmState

   #############################################################################
   @ActLikeASingletonBDM
   def shutdown(self):
      if self.bdmState == BDM_OFFLINE:
         return

      try:
         if CLI_OPTIONS.bip150Used or CLI_OPTIONS.bip151Used:
            Cpp.DisableBIP151()
         self.bdv_.unregisterFromDB()
         self.callback.shutdown()

         cookie = self.getCookie()
         self.bdv_.shutdown(cookie)
      except:
         pass

   #############################################################################
   def getCookie(self):
      if self.cookie == None:
         self.cookie = Cpp.BlockDataManagerConfig_getCookie(str(self.datadir))
      return self.cookie

   #############################################################################
   @ActLikeASingletonBDM
   def runBDM(self, fn):
      return self.inject.runCommand(fn)

   #############################################################################
   @ActLikeASingletonBDM
   def RegisterEventForSignal(self, func, signal):
      def bdmCallback(bdmSignal, args):
         if bdmSignal == signal:
            func(args)
      self.registerCppNotification(bdmCallback)

   #############################################################################
   def setWitness(self, wit):
      self.witness = wit   

   #############################################################################
   def isSegWitEnabled(self):
      return self.witness or FORCE_SEGWIT

   #############################################################################
   def pushNotification(self, notifProto):
      try:
         act = ''
         arglist = []

         # AOTODO replace with constants
         action = notifProto.type
         block = notifProto.height

         if action == BDMAction_Ready:
            print('BDM is ready!')
            act = FINISH_LOAD_BLOCKCHAIN_ACTION
            TheBDM.topBlockHeight = block
            TheBDM.setState(BDM_BLOCKCHAIN_READY)

         elif action == BDMAction_ZC:
            act = NEW_ZC_ACTION
            argLedgers = ClientProto_pb2.BridgeLedgers()
            argLedgers.ParseFromString(notifProto.opaque[0])
            arglist = argLedgers.le

         elif action == BDMAction_NewBlock:
            act = NEW_BLOCK_ACTION
            arglist.append(block)
            TheBDM.topBlockHeight = block

         elif action == BDMAction_Refresh:
            act = REFRESH_ACTION
            arglist = arg
            
         elif action == BDMAction_Exited:
            act = STOPPED_ACTION

         elif action == BDMAction_ErrorMsg:
            act = WARNING_ACTION
            argstr = Cpp.BtcUtils_cast_to_string(arg)
            arglist.append(argstr)

         elif action == BDMAction_BDV_Error:
            act = BDV_ERROR
            argBdvError = Cpp.BDV_Error_Struct_cast_to_BDVErrorStruct(arg)
            arglist.append(argBdvError)

         elif action == BDMAction_NodeStatus:
            act = NODESTATUS_UPDATE
            argNodeStatus = ClientProto_pb2.BridgeNodeStatus()
            argNodeStatus.ParseFromString(notifProto.opaque[0])
            arglist.append(argNodeStatus)

         #setup notifs
         elif action == CppBridge_Ready:
            act = SETUP_STEP2
         elif action == CppBridge_Registered:
            act = SETUP_STEP3

         listenerList = self.getListenerList()
         for cppNotificationListener in listenerList:
            cppNotificationListener(act, arglist)
      except:
         LOGEXCEPT('Error in running callback')
         print(sys.exc_info())
         raise

   #############################################################################
   def reportProgress(self, notifProto):
      phase = notifProto.phase
      prog = notifProto.progress
      seconds = notifProto.etaSec
      progressNumeric = notifProto.progressNumeric
      walletVec = notifProto.ids

      try:
         if len(walletVec) == 0:
            self.progressPhase = phase
            self.progressComplete = prog
            self.secondsRemaining = seconds
            self.progressNumeric = progressNumeric

            self.bdmState = BDM_SCANNING

            for cppNotificationListener in self.getListenerList():
               cppNotificationListener(BDM_SCAN_PROGRESS, [None, None])            
         else:
            progInfo = [walletVec, prog]
            for cppNotificationListener in self.getListenerList():
               cppNotificationListener(SCAN_ACTION, progInfo)

      except:
         LOGEXCEPT('Error in running progress callback')
         print(sys.exc_info())

   #############################################################################
   def promptUser(self, promptID, promptType, verbose, wltID, state):
      for prompt in self.userPrompts:
         prompt(promptID, promptType, verbose, wltID, state)

################################################################################
# Make TheBDM reference the asyncrhonous BlockDataManager wrapper if we are 
# running 
TheBDM = None
if CLI_OPTIONS.offline:
   LOGINFO('Armory loaded in offline-mode.  Will not attempt to load ')
   LOGINFO('blockchain without explicit command to do so.')
   TheBDM = BlockDataManager(isOffline=True)

else:
   # NOTE:  "TheBDM" is sometimes used in the C++ code to reference the
   #        singleton BlockDataManager_LevelDB class object.  Here, 
   #        "TheBDM" refers to a python BlockDataManagerThead class 
   #        object that wraps the C++ version.  It implements some of 
   #        it's own methods, and then passes through anything it 
   #        doesn't recognize to the C++ object.
   LOGINFO('Using the asynchronous/multi-threaded BlockDataManager.')
   LOGINFO('Blockchain operations will happen in the background.  ')
   LOGINFO('Devs: check TheBDM.getState() before asking for data.')
   LOGINFO('Registering addresses during rescans will queue them for ')
   LOGINFO('inclusion after the current scan is completed.')
   TheBDM = BlockDataManager(isOffline=False)

   cppLogFile = os.path.join(ARMORY_HOME_DIR, 'armorycpplog.txt')
   cpplf = cppLogFile
   if OS_WINDOWS and isinstance(cppLogFile, unicode):
      cpplf = cppLogFile.encode('utf8')

# Put the import at the end to avoid circular reference problem
from armoryengine.MultiSigUtils import MultiSigLockbox
from armoryengine.Transaction import PyTx
