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
from armoryengine.CppBridge import ServerPush, TheBridge

DISCONNECTED_CALLBACK_ID = 0xff543ad8

BDMPhase_DBHeaders = 1
BDMPhase_OrganizingChain = 2
BDMPhase_BlockHeaders = 3
BDMPhase_BlockData = 4
BDMPhase_Rescan = 5
BDMPhase_Balance = 6
BDMPhase_SearchHashes = 7
BDMPhase_ResolveHashes = 8
BDMPhase_Completed = 9


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
BDV_DISCONNECTED = 'BDV_Disconnected'

CPP_BDM_NOTIF_ID      = "bdm_callback"
CPP_PROGRESS_NOTIF_ID = "progress"

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
class BDMCallbackWrapper(ServerPush):
   def __init__(self, callbackId, callbackFunc):
      super().__init__(callbackId)
      self.callbackFunc = callbackFunc

   def parseProtoPacket(self, protoPacket):
      self.callbackFunc(protoPacket)

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
      self.cppPromptListeners = []
      self.pythonPrompts = {}

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
   @ActLikeASingletonBDM
   def getListenerList(self):
      return self.cppNotificationListenerList

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
      self.cppPromptListeners.append(prompt)

   #############################################################################
   @ActLikeASingletonBDM
   def registerCustomPrompt(self, prompt):
      while True:
         random.seed()
         id = bytes(random.getrandbits(8) for _ in range(10))

         if id in self.pythonPrompts:
            continue

         print ("registering callback id: " + id.hex())
         self.pythonPrompts[id] = prompt
         return id

   #############################################################################
   @ActLikeASingletonBDM
   def unregisterCustomPrompt(self, id):
      if id not in self.pythonPrompts:
         LOGWARN("id missing from pythonPrompts")
         return

      print ("deleting callback id: " + id.hex())
      del self.pythonPrompts[id]

   #############################################################################
   @ActLikeASingletonBDM
   def unregisterCppNotification(self, cppNotificationListener):
      if cppNotificationListener in self.cppNotificationListenerList:
         self.cppNotificationListenerList.remove(cppNotificationListener)

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
      return (self.progressPhase, self.progressComplete, \
         self.secondsRemaining, self.progressNumeric)

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
   @ActLikeASingletonBDM
   def RegisterEventForSignal(self, func, signal):
      def bdmCallback(bdmSignal, args):
         if bdmSignal == signal:
            func(args)
      self.registerCppNotification(bdmCallback)

   #############################################################################
   def pushNotification(self, notifProto):
      act = ''
      arglist = []

      # AOTODO replace with constants
      if notifProto.HasField("ready"):
         print('BDM is ready!')
         act = FINISH_LOAD_BLOCKCHAIN_ACTION
         TheBDM.topBlockHeight = notifProto.ready.height
         TheBDM.setState(BDM_BLOCKCHAIN_READY)

      elif notifProto.HasField("zero_conf"):
         act = NEW_ZC_ACTION
         arglist = notifProto.zero_conf.ledger

      elif notifProto.HasField("new_block"):
         act = NEW_BLOCK_ACTION
         arglist.append(notifProto.new_block.height)
         TheBDM.topBlockHeight = notifProto.new_block.height

      elif notifProto.HasField("refresh"):
         act = REFRESH_ACTION
         arglist = notifProto.refresh.id

      elif notifProto.HasField("error"):
         act = WARNING_ACTION
         arglist.append(notifProto.error)

      elif notifProto.HasField("node_status"):
         act = NODESTATUS_UPDATE
         arglist.append(notifProto.node_status)

      elif notifProto.HasField("disconnected"):
         TheBDM.setState(BDM_OFFLINE)
         act = BDV_DISCONNECTED

      #setup notifs
      elif notifProto.HasField("setup_done"):
         act = SETUP_STEP2
      elif notifProto.HasField("registered"):
         act = SETUP_STEP3

      listenerList = self.getListenerList()
      for cppNotificationListener in listenerList:
         cppNotificationListener(act, *arglist)

   #############################################################################
   def reportProgress(self, notifProto):
      phase = notifProto.progress.phase
      prog = notifProto.progress.progress
      seconds = notifProto.progress.eta_sec
      progressNumeric = notifProto.progress.progress_numeric
      walletVec = notifProto.progress.id

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
            progInfo = [walletVec, prog, phase]
            for cppNotificationListener in self.getListenerList():
               cppNotificationListener(SCAN_ACTION, progInfo)

      except:
         LOGEXCEPT('Error in running progress callback')
         print(sys.exc_info())

   #############################################################################
   def pushFromBridge(self, payloadType, payload, uniqueId, callerId):

      if payloadType == OpaquePayloadType.Value("commandWithCallback"):
         if len(uniqueId) == 0 or uniqueId not in self.pythonPrompts:
            LOGWARN("Unknown prompt id")
            return
         
         customCallback = self.pythonPrompts[uniqueId]
         customCallback(payload, callerId)

      elif payloadType == OpaquePayloadType.Value("prompt"):

         promptProto = UnlockPromptCallback()
         promptProto.ParseFromString(payload)

         for prompt in self.cppPromptListeners:
            prompt(\
               promptProto.promptID, promptProto.promptType, \
               promptProto.verbose, promptProto.walletID, promptProto.state)
      else:
         LOGWARN("Unknown prompt data type")

   #############################################################################
   def startBridge(self, stringArgs, notifyReadyLbd):
      pushNotifCallback = BDMCallbackWrapper(
         CPP_BDM_NOTIF_ID, self.pushNotification)
      reportProgressCallback = BDMCallbackWrapper(
         CPP_PROGRESS_NOTIF_ID, self.reportProgress)

      TheBridge.start(stringArgs, notifyReadyLbd)

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
