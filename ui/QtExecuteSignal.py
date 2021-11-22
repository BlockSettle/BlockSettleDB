from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
##############################################################################
#                                                                            #
# Copyright (C) 2017, goatpig                                                #
#  Distributed under the MIT license                                         #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                    #
#                                                                            #
##############################################################################

from PySide2.QtCore import QObject, Signal
from threading import Thread
from time import sleep

from armoryengine.ArmoryUtils import LOGERROR

################################################################################
class QtExecuteSignalError(Exception):
   pass

##############################################################################
class QtExecuteSignal(QObject):

   executeSignal = Signal(list)

   ###########################################################################
   def __init__(self, mainWnd):
      super(QtExecuteSignal, self).__init__(mainWnd)
      self.mainWnd = mainWnd
      self.executeSignal.connect(self.methodSlot)
      self.waiting = {}

   ###########################################################################
   def executeMethod(self, callableList):
      if len(callableList) == 0:
         raise Exception("-- invalid arg list --")
      self.executeSignal.emit(callableList)

   ###########################################################################
   def methodSlot(self, callableList):
      if type(callableList) != list or len(callableList) == 0:
         LOGERROR('[ArmoryQt::methodSlot] invalid callabale list:')
         LOGERROR(str(callableList))
         raise QtExecuteSignalError("invalid callable list")

      if not callable(callableList[0]):
         raise QtExecuteSignalError("first list entry isn't callable")

      args = []
      if len(callableList) == 2:
         if type(callableList[1]) != list:
            raise QtExecuteSignalError("second list entry isn't list")
         args = callableList[1]

      callableList[0](*args)

   ###########################################################################
   def callLater(self, delay, _callable, *_args):

      #if a given method is already waiting on delayed execution, update the
      #args and return
      if _callable in self.waiting:
         self.waiting[_callable] = _args
         return

      self.waiting[_callable] = _args
      thr = Thread(target=self.callLaterThread, args=(delay, _callable) + _args)
      thr.start()

   ###########################################################################
   def callLaterThread(self, delay, _callable, *args):
      sleep(delay)
      args = self.waiting.pop(_callable, [])
      self.executeMethod([_callable, args])
