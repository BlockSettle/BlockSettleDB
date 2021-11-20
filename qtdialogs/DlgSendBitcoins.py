################################################################################
#                                                                              #
# Copyright (C) 2011-2021, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

from PySide2.QtCore import QSize
from PySide2.QtWidgets import QVBoxLayout

from qtdialogs.qtdefines import ArmoryDialog
from qtdialogs.DlgOfflineTx import DlgOfflineTxCreated

from ui.TxFrames import SendBitcoinsFrame

################################################################################
class DlgSendBitcoins(ArmoryDialog):
   def __init__(self, wlt, parent=None, main=None,
                              wltIDList=None, onlyOfflineWallets=False,
                              spendFromLockboxID=None):
      super(DlgSendBitcoins, self).__init__(parent, main)
      layout = QVBoxLayout()

      self.spendFromLockboxID = spendFromLockboxID

      self.frame = SendBitcoinsFrame(self, main, self.tr('Send Bitcoins'),
                   wlt, wltIDList, onlyOfflineWallets=onlyOfflineWallets,
                   sendCallback=self.createTxAndBroadcast,
                   createUnsignedTxCallback=self.createUnsignedTxAndDisplay,
                   spendFromLockboxID=spendFromLockboxID)
      layout.addWidget(self.frame)
      self.setLayout(layout)
      self.sizeHint = lambda: QSize(850, 600)
      self.setMinimumWidth(700)
      # Update the any controls based on the initial wallet selection
      self.frame.fireWalletChange()



   #############################################################################
   def createUnsignedTxAndDisplay(self, ustx):
      self.accept()
      if self.spendFromLockboxID is None:
         dlg = DlgOfflineTxCreated(self.frame.wlt, ustx, self.parent, self.main)
         dlg.exec_()
      else:
         dlg = DlgMultiSpendReview(self.parent, self.main, ustx)
         dlg.exec_()


   #############################################################################
   def createTxAndBroadcast(self):
      self.accept()

   #############################################################################
   def saveGeometrySettings(self):
      geom = self.saveGeometry().data().hex()
      self.main.writeSetting('SendBtcGeometry', geom)

   #############################################################################
   def closeEvent(self, event):
      self.saveGeometrySettings()
      super(DlgSendBitcoins, self).closeEvent(event)

   #############################################################################
   def accept(self, *args):
      self.saveGeometrySettings()
      super(DlgSendBitcoins, self).accept(*args)

   #############################################################################
   def reject(self, *args):
      self.saveGeometrySettings()
      super(DlgSendBitcoins, self).reject(*args)
