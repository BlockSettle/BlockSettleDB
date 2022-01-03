################################################################################
#                                                                              #
# Copyright (C) 2011-2021, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

from PySide2.QtWidgets import QLineEdit, QPushButton, QDialogButtonBox, \
   QVBoxLayout, QMessageBox

from armorycolors import htmlColor

from qtdialogs.qtdefines import ArmoryDialog, relaxedSizeStr, \
   STYLE_SUNKEN, QRichLabel, makeHorizFrame, makeVertFrame
from qtdialogs.qtdialogs import STRETCH
from qtdialogs.DlgProgress import DlgProgress

################################################################################
class DlgKeypoolSettings(ArmoryDialog):
   """
   Let the user manually adjust the keypool for this wallet
   """
   def __init__(self, wlt, parent=None, main=None):
      super(DlgKeypoolSettings, self).__init__(parent, main)

      self.wlt = wlt
      self.addressesWereGenerated = False

      self.lblDescr = QRichLabel(self.tr(
         'Armory pre-computes a pool of addresses beyond the last address '
         'you have used, and keeps them in your wallet to "look-ahead."  One '
         'reason it does this is in case you have restored this wallet from '
         'a backup, and Armory does not know how many addresses you have actually '
         'used. '
         '<br><br>'
         'If this wallet was restored from a backup and was very active after '
         'it was backed up, then it is possible Armory did not pre-compute '
         'enough addresses to find your entire balance.  <b>This condition is '
         'rare</b>, but it can happen.  You may extend the keypool manually, '
         'below.'))

      self.lblAddrUsed = QRichLabel(self.tr('Addresses used: '), doWrap=False)
      self.lblAddrComp = QRichLabel(self.tr('Addresses computed: '), doWrap=False)
      self.lblAddrUsedVal = QRichLabel('%d' % max(0, self.wlt.highestUsedChainIndex))
      self.lblAddrCompVal = QRichLabel('%d' % self.wlt.lastComputedChainIndex)

      self.lblNumAddr = QRichLabel(self.tr('Compute this many more addresses: '))
      self.edtNumAddr = QLineEdit()
      self.edtNumAddr.setText('100')
      self.edtNumAddr.setMaximumWidth(relaxedSizeStr(self, '9999999')[0])

      self.lblWarnSpeed = QRichLabel(self.tr(
         'Address computation is very slow.  It may take up to one minute '
         'to compute 200-1000 addresses (system-dependent).  Only generate '
         'as many as you think you need.'))


      buttonBox = QDialogButtonBox()
      self.btnAccept = QPushButton(self.tr("Compute"))
      self.btnReject = QPushButton(self.tr("Done"))
      self.btnAccept.clicked.connect(self.clickCompute)
      self.btnReject.clicked.connect(self.reject)
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnReject, QDialogButtonBox.RejectRole)


      frmLbl = makeVertFrame([self.lblAddrUsed, self.lblAddrComp])
      frmVal = makeVertFrame([self.lblAddrUsedVal, self.lblAddrCompVal])
      subFrm1 = makeHorizFrame([STRETCH, frmLbl, frmVal, STRETCH], STYLE_SUNKEN)

      subFrm2 = makeHorizFrame([STRETCH, \
                                self.lblNumAddr, \
                                self.edtNumAddr, \
                                STRETCH], STYLE_SUNKEN)

      layout = QVBoxLayout()
      layout.addWidget(self.lblDescr)
      layout.addWidget(subFrm1)
      layout.addWidget(self.lblWarnSpeed)
      layout.addWidget(subFrm2)
      layout.addWidget(buttonBox)

      self.setLayout(layout)
      self.setWindowTitle(self.tr('Extend Address Pool'))

   #############################################################################
   def clickCompute(self):
      # if TheBDM.getState()==BDM_SCANNING:
         # QMessageBox.warning(self, 'Armory is Busy', \
            # 'Armory is in the middle of a scan, and cannot add addresses to '
            # 'any of its wallets until the scan is finished.  Please wait until '
            # 'the dashboard says that Armory is "online."', QMessageBox.Ok)
         # return


      err = False
      try:
         naddr = int(self.edtNumAddr.text())
      except:
         err = True

      if err or naddr < 1:
         QMessageBox.critical(self, self.tr('Invalid input'), self.tr(
            'The value you entered is invalid.  Please enter a positive '
            'number of addresses to generate.'), QMessageBox.Ok)
         return

      if naddr >= 1000:
         confirm = QMessageBox.warning(self, self.tr('Are you sure?'), self.tr(
            'You have entered that you want to compute %s more addresses'
            'for this wallet.  This operation will take a very long time, '
            'and Armory will become unresponsive until the computation is '
            'finished.  Armory estimates it will take about %d minutes.'
            '<br><br>Do you want to continue?' % (naddr, int(naddr / 750.))), \
            QMessageBox.Yes | QMessageBox.No)

         if not confirm == QMessageBox.Yes:
            return

      cred = htmlColor('TextRed')
      self.lblAddrCompVal.setText(self.tr('<font color="%s">Calculating...</font>' % cred))

      fillAddressPoolProgress = DlgProgress(self, self.main,
         HBar=1, Title=self.tr('Computing New Addresses'))

      def completeCallback():
         if self.main is None:
            return
         self.main.signalExecution.executeMethod([self.completeCompute, []])

      fillAddressPoolProgress.exec_(self.wlt.fillAddressPool,
         naddr, fillAddressPoolProgress.callbackId, completeCallback)

   #############################################################################
   def completeCompute(self):
      cred = htmlColor('TextRed')
      self.lblAddrCompVal.setText('<font color="%s">%d</font>' % \
         (cred, self.wlt.lastComputedChainIndex))
      self.addressesWereGenerated = True
