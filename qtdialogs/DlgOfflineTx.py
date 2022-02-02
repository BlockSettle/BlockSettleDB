##############################################################################
#                                                                            #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                         #
# Distributed under the GNU Affero General Public License (AGPL v3)          #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                       #
#                                                                            #
# Copyright (C) 2016-2022, goatpig                                           #
#  Distributed under the MIT license                                         #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                    #
#                                                                            #
##############################################################################

from PySide2.QtCore import Qt
from PySide2.QtGui import QIcon
from PySide2.QtWidgets import QVBoxLayout, QPushButton, QTextEdit, \
   QFrame, QGridLayout, QApplication, QSpacerItem

from armoryengine.ArmoryUtils import OS_WINDOWS, LOGINFO, LOGEXCEPT
from armoryengine.BDM import TheBDM, BDM_BLOCKCHAIN_READY

from qtdialogs.qtdefines import QRichLabel, HORIZONTAL, \
   STYLE_SUNKEN, GETFONT, STYLE_RAISED, VERTICAL, makeLayoutFrame, \
   relaxedSizeNChar, determineWalletType, WLTTYPES, makeHorizFrame, \
   makeVertFrame, STYLE_PLAIN, HLINE, tightSizeNChar
from qtdialogs.qtdialogs import STRETCH
from qtdialogs.ArmoryDialog import ArmoryDialog

from ui.TxFramesOffline import SignBroadcastOfflineTxFrame

################################################################################
class ReviewOfflineTxFrame(ArmoryDialog):
   def __init__(self, parent=None, main=None, initLabel=''):
      super(ReviewOfflineTxFrame, self).__init__(parent, main)

      self.ustx = None
      self.wlt = None
      self.lblDescr = QRichLabel('')

      ttipDataIsSafe = self.main.createToolTipWidget(\
         self.tr('There is no security-sensitive information in this data below, so '
         'it is perfectly safe to copy-and-paste it into an '
         'email message, or save it to a borrowed USB key.'))

      btnSave = QPushButton(self.tr('Save as file...'))
      btnSave.clicked.connect(self.doSaveFile)
      ttipSave = self.main.createToolTipWidget(\
         self.tr('Save this data to a USB key or other device, to be transferred to '
         'a computer that contains the private keys for this wallet.'))

      btnCopy = QPushButton(self.tr('Copy to clipboard'))
      btnCopy.clicked.connect(self.copyAsciiUSTX)
      self.lblCopied = QRichLabel('  ')
      self.lblCopied.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      ttipCopy = self.main.createToolTipWidget(\
         self.tr('Copy the transaction data to the clipboard, so that it can be '
         'pasted into an email or a text document.'))

      lblInstruct = QRichLabel(self.tr('<b>Instructions for completing this transaction:</b>'))
      self.lblUTX = QRichLabel('')

      frmUTX = makeLayoutFrame(HORIZONTAL, [ttipDataIsSafe, self.lblUTX])
      frmUpper = makeLayoutFrame(HORIZONTAL, [self.lblDescr], STYLE_SUNKEN)

      # Wow, I just cannot get the txtEdits to be the right size without
      # forcing them very explicitly
      self.txtUSTX = QTextEdit()
      self.txtUSTX.setFont(GETFONT('Fixed', 8))
      w,h = relaxedSizeNChar(self.txtUSTX, 68)[0], int(12 * 8.2)
      self.txtUSTX.setMinimumWidth(w)
      self.txtUSTX.setMinimumHeight(h)
      self.txtUSTX.setReadOnly(True)



      frmLower = QFrame()
      frmLower.setFrameStyle(STYLE_RAISED)
      frmLowerLayout = QGridLayout()

      frmLowerLayout.addWidget(frmUTX, 0, 0, 1, 3)
      frmLowerLayout.addWidget(self.txtUSTX, 1, 0, 3, 1)
      frmLowerLayout.addWidget(btnSave, 1, 1, 1, 1)
      frmLowerLayout.addWidget(ttipSave, 1, 2, 1, 1)
      frmLowerLayout.addWidget(btnCopy, 2, 1, 1, 1)
      frmLowerLayout.addWidget(ttipCopy, 2, 2, 1, 1)
      frmLowerLayout.addWidget(self.lblCopied, 3, 1, 1, 2)
      frmLowerLayout.setColumnStretch(0, 1)
      frmLowerLayout.setColumnStretch(1, 0)
      frmLowerLayout.setColumnStretch(2, 0)
      frmLowerLayout.setColumnStretch(3, 0)
      frmLowerLayout.setRowStretch(0, 0)
      frmLowerLayout.setRowStretch(1, 1)
      frmLowerLayout.setRowStretch(2, 1)
      frmLowerLayout.setRowStretch(3, 1)

      frmLower.setLayout(frmLowerLayout)


      frmAll = makeLayoutFrame(VERTICAL, \
         [lblInstruct, frmUpper, 'Space(5)', frmLower])
      frmAll.layout().setStretch(0, 0)
      frmAll.layout().setStretch(1, 0)
      frmAll.layout().setStretch(2, 0)
      frmAll.layout().setStretch(3, 2)
      frmAll.layout().setStretch(4, 1)
      frmAll.layout().setStretch(5, 0)

      dlgLayout = QVBoxLayout()
      dlgLayout.addWidget(frmAll)

      self.setLayout(dlgLayout)

   def setUSTX(self, ustx):
      self.ustx = ustx
      self.lblUTX.setText(self.tr('<b>Transaction Data</b> \t (Unsigned ID: %s)' % ustx.uniqueIDB58))
      self.txtUSTX.setText(ustx.serializeAscii())

   def setWallet(self, wlt):
      self.wlt = wlt
      if determineWalletType(\
         wlt, self.main)[0] in [ WLTTYPES.Offline, WLTTYPES.WatchOnly ]:
         self.lblDescr.setText(self.tr(
            'The block of data shown below is the complete transaction you '
            'just requested, but is invalid because it does not contain any '
            'signatures.  You must take this data to the computer with the '
            'full wallet to get it signed, then bring it back here to be '
            'broadcast to the Bitcoin network. '
            '<br><br>'
            'Use "Save as file..." to save an <i>*.unsigned.tx</i> '
            'file to USB drive or other removable media. '
            'On the offline computer, click "Offline Transactions" on the main '
            'window.  Load the transaction, <b>review it</b>, then sign it '
            '(the filename now end with <i>*.signed.tx</i>).  Click "Continue" '
            'below when you have the signed transaction on this computer. '
            '<br><br>'
            '<b>NOTE:</b> The USB drive only ever holds public transaction '
            'data that will be broadcast to the network.  This data may be '
            'considered privacy-sensitive, but does <u>not</u> compromise '
            'the security of your wallet.'))
      else:
         self.lblDescr.setText(self.tr(
            'You have chosen to create the previous transaction but not sign '
            'it or broadcast it, yet.  You can save the unsigned '
            'transaction to file, or copy&paste from the text box. '
            'You can use the following window (after clicking "Continue") to '
            'sign and broadcast the transaction when you are ready'))


   def copyAsciiUSTX(self):
      clipb = QApplication.clipboard()
      clipb.clear()
      clipb.setText(self.txtUSTX.toPlainText())
      self.lblCopied.setText('<i>Copied!</i>')

   def doSaveFile(self):
      """ Save the Unsigned-Tx block of data """
      dpid = self.ustx.uniqueIDB58
      suffix = ('' if OS_WINDOWS else '.unsigned.tx')
      toSave = self.main.getFileSave(\
                      'Save Unsigned Transaction', \
                      ['Armory Transactions (*.unsigned.tx)'], \
                      'armory_%s_%s' % (dpid, suffix))
      LOGINFO('Saving unsigned tx file: %s', toSave)
      try:
         theFile = open(toSave, 'w')
         theFile.write(self.txtUSTX.toPlainText())
         theFile.close()
      except IOError:
         LOGEXCEPT('Failed to save file: %s', toSave)
         pass


################################################################################
class DlgOfflineTxCreated(ArmoryDialog):
   def __init__(self, wlt, ustx, parent=None, main=None):
      super(DlgOfflineTxCreated, self).__init__(parent, main)
      layout = QVBoxLayout()

      reviewOfflineTxFrame = ReviewOfflineTxFrame(\
         self, main, self.tr("Review Offline Transaction"))
      reviewOfflineTxFrame.setWallet(wlt)
      reviewOfflineTxFrame.setUSTX(ustx)
      continueButton = QPushButton(self.tr('Continue'))
      continueButton.clicked.connect(self.signBroadcastTx)
      doneButton = QPushButton(self.tr('Done'))
      doneButton.clicked.connect(self.accept)

      ttipDone = self.main.createToolTipWidget(self.tr(
         'By clicking Done you will exit the offline transaction process for now. '
         'When you are ready to sign and/or broadcast the transaction, click the Offline '
         'Transactions button in the main window, then click the Sign and/or '
         'Broadcast Transaction button in the Select Offline Action dialog.'))

      ttipContinue = self.main.createToolTipWidget(self.tr(
         'By clicking Continue you will continue to the next step in the offline '
         'transaction process to sign and/or broadcast the transaction.'))

      bottomStrip = makeHorizFrame(
         [doneButton, ttipDone, STRETCH, continueButton, ttipContinue])

      frame = makeVertFrame([reviewOfflineTxFrame, bottomStrip])
      layout.addWidget(frame)
      self.setLayout(layout)
      self.setWindowTitle(self.tr('Review Offline Transaction'))
      self.setWindowIcon(QIcon(self.main.iconfile))


   def signBroadcastTx(self):
      self.accept()
      DlgSignBroadcastOfflineTx(self.parent,self.main).exec_()


################################################################################
class DlgOfflineSelect(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgOfflineSelect, self).__init__(parent, main)


      self.do_review = False
      self.do_create = False
      self.do_broadc = False
      lblDescr = QRichLabel(self.tr(
         'In order to execute an offline transaction, three steps must '
         'be followed:'
         '<ol>'
         '<li><u>On</u>line Computer:  Create the unsigned transaction</li> '
         '<li><u>Off</u>line Computer: Get the transaction signed</li> '
         '<li><u>On</u>line Computer:  Broadcast the signed transaction</li></ol> '
         'You must create the transaction using a watch-only wallet on an online '
         'system, but watch-only wallets cannot sign it.  Only the offline system '
         'can create a valid signature.  The easiest way to execute all three steps '
         'is to use a USB key to move the data between computers.<br><br> '
         'All the data saved to the removable medium during all three steps are '
         'completely safe and do not reveal any private information that would benefit an '
         'attacker trying to steal your funds.  However, this transaction data does '
         'reveal some addresses in your wallet, and may represent a breach of '
         '<i>privacy</i> if not protected.'))

      btnCreate = QPushButton(self.tr('Create New Offline Transaction'))
      broadcastButton = QPushButton(self.tr('Sign and/or Broadcast Transaction'))
      if not TheBDM.getState() == BDM_BLOCKCHAIN_READY:
         btnCreate.setEnabled(False)
         if len(self.main.walletMap) == 0:
            broadcastButton = QPushButton(self.tr('No wallets available!'))
            broadcastButton.setEnabled(False)
         else:
            broadcastButton = QPushButton(self.tr('Sign Offline Transaction'))
      else:
         if len(self.main.getWatchingOnlyWallets()) == 0:
            btnCreate = QPushButton(self.tr('No watching-only wallets available!'))
            btnCreate.setEnabled(False)
         if len(self.main.walletMap) == 0 and self.main.netMode == NETWORKMODE.Full:
            broadcastButton = QPushButton('Broadcast Signed Transaction')

      btnCancel = QPushButton(self.tr('<<< Go Back'))

      def create():
         self.do_create = True; self.accept()
      def broadc():
         self.do_broadc = True; self.accept()

      btnCreate.clicked.connect(create)
      broadcastButton.clicked.connect(broadc)
      btnCancel.clicked.connect(self.reject)

      lblCreate = QRichLabel(self.tr(
         'Create a transaction from an Offline/Watching-Only wallet '
         'to be signed by the computer with the full wallet '))

      lblReview = QRichLabel(self.tr(
         'Review an unsigned transaction and sign it if you have '
         'the private keys needed for it '))

      lblBroadc = QRichLabel(self.tr(
         'Send a pre-signed transaction to the Bitcoin network to finalize it'))

      lblBroadc.setMinimumWidth(tightSizeNChar(lblBroadc, 45)[0])

      frmOptions = QFrame()
      frmOptions.setFrameStyle(STYLE_PLAIN)
      frmOptionsLayout = QGridLayout()
      frmOptionsLayout.addWidget(btnCreate, 0, 0)
      frmOptionsLayout.addWidget(lblCreate, 0, 2)
      frmOptionsLayout.addWidget(HLINE(), 1, 0, 1, 3)
      frmOptionsLayout.addWidget(broadcastButton, 2, 0, 3, 1)
      frmOptionsLayout.addWidget(lblReview, 2, 2)
      frmOptionsLayout.addWidget(HLINE(), 3, 2, 1, 1)
      frmOptionsLayout.addWidget(lblBroadc, 4, 2)

      frmOptionsLayout.addItem(QSpacerItem(20, 20), 0, 1, 3, 1)
      frmOptions.setLayout(frmOptionsLayout)

      frmDescr = makeLayoutFrame(HORIZONTAL,
         ['Space(10)', lblDescr, 'Space(10)'], STYLE_SUNKEN)
      frmCancel = makeLayoutFrame(HORIZONTAL, [btnCancel, STRETCH])

      dlgLayout = QGridLayout()
      dlgLayout.addWidget(frmDescr, 0, 0, 1, 1)
      dlgLayout.addWidget(frmOptions, 1, 0, 1, 1)
      dlgLayout.addWidget(frmCancel, 2, 0, 1, 1)

      self.setLayout(dlgLayout)
      self.setWindowTitle('Select Offline Action')
      self.setWindowIcon(QIcon(self.main.iconfile))

################################################################################
class DlgSignBroadcastOfflineTx(ArmoryDialog):
   """
   We will make the assumption that this dialog is used ONLY for outgoing
   transactions from your wallet.  This simplifies the logic if we don't
   have to identify input senders/values, and handle the cases where those
   may not be specified
   """
   def __init__(self, parent=None, main=None):
      super(DlgSignBroadcastOfflineTx, self).__init__(parent, main)

      self.setWindowTitle(self.tr('Review Offline Transaction'))
      self.setWindowIcon(QIcon(self.main.iconfile))

      signBroadcastOfflineTxFrame = SignBroadcastOfflineTxFrame(
         self, main, self.tr("Sign or Broadcast Transaction"))

      doneButton = QPushButton(self.tr('Done'))
      doneButton.clicked.connect(self.accept)
      doneForm = makeLayoutFrame(HORIZONTAL, [STRETCH, doneButton])
      dlgLayout = QVBoxLayout()
      dlgLayout.addWidget(signBroadcastOfflineTxFrame)
      dlgLayout.addWidget(doneForm)
      self.setLayout(dlgLayout)
      signBroadcastOfflineTxFrame.processUSTX()
