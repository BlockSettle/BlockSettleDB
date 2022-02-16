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

from PySide2.QtWidgets import QButtonGroup, QCheckBox, QDialogButtonBox, \
   QFrame, QGridLayout, QLabel, QLayout, QLineEdit, QMessageBox, \
   QPushButton, QRadioButton, QTabWidget, QVBoxLayout

from armoryengine import ClientProto_pb2
from armoryengine.CppBridge import TheBridge
from armoryengine.ArmoryUtils import LOGERROR, UINT32_MAX, UINT8_MAX
from armoryengine.BDM import TheBDM
from armoryengine.PyBtcWallet import PyBtcWallet

from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.DlgChangePassphrase import DlgChangePassphrase
from qtdialogs.DlgReplaceWallet import DlgReplaceWallet
from qtdialogs.qtdefines import HLINE, QRichLabel, STRETCH, STYLE_RAISED, \
   makeHorizFrame, makeVertFrame
from qtdialogs.qtdialogs import MaskedInputLineEdit, verifyRecoveryTestID

from ui.WalletFrames import AdvancedOptionsFrame

################################################################################
class DlgRestoreSingle(ArmoryDialog):
   #############################################################################
   def __init__(self, parent, main, thisIsATest=False, expectWltID=None):
      super(DlgRestoreSingle, self).__init__(parent, main)

      self.newWltID = None
      self.callbackId = None
      self.thisIsATest = thisIsATest
      self.testWltID = expectWltID
      headerStr = ''
      if thisIsATest:
         lblDescr = QRichLabel(self.tr(
          '<b><u><font color="blue" size="4">Test a Paper Backup</font></u></b> '
          '<br><br>'
          'Use this window to test a single-sheet paper backup.  If your '
          'backup includes imported keys, those will not be covered by this test.'))
      else:
         lblDescr = QRichLabel(self.tr(
          '<b><u>Restore a Wallet from Paper Backup</u></b> '
          '<br><br>'
          'Use this window to restore a single-sheet paper backup. '
          'If your backup includes extra pages with '
          'imported keys, please restore the base wallet first, then '
          'double-click the restored wallet and select "Import Private '
          'Keys" from the right-hand menu.'))


      lblType = QRichLabel(self.tr('<b>Backup Type:</b>'), doWrap=False)

      self.version135Button = QRadioButton(self.tr('Version 1.35 (4 lines)'), self)
      self.version135aButton = QRadioButton(self.tr('Version 1.35a (4 lines Unencrypted)'), self)
      self.version135aSPButton = QRadioButton(self.tr(u'Version 1.35a (4 lines + SecurePrint\u200b\u2122)'), self)
      self.version135cButton = QRadioButton(self.tr('Version 1.35c (2 lines Unencrypted)'), self)
      self.version135cSPButton = QRadioButton(self.tr(u'Version 1.35c (2 lines + SecurePrint\u200b\u2122)'), self)
      self.backupTypeButtonGroup = QButtonGroup(self)
      self.backupTypeButtonGroup.addButton(self.version135Button)
      self.backupTypeButtonGroup.addButton(self.version135aButton)
      self.backupTypeButtonGroup.addButton(self.version135aSPButton)
      self.backupTypeButtonGroup.addButton(self.version135cButton)
      self.backupTypeButtonGroup.addButton(self.version135cSPButton)
      self.version135cButton.setChecked(True)
      self.connect(self.backupTypeButtonGroup, SIGNAL('buttonClicked(int)'), self.changeType)

      layoutRadio = QVBoxLayout()
      layoutRadio.addWidget(self.version135Button)
      layoutRadio.addWidget(self.version135aButton)
      layoutRadio.addWidget(self.version135aSPButton)
      layoutRadio.addWidget(self.version135cButton)
      layoutRadio.addWidget(self.version135cSPButton)
      layoutRadio.setSpacing(0)

      radioButtonFrame = QFrame()
      radioButtonFrame.setLayout(layoutRadio)

      frmBackupType = makeVertFrame([lblType, radioButtonFrame])

      self.lblSP = QRichLabel(self.tr(u'SecurePrint\u200b\u2122 Code:'), doWrap=False)
      self.editSecurePrint = QLineEdit()
      self.prfxList = [QLabel(self.tr('Root Key:')), QLabel(''), QLabel(self.tr('Chaincode:')), QLabel('')]

      inpMask = '<AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA!'
      self.edtList = [MaskedInputLineEdit(inpMask) for i in range(4)]


      self.frmSP = makeHorizFrame([STRETCH, self.lblSP, self.editSecurePrint])

      frmAllInputs = QFrame()
      frmAllInputs.setFrameStyle(STYLE_RAISED)
      layoutAllInp = QGridLayout()
      layoutAllInp.addWidget(self.frmSP, 0, 0, 1, 2)
      for i in range(4):
         layoutAllInp.addWidget(self.prfxList[i], i + 1, 0)
         layoutAllInp.addWidget(self.edtList[i], i + 1, 1)
      frmAllInputs.setLayout(layoutAllInp)

      doItText = self.tr('Test Backup') if thisIsATest else self.tr('Restore Wallet')

      self.btnAccept = QPushButton(doItText)
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.btnAccept.clicked.connect(self.verifyUserInput)
      self.btnCancel.clicked.connect(self.reject)
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)

      self.chkEncrypt = QCheckBox(self.tr('Encrypt Wallet'))
      self.chkEncrypt.setChecked(True)
      bottomFrm = makeHorizFrame([self.chkEncrypt, buttonBox])

      walletRestoreTabs = QTabWidget()
      backupTypeFrame = makeVertFrame([frmBackupType, frmAllInputs])
      walletRestoreTabs.addTab(backupTypeFrame, self.tr("Backup"))
      self.advancedOptionsTab = AdvancedOptionsFrame(parent, main)
      walletRestoreTabs.addTab(self.advancedOptionsTab, self.tr("Advanced Options"))

      layout = QVBoxLayout()
      layout.addWidget(lblDescr)
      layout.addWidget(HLINE())
      layout.addWidget(walletRestoreTabs)
      layout.addWidget(bottomFrm)
      self.setLayout(layout)


      self.chkEncrypt.setChecked(not thisIsATest)
      self.chkEncrypt.setVisible(not thisIsATest)
      self.advancedOptionsTab.setEnabled(not thisIsATest)
      if thisIsATest:
         self.setWindowTitle(self.tr('Test Single-Sheet Backup'))
      else:
         self.setWindowTitle(self.tr('Restore Single-Sheet Backup'))
         self.connect(self.chkEncrypt, SIGNAL("clicked()"), self.onEncryptCheckboxChange)

      self.setMinimumWidth(500)
      self.layout().setSizeConstraint(QLayout.SetFixedSize)
      self.changeType(self.backupTypeButtonGroup.checkedId())

   #############################################################################
   # Hide advanced options whenver the restored wallet is unencrypted
   def onEncryptCheckboxChange(self):
      self.advancedOptionsTab.setEnabled(self.chkEncrypt.isChecked())

   #############################################################################
   def accept(self):
      TheBDM.unregisterCustomPrompt(self.callbackId)
      super(ArmoryDialog, self).accept()

   #############################################################################
   def reject(self):
      TheBDM.unregisterCustomPrompt(self.callbackId)
      super(ArmoryDialog, self).reject()

   #############################################################################
   def changeType(self, sel):
      if   sel == self.backupTypeButtonGroup.id(self.version135Button):
         visList = [0, 1, 1, 1, 1]
      elif sel == self.backupTypeButtonGroup.id(self.version135aButton):
         visList = [0, 1, 1, 1, 1]
      elif sel == self.backupTypeButtonGroup.id(self.version135aSPButton):
         visList = [1, 1, 1, 1, 1]
      elif sel == self.backupTypeButtonGroup.id(self.version135cButton):
         visList = [0, 1, 1, 0, 0]
      elif sel == self.backupTypeButtonGroup.id(self.version135cSPButton):
         visList = [1, 1, 1, 0, 0]
      else:
         LOGERROR('What the heck backup type is selected?  %d', sel)
         return

      self.doMask = (visList[0] == 1)
      self.frmSP.setVisible(self.doMask)
      for i in range(4):
         self.prfxList[i].setVisible(visList[i + 1] == 1)
         self.edtList[ i].setVisible(visList[i + 1] == 1)

      self.isLongForm = (visList[-1] == 1)

   #############################################################################
   def processCallback(self, payload, callerId):

      if callerId == UINT32_MAX:
         errorMsg = "N/A"
         try:
            errorVerbose = ClientProto_pb2.ReplyStrings()
            errorVerbose.ParseFromString(payload)
            errorMsg = errorVerbose.reply[0]
         except:
            pass

         LOGERROR("C++ side unhandled error in RestoreWallet: " + errorMsg)
         QMessageBox.critical(self, self.tr('Unhandled Error'), \
            self.tr(\
               'The import operation failed with the following error: '
               '<br><br><b>%s</b>' % errorMsg \
               ), QMessageBox.Ok)

         self.reject()
         return

      result, extra = self.processCallbackPayload(payload)
      if result == False:
         TheBDM.unregisterCustomPrompt(self.callbackId)

      reply = ClientProto_pb2.RestoreReply()
      reply.result = result

      if extra != None:
         reply.extra = bytes(extra, 'utf-8')

      TheBridge.callbackFollowUp(reply, self.callbackId, callerId)

   #############################################################################
   def processCallbackPayload(self, payload):
      msg = ClientProto_pb2.RestorePrompt()
      msg.ParseFromString(payload)

      if msg.promptType == ClientProto_pb2.RestorePromptType.Value("Id") or \
           msg.promptType == ClientProto_pb2.RestorePromptType.Value("ChecksumError"):
            #check the id generated by this backup

         newWltID = msg.extra
         if len(newWltID) > 0:
            if self.thisIsATest:
               # Stop here if this was just a test
               verifyRecoveryTestID(self, newWltID, self.testWltID)

                    #return false to caller to end the restore process
               return False, None

            # return result of id comparison
            dlgOwnWlt = None
            if newWltID in self.main.walletMap:
               dlgOwnWlt = DlgReplaceWallet(newWltID, self.parent, self.main)

               if (dlgOwnWlt.exec_()):
                  #TODO: deal with replacement code
                  if dlgOwnWlt.output == 0:
                     return False, None
               else:
                  return False, None
            else:
               reply = QMessageBox.question(self, self.tr('Verify Wallet ID'), \
                        self.tr('The data you entered corresponds to a wallet with a wallet ID: \n\n'
                        '%s\n\nDoes this ID match the "Wallet Unique ID" '
                        'printed on your paper backup?  If not, click "No" and reenter '
                        'key and chain-code data again.' % newWltID), \
                        QMessageBox.Yes | QMessageBox.No)
               if reply == QMessageBox.Yes:
                  #return true to caller to proceed with restore operation
                  self.newWltID = newWltID
                  return True, None

         #reconstructed wallet id is invalid if we get this far
         lineNumber = -1
         canBeSalvaged = True
         if len(msg.checksums) != self.lineCount:
            canBeSalvaged = False

         for i in range(0, len(msg.checksums)):
            if msg.checksums[i] < 0 or msg.checksums[i] == UINT8_MAX:
               lineNumber = i + 1
               break

         if lineNumber == -1 or canBeSalvaged == False:
            QMessageBox.critical(self, self.tr('Unknown Error'), self.tr(
               'Encountered an unkonwn error when restoring this backup. Aborting.'), \
               QMessageBox.Ok)

            self.reject()
            return False, None

         reply = QMessageBox.critical(self, self.tr('Invalid Data'), self.tr(
            'There is an error in the data you entered that could not be '
            'fixed automatically.  Please double-check that you entered the '
            'text exactly as it appears on the wallet-backup page.  <br><br> '
            'The error occured on <font color="red">line #%d</font>.' % lineNumber), \
            QMessageBox.Ok)
         LOGERROR('Error in wallet restore field')
         self.prfxList[i].setText(\
            '<font color="red">' + str(self.prfxList[i].text()) + '</font>')

         return False, None

      if msg.promptType == ClientProto_pb2.RestorePromptType.Value("Passphrase"):
         #return new wallet's private keys password
         passwd = []
         if self.chkEncrypt.isChecked():
            dlgPasswd = DlgChangePassphrase(self, self.main)
            if dlgPasswd.exec_():
               passwd = str(dlgPasswd.edtPasswd1.text())
               return True, passwd
            else:
               QMessageBox.critical(self, self.tr('Cannot Encrypt'), \
                  self.tr('You requested your restored wallet be encrypted, but no '
                  'valid passphrase was supplied.  Aborting wallet recovery.'), \
                  QMessageBox.Ok)
               self.reject()
               return False, None

      if msg.promptType == ClientProto_pb2.RestorePromptType.Value("Control"):
         #TODO: need UI to input control passphrase
         return True, None

      if msg.promptType == ClientProto_pb2.RestorePromptType.Value("Success"):
         if self.newWltID == None or len(self.newWltID) == 0:
            LOGERROR("wallet import did not yield an id")
            raise Exception("wallet import did not yield an id")

         self.newWallet = PyBtcWallet()
         self.newWallet.loadFromBridge(self.newWltID)
         self.accept()

         return True, None

      if msg.promptType == ClientProto_pb2.RestorePromptType.Value("FormatError") or \
         sg.promptType == ClientProto_pb2.RestorePromptType.Value("Failure"):

         QMessageBox.critical(self, self.tr('Unknown Error'), self.tr(
            'Encountered an unkonwn error when restoring this backup. Aborting.', \
            QMessageBox.Ok))

         self.reject()
         return False, None

      if msg.promptType == ClientProto_pb2.RestorePromptType.Value("DecryptError"):
         #TODO: notify of invalid SP pass
         pass

      if msg.promptType == ClientProto_pb2.RestorePromptType.Value("TypeError"):
         #TODO: wallet type conveyed by backup is unknown
         pass

      else:
         #TODO: unknown error
         return False, None


    #############################################################################
   def verifyUserInput(self):

      root = []
      for i in range(2):
         root.append(str(self.edtList[i].text()))

      chaincode = []
      if self.isLongForm:
         for i in range(2):
            chaincode.append(str(self.edtList[i+2].text()))

      self.lineCount = len(root) + len(chaincode)

      spPass = ""
      if self.doMask:
         #add secureprint passphrase if this backup is encrypted
         spPass = str(self.editSecurePrint.text()).strip()

      '''
      verifyBackupString is a method that will trigger multiple callbacks
      during the course of its execution. Unlike a password request callback
      which only requires to generate a dedicated dialog to retrieve passwords
      from users, verifyBackupString set of notifications is complex and comes
      with branches.

      A dedicated callbackId is generated for this interaction and passed to
      TheBDM callback map along with a py side method to handle the protobuf
      packet from the C++ side.

      The C++ method is called with that id.
      '''
      def callback(payload, callerId):
         self.main.signalExecution.executeMethod(\
            [self.processCallback, [payload, callerId]])

      self.callbackId = TheBDM.registerCustomPrompt(callback)
      TheBridge.restoreWallet(root, chaincode, spPass, self.callbackId)

      '''
      if self.chkEncrypt.isChecked() and self.advancedOptionsTab.getKdfSec() == -1:
         QMessageBox.critical(self, self.tr('Invalid Target Compute Time'), \
            self.tr('You entered Target Compute Time incorrectly.\n\nEnter: <Number> (ms, s)'), QMessageBox.Ok)
         return
      if self.chkEncrypt.isChecked() and self.advancedOptionsTab.getKdfBytes() == -1:
         QMessageBox.critical(self, self.tr('Invalid Max Memory Usage'), \
            self.tr('You entered Max Memory Usage incorrectly.\n\nEnter: <Number> (kB, MB)'), QMessageBox.Ok)
         return
        if nError > 0:
            pluralStr = 'error' if nError == 1 else 'errors'

            msg = self.tr(
               'Detected errors in the data you entered. '
               'Armory attempted to fix the errors but it is not '
               'always right.  Be sure to verify the "Wallet Unique ID" '
               'closely on the next window.')

            QMessageBox.question(self, self.tr('Errors Corrected'), msg, \
               QMessageBox.Ok)
      '''