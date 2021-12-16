################################################################################
#                                                                              #
# Copyright (C) 2011-2021, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

# Class that will create the watch-only wallet data (root public key & chain
# code) restoration window.
################################################################################

import os
import sys

from PySide2.QtWidgets import QDialogButtonBox, QFrame, QGridLayout, QLabel, QLayout, QMessageBox, QPushButton, QVBoxLayout
from PySide2.QtCore import SIGNAL

from armoryengine.ArmoryUtils import LOGERROR, binary_to_base58, binary_to_int, easyType16_to_binary, int_to_binary, readSixteenEasyBytes, verifyChecksum
from armoryengine.PyBtcWallet import PYROOTPKCCSIGNMASK, PYROOTPKCCVERMASK, PyBtcWallet
from armoryengine.PyBtcAddress import PyBtcAddress
#from CppBlockUtils import CryptoECDSA, SecureBinaryData

from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.DlgProgress import DlgProgress
from qtdialogs.qtdefines import GETFONT, HLINE, QRichLabel, STRETCH, STYLE_RAISED, makeHorizFrame
from qtdialogs.qtdialogs import MaskedInputLineEdit, verifyRecoveryTestID

class DlgRestoreWOData(ArmoryDialog):
    #############################################################################
   def __init__(self, parent, main, thisIsATest=False, expectWltID=None):
      super(DlgRestoreWOData, self).__init__(parent, main)

      self.thisIsATest = thisIsATest
      self.testWltID = expectWltID
      headerStr = ''
      lblDescr = ''

        # Write the text at the top of the window.
      if thisIsATest:
         lblDescr = QRichLabel(self.tr(
          '<b><u><font color="blue" size="4">Test a Watch-Only Wallet Restore '
          '</font></u></b><br><br>'
          'Use this window to test the restoration of a watch-only wallet using '
          'the wallet\'s data. You can either type the data on a root data '
          'printout or import the data from a file.'))
      else:
         lblDescr = QRichLabel(self.tr(
            '<b><u><font color="blue" size="4">Restore a Watch-Only Wallet '
            '</font></u></b><br><br>'
            'Use this window to restore a watch-only wallet using the wallet\'s '
            'data. You can either type the data on a root data printout or import '
            'the data from a file.'))

        # Create the line that will contain the imported ID.
      self.rootIDLabel = QRichLabel(self.tr('Watch-Only Root ID:'), doWrap=False)
      inpMask = '<AAAA\ AAAA\ AAAA\ AAAA\ AA!'
      self.rootIDLine = MaskedInputLineEdit(inpMask)
      self.rootIDLine.setFont(GETFONT('Fixed', 9))
      self.rootIDFrame = makeHorizFrame([STRETCH, self.rootIDLabel, \
                                           self.rootIDLine])

        # Create the lines that will contain the imported key/code data.
      self.pkccLList = [QLabel(self.tr('Data:')), QLabel(''), QLabel(''), QLabel('')]
      for y in self.pkccLList:
         y.setFont(GETFONT('Fixed', 9))
      inpMask = '<AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA!'
      self.pkccList = [MaskedInputLineEdit(inpMask) for i in range(4)]
      for x in self.pkccList:
         x.setFont(GETFONT('Fixed', 9))

        # Build the frame that will contain both the ID and the key/code data.
      frmAllInputs = QFrame()
      frmAllInputs.setFrameStyle(STYLE_RAISED)
      layoutAllInp = QGridLayout()
      layoutAllInp.addWidget(self.rootIDFrame, 0, 0, 1, 2)
      for i in range(4):
         layoutAllInp.addWidget(self.pkccLList[i], i + 1, 0)
         layoutAllInp.addWidget(self.pkccList[i], i + 1, 1)
      frmAllInputs.setLayout(layoutAllInp)

        # Put together the button code.
      doItText = self.tr('Test Backup') if thisIsATest else self.tr('Restore Wallet')
      self.btnLoad   = QPushButton(self.tr("Load From Text File"))
      self.btnAccept = QPushButton(doItText)
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.connect(self.btnLoad, SIGNAL("clicked()"), self.loadWODataFile)
      self.connect(self.btnAccept, SIGNAL("clicked()"), self.verifyUserInput)
      self.connect(self.btnCancel, SIGNAL("clicked()"), self.reject)
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnLoad, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)

        # Set the final window layout.
      finalLayout = QVBoxLayout()
      finalLayout.addWidget(lblDescr)
      finalLayout.addWidget(makeHorizFrame(['Stretch',self.btnLoad]))
      finalLayout.addWidget(HLINE())
      finalLayout.addWidget(frmAllInputs)
      finalLayout.addWidget(makeHorizFrame([self.btnCancel, 'Stretch', self.btnAccept]))
      finalLayout.setStretch(0, 0)
      finalLayout.setStretch(1, 0)
      finalLayout.setStretch(2, 0)
      finalLayout.setStretch(3, 0)
      finalLayout.setStretch(4, 0)
      finalLayout.setStretch(4, 1)
      finalLayout.setStretch(4, 2)
      self.setLayout(finalLayout)

        # Set window title.
      if thisIsATest:
         self.setWindowTitle(self.tr('Test Watch-Only Wallet Backup'))
      else:
         self.setWindowTitle(self.tr('Restore Watch-Only Wallet Backup'))

        # Set final window layout options.
      self.setMinimumWidth(550)
      self.layout().setSizeConstraint(QLayout.SetFixedSize)


    #############################################################################
   def loadWODataFile(self):
      '''Function for loading a root public key/chain code (\"pkcc\") file.'''
      fn = self.main.getFileLoad(self.tr('Import Wallet File'),
                                 ffilter=[self.tr('Root Pubkey Text Files (*.rootpubkey)')])
      if not os.path.exists(fn):
         return

        # Read in the data.
        # Protip: readlines() leaves in '\n'. read().splitlines() nukes '\n'.
      loadFile = open(fn, 'rb')
      fileLines = loadFile.read().splitlines()
      loadFile.close()

        # Confirm that we have an actual PKCC file.
      pkccFileVer = int(fileLines[0], 10)
      if pkccFileVer != 1:
         return
      else:
         self.rootIDLine.setText(str(fileLines[1]))
         for curLineNum, curLine in enumerate(fileLines[2:6]):
            self.pkccList[curLineNum].setText(str(curLine))


    #############################################################################
   def verifyUserInput(self):
      '''Function that verifies the input for a root public key/chain code
         restoration validation.'''
      inRootChecked = ''
      inputLines = []
      nError = 0
      rawBin = None
      nLine = 4
      hasError = False

        # Read in the root ID data and handle any errors.
      try:
         rawID = easyType16_to_binary(str(self.rootIDLine.text()).replace(' ', ''))
         if len(rawID) != 9:
            raise ValueError('Must supply 9 byte input for the ID')

            # Grab the data and apply the checksum to make sure it's okay.
         inRootData = rawID[:7]   # 7 bytes
         inRootChksum = rawID[7:] # 2 bytes
         inRootChecked = verifyChecksum(inRootData, inRootChksum)
         if len(inRootChecked) != 7:
            hasError = True
         elif inRootChecked != inRootData:
            nError += 1
      except:
         hasError = True

        # If the root ID is busted, stop.
      if hasError:
         (errType, errVal) = sys.exc_info()[:2]
         reply = QMessageBox.critical(self, self.tr('Invalid Data'), self.tr(
               'There is an error in the root ID you entered that could not '
               'be fixed automatically.  Please double-check that you entered the '
               'text exactly as it appears on the wallet-backup page.<br><br>'),
               QMessageBox.Ok)
         LOGERROR('Error in root ID restore field')
         LOGERROR('Error Type: %s', errType)
         LOGERROR('Error Value: %s', errVal)
         return

        # Save the version/key byte and the root ID. For now, ignore the version.
      inRootVer = inRootChecked[0]  # 1 byte
      inRootID = inRootChecked[1:7] # 6 bytes

        # Read in the root data (public key & chain code) and handle any errors.
      for i in range(nLine):
         hasError = False
         try:
            rawEntry = str(self.pkccList[i].text())
            rawBin, err = readSixteenEasyBytes(rawEntry.replace(' ', ''))
            if err == 'Error_2+':  # 2+ bytes are wrong, so we need to stop.
               hasError = True
            elif err == 'Fixed_1': # 1 byte is wrong, so we may be okay.
               nError += 1
         except:
            hasError = True

            # If the root ID is busted, stop.
         if hasError:
            lineNumber = i+1
            reply = QMessageBox.critical(self, self.tr('Invalid Data'), self.tr(
               'There is an error in the root data you entered that could not be '
               'fixed automatically.  Please double-check that you entered the '
               'text exactly as it appears on the wallet-backup page.  <br><br>'
               'The error occured on <font color="red">line #%d</font>.' % lineNumber), QMessageBox.Ok)
            LOGERROR('Error in root data restore field')
            return

            # If we've gotten this far, save the incoming line.
         inputLines.append(rawBin)

        # Set up the root ID data.
      pkVer = binary_to_int(inRootVer) & PYROOTPKCCVERMASK  # Ignored for now.
      pkSignByte = ((binary_to_int(inRootVer) & PYROOTPKCCSIGNMASK) >> 7) + 2
      rootPKComBin = int_to_binary(pkSignByte) + ''.join(inputLines[:2])
      rootPubKey = CryptoECDSA().UncompressPoint(SecureBinaryData(rootPKComBin))
      rootChainCode = SecureBinaryData(''.join(inputLines[2:]))

        # Now we should have a fully-plaintext root key and chain code, and can
        # get some related data.
      root = PyBtcAddress().createFromPublicKeyData(rootPubKey)
      root.chaincode = rootChainCode
      first = root.extendAddressChain()
      newWltID = binary_to_base58(inRootID)

        # Stop here if this was just a test
      if self.thisIsATest:
         verifyRecoveryTestID(self, newWltID, self.testWltID)
         return

        # If we already have the wallet, don't replace it, otherwise proceed.
      dlgOwnWlt = None
      if newWltID in self.main.walletMap:
         QMessageBox.warning(self, self.tr('Wallet Already Exists'), self.tr(
                             'The wallet already exists and will not be '
                             'replaced.'), QMessageBox.Ok)
         self.reject()
         return
      else:
            # Make sure the user is restoring the wallet they want to restore.
         reply = QMessageBox.question(self, self.tr('Verify Wallet ID'), \
                  self.tr('The data you entered corresponds to a wallet with a wallet '
                  'ID: \n\n\t%s\n\nDoes this '
                  'ID match the "Wallet Unique ID" you intend to restore? '
                  'If not, click "No" and enter the key and chain-code data '
                  'again.' % binary_to_base58(inRootID)), QMessageBox.Yes | QMessageBox.No)
         if reply == QMessageBox.No:
            return

            # Create the wallet.
         self.newWallet = PyBtcWallet().createNewWalletFromPKCC(rootPubKey, \
                                                                   rootChainCode)

            # Create some more addresses and show a progress bar while restoring.
         nPool = 1000
         fillAddrPoolProgress = DlgProgress(self, self.main, HBar=1,
                                            Title=self.tr("Computing New Addresses"))
         fillAddrPoolProgress.exec_(self.newWallet.fillAddressPool, nPool)

      self.accept()