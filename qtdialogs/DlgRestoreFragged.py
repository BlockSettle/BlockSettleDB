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

from PySide2.QtWidgets import QCheckBox, QFrame, QGridLayout, QLabel, \
   QLineEdit, QMessageBox, QPushButton, QScrollArea, QTabWidget, QVBoxLayout
from PySide2.QtGui import QPixmap
from PySide2.QtCore import QSize, Qt, SIGNAL

from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.qtdefines import HLINE, QRichLabel, STRETCH, STYLE_RAISED, \
   STYLE_SUNKEN, makeHorizFrame, makeVertFrame, relaxedSizeNChar

################################################################################
class DlgRestoreFragged(ArmoryDialog):
   def __init__(self, parent, main, thisIsATest=False, expectWltID=None):
      super(DlgRestoreFragged, self).__init__(parent, main)

      self.thisIsATest = thisIsATest
      self.testWltID = expectWltID
      headerStr = ''
      if thisIsATest:
         headerStr = self.tr('<font color="blue" size="4">Testing a '
                      'Fragmented Backup</font>')
      else:
         headerStr = self.tr('Restore Wallet from Fragments')

      descr = self.trUtf8(
         '<b><u>%s</u></b> <br><br>'
         'Use this form to enter all the fragments to be restored.  Fragments '
         'can be stored on a mix of paper printouts, and saved files. '
         u'If any of the fragments require a SecurePrint\u200b\u2122 code, '
         'you will only have to enter it once, since that code is the same for '
         'all fragments of any given wallet.' % headerStr)

      if self.thisIsATest:
         descr += self.tr('<br><br>'
             '<b>For testing purposes, you may enter more fragments than needed '
             'and Armory will test all subsets of the entered fragments to verify '
             'that each one still recovers the wallet successfully.</b>')

      lblDescr = QRichLabel(descr)

      frmDescr = makeHorizFrame([lblDescr], STYLE_RAISED)

        # HLINE

      self.scrollFragInput = QScrollArea()
      self.scrollFragInput.setWidgetResizable(True)
      self.scrollFragInput.setMinimumHeight(150)

      lblFragList = QRichLabel(self.tr('Input Fragments Below:'), doWrap=False, bold=True)
      self.btnAddFrag = QPushButton(self.tr('+Frag'))
      self.btnRmFrag = QPushButton(self.tr('-Frag'))
      self.btnRmFrag.setVisible(False)
      self.connect(self.btnAddFrag, SIGNAL(CLICKED), self.addFragment)
      self.connect(self.btnRmFrag, SIGNAL(CLICKED), self.removeFragment)
      self.chkEncrypt = QCheckBox(self.tr('Encrypt Restored Wallet'))
      self.chkEncrypt.setChecked(True)
      frmAddRm = makeHorizFrame([self.chkEncrypt, STRETCH, self.btnRmFrag, self.btnAddFrag])

      self.fragDataMap = {}
      self.tableSize = 2
      self.wltType = UNKNOWN
      self.fragIDPrefix = UNKNOWN

      doItText = self.tr('Test Backup') if thisIsATest else self.tr('Restore from Fragments')

      btnExit = QPushButton(self.tr('Cancel'))
      self.btnRestore = QPushButton(doItText)
      self.connect(btnExit, SIGNAL(CLICKED), self.reject)
      self.connect(self.btnRestore, SIGNAL(CLICKED), self.processFrags)
      frmBtns = makeHorizFrame([btnExit, STRETCH, self.btnRestore])

      self.lblRightFrm = QRichLabel('', hAlign=Qt.AlignHCenter)
      self.lblSecureStr = QRichLabel(self.trUtf8(u'SecurePrint\u200b\u2122 Code:'), \
                                     hAlign=Qt.AlignHCenter,
                                     doWrap=False,
                                     color='TextWarn')
      self.displaySecureString = QLineEdit()
      self.imgPie = QRichLabel('', hAlign=Qt.AlignHCenter)
      self.imgPie.setMinimumWidth(96)
      self.imgPie.setMinimumHeight(96)
      self.lblReqd = QRichLabel('', hAlign=Qt.AlignHCenter)
      self.lblWltID = QRichLabel('', doWrap=False, hAlign=Qt.AlignHCenter)
      self.lblFragID = QRichLabel('', doWrap=False, hAlign=Qt.AlignHCenter)
      self.lblSecureStr.setVisible(False)
      self.displaySecureString.setVisible(False)
      self.displaySecureString.setMaximumWidth(relaxedSizeNChar(self.displaySecureString, 16)[0])
        # The Secure String is now edited in DlgEnterOneFrag, It is only displayed here
      self.displaySecureString.setEnabled(False)
      frmSecPair = makeVertFrame([self.lblSecureStr, self.displaySecureString])
      frmSecCtr = makeHorizFrame([STRETCH, frmSecPair, STRETCH])

      frmWltInfo = makeVertFrame([STRETCH,
                                   self.lblRightFrm,
                                   self.imgPie,
                                   self.lblReqd,
                                   self.lblWltID,
                                   self.lblFragID,
                                   HLINE(),
                                   frmSecCtr,
                                   'Strut(200)',
                                   STRETCH], STYLE_SUNKEN)


      fragmentsLayout = QGridLayout()
      fragmentsLayout.addWidget(frmDescr, 0, 0, 1, 2)
      fragmentsLayout.addWidget(frmAddRm, 1, 0, 1, 1)
      fragmentsLayout.addWidget(self.scrollFragInput, 2, 0, 1, 1)
      fragmentsLayout.addWidget(frmWltInfo, 1, 1, 2, 1)
      setLayoutStretchCols(fragmentsLayout, 1, 0)

      walletRestoreTabs = QTabWidget()
      fragmentsFrame = QFrame()
      fragmentsFrame.setLayout(fragmentsLayout)
      walletRestoreTabs.addTab(fragmentsFrame, self.tr("Fragments"))
      self.advancedOptionsTab = AdvancedOptionsFrame(parent, main)
      walletRestoreTabs.addTab(self.advancedOptionsTab, self.tr("Advanced Options"))

      self.chkEncrypt.setChecked(not thisIsATest)
      self.chkEncrypt.setVisible(not thisIsATest)
      self.advancedOptionsTab.setEnabled(not thisIsATest)
      if not thisIsATest:
         self.connect(self.chkEncrypt, SIGNAL(CLICKED), self.onEncryptCheckboxChange)

      layout = QVBoxLayout()
      layout.addWidget(walletRestoreTabs)
      layout.addWidget(frmBtns)
      self.setLayout(layout)
      self.setMinimumWidth(650)
      self.setMinimumHeight(500)
      self.sizeHint = lambda: QSize(800, 650)
      self.setWindowTitle(self.tr('Restore wallet from fragments'))

      self.makeFragInputTable()
      self.checkRestoreParams()

    #############################################################################
    # Hide advanced options whenver the restored wallet is unencrypted
   def onEncryptCheckboxChange(self):
      self.advancedOptionsTab.setEnabled(self.chkEncrypt.isChecked())

   def makeFragInputTable(self, addCount=0):

      self.tableSize += addCount
      newLayout = QGridLayout()
      newFrame = QFrame()
      self.fragsDone = []
      newLayout.addWidget(HLINE(), 0, 0, 1, 5)
      for i in range(self.tableSize):
         btnEnter = QPushButton(self.tr('Type Data'))
         btnLoad = QPushButton(self.tr('Load File'))
         btnClear = QPushButton(self.tr('Clear'))
         lblFragID = QRichLabel('', doWrap=False)
         lblSecure = QLabel('')
         if i in self.fragDataMap:
            M, fnum, wltID, doMask, fid = ReadFragIDLineBin(self.fragDataMap[i][0])
            self.fragsDone.append(fnum)
            lblFragID.setText('<b>' + fid + '</b>')
            if doMask:
               lblFragID.setText('<b>' + fid + '</b>', color='TextWarn')


         self.connect(btnEnter, SIGNAL(CLICKED), \
                      functools.partial(self.dataEnter, fnum=i))
         self.connect(btnLoad, SIGNAL(CLICKED), \
                      functools.partial(self.dataLoad, fnum=i))
         self.connect(btnClear, SIGNAL(CLICKED), \
                      functools.partial(self.dataClear, fnum=i))


         newLayout.addWidget(btnEnter, 2 * i + 1, 0)
         newLayout.addWidget(btnLoad, 2 * i + 1, 1)
         newLayout.addWidget(btnClear, 2 * i + 1, 2)
         newLayout.addWidget(lblFragID, 2 * i + 1, 3)
         newLayout.addWidget(lblSecure, 2 * i + 1, 4)
         newLayout.addWidget(HLINE(), 2 * i + 2, 0, 1, 5)

      btnFrame = QFrame()
      btnFrame.setLayout(newLayout)

      frmFinal = makeVertFrame([btnFrame, STRETCH], STYLE_SUNKEN)
      self.scrollFragInput.setWidget(frmFinal)

      self.btnAddFrag.setVisible(self.tableSize < 12)
      self.btnRmFrag.setVisible(self.tableSize > 2)


    #############################################################################
   def addFragment(self):
      self.makeFragInputTable(1)

    #############################################################################
   def removeFragment(self):
      self.makeFragInputTable(-1)
      toRemove = []
      for key, val in self.fragDataMap.iteritems():
         if key >= self.tableSize:
            toRemove.append(key)

        # Have to do this in a separate loop, cause you can't remove items
        # from a map while you are iterating over them
      for key in toRemove:
         self.dataClear(key)


    #############################################################################
   def dataEnter(self, fnum):
      dlg = DlgEnterOneFrag(self, self.main, self.fragsDone, self.wltType, self.displaySecureString.text())
      if dlg.exec_():
         LOGINFO('Good data from enter_one_frag exec! %d', fnum)
         self.displaySecureString.setText(dlg.editSecurePrint.text())
         self.addFragToTable(fnum, dlg.fragData)
         self.makeFragInputTable()


    #############################################################################
   def dataLoad(self, fnum):
      LOGINFO('Loading data for entry, %d', fnum)
      toLoad = str(self.main.getFileLoad('Load Fragment File', \
                                    ['Wallet Fragments (*.frag)']))

      if len(toLoad) == 0:
         return

      if not os.path.exists(toLoad):
         LOGERROR('File just chosen does not exist! %s', toLoad)
         QMessageBox.critical(self, self.tr('File Does Not Exist'), self.tr(
             'The file you select somehow does not exist...? '
             '<br><br>%s<br><br> Try a different file' % toLoad), \
             QMessageBox.Ok)

      fragMap = {}
      with open(toLoad, 'r') as fin:
         allData = [line.strip() for line in fin.readlines()]
         fragMap = {}
         for line in allData:
            if line[:2].lower() in ['id', 'x1', 'x2', 'x3', 'x4', \
                                        'y1', 'y2', 'y3', 'y4', \
                                        'f1', 'f2', 'f3', 'f4']:
               fragMap[line[:2].lower()] = line[3:].strip().replace(' ', '')


      cList, nList = [], []
      if len(fragMap) == 9:
         cList, nList = ['x', 'y'], ['1', '2', '3', '4']
      elif len(fragMap) == 5:
         cList, nList = ['f'], ['1', '2', '3', '4']
      elif len(fragMap) == 3:
         cList, nList = ['f'], ['1', '2']
      else:
         LOGERROR('Unexpected number of lines in the frag file, %d', len(fragMap))
         return

      fragData = []
      fragData.append(hex_to_binary(fragMap['id']))
      for c in cList:
         for n in nList:
            mapKey = c + n
            rawBin, err = readSixteenEasyBytes(fragMap[c + n])
            if err == 'Error_2+':
               QMessageBox.critical(self, self.tr('Fragment Error'), self.tr(
                  'There was an unfixable error in the fragment file: '
                  '<br><br> File: %s <br> Line: %s <br>' % (toLoad, mapKey)), \
                  QMessageBox.Ok)
               return
#                fragData.append(SecureBinaryData(rawBin))
            rawBin = None

      self.addFragToTable(fnum, fragData)
      self.makeFragInputTable()


    #############################################################################
   def dataClear(self, fnum):
      if not fnum in self.fragDataMap:
         return

      for i in range(1, 3):
         self.fragDataMap[fnum][i].destroy()
      del self.fragDataMap[fnum]
      self.makeFragInputTable()
      self.checkRestoreParams()


    #############################################################################
   def checkRestoreParams(self):
      showRightFrm = False
      self.btnRestore.setEnabled(False)
      self.lblRightFrm.setText(self.tr(
         '<b>Start entering fragments into the table to left...</b>'))
      for row, data in self.fragDataMap.iteritems():
         showRightFrm = True
         M, fnum, setIDBin, doMask, idBase58 = ReadFragIDLineBin(data[0])
         self.lblRightFrm.setText(self.tr('<b><u>Wallet Being Restored:</u></b>'))
         self.imgPie.setPixmap(QPixmap('./img/frag%df.png' % M).scaled(96,96))
         self.lblReqd.setText(self.tr('<b>Frags Needed:</b> %s' % M))
         self.lblFragID.setText(self.tr('<b>Fragments:</b> %s' % idBase58.split('-')[0]))
         self.btnRestore.setEnabled(len(self.fragDataMap) >= M)
         break

      anyMask = False
      for row, data in self.fragDataMap.iteritems():
         M, fnum, wltIDBin, doMask, idBase58 = ReadFragIDLineBin(data[0])
         if doMask:
            anyMask = True
            break
        # If all of the rows with a Mask have been removed clear the securePrintCode
      if  not anyMask:
         self.displaySecureString.setText('')
      self.lblSecureStr.setVisible(anyMask)
      self.displaySecureString.setVisible(anyMask)

      if not showRightFrm:
         self.fragIDPrefix = UNKNOWN
         self.wltType = UNKNOWN

      self.imgPie.setVisible(showRightFrm)
      self.lblReqd.setVisible(showRightFrm)
      self.lblWltID.setVisible(showRightFrm)
      self.lblFragID.setVisible(showRightFrm)


    #############################################################################
   def addFragToTable(self, tableIndex, fragData):

      if len(fragData) == 9:
         currType = '0'
      elif len(fragData) == 5:
         currType = BACKUP_TYPE_135A
      elif len(fragData) == 3:
         currType = BACKUP_TYPE_135C
      else:
         LOGERROR('How\'d we get fragData of size: %d', len(fragData))
         return

      if self.wltType == UNKNOWN:
         self.wltType = currType
      elif not self.wltType == currType:
         QMessageBox.critical(self, self.tr('Mixed fragment types'), self.tr(
            'You entered a fragment for a different wallet type.  Please check '
            'that all fragments are for the same wallet, of the same version, '
            'and require the same number of fragments.'), QMessageBox.Ok)
         LOGERROR('Mixing frag types!  How did that happen?')
         return


      M, fnum, wltIDBin, doMask, idBase58 = ReadFragIDLineBin(fragData[0])
        # If we don't know the Secure String Yet we have to get it
      if doMask and len(str(self.displaySecureString.text()).strip()) == 0:
         dlg = DlgEnterSecurePrintCode(self, self.main)
         if dlg.exec_():
            self.displaySecureString.setText(dlg.editSecurePrint.text())
         else:
            return

      if self.fragIDPrefix == UNKNOWN:
         self.fragIDPrefix = idBase58.split('-')[0]
      elif not self.fragIDPrefix == idBase58.split('-')[0]:
         QMessageBox.critical(self, self.tr('Multiple Wallets'), self.tr(
            'The fragment you just entered is actually for a different wallet '
            'than the previous fragments you entered.  Please double-check that '
            'all the fragments you are entering belong to the same wallet and '
            'have the "number of needed fragments" (M-value, in M-of-N).'), \
            QMessageBox.Ok)
         LOGERROR('Mixing fragments of different wallets! %s', idBase58)
         return


      if not self.verifyNonDuplicateFrag(fnum):
         QMessageBox.critical(self, self.tr('Duplicate Fragment'), self.tr(
            'You just input fragment #%s, but that fragment has already been '
            'entered!' % fnum), QMessageBox.Ok)
         return



#        if currType == '0':
#            X = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(1, 5)]))
#            Y = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(5, 9)]))
#        elif currType == BACKUP_TYPE_135A:
#            X = SecureBinaryData(int_to_binary(fnum + 1, widthBytes=64, endOut=BIGENDIAN))
#            Y = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(1, 5)]))
#        elif currType == BACKUP_TYPE_135C:
#            X = SecureBinaryData(int_to_binary(fnum + 1, widthBytes=32, endOut=BIGENDIAN))
#            Y = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(1, 3)]))

      self.fragDataMap[tableIndex] = [fragData[0][:], X.copy(), Y.copy()]

      X.destroy()
      Y.destroy()
      self.checkRestoreParams()

    #############################################################################
   def verifyNonDuplicateFrag(self, fnum):
      for row, data in self.fragDataMap.iteritems():
         rowFrag = ReadFragIDLineBin(data[0])[1]
         if fnum == rowFrag:
            return False

      return True



    #############################################################################
   def processFrags(self):
      if self.chkEncrypt.isChecked() and self.advancedOptionsTab.getKdfSec() == -1:
         QMessageBox.critical(self, self.tr('Invalid Target Compute Time'), \
            self.tr('You entered Target Compute Time incorrectly.\n\nEnter: <Number> (ms, s)'), QMessageBox.Ok)
         return
      if self.chkEncrypt.isChecked() and self.advancedOptionsTab.getKdfBytes() == -1:
         QMessageBox.critical(self, self.tr('Invalid Max Memory Usage'), \
            self.tr('You entered Max Memory Usage incorrectly.\n\nEnter: <Number> (kB, MB)'), QMessageBox.Ok)
         return
      SECPRINT = HardcodedKeyMaskParams()
      pwd, ekey = '', ''
      if self.displaySecureString.isVisible():
         pwd = str(self.displaySecureString.text()).strip()
         maskKey = SECPRINT['FUNC_KDF'](pwd)

      fragMtrx, M = [], -1
      for row, trip in self.fragDataMap.iteritems():
         M, fnum, wltID, doMask, fid = ReadFragIDLineBin(trip[0])
         X, Y = trip[1], trip[2]
         if doMask:
            LOGINFO('Row %d needs unmasking' % row)
            Y = SECPRINT['FUNC_UNMASK'](Y, ekey=maskKey)
         else:
            LOGINFO('Row %d is already unencrypted' % row)
         fragMtrx.append([X.toBinStr(), Y.toBinStr()])

      typeToBytes = {'0': 64, BACKUP_TYPE_135A: 64, BACKUP_TYPE_135C: 32}
      nBytes = typeToBytes[self.wltType]


      if self.thisIsATest and len(fragMtrx) > M:
         self.testFragSubsets(fragMtrx, M)
         return


      SECRET = ReconstructSecret(fragMtrx, M, nBytes)
      for i in range(len(fragMtrx)):
         fragMtrx[i] = []

      LOGINFO('Final length of frag mtrx: %d', len(fragMtrx))
      LOGINFO('Final length of secret:    %d', len(SECRET))

      priv, chain = '', ''
#        if len(SECRET) == 64:
#            priv = SecureBinaryData(SECRET[:32 ])
#            chain = SecureBinaryData(SECRET[ 32:])
#        elif len(SECRET) == 32:
#            priv = SecureBinaryData(SECRET)
#            chain = DeriveChaincodeFromRootKey(priv)


        # If we got here, the data is valid, let's create the wallet and accept the dlg
        # Now we should have a fully-plaintext rootkey and chaincode
      root = PyBtcAddress().createFromPlainKeyData(priv)
      root.chaincode = chain

      first = root.extendAddressChain()
      newWltID = binary_to_base58((ADDRBYTE + first.getAddr160()[:5])[::-1])

        # If this is a test, then bail
      if self.thisIsATest:
         verifyRecoveryTestID(self, newWltID, self.testWltID)
         return

      dlgOwnWlt = None
      if newWltID in self.main.walletMap:
         dlgOwnWlt = DlgReplaceWallet(newWltID, self.parent, self.main)

         if (dlgOwnWlt.exec_()):
            if dlgOwnWlt.output == 0:
               return
         else:
            self.reject()
            return

      reply = QMessageBox.question(self, self.tr('Verify Wallet ID'), self.tr(
         'The data you entered corresponds to a wallet with the '
         'ID:<blockquote><b>{%s}</b></blockquote>Does this ID '
         'match the "Wallet Unique ID" printed on your paper backup? '
         'If not, click "No" and reenter key and chain-code data '
         'again.' % newWltID), QMessageBox.Yes | QMessageBox.No)
      if reply == QMessageBox.No:
         return


      passwd = []
      if self.chkEncrypt.isChecked():
         dlgPasswd = DlgChangePassphrase(self, self.main)
#            if dlgPasswd.exec_():
#                passwd = SecureBinaryData(str(dlgPasswd.edtPasswd1.text()))
#            else:
#                QMessageBox.critical(self, self.tr('Cannot Encrypt'), self.tr(
#                   'You requested your restored wallet be encrypted, but no '
#                   'valid passphrase was supplied.  Aborting wallet '
#                   'recovery.'), QMessageBox.Ok)
#                return

      shortl = ''
      longl  = ''
      nPool  = 1000

      if dlgOwnWlt is not None:
         if dlgOwnWlt.Meta is not None:
            shortl = ' - %s' % (dlgOwnWlt.Meta['shortLabel'])
            longl  = dlgOwnWlt.Meta['longLabel']
            nPool = max(nPool, dlgOwnWlt.Meta['naddress'])

      if passwd:
         self.newWallet = PyBtcWallet().createNewWallet(\
                                  plainRootKey=priv, \
                                  chaincode=chain, \
                                  shortLabel='Restored - ' + newWltID + shortl, \
                                  longLabel=longl, \
                                  withEncrypt=True, \
                                  securePassphrase=passwd, \
                                  kdfTargSec=self.advancedOptionsTab.getKdfSec(), \
                                  kdfMaxMem=self.advancedOptionsTab.getKdfBytes(),
                                  isActuallyNew=False, \
                                  doRegisterWithBDM=False)
      else:
         self.newWallet = PyBtcWallet().createNewWallet(\
                                    plainRootKey=priv, \
                                    chaincode=chain, \
                                    shortLabel='Restored - ' + newWltID +shortl, \
                                    longLabel=longl, \
                                    withEncrypt=False, \
                                    isActuallyNew=False, \
                                    doRegisterWithBDM=False)


        # Will pop up a little "please wait..." window while filling addr pool
      fillAddrPoolProgress = DlgProgress(self, self.parent, HBar=1,
                                         Title=self.tr("Computing New Addresses"))
      fillAddrPoolProgress.exec_(self.newWallet.fillAddressPool, nPool)

      if dlgOwnWlt is not None:
         if dlgOwnWlt.Meta is not None:
            from armoryengine.PyBtcWallet import WLT_UPDATE_ADD
            for n_cmt in range(0, dlgOwnWlt.Meta['ncomments']):
               entrylist = []
               entrylist = list(dlgOwnWlt.Meta[n_cmt])
               self.newWallet.walletFileSafeUpdate([[WLT_UPDATE_ADD, entrylist[2], entrylist[1], entrylist[0]]])

         self.newWallet = PyBtcWallet().readWalletFile(self.newWallet.walletPath)
      self.accept()

    #############################################################################
   def testFragSubsets(self, fragMtrx, M):
        # If the user entered multiple fragments
      fragMap = {}
      for x, y in fragMtrx:
         fragMap[binary_to_int(x, BIGENDIAN) - 1] = [x, y]
      typeToBytes = {'0': 64, BACKUP_TYPE_135A: 64, BACKUP_TYPE_135C: 32}

      isRandom, results = testReconstructSecrets(fragMap, M, 100)
      def privAndChainFromRow(secret):
         priv, chain = None, None
#            if len(secret) == 64:
#                priv = SecureBinaryData(secret[:32 ])
#                chain = SecureBinaryData(secret[ 32:])
#                return (priv, chain)
#            elif len(secret) == 32:
#                priv = SecureBinaryData(secret)
#                chain = DeriveChaincodeFromRootKey(priv)
#                return (priv, chain)
#            else:
#                LOGERROR('Root secret is %s bytes ?!' % len(secret))
#                raise KeyDataError

      results = [(row[0], privAndChainFromRow(row[1])) for row in results]
      subsAndIDs = [(row[0], calcWalletIDFromRoot(*row[1])) for row in results]

      DlgShowTestResults(self, isRandom, subsAndIDs, \
