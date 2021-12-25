from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
################################################################################
#                                                                              #
# Copyright (C) 2011-2021, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

import os

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QPushButton, QGridLayout, QFrame, \
   QVBoxLayout, QLabel, QMessageBox, QTextEdit, QSizePolicy, \
   QApplication

from qtdialogs.qtdefines import ArmoryFrame, tightSizeNChar, \
   GETFONT, QRichLabel, HLINE, QLabelButton, USERMODE, \
   VERTICAL, HORIZONTAL, STYLE_RAISED, relaxedSizeNChar, STYLE_SUNKEN, \
   relaxedSizeStr, makeLayoutFrame, tightSizeStr, NETWORKMODE, \
   MsgBoxWithDNAA, MSGBOX

from qtdialogs.qtdialogs import STRETCH
from qtdialogs.DlgDispTxInfo import DlgDispTxInfo, extractTxInfo
from qtdialogs.DlgConfirmSend import DlgConfirmSend

from armoryengine.Transaction import UnsignedTransaction
from armoryengine.ArmoryUtils import LOGEXCEPT, LOGERROR, LOGINFO, \
   CPP_TXOUT_STDSINGLESIG, CPP_TXOUT_P2SH, coin2str, enum, \
   script_to_scrAddr, binary_to_hex, coin2strNZS

################################################################################
class SignBroadcastOfflineTxFrame(ArmoryFrame):
   """
   We will make the assumption that this Frame is used ONLY for outgoing
   transactions from your wallet.  This simplifies the logic if we don't
   have to identify input senders/values, and handle the cases where those
   may not be specified
   """
   def __init__(self, parent=None, main=None, initLabel=''):
      super(SignBroadcastOfflineTxFrame, self).__init__(parent, main)

      self.wlt = None
      self.sentToSelfWarn = False
      self.fileLoaded = None

      lblDescr = QRichLabel(self.tr(
         'Copy or load a transaction from file into the text box below.  '
         'If the transaction is unsigned and you have the correct wallet, '
         'you will have the opportunity to sign it.  If it is already signed '
         'you will have the opportunity to broadcast it to '
         'the Bitcoin network to make it final.'))

      self.txtUSTX = QTextEdit()
      self.txtUSTX.setFont(GETFONT('Fixed', 8))
      w,h = relaxedSizeNChar(self.txtUSTX, 68)
      self.txtUSTX.setMinimumWidth(w)
      self.txtUSTX.setMinimumHeight(8*h)
      self.txtUSTX.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

      self.btnSign = QPushButton(self.tr('Sign'))
      self.btnBroadcast = QPushButton(self.tr('Broadcast'))
      self.btnSave = QPushButton(self.tr('Save file...'))
      self.btnLoad = QPushButton(self.tr('Load file...'))
      self.btnCopy = QPushButton(self.tr('Copy Text'))
      self.btnCopyHex = QPushButton(self.tr('Copy Raw Tx (Hex)'))
      self.lblCopied = QRichLabel('')
      self.lblCopied.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      self.btnSign.setEnabled(False)
      self.btnBroadcast.setEnabled(False)

      self.txtUSTX.textChanged.connect(self.processUSTX)


      self.btnSign.clicked.connect(self.signTx)
      self.btnBroadcast.clicked.connect(self.broadTx)
      self.btnSave.clicked.connect(self.saveTx)
      self.btnLoad.clicked.connect(self.loadTx)
      self.btnCopy.clicked.connect(self.copyTx)
      self.btnCopyHex.clicked.connect(self.copyTxHex)

      self.lblStatus = QRichLabel('')
      self.lblStatus.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      wStat, hStat = relaxedSizeStr(self.lblStatus, self.tr('Signature is Invalid!'))
      self.lblStatus.setMinimumWidth(int(wStat * 1.2))
      self.lblStatus.setMinimumHeight(int(hStat * 1.2))


      frmDescr = makeLayoutFrame(HORIZONTAL, [lblDescr], STYLE_RAISED)

      self.infoLbls = []

      # ##
      self.infoLbls.append([])
      self.infoLbls[-1].append(self.main.createToolTipWidget(\
            self.tr('This is wallet from which the offline transaction spends bitcoins')))
      self.infoLbls[-1].append(QRichLabel('<b>Wallet:</b>'))
      self.infoLbls[-1].append(QRichLabel(''))

      # ##
      self.infoLbls.append([])
      self.infoLbls[-1].append(self.main.createToolTipWidget(self.tr('The name of the wallet')))
      self.infoLbls[-1].append(QRichLabel(self.tr('<b>Wallet Label:</b>')))
      self.infoLbls[-1].append(QRichLabel(''))

      # ##
      self.infoLbls.append([])
      self.infoLbls[-1].append(self.main.createToolTipWidget(self.tr(
         'A unique string that identifies an <i>unsigned</i> transaction.  '
         'This is different than the ID that the transaction will have when '
         'it is finally broadcast, because the broadcast ID cannot be '
         'calculated without all the signatures')))
      self.infoLbls[-1].append(QRichLabel(self.tr('<b>Pre-Broadcast ID:</b>')))
      self.infoLbls[-1].append(QRichLabel(''))

      # ##
      self.infoLbls.append([])
      self.infoLbls[-1].append(self.main.createToolTipWidget(\
                               self.tr('Net effect on this wallet\'s balance')))
      self.infoLbls[-1].append(QRichLabel(self.tr('<b>Transaction Amount:</b>')))
      self.infoLbls[-1].append(QRichLabel(''))

      self.moreInfo = QLabelButton(self.tr('Click here for more<br> information about <br>this transaction'))
      self.moreInfo.linkActivated.connect(self.execMoreTxInfo)
      frmMoreInfo = makeLayoutFrame(HORIZONTAL, [self.moreInfo], STYLE_SUNKEN)
      frmMoreInfo.setMinimumHeight(tightSizeStr(self.moreInfo, 'Any String')[1] * 5)

      expert = (self.main.usermode == USERMODE.Expert)
      frmBtn = makeLayoutFrame(VERTICAL, [ self.btnSign, \
                                         self.btnBroadcast, \
                                         self.btnSave, \
                                         self.btnLoad, \
                                         self.btnCopy, \
                                         self.btnCopyHex if expert else QRichLabel(''), \
                                         self.lblCopied, \
                                         HLINE(), \
                                         self.lblStatus, \
                                         HLINE(), \
                                         'Stretch', \
                                         frmMoreInfo])

      frmBtn.setMaximumWidth(tightSizeNChar(QPushButton(''), 30)[0])

      frmInfoLayout = QGridLayout()
      for r in range(len(self.infoLbls)):
         for c in range(len(self.infoLbls[r])):
            frmInfoLayout.addWidget(self.infoLbls[r][c], r, c, 1, 1)

      frmInfo = QFrame()
      frmInfo.setFrameStyle(STYLE_SUNKEN)
      frmInfo.setLayout(frmInfoLayout)

      frmBottom = QFrame()
      frmBottom.setFrameStyle(STYLE_SUNKEN)
      frmBottomLayout = QGridLayout()
      frmBottomLayout.addWidget(self.txtUSTX, 0, 0, 1, 1)
      frmBottomLayout.addWidget(frmBtn, 0, 1, 2, 1)
      frmBottomLayout.addWidget(frmInfo, 1, 0, 1, 1)
      # frmBottomLayout.addWidget(frmMoreInfo,   1,1,  1,1)
      frmBottom.setLayout(frmBottomLayout)

      layout = QVBoxLayout()
      layout.addWidget(frmDescr)
      layout.addWidget(frmBottom)

      self.setLayout(layout)
      self.processUSTX()

   def processUSTX(self):
      # TODO:  it wouldn't be TOO hard to modify this dialog to take
      #        arbitrary hex-serialized transactions for broadcast...
      #        but it's not trivial either (for instance, I assume
      #        that we have inputs values, etc)
      self.wlt = None
      self.leValue = None
      self.ustxObj = None
      self.idxSelf = []
      self.idxOther = []
      self.lblStatus.setText('')
      self.lblCopied.setText('')
      self.enoughSigs = False
      self.sigsValid = False
      self.ustxReadable = False
      self.btnSign.setEnabled(False)

      ustxStr = str(self.txtUSTX.toPlainText())
      if len(ustxStr) > 0:
         try:
            self.ustxObj = UnsignedTransaction().unserializeAscii(ustxStr)
            self.signStat = self.ustxObj.evaluateSigningStatus()
            self.enoughSigs = self.signStat.canBroadcast
            self.sigsValid = self.ustxObj.verifySigsAllInputs()
            self.ustxReadable = True
         except BadAddressError:
            QMessageBox.critical(self, self.tr('Inconsistent Data!'), \
               self.tr('This transaction contains inconsistent information.  This '
               'is probably not your fault...'), QMessageBox.Ok)
            self.ustxObj = None
            self.ustxReadable = False
         except NetworkIDError:
            QMessageBox.critical(self, self.tr('Wrong Network!'), \
               self.tr('This transaction is actually for a different network!  '
               'Did you load the correct transaction?'), QMessageBox.Ok)
            self.ustxObj = None
            self.ustxReadable = False
         except (UnserializeError, IndexError, ValueError):
            self.ustxObj = None
            self.ustxReadable = False

         if not self.enoughSigs or not self.sigsValid or not self.ustxReadable:
            self.btnBroadcast.setEnabled(False)
         else:
            if self.main.netMode == NETWORKMODE.Full:
               self.btnBroadcast.setEnabled(True)
            else:
               self.btnBroadcast.setEnabled(False)
               self.btnBroadcast.setToolTip(self.tr('No connection to Bitcoin network!'))
      else:
         self.ustxObj = None
         self.ustxReadable = False
         self.btnBroadcast.setEnabled(False)


      self.btnSave.setEnabled(True)
      self.btnCopyHex.setEnabled(False)
      if not self.ustxReadable:
         if len(ustxStr) > 0:
            self.lblStatus.setText(self.tr('<b><font color="red">Unrecognized!</font></b>'))
         else:
            self.lblStatus.setText('')
         self.btnSign.setEnabled(False)
         self.btnBroadcast.setEnabled(False)
         self.btnSave.setEnabled(False)
         self.makeReviewFrame()
         return
      elif not self.enoughSigs:
         if not self.main.getSettingOrSetDefault('DNAA_ReviewOfflineTx', False):
            result = MsgBoxWithDNAA(self, self.main, MSGBOX.Warning, title=self.tr('Offline Warning'), \
                  msg=self.tr('<b>Please review your transaction carefully before '
                  'signing and broadcasting it!</b>  The extra security of '
                  'using offline wallets is lost if you do '
                  'not confirm the transaction is correct!'), dnaaMsg=None)
            self.main.writeSetting('DNAA_ReviewOfflineTx', result[1])
         self.lblStatus.setText(self.tr('<b><font color="red">Unsigned</font></b>'))
         self.btnSign.setEnabled(True)
         self.btnBroadcast.setEnabled(False)
      elif not self.sigsValid:
         self.lblStatus.setText(self.tr('<b><font color="red">Bad Signature!</font></b>'))
         self.btnSign.setEnabled(True)
         self.btnBroadcast.setEnabled(False)
      else:
         self.lblStatus.setText(self.tr('<b><font color="green">All Signatures Valid!</font></b>'))
         self.btnSign.setEnabled(False)
         self.btnCopyHex.setEnabled(True)


      # NOTE:  We assume this is an OUTGOING transaction.  When I pull in the
      #        multi-sig code, I will have to either make a different dialog,
      #        or add some logic to this one
      FIELDS = enum('Hash', 'OutList', 'SumOut', 'InList', 'SumIn', 'Time', 'Blk', 'Idx')
      data = extractTxInfo(self.ustxObj, -1)

      # Collect the input wallets (hopefully just one of them)
      fromWlts = set()
      for addrStr, amt, a, b, c, script in data[FIELDS.InList]:
         wltID = self.main.getWalletForAddressString(addrStr)
         if not wltID == '':
            fromWlts.add(wltID)

      if len(fromWlts) > 1:
         QMessageBox.warning(self, self.tr('Multiple Input Wallets'), \
            self.tr('Somehow, you have obtained a transaction that actually pulls from more '
            'than one wallet.  The support for handling multi-wallet signatures is '
            'not currently implemented (this also could have happened if you imported '
            'the same private key into two different wallets).') , QMessageBox.Ok)
         self.makeReviewFrame()
         return
      elif len(fromWlts) == 0:
         QMessageBox.warning(self, self.tr('Unrelated Transaction'), \
            self.tr('This transaction appears to have no relationship to any of the wallets '
            'stored on this computer.  Did you load the correct transaction?'), \
            QMessageBox.Ok)
         self.makeReviewFrame()
         return

      spendWltID = fromWlts.pop()
      self.wlt = self.main.walletMap[spendWltID]

      toWlts = set()
      myOutSum = 0
      theirOutSum = 0
      rvPairs = []
      idx = 0
      for scrType, amt, binScript, multiSigList in data[FIELDS.OutList]:
         recip = script_to_scrAddr(binScript)
         try:
            wltID = self.main.getWalletForAddrHash(recip)
         except BadAddressError:
            wltID = ''

         if wltID == spendWltID:
            toWlts.add(wltID)
            myOutSum += amt
            self.idxSelf.append(idx)
         else:
            rvPairs.append([recip, amt])
            theirOutSum += amt
            self.idxOther.append(idx)
         idx += 1

      myInSum = data[FIELDS.SumIn]  # because we assume all are ours

      if myInSum == None:
         fee = None
      else:
         fee = myInSum - data[FIELDS.SumOut]

      self.leValue = theirOutSum
      self.makeReviewFrame()


   ############################################################################
   def makeReviewFrame(self):
      # ##
      if self.ustxObj == None:
         self.infoLbls[0][2].setText('')
         self.infoLbls[1][2].setText('')
         self.infoLbls[2][2].setText('')
         self.infoLbls[3][2].setText('')
      else:
         ##### 0
         #self.btnSign.setDisabled(True)

         ##### 1
         if self.wlt:
            self.infoLbls[0][2].setText(self.wlt.uniqueIDB58)
            self.infoLbls[1][2].setText(self.wlt.labelName)
         else:
            self.infoLbls[0][2].setText(self.tr('[[ Unrelated ]]'))
            self.infoLbls[1][2].setText('')

         ##### 2
         self.infoLbls[2][2].setText(self.ustxObj.uniqueIDB58)

         ##### 3
         if self.leValue:
            self.infoLbls[3][2].setText(coin2strNZS(self.leValue) + '  BTC')
         else:
            self.infoLbls[3][2].setText('')

         self.moreInfo.setVisible(True)

   def execMoreTxInfo(self):

      if not self.ustxObj:
         self.processUSTX()

      if not self.ustxObj:
         QMessageBox.warning(self, self.tr('Invalid Transaction'), \
            self.tr('Transaction data is invalid and cannot be shown!'), QMessageBox.Ok)
         return

      leVal = 0 if self.leValue is None else -self.leValue
      dlgTxInfo = DlgDispTxInfo(self.ustxObj, self.wlt, self.parent(), self.main, \
         precomputeIdxGray=self.idxSelf, precomputeAmt=leVal, txtime=-1)
      dlgTxInfo.exec_()



   def signTx(self):
      if not self.ustxObj:
         QMessageBox.critical(self, self.tr('Cannot Sign'), \
               self.tr('This transaction is not relevant to any of your wallets.'
               'Did you load the correct transaction?'), QMessageBox.Ok)
         return

      if self.ustxObj == None:
         QMessageBox.warning(self, self.tr('Not Signable'), \
               self.tr('This is not a valid transaction, and thus it cannot '
               'be signed. '), QMessageBox.Ok)
         return
      elif self.enoughSigs and self.sigsValid:
         QMessageBox.warning(self, self.tr('Already Signed'), \
               self.tr('This transaction has already been signed!'), QMessageBox.Ok)
         return


      if self.wlt and self.wlt.watchingOnly:
         QMessageBox.warning(self, self.tr('No Private Keys!'), \
            self.tr('This transaction refers one of your wallets, but that wallet '
            'is a watching-only wallet.  Therefore, private keys are '
            'not available to sign this transaction.'), \
             QMessageBox.Ok)
         return


      # We should provide the same confirmation dialog here, as we do when
      # sending a regular (online) transaction.  But the DlgConfirmSend was
      # not really designed
      ustx = self.ustxObj
      svpairs = []
      svpairsMine = []
      theFee = ustx.calculateFee()
      for scrType,value,script,msInfo in ustx.pytxObj.makeRecipientsList():
         svpairs.append([script, value])
         scrAddr = script_to_scrAddr(script)
         if self.wlt.hasAddrHash(scrAddr):
            svpairsMine.append([script, value])

      if len(svpairsMine) == 0 and len(svpairs) > 1:
         QMessageBox.warning(self, self.tr('Missing Change'), self.tr(
            'This transaction has %d recipients, and none of them '
            'are addresses in this wallet (for receiving change). '
            'This can happen if you specified a custom change address '
            'for this transaction, or sometimes happens solely by '
            'chance with a multi-recipient transaction.  It could also '
            'be the result of someone tampering with the transaction. '
            '<br><br>The transaction is valid and ready to be signed. '
            'Please verify the recipient and amounts carefully before '
            'confirming the transaction on the next screen.' % len(svpairs)), QMessageBox.Ok)

      dlg = DlgConfirmSend(self.wlt, svpairs, theFee, self, self.main, pytxOrUstx=ustx)
      if not dlg.exec_():
         return

      def completeSignProcess(success, signerObj):
         def signTxLastStep(success, signerObj):
            serTx = self.ustxObj.serializeAscii()
            self.txtUSTX.setText(serTx)

            if not self.fileLoaded == None:
               self.saveTxAuto()

         self.main.signalExecution.executeMethod(\
            [signTxLastStep, [success, signerObj]])

      self.ustxObj.signTx(self.wlt.uniqueIDB58, completeSignProcess)

   def broadTx(self):
      if self.main.netMode == NETWORKMODE.Disconnected:
         QMessageBox.warning(self, self.tr('No Internet!'), \
            self.tr('Armory lost its connection to Bitcoin Core, and cannot '
            'broadcast any transactions until it is reconnected. '
            'Please verify that Bitcoin Core (or bitcoind) is open '
            'and synchronized with the network.'), QMessageBox.Ok)
         return
      elif self.main.netMode == NETWORKMODE.Offline:
         QMessageBox.warning(self, self.tr('No Internet!'), \
            self.tr('You do not currently have a connection to the Bitcoin network. '
            'If this does not seem correct, verify that  is open '
            'and synchronized with the network.'), QMessageBox.Ok)
         return



      try:
         finalTx = self.ustxObj.getSignedPyTx()
      except SignatureError:
         QMessageBox.warning(self, self.tr('Signature Error'), self.tr(
            'Not all signatures are valid.  This transaction '
            'cannot be broadcast.'), QMessageBox.Ok)
      except:
         QMessageBox.warning(self, self.tr('Error'), self.tr(
            'There was an error processing this transaction, for reasons '
            'that are probably not your fault...'), QMessageBox.Ok)
         return

      # We should provide the same confirmation dialog here, as we do when
      # sending a regular (online) transaction.  But the DlgConfirmSend was
      # not really designed
      ustx = self.ustxObj
      svpairs = [[r[2],r[1]] for r in ustx.pytxObj.makeRecipientsList()]
      theFee = ustx.calculateFee()

      doIt = True
      if self.wlt:
         dlg = DlgConfirmSend(self.wlt, svpairs, theFee, self, self.main, 
                                          sendNow=True, pytxOrUstx=ustx)
         doIt = dlg.exec_()

      if doIt:
         self.main.broadcastTransaction(finalTx)
         if self.fileLoaded and os.path.exists(self.fileLoaded):
            try:
               # pcs = self.fileLoaded.split('.')
               # newFileName = '.'.join(pcs[:-2]) + '.DONE.' + '.'.join(pcs[-2:])
               shutil.move(self.fileLoaded, self.fileLoaded.replace('signed', 'SENT'))
            except:
               QMessageBox.critical(self, self.tr('File Remove Error'), \
                  self.tr('The file could not be deleted.  If you want to delete '
                  'it, please do so manually.  The file was loaded from: '
                  '<br><br>%s: ' % self.fileLoaded), QMessageBox.Ok)

         try:
            self.parent().accept()
         except:
            # This just attempts to close the OfflineReview&Sign window.  If 
            # it fails, the user can close it themselves.
            LOGEXCEPT('Could not close/accept parent dialog.')            


   def saveTxAuto(self):
      if not self.ustxReadable:
         QMessageBox.warning(self, self.tr('Formatting Error'), \
            self.tr('The transaction data was not in a format recognized by '
            'Armory.'))
         return


      if not self.fileLoaded == None and self.enoughSigs and self.sigsValid:
         newSaveFile = self.fileLoaded.replace('unsigned', 'signed')
         LOGINFO('New save file: %s' % newSaveFile)
         f = open(newSaveFile, 'w')
         f.write(str(self.txtUSTX.toPlainText()))
         f.close()
         if not newSaveFile == self.fileLoaded:
            os.remove(self.fileLoaded)
         self.fileLoaded = newSaveFile
         QMessageBox.information(self, self.tr('Transaction Saved!'), \
            self.tr('Your transaction has been saved to the following location:'
            '\n\n%s\n\nIt can now be broadcast from any computer running '
            'Armory in online mode.' % newSaveFile), QMessageBox.Ok)
         return

   def saveTx(self):
      if not self.ustxReadable:
         QMessageBox.warning(self, self.tr('Formatting Error'), \
            self.tr('The transaction data was not in a format recognized by '
            'Armory.'))
         return


      # The strange windows branching is because PyQt in Windows automatically
      # adds the ffilter suffix to the default filename, where as it needs to
      # be explicitly added in PyQt in Linux.  Not sure why this behavior exists.
      defaultFilename = ''
      if not self.ustxObj == None:
         if self.enoughSigs and self.sigsValid:
            suffix = '' if OS_WINDOWS else '.signed.tx'
            defaultFilename = 'armory_%s_%s' % (self.ustxObj.uniqueIDB58, suffix)
            ffilt = 'Transactions (*.signed.tx *.unsigned.tx)'
         else:
            suffix = '' if OS_WINDOWS else '.unsigned.tx'
            defaultFilename = 'armory_%s_%s' % (self.ustxObj.uniqueIDB58, suffix)
            ffilt = 'Transactions (*.unsigned.tx *.signed.tx)'
      filename = self.main.getFileSave('Save Transaction', \
                             [ffilt], \
                             defaultFilename)
      if len(str(filename)) > 0:
         LOGINFO('Saving transaction file: %s', filename)
         f = open(filename, 'w')
         f.write(str(self.txtUSTX.toPlainText()))
         f.close()


   def loadTx(self):
      filename = self.main.getFileLoad(self.tr('Load Transaction'), \
                    ['Transactions (*.signed.tx *.unsigned.tx *.SENT.tx)'])

      if len(str(filename)) > 0:
         LOGINFO('Selected transaction file to load: %s', filename)
         f = open(filename, 'r')
         self.txtUSTX.setText(f.read())
         f.close()
         self.fileLoaded = filename


   def copyTx(self):
      clipb = QApplication.clipboard()
      clipb.clear()
      clipb.setText(str(self.txtUSTX.toPlainText()))
      self.lblCopied.setText(self.tr('<i>Copied!</i>'))


   def copyTxHex(self):
      clipb = QApplication.clipboard()
      clipb.clear()
      clipb.setText(binary_to_hex(\
         self.ustxObj.getSignedPyTx().serialize()))
      self.lblCopied.setText(self.tr('<i>Copied!</i>'))