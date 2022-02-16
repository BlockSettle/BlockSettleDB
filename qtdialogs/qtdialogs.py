# -*- coding: UTF-8 -*-
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

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

import functools
import shutil
import socket
import sys
import time
from zipfile import ZipFile, ZIP_DEFLATED

from PySide2.QtCore import QObject, QSize, QByteArray
from PySide2.QtGui import QColor, QIcon, QPixmap
from PySide2.QtWidgets import QPushButton, QRadioButton, QLineEdit, \
   QGraphicsItem, QGraphicsView, QGraphicsTextItem, \
   QSplashScreen, QProgressBar, QTextEdit, QCheckBox, \
   QSizePolicy, QSpacerItem, QDialogButtonBox, QGridLayout, \
   QTreeView, QScrollArea, QTextBrowser

from armorycolors import Colors, htmlColor
from armoryengine.MultiSigUtils import calcLockboxID, createLockboxEntryStr,\
   LBPREFIX, isBareLockbox, isP2SHLockbox
from armoryengine.ArmoryUtils import BTC_HOME_DIR, MAX_COMMENT_LENGTH, \
   UNKNOWN

from ui.TreeViewGUI import AddressTreeModel
from ui.QrCodeMatrix import CreateQRMatrix
from armoryengine.Block import PyBlockHeader
from armoryengine import ClientProto_pb2

from qtdialogs.qtdefines import USERMODE, GETFONT, tightSizeStr, \
   determineWalletType, WLTTYPES, MSGBOX, QRichLabel

from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.MsgBoxCustom import MsgBoxCustom

NO_CHANGE = 'NoChange'
MIN_PASSWD_WIDTH = lambda obj: tightSizeStr(obj, '*' * 16)[0]
STRETCH = 'Stretch'
BACKUP_TYPE_135A = '1.35a'
BACKUP_TYPE_135C = '1.35c'
BACKUP_TYPE_0_TEXT = 'Version 0  (from script, 9 lines)'
BACKUP_TYPE_135a_TEXT = 'Version 1.35a (5 lines Unencrypted)'
BACKUP_TYPE_135a_SP_TEXT = u'Version 1.35a (5 lines + SecurePrint\u200b\u2122)'
BACKUP_TYPE_135c_TEXT = 'Version 1.35c (3 lines Unencrypted)'
BACKUP_TYPE_135c_SP_TEXT = u'Version 1.35c (3 lines + SecurePrint\u200b\u2122)'
MAX_QR_SIZE = 198
MAX_SATOSHIS = 2100000000000000

#############################################################################
class LetterButton(QPushButton):
   def __init__(self, Low, Up, Row, Spec, edtTarget, parent):
      super(LetterButton, self).__init__('')
      self.lower = Low
      self.upper = Up
      self.defRow = Row
      self.special = Spec
      self.target = edtTarget
      self.parent = parent

      if self.special:
         super(LetterButton, self).setFont(GETFONT('Var', 8))
      else:
         super(LetterButton, self).setFont(GETFONT('Fixed', 10))
      if self.special == 'space':
         self.setText(self.tr('SPACE'))
         self.lower = ' '
         self.upper = ' '
         self.special = 5
      elif self.special == 'shift':
         self.setText(self.tr('SHIFT'))
         self.special = 5
         self.insertLetter = self.pressShift
      elif self.special == 'delete':
         self.setText(self.tr('DEL'))
         self.special = 5
         self.insertLetter = self.pressBackspace

   def insertLetter(self):
      currPwd = str(self.parent.edtPasswd.text())
      insChar = self.upper if self.parent.btnShift.isChecked() else self.lower
      if len(insChar) == 2 and insChar.startswith('#'):
         insChar = insChar[1]

      self.parent.edtPasswd.setText(currPwd + insChar)
      self.parent.reshuffleKeys()

   def pressShift(self):
      self.parent.redrawKeys()

   def pressBackspace(self):
      currPwd = str(self.parent.edtPasswd.text())
      if len(currPwd) > 0:
         self.parent.edtPasswd.setText(currPwd[:-1])
      self.parent.redrawKeys()

################################################################################
class DlgGenericGetPassword(ArmoryDialog):
   def __init__(self, descriptionStr, parent=None, main=None):
      super(DlgGenericGetPassword, self).__init__(parent, main)


      lblDescr = QRichLabel(descriptionStr)
      lblPasswd = QRichLabel(self.tr("Password:"))
      self.edtPasswd = QLineEdit()
      self.edtPasswd.setEchoMode(QLineEdit.Password)
      self.edtPasswd.setMinimumWidth(MIN_PASSWD_WIDTH(self))
      self.edtPasswd.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

      self.btnAccept = QPushButton(self.tr("OK"))
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.accept)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)

      layout = QGridLayout()
      layout.addWidget(lblDescr, 1, 0, 1, 2)
      layout.addWidget(lblPasswd, 2, 0, 1, 1)
      layout.addWidget(self.edtPasswd, 2, 1, 1, 1)
      layout.addWidget(buttonBox, 3, 1, 1, 2)

      self.setLayout(layout)
      self.setWindowTitle(self.tr('Enter Password'))
      self.setWindowIcon(QIcon(self.main.iconfile))

################################################################################
# Hack!  We need to replicate the DlgBugReport... but to be as safe as
# possible for 0.91.1, we simply duplicate the dialog and modify directly.
# TODO:  There's definitely a way to make DlgBugReport more generic so that
#        both these contexts can be handled by it.
class DlgInconsistentWltReport(ArmoryDialog):

   def __init__(self, parent, main, logPathList):
      super(DlgInconsistentWltReport, self).__init__(parent, main)


      QMessageBox.critical(self, self.tr('Inconsistent Wallet!'), self.tr(
         '<font color="%s" size=4><b><u>Important:</u>  Wallet Consistency'
         'Issues Detected!</b></font>'
         '<br><br>'
         'Armory now detects certain kinds of hardware errors, and one'
         'or more of your wallets'
         'was flagged.  The consistency logs need to be analyzed by the'
         'Armory team to determine if any further action is required.'
         '<br><br>'
         '<b>This warning will pop up every time you start Armory until'
         'the wallet is fixed</b>' % htmlColor('TextWarn')),
         QMessageBox.Ok)



      # logPathList is [wltID, corruptFolder] pairs
      self.logPathList = logPathList[:]
      walletList = [self.main.walletMap[wid] for wid,folder in logPathList]

      getWltStr = lambda w: '<b>Wallet "%s" (%s)</b>' % \
                                       (w.labelName, w.uniqueIDB58)

      if len(logPathList) == 1:
         wltDispStr = getWltStr(walletList[0]) + ' is'
      else:
         strList = [getWltStr(w) for w in walletList]
         wltDispStr = ', '.join(strList[:-1]) + ' and ' + strList[-1] + ' are '

      lblTopDescr = QRichLabel(self.tr(
         '<b><u><font color="%s" size=4>Submit Wallet Analysis Logs for '
         'Review</font></u></b><br>' % htmlColor('TextWarn')),
         hAlign=Qt.AlignHCenter)

      lblDescr = QRichLabel(self.tr(
         'Armory has detected that %s is inconsistent, '
         'possibly due to hardware errors out of our control.  It <u>strongly '
         'recommended</u> you submit the wallet logs to the Armory developers '
         'for review.  Until you hear back from an Armory developer, '
         'it is recommended that you: '
         '<ul>'
         '<li><b>Do not delete any data in your Armory home directory</b></li> '
         '<li><b>Do not send or receive any funds with the affected wallet(s)</b></li> '
         '<li><b>Create a backup of the wallet analysis logs</b></li> '
         '</ul>' % wltDispStr))

      btnBackupLogs = QPushButton(self.tr("Save backup of log files"))
      self.connect(btnBackupLogs, SIGNAL('clicked()'), self.doBackupLogs)
      frmBackup = makeHorizFrame(['Stretch', btnBackupLogs, 'Stretch'])

      self.lblSubject = QRichLabel(self.tr('Subject:'))
      self.edtSubject = QLineEdit()
      self.edtSubject.setMaxLength(64)
      self.edtSubject.setText("Wallet Consistency Logs")

      self.txtDescr = QTextEdit()
      self.txtDescr.setFont(GETFONT('Fixed', 9))
      w,h = tightSizeNChar(self, 80)
      self.txtDescr.setMinimumWidth(w)
      self.txtDescr.setMinimumHeight(int(2.5*h))

      self.btnCancel = QPushButton(self.tr('Close'))
      self.btnbox = QDialogButtonBox()
      self.btnbox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self, SLOT('reject()'))

      layout = QGridLayout()
      i = -1

      i += 1
      layout.addWidget(lblTopDescr,      i,0, 1,2)

      i += 1
      layout.addWidget(lblDescr,         i,0, 1,2)

      i += 1
      layout.addWidget(frmBackup,        i,0, 1,2)

      i += 1
      layout.addWidget(HLINE(),          i,0, 1,2)

      i += 1
      layout.addWidget(self.btnbox,      i,0, 1,2)

      self.setLayout(layout)
      self.setWindowTitle(self.tr('Inconsistent Wallet'))
      self.setWindowIcon(QIcon(self.main.iconfile))

   #############################################################################
   def createZipfile(self, zfilePath=None, forceIncludeAllData=False):
      """
      If not forceIncludeAllData, then we will exclude wallet file and/or
      regular logs, depending on the user's checkbox selection.   For making
      a user backup, we always want to include everything, regardless of
      that selection.
      """

      # Should we include wallet files from logs directory?
      includeWlt = self.chkIncludeWOW.isChecked()
      includeReg = self.chkIncludeReg.isChecked()

      # Set to default save path if needed
      if zfilePath is None:
         zfilePath = os.path.join(ARMORY_HOME_DIR, 'wallet_analyze_logs.zip')

      # Remove a previous copy
      if os.path.exists(zfilePath):
         os.remove(zfilePath)

      LOGINFO('Creating archive: %s', zfilePath)
      zfile = ZipFile(zfilePath, 'w', ZIP_DEFLATED)

      # Iterate over all log directories (usually one)
      for wltID,logDir in self.logPathList:
         for fn in os.listdir(logDir):
            fullpath = os.path.join(logDir, fn)

            # If multiple dirs, will see duplicate armorylogs and multipliers
            if not os.path.isfile(fullpath):
               continue


            if not forceIncludeAllData:
               # Exclude any wallet files if the checkbox was not checked
               if not includeWlt and os.path.getsize(fullpath) >= 8:
                  # Don't exclude based on file extension, check leading bytes
                  with open(fullpath, 'rb') as tempopen:
                     if tempopen.read(8) == '\xbaWALLET\x00':
                        continue

               # Exclude regular logs as well, if desired
               if not includeReg and fn in ['armorylog.txt', 'armorycpplog.txt', 'dbLog.txt']:
                  continue


            # If we got here, add file to archive
            parentDir = os.path.basename(logDir)
            archiveName = '%s_%s_%s' % (wltID, parentDir, fn)
            LOGINFO('   Adding %s to archive' % archiveName)
            zfile.write(fullpath, archiveName)

      zfile.close()

      return zfilePath


   #############################################################################
   def doBackupLogs(self):
      saveTo = self.main.getFileSave(ffilter=['Zip files (*.zip)'],
                                     defaultFilename='wallet_analyze_logs.zip')
      if not saveTo:
         QMessageBox.critical(self, self.tr("Not saved"), self.tr(
            'You canceled the backup operation.  No backup was made.'),
            QMessageBox.Ok)
         return

      try:
         self.createZipfile(saveTo, forceIncludeAllData=True)
         QMessageBox.information(self, self.tr('Success'), self.tr(
            'The wallet logs were successfully saved to the following'
            'location:'
            '<br><br>'
            '%s'
            '<br><br>'
            'It is still important to complete the rest of this form'
            'and submit the data to the Armory team for review!' % saveTo), QMessageBox.Ok)

      except:
         LOGEXCEPT('Failed to create zip file')
         QMessageBox.warning(self, self.tr('Save Failed'), self.tr('There was an '
            'error saving a copy of your log files'), QMessageBox.Ok)




################################################################################
class DlgNewWallet(ArmoryDialog):

   def __init__(self, parent=None, main=None, initLabel=''):
      super(DlgNewWallet, self).__init__(parent, main)


      self.selectedImport = False

      # Options for creating a new wallet
      lblDlgDescr = QRichLabel(self.tr(
         'Create a new wallet for managing your funds.<br> '
         'The name and description can be changed at any time.'))
      lblDlgDescr.setWordWrap(True)

      self.edtName = QLineEdit()
      self.edtName.setMaxLength(32)
      self.edtName.setText(initLabel)
      lblName = QLabel("Wallet &name:")
      lblName.setBuddy(self.edtName)


      self.edtDescr = QTextEdit()
      self.edtDescr.setMaximumHeight(75)
      lblDescr = QLabel("Wallet &description:")
      lblDescr.setAlignment(Qt.AlignVCenter)
      lblDescr.setBuddy(self.edtDescr)

      buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | \
                                   QDialogButtonBox.Cancel)



      # Advanced Encryption Options
      lblComputeDescr = QLabel(self.tr(
                  'Armory will test your system\'s speed to determine the most '
                  'challenging encryption settings that can be performed '
                  'in a given amount of time.  High settings make it much harder '
                  'for someone to guess your passphrase.  This is used for all '
                  'encrypted wallets, but the default parameters can be changed below.\n'))
      lblComputeDescr.setWordWrap(True)
      timeDescrTip = self.main.createToolTipWidget(self.tr(
                  'This is the amount of time it will take for your computer '
                  'to unlock your wallet after you enter your passphrase. '
                  '(the actual time used will be less than the specified '
                  'time, but more than one half of it).'))


      # Set maximum compute time
      self.edtComputeTime = QLineEdit()
      self.edtComputeTime.setText('250 ms')
      self.edtComputeTime.setMaxLength(12)
      lblComputeTime = QLabel('Target compute &time (s, ms):')
      memDescrTip = self.main.createToolTipWidget(self.tr(
                  'This is the <b>maximum</b> memory that will be '
                  'used as part of the encryption process.  The actual value used '
                  'may be lower, depending on your system\'s speed.  If a '
                  'low value is chosen, Armory will compensate by chaining '
                  'together more calculations to meet the target time.  High '
                  'memory target will make GPU-acceleration useless for '
                  'guessing your passphrase.'))
      lblComputeTime.setBuddy(self.edtComputeTime)


      # Set maximum memory usage
      self.edtComputeMem = QLineEdit()
      self.edtComputeMem.setText('32.0 MB')
      self.edtComputeMem.setMaxLength(12)
      lblComputeMem = QLabel(self.tr('Max &memory usage (kB, MB):'))
      lblComputeMem.setBuddy(self.edtComputeMem)

      self.edtComputeTime.setMaximumWidth(tightSizeNChar(self, 20)[0])
      self.edtComputeMem.setMaximumWidth(tightSizeNChar(self, 20)[0])

      # Fork watching-only wallet
      cryptoLayout = QGridLayout()
      cryptoLayout.addWidget(lblComputeDescr, 0, 0, 1, 3)

      cryptoLayout.addWidget(timeDescrTip, 1, 0, 1, 1)
      cryptoLayout.addWidget(lblComputeTime, 1, 1, 1, 1)
      cryptoLayout.addWidget(self.edtComputeTime, 1, 2, 1, 1)

      cryptoLayout.addWidget(memDescrTip, 2, 0, 1, 1)
      cryptoLayout.addWidget(lblComputeMem, 2, 1, 1, 1)
      cryptoLayout.addWidget(self.edtComputeMem, 2, 2, 1, 1)

      self.cryptoFrame = QFrame()
      self.cryptoFrame.setFrameStyle(STYLE_SUNKEN)
      self.cryptoFrame.setLayout(cryptoLayout)
      self.cryptoFrame.setVisible(False)

      self.chkUseCrypto = QCheckBox(self.tr("Use wallet &encryption"))
      self.chkUseCrypto.setChecked(True)
      usecryptoTooltip = self.main.createToolTipWidget(self.tr(
                  'Encryption prevents anyone who accesses your computer '
                  'or wallet file from being able to spend your money, as '
                  'long as they do not have the passphrase. '
                  'You can choose to encrypt your wallet at a later time '
                  'through the wallet properties dialog by double clicking '
                  'the wallet on the dashboard.'))

      # For a new wallet, the user may want to print out a paper backup
      self.chkPrintPaper = QCheckBox(self.tr("Print a paper-backup of this wallet"))
      self.chkPrintPaper.setChecked(True)
      paperBackupTooltip = self.main.createToolTipWidget(self.tr(
                  'A paper-backup allows you to recover your wallet/funds even '
                  'if you lose your original wallet file, any time in the future. '
                  'Because Armory uses "deterministic wallets," '
                  'a single backup when the wallet is first made is sufficient '
                  'for all future transactions (except ones to imported '
                  'addresses).\n\n'
                  'Anyone who gets hold of your paper backup will be able to spend '
                  'the money in your wallet, so please secure it appropriately.'))


      self.btnAccept = QPushButton(self.tr("Accept"))
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.btnAdvCrypto = QPushButton(self.tr("Advanced Encryption Options>>>"))
      self.btnAdvCrypto.setCheckable(True)
      self.btnbox = QDialogButtonBox()
      self.btnbox.addButton(self.btnAdvCrypto, QDialogButtonBox.ActionRole)
      self.btnbox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)
      self.btnbox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)

      self.connect(self.btnAdvCrypto, SIGNAL('toggled(bool)'), \
                   self.cryptoFrame, SLOT('setVisible(bool)'))
      self.connect(self.btnAccept, SIGNAL(CLICKED), \
                   self.verifyInputsBeforeAccept)
      self.connect(self.btnCancel, SIGNAL(CLICKED), \
                   self, SLOT('reject()'))


      self.btnImportWlt = QPushButton(self.tr("Import wallet..."))
      self.connect(self.btnImportWlt, SIGNAL("clicked()"), \
                    self.importButtonClicked)

      masterLayout = QGridLayout()
      masterLayout.addWidget(lblDlgDescr, 1, 0, 1, 2)
      # masterLayout.addWidget(self.btnImportWlt,  1, 2, 1, 1)
      masterLayout.addWidget(lblName, 2, 0, 1, 1)
      masterLayout.addWidget(self.edtName, 2, 1, 1, 2)
      masterLayout.addWidget(lblDescr, 3, 0, 1, 2)
      masterLayout.addWidget(self.edtDescr, 3, 1, 2, 2)
      masterLayout.addWidget(self.chkUseCrypto, 5, 0, 1, 1)
      masterLayout.addWidget(usecryptoTooltip, 5, 1, 1, 1)
      masterLayout.addWidget(self.chkPrintPaper, 6, 0, 1, 1)
      masterLayout.addWidget(paperBackupTooltip, 6, 1, 1, 1)
      masterLayout.addWidget(self.cryptoFrame, 8, 0, 3, 3)

      masterLayout.addWidget(self.btnbox, 11, 0, 1, 2)

      masterLayout.setVerticalSpacing(5)

      self.setLayout(masterLayout)

      self.layout().setSizeConstraint(QLayout.SetFixedSize)

      self.connect(self.chkUseCrypto, SIGNAL("clicked()"), \
                   self.cryptoFrame, SLOT("setEnabled(bool)"))

      self.setWindowTitle(self.tr('Create Armory wallet'))
      self.setWindowIcon(QIcon(self.main.iconfile))



   def importButtonClicked(self):
      self.selectedImport = True
      self.accept()

   def verifyInputsBeforeAccept(self):

      ### Confirm that the name and descr are within size limits #######
      wltName = self.edtName.text()
      wltDescr = self.edtDescr.toPlainText()
      if len(wltName) < 1:
         QMessageBox.warning(self, self.tr('Invalid wallet name'), \
                  self.tr('You must enter a name for this wallet, up to 32 characters.'), \
                  QMessageBox.Ok)
         return False

      if len(wltDescr) > 256:
         reply = QMessageBox.warning(self, self.tr('Input too long'), self.tr(
                  'The wallet description is limited to 256 characters.  Only the first '
                  '256 characters will be used.'), \
                  QMessageBox.Ok | QMessageBox.Cancel)
         if reply == QMessageBox.Ok:
            self.edtDescr.setText(wltDescr[:256])
         else:
            return False

      ### Check that the KDF inputs are well-formed ####################
      try:
         kdfT, kdfUnit = str(self.edtComputeTime.text()).strip().split(' ')
         if kdfUnit.lower() == 'ms':
            self.kdfSec = float(kdfT) / 1000.
         elif kdfUnit.lower() in ('s', 'sec', 'seconds'):
            self.kdfSec = float(kdfT)

         if not (self.kdfSec <= 20.0):
            QMessageBox.critical(self, self.tr('Invalid KDF Parameters'), self.tr(
               'Please specify a compute time no more than 20 seconds. '
               'Values above one second are usually unnecessary.'))
            return False

         kdfM, kdfUnit = str(self.edtComputeMem.text()).split(' ')
         if kdfUnit.lower() == 'mb':
            self.kdfBytes = round(float(kdfM) * (1024.0 ** 2))
         if kdfUnit.lower() == 'kb':
            self.kdfBytes = round(float(kdfM) * (1024.0))

         if not (2 ** 15 <= self.kdfBytes <= 2 ** 31):
            QMessageBox.critical(self, self.tr('Invalid KDF Parameters'), \
               self.tr('Please specify a maximum memory usage between 32 kB and 2048 MB.'))
            return False

         LOGINFO('KDF takes %0.2f seconds and %d bytes', self.kdfSec, self.kdfBytes)
      except:
         QMessageBox.critical(self, self.tr('Invalid Input'), self.tr(
            'Please specify time with units, such as '
            '"250 ms" or "2.1 s".  Specify memory as kB or MB, such as '
            '"32 MB" or "256 kB". '), QMessageBox.Ok)
         return False


      self.accept()


   def getImportWltPath(self):
      self.importFile = QFileDialog.getOpenFileName(self, self.tr('Import Wallet File'), \
          ARMORY_HOME_DIR, self.tr('Wallet files (*.wallet);; All files (*)'))
      if self.importFile:
         self.accept()


################################################################################
class DlgChangeLabels(ArmoryDialog):
   def __init__(self, currName='', currDescr='', parent=None, main=None):
      super(DlgChangeLabels, self).__init__(parent, main)

      self.edtName = QLineEdit()
      self.edtName.setMaxLength(32)
      lblName = QLabel(self.tr("Wallet &name:"))
      lblName.setBuddy(self.edtName)

      self.edtDescr = QTextEdit()
      tightHeight = tightSizeNChar(self.edtDescr, 1)[1]
      self.edtDescr.setMaximumHeight(tightHeight * 4.2)
      lblDescr = QLabel(self.tr("Wallet &description:"))
      lblDescr.setAlignment(Qt.AlignVCenter)
      lblDescr.setBuddy(self.edtDescr)

      self.edtName.setText(currName)
      self.edtDescr.setText(currDescr)

      buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | \
                                   QDialogButtonBox.Cancel)
      self.connect(buttonBox, SIGNAL('accepted()'), self.accept)
      self.connect(buttonBox, SIGNAL('rejected()'), self.reject)

      layout = QGridLayout()
      layout.addWidget(lblName, 1, 0, 1, 1)
      layout.addWidget(self.edtName, 1, 1, 1, 1)
      layout.addWidget(lblDescr, 2, 0, 1, 1)
      layout.addWidget(self.edtDescr, 2, 1, 2, 1)
      layout.addWidget(buttonBox, 4, 0, 1, 2)
      self.setLayout(layout)

      self.setWindowTitle(self.tr('Wallet Descriptions'))


   def accept(self, *args):
      if not isASCII(unicode(self.edtName.text())) or \
         not isASCII(unicode(self.edtDescr.toPlainText())):
         UnicodeErrorBox(self)
         return

      if len(str(self.edtName.text()).strip()) == 0:
         QMessageBox.critical(self, self.tr('Empty Name'), \
            self.tr('All wallets must have a name. '), QMessageBox.Ok)
         return
      super(DlgChangeLabels, self).accept(*args)

################################################################################
class LoadingDisp(ArmoryDialog):
   def __init__(self, parent, main):
      super(LoadingDisp, self).__init__(parent, main)
      layout = QGridLayout()
      self.setLayout(layout)
      self.barLoading = QProgressBar(self)
      self.barLoading.setRange(0,100)
      self.barLoading.setFormat('%p%')
      self.barLoading.setValue(0)
      layout.addWidget(self.barLoading, 0, 0, 1, 1)
      self.setWindowTitle('Loading...')
      self.setFocus()

   def setValue(self, val):
      self.barLoading.setValue(val)

#############################################################################
class DlgImportAddress(ArmoryDialog):
   def __init__(self, wlt, parent=None, main=None):
      super(DlgImportAddress, self).__init__(parent, main)

      self.wlt = wlt


      lblImportLbl = QRichLabel(self.tr('Enter:'))

      self.radioImportOne = QRadioButton(self.tr('One Key'))
      self.radioImportMany = QRadioButton(self.tr('Multiple Keys'))
      btngrp = QButtonGroup(self)
      btngrp.addButton(self.radioImportOne)
      btngrp.addButton(self.radioImportMany)
      btngrp.setExclusive(True)
      self.radioImportOne.setChecked(True)
      self.connect(self.radioImportOne, SIGNAL(CLICKED), self.clickImportCount)
      self.connect(self.radioImportMany, SIGNAL(CLICKED), self.clickImportCount)

      frmTop = makeHorizFrame([lblImportLbl, self.radioImportOne, \
                                             self.radioImportMany, STRETCH])
      self.stackedImport = QStackedWidget()

      # Set up the single-key import widget
      lblDescrOne = QRichLabel(self.tr('The key can either be imported into your wallet, '
                     'or have its available balance "swept" to another address '
                     'in your wallet.  Only import private '
                     'key data if you are absolutely sure that no one else '
                     'has access to it.  Otherwise, sweep it to get '
                     'the funds out of it.  All standard private-key formats '
                     'are supported <i>except for private keys created by '
                     'Bitcoin Core version 0.6.0 and later (compressed)</i>.'))

      lblPrivOne = QRichLabel('Private Key')
      self.edtPrivData = QLineEdit()
      self.edtPrivData.setMinimumWidth(tightSizeStr(self.edtPrivData, 'X' * 60)[0])
      privTooltip = self.main.createToolTipWidget(self.tr(
                       'Supported formats are any hexadecimal or Base58 '
                       'representation of a 32-byte private key (with or '
                       'without checksums), and mini-private-key format '
                       'used on Casascius physical bitcoins.  Private keys '
                       'that use <i>compressed</i> public keys are not yet '
                       'supported by Armory.'))

      frmMid1 = makeHorizFrame([lblPrivOne, self.edtPrivData, privTooltip])
      stkOne = makeVertFrame([HLINE(), lblDescrOne, frmMid1, STRETCH])
      self.stackedImport.addWidget(stkOne)



      # Set up the multi-Sig import widget
      lblDescrMany = QRichLabel(self.tr(
                   'Enter a list of private keys to be "swept" or imported. '
                   'All standard private-key formats are supported.'))
      lblPrivMany = QRichLabel('Private Key List')
      lblPrivMany.setAlignment(Qt.AlignTop)
      ttipPrivMany = self.main.createToolTipWidget(self.tr(
                  'One private key per line, in any standard format. '
                  'Data may be copied directly from the "Export Key Lists" '
                  'dialog (all text on a line preceding '
                  'the key data, separated by a colon, will be ignored).'))
      self.txtPrivBulk = QTextEdit()
      w, h = tightSizeStr(self.edtPrivData, 'X' * 70)
      self.txtPrivBulk.setMinimumWidth(w)
      self.txtPrivBulk.setMinimumHeight(2.2 * h)
      self.txtPrivBulk.setMaximumHeight(4.2 * h)
      frmMid = makeHorizFrame([lblPrivMany, self.txtPrivBulk, ttipPrivMany])
      stkMany = makeVertFrame([HLINE(), lblDescrMany, frmMid])
      self.stackedImport.addWidget(stkMany)


      self.chkUseSP = QCheckBox(self.tr('This is from a backup with SecurePrint\x99'))
      self.edtSecurePrint = QLineEdit()
      self.edtSecurePrint.setFont(GETFONT('Fixed',9))
      self.edtSecurePrint.setEnabled(False)
      w, h = relaxedSizeStr(self.edtSecurePrint, 'X' * 12)
      self.edtSecurePrint.setMaximumWidth(w)

      def toggleSP():
         if self.chkUseSP.isChecked():
            self.edtSecurePrint.setEnabled(True)
         else:
            self.edtSecurePrint.setEnabled(False)

      self.chkUseSP.stateChanged.connect(toggleSP)
      frmSP = makeHorizFrame([self.chkUseSP, self.edtSecurePrint, 'Stretch'])
      #frmSP.setFrameStyle(STYLE_PLAIN)


      # Set up the Import/Sweep select frame
      # # Import option
      self.radioSweep = QRadioButton(self.tr('Sweep any funds owned by these addresses '
                                      'into your wallet\n'
                                      'Select this option if someone else gave you this key'))
      self.radioImport = QRadioButton(self.tr('Import these addresses to your wallet\n'
                                      'Only select this option if you are positive '
                                      'that no one else has access to this key'))


      # # Sweep option (only available when online)
      if TheBDM.getState() == BDM_BLOCKCHAIN_READY:
         self.radioSweep = QRadioButton(self.tr('Sweep any funds owned by this address '
                                         'into your wallet\n'
                                         'Select this option if someone else gave you this key'))
         if self.wlt.watchingOnly:
            self.radioImport.setEnabled(False)
         self.radioSweep.setChecked(True)
      else:
         if TheBDM.getState() in (BDM_OFFLINE, BDM_UNINITIALIZED):
            self.radioSweep = QRadioButton(self.tr('Sweep any funds owned by this address '
                                            'into your wallet\n'
                                            '(Not available in offline mode)'))
         elif TheBDM.getState() == BDM_SCANNING:
            self.radioSweep = QRadioButton(self.tr('Sweep any funds owned by this address into your wallet'))
         self.radioImport.setChecked(True)
         self.radioSweep.setEnabled(False)


      sweepTooltip = self.main.createToolTipWidget(self.tr(
         'You should never add an untrusted key to your wallet.  By choosing this '
         'option, you are only moving the funds into your wallet, but not the key '
         'itself.  You should use this option for Casascius physical bitcoins.'))

      importTooltip = self.main.createToolTipWidget(self.tr(
         'This option will make the key part of your wallet, meaning that it '
         'can be used to securely receive future payments.  <b>Never</b> select this '
         'option for private keys that other people may have access to.'))


      # Make sure that there can only be one selection
      btngrp = QButtonGroup(self)
      btngrp.addButton(self.radioSweep)
      btngrp.addButton(self.radioImport)
      btngrp.setExclusive(True)

      frmWarn = QFrame()
      frmWarn.setFrameStyle(QFrame.Box | QFrame.Plain)
      frmWarnLayout = QGridLayout()
      frmWarnLayout.addWidget(self.radioSweep, 0, 0, 1, 1)
      frmWarnLayout.addWidget(self.radioImport, 1, 0, 1, 1)
      frmWarnLayout.addWidget(sweepTooltip, 0, 1, 1, 1)
      frmWarnLayout.addWidget(importTooltip, 1, 1, 1, 1)
      frmWarn.setLayout(frmWarnLayout)



      buttonbox = QDialogButtonBox(QDialogButtonBox.Ok | \
                                   QDialogButtonBox.Cancel)
      self.connect(buttonbox, SIGNAL('accepted()'), self.okayClicked)
      self.connect(buttonbox, SIGNAL('rejected()'), self.reject)





      layout = QVBoxLayout()
      layout.addWidget(frmTop)
      layout.addWidget(self.stackedImport)
      layout.addWidget(frmSP)
      layout.addWidget(frmWarn)
      layout.addWidget(buttonbox)

      self.setWindowTitle(self.tr('Private Key Import'))
      self.setLayout(layout)




   #############################################################################
   def clickImportCount(self):
      isOne = self.radioImportOne.isChecked()
      if isOne:
         self.stackedImport.setCurrentIndex(0)
      else:
         self.stackedImport.setCurrentIndex(1)


   #############################################################################
   def okayClicked(self):
      securePrintCode = None
      if self.chkUseSP.isChecked():
         SECPRINT = HardcodedKeyMaskParams()
         securePrintCode = str(self.edtSecurePrint.text()).strip()
         self.edtSecurePrint.setText("")

         if not checkSecurePrintCode(self, SECPRINT, securePrintCode):
            return

      if self.radioImportOne.isChecked():
         self.processUserString(securePrintCode)
      else:
         self.processMultiSig(securePrintCode)


   #############################################################################
   def processUserString(self, pwd=None):
      theStr = str(self.edtPrivData.text()).strip().replace(' ', '')
      binKeyData, addr160, addrStr = '', '', ''

      try:
         binKeyData, keyType = parsePrivateKeyData(theStr)

         if pwd:
            SECPRINT = HardcodedKeyMaskParams()
            maskKey = SECPRINT['FUNC_KDF'](pwd)
            SBDbinKeyData = SECPRINT['FUNC_UNMASK'](SecureBinaryData(binKeyData), ekey=maskKey)
            binKeyData = SBDbinKeyData.toBinStr()
            SBDbinKeyData.destroy()

         zeroes32 = '\x00'*32
         if binKeyData==zeroes32:
            QMessageBox.critical(self, self.tr('Invalid Private Key'), self.tr(
               'You entered all zeros.  This is not a valid private key!'),
               QMessageBox.Ok)
            LOGERROR('User attempted import of private key 0x00*32')
            return

         if binary_to_int(binKeyData, BIGENDIAN) >= SECP256K1_ORDER:
            QMessageBox.critical(self, self.tr('Invalid Private Key'), self.tr(
               'The private key you have entered is actually not valid '
               'for the elliptic curve used by Bitcoin (secp256k1). '
               'Almost any 64-character hex is a valid private key '
               '<b>except</b> for those greater than: '
               '<br><br>'
               'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
               '<br><br>'
               'Please try a different private key.'), QMessageBox.Ok)
            LOGERROR('User attempted import of invalid private key!')
            return

         addr160 = convertKeyDataToAddress(privKey=binKeyData)
         addrStr = hash160_to_addrStr(addr160)

      except InvalidHashError as e:
         QMessageBox.warning(self, self.tr('Entry Error'), self.tr(
            'The private key data you supplied appears to '
            'contain a consistency check.  This consistency '
            'check failed.  Please verify you entered the '
            'key data correctly.'), QMessageBox.Ok)
         LOGERROR('Private key consistency check failed.')
         return
      except BadInputError as e:
         QMessageBox.critical(self, self.tr('Invalid Data'), self.tr('Something went terribly '
            'wrong!  (key data unrecognized)'), QMessageBox.Ok)
         LOGERROR('Unrecognized key data!')
         return
      except CompressedKeyError as e:
         QMessageBox.critical(self, self.tr('Unsupported key type'), self.tr('You entered a key '
            'for an address that uses a compressed public key, usually produced '
            'in Bitcoin Core/bitcoind wallets created after version 0.6.0.  Armory '
            'does not yet support this key type.'))
         LOGERROR('Compressed key data recognized but not supported')
         return
      except:
         QMessageBox.critical(self, self.tr('Error Processing Key'), self.tr(
            'There was an error processing the private key data. '
            'Please check that you entered it correctly'), QMessageBox.Ok)
         LOGEXCEPT('Error processing the private key data')
         return



      if not 'mini' in keyType.lower():
         reply = QMessageBox.question(self, self.tr('Verify Address'), self.tr(
               'The key data you entered appears to correspond to '
               'the following Bitcoin address:\n\n %s '
               '\n\nIs this the correct address?' % addrStr),
               QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
         if reply == QMessageBox.Cancel:
            return
         else:
            if reply == QMessageBox.No:
               binKeyData = binary_switchEndian(binKeyData)
               addr160 = convertKeyDataToAddress(privKey=binKeyData)
               addrStr = hash160_to_addrStr(addr160)
               reply = QMessageBox.question(self, self.tr('Try Again'), self.tr(
                     'It is possible that the key was supplied in a '
                     '"reversed" form.  When the data you provide is '
                     'reversed, the following address is obtained:\n\n '
                     '%s \n\nIs this the correct address?' % addrStr), \
                     QMessageBox.Yes | QMessageBox.No)
               if reply == QMessageBox.No:
                  binKeyData = ''
                  return

      # Finally, let's add the address to the wallet, or sweep the funds
      if self.radioSweep.isChecked():
         if self.wlt.hasAddr(addr160):
            result = QMessageBox.warning(self, 'Duplicate Address', \
            'The address you are trying to sweep is already part of this '
            'wallet.  You can still sweep it to a new address, but it will '
            'have no effect on your overall balance (in fact, it might be '
            'negative if you have to pay a fee for the transfer)\n\n'
            'Do you still want to sweep this key?', \
            QMessageBox.Yes | QMessageBox.Cancel)
            if not result == QMessageBox.Yes:
               return

         else:
            wltID = self.main.getWalletForAddrHash(addr160)
            if not wltID == '':
               addr = self.main.walletMap[wltID].addrMap[addr160]
               typ = 'Imported' if addr.chainIndex == -2 else 'Permanent'
               msg = ('The key you entered is already part of another wallet you '
                      'are maintaining:'
                     '<br><br>'
                     '<b>Address</b>: ' + addrStr + '<br>'
                     '<b>Wallet ID</b>: ' + wltID + '<br>'
                     '<b>Wallet Name</b>: ' + self.main.walletMap[wltID].labelName + '<br>'
                     '<b>Address Type</b>: ' + typ +
                     '<br><br>'
                     'The sweep operation will simply move bitcoins out of the wallet '
                     'above into this wallet.  If the network charges a fee for this '
                     'transaction, you balance will be reduced by that much.')
               result = QMessageBox.warning(self, 'Duplicate Address', msg, \
                     QMessageBox.Ok | QMessageBox.Cancel)
               if not result == QMessageBox.Ok:
                  return

         # Create the address object for the addr to be swept
         sweepAddrList = []
         sweepAddrList.append(PyBtcAddress().createFromPlainKeyData(SecureBinaryData(binKeyData)))
         self.wlt.sweepAddressList(sweepAddrList, self.main)

         # Regardless of the user confirmation, we're done here
         self.accept()

      elif self.radioImport.isChecked():
         if self.wlt.hasAddr(addr160):
            QMessageBox.critical(self, 'Duplicate Address', \
            'The address you are trying to import is already part of your '
            'wallet.  Address cannot be imported', QMessageBox.Ok)
            return

         wltID = self.main.getWalletForAddrHash(addr160)
         if not wltID == '':
            addr = self.main.walletMap[wltID].addrMap[addr160]
            typ = 'Imported' if addr.chainIndex == -2 else 'Permanent'
            msg = self.tr('The key you entered is already part of another wallet you own:'
                   '<br><br>'
                   '<b>Address</b>: ' + addrStr + '<br>'
                   '<b>Wallet ID</b>: ' + wltID + '<br>'
                   '<b>Wallet Name</b>: ' + self.main.walletMap[wltID].labelName + '<br>'
                   '<b>Address Type</b>: ' + typ +
                   '<br><br>'
                   'Armory cannot properly display balances or create transactions '
                   'when the same address is in multiple wallets at once.  ')
            if typ == 'Imported':
               QMessageBox.critical(self, 'Duplicate Addresses', \
                  msg + 'To import this address to this wallet, please remove it from the '
                  'other wallet, then try the import operation again.', QMessageBox.Ok)
            else:
               QMessageBox.critical(self, 'Duplicate Addresses', \
                  msg + 'Additionally, this address is mathematically linked '
                  'to its wallet (permanently) and cannot be deleted or '
                  'imported to any other wallet.  The import operation cannot '
                  'continue.', QMessageBox.Ok)
            return

         if self.wlt.useEncryption and self.wlt.isLocked:
            dlg = DlgUnlockWallet(self.wlt, self, self.main, 'Encrypt New Address')
            if not dlg.exec_():
               reply = QMessageBox.critical(self, 'Wallet is locked',
                  'New private key data cannot be imported unless the wallet is '
                  'unlocked.  Please try again when you have the passphrase.', \
                  QMessageBox.Ok)
               return


         self.wlt.importExternalAddressData(privKey=SecureBinaryData(binKeyData))
         self.main.statusBar().showMessage('Successful import of address ' \
                                 + addrStr + ' into wallet ' + self.wlt.uniqueIDB58, 10000)

      try:
         self.parent.wltAddrModel.reset()
      except:
         pass

      self.accept()
      self.main.loadCppWallets()


   #############################################################################
   def processMultiSig(self, pwd=None):
      thisWltID = self.wlt.uniqueIDB58

      inputText = str(self.txtPrivBulk.toPlainText())
      inputLines = [s.strip().replace(' ', '') for s in inputText.split('\n')]
      binKeyData, addr160, addrStr = '', '', ''

      if pwd:
         SECPRINT = HardcodedKeyMaskParams()
         maskKey = SECPRINT['FUNC_KDF'](pwd)

      privKeyList = []
      addrSet = set()
      nLines = 0
      for line in inputLines:
         if 'PublicX' in line or 'PublicY' in line:
            continue
         lineend = line.split(':')[-1]
         try:
            nLines += 1
            binKeyData = SecureBinaryData(parsePrivateKeyData(lineend)[0])
            if pwd: binKeyData = SECPRINT['FUNC_UNMASK'](binKeyData, ekey=maskKey)

            addr160 = convertKeyDataToAddress(privKey=binKeyData.toBinStr())
            if not addr160 in addrSet:
               addrSet.add(addr160)
               addrStr = hash160_to_addrStr(addr160)
               privKeyList.append([addr160, addrStr, binKeyData])
         except:
            LOGWARN('Key line skipped, probably not a private key (key not shown for security)')
            continue

      if len(privKeyList) == 0:
         if nLines > 1:
            QMessageBox.critical(self, 'Invalid Data', \
               'No valid private key data was entered.', QMessageBox.Ok)
         return

      # privKeyList now contains:
      #  [ [A160, AddrStr, Priv],
      #    [A160, AddrStr, Priv],
      #    [A160, AddrStr, Priv], ... ]
      # Determine if any addresses are already part of some wallets
      addr_to_wltID = lambda a: self.main.getWalletForAddrHash(a)
      allWltList = [ [addr_to_wltID(k[0]), k[1]] for k in privKeyList]
      # allWltList is now [ [WltID, AddrStr], [WltID, AddrStr], ... ]


      if self.radioSweep.isChecked():
         ##### SWEEPING #####
         dupeWltList = filter(lambda a: len(a[0]) > 0, allWltList)
         if len(dupeWltList) > 0:
            reply = QMessageBox.critical(self, self.tr('Duplicate Addresses!'), self.tr(
               'You are attempting to sweep %d addresses, but %d of them '
               'are already part of existing wallets.  That means that some or '
               'all of the bitcoins you sweep may already be owned by you. '
               '<br><br>'
               'Would you like to continue anyway?' % (len(allWltList), len(dupeWltList))), \
               QMessageBox.Ok | QMessageBox.Cancel)
            if reply == QMessageBox.Cancel:
               return


         #create address less to sweep
         addrList = []
         for addr160, addrStr, SecurePriv in privKeyList:
            pyAddr = PyBtcAddress().createFromPlainKeyData(SecurePriv)
            addrList.append(pyAddr)

         #get PyBtcWallet object
         self.wlt.sweepAddressList(addrList, self.main)

      else:
         ##### IMPORTING #####

         # allWltList is [ [WltID, AddrStr], [WltID, AddrStr], ... ]

         # Warn about addresses that would be duplicates.
         # Addresses already in the selected wallet will simply be skipped, no
         # need to do anything about that -- only addresses that would appear in
         # two wlts if we were to continue.
         dupeWltList = filter(lambda a: (len(a[0]) > 0 and a[0] != thisWltID), allWltList)
         if len(dupeWltList) > 0:
            dupeAddrStrList = [d[1] for d in dupeWltList]
            dlg = DlgDuplicateAddr(dupeAddrStrList, self, self.main)

            if not dlg.exec_():
               return

            privKeyList = filter(lambda x: (x[1] not in dupeAddrStrList), privKeyList)


         # Confirm import
         addrStrList = [k[1] for k in privKeyList]
         dlg = DlgConfirmBulkImport(addrStrList, thisWltID, self, self.main)
         if not dlg.exec_():
            return

         if self.wlt.useEncryption and self.wlt.isLocked:
            # Target wallet is encrypted...
            unlockdlg = DlgUnlockWallet(self.wlt, self, self.main, self.tr('Unlock Wallet to Import'))
            if not unlockdlg.exec_():
               QMessageBox.critical(self, self.tr('Wallet is Locked'), self.tr(
                  'Cannot import private keys without unlocking wallet!'), \
                  QMessageBox.Ok)
               return


         nTotal = 0
         nImport = 0
         nAlready = 0
         nError = 0
         privKeyToImport = []
         for addr160, addrStr, sbdKey in privKeyList:
            nTotal += 1
            try:
               if not self.main.getWalletForAddrHash(addr160) == thisWltID:
                  privKeyToImport.append([sbdKey, addr160])
                  nImport += 1
               else:
                  nAlready += 1
            except Exception as msg:
               # print '***ERROR importing:', addrStr
               # print '         Error Msg:', msg
               # nError += 1
               LOGERROR('Problem importing: %s: %s', addrStr, msg)
               raise

         self.wlt.importExternalAddressBatch(privKeyToImport)

         if nAlready == nTotal:
            MsgBoxCustom(MSGBOX.Warning, self.tr('Nothing Imported!'), self.tr('All addresses '
               'chosen to be imported are already part of this wallet. '
               'Nothing was imported.'))
            return
         elif nImport == 0 and nTotal > 0:
            MsgBoxCustom(MSGBOX.Error, self.tr('Error!'), self.tr(
               'Failed:  No addresses could be imported. '
               'Please check the logfile (ArmoryQt.exe.log) or the console output '
               'for information about why it failed.'))
            return
         else:
            if nError == 0:
               if nAlready > 0:
                  MsgBoxCustom(MSGBOX.Good, self.tr('Success!'), self.tr(
                     'Success: %d private keys were imported into your wallet. '
                     '<br><br>'
                     'The other %d private keys were skipped, because they were '
                     'already part of your wallet.' % (nImport, nAlready)))
               else:
                  MsgBoxCustom(MSGBOX.Good, self.tr('Success!'), self.tr(
                     'Success: %d private keys were imported into your wallet.' % nImport))
            else:
               MsgBoxCustom(MSGBOX.Warning, self.tr('Partial Success!'), self.tr(
                  '%d private keys were imported into your wallet, but there were '
                  'also %d addresses that could not be imported (see console '
                  'or log file for more information).  It is safe to try this '
                  'operation again: all addresses previously imported will be '
                  'skipped.' % (nImport, nError)))

      try:
         self.parent.wltAddrModel.reset()
      except AttributeError:
         pass

      self.accept()
      self.main.loadCppWallets()


#############################################################################
class DlgVerifySweep(ArmoryDialog):
   def __init__(self, inputStr, outputStr, outVal, fee, parent=None, main=None):
      super(DlgVerifySweep, self).__init__(parent, main)


      lblQuestion = QRichLabel(self.tr(
            'You are about to <i>sweep</i> all funds from the specified address '
            'to your wallet.  Please confirm the action:'))


      outStr = coin2str(outVal, maxZeros=2)
      feeStr = ('') if (fee == 0) else (self.tr('(Fee: %s)' % coin2str(fee, maxZeros=0)))

      frm = QFrame()
      frm.setFrameStyle(STYLE_RAISED)
      frmLayout = QGridLayout()
      # frmLayout.addWidget(QRichLabel('Funds will be <i>swept</i>...'), 0,0, 1,2)
      frmLayout.addWidget(QRichLabel(self.tr('      From %s' % inputStr), doWrap=False), 1, 0, 1, 2)
      frmLayout.addWidget(QRichLabel(self.tr('      To %s' % outputStr), doWrap=False), 2, 0, 1, 2)
      frmLayout.addWidget(QRichLabel(self.tr('      Total <b>%s</b> BTC %s' % (outStr, feeStr)), doWrap=False), 3, 0, 1, 2)
      frm.setLayout(frmLayout)

      lblFinalConfirm = QLabel(self.tr('Are you sure you want to execute this transaction?'))

      bbox = QDialogButtonBox(QDialogButtonBox.Ok | \
                              QDialogButtonBox.Cancel)
      self.connect(bbox, SIGNAL('accepted()'), self.accept)
      self.connect(bbox, SIGNAL('rejected()'), self.reject)

      lblWarnImg = QLabel()
      lblWarnImg.setPixmap(QPixmap('./img/MsgBox_warning48.png'))
      lblWarnImg.setAlignment(Qt.AlignHCenter | Qt.AlignTop)

      layout = QHBoxLayout()
      layout.addWidget(lblWarnImg)
      layout.addWidget(makeLayoutFrame(VERTICAL, [lblQuestion, frm, lblFinalConfirm, bbox]))
      self.setLayout(layout)

      self.setWindowTitle(self.tr('Confirm Sweep'))




##############################################################################
class DlgConfirmBulkImport(ArmoryDialog):
   def __init__(self, addrList, wltID, parent=None, main=None):
      super(DlgConfirmBulkImport, self).__init__(parent, main)

      self.wltID = wltID

      if len(addrList) == 0:
         QMessageBox.warning(self, self.tr('No Addresses to Import'), self.tr(
           'There are no addresses to import!'), QMessageBox.Ok)
         self.reject()


      walletDescr = self.tr('a new wallet')
      if not wltID == None:
         wlt = self.main.walletMap[wltID]
         walletDescr = self.tr('wallet, <b>%s</b> (%s)' % (wltID, wlt.labelName))
      lblDescr = QRichLabel(self.tr(
         'You are about to import <b>%d</b> addresses into %s.<br><br> '
         'The following is a list of addresses to be imported:' % (len(addrList), walletDescr)))

      fnt = GETFONT('Fixed', 10)
      w, h = tightSizeNChar(fnt, 100)
      txtDispAddr = QTextEdit()
      txtDispAddr.setFont(fnt)
      txtDispAddr.setReadOnly(True)
      txtDispAddr.setMinimumWidth(min(w, 700))
      txtDispAddr.setMinimumHeight(16.2 * h)
      txtDispAddr.setText('\n'.join(addrList))

      buttonBox = QDialogButtonBox()
      self.btnAccept = QPushButton(self.tr("Import"))
      self.btnReject = QPushButton(self.tr("Cancel"))
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.accept)
      self.connect(self.btnReject, SIGNAL(CLICKED), self.reject)
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnReject, QDialogButtonBox.RejectRole)

      dlgLayout = QVBoxLayout()
      dlgLayout.addWidget(lblDescr)
      dlgLayout.addWidget(txtDispAddr)
      dlgLayout.addWidget(buttonBox)
      self.setLayout(dlgLayout)

      self.setWindowTitle(self.tr('Confirm Import'))
      self.setWindowIcon(QIcon(self.main.iconfile))


#############################################################################
class DlgDuplicateAddr(ArmoryDialog):
   def __init__(self, addrList, wlt, parent=None, main=None):
      super(DlgDuplicateAddr, self).__init__(parent, main)

      self.wlt = wlt
      self.doCancel = True
      self.newOnly = False

      if len(addrList) == 0:
         QMessageBox.warning(self, self.tr('No Addresses to Import'), \
           self.tr('There are no addresses to import!'), QMessageBox.Ok)
         self.reject()

      lblDescr = QRichLabel(self.tr(
         '<font color=%s>Duplicate addresses detected!</font> The following '
         'addresses already exist in other Armory wallets:' % htmlColor('TextWarn')))

      fnt = GETFONT('Fixed', 8)
      w, h = tightSizeNChar(fnt, 50)
      txtDispAddr = QTextEdit()
      txtDispAddr.setFont(fnt)
      txtDispAddr.setReadOnly(True)
      txtDispAddr.setMinimumWidth(w)
      txtDispAddr.setMinimumHeight(8.2 * h)
      txtDispAddr.setText('\n'.join(addrList))

      lblWarn = QRichLabel(self.tr(
         'Duplicate addresses cannot be imported.  If you continue, '
         'the addresses above will be ignored, and only new addresses '
         'will be imported to this wallet.'))

      buttonBox = QDialogButtonBox()
      self.btnContinue = QPushButton(self.tr("Continue"))
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.connect(self.btnContinue, SIGNAL(CLICKED), self.accept)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      buttonBox.addButton(self.btnContinue, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)

      dlgLayout = QVBoxLayout()
      dlgLayout.addWidget(lblDescr)
      dlgLayout.addWidget(txtDispAddr)
      dlgLayout.addWidget(lblWarn)
      dlgLayout.addWidget(buttonBox)
      self.setLayout(dlgLayout)

      self.setWindowTitle(self.tr('Duplicate Addresses'))




#############################################################################
class DlgAddressInfo(ArmoryDialog):
   def __init__(self, wlt, addrObj, parent=None, main=None, mode=None):
      super(DlgAddressInfo, self).__init__(parent, main)

      self.wlt = wlt
      self.addrObj = addrObj
      addr160 = addrObj.getPrefixedAddr()

      self.ledgerTable = []

      self.mode = mode
      if mode == None:
         if main == None:
            self.mode = USERMODE.Standard
         else:
            self.mode = self.main.usermode


      dlgLayout = QGridLayout()
      addrStr = addrObj.getAddressString()

      frmInfo = QFrame()
      frmInfo.setFrameStyle(STYLE_RAISED)
      frmInfoLayout = QGridLayout()

      lbls = []

      # Hash160
      if mode in (USERMODE.Advanced, USERMODE.Expert):
         bin25 = base58_to_binary(addrStr)
         lbls.append([])
         lbls[-1].append(self.main.createToolTipWidget(\
                   self.tr('This is the computer-readable form of the address')))
         lbls[-1].append(QRichLabel(self.tr('<b>Public Key Hash</b>')))
         h160Str = binary_to_hex(bin25[1:-4])
         if mode == USERMODE.Expert:
            network = binary_to_hex(bin25[:1    ])
            hash160 = binary_to_hex(bin25[ 1:-4 ])
            addrChk = binary_to_hex(bin25[   -4:])
            h160Str += self.tr('%s (Network: %s / Checksum: %s)' % (hash160, network, addrChk))
         lbls[-1].append(QLabel(h160Str))



      lbls.append([])
      lbls[-1].append(QLabel(''))
      lbls[-1].append(QRichLabel(self.tr('<b>Wallet:</b>')))
      lbls[-1].append(QLabel(self.wlt.labelName))

      lbls.append([])
      lbls[-1].append(QLabel(''))
      lbls[-1].append(QRichLabel(self.tr('<b>Address:</b>')))
      lbls[-1].append(QLabel(addrStr))


      lbls.append([])
      lbls[-1].append(self.main.createToolTipWidget(self.tr(
         'Address type is either <i>Imported</i> or <i>Permanent</i>. '
         '<i>Permanent</i> '
         'addresses are part of the base wallet, and are protected by printed '
         'paper backups, regardless of when the backup was performed. '
         'Imported addresses are only protected by digital backups, or manually '
         'printing the individual keys list, and only if the wallet was backed up '
         '<i>after</i> the keys were imported.')))

      lbls[-1].append(QRichLabel(self.tr('<b>Address Type:</b>')))
      if self.addrObj.chainIndex == -2:
         lbls[-1].append(QLabel(self.tr('Imported')))
      else:
         lbls[-1].append(QLabel(self.tr('Permanent')))

      # TODO: fix for BIP-32
      lbls.append([])
      lbls[-1].append(self.main.createToolTipWidget(
            self.tr('The index of this address within the wallet.')))
      lbls[-1].append(QRichLabel(self.tr('<b>Index:</b>')))
      if self.addrObj.chainIndex > -1:
         lbls[-1].append(QLabel(str(self.addrObj.chainIndex+1)))
      else:
         lbls[-1].append(QLabel(self.tr("Imported")))


      # Current Balance of address
      lbls.append([])
      lbls[-1].append(self.main.createToolTipWidget(self.tr(
            'This is the current <i>spendable</i> balance of this address, '
            'not including zero-confirmation transactions from others.')))
      lbls[-1].append(QRichLabel(self.tr('<b>Current Balance</b>')))
      try:
         balCoin = addrObj.getSpendableBalance()
         balStr = coin2str(balCoin, maxZeros=1)
         if balCoin > 0:
            goodColor = htmlColor('MoneyPos')
            lbls[-1].append(QRichLabel(\
               '<font color=' + goodColor + '>' + balStr.strip() + '</font> BTC'))
         else:
            lbls[-1].append(QRichLabel(balStr.strip() + ' BTC'))
      except:
         lbls[-1].append(QRichLabel("N/A"))


      lbls.append([])
      lbls[-1].append(QLabel(''))
      lbls[-1].append(QRichLabel(self.tr('<b>Comment:</b>')))
      if self.addrObj.chainIndex > -1:
         lbls[-1].append(QLabel(str(wlt.commentsMap[addr160]) if addr160 in wlt.commentsMap else ''))
      else:
         lbls[-1].append(QLabel(''))

      lbls.append([])
      lbls[-1].append(self.main.createToolTipWidget(
            self.tr('The total number of transactions in which this address was involved')))
      lbls[-1].append(QRichLabel(self.tr('<b>Transaction Count:</b>')))
      #lbls[-1].append(QLabel(str(len(txHashes))))
      try:
         txnCount = self.addrObj.getTxioCount()
         lbls[-1].append(QLabel(str(txnCount)))
      except:
         lbls[-1].append(QLabel("N/A"))


      for i in range(len(lbls)):
         for j in range(1, 3):
            lbls[i][j].setTextInteractionFlags(Qt.TextSelectableByMouse | \
                                                Qt.TextSelectableByKeyboard)
         for j in range(3):
            if (i, j) == (0, 2):
               frmInfoLayout.addWidget(lbls[i][j], i, j, 1, 2)
            else:
               frmInfoLayout.addWidget(lbls[i][j], i, j, 1, 1)

      qrcode = QRCodeWidget(addrStr, 80, parent=self)
      qrlbl = QRichLabel(self.tr('<font size=2>Double-click to expand</font>'))
      frmqr = makeVertFrame([qrcode, qrlbl])

      frmInfoLayout.addWidget(frmqr, 0, 4, len(lbls), 1)
      frmInfo.setLayout(frmInfoLayout)
      dlgLayout.addWidget(frmInfo, 0, 0, 1, 1)


      # ## Set up the address ledger
      self.ledgerModel = LedgerDispModelSimple(self.ledgerTable, self, self.main)
      delegateId = TheBridge.getLedgerDelegateIdForScrAddr(\
         self.wlt.uniqueIDB58, addr160)
      self.ledgerModel.setLedgerDelegateId(delegateId)

      def ledgerToTableScrAddr(ledger):
         return self.main.convertLedgerToTable(ledger, \
                                               wltIDIn=self.wlt.uniqueIDB58)
      self.ledgerModel.setConvertLedgerMethod(ledgerToTableScrAddr)

      self.frmLedgUpDown = QFrame()
      #self.ledgerView = ArmoryTableView(self, self.main, self.frmLedgUpDown)
      self.ledgerView = QTableView(self.main)
      self.ledgerView.setModel(self.ledgerModel)
      self.ledgerView.setItemDelegate(LedgerDispDelegate(self))

      self.ledgerView.hideColumn(LEDGERCOLS.isOther)
      self.ledgerView.hideColumn(LEDGERCOLS.UnixTime)
      self.ledgerView.hideColumn(LEDGERCOLS.WltID)
      self.ledgerView.hideColumn(LEDGERCOLS.WltName)
      self.ledgerView.hideColumn(LEDGERCOLS.TxHash)
      self.ledgerView.hideColumn(LEDGERCOLS.isCoinbase)
      self.ledgerView.hideColumn(LEDGERCOLS.toSelf)
      self.ledgerView.hideColumn(LEDGERCOLS.optInRBF)

      self.ledgerView.setSelectionBehavior(QTableView.SelectRows)
      self.ledgerView.setSelectionMode(QTableView.SingleSelection)
      self.ledgerView.horizontalHeader().setStretchLastSection(True)
      self.ledgerView.verticalHeader().setDefaultSectionSize(20)
      self.ledgerView.verticalHeader().hide()
      self.ledgerView.setMinimumWidth(650)

      dateWidth = tightSizeStr(self.ledgerView, '_9999-Dec-99 99:99pm__')[0]
      initialColResize(self.ledgerView, [20, 0, dateWidth, 72, 0, 0.45, 0.3])

      ttipLedger = self.main.createToolTipWidget(self.tr(
            'Unlike the wallet-level ledger, this table shows every '
            'transaction <i>input</i> and <i>output</i> as a separate entry. '
            'Therefore, there may be multiple entries for a single transaction, '
            'which will happen if money was sent-to-self (explicitly, or as '
            'the change-back-to-self address).'))
      lblLedger = QLabel(self.tr('All Address Activity:'))

      lblstrip = makeLayoutFrame(HORIZONTAL, [lblLedger, ttipLedger, STRETCH])
      bottomRow = makeHorizFrame([STRETCH, self.frmLedgUpDown, STRETCH], condenseMargins=True)
      frmLedger = makeLayoutFrame(VERTICAL, [lblstrip, self.ledgerView, bottomRow])
      dlgLayout.addWidget(frmLedger, 1, 0, 1, 1)


      # Now add the right-hand-side option buttons
      lbtnCopyAddr = QLabelButton(self.tr('Copy Address to Clipboard'))
      lbtnViewKeys = QLabelButton(self.tr('View Address Keys'))
      # lbtnSweepA   = QLabelButton('Sweep Address')
      lbtnDelete = QLabelButton(self.tr('Delete Address'))

      lbtnCopyAddr.linkActivated.connect(self.copyAddr)
      lbtnViewKeys.linkActivated.connect(self.viewKeys)
      lbtnDelete.linkActivated.connect(self.deleteAddr)

      optFrame = QFrame()
      optFrame.setFrameStyle(STYLE_SUNKEN)

      hasPriv = self.addrObj.hasPrivKey
      adv = (self.main.usermode in (USERMODE.Advanced, USERMODE.Expert))
      watch = self.wlt.watchingOnly


      self.lblCopied = QRichLabel('')
      self.lblCopied.setMinimumHeight(tightSizeNChar(self.lblCopied, 1)[1])

      self.lblLedgerWarning = QRichLabel(self.tr(
         'NOTE:  The ledger shows each transaction <i><b>input</b></i> and '
         '<i><b>output</b></i> for this address.  There are typically many '
         'inputs and outputs for each transaction, therefore the entries '
         'represent only partial transactions.  Do not worry if these entries '
         'do not look familiar.'))


      optLayout = QVBoxLayout()
      if True:           optLayout.addWidget(lbtnCopyAddr)
      if adv:            optLayout.addWidget(lbtnViewKeys)

      if True:           optLayout.addStretch()
      if True:           optLayout.addWidget(self.lblCopied)

      optLayout.addWidget(self.lblLedgerWarning)

      optLayout.addStretch()
      optFrame.setLayout(optLayout)

      rightFrm = makeLayoutFrame(VERTICAL, [QLabel(self.tr('Available Actions:')), optFrame])
      dlgLayout.addWidget(rightFrm, 0, 1, 2, 1)

      btnGoBack = QPushButton(self.tr('<<< Go Back'))
      btnGoBack.clicked.connect(self.reject)

      self.setLayout(dlgLayout)
      self.setWindowTitle(self.tr('Address Information'))

      self.ledgerModel.reset()

   def copyAddr(self):
      clipb = QApplication.clipboard()
      clipb.clear()
      clipb.setText(self.addrObj.getAddr160())
      self.lblCopied.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      self.lblCopied.setText(self.tr('<i>Copied!</i>'))

   def makePaper(self):
      pass

   def viewKeys(self):
      if self.wlt.useEncryption and self.wlt.isLocked:
         unlockdlg = DlgUnlockWallet(self.wlt, self, self.main, 'View Private Keys')
         if not unlockdlg.exec_():
            QMessageBox.critical(self, self.tr('Wallet is Locked'), \
               self.tr('Key information will not include the private key data.'), \
               QMessageBox.Ok)

      addr = self.addr.copy()
      dlg = DlgShowKeys(addr, self.wlt, self, self.main)
      dlg.exec_()

   def deleteAddr(self):
      pass

#############################################################################
class DlgShowKeys(ArmoryDialog):

   def __init__(self, addr, wlt, parent=None, main=None):
      super(DlgShowKeys, self).__init__(parent, main)

      self.addr = addr
      self.wlt = wlt

      self.scrAddr = \
         self.wlt.cppWallet.getAddrObjByIndex(self.addr.chainIndex).getScrAddr()


      lblWarn = QRichLabel('')
      plainPriv = False
      if addr.binPrivKey32_Plain.getSize() > 0:
         plainPriv = True
         lblWarn = QRichLabel(self.tr(
            '<font color=%s><b>Warning:</b> the unencrypted private keys '
            'for this address are shown below.  They are "private" because '
            'anyone who obtains them can spend the money held '
            'by this address.  Please protect this information the '
            'same as you protect your wallet.</font>' % htmlColor('TextWarn')))
      warnFrm = makeLayoutFrame(HORIZONTAL, [lblWarn])

      endianness = self.main.getSettingOrSetDefault('PrefEndian', BIGENDIAN)
      estr = 'BE' if endianness == BIGENDIAN else 'LE'
      def formatBinData(binStr, endian=LITTLEENDIAN):
         binHex = binary_to_hex(binStr)
         if endian != LITTLEENDIAN:
            binHex = hex_switchEndian(binHex)
         binHexPieces = [binHex[i:i + 8] for i in range(0, len(binHex), 8)]
         return ' '.join(binHexPieces)


      lblDescr = QRichLabel(self.tr('Key Data for address: <b>%s</b>' % self.scrAddr))

      lbls = []

      lbls.append([])
      binKey = self.addr.binPrivKey32_Plain.toBinStr()
      lbls[-1].append(self.main.createToolTipWidget(self.tr(
            'The raw form of the private key for this address.  It is '
            '32-bytes of randomly generated data')))
      lbls[-1].append(QRichLabel(self.tr('Private Key (hex,%s):' % estr)))
      if not addr.hasPrivKey():
         lbls[-1].append(QRichLabel(self.tr('<i>[[ No Private Key in Watching-Only Wallet ]]</i>')))
      elif plainPriv:
         lbls[-1].append(QLabel(formatBinData(binKey)))
      else:
         lbls[-1].append(QRichLabel(self.tr('<i>[[ ENCRYPTED ]]</i>')))

      if plainPriv:
         lbls.append([])
         lbls[-1].append(self.main.createToolTipWidget(self.tr(
               'This is a more compact form of the private key, and includes '
               'a checksum for error detection.')))
         lbls[-1].append(QRichLabel(self.tr('Private Key (Base58):')))
         b58Key = encodePrivKeyBase58(binKey)
         lbls[-1].append(QLabel(' '.join([b58Key[i:i + 6] for i in range(0, len(b58Key), 6)])))



      lbls.append([])
      lbls[-1].append(self.main.createToolTipWidget(self.tr(
               'The raw public key data.  This is the X-coordinate of '
               'the Elliptic-curve public key point.')))
      lbls[-1].append(QRichLabel(self.tr('Public Key X (%s):' % estr)))
      lbls[-1].append(QRichLabel(formatBinData(self.addr.binPublicKey65.toBinStr()[1:1 + 32])))


      lbls.append([])
      lbls[-1].append(self.main.createToolTipWidget(self.tr(
               'The raw public key data.  This is the Y-coordinate of '
               'the Elliptic-curve public key point.')))
      lbls[-1].append(QRichLabel(self.tr('Public Key Y (%s):' % estr)))
      lbls[-1].append(QRichLabel(formatBinData(self.addr.binPublicKey65.toBinStr()[1 + 32:1 + 32 + 32])))


      bin25 = base58_to_binary(self.scrAddr)
      network = binary_to_hex(bin25[:1    ])
      hash160 = binary_to_hex(bin25[ 1:-4 ])
      addrChk = binary_to_hex(bin25[   -4:])
      h160Str = self.tr('%s (Network: %s / Checksum: %s)' % (hash160, network, addrChk))

      lbls.append([])
      lbls[-1].append(self.main.createToolTipWidget(\
               self.tr('This is the hexadecimal version if the address string')))
      lbls[-1].append(QRichLabel(self.tr('Public Key Hash:')))
      lbls[-1].append(QLabel(h160Str))

      frmKeyData = QFrame()
      frmKeyData.setFrameStyle(STYLE_RAISED)
      frmKeyDataLayout = QGridLayout()


      # Now set the label properties and jam them into an information frame
      for row, lbl3 in enumerate(lbls):
         lbl3[1].setFont(GETFONT('Var'))
         lbl3[2].setFont(GETFONT('Fixed'))
         lbl3[2].setTextInteractionFlags(Qt.TextSelectableByMouse | \
                                         Qt.TextSelectableByKeyboard)
         lbl3[2].setWordWrap(False)

         for j in range(3):
            frmKeyDataLayout.addWidget(lbl3[j], row, j)


      frmKeyData.setLayout(frmKeyDataLayout)

      bbox = QDialogButtonBox(QDialogButtonBox.Ok)
      self.connect(bbox, SIGNAL('accepted()'), self.accept)


      dlgLayout = QVBoxLayout()
      dlgLayout.addWidget(lblWarn)
      dlgLayout.addWidget(lblDescr)
      dlgLayout.addWidget(frmKeyData)
      dlgLayout.addWidget(bbox)


      self.setLayout(dlgLayout)
      self.setWindowTitle(self.tr('Address Key Information'))

#############################################################################
class DlgImportPaperWallet(ArmoryDialog):

   def __init__(self, parent=None, main=None):
      super(DlgImportPaperWallet, self).__init__(parent, main)

      self.wltDataLines = [[]] * 4
      self.prevChars = [''] * 4

      for i, edt in enumerate(self.lineEdits):
         # I screwed up the ref/copy, this loop only connected the last one...
         # theSlot = lambda: self.autoSpacerFunction(i)
         # self.connect(edt, SIGNAL('textChanged(QString)'), theSlot)
         edt.setMinimumWidth(tightSizeNChar(edt, 50)[0])

      # Just do it manually because it's guaranteed to work!
      slot = lambda: self.autoSpacerFunction(0)
      self.connect(self.lineEdits[0], SIGNAL('textEdited(QString)'), slot)

      slot = lambda: self.autoSpacerFunction(1)
      self.connect(self.lineEdits[1], SIGNAL('textEdited(QString)'), slot)

      slot = lambda: self.autoSpacerFunction(2)
      self.connect(self.lineEdits[2], SIGNAL('textEdited(QString)'), slot)

      slot = lambda: self.autoSpacerFunction(3)
      self.connect(self.lineEdits[3], SIGNAL('textEdited(QString)'), slot)

      buttonbox = QDialogButtonBox(QDialogButtonBox.Ok | \
                                   QDialogButtonBox.Cancel)
      self.connect(buttonbox, SIGNAL('accepted()'), self.verifyUserInput)
      self.connect(buttonbox, SIGNAL('rejected()'), self.reject)

      self.labels = [QLabel() for i in range(4)]
      self.labels[0].setText(self.tr('Root Key:'))
      self.labels[1].setText('')
      self.labels[2].setText(self.tr('Chain Code:'))
      self.labels[3].setText('')

      lblDescr1 = QLabel(self.tr(
          'Enter the characters exactly as they are printed on the '
          'paper-backup page.  Alternatively, you can scan the QR '
          'code from another application, then copy&paste into the '
          'entry boxes below.'))
      lblDescr2 = QLabel(self.tr(
          'The data can be entered <i>with</i> or <i>without</i> '
          'spaces, and up to '
          'one character per line will be corrected automatically.'))
      for lbl in (lblDescr1, lblDescr2):
         lbl.setTextFormat(Qt.RichText)
         lbl.setWordWrap(True)

      layout = QGridLayout()
      layout.addWidget(lblDescr1, 0, 0, 1, 2)
      layout.addWidget(lblDescr2, 1, 0, 1, 2)
      for i, edt in enumerate(self.lineEdits):
         layout.addWidget(self.labels[i], i + 2, 0)
         layout.addWidget(self.lineEdits[i], i + 2, 1)

      self.chkEncrypt = QCheckBox(self.tr('Encrypt Wallet'))
      self.chkEncrypt.setChecked(True)

      bottomFrm = makeHorizFrame([self.chkEncrypt, buttonbox])
      layout.addWidget(bottomFrm, 6, 0, 1, 2)
      layout.setVerticalSpacing(10)
      self.setLayout(layout)


      self.setWindowTitle(self.tr('Recover Wallet from Paper Backup'))
      self.setWindowIcon(QIcon(self.main.iconfile))


   def autoSpacerFunction(self, i):
      currStr = str(self.lineEdits[i].text())
      rawStr = currStr.replace(' ', '')
      if len(rawStr) > 36:
         rawStr = rawStr[:36]

      if len(rawStr) == 36:
         quads = [rawStr[j:j + 4] for j in range(0, 36, 4)]
         self.lineEdits[i].setText(' '.join(quads))


   def verifyUserInput(self):
      def englishNumberList(nums):
         nums = map(str, nums)
         if len(nums) == 1:
            return nums[0]
         return ', '.join(nums[:-1]) + ' and ' + nums[-1]

      errorLines = []
      for i in range(4):
         hasError = False
         try:
            data, err = readSixteenEasyBytes(str(self.lineEdits[i].text()))
         except (KeyError, TypeError):
            data, err = ('', 'Exception')

         if data == '':
            reply = QMessageBox.critical(self, self.tr('Verify Wallet ID'), self.tr(
               'There is an error on line %d of the data you '
               'entered, which could not be fixed automatically.  Please '
               'double-check that you entered the text exactly as it appears '
               'on the wallet-backup page.' % (i + 1)),
               QMessageBox.Ok)
            LOGERROR('Error in wallet restore field')
            self.labels[i].setText('<font color="red">' + str(self.labels[i].text()) + '</font>')
            return
         if err == 'Fixed_1' or err == 'No_Checksum':
            errorLines += [i + 1]

         self.wltDataLines[i] = data

      if errorLines:
         pluralChar = '' if len(errorLines) == 1 else 's'
         article = ' an' if len(errorLines) == 1 else ''
         QMessageBox.question(self, self.tr('Errors Corrected!'), self.tr(
            'Detected %d error(s) on line(s) %s '
            'in the data you entered.  Armory attempted to fix the '
            'error(s) but it is not always right.  Be sure '
            'to verify the "Wallet Unique ID" closely on the next window.' % (len(errorLines),
               englishNumberList(errorLines))), "", QMessageBox.Ok)

      # If we got here, the data is valid, let's create the wallet and accept the dlg
      privKey = ''.join(self.wltDataLines[:2])
      chain = ''.join(self.wltDataLines[2:])

      root = PyBtcAddress().createFromPlainKeyData(SecureBinaryData(privKey))
      root.chaincode = SecureBinaryData(chain)
      first = root.extendAddressChain()
      newWltID = binary_to_base58((ADDRBYTE + first.getAddr160()[:5])[::-1])

      if newWltID in self.main.walletMap:
         QMessageBox.question(self, self.tr('Duplicate Wallet!'), self.tr(
               'The data you entered is for a wallet with a ID: \n\n %s '
               '\n\nYou already own this wallet! \n  '
               'Nothing to do...' % newWltID), QMessageBox.Ok)
         self.reject()
         return



      reply = QMessageBox.question(self, self.tr('Verify Wallet ID'), self.tr(
               'The data you entered corresponds to a wallet with a wallet ID: \n\n '
               '%s \n\nDoes this ID match the "Wallet Unique ID" '
               'printed on your paper backup?  If not, click "No" and reenter '
               'key and chain-code data again.' % newWltID), \
               QMessageBox.Yes | QMessageBox.No)
      if reply == QMessageBox.No:
         return

      passwd = []
      if self.chkEncrypt.isChecked():
         dlgPasswd = DlgChangePassphrase(self, self.main)
         if dlgPasswd.exec_():
            passwd = SecureBinaryData(str(dlgPasswd.edtPasswd1.text()))
         else:
            QMessageBox.critical(self, self.tr('Cannot Encrypt'), self.tr(
               'You requested your restored wallet be encrypted, but no '
               'valid passphrase was supplied.  Aborting wallet recovery.'), \
               QMessageBox.Ok)
            return

      if passwd:
         self.newWallet = PyBtcWallet().createNewWallet(\
                                 plainRootKey=SecureBinaryData(privKey), \
                                 chaincode=SecureBinaryData(chain), \
                                 shortLabel=self.tr('PaperBackup - %s' % newWltID), \
                                 withEncrypt=True, \
                                 securePassphrase=passwd, \
                                 kdfTargSec=0.25, \
                                 kdfMaxMem=32 * 1024 * 1024, \
                                 isActuallyNew=False, \
                                 doRegisterWithBDM=False)
      else:
         self.newWallet = PyBtcWallet().createNewWallet(\
                                 plainRootKey=SecureBinaryData(privKey), \
                                 chaincode=SecureBinaryData(chain), \
                                 shortLabel=self.tr('PaperBackup - %s' % newWltID), \
                                 withEncrypt=False, \
                                 isActuallyNew=False, \
                                 doRegisterWithBDM=False)

      def fillAddrPoolAndAccept():
         progressBar = DlgProgress(self, self.main, None, HBar=1,
                                   Title=self.tr("Computing New Addresses"))
         progressBar.exec_(self.newWallet.fillAddressPool)
         self.accept()

      # Will pop up a little "please wait..." window while filling addr pool
      DlgExecLongProcess(fillAddrPoolAndAccept, self.tr("Recovering wallet..."), self, self.main).exec_()

################################################################################
def OpenPaperBackupWindow(backupType, parent, main, wlt, unlockTitle=None):

   if wlt.useEncryption and wlt.isLocked:
      if unlockTitle == None:
         unlockTitle = parent.tr("Unlock Paper Backup")
      dlg = DlgUnlockWallet(wlt, parent, main, unlockTitle)
      if not dlg.exec_():
         QMessageBox.warning(parent, parent.tr('Unlock Failed'), parent.tr(
            'The wallet could not be unlocked.  Please try again with '
            'the correct unlock passphrase.'), QMessageBox.Ok)
         return False

   result = True
   verifyText = ''
   if backupType == 'Single':
      from qtdialogs.DlgBackupCenter import DlgPrintBackup
      result = DlgPrintBackup(parent, main, wlt).exec_()
      verifyText = parent.tr(
         u'If the backup was printed with SecurePrint\u200b\u2122, please '
         u'make sure you wrote the SecurePrint\u200b\u2122 code on the '
         'printed sheet of paper. Note that the code <b><u>is</u></b> '
         'case-sensitive!')
   elif backupType == 'Frag':
      result = DlgFragBackup(parent, main, wlt).exec_()
      verifyText = parent.tr(
         u'If the backup was created with SecurePrint\u200b\u2122, please '
         u'make sure you wrote the SecurePrint\u200b\u2122 code on each '
         'fragment (or stored with each file fragment). The code is the '
         'same for all fragments.')

   doTest = MsgBoxCustom(MSGBOX.Warning, parent.tr('Verify Your Backup!'), parent.tr(
      '<b><u>Verify your backup!</u></b> '
      '<br><br>'
      'If you just made a backup, make sure that it is correct! '
      'The following steps are recommended to verify its integrity: '
      '<br>'
      '<ul>'
      '<li>Verify each line of the backup data contains <b>9 columns</b> '
      'of <b>4 letters each</b> (excluding any "ID" lines).</li> '
      '<li>%s</li>'
      '<li>Use Armory\'s backup tester to test the backup before you '
      'physiclly secure it.</li> '
      '</ul>'
      '<br>'
      'Armory has a backup tester that uses the exact same '
      'process as restoring your wallet, but stops before it writes any '
      'data to disk.  Would you like to test your backup now? '
       % verifyText), yesStr="Test Backup", noStr="Cancel")

   if doTest:
      if backupType == 'Single':
         DlgRestoreSingle(parent, main, True, wlt.uniqueIDB58).exec_()
      elif backupType == 'Frag':
         DlgRestoreFragged(parent, main, True, wlt.uniqueIDB58).exec_()

   return result


################################################################################
class DlgRemoveWallet(ArmoryDialog):
   def __init__(self, wlt, parent=None, main=None):
      super(DlgRemoveWallet, self).__init__(parent, main)

      wltID = wlt.uniqueIDB58
      wltName = wlt.labelName
      wltDescr = wlt.labelDescr
      lblWarning = QLabel(self.tr('<b>!!! WARNING !!!</b>\n\n'))
      lblWarning.setTextFormat(Qt.RichText)
      lblWarning.setAlignment(Qt.AlignHCenter)

      lblWarning2 = QLabel(self.tr('<i>You have requested that the following wallet '
                            'be removed from Armory:</i>'))
      lblWarning.setTextFormat(Qt.RichText)
      lblWarning.setWordWrap(True)
      lblWarning.setAlignment(Qt.AlignHCenter)

      lbls = []
      lbls.append([])
      lbls[0].append(QLabel(self.tr('Wallet Unique ID:')))
      lbls[0].append(QLabel(wltID))
      lbls.append([])
      lbls[1].append(QLabel(self.tr('Wallet Name:')))
      lbls[1].append(QLabel(wlt.labelName))
      lbls.append([])
      lbls[2].append(QLabel(self.tr('Description:')))
      lbls[2].append(QLabel(wlt.labelDescr))
      lbls[2][-1].setWordWrap(True)


      # TODO:  This should not *ever* require a blockchain scan, because all
      #        current wallets should already be registered and up-to-date.
      #        But I should verify that this is actually the case.
      wltEmpty = True
      if TheBDM.getState() == BDM_BLOCKCHAIN_READY:
         # Removed this line of code because it's part of the old BDM paradigm.
         # Leaving this comment here in case it needs to be replaced by anything
         # wlt.syncWithBlockchainLite()
         bal = wlt.getBalance('Full')
         lbls.append([])
         lbls[3].append(QLabel(self.tr('Current Balance (w/ unconfirmed):')))
         if bal > 0:
            lbls[3].append(QLabel('<font color="red"><b>' + coin2str(bal, maxZeros=1).strip() + ' BTC</b></font>'))
            lbls[3][-1].setTextFormat(Qt.RichText)
            wltEmpty = False
         else:
            lbls[3].append(QLabel(coin2str(bal, maxZeros=1) + ' BTC'))


      # Add two WARNING images on either side of dialog
      lblWarnImg = QLabel()
      lblWarnImg.setPixmap(QPixmap('./img/MsgBox_warning48.png'))
      lblWarnImg.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      lblWarnImg2 = QLabel()
      lblWarnImg2.setPixmap(QPixmap('./img/MsgBox_warning48.png'))
      lblWarnImg2.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      # Add the warning text and images to the top of the dialog
      layout = QGridLayout()
      layout.addWidget(lblWarning, 0, 1, 1, 1)
      layout.addWidget(lblWarning2, 1, 1, 1, 1)
      layout.addWidget(lblWarnImg, 0, 0, 2, 1)
      layout.addWidget(lblWarnImg2, 0, 2, 2, 1)

      frmInfo = QFrame()
      frmInfo.setFrameStyle(QFrame.Box | QFrame.Plain)
      frmInfo.setLineWidth(3)
      frmInfoLayout = QGridLayout()
      for i in range(len(lbls)):
         lbls[i][0].setText('<b>' + lbls[i][0].text() + '</b>')
         lbls[i][0].setTextFormat(Qt.RichText)
         frmInfoLayout.addWidget(lbls[i][0], i, 0)
         frmInfoLayout.addWidget(lbls[i][1], i, 1, 1, 2)

      frmInfo.setLayout(frmInfoLayout)
      layout.addWidget(frmInfo, 2, 0, 2, 3)
      hasWarningRow = False
      if not wlt.watchingOnly:
         if not wltEmpty:
            lbl = QRichLabel(self.tr('<b>WALLET IS NOT EMPTY.  Only delete this wallet if you '
                             'have a backup on paper or saved to a another location '
                             'outside your settings directory.</b>'))
            hasWarningRow = True
         elif wlt.isWltSigningAnyLockbox(self.main.allLockboxes):
            lbl = QRichLabel(self.tr('<b>WALLET IS PART OF A LOCKBOX.  Only delete this wallet if you '
                             'have a backup on paper or saved to a another location '
                             'outside your settings directory.</b>'))
            hasWarningRow = True
         if hasWarningRow:
            lbls.append(lbl)
            layout.addWidget(lbl, 4, 0, 1, 3)

      self.radioDelete = QRadioButton(self.tr('Permanently delete this wallet'))
      self.radioWatch = QRadioButton(self.tr('Delete private keys only, make watching-only'))

      # Make sure that there can only be one selection
      btngrp = QButtonGroup(self)
      btngrp.addButton(self.radioDelete)
      if not self.main.usermode == USERMODE.Standard:
         btngrp.addButton(self.radioWatch)
      btngrp.setExclusive(True)

      ttipDelete = self.main.createToolTipWidget(self.tr(
         'This will delete the wallet file, removing '
         'all its private keys from your settings directory. '
         'If you intend to keep using addresses from this '
         'wallet, do not select this option unless the wallet '
         'is backed up elsewhere.'))
      ttipWatch = self.main.createToolTipWidget(self.tr(
         'This will delete the private keys from your wallet, '
         'leaving you with a watching-only wallet, which can be '
         'used to generate addresses and monitor incoming '
         'payments.  This option would be used if you created '
         'the wallet on this computer <i>in order to transfer '
         'it to a different computer or device and want to '
         'remove the private data from this system for security.</i>'))


      self.chkPrintBackup = QCheckBox(self.tr(
         'Print a paper backup of this wallet before deleting'))

      if wlt.watchingOnly:
         ttipDelete = self.main.createToolTipWidget(self.tr(
            'This will delete the wallet file from your system. '
            'Since this is a watching-only wallet, no private keys '
            'will be deleted.'))
         ttipWatch = self.main.createToolTipWidget(self.tr(
            'This wallet is already a watching-only wallet so this option '
            'is pointless'))
         self.radioWatch.setEnabled(False)
         self.chkPrintBackup.setEnabled(False)


      self.frm = []

      rdoFrm = QFrame()
      rdoFrm.setFrameStyle(STYLE_RAISED)
      rdoLayout = QGridLayout()

      startRow = 0
      for rdo, ttip in [(self.radioDelete, ttipDelete), \
                       (self.radioWatch, ttipWatch)]:
         self.frm.append(QFrame())
         # self.frm[-1].setFrameStyle(STYLE_SUNKEN)
         self.frm[-1].setFrameStyle(QFrame.NoFrame)
         frmLayout = QHBoxLayout()
         frmLayout.addWidget(rdo)
         ttip.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
         frmLayout.addWidget(ttip)
         frmLayout.addStretch()
         self.frm[-1].setLayout(frmLayout)
         rdoLayout.addWidget(self.frm[-1], startRow, 0, 1, 3)
         startRow += 1


      self.radioDelete.setChecked(True)
      rdoFrm.setLayout(rdoLayout)

      startRow = 6 if not hasWarningRow else 5
      layout.addWidget(rdoFrm, startRow, 0, 1, 3)

      if wlt.watchingOnly:
         self.frm[-1].setVisible(False)


      printTtip = self.main.createToolTipWidget(self.tr(
         'If this box is checked, you will have the ability to print off an '
         'unencrypted version of your wallet before it is deleted.  <b>If '
         'printing is unsuccessful, please press *CANCEL* on the print dialog '
         'to prevent the delete operation from continuing</b>'))
      printFrm = makeLayoutFrame(HORIZONTAL, [self.chkPrintBackup, \
                                              printTtip, \
                                              'Stretch'])
      startRow += 1
      layout.addWidget(printFrm, startRow, 0, 1, 3)

      if wlt.watchingOnly:
         printFrm.setVisible(False)


      rmWalletSlot = lambda: self.removeWallet(wlt)

      startRow += 1
      self.btnDelete = QPushButton(self.tr("Delete"))
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.connect(self.btnDelete, SIGNAL(CLICKED), rmWalletSlot)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnDelete, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)
      layout.addWidget(buttonBox, startRow, 0, 1, 3)

      self.setLayout(layout)
      self.setWindowTitle(self.tr('Delete Wallet Options'))


   def removeWallet(self, wlt):

      # Open the print dialog.  If they hit cancel at any time, then
      # we go back to the primary wallet-remove dialog without any other action
      if self.chkPrintBackup.isChecked():
         if not OpenPaperBackupWindow('Single', self, self.main, wlt, \
                                                self.tr('Unlock Paper Backup')):
            QMessageBox.warning(self, self.tr('Operation Aborted'), self.tr(
              'You requested a paper backup before deleting the wallet, but '
              'clicked "Cancel" on the backup printing window.  So, the delete '
              'operation was canceled as well.'), QMessageBox.Ok)
            return


      # If they only want to exclude the wallet, we will add it to the excluded
      # list and remove it from the application.  The wallet files will remain
      # in the settings directory but will be ignored by Armory

      wltID = wlt.uniqueIDB58
      if wlt.watchingOnly:
         reply = QMessageBox.warning(self, self.tr('Confirm Delete'), \
         self.tr('You are about to delete a watching-only wallet.  Are you sure '
         'you want to do this?'), QMessageBox.Yes | QMessageBox.Cancel)
      elif self.radioDelete.isChecked():
         reply = QMessageBox.warning(self, self.tr('Are you absolutely sure?!?'), \
         self.tr('Are you absolutely sure you want to permanently delete '
         'this wallet?  Unless this wallet is saved on another device '
         'you will permanently lose access to all the addresses in this '
         'wallet.'), QMessageBox.Yes | QMessageBox.Cancel)
      elif self.radioWatch.isChecked():
         reply = QMessageBox.warning(self, self.tr('Are you absolutely sure?!?'), \
         self.tr('<i>This will permanently delete the information you need to spend '
         'funds from this wallet!</i>  You will only be able to receive '
         'coins, but not spend them.  Only do this if you have another copy '
         'of this wallet elsewhere, such as a paper backup or on an offline '
         'computer with the full wallet.'), QMessageBox.Yes | QMessageBox.Cancel)

      if reply == QMessageBox.Yes:

         thepath = wlt.getWalletPath()
         thepathBackup = wlt.getWalletPath('backup')

         if self.radioWatch.isChecked():
            LOGINFO('***Converting to watching-only wallet')
            newWltPath = wlt.getWalletPath('WatchOnly')
            wlt.forkOnlineWallet(newWltPath, wlt.labelName, wlt.labelDescr)
            self.main.removeWalletFromApplication(wltID)

            newWlt = PyBtcWallet().readWalletFile(newWltPath)
            self.main.addWalletToApplication(newWlt, True)
            # Removed this line of code because it's part of the old BDM paradigm.
            # Leaving this comment here in case it needs to be replaced by anything
            # newWlt.syncWithBlockchainLite()

            os.remove(thepath)
            os.remove(thepathBackup)
            self.main.statusBar().showMessage( \
               self.tr('Wallet %s was replaced with a watching-only wallet.' % wltID), 10000)

         elif self.radioDelete.isChecked():
            LOGINFO('***Completely deleting wallet')
            if TheBridge.deleteWallet(wltID) != 1:
               LOGERROR("failed to delete wallet")
               raise Exception("failed to delete wallet")

            self.main.removeWalletFromApplication(wltID)
            self.main.statusBar().showMessage( \
               self.tr('Wallet %s was deleted!' % wltID), 10000)

         self.parent.accept()
         self.accept()
      else:
         self.reject()


################################################################################
class DlgRemoveAddress(ArmoryDialog):
   def __init__(self, wlt, addr160, parent=None, main=None):
      super(DlgRemoveAddress, self).__init__(parent, main)


      if not wlt.hasScrAddr(addr160):
         raise WalletAddressError('Address does not exist in wallet!')

      addrIndex = wlt.cppWallet.getAssetIndexForAddr(addr160)
      self.cppAddrObj = wlt.cppWallet.getAddrObjByIndex(addrIndex)

      if addrIndex >= 0:
         raise WalletAddressError('Cannot delete regular chained addresses! '
                                   'Can only delete imported addresses.')


      importIndex = wlt.cppWallet.convertToImportIndex(addrIndex)

      self.wlt = wlt
      importStr = wlt.linearAddr160List[importIndex]
      self.addr = wlt.addrMap[importStr]
      self.comm = wlt.getCommentForAddress(addr160)

      lblWarning = QLabel(self.tr('<b>!!! WARNING !!!</b>\n\n'))
      lblWarning.setTextFormat(Qt.RichText)
      lblWarning.setAlignment(Qt.AlignHCenter)

      lblWarning2 = QLabel(self.tr('<i>You have requested that the following address '
                            'be deleted from your wallet:</i>'))
      lblWarning.setTextFormat(Qt.RichText)
      lblWarning.setWordWrap(True)
      lblWarning.setAlignment(Qt.AlignHCenter)

      lbls = []
      lbls.append([])
      lbls[-1].append(QLabel(self.tr('Address:')))
      lbls[-1].append(QLabel(self.cppAddrObj.getScrAddr()))
      lbls.append([])
      lbls[-1].append(QLabel(self.tr('Comment:')))
      lbls[-1].append(QLabel(self.comm))
      lbls[-1][-1].setWordWrap(True)
      lbls.append([])
      lbls[-1].append(QLabel(self.tr('In Wallet:')))
      lbls[-1].append(QLabel('"%s" (%s)' % (wlt.labelName, wlt.uniqueIDB58)))

      addrEmpty = True
      if TheBDM.getState() == BDM_BLOCKCHAIN_READY:
         bal = wlt.getAddrBalance(addr160, 'Full')
         lbls.append([])
         lbls[-1].append(QLabel(self.tr('Address Balance (w/ unconfirmed):')))
         if bal > 0:
            lbls[-1].append(QLabel('<font color="red"><b>' + coin2str(bal, maxZeros=1) + ' BTC</b></font>'))
            lbls[-1][-1].setTextFormat(Qt.RichText)
            addrEmpty = False
         else:
            lbls[3].append(QLabel(coin2str(bal, maxZeros=1) + ' BTC'))


      # Add two WARNING images on either side of dialog
      lblWarnImg = QLabel()
      lblWarnImg.setPixmap(QPixmap('./img/MsgBox_warning48.png'))
      lblWarnImg.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      lblWarnImg2 = QLabel()
      lblWarnImg2.setPixmap(QPixmap('./img/MsgBox_warning48.png'))
      lblWarnImg2.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      # Add the warning text and images to the top of the dialog
      layout = QGridLayout()
      layout.addWidget(lblWarning, 0, 1, 1, 1)
      layout.addWidget(lblWarning2, 1, 1, 1, 1)
      layout.addWidget(lblWarnImg, 0, 0, 2, 1)
      layout.addWidget(lblWarnImg2, 0, 2, 2, 1)

      frmInfo = QFrame()
      frmInfo.setFrameStyle(QFrame.Box | QFrame.Plain)
      frmInfo.setLineWidth(3)
      frmInfoLayout = QGridLayout()
      for i in range(len(lbls)):
         lbls[i][0].setText('<b>' + lbls[i][0].text() + '</b>')
         lbls[i][0].setTextFormat(Qt.RichText)
         frmInfoLayout.addWidget(lbls[i][0], i, 0)
         frmInfoLayout.addWidget(lbls[i][1], i, 1, 1, 2)

      frmInfo.setLayout(frmInfoLayout)
      layout.addWidget(frmInfo, 2, 0, 2, 3)

      lblDelete = QLabel(\
            self.tr('Do you want to delete this address?  No other addresses in this '
            'wallet will be affected.'))
      lblDelete.setWordWrap(True)
      lblDelete.setTextFormat(Qt.RichText)
      layout.addWidget(lblDelete, 4, 0, 1, 3)

      bbox = QDialogButtonBox(QDialogButtonBox.Ok | \
                              QDialogButtonBox.Cancel)
      self.connect(bbox, SIGNAL('accepted()'), self.removeAddress)
      self.connect(bbox, SIGNAL('rejected()'), self.reject)
      layout.addWidget(bbox, 5, 0, 1, 3)

      self.setLayout(layout)
      self.setWindowTitle(self.tr('Confirm Delete Address'))


   def removeAddress(self):
      reply = QMessageBox.warning(self, self.tr('One more time...'), self.tr(
           'Simply deleting an address does not prevent anyone '
           'from sending money to it.  If you have given this address '
           'to anyone in the past, make sure that they know not to '
           'use it again, since any bitcoins sent to it will be '
           'inaccessible.\n\n '
           'If you are maintaining an external copy of this address '
           'please ignore this warning\n\n'
           'Are you absolutely sure you want to delete %s ?' % self.cppAddrObj.getScrAddr()) , \
           QMessageBox.Yes | QMessageBox.Cancel)

      if reply == QMessageBox.Yes:
         self.wlt.deleteImportedAddress(self.addr.getAddr160())
         try:
            self.parent.wltAddrModel.reset()
            self.parent.setSummaryBalances()
         except AttributeError:
            pass
         self.accept()

      else:
         self.reject()

################################################################################
class DlgAddressProperties(ArmoryDialog):
   def __init__(self, wlt, parent=None, main=None):
      super(DlgAddressProperties, self).__init__(parent, main)

class GfxViewPaper(QGraphicsView):
   def __init__(self, parent=None, main=None):
      super(GfxViewPaper, self).__init__(parent)
      self.setRenderHint(QPainter.TextAntialiasing)

class GfxItemText(QGraphicsTextItem):
   """
   So far, I'm pretty bad at setting the boundingRect properly.  I have
   hacked it to be usable for this specific situation, but it's not very
   reusable...
   """
   def __init__(self, text, position, scene, font=GETFONT('Courier', 8), lineWidth=None):
      super(GfxItemText, self).__init__(text)
      self.setFont(font)
      self.setPos(position)
      if lineWidth:
         self.setTextWidth(lineWidth)

      self.setDefaultTextColor(self.PAGE_TEXT_COLOR)

   def boundingRect(self):
      w, h = relaxedSizeStr(self, self.toPlainText())
      nLine = 1
      if self.textWidth() > 0:
         twid = self.textWidth()
         nLine = max(1, int(float(w) / float(twid) + 0.5))
      return QRectF(0, 0, w, nLine * (1.5 * h))


################################################################################
class DlgBadConnection(ArmoryDialog):
   def __init__(self, haveInternet, haveSatoshi, parent=None, main=None):
      super(DlgBadConnection, self).__init__(parent, main)


      layout = QGridLayout()
      lblWarnImg = QLabel()
      lblWarnImg.setPixmap(QPixmap('./img/MsgBox_warning48.png'))
      lblWarnImg.setAlignment(Qt.AlignHCenter | Qt.AlignTop)

      lblDescr = QLabel()
      if not haveInternet and not CLI_OPTIONS.offline:
         lblDescr = QRichLabel(self.tr(
            'Armory was not able to detect an internet connection, so Armory '
            'will operate in "Offline" mode.  In this mode, only wallet '
            '-management and unsigned-transaction functionality will be available. '
            '<br><br>'
            'If this is an error, please check your internet connection and '
            'restart Armory.<br><br>Would you like to continue in "Offline" mode?'))
      elif haveInternet and not haveSatoshi:
         lblDescr = QRichLabel(self.tr(
            'Armory was not able to detect the presence of Bitcoin Core or bitcoind '
            'client software (available at https://bitcoin.org).  Please make sure that '
            'the one of those programs is... <br> '
            '<br><b>(1)</b> ...open and connected to the network '
            '<br><b>(2)</b> ...on the same network as Armory (main-network or test-network) '
            '<br><b>(3)</b> ...synchronized with the blockchain before '
            'starting Armory<br><br>Without the Bitcoin Core or bitcoind open, you will only '
            'be able to run Armory in "Offline" mode, which will not have access '
            'to new blockchain data, and you will not be able to send outgoing '
            'transactions<br><br>If you do not want to be in "Offline" mode, please '
            'restart Armory after one of these programs is open and synchronized with '
            'the network'))
      else:
         # Nothing to do -- we shouldn't have even gotten here
         # self.reject()
         pass


      self.main.abortLoad = False
      def abortLoad():
         self.main.abortLoad = True
         self.reject()

      lblDescr.setMinimumWidth(500)
      self.btnAccept = QPushButton(self.tr("Continue in Offline Mode"))
      self.btnCancel = QPushButton(self.tr("Close Armory"))
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.accept)
      self.connect(self.btnCancel, SIGNAL(CLICKED), abortLoad)
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)

      layout.addWidget(lblWarnImg, 0, 1, 2, 1)
      layout.addWidget(lblDescr, 0, 2, 1, 1)
      layout.addWidget(buttonBox, 1, 2, 1, 1)

      self.setLayout(layout)
      self.setWindowTitle(self.tr('Network not available'))


################################################################################
def readSigBlock(parent, fullPacket):
   addrB58, messageStr, pubkey, sig = '', '', '', ''
   lines = fullPacket.split('\n')
   readingMessage, readingPub, readingSig = False, False, False
   for i in range(len(lines)):
      s = lines[i].strip()

      # ADDRESS
      if s.startswith('Addr'):
         addrB58 = s.split(':')[-1].strip()

      # MESSAGE STRING
      if s.startswith('Message') or readingMessage:
         readingMessage = True
         if s.startswith('Pub') or s.startswith('Sig') or ('END-CHAL' in s):
            readingMessage = False
         else:
            # Message string needs to be exact, grab what's between the
            # double quotes, no newlines
            iq1 = s.index('"') + 1
            iq2 = s.index('"', iq1)
            messageStr += s[iq1:iq2]

      # PUBLIC KEY
      if s.startswith('Pub') or readingPub:
         readingPub = True
         if s.startswith('Sig') or ('END-SIGNATURE-BLOCK' in s):
            readingPub = False
         else:
            pubkey += s.split(':')[-1].strip().replace(' ', '')

      # SIGNATURE
      if s.startswith('Sig') or readingSig:
         readingSig = True
         if 'END-SIGNATURE-BLOCK' in s:
            readingSig = False
         else:
            sig += s.split(':')[-1].strip().replace(' ', '')


   if len(pubkey) > 0:
      try:
         pubkey = hex_to_binary(pubkey)
         if len(pubkey) not in (32, 33, 64, 65):  raise
      except:
         QMessageBox.critical(parent, parent.tr('Bad Public Key'), \
             parent.tr('Public key data was not recognized'), QMessageBox.Ok)
         pubkey = ''

   if len(sig) > 0:
      try:
         sig = hex_to_binary(sig)
      except:
         QMessageBox.critical(parent, parent.tr('Bad Signature'), \
            parent.tr('Signature data is malformed!'), QMessageBox.Ok)
         sig = ''


   pubkeyhash = hash160(pubkey)
   if not pubkeyhash == addrStr_to_hash160(addrB58)[1]:
      QMessageBox.critical(parent, parent.tr('Address Mismatch'), \
         parent.tr('!!! The address included in the signature block does not '
         'match the supplied public key!  This should never happen, '
         'and may in fact be an attempt to mislead you !!!'), QMessageBox.Ok)
      sig = ''



   return addrB58, messageStr, pubkey, sig


################################################################################
def makeSigBlock(addrB58, MessageStr, binPubkey='', binSig=''):
   lineWid = 50
   s = '-----BEGIN-SIGNATURE-BLOCK'.ljust(lineWid + 13, '-') + '\n'

   ### Address ###
   s += 'Address:    %s\n' % addrB58

   ### Message ###
   chPerLine = lineWid - 2
   nMessageLines = (len(MessageStr) - 1) / chPerLine + 1
   for i in range(nMessageLines):
      cLine = 'Message:    "%s"\n' if i == 0 else '            "%s"\n'
      s += cLine % MessageStr[i * chPerLine:(i + 1) * chPerLine]

   ### Public Key ###
   if len(binPubkey) > 0:
      hexPub = binary_to_hex(binPubkey)
      nPubLines = (len(hexPub) - 1) / lineWid + 1
      for i in range(nPubLines):
         pLine = 'PublicKey:  %s\n' if i == 0 else '            %s\n'
         s += pLine % hexPub[i * lineWid:(i + 1) * lineWid]

   ### Signature ###
   if len(binSig) > 0:
      hexSig = binary_to_hex(binSig)
      nSigLines = (len(hexSig) - 1) / lineWid + 1
      for i in range(nSigLines):
         sLine = 'Signature:  %s\n' if i == 0 else '            %s\n'
         s += sLine % hexSig[i * lineWid:(i + 1) * lineWid]

   s += '-----END-SIGNATURE-BLOCK'.ljust(lineWid + 13, '-') + '\n'
   return s



class DlgExecLongProcess(ArmoryDialog):
   """
   Execute a processing that may require having the user to wait a while.
   Should appear like a splash screen, and will automatically close when
   the processing is done.  As such, you should have very little text, just
   in case it finishes immediately, the user won't have time to read it.

   DlgExecLongProcess(execFunc, 'Short Description', self, self.main).exec_()
   """
   def __init__(self, funcExec, msg='', parent=None, main=None):
      super(DlgExecLongProcess, self).__init__(parent, main)

      self.func = funcExec

      waitFont = GETFONT('Var', 14)
      descrFont = GETFONT('Var', 12)
      palette = QPalette()
      palette.setColor(QPalette.Window, QColor(235, 235, 255))
      self.setPalette(palette);
      self.setAutoFillBackground(True)

      if parent:
         qr = parent.geometry()
         x, y, w, h = qr.left(), qr.top(), qr.width(), qr.height()
         dlgW = relaxedSizeStr(waitFont, msg)[0]
         dlgW = min(dlgW, 400)
         dlgH = 150
         self.setGeometry(int(x + w / 2 - dlgW / 2), int(y + h / 2 - dlgH / 2), dlgW, dlgH)

      lblWaitMsg = QRichLabel(self.tr('Please Wait...'))
      lblWaitMsg.setFont(waitFont)
      lblWaitMsg.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter)

      lblDescrMsg = QRichLabel(msg)
      lblDescrMsg.setFont(descrFont)
      lblDescrMsg.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter)

      self.setWindowFlags(Qt.SplashScreen)

      layout = QVBoxLayout()
      layout.addWidget(lblWaitMsg)
      layout.addWidget(lblDescrMsg)
      self.setLayout(layout)


   def exec_(self):
      def execAndClose():
         self.func()
         self.accept()

      self.callLater(0.1, execAndClose)
      QDialog.exec_(self)






################################################################################
class DlgECDSACalc(ArmoryDialog):
   def __init__(self, parent=None, main=None, tabStart=0):
      super(DlgECDSACalc, self).__init__(parent, main)

      dispFont = GETFONT('Var', 8)
      w, h = tightSizeNChar(dispFont, 40)



      ##########################################################################
      ##########################################################################
      # TAB:  secp256k1
      ##########################################################################
      ##########################################################################
      # STUB: I'll probably finish implementing this eventually....
      eccWidget = QWidget()

      tabEccLayout = QGridLayout()
      self.txtScalarScalarA = QLineEdit()
      self.txtScalarScalarB = QLineEdit()
      self.txtScalarScalarC = QLineEdit()
      self.txtScalarScalarC.setReadOnly(True)

      self.txtScalarPtA = QLineEdit()
      self.txtScalarPtB_x = QLineEdit()
      self.txtScalarPtB_y = QLineEdit()
      self.txtScalarPtC_x = QLineEdit()
      self.txtScalarPtC_y = QLineEdit()
      self.txtScalarPtC_x.setReadOnly(True)
      self.txtScalarPtC_y.setReadOnly(True)

      self.txtPtPtA_x = QLineEdit()
      self.txtPtPtA_y = QLineEdit()
      self.txtPtPtB_x = QLineEdit()
      self.txtPtPtB_y = QLineEdit()
      self.txtPtPtC_x = QLineEdit()
      self.txtPtPtC_y = QLineEdit()
      self.txtPtPtC_x.setReadOnly(True)
      self.txtPtPtC_y.setReadOnly(True)

      eccTxtList = [ \
          self.txtScalarScalarA, self.txtScalarScalarB, \
          self.txtScalarScalarC, self.txtScalarPtA, self.txtScalarPtB_x, \
          self.txtScalarPtB_y, self.txtScalarPtC_x, self.txtScalarPtC_y, \
          self.txtPtPtA_x, self.txtPtPtA_y, self.txtPtPtB_x, \
          self.txtPtPtB_y, self.txtPtPtC_x, self.txtPtPtC_y]

      dispFont = GETFONT('Var', 8)
      w, h = tightSizeNChar(dispFont, 60)
      for txt in eccTxtList:
         txt.setMinimumWidth(w)
         txt.setFont(dispFont)


      self.btnCalcSS = QPushButton(self.tr('Multiply Scalars (mod n)'))
      self.btnCalcSP = QPushButton(self.tr('Scalar Multiply EC Point'))
      self.btnCalcPP = QPushButton(self.tr('Add EC Points'))
      self.btnClearSS = QPushButton(self.tr('Clear'))
      self.btnClearSP = QPushButton(self.tr('Clear'))
      self.btnClearPP = QPushButton(self.tr('Clear'))


      imgPlus = QRichLabel('<b>+</b>')
      imgTimes1 = QRichLabel('<b>*</b>')
      imgTimes2 = QRichLabel('<b>*</b>')
      imgDown = QRichLabel('')

      self.connect(self.btnCalcSS, SIGNAL(CLICKED), self.multss)
      self.connect(self.btnCalcSP, SIGNAL(CLICKED), self.multsp)
      self.connect(self.btnCalcPP, SIGNAL(CLICKED), self.addpp)


      ##########################################################################
      # Scalar-Scalar Multiply
      sslblA = QRichLabel('a', hAlign=Qt.AlignHCenter)
      sslblB = QRichLabel('b', hAlign=Qt.AlignHCenter)
      sslblC = QRichLabel('a*b mod n', hAlign=Qt.AlignHCenter)


      ssLayout = QGridLayout()
      ssLayout.addWidget(sslblA, 0, 0, 1, 1)
      ssLayout.addWidget(sslblB, 0, 2, 1, 1)

      ssLayout.addWidget(self.txtScalarScalarA, 1, 0, 1, 1)
      ssLayout.addWidget(imgTimes1, 1, 1, 1, 1)
      ssLayout.addWidget(self.txtScalarScalarB, 1, 2, 1, 1)

      ssLayout.addWidget(makeHorizFrame([STRETCH, self.btnCalcSS, STRETCH]), \
                                                  2, 0, 1, 3)
      ssLayout.addWidget(makeHorizFrame([STRETCH, sslblC, self.txtScalarScalarC, STRETCH]), \
                                                  3, 0, 1, 3)
      ssLayout.setVerticalSpacing(1)
      frmSS = QFrame()
      frmSS.setFrameStyle(STYLE_SUNKEN)
      frmSS.setLayout(ssLayout)

      ##########################################################################
      # Scalar-ECPoint Multiply
      splblA = QRichLabel('a', hAlign=Qt.AlignHCenter)
      splblB = QRichLabel('<b>B</b>', hAlign=Qt.AlignHCenter)
      splblBx = QRichLabel('<b>B</b><font size=2>x</font>', hAlign=Qt.AlignRight)
      splblBy = QRichLabel('<b>B</b><font size=2>y</font>', hAlign=Qt.AlignRight)
      splblC = QRichLabel('<b>C</b> = a*<b>B</b>', hAlign=Qt.AlignHCenter)
      splblCx = QRichLabel('(a*<b>B</b>)<font size=2>x</font>', hAlign=Qt.AlignRight)
      splblCy = QRichLabel('(a*<b>B</b>)<font size=2>y</font>', hAlign=Qt.AlignRight)
      spLayout = QGridLayout()
      spLayout.addWidget(splblA, 0, 0, 1, 1)
      spLayout.addWidget(splblB, 0, 2, 1, 1)

      spLayout.addWidget(self.txtScalarPtA, 1, 0, 1, 1)
      spLayout.addWidget(imgTimes2, 1, 1, 1, 1)
      spLayout.addWidget(self.txtScalarPtB_x, 1, 2, 1, 1)
      spLayout.addWidget(self.txtScalarPtB_y, 2, 2, 1, 1)

      spLayout.addWidget(makeHorizFrame([STRETCH, self.btnCalcSP, STRETCH]), \
                                                  3, 0, 1, 3)
      spLayout.addWidget(makeHorizFrame([STRETCH, splblCx, self.txtScalarPtC_x, STRETCH]), \
                                                  4, 0, 1, 3)
      spLayout.addWidget(makeHorizFrame([STRETCH, splblCy, self.txtScalarPtC_y, STRETCH]), \
                                                  5, 0, 1, 3)
      spLayout.setVerticalSpacing(1)
      frmSP = QFrame()
      frmSP.setFrameStyle(STYLE_SUNKEN)
      frmSP.setLayout(spLayout)

      ##########################################################################
      # ECPoint Addition
      pplblA = QRichLabel('<b>A</b>', hAlign=Qt.AlignHCenter)
      pplblB = QRichLabel('<b>B</b>', hAlign=Qt.AlignHCenter)
      pplblAx = QRichLabel('<b>A</b><font size=2>x</font>', hAlign=Qt.AlignHCenter)
      pplblAy = QRichLabel('<b>A</b><font size=2>y</font>', hAlign=Qt.AlignHCenter)
      pplblBx = QRichLabel('<b>B</b><font size=2>x</font>', hAlign=Qt.AlignHCenter)
      pplblBy = QRichLabel('<b>B</b><font size=2>y</font>', hAlign=Qt.AlignHCenter)
      pplblC = QRichLabel('<b>C</b> = <b>A</b>+<b>B</b>', hAlign=Qt.AlignHCenter)
      pplblCx = QRichLabel('(<b>A</b>+<b>B</b>)<font size=2>x</font>', hAlign=Qt.AlignRight)
      pplblCy = QRichLabel('(<b>A</b>+<b>B</b>)<font size=2>y</font>', hAlign=Qt.AlignRight)
      ppLayout = QGridLayout()
      ppLayout.addWidget(pplblA, 0, 0, 1, 1)
      ppLayout.addWidget(pplblB, 0, 2, 1, 1)
      ppLayout.addWidget(self.txtPtPtA_x, 1, 0, 1, 1)
      ppLayout.addWidget(self.txtPtPtA_y, 2, 0, 1, 1)
      ppLayout.addWidget(imgPlus, 1, 1, 2, 1)
      ppLayout.addWidget(self.txtPtPtB_x, 1, 2, 1, 1)
      ppLayout.addWidget(self.txtPtPtB_y, 2, 2, 1, 1)
      ppLayout.addWidget(makeHorizFrame([STRETCH, self.btnCalcPP, STRETCH]), \
                                                  3, 0, 1, 3)
      ppLayout.addWidget(makeHorizFrame([STRETCH, pplblCx, self.txtPtPtC_x, STRETCH]), \
                                                  4, 0, 1, 3)
      ppLayout.addWidget(makeHorizFrame([STRETCH, pplblCy, self.txtPtPtC_y, STRETCH]), \
                                                  5, 0, 1, 3)
      ppLayout.setVerticalSpacing(1)
      frmPP = QFrame()
      frmPP.setFrameStyle(STYLE_SUNKEN)
      frmPP.setLayout(ppLayout)

      gxstr = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
      gystr = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'

      lblDescr = QRichLabel(self.tr(
         'Use this form to perform Bitcoin elliptic curve calculations.  All '
         'operations are performed on the secp256k1 elliptic curve, which is '
         'the one used for Bitcoin. '
         'Supply all values as 32-byte, big-endian, hex-encoded integers. '
         '<br><br>'
         'The following is the secp256k1 generator point coordinates (G): <br> '
         '<b>G</b><sub>x</sub>: %s <br> '
         '<b>G</b><sub>y</sub>: %s' % (gxstr, gystr)))

      lblDescr.setTextInteractionFlags(Qt.TextSelectableByMouse | \
                                       Qt.TextSelectableByKeyboard)

      btnClear = QPushButton(self.tr('Clear'))
      btnClear.setMaximumWidth(2 * relaxedSizeStr(btnClear, 'Clear')[0])
      self.connect(btnClear, SIGNAL(CLICKED), self.eccClear)

      btnBack = QPushButton(self.tr('<<< Go Back'))
      self.connect(btnBack, SIGNAL(CLICKED), self.accept)
      frmBack = makeHorizFrame([btnBack, STRETCH])

      eccLayout = QVBoxLayout()
      eccLayout.addWidget(makeHorizFrame([lblDescr, btnClear]))
      eccLayout.addWidget(frmSS)
      eccLayout.addWidget(frmSP)
      eccLayout.addWidget(frmBack)

      eccWidget.setLayout(eccLayout)

      calcLayout = QHBoxLayout()
      calcLayout.addWidget(eccWidget)
      self.setLayout(calcLayout)

      self.setWindowTitle(self.tr('ECDSA Calculator'))
      self.setWindowIcon(QIcon(self.main.iconfile))


   #############################################################################
   def getBinary(self, widget, name):
      try:
         hexVal = str(widget.text())
         binVal = hex_to_binary(hexVal)
      except:
         QMessageBox.critical(self, self.tr('Bad Input'), self.tr('Value "%s" is invalid. '
            'Make sure the value is specified in hex, big-endian.' % name) , QMessageBox.Ok)
         return ''
      return binVal


   #############################################################################
   def multss(self):
      binA = self.getBinary(self.txtScalarScalarA, 'a')
      binB = self.getBinary(self.txtScalarScalarB, 'b')
      C = CryptoECDSA().ECMultiplyScalars(binA, binB)
      self.txtScalarScalarC.setText(binary_to_hex(C))

      for txt in [self.txtScalarScalarA, \
                  self.txtScalarScalarB, \
                  self.txtScalarScalarC]:
         txt.setCursorPosition(0)

   #############################################################################
   def multsp(self):
      binA = self.getBinary(self.txtScalarPtA, 'a')
      binBx = self.getBinary(self.txtScalarPtB_x, '<b>B</b><font size=2>x</font>')
      binBy = self.getBinary(self.txtScalarPtB_y, '<b>B</b><font size=2>y</font>')

      if not CryptoECDSA().ECVerifyPoint(binBx, binBy):
         QMessageBox.critical(self, self.tr('Invalid EC Point'), \
            self.tr('The point you specified (<b>B</b>) is not on the '
            'elliptic curve used in Bitcoin (secp256k1).'), QMessageBox.Ok)
         return

      C = CryptoECDSA().ECMultiplyPoint(binA, binBx, binBy)
      self.txtScalarPtC_x.setText(binary_to_hex(C[:32]))
      self.txtScalarPtC_y.setText(binary_to_hex(C[32:]))

      for txt in [self.txtScalarPtA, \
                  self.txtScalarPtB_x, self.txtScalarPtB_y, \
                  self.txtScalarPtC_x, self.txtScalarPtC_y]:
         txt.setCursorPosition(0)

   #############################################################################
   def addpp(self):
      binAx = self.getBinary(self.txtPtPtA_x, '<b>A</b><font size=2>x</font>')
      binAy = self.getBinary(self.txtPtPtA_y, '<b>A</b><font size=2>y</font>')
      binBx = self.getBinary(self.txtPtPtB_x, '<b>B</b><font size=2>x</font>')
      binBy = self.getBinary(self.txtPtPtB_y, '<b>B</b><font size=2>y</font>')

      if not CryptoECDSA().ECVerifyPoint(binAx, binAy):
         QMessageBox.critical(self, self.tr('Invalid EC Point'), \
            self.tr('The point you specified (<b>A</b>) is not on the '
            'elliptic curve used in Bitcoin (secp256k1).'), QMessageBox.Ok)
         return

      if not CryptoECDSA().ECVerifyPoint(binBx, binBy):
         QMessageBox.critical(self, self.tr('Invalid EC Point'), \
            self.tr('The point you specified (<b>B</b>) is not on the '
            'elliptic curve used in Bitcoin (secp256k1).'), QMessageBox.Ok)
         return

      C = CryptoECDSA().ECAddPoints(binAx, binAy, binBx, binBy)
      self.txtPtPtC_x.setText(binary_to_hex(C[:32]))
      self.txtPtPtC_y.setText(binary_to_hex(C[32:]))

      for txt in [self.txtPtPtA_x, self.txtPtPtA_y, \
                  self.txtPtPtB_x, self.txtPtPtB_y, \
                  self.txtPtPtC_x, self.txtPtPtC_y]:
         txt.setCursorPosition(0)


   #############################################################################
   def eccClear(self):
      self.txtScalarScalarA.setText('')
      self.txtScalarScalarB.setText('')
      self.txtScalarScalarC.setText('')

      self.txtScalarPtA.setText('')
      self.txtScalarPtB_x.setText('')
      self.txtScalarPtB_y.setText('')
      self.txtScalarPtC_x.setText('')
      self.txtScalarPtC_y.setText('')

      self.txtPtPtA_x.setText('')
      self.txtPtPtA_y.setText('')
      self.txtPtPtB_x.setText('')
      self.txtPtPtB_y.setText('')
      self.txtPtPtC_x.setText('')
      self.txtPtPtC_y.setText('')


################################################################################
# STUB STUB STUB STUB STUB
class ArmoryPref(object):
   """
   Create a class that will handle arbitrary preferences for Armory.  This
   means that I can just create maps/lists of preferences, and auto-include
   them in the preferences dialog, and know how to set/get them.  This will
   be subclassed for each unique/custom preference type that is needed.
   """
   def __init__(self, prefName, dispStr, setType, defaultVal, validRange, descr, ttip, usermodes=None):
      self.preference = prefName
      self.displayStr = dispStr
      self.preferType = setType
      self.defaultVal = defaultVal
      self.validRange = validRange
      self.description = descr
      self.ttip = ttip

      # Some options may only be displayed for certain usermodes
      self.users = usermodes
      if usermodes == None:
         self.users = set([USERMODE.Standard, USERMODE.Advanced, USERMODE.Expert])

      if self.preferType == 'str':
         self.entryObj = QLineEdit()
      elif self.preferType == 'num':
         self.entryObj = QLineEdit()
      elif self.preferType == 'file':
         self.entryObj = QLineEdit()
      elif self.preferType == 'bool':
         self.entryObj = QCheckBox()
      elif self.preferType == 'combo':
         self.entryObj = QComboBox()


   def setEntryVal(self):
      pass

   def readEntryVal(self):
      pass


   def setWidthChars(self, nChar):
      self.entryObj.setMinimumWidth(relaxedSizeNChar(self.entryObj, nChar)[0])

   def render(self):
      """
      Return a map of qt objects to insert into the frame
      """
      toDraw = []
      row = 0
      if len(self.description) > 0:
         toDraw.append([QRichLabel(self.description), row, 0, 1, 4])
         row += 1


################################################################################
class QRadioButtonBackupCtr(QRadioButton):
   def __init__(self, parent, txt, index):
      super(QRadioButtonBackupCtr, self).__init__(txt)
      self.parent = parent
      self.index = index


   def enterEvent(self, ev):
      pass
      # self.parent.setDispFrame(self.index)
      # self.setStyleSheet('QRadioButton { background-color : %s }' % \
                                          # htmlColor('SlightBkgdDark'))

   def leaveEvent(self, ev):
      pass
      # self.parent.setDispFrame(-1)
      # self.setStyleSheet('QRadioButton { background-color : %s }' % \
                                          # htmlColor('Background'))


################################################################################
# Class that acts as a center where the user can decide what to do with the
# watch-only wallet. The data can be displayed, printed, or saved to a file as a
# wallet or as the watch-only data (i.e., root key & chain code).
class DlgExpWOWltData(ArmoryDialog):
   """
   This dialog will be used to export a wallet's root public key and chain code.
   """
   def __init__(self, wlt, parent, main):
      super(DlgExpWOWltData, self).__init__(parent, main)

      # Save a copy of the wallet.
      self.wlt = wlt
      self.main = main

      # Get the chain code and uncompressed public key of info from the wallet,
      # along with other useful info.
      wltRootIDConcat, pkccET16Lines = wlt.getRootPKCCBackupData(True)
      wltIDB58 = wlt.uniqueIDB58

      # Create the data export buttons.
      expWltButton = QPushButton(self.tr('Export Watching-Only Wallet File'))
      clipboardBtn = QPushButton(self.tr('Copy to clipboard'))
      clipboardLbl = QRichLabel('', hAlign=Qt.AlignHCenter)
      expDataButton = QPushButton(self.tr('Save to Text File'))
      printWODataButton = QPushButton(self.tr('Print Root Data'))


      self.connect(expWltButton, SIGNAL(CLICKED), self.clickedExpWlt)
      self.connect(expDataButton, SIGNAL(CLICKED), self.clickedExpData)
      self.connect(printWODataButton, SIGNAL(CLICKED), \
                   self.clickedPrintWOData)


      # Let's put the window together.
      layout = QVBoxLayout()

      self.dispText = self.tr(
         'Watch-Only Root ID:<br><b>%s</b>'
         '<br><br>'
         'Watch-Only Root Data:' % wltRootIDConcat)
      for j in pkccET16Lines:
         self.dispText += '<br><b>%s</b>' % (j)

      titleStr = self.tr('Watch-Only Wallet Export')

      self.txtLongDescr = QTextBrowser()
      self.txtLongDescr.setFont(GETFONT('Fixed', 9))
      self.txtLongDescr.setHtml(self.dispText)
      w,h = tightSizeNChar(self.txtLongDescr, 20)
      self.txtLongDescr.setMaximumHeight(9.5*h)

      def clippy():
         clipb = QApplication.clipboard()
         clipb.clear()
         clipb.setText(str(self.txtLongDescr.toPlainText()))
         clipboardLbl.setText(self.tr('<i>Copied!</i>'))

      self.connect(clipboardBtn, SIGNAL('clicked()'), clippy)


      lblDescr = QRichLabel(self.tr(
         '<center><b><u><font size=4 color="%s">Export Watch-Only '
         'Wallet: %s</font></u></b></center> '
         '<br>'
         'Use a watching-only wallet on an online computer to distribute '
         'payment addresses, verify transactions and monitor balances, but '
         'without the ability to move the funds.' % (htmlColor('TextBlue'), wlt.uniqueIDB58)))

      lblTopHalf = QRichLabel(self.tr(
         '<center><b><u>Entire Wallet File</u></b></center> '
         '<br>'
         '<i><b><font color="%s">(Recommended)</font></b></i> '
         'An exact copy of your wallet file but without any of the private '
         'signing keys. All existing comments and labels will be carried '
         'with the file. Use this option if it is easy to transfer files '
         'from this system to the target system.' % htmlColor('TextBlue')))

      lblBotHalf = QRichLabel(self.tr(
         '<center><b><u>Only Root Data</u></b></center> '
         '<br>'
         'Same as above, but only five lines of text that are easy to '
         'print, email inline, or copy by hand.  Only produces the '
         'wallet addresses.   No comments or labels are carried with '
         'it.'))

      btnDone = QPushButton(self.tr('Done'))
      self.connect(btnDone, SIGNAL('clicked()'), self.accept)


      frmButtons = makeVertFrame([clipboardBtn,
                                  expDataButton,
                                  printWODataButton,
                                  clipboardLbl,
                                  'Stretch'])
      layoutBottom = QHBoxLayout()
      layoutBottom.addWidget(frmButtons, 0)
      layoutBottom.addItem(QSpacerItem(5,5))
      layoutBottom.addWidget(self.txtLongDescr, 1)
      layoutBottom.setSpacing(5)


      layout.addWidget(lblDescr)
      layout.addItem(QSpacerItem(10, 10))
      layout.addWidget(HLINE())
      layout.addWidget(lblTopHalf, 1)
      layout.addWidget(makeHorizFrame(['Stretch', expWltButton, 'Stretch']))
      layout.addItem(QSpacerItem(20, 20))
      layout.addWidget(HLINE())
      layout.addWidget(lblBotHalf, 1)
      layout.addLayout(layoutBottom)
      layout.addItem(QSpacerItem(20, 20))
      layout.addWidget(HLINE())
      layout.addWidget(makeHorizFrame(['Stretch', btnDone]))
      layout.setSpacing(3)

      self.setLayout(layout)
      self.setMinimumWidth(600)

      # TODO:  Dear god this is terrible, but for my life I cannot figure
      #        out how to move the vbar, because you can't do it until
      #        the dialog is drawn which doesn't happen til after __init__.
      self.callLater(0.05, self.resizeEvent)

      self.setWindowTitle(titleStr)


   def resizeEvent(self, ev=None):
      super(DlgExpWOWltData, self).resizeEvent(ev)
      vbar = self.txtLongDescr.verticalScrollBar()
      vbar.setValue(vbar.minimum())


   # The function that is executed when the user wants to back up the full
   # watch-only wallet to a file.
   def clickedExpWlt(self):
      currPath = self.wlt.walletPath
      if not self.wlt.watchingOnly:
         pieces = os.path.splitext(currPath)
         currPath = pieces[0] + '_WatchOnly' + pieces[1]

      saveLoc = self.main.getFileSave('Save Watching-Only Copy', \
                                      defaultFilename=currPath)
      if not saveLoc.endswith('.wallet'):
         saveLoc += '.wallet'

      if not self.wlt.watchingOnly:
         self.wlt.forkOnlineWallet(saveLoc, self.wlt.labelName, \
                                '(Watching-Only) ' + self.wlt.labelDescr)
      else:
         self.wlt.writeFreshWalletFile(saveLoc)



   # The function that is executed when the user wants to save the watch-only
   # data to a file.
   def clickedExpData(self):
      self.main.makeWalletCopy(self, self.wlt, 'PKCC', 'rootpubkey')


   # The function that is executed when the user wants to print the watch-only
   # data.
   def clickedPrintWOData(self):
      self.result = DlgWODataPrintBackup(self, self.main, self.wlt).exec_()


################################################################################
# Class that handles the printing of the watch-only wallet data. The formatting
# is mostly the same as a normal paper backup. Note that neither fragmented
# backups nor SecurePrint are used.
class DlgWODataPrintBackup(ArmoryDialog):
   """
   Open up a "Make Paper Backup" dialog, so the user can print out a hard
   copy of whatever data they need to recover their wallet should they lose
   it.
   """
   def __init__(self, parent, main, wlt):
      super(DlgWODataPrintBackup, self).__init__(parent, main)

      self.wlt = wlt

      # Create the scene and the view.
      self.scene = SimplePrintableGraphicsScene(self, self.main)
      self.view = QGraphicsView()
      self.view.setRenderHint(QPainter.TextAntialiasing)
      self.view.setScene(self.scene.getScene())

      # Label displayed above the sheet to be printed.
      lblDescr = QRichLabel(self.tr(
         '<b><u>Print Watch-Only Wallet Root</u></b><br><br> '
         'The lines below are sufficient to calculate public keys '
         'for every private key ever produced by the full wallet. '
         'Importing this data to an online computer is sufficient '
         'to receive and verify transactions, and monitor balances, '
         'but without the ability to spend the funds.'))
      lblDescr.setContentsMargins(5, 5, 5, 5)
      frmDescr = makeHorizFrame([lblDescr], STYLE_RAISED)

      # Buttons shown below the sheet to be printed.
      self.btnPrint = QPushButton('&Print...')
      self.btnPrint.setMinimumWidth(3 * tightSizeStr(self.btnPrint, 'Print...')[0])
      self.btnCancel = QPushButton('&Cancel')
      self.connect(self.btnPrint, SIGNAL(CLICKED), self.print_)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      frmButtons = makeHorizFrame([self.btnCancel, STRETCH, self.btnPrint])

      # Draw the sheet for the first time.
      self.redrawBackup()

      # Lay out the dialog.
      layout = QVBoxLayout()
      layout.addWidget(frmDescr)
      layout.addWidget(self.view)
      layout.addWidget(frmButtons)
      setLayoutStretch(layout, 0, 1, 0)
      self.setLayout(layout)
      self.setWindowIcon(QIcon('./img/printer_icon.png'))
      self.setWindowTitle('Print Watch-Only Root')

      # Apparently I can't programmatically scroll until after it's painted
      def scrollTop():
         vbar = self.view.verticalScrollBar()
         vbar.setValue(vbar.minimum())
      self.callLater(0.01, scrollTop)


   # Class called to redraw the print "canvas" when the data changes.
   def redrawBackup(self):
      self.createPrintScene()
      self.view.update()


   # Class that handles the actual printing code.
   def print_(self):
      LOGINFO('Printing!')
      self.printer = QPrinter(QPrinter.HighResolution)
      self.printer.setPageSize(QPrinter.Letter)

      if QPrintDialog(self.printer).exec_():
         painter = QPainter(self.printer)
         painter.setRenderHint(QPainter.TextAntialiasing)

         self.createPrintScene()
         self.scene.getScene().render(painter)
         painter.end()
         self.accept()


   # Class that lays out the actual print "canvas" to be printed.
   def createPrintScene(self):
      # Do initial setup.
      self.scene.gfxScene.clear()
      self.scene.resetCursor()

      # Draw the background paper?
      pr = self.scene.pageRect()
      self.scene.drawRect(pr.width(), pr.height(), edgeColor=None, \
                          fillColor=QColor(255, 255, 255))
      self.scene.resetCursor()

      INCH = self.scene.INCH
      MARGIN = self.scene.MARGIN_PIXELS
      wrap = 0.9 * self.scene.pageRect().width()

      # Start drawing the page.
      if USE_TESTNET or USE_REGTEST:
         self.scene.drawPixmapFile('./img/armory_logo_green_h56.png')
      else:
         self.scene.drawPixmapFile('./img/armory_logo_h36.png')
      self.scene.newLine()

      warnMsg = self.tr(
         '<b><font size=4><font color="#aa0000">WARNING:</font>  <u>This is not '
         'a wallet backup!</u></font></b> '
         '<br><br>Please make a regular digital or paper backup of your wallet '
         'to keep it protected!  This data simply lets you '
         'monitor the funds in this wallet but gives you no ability to move any '
         'funds.')
      self.scene.drawText(warnMsg, GETFONT('Var', 9), wrapWidth=wrap)

      self.scene.newLine(extra_dy=20)
      self.scene.drawHLine()
      self.scene.newLine(extra_dy=20)

      # Print the wallet info.
      colRect, rowHgt = self.scene.drawColumn(['<b>Watch-Only Root Data</b>',
                                               'Wallet ID:',
                                               'Wallet Name:'])
      self.scene.moveCursor(15, 0)
      colRect, rowHgt = self.scene.drawColumn(['',
                                               self.wlt.uniqueIDB58,
                                               self.wlt.labelName])

      self.scene.moveCursor(15, colRect.y() + colRect.height(), absolute=True)

      # Display warning about unprotected key data.
      self.scene.newLine(extra_dy=20)
      self.scene.drawHLine()
      self.scene.newLine(extra_dy=20)

      # Draw the description of the data.
      descrMsg = self.tr(
         'The following five lines are sufficient to reproduce all public '
         'keys matching the private keys produced by the full wallet.')
      self.scene.drawText(descrMsg, GETFONT('var', 8), wrapWidth=wrap)
      self.scene.newLine(extra_dy=10)

      # Prepare the data.
      self.wltRootIDConcat, self.pkccET16Lines = \
                                            self.wlt.getRootPKCCBackupData(True)
      Lines = []
      Prefix = []
      Prefix.append('Watch-Only Root ID:');  Lines.append(self.wltRootIDConcat)
      Prefix.append('Watch-Only Root:');     Lines.append(self.pkccET16Lines[0])
      Prefix.append('');                     Lines.append(self.pkccET16Lines[1])
      Prefix.append('');                     Lines.append(self.pkccET16Lines[2])
      Prefix.append('');                     Lines.append(self.pkccET16Lines[3])

      # Draw the prefix data.
      origX, origY = self.scene.getCursorXY()
      self.scene.moveCursor(10, 0)
      colRect, rowHgt = self.scene.drawColumn(['<b>' + l + '</b>' \
                                               for l in Prefix])

      # Draw the data.
      nudgeDown = 2  # because the differing font size makes it look unaligned
      self.scene.moveCursor(10, nudgeDown)
      self.scene.drawColumn(Lines,
                              font=GETFONT('Fixed', 8, bold=True), \
                              rowHeight=rowHgt,
                              useHtml=False)

      # Draw the rectangle around the data.
      self.scene.moveCursor(MARGIN, colRect.y() - 2, absolute=True)
      width = self.scene.pageRect().width() - 2 * MARGIN
      self.scene.drawRect(width, colRect.height() + 7, \
                          edgeColor=QColor(0, 0, 0), fillColor=None)

      # Draw the QR-related text below the data.
      self.scene.newLine(extra_dy=30)
      self.scene.drawText(self.tr(
         'The following QR code is for convenience only.  It contains the '
         'exact same data as the five lines above.  If you copy this data '
         'by hand, you can safely ignore this QR code.'), wrapWidth=4 * INCH)

      # Draw the QR code.
      self.scene.moveCursor(20, 0)
      x, y = self.scene.getCursorXY()
      edgeRgt = self.scene.pageRect().width() - MARGIN
      edgeBot = self.scene.pageRect().height() - MARGIN
      qrSize = max(1.5 * INCH, min(edgeRgt - x, edgeBot - y, 2.0 * INCH))
      self.scene.drawQR('\n'.join(Lines), qrSize)
      self.scene.newLine(extra_dy=25)

      # Clear the data and create a vertical scroll bar.
      Lines = None
      vbar = self.view.verticalScrollBar()
      vbar.setValue(vbar.minimum())
      self.view.update()


################################################################################
# Create a special QLineEdit with a masked input
# Forces the cursor to start at position 0 whenever there is no input
class MaskedInputLineEdit(QLineEdit):

   def __init__(self, inputMask):
      super(MaskedInputLineEdit, self).__init__()
      self.setInputMask(inputMask)
      fixFont = GETFONT('Fix', 9)
      self.setFont(fixFont)
      self.setMinimumWidth(tightSizeStr(fixFont, inputMask)[0] + 10)
      self.cursorPositionChanged.connect(self.controlCursor)

   def controlCursor(self, oldpos, newpos):
      if newpos != 0 and len(str(self.text()).strip()) == 0:
         self.setCursorPosition(0)


def checkSecurePrintCode(context, SECPRINT, securePrintCode):
   result = True
   try:
      if len(securePrintCode) < 9:
         QMessageBox.critical(context, context.tr('Invalid Code'), context.trUtf8(
            u'You didn\'t enter a full SecurePrint\u200b\u2122 code.  This '
            'code is needed to decrypt your backup file.'), QMessageBox.Ok)
         result = False
      elif not SECPRINT['FUNC_CHKPWD'](securePrintCode):
         QMessageBox.critical(context, context.trUtf8(u'Bad SecurePrint\u200b\u2122 Code'), context.trUtf8(
            u'The SecurePrint\u200b\u2122 code you entered has an error '
            'in it.  Note that the code is case-sensitive.  Please verify '
            'you entered it correctly and try again.'), QMessageBox.Ok)
         result = False
   except NonBase58CharacterError as e:
      QMessageBox.critical(context, context.trUtf8(u'Bad SecurePrint\u200b\u2122 Code'), context.trUtf8(
         u'The SecurePrint\u200b\u2122 code you entered has unrecognized characters '
         'in it.  %s Only the following characters are allowed: %s' % (e.message, BASE58CHARS)), QMessageBox.Ok)
      result = False
   return result



##########################################################################
class DlgShowTestResults(ArmoryDialog):
   #######################################################################
   def __init__(self, parent, isRandom, subsAndIDs, M, nFrag, expectID):
      super(DlgShowTestResults, self).__init__(parent, parent.main)

      accumSet = set()
      for sub, ID in subsAndIDs:
         accumSet.add(ID)

      allEqual = (len(accumSet) == 1)
      allCorrect = True
      testID = expectID
      if not testID:
         testID = subsAndIDs[0][1]

      allCorrect = testID == subsAndIDs[0][1]

      descr = ''
      nSubs = len(subsAndIDs)
      fact = lambda x: math.factorial(x)
      total = fact(nFrag) // (fact(M) * fact(nFrag - M))
      if isRandom:
         descr = self.tr(
            'The total number of fragment subsets (%d) is too high '
            'to test and display.  Instead, %d subsets were tested '
            'at random.  The results are below ' % (total, nSubs))
      else:
         descr = self.tr(
            'For the fragments you entered, there are a total of '
            '%d possible subsets that can restore your wallet. '
            'The test results for all subsets are shown below' % total)

      lblDescr = QRichLabel(descr)

      lblWltIDDescr = QRichLabel(self.tr(
         'The wallet ID is computed from the first '
         'address in your wallet based on the root key data (and the '
         '"chain code").  Therefore, a matching wallet ID proves that '
         'the wallet will produce identical addresses.'))


      frmResults = QFrame()
      layout = QGridLayout()
      row = 0
      for sub, ID in subsAndIDs:
         subStrs = [str(s) for s in sub]
         subText = ', '.join(subStrs[:-1])
         dispTxt = self.tr(
            'Fragments <b>%s</b> and <b>%s</b> produce a '
            'wallet with ID "<b>%s</b>"' % (subText, subStrs[-1], ID))

         chk = lambda: QPixmap('./img/checkmark32.png').scaled(20, 20)
         _X_ = lambda: QPixmap('./img/red_X.png').scaled(16, 16)

         lblTxt = QRichLabel(dispTxt)
         lblTxt.setWordWrap(False)
         lblPix = QLabel('')
         lblPix.setPixmap(chk() if ID == testID else _X_())
         layout.addWidget(lblTxt, row, 0)
         layout.addWidget(lblPix, row, 1)
         row += 1



      scrollResults = QScrollArea()
      frmResults = QFrame()
      frmResults.setLayout(layout)
      scrollResults.setWidget(frmResults)

      btnOkay = QPushButton(self.tr('Ok'))
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(btnOkay, QDialogButtonBox.AcceptRole)
      self.connect(btnOkay, SIGNAL(CLICKED), self.accept)

      mainLayout = QVBoxLayout()
      mainLayout.addWidget(lblDescr)
      mainLayout.addWidget(scrollResults)
      mainLayout.addWidget(lblWltIDDescr)
      mainLayout.addWidget(buttonBox)
      self.setLayout(mainLayout)

      self.setWindowTitle(self.tr('Fragment Test Results'))
      self.setMinimumWidth(500)

################################################################################
class DlgEnterSecurePrintCode(ArmoryDialog):

   def __init__(self, parent, main):
      super(DlgEnterSecurePrintCode, self).__init__(parent, main)

      lblSecurePrintCodeDescr = QRichLabel(self.tr(
         u'This fragment file requires a SecurePrint\u200b\u2122 code. '
         'You will only have to enter this code once since it is the same '
         'on all fragments.'))
      lblSecurePrintCodeDescr.setMinimumWidth(440)
      self.lblSP = QRichLabel(self.tr(u'SecurePrint\u200b\u2122 Code: '), doWrap=False)
      self.editSecurePrint = QLineEdit()
      spFrame = makeHorizFrame([self.lblSP, self.editSecurePrint, STRETCH])

      self.btnAccept = QPushButton(self.tr("Done"))
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.verifySecurePrintCode)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)

      layout = QVBoxLayout()
      layout.addWidget(lblSecurePrintCodeDescr)
      layout.addWidget(spFrame)
      layout.addWidget(buttonBox)
      self.setLayout(layout)
      self.setWindowTitle(self.tr('Enter Secure Print Code'))

   def verifySecurePrintCode(self):
      # Prepare the key mask parameters
      SECPRINT = HardcodedKeyMaskParams()
      securePrintCode = str(self.editSecurePrint.text()).strip()

      if not checkSecurePrintCode(self, SECPRINT, securePrintCode):
         return

      self.accept()

################################################################################
class DlgEnterOneFrag(ArmoryDialog):

   def __init__(self, parent, main, fragList=[], wltType=UNKNOWN, securePrintCode=None):
      super(DlgEnterOneFrag, self).__init__(parent, main)
      self.fragData = []
      BLUE = htmlColor('TextBlue')
      already = ''
      if len(fragList) > 0:
         strList = ['<font color="%s">%d</font>' % (BLUE, f) for f in fragList]
         replStr = '[' + ','.join(strList[:]) + ']'
         already = self.tr('You have entered fragments %s, so far.' % replStr)

      lblDescr = QRichLabel(self.tr(
         '<b><u>Enter Another Fragment...</u></b> <br><br> %s '
         'The fragments can be entered in any order, as long as you provide '
         'enough of them to restore the wallet.  If any fragments use a '
         u'SecurePrint\u200b\u2122 code, please enter it once on the '
         'previous window, and it will be applied to all fragments that '
         'require it.' % already))

      self.version0Button = QRadioButton(self.tr( BACKUP_TYPE_0_TEXT), self)
      self.version135aButton = QRadioButton(self.tr( BACKUP_TYPE_135a_TEXT), self)
      self.version135aSPButton = QRadioButton(self.tr( BACKUP_TYPE_135a_SP_TEXT), self)
      self.version135cButton = QRadioButton(self.tr( BACKUP_TYPE_135c_TEXT), self)
      self.version135cSPButton = QRadioButton(self.tr( BACKUP_TYPE_135c_SP_TEXT), self)
      self.backupTypeButtonGroup = QButtonGroup(self)
      self.backupTypeButtonGroup.addButton(self.version0Button)
      self.backupTypeButtonGroup.addButton(self.version135aButton)
      self.backupTypeButtonGroup.addButton(self.version135aSPButton)
      self.backupTypeButtonGroup.addButton(self.version135cButton)
      self.backupTypeButtonGroup.addButton(self.version135cSPButton)
      self.version135cButton.setChecked(True)
      self.connect(self.backupTypeButtonGroup, SIGNAL('buttonClicked(int)'), self.changeType)

      # This value will be locked after the first fragment is entered.
      if wltType == UNKNOWN:
         self.version135cButton.setChecked(True)
      elif wltType == '0':
         self.version0Button.setChecked(True)
         self.version135aButton.setEnabled(False)
         self.version135aSPButton.setEnabled(False)
         self.version135cButton.setEnabled(False)
         self.version135cSPButton.setEnabled(False)
      elif wltType == BACKUP_TYPE_135A:
            # Could be 1.35a with or without SecurePrintCode so remove the rest
         self.version0Button.setEnabled(False)
         self.version135cButton.setEnabled(False)
         self.version135cSPButton.setEnabled(False)
         if securePrintCode:
            self.version135aSPButton.setChecked(True)
         else:
            self.version135aButton.setChecked(True)
      elif wltType == BACKUP_TYPE_135C:
         # Could be 1.35c with or without SecurePrintCode so remove the rest
         self.version0Button.setEnabled(False)
         self.version135aButton.setEnabled(False)
         self.version135aSPButton.setEnabled(False)
         if securePrintCode:
            self.version135cSPButton.setChecked(True)
         else:
            self.version135cButton.setChecked(True)

      lblType = QRichLabel(self.tr('<b>Backup Type:</b>'), doWrap=False)

      layoutRadio = QVBoxLayout()
      layoutRadio.addWidget(self.version0Button)
      layoutRadio.addWidget(self.version135aButton)
      layoutRadio.addWidget(self.version135aSPButton)
      layoutRadio.addWidget(self.version135cButton)
      layoutRadio.addWidget(self.version135cSPButton)
      layoutRadio.setSpacing(0)

      radioButtonFrame = QFrame()
      radioButtonFrame.setLayout(layoutRadio)

      frmBackupType = makeVertFrame([lblType, radioButtonFrame])

      self.prfxList = ['x1:', 'x2:', 'x3:', 'x4:', \
                       'y1:', 'y2:', 'y3:', 'y4:', \
                       'F1:', 'F2:', 'F3:', 'F4:']
      self.prfxList = [QLabel(p) for p in self.prfxList]
      inpMask = '<AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA\ AAAA\ AAAA\ AAAA\ \ AAAA!'
      self.edtList = [MaskedInputLineEdit(inpMask) for i in range(12)]

      inpMaskID = '<HHHH\ HHHH\ HHHH\ HHHH!'
      self.lblID = QRichLabel('ID:')
      self.edtID = MaskedInputLineEdit(inpMaskID)

      frmAllInputs = QFrame()
      frmAllInputs.setFrameStyle(STYLE_RAISED)
      layoutAllInp = QGridLayout()

      # Add Secure Print row - Use supplied securePrintCode and
      # disable text entry if it is not None
      self.lblSP = QRichLabel(self.tr(u'SecurePrint\u200b\u2122 Code:'), doWrap=False)
      self.editSecurePrint = QLineEdit()
      self.editSecurePrint.setEnabled(not securePrintCode)
      if (securePrintCode):
         self.editSecurePrint.setText(securePrintCode)
      self.frmSP = makeHorizFrame([STRETCH, self.lblSP, self.editSecurePrint])
      layoutAllInp.addWidget(self.frmSP, 0, 0, 1, 2)

      layoutAllInp.addWidget(self.lblID, 1, 0, 1, 1)
      layoutAllInp.addWidget(self.edtID, 1, 1, 1, 1)
      for i in range(12):
         layoutAllInp.addWidget(self.prfxList[i], i + 2, 0, 1, 2)
         layoutAllInp.addWidget(self.edtList[i], i + 2, 1, 1, 2)
      frmAllInputs.setLayout(layoutAllInp)

      self.btnAccept = QPushButton(self.tr("Done"))
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.verifyUserInput)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)

      layout = QVBoxLayout()
      layout.addWidget(lblDescr)
      layout.addWidget(HLINE())
      layout.addWidget(frmBackupType)
      layout.addWidget(frmAllInputs)
      layout.addWidget(buttonBox)
      self.setLayout(layout)


      self.setWindowTitle(self.tr('Restore Single-Sheet Backup'))
      self.setMinimumWidth(500)
      self.layout().setSizeConstraint(QLayout.SetFixedSize)
      self.changeType(self.backupTypeButtonGroup.checkedId())


   #############################################################################
   def changeType(self, sel):
      #            |-- X --| |-- Y --| |-- F --|
      if sel == self.backupTypeButtonGroup.id(self.version0Button):
         visList = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0]
      elif sel == self.backupTypeButtonGroup.id(self.version135aButton) or \
           sel == self.backupTypeButtonGroup.id(self.version135aSPButton):
         visList = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1]
      elif sel == self.backupTypeButtonGroup.id(self.version135cButton) or \
           sel == self.backupTypeButtonGroup.id(self.version135cSPButton):
         visList = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0]
      else:
         LOGERROR('What the heck backup type is selected?  %d', sel)
         return

      self.frmSP.setVisible(sel == self.backupTypeButtonGroup.id(self.version135aSPButton) or \
                            sel == self.backupTypeButtonGroup.id(self.version135cSPButton))
      for i in range(12):
         self.prfxList[i].setVisible(visList[i] == 1)
         self.edtList[ i].setVisible(visList[i] == 1)



   #############################################################################
   def destroyFragData(self):
      for line in self.fragData:
         if not isinstance(line, basestring):
            # It's an SBD Object.  Destroy it.
            line.destroy()

   #############################################################################
   def isSecurePrintID(self):
      return hex_to_int(str(self.edtID.text()[:2])) > 127

   #############################################################################
   def verifyUserInput(self):
      self.fragData = []
      nError = 0
      rawBin = None

      sel = self.backupTypeButtonGroup.checkedId()
      rng = [-1]
      if   sel == self.backupTypeButtonGroup.id(self.version0Button):
         rng = range(8)
      elif sel == self.backupTypeButtonGroup.id(self.version135aButton) or \
           sel == self.backupTypeButtonGroup.id(self.version135aSPButton):
         rng = range(8, 12)
      elif sel == self.backupTypeButtonGroup.id(self.version135cButton) or \
           sel == self.backupTypeButtonGroup.id(self.version135cSPButton):
         rng = range(8, 10)


      if sel == self.backupTypeButtonGroup.id(self.version135aSPButton) or \
         sel == self.backupTypeButtonGroup.id(self.version135cSPButton):
         # Prepare the key mask parameters
         SECPRINT = HardcodedKeyMaskParams()
         securePrintCode = str(self.editSecurePrint.text()).strip()
         if not checkSecurePrintCode(self, SECPRINT, securePrintCode):
            return
      elif self.isSecurePrintID():
            QMessageBox.critical(self, 'Bad Encryption Code', self.tr(
               'The ID field indicates that this is a SecurePrint™ '
               'Backup Type. You have either entered the ID incorrectly or '
               'have chosen an incorrect Backup Type.'), QMessageBox.Ok)
            return
      for i in rng:
         hasError = False
         try:
            rawEntry = str(self.edtList[i].text())
            rawBin, err = readSixteenEasyBytes(rawEntry.replace(' ', ''))
            if err == 'Error_2+':
               hasError = True
            elif err == 'Fixed_1':
               nError += 1
         except KeyError:
            hasError = True

         if hasError:
            reply = QMessageBox.critical(self, self.tr('Verify Wallet ID'), self.tr(
               'There is an error in the data you entered that could not be '
               'fixed automatically.  Please double-check that you entered the '
               'text exactly as it appears on the wallet-backup page. <br><br> '
               'The error occured on the "%s" line.' % str(self.prfxList[i].text())), QMessageBox.Ok)
            LOGERROR('Error in wallet restore field')
            self.prfxList[i].setText('<font color="red">' + str(self.prfxList[i].text()) + '</font>')
            self.destroyFragData()
            return

         self.fragData.append(SecureBinaryData(rawBin))
         rawBin = None


      idLine = str(self.edtID.text()).replace(' ', '')
      self.fragData.insert(0, hex_to_binary(idLine))

      M, fnum, wltID, doMask, fid = ReadFragIDLineBin(self.fragData[0])

      reply = QMessageBox.question(self, self.tr('Verify Fragment ID'), self.tr(
         'The data you entered is for fragment: '
         '<br><br> <font color="%s" size=3><b>%s</b></font>  <br><br> '
         'Does this ID match the "Fragment:" field displayed on your backup? '
         'If not, click "No" and re-enter the fragment data.' % (htmlColor('TextBlue'), fid)), QMessageBox.Yes | QMessageBox.No)

      if reply == QMessageBox.Yes:
         self.accept()


################################################################################
def verifyRecoveryTestID(parent, computedWltID, expectedWltID=None):

   if expectedWltID == None:
      # Testing an arbitrary paper backup
      yesno = QMessageBox.question(parent, parent.tr('Recovery Test'), parent.tr(
         'From the data you entered, Armory calculated the following '
         'wallet ID: <font color="blue"><b>%s</b></font> '
         '<br><br>'
         'Does this match the wallet ID on the backup you are '
         'testing?' % computedWltID), QMessageBox.Yes | QMessageBox.No)

      if yesno == QMessageBox.No:
         QMessageBox.critical(parent, parent.tr('Bad Backup!'), parent.tr(
            'If this is your only backup and you are sure that you entered '
            'the data correctly, then it is <b>highly recommended you stop using '
            'this wallet!</b>  If this wallet currently holds any funds, '
            'you should move the funds to a wallet that <u>does</u> '
            'have a working backup. '
            '<br><br> <br><br>'
            'Wallet ID of the data you entered: %s <br>' % computedWltID), \
            QMessageBox.Ok)
      elif yesno == QMessageBox.Yes:
         MsgBoxCustom(MSGBOX.Good, parent.tr('Backup is Good!'), parent.tr(
            '<b>Your backup works!</b> '
            '<br><br>'
            'The wallet ID is computed from a combination of the root '
            'private key, the "chaincode" and the first address derived '
            'from those two pieces of data.  A matching wallet ID '
            'guarantees it will produce the same chain of addresses as '
            'the original.'))
   else:  # an expected wallet ID was supplied
      if not computedWltID == expectedWltID:
         QMessageBox.critical(parent, parent.tr('Bad Backup!'), parent.tr(
            'If you are sure that you entered the backup information '
            'correctly, then it is <b>highly recommended you stop using '
            'this wallet!</b>  If this wallet currently holds any funds, '
            'you should move the funds to a wallet that <u>does</u> '
            'have a working backup.'
            '<br><br>'
            'Computed wallet ID: %s <br>'
            'Expected wallet ID: %s <br><br>'
            'Is it possible that you loaded a different backup than the '
            'one you just made?' % (computedWltID, expectedWltID)), \
            QMessageBox.Ok)
      else:
         MsgBoxCustom(MSGBOX.Good, parent.tr('Backup is Good!'), parent.tr(
            'Your backup works! '
            '<br><br> '
            'The wallet ID computed from the data you entered matches '
            'the expected ID.  This confirms that the backup produces '
            'the same sequence of private keys as the original wallet! '
            '<br><br> '
            'Computed wallet ID: %s <br> '
            'Expected wallet ID: %s <br> '
            '<br>' % (computedWltID, expectedWltID )))

#################################################################################
class DlgFactoryReset(ArmoryDialog):
   def __init__(self, main=None, parent=None):
      super(DlgFactoryReset, self).__init__(parent, main)

      lblDescr = QRichLabel(self.tr(
         '<b><u>Armory Factory Reset</u></b> '
         '<br><br>'
         'It is <i>strongly</i> recommended that you make backups of your '
         'wallets before continuing, though <b>wallet files will never be '
         'intentionally deleted!</b>  All Armory '
         'wallet files, and the wallet.dat file used by Bitcoin Core/bitcoind '
         'should remain untouched in their current locations.  All Armory '
         'wallets will automatically be detected and loaded after the reset. '
         '<br><br>'
         'If you are not sure which option to pick, try the "lightest option" '
         'first, and see if your problems are resolved before trying the more '
         'extreme options.'))



      self.rdoSettings = QRadioButton()
      self.lblSettingsText = QRichLabel(self.tr(
         '<b>Delete settings and rescan (lightest option)</b>'))
      self.lblSettings = QRichLabel(self.tr(
         'Only delete the settings file and transient network data.  The '
         'databases built by Armory will be rescanned (about 5-45 minutes)'))

      self.rdoArmoryDB = QRadioButton()
      self.lblArmoryDBText = QRichLabel(self.tr('<b>Also delete databases and rebuild</b>'))
      self.lblArmoryDB = QRichLabel(self.tr(
         'Will delete settings, network data, and delete Armory\'s databases. The databases '
         'will be rebuilt and rescanned (45 min to 3 hours)'))

      self.rdoBitcoinDB = QRadioButton()
      self.lblBitcoinDBText = QRichLabel(self.tr('<b>Also re-download the blockchain (extreme)</b>'))
      self.lblBitcoinDB = QRichLabel(self.tr(
         'This will delete settings, network data, Armory\'s databases, '
         '<b>and</b> Bitcoin Core\'s databases.  Bitcoin Core will '
         'have to download the blockchain again. This can take 8-72 hours depending on your '
         'system\'s speed and connection.  Only use this if you '
         'suspect blockchain corruption, such as receiving StdOut/StdErr errors '
         'on the dashboard.'))


      self.chkSaveSettings = QCheckBox(self.tr('Do not delete settings files'))


      optFrames = []
      for rdo,txt,lbl in [ \
            [self.rdoSettings,  self.lblSettingsText,  self.lblSettings], \
            [self.rdoArmoryDB,  self.lblArmoryDBText,  self.lblArmoryDB], \
            [self.rdoBitcoinDB, self.lblBitcoinDBText, self.lblBitcoinDB]]:

         optLayout = QGridLayout()
         txt.setWordWrap(False)
         optLayout.addWidget(makeHorizFrame([rdo, txt, 'Stretch']))
         optLayout.addWidget(lbl, 1,0, 1,3)
         if len(optFrames)==2:
            # Add option to disable deleting settings, on most extreme option
            optLayout.addWidget(self.chkSaveSettings, 2,0, 1,3)
         optFrames.append(QFrame())
         optFrames[-1].setLayout(optLayout)
         optFrames[-1].setFrameStyle(STYLE_RAISED)


      self.rdoSettings.setChecked(True)

      btngrp = QButtonGroup(self)
      btngrp.addButton(self.rdoSettings)
      btngrp.addButton(self.rdoArmoryDB)
      btngrp.addButton(self.rdoBitcoinDB)

      frmDescr = makeHorizFrame([lblDescr], STYLE_SUNKEN)
      frmOptions = makeVertFrame(optFrames, STYLE_SUNKEN)

      self.btnOkay = QPushButton(self.tr('Continue'))
      self.btnCancel = QPushButton(self.tr('Cancel'))
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnOkay, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)
      self.connect(self.btnOkay, SIGNAL(CLICKED), self.clickedOkay)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)

      layout = QVBoxLayout()
      layout.addWidget(frmDescr)
      layout.addWidget(frmOptions)
      layout.addWidget(buttonBox)

      self.setLayout(layout)
      self.setMinimumWidth(600)
      self.setWindowTitle(self.tr('Factory Reset'))
      self.setWindowIcon(QIcon(self.main.iconfile))



   ###
   def clickedOkay(self):


      if self.rdoSettings.isChecked():
         reply = QMessageBox.warning(self, self.tr('Confirmation'), self.tr(
            'You are about to delete your settings and force Armory to rescan '
            'its databases.  Are you sure you want to do this?'), \
            QMessageBox.Cancel | QMessageBox.Ok)

         if not reply==QMessageBox.Ok:
            self.reject()
            return

         touchFile( os.path.join(ARMORY_HOME_DIR, 'rescan.flag') )
         touchFile( os.path.join(ARMORY_HOME_DIR, 'clearmempool.flag'))
         touchFile( os.path.join(ARMORY_HOME_DIR, 'delsettings.flag'))
         self.accept()

      elif self.rdoArmoryDB.isChecked():
         reply = QMessageBox.warning(self, self.tr('Confirmation'), self.tr(
            'You are about to delete your settings and force Armory to delete '
            'and rebuild its databases.  Are you sure you want to do this?'), \
            QMessageBox.Cancel | QMessageBox.Ok)

         if not reply==QMessageBox.Ok:
            self.reject()
            return

         touchFile( os.path.join(ARMORY_HOME_DIR, 'rebuild.flag') )
         touchFile( os.path.join(ARMORY_HOME_DIR, 'clearmempool.flag'))
         touchFile( os.path.join(ARMORY_HOME_DIR, 'delsettings.flag'))
         self.accept()

      elif self.rdoBitcoinDB.isChecked():
         msg = 'delete your settings and '

         if self.chkSaveSettings.isChecked():
            msg = self.tr(
               'You are about to delete <b>all</b> '
               'blockchain databases on your system.  The Bitcoin software will '
               'have to redownload all of the blockchain data over the peer-to-peer '
               'network again. This can take from 8 to 72 hours depending on '
               'your system\'s speed and connection.  <br><br><b>Are you absolutely '
               'sure you want to do this?</b>')
         else:
            msg = self.tr(
               'You are about to delete your settings and delete <b>all</b> '
               'blockchain databases on your system.  The Bitcoin software will '
               'have to redownload all of the blockchain data over the peer-to-peer '
               'network again. This can take from 8 to 72 hours depending on '
               'your system\'s speed and connection.  <br><br><b>Are you absolutely '
               'sure you want to do this?</b>')

         reply = QMessageBox.warning(self, self.tr('Confirmation'), msg, \
            QMessageBox.Cancel | QMessageBox.Yes)

         if not reply==QMessageBox.Yes:
            QMessageBox.warning(self, self.tr('Aborted'), self.tr(
                  'You canceled the factory reset operation.  No changes were '
                  'made.'), QMessageBox.Ok)
            self.reject()
            return


         if not self.main.settings.get('ManageSatoshi'):
            # Must have user shutdown Bitcoin sw now, and delete DBs now
            reply = MsgBoxCustom(MSGBOX.Warning, self.tr('Restart Armory'), self.tr(
               '<b>Bitcoin Core (or bitcoind) must be closed to do the reset!</b> '
               'Please close all Bitcoin software, <u><b>right now</b></u>, '
               'before clicking "Continue". '
               '<br><br>'
               'Armory will now close.  Please restart Bitcoin Core/bitcoind '
               'first and wait for it to finish synchronizing before restarting '
               'Armory.'), wCancel=True, yesStr="Continue")

            if not reply:
               QMessageBox.warning(self, self.tr('Aborted'), self.tr(
                  'You canceled the factory reset operation.  No changes were '
                  'made.'), QMessageBox.Ok)
               self.reject()
               return

            # Do the delete operation now
            deleteBitcoindDBs()
         else:
            reply = QMessageBox.warning(self, self.tr('Restart Armory'), self.tr(
               'Armory will now close to apply the requested changes.  Please '
               'restart it when you are ready to start the blockchain download '
               'again.'), QMessageBox.Ok)

            if not reply == QMessageBox.Ok:
               QMessageBox.warning(self, self.tr('Aborted'), self.tr(
                  'You canceled the factory reset operation.  No changes were '
                  'made.'), QMessageBox.Ok)
               self.reject()
               return

            touchFile( os.path.join(ARMORY_HOME_DIR, 'redownload.flag') )

         #  Always flag the rebuild, and del mempool and settings
         touchFile( os.path.join(ARMORY_HOME_DIR, 'rebuild.flag') )
         touchFile( os.path.join(ARMORY_HOME_DIR, 'clearmempool.flag'))
         if not self.chkSaveSettings.isChecked():
            touchFile( os.path.join(ARMORY_HOME_DIR, 'delsettings.flag'))
         self.accept()


      QMessageBox.information(self, self.tr('Restart Armory'), self.tr(
         'Armory will now close so that the requested changes can '
         'be applied.'), QMessageBox.Ok)
      self.accept()


#################################################################################
class DlgForkedImports(ArmoryDialog):
   def __init__(self, walletList, main=None, parent=None):
      super(DlgForkedImports, self).__init__(parent, main)

      descr1 = self.tr('<h2 style="color: red; text-align: center;">Forked imported addresses have been \
      detected in your wallets!!!</h2>')

      descr2 = self.tr('The following wallets have forked imported addresses: <br><br><b>') + \
      '<br>'.join(walletList) + '</b>'

      descr3 = self.tr('When you fix a corrupted wallet, any damaged private keys will be off \
      the deterministic chain. It means these private keys cannot be recreated \
      by your paper backup. If such private keys are encountered, Armory saves \
      them as forked imported private keys after it fixes the relevant wallets.')

      descr4 = self.tr('<h1 style="color: orange;"> - Do not accept payments to these wallets anymore<br>\
      - Do not delete or overwrite these wallets. <br> \
      - Transfer all funds to a fresh and backed up wallet</h1>')

      lblDescr1 = QRichLabel(descr1)
      lblDescr2 = QRichLabel(descr2)
      lblDescr3 = QRichLabel(descr3)
      lblDescr4 = QRichLabel(descr4)

      layout2 = QVBoxLayout()
      layout2.addWidget(lblDescr2)
      frame2 = QFrame()
      frame2.setLayout(layout2)
      frame2.setFrameStyle(QFrame.StyledPanel)

      layout4 = QVBoxLayout()
      layout4.addWidget(lblDescr4)
      frame4 = QFrame()
      frame4.setLayout(layout4)
      frame4.setFrameStyle(QFrame.StyledPanel)


      self.btnOk = QPushButton('Ok')
      self.connect(self.btnOk, SIGNAL('clicked()'), self.accept)


      layout = QVBoxLayout()
      layout.addWidget(lblDescr1)
      layout.addWidget(frame2)
      layout.addWidget(lblDescr3)
      layout.addWidget(frame4)
      layout.addWidget(self.btnOk)


      self.setLayout(layout)
      self.setMinimumWidth(600)
      self.setWindowTitle(self.tr('Forked Imported Addresses'))
###


################################################################################
class DlgBroadcastBlindTx(ArmoryDialog):
   def __init__(self, main=None, parent=None):
      super(DlgBroadcastBlindTx, self).__init__(parent, main)

      self.pytx = None
      self.txList = []

      lblDescr = QRichLabel(self.tr(
         'Copy a raw, hex-encoded transaction below to have Armory '
         'broadcast it to the Bitcoin network.  This function is '
         'provided as a convenience to expert users, and carries '
         'no guarantees of usefulness. '
         '<br><br>'
         'Specifically, be aware of the following limitations of '
         'this broadcast function: '
         '<ul>'
         '<li>The transaction will be "broadcast" by sending it '
         'to the connected Bitcon Core instance which will '
         'forward it to the rest of the Bitcoin network. '
         'However, if the transaction is non-standard or '
         'does not satisfy standard fee rules, Bitcoin Core '
         '<u>will</u> drop it and it '
         'will never be seen by the Bitcoin network. '
         '</li>'
         '<li>There will be no feedback as to whether the '
         'transaction succeeded.  You will have to verify the '
         'success of this operation via other means. '
         'However, if the transaction sends '
         'funds directly to or from an address in one of your '
         'wallets, it will still generate a notification and show '
         'up in your transaction history for that wallet. '
         '</li>'
         '</ul>'))

      self.txtRawTx = QPlainTextEdit()
      self.txtRawTx.setFont(GETFONT('Fixed', 9))
      w,h = relaxedSizeNChar(self.txtRawTx, 90)
      self.txtRawTx.setMinimumWidth(w)
      self.txtRawTx.setMinimumHeight(h*5)
      self.connect(self.txtRawTx, SIGNAL('textChanged()'), self.txChanged)

      lblTxInfo = QRichLabel(self.tr('Parsed Transaction:'))

      self.txtTxInfo = QPlainTextEdit()
      self.txtTxInfo.setFont(GETFONT('Fixed', 9))
      self.txtTxInfo.setMinimumWidth(w)
      self.txtTxInfo.setMinimumHeight(h*7)
      self.txtTxInfo.setReadOnly(True)

      self.lblInvalid = QRichLabel('')

      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.btnAdd    = QPushButton(self.tr("Add"))
      self.btnBroad  = QPushButton(self.tr("Broadcast"))
      self.btnBroad.setEnabled(False)
      self.connect(self.btnCancel, SIGNAL('clicked()'), self.reject)
      self.connect(self.btnAdd, SIGNAL('clicked()'), self.addTx)
      self.connect(self.btnBroad, SIGNAL('clicked()'), self.doBroadcast)
      frmButtons = makeHorizFrame(['Stretch', self.btnCancel, self.btnAdd, self.btnBroad])

      layout = QVBoxLayout()
      layout.addWidget(lblDescr)
      layout.addWidget(self.txtRawTx)
      layout.addWidget(lblTxInfo)
      layout.addWidget(self.txtTxInfo)
      layout.addWidget(self.lblInvalid)
      layout.addWidget(HLINE())
      layout.addWidget(frmButtons)

      self.setLayout(layout)
      self.setWindowTitle(self.tr("Broadcast Raw Transaction"))


   #############################################################################
   def txChanged(self):
      try:
         txt = str(self.txtRawTx.toPlainText()).strip()
         print (txt)
         txt = ''.join(txt.split())  # removes all whitespace
         self.pytx = PyTx().unserialize(hex_to_binary(txt))
         self.txtTxInfo.setPlainText(self.pytx.toString())
         LOGINFO('Valid tx entered:')
         LOGINFO(self.pytx.toString())
         self.setReady(True)
      except:
         LOGEXCEPT('Failed to parse tx')
         self.setReady(False)
         self.pytx = None

   #############################################################################
   def addTx(self):
      if self.pytx is not None:
         self.txList.append(self.pytx)

      self.txtRawTx.clear()

   #############################################################################
   def setReady(self, isTrue):
      self.btnBroad.setEnabled(isTrue)
      self.lblInvalid.setText("")
      if not isTrue:
         self.txtTxInfo.setPlainText('')
         if len(str(self.txtRawTx.toPlainText()).strip()) > 0:
            self.lblInvalid.setText(self.tr('<font color="%s"><b>Raw transaction '
            'is invalid!</font></b>' % htmlColor('TextWarn')))


   #############################################################################
   def doBroadcast(self):
      if self.pytx is not None:
         self.txList.append(self.pytx)

      rawTxList = []
      for txObj in self.txList:
         rawTxList.append(txObj.serialize())

      TheBridge.broadcastTx(rawTxList)

      ''' TODO: replace this with a tx broadcast successful popup notification
      txhash = self.pytx.getHash()


      hexhash = binary_to_hex(txhash, endOut=BIGENDIAN)
      if USE_TESTNET:
         linkToExplorer = 'https://blockexplorer.com/testnet/tx/%s' % hexhash
         dispToExplorer = 'https://blockexplorer.com/testnet/tx/%s...' % hexhash[:16]
      elif USE_REGTEST:
         linkToExplorer = ''
         dispToExplorer = ''
      else:
         linkToExplorer = 'https://blockchain.info/search/%s' % hexhash
         dispToExplorer = 'https://blockchain.info/search/%s...' % hexhash[:16]

      QMessageBox.information(self, self.tr("Broadcast!"), self.tr(
         'Your transaction was successfully sent to the local Bitcoin '
         'Core instance, though there is no guarantees that it was '
         'forwarded to the rest of the network.   On testnet, just about '
         'every valid transaction will successfully propagate.  On the '
         'main Bitcoin network, this will fail unless it was a standard '
         'transaction type. '
         'The transaction '
         'had the following hash: '
         '<br><br> '
         '%1 '
         '<br><br>'
         'You can check whether it was seen by other nodes on the network '
         'with the link below: '
         '<br><br>'
         '<a href="%2">%3</a>').arg(hexhash, linkToExplorer, dispToExplorer), QMessageBox.Ok)
      '''
      self.accept()

#################################################################################
class ArmorySplashScreen(QSplashScreen):
   def __init__(self, pixLogo):
      super(ArmorySplashScreen, self).__init__(pixLogo)

      css = """
            QProgressBar{ text-align: center; font-size: 8px; }
            """
      self.setStyleSheet(css)

      self.progressBar = QProgressBar(self)
      self.progressBar.setMaximum(100)
      self.progressBar.setMinimum(0)
      self.progressBar.setValue(0)
      self.progressBar.setMinimumWidth(self.width())
      self.progressBar.setMaximumHeight(10)
      self.progressBar.setFormat(self.tr("Loading: %d%s" % (int(self.progressBar.value()) * 10, "%")))

   def updateProgress(self, val):
      self.progressBar.setValue(val)

#############################################################################
class DlgRegAndTest(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgRegAndTest, self).__init__(parent, main)

      self.btcClose = QPushButton("Close")
      self.connect(self.btcClose, SIGNAL(CLICKED), self.close)
      btnBox = makeHorizFrame([STRETCH, self.btcClose])

      lblError = QRichLabel(self.tr('Error: You cannot run the Regression Test network and Bitcoin Test Network at the same time.'))

      dlgLayout = QVBoxLayout()
      frmBtn = makeHorizFrame([STRETCH, self.btcClose])
      frmAll = makeVertFrame([lblError, frmBtn])

      dlgLayout.addWidget(frmAll)
      self.setLayout(dlgLayout)
      self.setWindowTitle('Error')

   def close(self):
      self.main.abortLoad = True
      LOGERROR('User attempted to run regtest and testnet simultaneously')
      super(DlgRegAndTest, self).reject()

#############################################################################
class URLHandler(QObject):
   #@pyqtSignature("QUrl")
   def handleURL(self, link):
      DlgBrowserWarn(link.toString()).exec_()
