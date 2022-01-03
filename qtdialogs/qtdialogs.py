# -*- coding: UTF-8 -*-
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

################################################################################
#                                                                              #
# Copyright (C) 2011-2021, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

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

from qtdialogs.qtdefines import ArmoryDialog, USERMODE, GETFONT, \
   tightSizeStr, determineWalletType, WLTTYPES

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
class DlgChangePassphrase(ArmoryDialog):
   def __init__(self, parent=None, main=None, noPrevEncrypt=True):
      super(DlgChangePassphrase, self).__init__(parent, main)



      layout = QGridLayout()
      if noPrevEncrypt:
         lblDlgDescr = QLabel(self.tr('Please enter an passphrase for wallet encryption.\n\n'
                              'A good passphrase consists of at least 8 or more\n'
                              'random letters, or 5 or more random words.\n'))
         lblDlgDescr.setWordWrap(True)
         layout.addWidget(lblDlgDescr, 0, 0, 1, 2)
      else:
         lblDlgDescr = QLabel(self.tr("Change your wallet encryption passphrase"))
         layout.addWidget(lblDlgDescr, 0, 0, 1, 2)
         self.edtPasswdOrig = QLineEdit()
         self.edtPasswdOrig.setEchoMode(QLineEdit.Password)
         self.edtPasswdOrig.setMinimumWidth(MIN_PASSWD_WIDTH(self))
         lblCurrPasswd = QLabel(self.tr('Current Passphrase:'))
         layout.addWidget(lblCurrPasswd, 1, 0)
         layout.addWidget(self.edtPasswdOrig, 1, 1)



      lblPwd1 = QLabel(self.tr("New Passphrase:"))
      self.edtPasswd1 = QLineEdit()
      self.edtPasswd1.setEchoMode(QLineEdit.Password)
      self.edtPasswd1.setMinimumWidth(MIN_PASSWD_WIDTH(self))

      lblPwd2 = QLabel(self.tr("Again:"))
      self.edtPasswd2 = QLineEdit()
      self.edtPasswd2.setEchoMode(QLineEdit.Password)
      self.edtPasswd2.setMinimumWidth(MIN_PASSWD_WIDTH(self))

      layout.addWidget(lblPwd1, 2, 0)
      layout.addWidget(lblPwd2, 3, 0)
      layout.addWidget(self.edtPasswd1, 2, 1)
      layout.addWidget(self.edtPasswd2, 3, 1)

      self.lblMatches = QLabel(' ' * 20)
      self.lblMatches.setTextFormat(Qt.RichText)
      layout.addWidget(self.lblMatches, 4, 1)


      self.chkDisableCrypt = QCheckBox(self.tr('Disable encryption for this wallet'))
      if not noPrevEncrypt:
         self.connect(self.chkDisableCrypt, SIGNAL('toggled(bool)'), \
                      self.disablePassphraseBoxes)
         layout.addWidget(self.chkDisableCrypt, 4, 0)


      self.btnAccept = QPushButton(self.tr("Accept"))
      self.btnCancel = QPushButton(self.tr("Cancel"))
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnAccept, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)
      layout.addWidget(buttonBox, 5, 0, 1, 2)

      if noPrevEncrypt:
         self.setWindowTitle(self.tr("Set Encryption Passphrase"))
      else:
         self.setWindowTitle(self.tr("Change Encryption Passphrase"))

      self.setWindowIcon(QIcon(self.main.iconfile))

      self.setLayout(layout)

      self.connect(self.edtPasswd1, SIGNAL('textChanged(QString)'), \
                   self.checkPassphrase)
      self.connect(self.edtPasswd2, SIGNAL('textChanged(QString)'), \
                   self.checkPassphrase)

      self.connect(self.btnAccept, SIGNAL(CLICKED), \
                   self.checkPassphraseFinal)

      self.connect(self.btnCancel, SIGNAL(CLICKED), \
                   self, SLOT('reject()'))


   def disablePassphraseBoxes(self, noEncrypt=True):
      self.edtPasswd1.setEnabled(not noEncrypt)
      self.edtPasswd2.setEnabled(not noEncrypt)


   def checkPassphrase(self):
      if self.chkDisableCrypt.isChecked():
         return True
      p1 = self.edtPasswd1.text()
      p2 = self.edtPasswd2.text()
      goodColor = htmlColor('TextGreen')
      badColor = htmlColor('TextRed')
      if not isASCII(p1) or \
         not isASCII(p2):
         self.lblMatches.setText(self.tr('<font color=%s><b>Passphrase is non-ASCII!</b></font>' % badColor))
         return False
      if not p1 == p2:
         self.lblMatches.setText(self.tr('<font color=%s><b>Passphrases do not match!</b></font>' % badColor))
         return False
      if len(p1) < 5:
         self.lblMatches.setText(self.tr('<font color=%s><b>Passphrase is too short!</b></font>' % badColor))
         return False
      self.lblMatches.setText(self.tr('<font color=%s><b>Passphrases match!</b></font>' % goodColor))
      return True


   def checkPassphraseFinal(self):
      if self.chkDisableCrypt.isChecked():
         self.accept()
      else:
         if self.checkPassphrase():
            dlg = DlgPasswd3(self, self.main)
            if dlg.exec_():
               if not str(dlg.edtPasswd3.text()) == str(self.edtPasswd1.text()):
                  QMessageBox.critical(self, self.tr('Invalid Passphrase'), \
                     self.tr('You entered your confirmation passphrase incorrectly!'), QMessageBox.Ok)
               else:
                  self.accept()
            else:
               self.reject()



class DlgPasswd3(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgPasswd3, self).__init__(parent, main)


      lblWarnImgL = QLabel()
      lblWarnImgL.setPixmap(QPixmap('./img/MsgBox_warning48.png'))
      lblWarnImgL.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      lblWarnTxt1 = QRichLabel(\
         self.tr('<font color="red"><b>!!! DO NOT FORGET YOUR PASSPHRASE !!!</b></font>'), size=4)
      lblWarnTxt1.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      lblWarnTxt2 = QRichLabel(self.tr(
        '<b>No one can help you recover you bitcoins if you forget the '
         'passphrase and don\'t have a paper backup!</b> Your wallet and '
         'any <u>digital</u> backups are useless if you forget it.  '
         '<br><br>'
         'A <u>paper</u> backup protects your wallet forever, against '
         'hard-drive loss and losing your passphrase.  It also protects you '
         'from theft, if the wallet was encrypted and the paper backup '
         'was not stolen with it.  Please make a paper backup and keep it in '
         'a safe place.'
         '<br><br>'
         '<b>Please enter your passphrase a third time to indicate that you '
         'are aware of the risks of losing your passphrase!</b>'), doWrap=True)


      self.edtPasswd3 = QLineEdit()
      self.edtPasswd3.setEchoMode(QLineEdit.Password)
      self.edtPasswd3.setMinimumWidth(MIN_PASSWD_WIDTH(self))

      bbox = QDialogButtonBox()
      btnOk = QPushButton(self.tr('Accept'))
      btnNo = QPushButton(self.tr('Cancel'))
      self.connect(btnOk, SIGNAL(CLICKED), self.accept)
      self.connect(btnNo, SIGNAL(CLICKED), self.reject)
      bbox.addButton(btnOk, QDialogButtonBox.AcceptRole)
      bbox.addButton(btnNo, QDialogButtonBox.RejectRole)
      layout = QGridLayout()
      layout.addWidget(lblWarnImgL, 0, 0, 4, 1)
      layout.addWidget(lblWarnTxt1, 0, 1, 1, 1)
      layout.addWidget(lblWarnTxt2, 2, 1, 1, 1)
      layout.addWidget(self.edtPasswd3, 5, 1, 1, 1)
      layout.addWidget(bbox, 6, 1, 1, 2)
      self.setLayout(layout)
      self.setWindowTitle(self.tr('WARNING!'))



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


class GfxItemQRCode(QGraphicsItem):
   """
   Converts binary data to base58, and encodes the Base58 characters in
   the QR-code.  It seems weird to use Base58 instead of binary, but the
   QR-code has no problem with the size, instead, we want the data in the
   QR-code to match exactly what is human-readable on the page, which is
   in Base58.

   You must supply exactly one of "totalSize" or "modSize".  TotalSize
   guarantees that the QR code will fit insides box of a given size.
   ModSize is how big each module/pixel of the QR code is, which means
   that a bigger QR block results in a bigger physical size on paper.
   """
   def __init__(self, rawDataToEncode, maxSize=None):
      super(GfxItemQRCode, self).__init__()
      self.maxSize = maxSize
      self.updateQRData(rawDataToEncode)

   def boundingRect(self):
      return self.Rect

   def updateQRData(self, toEncode, maxSize=None):
      if maxSize == None:
         maxSize = self.maxSize
      else:
         self.maxSize = maxSize

      self.qrmtrx, self.modCt = CreateQRMatrix(toEncode, 'H')
      self.modSz = round(float(self.maxSize) / float(self.modCt) - 0.5)
      totalSize = self.modCt * self.modSz
      self.Rect = QRectF(0, 0, totalSize, totalSize)

   def paint(self, painter, option, widget=None):
      painter.setPen(Qt.NoPen)
      painter.setBrush(QBrush(QColor(0, 0, 0)))

      for r in range(self.modCt):
         for c in range(self.modCt):
            if self.qrmtrx[r][c] > 0:
               painter.drawRect(*[self.modSz * a for a in [r, c, 1, 1]])


class SimplePrintableGraphicsScene(object):


   def __init__(self, parent, main):
      """
      We use the following coordinates:

            -----> +x
            |
            |
            V +y

      """
      self.parent = parent
      self.main = main

      self.INCH = 72
      self.PAPER_A4_WIDTH = 8.5 * self.INCH
      self.PAPER_A4_HEIGHT = 11.0 * self.INCH
      self.MARGIN_PIXELS = 0.6 * self.INCH

      self.PAGE_BKGD_COLOR = QColor(255, 255, 255)
      self.PAGE_TEXT_COLOR = QColor(0, 0, 0)

      self.fontFix = GETFONT('Courier', 9)
      self.fontVar = GETFONT('Times', 10)

      self.gfxScene = QGraphicsScene(self.parent)
      self.gfxScene.setSceneRect(0, 0, self.PAPER_A4_WIDTH, self.PAPER_A4_HEIGHT)
      self.gfxScene.setBackgroundBrush(self.PAGE_BKGD_COLOR)

      # For when it eventually makes it to the printer
      # self.printer = QPrinter(QPrinter.HighResolution)
      # self.printer.setPageSize(QPrinter.Letter)
      # self.gfxPainter = QPainter(self.printer)
      # self.gfxPainter.setRenderHint(QPainter.TextAntialiasing)
      # self.gfxPainter.setPen(Qt.NoPen)
      # self.gfxPainter.setBrush(QBrush(self.PAGE_TEXT_COLOR))

      self.cursorPos = QPointF(self.MARGIN_PIXELS, self.MARGIN_PIXELS)
      self.lastCursorMove = (0, 0)


   def getCursorXY(self):
      return (self.cursorPos.x(), self.cursorPos.y())

   def getScene(self):
      return self.gfxScene

   def pageRect(self):
      marg = self.MARGIN_PIXELS
      return QRectF(marg, marg, self.PAPER_A4_WIDTH - marg, self.PAPER_A4_HEIGHT - marg)

   def insidePageRect(self, pt=None):
      if pt == None:
         pt = self.cursorPos

      return self.pageRect.contains(pt)

   def moveCursor(self, dx, dy, absolute=False):
      xOld, yOld = self.getCursorXY()
      if absolute:
         self.cursorPos = QPointF(dx, dy)
         self.lastCursorMove = (dx - xOld, dy - yOld)
      else:
         self.cursorPos = QPointF(xOld + dx, yOld + dy)
         self.lastCursorMove = (dx, dy)


   def resetScene(self):
      self.gfxScene.clear()
      self.resetCursor()

   def resetCursor(self):
      self.cursorPos = QPointF(self.MARGIN_PIXELS, self.MARGIN_PIXELS)


   def newLine(self, extra_dy=0):
      xOld, yOld = self.getCursorXY()
      xNew = self.MARGIN_PIXELS
      yNew = self.cursorPos.y() + self.lastItemSize[1] + extra_dy - 5
      self.moveCursor(xNew - xOld, yNew - yOld)


   def drawHLine(self, width=None, penWidth=1):
      if width == None:
         width = 3 * self.INCH
      currX, currY = self.getCursorXY()
      lineItem = QGraphicsLineItem(currX, currY, currX + width, currY)
      pen = QPen()
      pen.setWidth(penWidth)
      lineItem.setPen(pen)
      self.gfxScene.addItem(lineItem)
      rect = lineItem.boundingRect()
      self.lastItemSize = (rect.width(), rect.height())
      self.moveCursor(rect.width(), 0)
      return self.lastItemSize

   def drawRect(self, w, h, edgeColor=QColor(0, 0, 0), fillColor=None, penWidth=1):
      rectItem = QGraphicsRectItem(self.cursorPos.x(), self.cursorPos.y(), w, h)
      if edgeColor == None:
         rectItem.setPen(QPen(Qt.NoPen))
      else:
         pen = QPen(edgeColor)
         pen.setWidth(penWidth)
         rectItem.setPen(pen)

      if fillColor == None:
         rectItem.setBrush(QBrush(Qt.NoBrush))
      else:
         rectItem.setBrush(QBrush(fillColor))

      self.gfxScene.addItem(rectItem)
      rect = rectItem.boundingRect()
      self.lastItemSize = (rect.width(), rect.height())
      self.moveCursor(rect.width(), 0)
      return self.lastItemSize


   def drawText(self, txt, font=None, wrapWidth=None, useHtml=True):
      if font == None:
         font = GETFONT('Var', 9)
      txtItem = QGraphicsTextItem('')
      if useHtml:
         txtItem.setHtml(toUnicode(txt))
      else:
         txtItem.setPlainText(toUnicode(txt))
      txtItem.setDefaultTextColor(self.PAGE_TEXT_COLOR)
      txtItem.setPos(self.cursorPos)
      txtItem.setFont(font)
      if not wrapWidth == None:
         txtItem.setTextWidth(wrapWidth)
      self.gfxScene.addItem(txtItem)
      rect = txtItem.boundingRect()
      self.lastItemSize = (rect.width(), rect.height())
      self.moveCursor(rect.width(), 0)
      return self.lastItemSize

   def drawPixmapFile(self, pixFn, sizePx=None):
      pix = QPixmap(pixFn)
      if not sizePx == None:
         pix = pix.scaled(sizePx, sizePx)
      pixItem = QGraphicsPixmapItem(pix)
      pixItem.setPos(self.cursorPos)
      pixItem.setMatrix(QMatrix())
      self.gfxScene.addItem(pixItem)
      rect = pixItem.boundingRect()
      self.lastItemSize = (rect.width(), rect.height())
      self.moveCursor(rect.width(), 0)
      return self.lastItemSize

   def drawQR(self, qrdata, size=150):
      objQR = GfxItemQRCode(qrdata, size)
      objQR.setPos(self.cursorPos)
      objQR.setMatrix(QMatrix())
      self.gfxScene.addItem(objQR)
      rect = objQR.boundingRect()
      self.lastItemSize = (rect.width(), rect.height())
      self.moveCursor(rect.width(), 0)
      return self.lastItemSize


   def drawColumn(self, strList, rowHeight=None, font=None, useHtml=True):
      """
      This draws a bunch of left-justified strings in a column.  It returns
      a tight bounding box around all elements in the column, which can easily
      be used to start the next column.  The rowHeight is returned, and also
      an available input, in case you are drawing text/font that has a different
      height in each column, and want to make sure they stay aligned.

      Just like the other methods, this leaves the cursor sitting at the
      original y-value, but shifted to the right by the width of the column.
      """
      origX, origY = self.getCursorXY()
      maxColWidth = 0
      cumulativeY = 0
      for r in strList:
         szX, szY = self.drawText(r, font=font, useHtml=useHtml)
         prevY = self.cursorPos.y()
         if rowHeight == None:
            self.newLine()
            szY = self.cursorPos.y() - prevY
            self.moveCursor(origX - self.MARGIN_PIXELS, 0)
         else:
            self.moveCursor(-szX, rowHeight)
         maxColWidth = max(maxColWidth, szX)
         cumulativeY += szY

      if rowHeight == None:
         rowHeight = float(cumulativeY) / len(strList)

      self.moveCursor(origX + maxColWidth, origY, absolute=True)

      return [QRectF(origX, origY, maxColWidth, cumulativeY), rowHeight]



class DlgPrintBackup(ArmoryDialog):
   """
   Open up a "Make Paper Backup" dialog, so the user can print out a hard
   copy of whatever data they need to recover their wallet should they lose
   it.

   This method is kind of a mess, because it ended up having to support
   printing of single-sheet, imported keys, single fragments, multiple
   fragments, with-or-without SecurePrint.
   """
   def __init__(self, parent, main, wlt, printType='SingleSheet', \
                                    fragMtrx=[], fragMtrxCrypt=[], fragData=[],
                                    privKey=None, chaincode=None):
      super(DlgPrintBackup, self).__init__(parent, main)


      self.wlt = wlt
      self.binImport = []
      self.fragMtrx = fragMtrx

      self.doPrintFrag = printType.lower().startswith('frag')
      self.fragMtrx = fragMtrx
      self.fragMtrxCrypt = fragMtrxCrypt
      self.fragData = fragData
      if self.doPrintFrag:
         self.doMultiFrag = len(fragData['Range']) > 1

      self.backupData = None
      def resumeSetup(rootData):
         self.backupData = rootData
         self.emit(SIGNAL('backupSetupSignal'))

      self.connect(self, SIGNAL('backupSetupSignal'), self.setup)
      rootData = self.wlt.createBackupString(resumeSetup)

   ###
   def setup(self):
      # This badBackup stuff was implemented to avoid making backups if there is
      # an inconsistency in the data.  Yes, this is like a goto!
      if self.backupData == None:
         LOGEXCEPT("Problem with private key and/or chaincode.  Aborting.")
         QMessageBox.critical(self, self.tr("Error Creating Backup"), self.tr(
            'There was an error with the backup creator.  The operation is being '
            'canceled to avoid making bad backups!'), QMessageBox.Ok)
         return

      # A self-evident check of whether we need to print the chaincode.
      # If we derive the chaincode from the private key, and it matches
      # what's already in the wallet, we obviously don't need to print it!
      self.noNeedChaincode = (len(self.backupData.chainclear) == 0)

      # Save off imported addresses in case they need to be printed, too
      for a160, addr in self.wlt.addrMap.items():
         if addr.chainIndex == -2:
            if addr.binPrivKey32_Plain.getSize() == 33 or addr.isCompressed():
               prv = addr.binPrivKey32_Plain.toBinStr()[:32]
               self.binImport.append([a160, SecureBinaryData(prv), 1])
               prv = None
            else:
               self.binImport.append([a160, addr.binPrivKey32_Plain.copy(), 0])


      tempTxtItem = QGraphicsTextItem('')
      tempTxtItem.setPlainText(toUnicode('0123QAZjqlmYy'))
      tempTxtItem.setFont(GETFONT('Fix', 7))
      self.importHgt = tempTxtItem.boundingRect().height() - 5


      # Create the scene and the view.
      self.scene = SimplePrintableGraphicsScene(self, self.main)
      self.view = QGraphicsView()
      self.view.setRenderHint(QPainter.TextAntialiasing)
      self.view.setScene(self.scene.getScene())


      self.chkImportPrint = QCheckBox(self.tr('Print imported keys'))
      self.connect(self.chkImportPrint, SIGNAL(CLICKED), self.clickImportChk)

      self.lblPageStr = QRichLabel(self.tr('Page:'))
      self.comboPageNum = QComboBox()
      self.lblPageMaxStr = QRichLabel('')
      self.connect(self.comboPageNum, SIGNAL('activated(int)'), self.redrawBackup)

      # We enable printing of imported addresses but not frag'ing them.... way
      # too much work for everyone (developer and user) to deal with 2x or 3x
      # the amount of data to type
      self.chkImportPrint.setVisible(len(self.binImport) > 0 and not self.doPrintFrag)
      self.lblPageStr.setVisible(False)
      self.comboPageNum.setVisible(False)
      self.lblPageMaxStr.setVisible(False)

      self.chkSecurePrint = QCheckBox(self.trUtf8(u'Use SecurePrint\u200b\u2122 to prevent exposing keys to printer or other '
         'network devices'))

      if(self.doPrintFrag):
         self.chkSecurePrint.setChecked(self.fragData['Secure'])

      self.ttipSecurePrint = self.main.createToolTipWidget(self.trUtf8(
         u'SecurePrint\u200b\u2122 encrypts your backup with a code displayed on '
         'the screen, so that no other devices on your network see the sensitive '
         'data when you send it to the printer.  If you turn on '
         u'SecurePrint\u200b\u2122 <u>you must write the code on the page after '
         'it is done printing!</u>  There is no point in using this feature if '
         'you copy the data by hand.'))

      self.lblSecurePrint = QRichLabel(self.trUtf8(
         u'<b><font color="%s"><u>IMPORTANT:</u></b>  You must write the SecurePrint\u200b\u2122 '
         u'encryption code on each printed backup page!  Your SecurePrint\u200b\u2122 code is </font> '
         '<font color="%s">%s</font>.  <font color="%s">Your backup will not work '
         'if this code is lost!</font>' % (htmlColor('TextWarn'), htmlColor('TextBlue'), \
         self.backupData.sppass, htmlColor('TextWarn'))))

      self.connect(self.chkSecurePrint, SIGNAL("clicked()"), self.redrawBackup)


      self.btnPrint = QPushButton('&Print...')
      self.btnPrint.setMinimumWidth(3 * tightSizeStr(self.btnPrint, 'Print...')[0])
      self.btnCancel = QPushButton('&Cancel')
      self.connect(self.btnPrint, SIGNAL(CLICKED), self.print_)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.accept)

      if self.doPrintFrag:
         M, N = self.fragData['M'], self.fragData['N']
         lblDescr = QRichLabel(self.tr(
            '<b><u>Print Wallet Backup Fragments</u></b><br><br> '
            'When any %s of these fragments are combined, all <u>previous '
            '<b>and</b> future</u> addresses generated by this wallet will be '
            'restored, giving you complete access to your bitcoins.  The '
            'data can be copied by hand if a working printer is not '
            'available.  Please make sure that all data lines contain '
            '<b>9 columns</b> '
            'of <b>4 characters each</b> (excluding "ID" lines).' % M))
      else:
         withChain = '' if self.noNeedChaincode else 'and "Chaincode"'
         lblDescr = QRichLabel(self.tr(
            '<b><u>Print a Forever-Backup</u></b><br><br> '
            'Printing this sheet protects all <u>previous <b>and</b> future</u> addresses '
            'generated by this wallet!  You can copy the "Root Key" %s '
            'by hand if a working printer is not available.  Please make sure that '
            'all data lines contain <b>9 columns</b> '
            'of <b>4 characters each</b>.' % withChain))

      lblDescr.setContentsMargins(5, 5, 5, 5)
      frmDescr = makeHorizFrame([lblDescr], STYLE_RAISED)

      self.redrawBackup()
      frmChkImport = makeHorizFrame([self.chkImportPrint, \
                                     STRETCH, \
                                     self.lblPageStr, \
                                     self.comboPageNum, \
                                     self.lblPageMaxStr])

      frmSecurePrint = makeHorizFrame([self.chkSecurePrint,
                                       self.ttipSecurePrint,
                                       STRETCH])

      frmButtons = makeHorizFrame([self.btnCancel, STRETCH, self.btnPrint])

      layout = QVBoxLayout()
      layout.addWidget(frmDescr)
      layout.addWidget(frmChkImport)
      layout.addWidget(self.view)
      layout.addWidget(frmSecurePrint)
      layout.addWidget(self.lblSecurePrint)
      layout.addWidget(frmButtons)
      setLayoutStretch(layout, 0, 1, 0, 0, 0)

      self.setLayout(layout)

      self.setWindowIcon(QIcon('./img/printer_icon.png'))
      self.setWindowTitle('Print Wallet Backup')


      # Apparently I can't programmatically scroll until after it's painted
      def scrollTop():
         vbar = self.view.verticalScrollBar()
         vbar.setValue(vbar.minimum())
      self.callLater(0.01, scrollTop)

   def redrawBackup(self):
      cmbPage = 1
      if self.comboPageNum.count() > 0:
         cmbPage = int(str(self.comboPageNum.currentText()))

      if self.doPrintFrag:
         cmbPage -= 1
         if not self.doMultiFrag:
            cmbPage = self.fragData['Range'][0]
         elif self.comboPageNum.count() > 0:
            cmbPage = int(str(self.comboPageNum.currentText())) - 1

         self.createPrintScene('Fragmented Backup', cmbPage)
      else:
         pgSelect = cmbPage if self.chkImportPrint.isChecked() else 1
         if pgSelect == 1:
            self.createPrintScene('SingleSheetFirstPage', '')
         else:
            pg = pgSelect - 2
            nKey = self.maxKeysPerPage
            self.createPrintScene('SingleSheetImported', [pg * nKey, (pg + 1) * nKey])


      showPageCombo = self.chkImportPrint.isChecked() or \
                      (self.doPrintFrag and self.doMultiFrag)
      self.showPageSelect(showPageCombo)
      self.view.update()




   def clickImportChk(self):
      if self.numImportPages > 1 and self.chkImportPrint.isChecked():
         ans = QMessageBox.warning(self, self.tr('Lots to Print!'), self.tr(
            'This wallet contains <b>%d</b> imported keys, which will require '
            '<b>%d</b> pages to print.  Not only will this use a lot of paper, '
            'it will be a lot of work to manually type in these keys in the '
            'event that you need to restore this backup. It is recommended '
            'that you do <u>not</u> print your imported keys and instead make '
            'a digital backup, which can be restored instantly if needed. '
            '<br><br> Do you want to print the imported keys, anyway?' % (len(self.binImport), self.numImportPages)), \
            QMessageBox.Yes | QMessageBox.No)
         if not ans == QMessageBox.Yes:
            self.chkImportPrint.setChecked(False)

      showPageCombo = self.chkImportPrint.isChecked() or \
                      (self.doPrintFrag and self.doMultiFrag)
      self.showPageSelect(showPageCombo)
      self.comboPageNum.setCurrentIndex(0)
      self.redrawBackup()


   def showPageSelect(self, doShow=True):
      MARGIN = self.scene.MARGIN_PIXELS
      bottomOfPage = self.scene.pageRect().height() + MARGIN
      totalHgt = bottomOfPage - self.bottomOfSceneHeader
      self.maxKeysPerPage = int(totalHgt / (self.importHgt))
      self.numImportPages = int((len(self.binImport) - 1) / self.maxKeysPerPage) + 1
      if self.comboPageNum.count() == 0:
         if self.doPrintFrag:
            numFrag = len(self.fragData['Range'])
            for i in range(numFrag):
               self.comboPageNum.addItem(str(i + 1))
            self.lblPageMaxStr.setText(self.tr('of %d' % numFrag))
         else:
            for i in range(self.numImportPages + 1):
               self.comboPageNum.addItem(str(i + 1))
            self.lblPageMaxStr.setText(self.tr('of %d' % (self.numImportPages + 1)))


      self.lblPageStr.setVisible(doShow)
      self.comboPageNum.setVisible(doShow)
      self.lblPageMaxStr.setVisible(doShow)




   def print_(self):
      LOGINFO('Printing!')
      self.printer = QPrinter(QPrinter.HighResolution)
      self.printer.setPageSize(QPrinter.Letter)

      if QPrintDialog(self.printer).exec_():
         painter = QPainter(self.printer)
         painter.setRenderHint(QPainter.TextAntialiasing)

         if self.doPrintFrag:
            for i in self.fragData['Range']:
               self.createPrintScene('Fragment', i)
               self.scene.getScene().render(painter)
               if not i == len(self.fragData['Range']) - 1:
                  self.printer.newPage()

         else:
            self.createPrintScene('SingleSheetFirstPage', '')
            self.scene.getScene().render(painter)

            if len(self.binImport) > 0 and self.chkImportPrint.isChecked():
               nKey = self.maxKeysPerPage
               for i in range(self.numImportPages):
                  self.printer.newPage()
                  self.createPrintScene('SingleSheetImported', [i * nKey, (i + 1) * nKey])
                  self.scene.getScene().render(painter)

         painter.end()

         # The last scene printed is what's displayed now.  Set the combo box
         self.comboPageNum.setCurrentIndex(self.comboPageNum.count() - 1)

         if self.chkSecurePrint.isChecked():
            QMessageBox.warning(self, self.tr('SecurePrint Code'), self.trUtf8(
               u'<br><b>You must write your SecurePrint\u200b\u2122 '
               'code on each sheet of paper you just printed!</b> '
               'Write it in the red box in upper-right corner '
               u'of each printed page. <br><br>SecurePrint\u200b\u2122 code: '
               '<font color="%s" size=5><b>%s</b></font> <br><br> '
               '<b>NOTE: the above code <u>is</u> case-sensitive!</b>' % (htmlColor('TextBlue'), self.randpass.toBinStr())), \
               QMessageBox.Ok)
         if self.chkSecurePrint.isChecked():
            self.btnCancel.setText('Done')
         else:
            self.accept()


   def cleanup(self):
      self.backupData = None

      for x, y in self.fragMtrxCrypt:
         x.destroy()
         y.destroy()

   def accept(self):
      self.cleanup()
      super(DlgPrintBackup, self).accept()

   def reject(self):
      self.cleanup()
      super(DlgPrintBackup, self).reject()


   #############################################################################
   #############################################################################
   def createPrintScene(self, printType, printData):
      self.scene.gfxScene.clear()
      self.scene.resetCursor()

      pr = self.scene.pageRect()
      self.scene.drawRect(pr.width(), pr.height(), edgeColor=None, fillColor=QColor(255, 255, 255))
      self.scene.resetCursor()


      INCH = self.scene.INCH
      MARGIN = self.scene.MARGIN_PIXELS

      doMask = self.chkSecurePrint.isChecked()

      if USE_TESTNET or USE_REGTEST:
         self.scene.drawPixmapFile('./img/armory_logo_green_h56.png')
      else:
         self.scene.drawPixmapFile('./img/armory_logo_h36.png')
      self.scene.newLine()

      self.scene.drawText('Paper Backup for Armory Wallet', GETFONT('Var', 11))
      self.scene.newLine()

      self.scene.newLine(extra_dy=20)
      self.scene.drawHLine()
      self.scene.newLine(extra_dy=20)


      ssType = self.trUtf8(u' (SecurePrint\u200b\u2122)') if doMask else self.tr(' (Unencrypted)')
      if printType == 'SingleSheetFirstPage':
         bType = self.tr('Single-Sheet') # %s' % ssType)
      elif printType == 'SingleSheetImported':
         bType = self.tr('Imported Keys %s' % ssType)
      elif printType.lower().startswith('frag'):
         m_count = str(self.fragData['M'])
         n_count = str(self.fragData['N'])
         bstr = self.tr('Fragmented Backup (%s-of-%s)' % (m_count, n_count))
         bType = bstr + ' ' + ssType

      if printType.startswith('SingleSheet'):
         colRect, rowHgt = self.scene.drawColumn(['Wallet Version:', 'Wallet ID:', \
                                                   'Wallet Name:', 'Backup Type:'])
         self.scene.moveCursor(15, 0)
         suf = 'c' if self.noNeedChaincode else 'a'
         colRect, rowHgt = self.scene.drawColumn(['1.35' + suf, self.wlt.uniqueIDB58, \
                                                   self.wlt.labelName, bType])
         self.scene.moveCursor(15, colRect.y() + colRect.height(), absolute=True)
      else:
         colRect, rowHgt = self.scene.drawColumn(['Wallet Version:', 'Wallet ID:', \
                                                   'Wallet Name:', 'Backup Type:', \
                                                   'Fragment:'])
         baseID = self.fragData['FragIDStr']
         fragNum = printData + 1
         fragID = '<b>%s-<font color="%s">#%d</font></b>' % (baseID, htmlColor('TextBlue'), fragNum)
         self.scene.moveCursor(15, 0)
         suf = 'c' if self.noNeedChaincode else 'a'
         colRect, rowHgt = self.scene.drawColumn(['1.35' + suf, self.wlt.uniqueIDB58, \
                                                   self.wlt.labelName, bType, fragID])
         self.scene.moveCursor(15, colRect.y() + colRect.height(), absolute=True)


      # Display warning about unprotected key data
      wrap = 0.9 * self.scene.pageRect().width()

      if self.doPrintFrag:
         warnMsg = self.tr(
            'Any subset of <font color="%s"><b>%s</b></font> fragments with this '
            'ID (<font color="%s"><b>%s</b></font>) are sufficient to recover all the '
            'coins contained in this wallet.  To optimize the physical security of '
            'your wallet, please store the fragments in different locations.' % (htmlColor('TextBlue'), \
                           str(self.fragData['M']), htmlColor('TextBlue'), self.fragData['FragIDStr']))
      else:
         container = 'this wallet' if printType == 'SingleSheetFirstPage' else 'these addresses'
         warnMsg = self.tr(
            '<font color="#aa0000"><b>WARNING:</b></font> Anyone who has access to this '
            'page has access to all the bitcoins in %s!  Please keep this '
            'page in a safe place.' % container)

      self.scene.newLine()
      self.scene.drawText(warnMsg, GETFONT('Var', 9), wrapWidth=wrap)

      self.scene.newLine(extra_dy=20)
      self.scene.drawHLine()
      self.scene.newLine(extra_dy=20)

      if self.doPrintFrag:
         numLine = 'three' if self.noNeedChaincode else 'five'
      else:
         numLine = 'two' if self.noNeedChaincode else 'four'

      if printType == 'SingleSheetFirstPage':
         descrMsg = self.tr(
            'The following %s lines backup all addresses '
            '<i>ever generated</i> by this wallet (previous and future). '
            'This can be used to recover your wallet if you forget your passphrase or '
            'suffer hardware failure and lose your wallet files.' % numLine)
      elif printType == 'SingleSheetImported':
         if self.chkSecurePrint.isChecked():
            descrMsg = self.trUtf8(
               'The following is a list of all private keys imported into your '
               'wallet before this backup was made.   These keys are encrypted '
               u'with the SecurePrint\u200b\u2122 code and can only be restored '
               'by entering them into Armory.  Print a copy of this backup without '
               u'the SecurePrint\u200b\u2122 option if you want to be able to import '
               'them into another application.')
         else:
            descrMsg = self.tr(
               'The following is a list of all private keys imported into your '
               'wallet before this backup was made.  Each one must be copied '
               'manually into the application where you wish to import them.')
      elif printType.lower().startswith('frag'):
         fragNum = printData + 1
         descrMsg = self.tr(
            'The following is fragment <font color="%s"><b>#%s</b></font> for this '
            'wallet.' % (htmlColor('TextBlue'), str(printData + 1)))


      self.scene.drawText(descrMsg, GETFONT('var', 8), wrapWidth=wrap)
      self.scene.newLine(extra_dy=10)

      ###########################################################################
      # Draw the SecurePrint box if needed, frag pie, then return cursor
      prevCursor = self.scene.getCursorXY()

      self.lblSecurePrint.setVisible(doMask)
      if doMask:
         self.scene.resetCursor()
         self.scene.moveCursor(4.0 * INCH, 0)
         spWid, spHgt = 2.75 * INCH, 1.5 * INCH,
         if doMask:
            self.scene.drawRect(spWid, spHgt, edgeColor=QColor(180, 0, 0), penWidth=3)

         self.scene.resetCursor()
         self.scene.moveCursor(4.07 * INCH, 0.07 * INCH)

         self.scene.drawText(self.trUtf8(
            '<b><font color="#770000">CRITICAL:</font>  This backup will not '
            u'work without the SecurePrint\u200b\u2122 '
            'code displayed on the screen during printing. '
            'Copy it here in ink:'), wrapWidth=spWid * 0.93, font=GETFONT('Var', 7))

         self.scene.newLine(extra_dy=8)
         self.scene.moveCursor(4.07 * INCH, 0)
         codeWid, codeHgt = self.scene.drawText('Code:')
         self.scene.moveCursor(0, codeHgt - 3)
         wid = spWid - codeWid
         w, h = self.scene.drawHLine(width=wid * 0.9, penWidth=2)



      # Done drawing other stuff, so return to the original drawing location
      self.scene.moveCursor(*prevCursor, absolute=True)
      ###########################################################################


      ###########################################################################
      # Finally, draw the backup information.

      # If this page is only imported addresses, draw them then bail
      self.bottomOfSceneHeader = self.scene.cursorPos.y()
      if printType == 'SingleSheetImported':
         self.scene.moveCursor(0, 0.1 * INCH)
         importList = self.binImport
         if self.chkSecurePrint.isChecked():
            importList = self.binImportCrypt

         for a160, priv, isCompr in importList[printData[0]:printData[1]]:
            comprByte = ('\x01' if isCompr == 1 else '')
            prprv = encodePrivKeyBase58(priv.toBinStr() + comprByte)
            toPrint = [prprv[i * 6:(i + 1) * 6] for i in range((len(prprv) + 5) / 6)]
            addrHint = '  (%s...)' % hash160_to_addrStr(a160)[:12]
            self.scene.drawText(' '.join(toPrint), GETFONT('Fix', 7))
            self.scene.moveCursor(0.02 * INCH, 0)
            self.scene.drawText(addrHint, GETFONT('Var', 7))
            self.scene.newLine(extra_dy=-3)
            prprv = None
         return


      if self.doPrintFrag:
         M = self.fragData['M']
         Lines = []
         Prefix = []
         fmtrx = self.fragMtrxCrypt if doMask else self.fragMtrx

         try:
            yBin = fmtrx[printData][1]
            binID = base58_to_binary(self.fragData['fragSetID'])
            IDLine = ComputeFragIDLineHex(M, printData, binID, doMask, addSpaces=True)
            if len(yBin) == 32:
               Prefix.append('ID:');  Lines.append(IDLine)
               Prefix.append('F1:');  Lines.append(makeSixteenBytesEasy(yBin[:16 ]))
               Prefix.append('F2:');  Lines.append(makeSixteenBytesEasy(yBin[ 16:]))
            elif len(yBin) == 64:
               Prefix.append('ID:');  Lines.append(IDLine)
               Prefix.append('F1:');  Lines.append(makeSixteenBytesEasy(yBin[:16       ]))
               Prefix.append('F2:');  Lines.append(makeSixteenBytesEasy(yBin[ 16:32    ]))
               Prefix.append('F3:');  Lines.append(makeSixteenBytesEasy(yBin[    32:48 ]))
               Prefix.append('F4:');  Lines.append(makeSixteenBytesEasy(yBin[       48:]))
            else:
               LOGERROR('yBin is not 32 or 64 bytes!  It is %s bytes', len(yBin))
         finally:
            yBin = None

      else:
         # Single-sheet backup
         if doMask:
            code12 = self.backupData.rootencr
            code34 = self.backupData.chainencr
         else:
            code12 = self.backupData.rootclear
            code34 = self.backupData.chainclear


         Lines = []
         Prefix = []
         Prefix.append('Root Key:');  Lines.append(code12[0])
         Prefix.append('');           Lines.append(code12[1])
         if not self.noNeedChaincode:
            Prefix.append('Chaincode:'); Lines.append(code34[0])
            Prefix.append('');           Lines.append(code34[1])

      # Draw the prefix
      origX, origY = self.scene.getCursorXY()
      self.scene.moveCursor(20, 0)
      colRect, rowHgt = self.scene.drawColumn(['<b>' + l + '</b>' for l in Prefix])

      nudgeDown = 2  # because the differing font size makes it look unaligned
      self.scene.moveCursor(20, nudgeDown)
      self.scene.drawColumn(Lines,
                              font=GETFONT('Fixed', 8, bold=True), \
                              rowHeight=rowHgt,
                              useHtml=False)

      self.scene.moveCursor(MARGIN, colRect.y() - 2, absolute=True)
      width = self.scene.pageRect().width() - 2 * MARGIN
      self.scene.drawRect(width, colRect.height() + 7, edgeColor=QColor(0, 0, 0), fillColor=None)

      self.scene.newLine(extra_dy=30)
      self.scene.drawText(self.tr(
         'The following QR code is for convenience only.  It contains the '
         'exact same data as the %s lines above.  If you copy this backup '
         'by hand, you can safely ignore this QR code.' % numLine), wrapWidth=4 * INCH)

      self.scene.moveCursor(20, 0)
      x, y = self.scene.getCursorXY()
      edgeRgt = self.scene.pageRect().width() - MARGIN
      edgeBot = self.scene.pageRect().height() - MARGIN

      qrSize = max(1.5 * INCH, min(edgeRgt - x, edgeBot - y, 2.0 * INCH))
      self.scene.drawQR('\n'.join(Lines), qrSize)
      self.scene.newLine(extra_dy=25)

      Lines = None

      # Finally, draw some pie slices at the bottom
      if self.doPrintFrag:
         M, N = self.fragData['M'], self.fragData['N']
         bottomOfPage = self.scene.pageRect().height() + MARGIN
         maxPieHeight = bottomOfPage - self.scene.getCursorXY()[1] - 8
         maxPieWidth = int((self.scene.pageRect().width() - 2 * MARGIN) / N) - 10
         pieSize = min(72., maxPieHeight, maxPieWidth)
         for i in range(N):
            startX, startY = self.scene.getCursorXY()
            drawSize = self.scene.drawPixmapFile('./img/frag%df.png' % M, sizePx=pieSize)
            self.scene.moveCursor(10, 0)
            if i == printData:
               returnX, returnY = self.scene.getCursorXY()
               self.scene.moveCursor(startX, startY, absolute=True)
               self.scene.moveCursor(-5, -5)
               self.scene.drawRect(drawSize[0] + 10, \
                                   drawSize[1] + 10, \
                                   edgeColor=Colors.TextBlue, \
                                   penWidth=3)
               self.scene.newLine()
               self.scene.moveCursor(startX - MARGIN, 0)
               self.scene.drawText('<font color="%s">#%d</font>' % \
                        (htmlColor('TextBlue'), fragNum), GETFONT('Var', 10))
               self.scene.moveCursor(returnX, returnY, absolute=True)



      vbar = self.view.verticalScrollBar()
      vbar.setValue(vbar.minimum())
      self.view.update()



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
      result = DlgPrintBackup(parent, main, wlt).exec_()
      verifyText = parent.trUtf8(
         u'If the backup was printed with SecurePrint\u200b\u2122, please '
         u'make sure you wrote the SecurePrint\u200b\u2122 code on the '
         'printed sheet of paper. Note that the code <b><u>is</u></b> '
         'case-sensitive!')
   elif backupType == 'Frag':
      result = DlgFragBackup(parent, main, wlt).exec_()
      verifyText = parent.trUtf8(
         u'If the backup was created with SecurePrint\u200b\u2122, please '
         u'make sure you wrote the SecurePrint\u200b\u2122 code on each '
         'fragment (or stored with each file fragment). The code is the '
         'same for all fragments.')

   doTest = MsgBoxCustom(MSGBOX.Warning, parent.tr('Verify Your Backup!'), parent.trUtf8(
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
class DlgHelpAbout(ArmoryDialog):
   def __init__(self, putResultInWidget, defaultWltID=None, parent=None, main=None):
      super(DlgHelpAbout, self).__init__(parent, main)

      imgLogo = QLabel()
      imgLogo.setPixmap(QPixmap('./img/armory_logo_h56.png'))
      imgLogo.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      if BTCARMORY_BUILD != None:
         lblHead = QRichLabel(self.tr('Armory Bitcoin Wallet : Version %s-beta-%s' % (getVersionString(BTCARMORY_VERSION), BTCARMORY_BUILD)), doWrap=False)
      else:
         lblHead = QRichLabel(self.tr('Armory Bitcoin Wallet : Version %s-beta' % getVersionString(BTCARMORY_VERSION)), doWrap=False)

      lblOldCopyright = QRichLabel(self.tr( u'Copyright &copy; 2011-2015 Armory Technologies, Inc.'))
      lblCopyright = QRichLabel(self.tr( u'Copyright &copy; 2016 Goatpig'))
      lblOldLicense = QRichLabel(self.tr( u'Licensed to Armory Technologies, Inc. under the '
                              '<a href="http://www.gnu.org/licenses/agpl-3.0.html">'
                              'Affero General Public License, Version 3</a> (AGPLv3)'))
      lblOldLicense.setOpenExternalLinks(True)
      lblLicense = QRichLabel(self.tr( u'Licensed to Goatpig under the '
                              '<a href="https://opensource.org/licenses/mit-license.php">'
                              'MIT License'))
      lblLicense.setOpenExternalLinks(True)

      lblHead.setAlignment(Qt.AlignHCenter)
      lblCopyright.setAlignment(Qt.AlignHCenter)
      lblOldCopyright.setAlignment(Qt.AlignHCenter)
      lblLicense.setAlignment(Qt.AlignHCenter)
      lblOldLicense.setAlignment(Qt.AlignHCenter)

      dlgLayout = QHBoxLayout()
      dlgLayout.addWidget(makeVertFrame([imgLogo, lblHead, lblCopyright, lblOldCopyright, STRETCH, lblLicense, lblOldLicense]))
      self.setLayout(dlgLayout)

      self.setMinimumWidth(450)

      self.setWindowTitle(self.tr('About Armory'))


################################################################################
class DlgSettings(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgSettings, self).__init__(parent, main)



      ##########################################################################
      # bitcoind-management settings
      self.chkManageSatoshi = QCheckBox(self.tr(
         'Let Armory run Bitcoin Core/bitcoind in the background'))
      self.edtSatoshiExePath = QLineEdit()
      self.edtSatoshiHomePath = QLineEdit()
      self.edtArmoryDbdir = QLineEdit()

      self.edtSatoshiExePath.setMinimumWidth(tightSizeNChar(GETFONT('Fixed', 10), 40)[0])
      self.connect(self.chkManageSatoshi, SIGNAL(CLICKED), self.clickChkManage)
      self.startChk = self.main.getSettingOrSetDefault('ManageSatoshi', not OS_MACOSX)
      if self.startChk:
         self.chkManageSatoshi.setChecked(True)
      if OS_MACOSX:
         self.chkManageSatoshi.setEnabled(False)
         lblManageSatoshi = QRichLabel(\
            self.tr('Bitcoin Core/bitcoind management is not available on Mac/OSX'))
      else:
         if self.main.settings.hasSetting('SatoshiExe'):
            satexe = self.main.settings.get('SatoshiExe')

         sathome = BTC_HOME_DIR
         if self.main.settings.hasSetting('SatoshiDatadir'):
            sathome = self.main.settings.get('SatoshiDatadir')

         lblManageSatoshi = QRichLabel(
            self.tr('<b>Bitcoin Software Management</b>'
            '<br><br>'
            'By default, Armory will manage the Bitcoin engine/software in the '
            'background.  You can choose to manage it yourself, or tell Armory '
            'about non-standard installation configuration.'))
      if self.main.settings.hasSetting('SatoshiExe'):
         self.edtSatoshiExePath.setText(self.main.settings.get('SatoshiExe'))
         self.edtSatoshiExePath.home(False)
      if self.main.settings.hasSetting('SatoshiDatadir'):
         self.edtSatoshiHomePath.setText(self.main.settings.get('SatoshiDatadir'))
         self.edtSatoshiHomePath.home(False)
      if self.main.settings.hasSetting('ArmoryDbdir'):
         self.edtArmoryDbdir.setText(self.main.settings.get('ArmoryDbdir'))
         self.edtArmoryDbdir.home(False)


      lblDescrExe = QRichLabel(self.tr('Bitcoin Install Dir:'))
      lblDefaultExe = QRichLabel(self.tr('Leave blank to have Armory search default '
                                  'locations for your OS'), size=2)

      self.btnSetExe = createDirectorySelectButton(self, self.edtSatoshiExePath)

      layoutMgmt = QGridLayout()
      layoutMgmt.addWidget(lblManageSatoshi, 0, 0, 1, 3)
      layoutMgmt.addWidget(self.chkManageSatoshi, 1, 0, 1, 3)

      layoutMgmt.addWidget(lblDescrExe, 2, 0)
      layoutMgmt.addWidget(self.edtSatoshiExePath, 2, 1)
      layoutMgmt.addWidget(self.btnSetExe, 2, 2)
      layoutMgmt.addWidget(lblDefaultExe, 3, 1, 1, 2)

      frmMgmt = QFrame()
      frmMgmt.setLayout(layoutMgmt)

      self.clickChkManage()
      ##########################################################################

      lblPathing = QRichLabel(self.tr('<b> Blockchain and Database Paths</b>'
         '<br><br>'
         'Optional feature to specify custom paths for blockchain '
         'data and Armory\'s database.'
         ))

      lblDescrHome = QRichLabel(self.tr('Bitcoin Home Dir:'))
      lblDefaultHome = QRichLabel(self.tr('Leave blank to use default datadir '
                                  '(%s)' % BTC_HOME_DIR), size=2)
      lblDescrDbdir = QRichLabel(self.tr('Armory Database Dir:'))
      lblDefaultDbdir = QRichLabel(self.tr('Leave blank to use default datadir '
                                  '(%s)' % ARMORY_DB_DIR), size=2)

      self.btnSetHome = createDirectorySelectButton(self, self.edtSatoshiHomePath)
      self.btnSetDbdir = createDirectorySelectButton(self, self.edtArmoryDbdir)

      layoutPath = QGridLayout()
      layoutPath.addWidget(lblPathing, 0, 0, 1, 3)

      layoutPath.addWidget(lblDescrHome, 1, 0)
      layoutPath.addWidget(self.edtSatoshiHomePath, 1, 1)
      layoutPath.addWidget(self.btnSetHome, 1, 2)
      layoutPath.addWidget(lblDefaultHome, 2, 1, 1, 2)

      layoutPath.addWidget(lblDescrDbdir, 3, 0)
      layoutPath.addWidget(self.edtArmoryDbdir, 3, 1)
      layoutPath.addWidget(self.btnSetDbdir, 3, 2)
      layoutPath.addWidget(lblDefaultDbdir, 4, 1, 1, 2)

      frmPaths = QFrame()
      frmPaths.setLayout(layoutPath)

      ##########################################################################
      lblDefaultUriTitle = QRichLabel(self.tr('<b>Set Armory as default URL handler</b>'))
      lblDefaultURI = QRichLabel(self.tr(
         'Set Armory to be the default when you click on "bitcoin:" '
         'links in your browser or in emails. '
         'You can test if your operating system is supported by clicking '
         'on a "bitcoin:" link right after clicking this button.'))
      btnDefaultURI = QPushButton(self.tr('Set Armory as Default'))
      frmBtnDefaultURI = makeHorizFrame([btnDefaultURI, 'Stretch'])

      self.chkAskURIAtStartup = QCheckBox(self.tr(
         'Check whether Armory is the default handler at startup'))
      askuriDNAA = self.main.getSettingOrSetDefault('DNAA_DefaultApp', False)
      self.chkAskURIAtStartup.setChecked(not askuriDNAA)

      def clickRegURI():
         self.main.setupUriRegistration(justDoIt=True)
         QMessageBox.information(self, self.tr('Registered'), self.tr(
            'Armory just attempted to register itself to handle "bitcoin:" '
            'links, but this does not work on all operating systems.'), QMessageBox.Ok)

      self.connect(btnDefaultURI, SIGNAL(CLICKED), clickRegURI)

      ###############################################################
      # Minimize on Close
      lblMinimizeDescr = QRichLabel(self.tr(
         '<b>Minimize to System Tray</b> '
         '<br>'
         'You can have Armory automatically minimize itself to your system '
         'tray on open or close.  Armory will stay open but run in the '
         'background, and you will still receive notifications.  Access Armory '
         'through the icon on your system tray. '
         '<br><br>'
         'If you select "Minimize on close", the \'x\' on the top window bar will '
         'minimize Armory instead of exiting the application.  You can always use '
         '<i>"File"</i> -> <i>"Quit Armory"</i> to actually close it.'))

      moo = self.main.getSettingOrSetDefault('MinimizeOnOpen', False)
      self.chkMinOnOpen = QCheckBox(self.tr('Minimize to system tray on open'))
      if moo:
         self.chkMinOnOpen.setChecked(True)

      moc = self.main.getSettingOrSetDefault('MinimizeOrClose', 'DontKnow')
      self.chkMinOrClose = QCheckBox(self.tr('Minimize to system tray on close'))

      if moc == 'Minimize':
         self.chkMinOrClose.setChecked(True)


      ###############################################################
      # System tray notifications. On OS X, notifications won't work on 10.7.
      # OS X's built-in notification system was implemented starting in 10.8.
      osxMinorVer = '0'
      if OS_MACOSX:
         osxMinorVer = OS_VARIANT[0].split(".")[1]

      lblNotify = QRichLabel(self.tr('<b>Enable notifications from the system-tray:</b>'))
      self.chkBtcIn = QCheckBox(self.tr('Bitcoins Received'))
      self.chkBtcOut = QCheckBox(self.tr('Bitcoins Sent'))
      self.chkDiscon = QCheckBox(self.tr('Bitcoin Core/bitcoind disconnected'))
      self.chkReconn = QCheckBox(self.tr('Bitcoin Core/bitcoind reconnected'))

      # FYI:If we're not on OS X, the if condition will never be hit.
      if (OS_MACOSX) and (int(osxMinorVer) < 7):
         lblNotify = QRichLabel(self.tr('<b>Sorry!  Notifications are not available ' \
                                'on your version of OS X.</b>'))
         self.chkBtcIn.setChecked(False)
         self.chkBtcOut.setChecked(False)
         self.chkDiscon.setChecked(False)
         self.chkReconn.setChecked(False)
         self.chkBtcIn.setEnabled(False)
         self.chkBtcOut.setEnabled(False)
         self.chkDiscon.setEnabled(False)
         self.chkReconn.setEnabled(False)
      else:
         notifyBtcIn = self.main.getSettingOrSetDefault('NotifyBtcIn', True)
         notifyBtcOut = self.main.getSettingOrSetDefault('NotifyBtcOut', True)
         notifyDiscon = self.main.getSettingOrSetDefault('NotifyDiscon', True)
         notifyReconn = self.main.getSettingOrSetDefault('NotifyReconn', True)
         self.chkBtcIn.setChecked(notifyBtcIn)
         self.chkBtcOut.setChecked(notifyBtcOut)
         self.chkDiscon.setChecked(notifyDiscon)
         self.chkReconn.setChecked(notifyReconn)

      ###############################################################
      # Date format preferences
      exampleTimeTuple = (2012, 4, 29, 19, 45, 0, -1, -1, -1)
      self.exampleUnixTime = time.mktime(exampleTimeTuple)
      exampleStr = unixTimeToFormatStr(self.exampleUnixTime, '%c')
      lblDateFmt = QRichLabel(self.tr('<b>Preferred Date Format<b>:<br>'))
      lblDateDescr = QRichLabel(self.tr(
                          'You can specify how you would like dates '
                          'to be displayed using percent-codes to '
                          'represent components of the date.  The '
                          'mouseover text of the "(?)" icon shows '
                          'the most commonly used codes/symbols.  '
                          'The text next to it shows how '
                          '"%s" would be shown with the '
                          'specified format.' % exampleStr))
      lblDateFmt.setAlignment(Qt.AlignTop)
      fmt = self.main.getPreferredDateFormat()
      ttipStr = self.tr('Use any of the following symbols:<br>')
      fmtSymbols = [x[0] + ' = ' + x[1] for x in FORMAT_SYMBOLS]
      ttipStr += '<br>'.join(fmtSymbols)

      fmtSymbols = [x[0] + '~' + x[1] for x in FORMAT_SYMBOLS]
      lblStk = QRichLabel('; '.join(fmtSymbols))

      self.edtDateFormat = QLineEdit()
      self.edtDateFormat.setText(fmt)
      self.ttipFormatDescr = self.main.createToolTipWidget(ttipStr)

      self.lblDateExample = QRichLabel('', doWrap=False)
      self.connect(self.edtDateFormat, SIGNAL('textEdited(QString)'), self.doExampleDate)
      self.doExampleDate()
      self.btnResetFormat = QPushButton(self.tr("Reset to Default"))

      def doReset():
         self.edtDateFormat.setText(DEFAULT_DATE_FORMAT)
         self.doExampleDate()
      self.connect(self.btnResetFormat, SIGNAL(CLICKED), doReset)

      # Make a little subframe just for the date format stuff... everything
      # fits nicer if I do this...
      frmTop = makeHorizFrame([self.lblDateExample, STRETCH, self.ttipFormatDescr])
      frmMid = makeHorizFrame([self.edtDateFormat])
      frmBot = makeHorizFrame([self.btnResetFormat, STRETCH])
      fStack = makeVertFrame([frmTop, frmMid, frmBot, STRETCH])
      lblStk = makeVertFrame([lblDateFmt, lblDateDescr, STRETCH])
      subFrm = makeHorizFrame([lblStk, STRETCH, fStack])


      # Save/Cancel Button
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.btnAccept = QPushButton(self.tr("Save"))
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.accept)

      ################################################################
      # User mode selection
      self.cmbUsermode = QComboBox()
      self.cmbUsermode.clear()
      self.cmbUsermode.addItem(self.tr('Standard'))
      self.cmbUsermode.addItem(self.tr('Advanced'))
      self.cmbUsermode.addItem(self.tr('Expert'))

      self.usermodeInit = self.main.usermode

      if self.main.usermode == USERMODE.Standard:
         self.cmbUsermode.setCurrentIndex(0)
      elif self.main.usermode == USERMODE.Advanced:
         self.cmbUsermode.setCurrentIndex(1)
      elif self.main.usermode == USERMODE.Expert:
         self.cmbUsermode.setCurrentIndex(2)

      lblUsermode = QRichLabel(self.tr('<b>Armory user mode:</b>'))
      self.lblUsermodeDescr = QRichLabel('')
      self.setUsermodeDescr()

      self.connect(self.cmbUsermode, SIGNAL('activated(int)'), self.setUsermodeDescr)

      ###############################################################
      # Language preferences
      self.lblLang = QRichLabel(self.tr('<b>Preferred Language<b>:<br>'))
      self.lblLangDescr = QRichLabel(self.tr(
         'Specify which language you would like Armory to be displayed in.'))
      self.cmbLang = QComboBox()
      self.cmbLang.clear()
      for lang in LANGUAGES:
         self.cmbLang.addItem(QLocale(lang).nativeLanguageName() + " (" + lang + ")")
      self.cmbLang.setCurrentIndex(LANGUAGES.index(self.main.language))
      self.langInit = self.main.language

      frmLayout = QGridLayout()

      i = 0
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(frmMgmt, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(frmPaths, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(lblDefaultUriTitle, i, 0)
      i += 1
      frmLayout.addWidget(lblDefaultURI, i, 0, 1, 3)
      i += 1
      frmLayout.addWidget(frmBtnDefaultURI, i, 0, 1, 3)
      i += 1
      frmLayout.addWidget(self.chkAskURIAtStartup, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(subFrm, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(lblMinimizeDescr, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(self.chkMinOnOpen, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(self.chkMinOrClose, i, 0, 1, 3)


      i += 1
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(lblNotify, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(self.chkBtcIn, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(self.chkBtcOut, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(self.chkDiscon, i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(self.chkReconn, i, 0, 1, 3)


      i += 1
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(lblUsermode, i, 0)
      frmLayout.addWidget(QLabel(''), i, 1)
      frmLayout.addWidget(self.cmbUsermode, i, 2)

      i += 1
      frmLayout.addWidget(self.lblUsermodeDescr, i, 0, 1, 3)


      i += 1
      frmLayout.addWidget(HLINE(), i, 0, 1, 3)

      i += 1
      frmLayout.addWidget(self.lblLang, i, 0)
      frmLayout.addWidget(QLabel(''), i, 1)
      frmLayout.addWidget(self.cmbLang, i, 2)

      i += 1
      frmLayout.addWidget(self.lblLangDescr, i, 0, 1, 3)


      frmOptions = QFrame()
      frmOptions.setLayout(frmLayout)

      self.settingsTab = QTabWidget()
      self.settingsTab.addTab(frmOptions, self.tr("General"))

      #FeeChange tab
      self.setupExtraTabs()
      frmFeeChange = makeVertFrame([\
         self.frmFee, self.frmChange, self.frmAddrType, 'Stretch'])

      self.settingsTab.addTab(frmFeeChange, self.tr("Fee and Address Types"))

      self.scrollOptions = QScrollArea()
      self.scrollOptions.setWidget(self.settingsTab)



      dlgLayout = QVBoxLayout()
      dlgLayout.addWidget(self.scrollOptions)
      dlgLayout.addWidget(makeHorizFrame([STRETCH, self.btnCancel, self.btnAccept]))

      self.setLayout(dlgLayout)

      self.setMinimumWidth(650)
      self.setWindowTitle(self.tr('Armory Settings'))

   #############################################################################
   def setupExtraTabs(self):
      ##########
      #fee

      feeByte = self.main.getSettingOrSetDefault('Default_FeeByte', MIN_FEE_BYTE)
      txFee = self.main.getSettingOrSetDefault('Default_Fee', MIN_TX_FEE)
      adjustFee = self.main.getSettingOrSetDefault('AdjustFee', True)
      feeOpt = self.main.getSettingOrSetDefault('FeeOption', DEFAULT_FEE_TYPE)
      blocksToConfirm = self.main.getSettingOrSetDefault(\
         "Default_FeeByte_BlocksToConfirm", NBLOCKS_TO_CONFIRM)

      def feeRadio(strArg):
         self.radioAutoFee.setChecked(False)

         self.radioFeeByte.setChecked(False)
         self.leFeeByte.setEnabled(False)

         self.radioFlatFee.setChecked(False)
         self.leFlatFee.setEnabled(False)

         if strArg == 'Auto':
            self.radioAutoFee.setChecked(True)
         elif strArg == 'FeeByte':
            self.radioFeeByte.setChecked(True)
            self.leFeeByte.setEnabled(True)
         elif strArg == 'FlatFee':
            self.radioFlatFee.setChecked(True)
            self.leFlatFee.setEnabled(True)

         self.feeOpt = strArg

      def getCallbck(strArg):
         def callbck():
            return feeRadio(strArg)
         return callbck

      labelFee = QRichLabel(self.tr("<b>Fee<br></b>"))

      self.radioAutoFee = QRadioButton(self.tr("Auto fee/byte"))
      self.connect(self.radioAutoFee, SIGNAL('clicked()'), getCallbck('Auto'))
      self.sliderAutoFee = QSlider(Qt.Horizontal, self)
      self.sliderAutoFee.setMinimum(2)
      self.sliderAutoFee.setMaximum(6)
      self.sliderAutoFee.setValue(blocksToConfirm)
      self.lblSlider = QLabel()

      def getLblSliderText():
         blocksToConfirm = str(self.sliderAutoFee.value())
         return self.tr("Blocks to confirm: %s" % blocksToConfirm)

      def setLblSliderText():
         self.lblSlider.setText(getLblSliderText())

      setLblSliderText()
      self.sliderAutoFee.valueChanged.connect(setLblSliderText)

      toolTipAutoFee = self.main.createToolTipWidget(self.tr(
      'Fetch fee/byte from local Bitcoin node. '
      'Defaults to manual fee/byte on failure.'))

      self.radioFeeByte = QRadioButton(self.tr("Manual fee/byte"))
      self.connect(self.radioFeeByte, SIGNAL('clicked()'), getCallbck('FeeByte'))
      self.leFeeByte = QLineEdit(str(feeByte))
      toolTipFeeByte = self.main.createToolTipWidget(self.tr('Values in satoshis/byte'))

      self.radioFlatFee = QRadioButton(self.tr("Flat fee"))
      self.connect(self.radioFlatFee, SIGNAL('clicked()'), getCallbck('FlatFee'))
      self.leFlatFee = QLineEdit(coin2str(txFee, maxZeros=0))
      toolTipFlatFee = self.main.createToolTipWidget(self.tr('Values in BTC'))

      self.checkAdjust = QCheckBox(self.tr("Auto-adjust fee/byte for better privacy"))
      self.checkAdjust.setChecked(adjustFee)
      feeToolTip = self.main.createToolTipWidget(self.tr(
      'Auto-adjust fee may increase your total fee using the selected fee/byte rate '
      'as its basis in an attempt to align the amount of digits after the decimal '
      'point between your spend values and change value.'
      '<br><br>'
      'The purpose of this obfuscation technique is to make the change output '
      'less obvious. '
      '<br><br>'
      'The auto-adjust fee feature only applies to fee/byte options '
      'and does not inflate your fee by more that 10% of its original value.'))

      frmFeeLayout = QGridLayout()
      frmFeeLayout.addWidget(labelFee, 0, 0, 1, 1)

      frmAutoFee = makeHorizFrame([self.radioAutoFee, self.lblSlider, toolTipAutoFee])
      frmFeeLayout.addWidget(frmAutoFee, 1, 0, 1, 1)
      frmFeeLayout.addWidget(self.sliderAutoFee, 2, 0, 1, 2)

      frmFeeByte = makeHorizFrame([self.radioFeeByte, self.leFeeByte, \
                                   toolTipFeeByte, STRETCH, STRETCH])
      frmFeeLayout.addWidget(frmFeeByte, 3, 0, 1, 1)

      frmFlatFee = makeHorizFrame([self.radioFlatFee, self.leFlatFee, \
                                   toolTipFlatFee, STRETCH, STRETCH])
      frmFeeLayout.addWidget(frmFlatFee, 4, 0, 1, 1)

      frmCheckAdjust = makeHorizFrame([self.checkAdjust, feeToolTip, STRETCH])
      frmFeeLayout.addWidget(frmCheckAdjust, 5, 0, 1, 2)

      feeRadio(feeOpt)

      self.frmFee = QFrame()
      self.frmFee.setFrameStyle(STYLE_RAISED)
      self.frmFee.setLayout(frmFeeLayout)

      #########
      #change

      def setChangeType(changeType):
         self.changeType = changeType

      from ui.AddressTypeSelectDialog import AddressLabelFrame
      changeType = self.main.getSettingOrSetDefault('Default_ChangeType', DEFAULT_CHANGE_TYPE)
      self.changeTypeFrame = AddressLabelFrame(self.main, setChangeType)

      def changeRadio(strArg):
         self.radioAutoChange.setChecked(False)
         self.radioForce.setChecked(False)
         self.changeTypeFrame.getFrame().setEnabled(False)

         if strArg == 'Auto':
            self.radioAutoChange.setChecked(True)
            self.changeType = 'Auto'
         elif strArg == 'Force':
            self.radioForce.setChecked(True)
            self.changeTypeFrame.getFrame().setEnabled(True)
            self.changeType = self.changeTypeFrame.getType()
         else:
            self.changeTypeFrame.setType(strArg)
            self.radioForce.setChecked(True)
            self.changeTypeFrame.getFrame().setEnabled(True)
            self.changeType = self.changeTypeFrame.getType()

      def changeCallbck(strArg):
         def callbck():
            return changeRadio(strArg)
         return callbck


      labelChange = QRichLabel(self.tr("<b>Change Address Type<br></b>"))

      self.radioAutoChange = QRadioButton(self.tr("Auto change"))
      self.connect(self.radioAutoChange, SIGNAL('clicked()'), changeCallbck('Auto'))
      toolTipAutoChange = self.main.createToolTipWidget(self.tr(
      "Change address type will match the address type of recipient "
      "addresses. <br>"

      "Favors P2SH when recipients are heterogenous. <br>"

      "Will create nested SegWit change if inputs are SegWit and "
      "recipient are P2SH. <br><br>"

      "<b>Pre 0.96 Armory cannot spend from P2SH address types</b>"
      ))

      self.radioForce = QRadioButton(self.tr("Force a script type:"))
      self.connect(self.radioForce, SIGNAL('clicked()'), changeCallbck('Force'))

      changeRadio(changeType)

      frmChangeLayout = QGridLayout()
      frmChangeLayout.addWidget(labelChange, 0, 0, 1, 1)

      frmAutoChange = makeHorizFrame([self.radioAutoChange, \
                                      toolTipAutoChange, STRETCH])
      frmChangeLayout.addWidget(frmAutoChange, 1, 0, 1, 1)

      frmForce = makeHorizFrame([self.radioForce, self.changeTypeFrame.getFrame()])
      frmChangeLayout.addWidget(frmForce, 2, 0, 1, 1)

      self.frmChange = QFrame()
      self.frmChange.setFrameStyle(STYLE_RAISED)
      self.frmChange.setLayout(frmChangeLayout)

      #########
      #receive addr type

      labelAddrType = QRichLabel(self.tr("<b>Preferred Receive Address Type</b>"))

      def setAddrType(addrType):
         self.addrType = addrType

      self.addrType = self.main.getSettingOrSetDefault('Default_ReceiveType', DEFAULT_RECEIVE_TYPE)
      self.addrTypeFrame = AddressLabelFrame(self.main, setAddrType)
      self.addrTypeFrame.setType(self.addrType)

      frmAddrLayout = QGridLayout()
      frmAddrLayout.addWidget(labelAddrType, 0, 0, 1, 1)

      frmAddrTypeSelect = makeHorizFrame([self.addrTypeFrame.getFrame()])

      frmAddrLayout.addWidget(frmAddrTypeSelect, 2, 0, 1, 1)

      self.frmAddrType = QFrame()
      self.frmAddrType.setFrameStyle(STYLE_RAISED)
      self.frmAddrType.setLayout(frmAddrLayout)

   #############################################################################
   def accept(self, *args):

      if self.chkManageSatoshi.isChecked():
         # Check valid path is supplied for bitcoin installation
         pathExe = unicode(self.edtSatoshiExePath.text()).strip()
         if len(pathExe) > 0:
            if not os.path.exists(pathExe):
               exeName = 'bitcoin-qt.exe' if OS_WINDOWS else 'bitcoin-qt'
               QMessageBox.warning(self, self.tr('Invalid Path'),self.tr(
                  'The path you specified for the Bitcoin software installation '
                  'does not exist.  Please select the directory that contains %s '
                  'or leave it blank to have Armory search the default location '
                  'for your operating system' % exeName), QMessageBox.Ok)
               return
            if os.path.isfile(pathExe):
               pathExe = os.path.dirname(pathExe)
            self.main.writeSetting('SatoshiExe', pathExe)
         else:
            self.main.settings.delete('SatoshiExe')

      # Check path is supplied for bitcoind home directory
      pathHome = str(self.edtSatoshiHomePath.text()).strip()
      if len(pathHome) > 0:
         if not os.path.exists(pathHome):
            QMessageBox.warning(self, self.tr('Invalid Path'), self.tr(
                  'The path you specified for the Bitcoin software home directory '
                  'does not exist.  Only specify this directory if you use a '
                  'non-standard "-datadir=" option when running Bitcoin Core or '
                  'bitcoind.  If you leave this field blank, the following '
                  'path will be used: <br><br> %s' % BTC_HOME_DIR), QMessageBox.Ok)
            return
         self.main.writeSetting('SatoshiDatadir', pathHome)
      else:
         self.main.settings.delete('SatoshiDatadir')

      # Check path is supplied for armory db directory
      pathDbdir = str(self.edtArmoryDbdir.text()).strip()
      if len(pathDbdir) > 0:
         if not os.path.exists(pathDbdir):
            QMessageBox.warning(self, self.tr('Invalid Path'), self.tr(
                  'The path you specified for Armory\'s database directory '
                  'does not exist.  Only specify this directory if you want '
                  'Armory to save its local database to a custom path. '
                  'If you leave this field blank, the following '
                  'path will be used: <br><br> %s' % ARMORY_DB_DIR), QMessageBox.Ok)
            return
         self.main.writeSetting('ArmoryDbdir', pathDbdir)
      else:
         self.main.settings.delete('ArmoryDbdir')


      self.main.writeSetting('ManageSatoshi', self.chkManageSatoshi.isChecked())

      # Reset the DNAA flag as needed
      askuriDNAA = self.chkAskURIAtStartup.isChecked()
      self.main.writeSetting('DNAA_DefaultApp', not askuriDNAA)

      if not self.main.setPreferredDateFormat(str(self.edtDateFormat.text())):
         return

      if not self.usermodeInit == self.cmbUsermode.currentIndex():
         self.main.setUserMode(self.cmbUsermode.currentIndex())

      if not self.langInit == self.cmbLang.currentText()[-3:-1]:
         self.main.setLang(LANGUAGES[self.cmbLang.currentIndex()])

      if self.chkMinOrClose.isChecked():
         self.main.writeSetting('MinimizeOrClose', 'Minimize')
      else:
         self.main.writeSetting('MinimizeOrClose', 'Close')

      self.main.writeSetting('MinimizeOnOpen', self.chkMinOnOpen.isChecked())

      # self.main.writeSetting('LedgDisplayFee', self.chkInclFee.isChecked())
      self.main.writeSetting('NotifyBtcIn', self.chkBtcIn.isChecked())
      self.main.writeSetting('NotifyBtcOut', self.chkBtcOut.isChecked())
      self.main.writeSetting('NotifyDiscon', self.chkDiscon.isChecked())
      self.main.writeSetting('NotifyReconn', self.chkReconn.isChecked())


      #fee
      self.main.writeSetting('FeeOption', self.feeOpt)
      self.main.writeSetting('Default_FeeByte', str(self.leFeeByte.text()))
      self.main.writeSetting('Default_Fee', str2coin(str(self.leFlatFee.text())))
      self.main.writeSetting('AdjustFee', self.checkAdjust.isChecked())
      self.main.writeSetting('Default_FeeByte_BlocksToConfirm',
                             self.sliderAutoFee.value())

      #change
      self.main.writeSetting('Default_ChangeType', self.changeType)

      #addr type
      self.main.writeSetting('Default_ReceiveType', self.addrType)
      armoryengine.ArmoryUtils.DEFAULT_ADDR_TYPE = self.addrType

      try:
         self.main.createCombinedLedger()
      except:
         pass
      super(DlgSettings, self).accept(*args)


   #############################################################################
   def setUsermodeDescr(self):
      strDescr = ''
      modeIdx = self.cmbUsermode.currentIndex()
      if modeIdx == USERMODE.Standard:
         strDescr += \
            self.tr('"Standard" is for users that only need the core set of features '
             'to send and receive bitcoins.  This includes maintaining multiple '
             'wallets, wallet encryption, and the ability to make backups '
             'of your wallets.')
      elif modeIdx == USERMODE.Advanced:
         strDescr += \
            self.tr('"Advanced" mode provides '
             'extra Armory features such as private key '
             'importing & sweeping, message signing, and the offline wallet '
             'interface.  But, with advanced features come advanced risks...')
      elif modeIdx == USERMODE.Expert:
         strDescr += \
            self.tr('"Expert" mode is similar to "Advanced" but includes '
             'access to lower-level info about transactions, scripts, keys '
             'and network protocol.  Most extra functionality is geared '
             'towards Bitcoin software developers.')
      self.lblUsermodeDescr.setText(strDescr)


   #############################################################################
   def doExampleDate(self, qstr=None):
      fmtstr = str(self.edtDateFormat.text())
      try:
         self.lblDateExample.setText(self.tr('Sample: ') + unixTimeToFormatStr(self.exampleUnixTime, fmtstr))
         self.isValidFormat = True
      except:
         self.lblDateExample.setText(self.tr('Sample: [[invalid date format]]'))
         self.isValidFormat = False

   #############################################################################
   def clickChkManage(self):
      self.edtSatoshiExePath.setEnabled(self.chkManageSatoshi.isChecked())
      self.btnSetExe.setEnabled(self.chkManageSatoshi.isChecked())


################################################################################
class DlgExportTxHistory(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgExportTxHistory, self).__init__(parent, main)

      self.reversedLBdict = {v:k for k,v in self.main.lockboxIDMap.items()}

      self.cmbWltSelect = QComboBox()
      self.cmbWltSelect.clear()
      self.cmbWltSelect.addItem(self.tr('My Wallets'))
      self.cmbWltSelect.addItem(self.tr('Offline Wallets'))
      self.cmbWltSelect.addItem(self.tr('Other Wallets'))

      self.cmbWltSelect.insertSeparator(4)
      self.cmbWltSelect.addItem(self.tr('All Wallets'))
      self.cmbWltSelect.addItem(self.tr('All Lockboxes'))
      self.cmbWltSelect.addItem(self.tr('All Wallets & Lockboxes'))

      self.cmbWltSelect.insertSeparator(8)
      for wltID in self.main.walletIDList:
         self.cmbWltSelect.addItem(self.main.walletMap[wltID].labelName)

      self.cmbWltSelect.insertSeparator(8 + len(self.main.walletIDList))
      for idx in self.reversedLBdict:
         self.cmbWltSelect.addItem(self.main.allLockboxes[idx].shortName)


      self.cmbSortSelect = QComboBox()
      self.cmbSortSelect.clear()
      self.cmbSortSelect.addItem(self.tr('Date (newest first)'))
      self.cmbSortSelect.addItem(self.tr('Date (oldest first)'))


      self.cmbFileFormat = QComboBox()
      self.cmbFileFormat.clear()
      self.cmbFileFormat.addItem(self.tr('Comma-Separated Values (*.csv)'))


      fmt = self.main.getPreferredDateFormat()
      ttipStr = self.tr('Use any of the following symbols:<br>')
      fmtSymbols = [x[0] + ' = ' + x[1] for x in FORMAT_SYMBOLS]
      ttipStr += '<br>'.join(fmtSymbols)

      self.edtDateFormat = QLineEdit()
      self.edtDateFormat.setText(fmt)
      self.ttipFormatDescr = self.main.createToolTipWidget(ttipStr)

      self.lblDateExample = QRichLabel('', doWrap=False)
      self.connect(self.edtDateFormat, SIGNAL('textEdited(QString)'), self.doExampleDate)
      self.doExampleDate()
      self.btnResetFormat = QPushButton(self.tr("Reset to Default"))

      def doReset():
         self.edtDateFormat.setText(DEFAULT_DATE_FORMAT)
         self.doExampleDate()
      self.connect(self.btnResetFormat, SIGNAL(CLICKED), doReset)



      # Add the usual buttons
      self.btnCancel = QPushButton(self.tr("Cancel"))
      self.btnAccept = QPushButton(self.tr("Export"))
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.accept)
      btnBox = makeHorizFrame([STRETCH, self.btnCancel, self.btnAccept])


      dlgLayout = QGridLayout()

      i = 0
      dlgLayout.addWidget(QRichLabel(self.tr('Export Format:')), i, 0)
      dlgLayout.addWidget(self.cmbFileFormat, i, 1)

      i += 1
      dlgLayout.addWidget(HLINE(), i, 0, 1, 2)

      i += 1
      dlgLayout.addWidget(QRichLabel(self.tr('Wallet(s) to export:')), i, 0)
      dlgLayout.addWidget(self.cmbWltSelect, i, 1)

      i += 1
      dlgLayout.addWidget(HLINE(), i, 0, 1, 2)

      i += 1
      dlgLayout.addWidget(QRichLabel(self.tr('Sort Table:')), i, 0)
      dlgLayout.addWidget(self.cmbSortSelect, i, 1)
      i += 1
      dlgLayout.addWidget(HLINE(), i, 0, 1, 2)

      i += 1
      dlgLayout.addWidget(QRichLabel(self.tr('Date Format:')), i, 0)
      fmtfrm = makeHorizFrame([self.lblDateExample, STRETCH, self.ttipFormatDescr])
      dlgLayout.addWidget(fmtfrm, i, 1)

      i += 1
      dlgLayout.addWidget(self.btnResetFormat, i, 0)
      dlgLayout.addWidget(self.edtDateFormat, i, 1)

      i += 1
      dlgLayout.addWidget(HLINE(), i, 0, 1, 2)

      i += 1
      dlgLayout.addWidget(HLINE(), i, 0, 1, 2)

      i += 1
      dlgLayout.addWidget(btnBox, i, 0, 1, 2)

      self.setLayout(dlgLayout)


   #############################################################################
   def doExampleDate(self, qstr=None):
      fmtstr = str(self.edtDateFormat.text())
      try:
         exampleDateStr = unixTimeToFormatStr(1030501970, fmtstr)
         self.lblDateExample.setText(self.tr('Example: %s' % exampleDateStr))
         self.isValidFormat = True
      except:
         self.lblDateExample.setText(self.tr('Example: [[invalid date format]]'))
         self.isValidFormat = False

   #############################################################################
   def accept(self, *args):
      if self.createFile_CSV():
         super(DlgExportTxHistory, self).accept(*args)


   #############################################################################
   def createFile_CSV(self):
      if not self.isValidFormat:
         QMessageBox.warning(self, self.tr('Invalid date format'), \
                  self.tr('Cannot create CSV without a valid format for transaction '
                  'dates and times'), QMessageBox.Ok)
         return False

      COL = LEDGERCOLS

      # This was pretty much copied from the createCombinedLedger method...
      # I rarely do this, but modularizing this piece is a non-trivial
      wltIDList = []
      typelist = [[wid, determineWalletType(self.main.walletMap[wid], self.main)[0]] \
                                                   for wid in self.main.walletIDList]
      currIdx = self.cmbWltSelect.currentIndex()
      if currIdx >= 8:
         idx = currIdx - 8
         if idx < len(self.main.walletIDList):
            #picked a single wallet
            wltIDList = [self.main.walletIDList[idx]]
         else:
            #picked a single lockbox
            idx -= len(self.main.walletIDList) +1
            wltIDList = [self.reversedLBdict[idx]]
      else:
         listOffline = [t[0] for t in filter(lambda x: x[1] == WLTTYPES.Offline, typelist)]
         listWatching = [t[0] for t in filter(lambda x: x[1] == WLTTYPES.WatchOnly, typelist)]
         listCrypt = [t[0] for t in filter(lambda x: x[1] == WLTTYPES.Crypt, typelist)]
         listPlain = [t[0] for t in filter(lambda x: x[1] == WLTTYPES.Plain, typelist)]
         lockboxIDList = [t for t in self.main.lockboxIDMap]

         if currIdx == 0:
            wltIDList = listOffline + listCrypt + listPlain
         elif currIdx == 1:
            wltIDList = listOffline
         elif currIdx == 2:
            wltIDList = listWatching
         elif currIdx == 4:
            wltIDList = self.main.walletIDList
         elif currIdx == 5:
            wltIDList = lockboxIDList
         elif currIdx == 6:
            wltIDList = self.main.walletIDList + lockboxIDList
         else:
            pass

      order = "ascending"
      sortTxt = str(self.cmbSortSelect.currentText())
      if 'newest' in sortTxt:
         order = "descending"

      totalFunds, spendFunds, unconfFunds = 0, 0, 0
      wltBalances = {}
      for wltID in wltIDList:
         if wltID in self.main.walletMap:
            wlt = self.main.walletMap[wltID]

            totalFunds += wlt.getBalance('Total')
            spendFunds += wlt.getBalance('Spendable')
            unconfFunds += wlt.getBalance('Unconfirmed')
            if order == "ascending":
               wltBalances[wltID] = 0   # will be accumulated
            else:
               wltBalances[wltID] = wlt.getBalance('Total')

         else:
            #lockbox
            cppwlt = self.main.cppLockboxWltMap[wltID]
            totalFunds += cppwlt.getFullBalance()
            spendFunds += cppwlt.getSpendableBalance(TheBDM.getTopBlockHeight(), IGNOREZC)
            unconfFunds += cppwlt.getUnconfirmedBalance(TheBDM.getTopBlockHeight(), IGNOREZC)
            if order == "ascending":
               wltBalances[wltID] = 0   # will be accumulated
            else:
               wltBalances[wltID] = cppwlt.getFullBalance()

      if order == "ascending":
         allBalances = 0
      else:
         allBalances = totalFunds


      #prepare csv file
      wltSelectStr = str(self.cmbWltSelect.currentText()).replace(' ', '_')
      timestampStr = unixTimeToFormatStr(RightNow(), '%Y%m%d_%H%M')
      filenamePrefix = 'ArmoryTxHistory_%s_%s' % (wltSelectStr, timestampStr)
      fmtstr = str(self.cmbFileFormat.currentText())
      if 'csv' in fmtstr:
         defaultName = filenamePrefix + '.csv'
         fullpath = self.main.getFileSave('Save CSV File', \
                                              ['Comma-Separated Values (*.csv)'], \
                                              defaultName)

         if len(fullpath) == 0:
            return

         f = open(fullpath, 'w')

         f.write(self.tr('Export Date: %s\n' % unixTimeToFormatStr(RightNow())))
         f.write(self.tr('Total Funds: %s\n' % coin2str(totalFunds, maxZeros=0).strip()))
         f.write(self.tr('Spendable Funds: %s\n' % coin2str(spendFunds, maxZeros=0).strip()))
         f.write(self.tr('Unconfirmed Funds: %s\n' % coin2str(unconfFunds, maxZeros=0).strip()))
         f.write('\n')

         f.write(self.tr('Included Wallets:\n'))
         for wltID in wltIDList:
            if wltID in self.main.walletMap:
               wlt = self.main.walletMap[wltID]
               f.write('%s,%s\n' % (wltID, wlt.labelName.replace(',', ';')))
            else:
               wlt = self.main.allLockboxes[self.main.lockboxIDMap[wltID]]
               f.write(self.tr('%s (lockbox),%s\n' % (wltID, wlt.shortName.replace(',', ';'))))
         f.write('\n')


         headerRow = [self.tr('Date'), self.tr('Transaction ID'), self.tr('Number of Confirmations'), self.tr('Wallet ID'),
                      self.tr('Wallet Name'), self.tr('Credit'), self.tr('Debit'), self.tr('Fee (paid by this wallet)'),
                      self.tr('Wallet Balance'), self.tr('Total Balance'), self.tr('Label')]

         f.write(','.join(unicode(header) for header in headerRow) + '\n')

         #get history
         historyLedger = TheBDM.bdv().getHistoryForWalletSelection(wltIDList, order)

         # Each value in COL.Amount will be exactly how much the wallet balance
         # increased or decreased as a result of this transaction.
         ledgerTable = self.main.convertLedgerToTable(historyLedger,
                                                      showSentToSelfAmt=True)

         # Sort the data chronologically first, compute the running balance for
         # each row, then sort it the way that was requested by the user.
         for row in ledgerTable:
            if row[COL.toSelf] == False:
               rawAmt = str2coin(row[COL.Amount])
            else:
               #if SentToSelf, balance and total rolling balance should only take fee in account
               rawAmt, fee_byte = getFeeForTx(hex_to_binary(row[COL.TxHash]))
               rawAmt = -1 * rawAmt

            if order == "ascending":
               wltBalances[row[COL.WltID]] += rawAmt
               allBalances += rawAmt

            row.append(wltBalances[row[COL.WltID]])
            row.append(allBalances)

            if order == "descending":
               wltBalances[row[COL.WltID]] -= rawAmt
               allBalances -= rawAmt


         for row in ledgerTable:
            vals = []

            fmtstr = str(self.edtDateFormat.text())
            unixTime = row[COL.UnixTime]
            vals.append(unixTimeToFormatStr(unixTime, fmtstr))
            vals.append(hex_switchEndian(row[COL.TxHash]))
            vals.append(row[COL.NumConf])
            vals.append(row[COL.WltID])
            if row[COL.WltID] in self.main.walletMap:
               vals.append(self.main.walletMap[row[COL.WltID]].labelName.replace(',', ';'))
            else:
               vals.append(self.main.allLockboxes[self.main.lockboxIDMap[row[COL.WltID]]].shortName.replace(',', ';'))

            wltEffect = row[COL.Amount]
            txFee, fee_byte = getFeeForTx(hex_to_binary(row[COL.TxHash]))
            if float(wltEffect) >= 0:
               if row[COL.toSelf] == False:
                  vals.append(wltEffect.strip())
                  vals.append('')
                  vals.append('')
               else:
                  vals.append(wltEffect.strip() + ' (STS)')
                  vals.append('')
                  vals.append(coin2str(txFee).strip())
            else:
               vals.append('')
               vals.append(wltEffect.strip()[1:]) # remove negative sign
               vals.append(coin2str(txFee).strip())

            vals.append(coin2str(row[-2]))
            vals.append(coin2str(row[-1]))
            vals.append(row[COL.Comment])

            f.write('%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,"%s"\n' % tuple(vals))

      f.close()
      return True


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
class DlgBackupCenter(ArmoryDialog):

   #############################################################################
   def __init__(self, parent, main, wlt):
      super(DlgBackupCenter, self).__init__(parent, main)

      self.wlt = wlt
      wltID = wlt.uniqueIDB58
      wltName = wlt.labelName

      self.walletBackupFrame = WalletBackupFrame(parent, main)
      self.walletBackupFrame.setWallet(wlt)
      self.btnDone = QPushButton(self.tr('Done'))
      self.connect(self.btnDone, SIGNAL(CLICKED), self.reject)
      frmBottomBtns = makeHorizFrame([STRETCH, self.btnDone])

      layoutDialog = QVBoxLayout()

      layoutDialog.addWidget(self.walletBackupFrame)

      layoutDialog.addWidget(frmBottomBtns)

      self.setLayout(layoutDialog)
      self.setWindowTitle(self.tr("Backup Center"))
      self.setMinimumSize(640, 350)

################################################################################
class DlgSimpleBackup(ArmoryDialog):
   def __init__(self, parent, main, wlt):
      super(DlgSimpleBackup, self).__init__(parent, main)

      self.wlt = wlt

      lblDescrTitle = QRichLabel(self.tr(
         '<b>Protect Your Bitcoins -- Make a Wallet Backup!</b>'))

      lblDescr = QRichLabel(self.tr(
         'A failed hard-drive or forgotten passphrase will lead to '
         '<u>permanent loss of bitcoins</u>!  Luckily, Armory wallets only '
         'need to be backed up <u>one time</u>, and protect you in both '
         'of these events.   If you\'ve ever forgotten a password or had '
         'a hardware failure, make a backup!'))

      # ## Paper
      lblPaper = QRichLabel(self.tr(
         'Use a printer or pen-and-paper to write down your wallet "seed."'))
      btnPaper = QPushButton(self.tr('Make Paper Backup'))

      # ## Digital
      lblDigital = QRichLabel(self.tr(
         'Create an unencrypted copy of your wallet file, including imported '
         'addresses.'))
      btnDigital = QPushButton(self.tr('Make Digital Backup'))

      # ## Other
      btnOther = QPushButton(self.tr('See Other Backup Options'))

      def backupDigital():
         if self.main.digitalBackupWarning():
            self.main.makeWalletCopy(self, self.wlt, 'Decrypt', 'decrypt')
            self.accept()

      def backupPaper():
         OpenPaperBackupWindow('Single', self, self.main, self.wlt)
         self.accept()

      def backupOther():
         self.accept()
         DlgBackupCenter(self, self.main, self.wlt).exec_()

      self.connect(btnPaper, SIGNAL(CLICKED), backupPaper)
      self.connect(btnDigital, SIGNAL(CLICKED), backupDigital)
      self.connect(btnOther, SIGNAL(CLICKED), backupOther)

      layout = QGridLayout()

      layout.addWidget(lblPaper, 0, 0)
      layout.addWidget(btnPaper, 0, 2)

      layout.addWidget(HLINE(), 1, 0, 1, 3)

      layout.addWidget(lblDigital, 2, 0)
      layout.addWidget(btnDigital, 2, 2)

      layout.addWidget(HLINE(), 3, 0, 1, 3)

      layout.addWidget(makeHorizFrame([STRETCH, btnOther, STRETCH]), 4, 0, 1, 3)

      # layout.addWidget( VLINE(),      0,1, 5,1)

      layout.setContentsMargins(10, 5, 10, 5)
      setLayoutStretchRows(layout, 1, 0, 1, 0, 0)
      setLayoutStretchCols(layout, 1, 0, 0)

      frmGrid = QFrame()
      frmGrid.setFrameStyle(STYLE_PLAIN)
      frmGrid.setLayout(layout)

      btnClose = QPushButton(self.tr('Done'))
      self.connect(btnClose, SIGNAL(CLICKED), self.accept)
      frmClose = makeHorizFrame([STRETCH, btnClose])

      frmAll = makeVertFrame([lblDescrTitle, lblDescr, frmGrid, frmClose])
      layoutAll = QVBoxLayout()
      layoutAll.addWidget(frmAll)
      self.setLayout(layoutAll)
      self.sizeHint = lambda: QSize(400, 250)

      self.setWindowTitle(self.tr('Backup Options'))


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
class DlgFragBackup(ArmoryDialog):

   #############################################################################
   def __init__(self, parent, main, wlt):
      super(DlgFragBackup, self).__init__(parent, main)

      self.wlt = wlt

      lblDescrTitle = QRichLabel(self.tr(
         '<b><u>Create M-of-N Fragmented Backup</u> of "%s" (%s)</b>' % (wlt.labelName, wlt.uniqueIDB58)), doWrap=False)
      lblDescrTitle.setContentsMargins(5, 5, 5, 5)

      self.lblAboveFrags = QRichLabel('')
      self.lblAboveFrags.setContentsMargins(10, 0, 10, 0)

      frmDescr = makeVertFrame([lblDescrTitle, self.lblAboveFrags], \
                                                            STYLE_RAISED)

      self.fragDisplayLastN = 0
      self.fragDisplayLastM = 0

      self.maxM = 5 if not self.main.usermode == USERMODE.Expert else 8
      self.maxN = 6 if not self.main.usermode == USERMODE.Expert else 12
      self.currMinN = 2
      self.maxmaxN = 12

      self.comboM = QComboBox()
      self.comboN = QComboBox()

      for M in range(2, self.maxM + 1):
         self.comboM.addItem(str(M))

      for N in range(self.currMinN, self.maxN + 1):
         self.comboN.addItem(str(N))

      self.comboM.setCurrentIndex(1)
      self.comboN.setCurrentIndex(2)

      def updateM():
         self.updateComboN()
         self.createFragDisplay()

      updateN = self.createFragDisplay

      self.connect(self.comboM, SIGNAL('activated(int)'), updateM)
      self.connect(self.comboN, SIGNAL('activated(int)'), updateN)
      self.comboM.setMinimumWidth(30)
      self.comboN.setMinimumWidth(30)

      btnAccept = QPushButton(self.tr('Close'))
      self.connect(btnAccept, SIGNAL(CLICKED), self.accept)
      frmBottomBtn = makeHorizFrame([STRETCH, btnAccept])

      # We will hold all fragments here, in SBD objects.  Destroy all of them
      # before the dialog exits
      self.secureRoot = self.wlt.addrMap['ROOT'].binPrivKey32_Plain.copy()
      self.secureChain = self.wlt.addrMap['ROOT'].chaincode.copy()
      self.secureMtrx = []

      testChain = DeriveChaincodeFromRootKey(self.secureRoot)
      if testChain == self.secureChain:
         self.noNeedChaincode = True
         self.securePrint = self.secureRoot
      else:
         self.securePrint = self.secureRoot + self.secureChain

      self.chkSecurePrint = QCheckBox(self.trUtf8(u'Use SecurePrint\u200b\u2122 '
         'to prevent exposing keys to printer or other devices'))

      self.scrollArea = QScrollArea()
      self.createFragDisplay()
      self.scrollArea.setWidgetResizable(True)

      self.ttipSecurePrint = self.main.createToolTipWidget(self.trUtf8(
         u'SecurePrint\u200b\u2122 encrypts your backup with a code displayed on '
         'the screen, so that no other devices or processes has access to the '
         'unencrypted private keys (either network devices when printing, or '
         'other applications if you save a fragment to disk or USB device). '
         u'<u>You must keep the SecurePrint\u200b\u2122 code with the backup!</u>'))
      self.lblSecurePrint = QRichLabel(self.trUtf8(
         '<b><font color="%s"><u>IMPORTANT:</u>  You must keep the '
         u'SecurePrint\u200b\u2122 encryption code with your backup! '
         u'Your SecurePrint\u200b\u2122 code is </font> '
         '<font color="%s">%s</font><font color="%s">. '
         'All fragments for a given wallet use the '
         'same code.</font>' % (htmlColor('TextWarn'), htmlColor('TextBlue'), self.backupData.sppass, \
          htmlColor('TextWarn'))))
      self.connect(self.chkSecurePrint, SIGNAL(CLICKED), self.clickChkSP)
      self.chkSecurePrint.setChecked(False)
      self.lblSecurePrint.setVisible(False)
      frmChkSP = makeHorizFrame([self.chkSecurePrint, self.ttipSecurePrint, STRETCH])

      dlgLayout = QVBoxLayout()
      dlgLayout.addWidget(frmDescr)
      dlgLayout.addWidget(self.scrollArea)
      dlgLayout.addWidget(frmChkSP)
      dlgLayout.addWidget(self.lblSecurePrint)
      dlgLayout.addWidget(frmBottomBtn)
      setLayoutStretch(dlgLayout, 0, 1, 0, 0, 0)

      self.setLayout(dlgLayout)
      self.setMinimumWidth(650)
      self.setMinimumHeight(450)
      self.setWindowTitle('Create Backup Fragments')


   #############################################################################
   def clickChkSP(self):
      self.lblSecurePrint.setVisible(self.chkSecurePrint.isChecked())
      self.createFragDisplay()


   #############################################################################
   def updateComboN(self):
      M = int(str(self.comboM.currentText()))
      oldN = int(str(self.comboN.currentText()))
      self.currMinN = M
      self.comboN.clear()

      for i, N in enumerate(range(self.currMinN, self.maxN + 1)):
         self.comboN.addItem(str(N))

      if M > oldN:
         self.comboN.setCurrentIndex(0)
      else:
         for i, N in enumerate(range(self.currMinN, self.maxN + 1)):
            if N == oldN:
               self.comboN.setCurrentIndex(i)



   #############################################################################
   def createFragDisplay(self):
      M = int(str(self.comboM.currentText()))
      N = int(str(self.comboN.currentText()))

      #only recompute fragments if M or N changed
      if self.fragDisplayLastN != N or \
         self.fragDisplayLastM != M:
         self.recomputeFragData()

      self.fragDisplayLastN = N
      self.fragDisplayLastM = M

      lblAboveM = QRichLabel(self.tr('<u><b>Required Fragments</b></u> '), hAlign=Qt.AlignHCenter, doWrap=False)
      lblAboveN = QRichLabel(self.tr('<u><b>Total Fragments</b></u> '), hAlign=Qt.AlignHCenter)
      frmComboM = makeHorizFrame([STRETCH, QLabel('M:'), self.comboM, STRETCH])
      frmComboN = makeHorizFrame([STRETCH, QLabel('N:'), self.comboN, STRETCH])

      btnPrintAll = QPushButton(self.tr('Print All Fragments'))
      self.connect(btnPrintAll, SIGNAL(CLICKED), self.clickPrintAll)
      leftFrame = makeVertFrame([STRETCH, \
                                 lblAboveM, \
                                 frmComboM, \
                                 lblAboveN, \
                                 frmComboN, \
                                 STRETCH, \
                                 HLINE(), \
                                 btnPrintAll, \
                                 STRETCH], STYLE_STYLED)

      layout = QHBoxLayout()
      layout.addWidget(leftFrame)

      for f in range(N):
         layout.addWidget(self.createFragFrm(f))


      frmScroll = QFrame()
      frmScroll.setFrameStyle(STYLE_SUNKEN)
      frmScroll.setStyleSheet('QFrame { background-color : %s  }' % \
                                                htmlColor('SlightBkgdDark'))
      frmScroll.setLayout(layout)
      self.scrollArea.setWidget(frmScroll)

      BLUE = htmlColor('TextBlue')
      self.lblAboveFrags.setText(self.tr(
         'Any <font color="%s"><b>%d</b></font> of these '
         '<font color="%s"><b>%d</b></font>'
         'fragments are sufficient to restore your wallet, and each fragment '
         'has the ID, <font color="%s"><b>%s</b></font>.  All fragments with the '
         'same fragment ID are compatible with each other!' % (BLUE, M, BLUE, N, BLUE, self.fragPrefixStr)))


   #############################################################################
   def createFragFrm(self, idx):

      doMask = self.chkSecurePrint.isChecked()
      M = int(str(self.comboM.currentText()))
      N = int(str(self.comboN.currentText()))

      lblFragID = QRichLabel(self.tr('<b>Fragment ID:<br>%s-%s</b>' % \
                                    (str(self.fragPrefixStr), str(idx + 1))))
      # lblWltID = QRichLabel('(%s)' % self.wlt.uniqueIDB58)
      lblFragPix = QImageLabel(self.fragPixmapFn, size=(72, 72))
      if doMask:
         ys = self.secureMtrxCrypt[idx][1].toBinStr()[:42]
      else:
         ys = self.secureMtrx[idx][1].toBinStr()[:42]

      easyYs1 = makeSixteenBytesEasy(ys[:16   ])
      easyYs2 = makeSixteenBytesEasy(ys[ 16:32])

      binID = base58_to_binary(self.uniqueFragSetID)
      ID = ComputeFragIDLineHex(M, idx, binID, doMask, addSpaces=True)

      fragPreview = 'ID: %s...<br>' % ID[:12]
      fragPreview += 'F1: %s...<br>' % easyYs1[:12]
      fragPreview += 'F2: %s...    ' % easyYs2[:12]
      lblPreview = QRichLabel(fragPreview)
      lblPreview.setFont(GETFONT('Fixed', 9))

      lblFragIdx = QRichLabel('#%d' % (idx + 1), size=4, color='TextBlue', \
                                                   hAlign=Qt.AlignHCenter)

      frmTopLeft = makeVertFrame([lblFragID, lblFragIdx, STRETCH])
      frmTopRight = makeVertFrame([lblFragPix, STRETCH])

      frmPaper = makeVertFrame([lblPreview])
      frmPaper.setStyleSheet('QFrame { background-color : #ffffff  }')

      fnPrint = lambda: self.clickPrintFrag(idx)
      fnSave = lambda: self.clickSaveFrag(idx)

      btnPrintFrag = QPushButton(self.tr('View/Print'))
      btnSaveFrag = QPushButton(self.tr('Save to File'))
      self.connect(btnPrintFrag, SIGNAL(CLICKED), fnPrint)
      self.connect(btnSaveFrag, SIGNAL(CLICKED), fnSave)
      frmButtons = makeHorizFrame([btnPrintFrag, btnSaveFrag])


      layout = QGridLayout()
      layout.addWidget(frmTopLeft, 0, 0, 1, 1)
      layout.addWidget(frmTopRight, 0, 1, 1, 1)
      layout.addWidget(frmPaper, 1, 0, 1, 2)
      layout.addWidget(frmButtons, 2, 0, 1, 2)
      layout.setSizeConstraint(QLayout.SetFixedSize)

      outFrame = QFrame()
      outFrame.setFrameStyle(STYLE_STYLED)
      outFrame.setLayout(layout)
      return outFrame


   #############################################################################
   def clickPrintAll(self):
      self.clickPrintFrag(range(int(str(self.comboN.currentText()))))

   #############################################################################
   def clickPrintFrag(self, zindex):
      if not isinstance(zindex, (list, tuple)):
         zindex = [zindex]
      fragData = {}
      fragData['M'] = int(str(self.comboM.currentText()))
      fragData['N'] = int(str(self.comboN.currentText()))
      fragData['FragIDStr'] = self.fragPrefixStr
      fragData['FragPixmap'] = self.fragPixmapFn
      fragData['Range'] = zindex
      fragData['Secure'] = self.chkSecurePrint.isChecked()
      fragData['fragSetID'] = self.uniqueFragSetID
      dlg = DlgPrintBackup(self, self.main, self.wlt, 'Fragments', \
                              self.secureMtrx, self.secureMtrxCrypt, fragData, \
                              self.secureRoot, self.secureChain)
      dlg.exec_()

   #############################################################################
   def clickSaveFrag(self, zindex):
      saveMtrx = self.secureMtrx
      doMask = False
      if self.chkSecurePrint.isChecked():
         response = QMessageBox.question(self, self.tr('Secure Backup?'), self.trUtf8(
            u'You have selected to use SecurePrint\u200b\u2122 for the printed '
            'backups, which can also be applied to fragments saved to file. '
            u'Doing so will require you store the SecurePrint\u200b\u2122 '
            'code with the backup, but it will prevent unencrypted key data from '
            'touching any disks.  <br><br> Do you want to encrypt the fragment '
            u'file with the same SecurePrint\u200b\u2122 code?'), \
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)

         if response == QMessageBox.Yes:
            saveMtrx = self.secureMtrxCrypt
            doMask = True
         elif response == QMessageBox.No:
            pass
         else:
            return


      wid = self.wlt.uniqueIDB58
      pref = self.fragPrefixStr
      fnum = zindex + 1
      M = self.M
      sec = 'secure.' if doMask else ''
      defaultFn = 'wallet_%s_%s_num%d_need%d.%sfrag' % (wid, pref, fnum, M, sec)
      #print 'FragFN:', defaultFn
      savepath = self.main.getFileSave('Save Fragment', \
                                       ['Wallet Fragments (*.frag)'], \
                                       defaultFn)

      if len(toUnicode(savepath)) == 0:
         return

      fout = open(savepath, 'w')
      fout.write('Wallet ID:     %s\n' % wid)
      fout.write('Create Date:   %s\n' % unixTimeToFormatStr(RightNow()))
      fout.write('Fragment ID:   %s-#%d\n' % (pref, fnum))
      fout.write('Frag Needed:   %d\n' % M)
      fout.write('\n\n')

      try:
         yBin = saveMtrx[zindex][1].toBinStr()
         binID = base58_to_binary(self.uniqueFragSetID)
         IDLine = ComputeFragIDLineHex(M, zindex, binID, doMask, addSpaces=True)
         if len(yBin) == 32:
            fout.write('ID: ' + IDLine + '\n')
            fout.write('F1: ' + makeSixteenBytesEasy(yBin[:16 ]) + '\n')
            fout.write('F2: ' + makeSixteenBytesEasy(yBin[ 16:]) + '\n')
         elif len(yBin) == 64:
            fout.write('ID: ' + IDLine + '\n')
            fout.write('F1: ' + makeSixteenBytesEasy(yBin[:16       ]) + '\n')
            fout.write('F2: ' + makeSixteenBytesEasy(yBin[ 16:32    ]) + '\n')
            fout.write('F3: ' + makeSixteenBytesEasy(yBin[    32:48 ]) + '\n')
            fout.write('F4: ' + makeSixteenBytesEasy(yBin[       48:]) + '\n')
         else:
            LOGERROR('yBin is not 32 or 64 bytes!  It is %s bytes', len(yBin))
      finally:
         yBin = None

      fout.close()

      qmsg = self.tr(
         'The fragment was successfully saved to the following location: '
         '<br><br> %s <br><br>' % savepath)

      if doMask:
         qmsg += self.trUtf8(
            '<b><u><font color="%s">Important</font</u></b>: '
            'The fragment was encrypted with the '
            u'SecurePrint\u200b\u2122 encryption code.  You must keep this '
            'code with the backup in order to use it!  The code <u>is</u> '
            'case-sensitive! '
            '<br><br> <font color="%s" size=5><b>%s</b></font>'
            '<br><br>'
            'The above code <u><b>is</b></u> case-sensitive!' \
            % (htmlColor('TextWarn'), htmlColor('TextBlue'), \
            self.backupData.sppass))

      QMessageBox.information(self, self.tr('Success'), qmsg, QMessageBox.Ok)



   #############################################################################
   def destroyFrags(self):
      if len(self.secureMtrx) == 0:
         return

      if isinstance(self.secureMtrx[0], (list, tuple)):
         for sbdList in self.secureMtrx:
            for sbd in sbdList:
               sbd.destroy()
         for sbdList in self.secureMtrxCrypt:
            for sbd in sbdList:
               sbd.destroy()
      else:
         for sbd in self.secureMtrx:
            sbd.destroy()
         for sbd in self.secureMtrxCrypt:
            sbd.destroy()

      self.secureMtrx = []
      self.secureMtrxCrypt = []


   #############################################################################
   def destroyEverything(self):
      self.secureRoot.destroy()
      self.secureChain.destroy()
      self.securePrint.destroy()
      self.destroyFrags()

   #############################################################################
   def recomputeFragData(self):
      """
      Only M is needed, since N doesn't change
      """

      M = int(str(self.comboM.currentText()))
      N = int(str(self.comboN.currentText()))
      # Make sure only local variables contain non-SBD data
      self.destroyFrags()
      self.uniqueFragSetID = \
         binary_to_base58(SecureBinaryData().GenerateRandom(6).toBinStr())
      insecureData = SplitSecret(self.securePrint, M, self.maxmaxN)
      for x, y in insecureData:
         self.secureMtrx.append([SecureBinaryData(x), SecureBinaryData(y)])
      insecureData, x, y = None, None, None

      #####
      # Now we compute the SecurePrint(TM) versions of the fragments
      SECPRINT = HardcodedKeyMaskParams()
      MASK = lambda x: SECPRINT['FUNC_MASK'](x, ekey=self.binCrypt32)
      if not self.randpass or not self.binCrypt32:
         self.randpass = SECPRINT['FUNC_PWD'](self.secureRoot + self.secureChain)
         self.binCrypt32 = SECPRINT['FUNC_KDF'](self.randpass)
      self.secureMtrxCrypt = []
      for sbdX, sbdY in self.secureMtrx:
         self.secureMtrxCrypt.append([sbdX.copy(), MASK(sbdY)])
      #####

      self.M, self.N = M, N
      self.fragPrefixStr = ComputeFragIDBase58(self.M, \
                              base58_to_binary(self.uniqueFragSetID))
      self.fragPixmapFn = './img/frag%df.png' % M


   #############################################################################
   def accept(self):
      self.destroyEverything()
      super(DlgFragBackup, self).accept()

   #############################################################################
   def reject(self):
      self.destroyEverything()
      super(DlgFragBackup, self).reject()




################################################################################
class DlgUniversalRestoreSelect(ArmoryDialog):

   #############################################################################
   def __init__(self, parent, main):
      super(DlgUniversalRestoreSelect, self).__init__(parent, main)


      lblDescrTitle = QRichLabel(self.tr('<b><u>Restore Wallet from Backup</u></b>'))
      lblDescr = QRichLabel(self.tr('You can restore any kind of backup ever created by Armory using '
         'one of the options below.  If you have a list of private keys '
         'you should open the target wallet and select "Import/Sweep '
         'Private Keys."'))

      self.rdoSingle = QRadioButton(self.tr('Single-Sheet Backup (printed)'))
      self.rdoFragged = QRadioButton(self.tr('Fragmented Backup (incl. mix of paper and files)'))
      self.rdoDigital = QRadioButton(self.tr('Import digital backup or watching-only wallet'))
      self.rdoWOData = QRadioButton(self.tr('Import watching-only wallet data'))
      self.chkTest = QCheckBox(self.tr('This is a test recovery to make sure my backup works'))
      btngrp = QButtonGroup(self)
      btngrp.addButton(self.rdoSingle)
      btngrp.addButton(self.rdoFragged)
      btngrp.addButton(self.rdoDigital)
      btngrp.addButton(self.rdoWOData)
      btngrp.setExclusive(True)

      self.rdoSingle.setChecked(True)
      self.connect(self.rdoSingle, SIGNAL(CLICKED), self.clickedRadio)
      self.connect(self.rdoFragged, SIGNAL(CLICKED), self.clickedRadio)
      self.connect(self.rdoDigital, SIGNAL(CLICKED), self.clickedRadio)
      self.connect(self.rdoWOData, SIGNAL(CLICKED), self.clickedRadio)

      self.btnOkay = QPushButton(self.tr('Continue'))
      self.btnCancel = QPushButton(self.tr('Cancel'))
      buttonBox = QDialogButtonBox()
      buttonBox.addButton(self.btnOkay, QDialogButtonBox.AcceptRole)
      buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)
      self.connect(self.btnOkay, SIGNAL(CLICKED), self.clickedOkay)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)


      layout = QVBoxLayout()
      layout.addWidget(lblDescrTitle)
      layout.addWidget(lblDescr)
      layout.addWidget(HLINE())
      layout.addWidget(self.rdoSingle)
      layout.addWidget(self.rdoFragged)
      layout.addWidget(self.rdoDigital)
      layout.addWidget(self.rdoWOData)
      layout.addWidget(HLINE())
      layout.addWidget(self.chkTest)
      layout.addWidget(buttonBox)
      self.setLayout(layout)
      self.setMinimumWidth(450)

   def clickedRadio(self):
      if self.rdoDigital.isChecked():
         self.chkTest.setChecked(False)
         self.chkTest.setEnabled(False)
      else:
         self.chkTest.setEnabled(True)

   def clickedOkay(self):
      # ## Test backup option

      doTest = self.chkTest.isChecked()

      if self.rdoSingle.isChecked():
         self.accept()
         dlg = DlgRestoreSingle(self.parent, self.main, doTest)
         if dlg.exec_():
            self.main.addWalletToApplication(dlg.newWallet)
            LOGINFO('Wallet Restore Complete!')

      elif self.rdoFragged.isChecked():
         self.accept()
         dlg = DlgRestoreFragged(self.parent, self.main, doTest)
         if dlg.exec_():
            self.main.addWalletToApplication(dlg.newWallet)
            LOGINFO('Wallet Restore Complete!')
      elif self.rdoDigital.isChecked():
         self.main.execGetImportWltName()
         self.accept()
      elif self.rdoWOData.isChecked():
         # Attempt to restore the root public key & chain code for a wallet.
         # When done, ask for a wallet rescan.
         self.accept()
         dlg = DlgRestoreWOData(self.parent, self.main, doTest)
         if dlg.exec_():
            LOGINFO('Watching-Only Wallet Restore Complete! Will ask for a' \
                    'rescan.')
            self.main.addWalletToApplication(dlg.newWallet)


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
      self.connect(self, SIGNAL('cursorPositionChanged(int,int)'), self.controlCursor)

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
      self.version135aSPButton = QRadioButton(self.trUtf8(u'Version 1.35a (4 lines + SecurePrint\u200b\u2122)'), self)
      self.version135cButton = QRadioButton(self.tr('Version 1.35c (2 lines Unencrypted)'), self)
      self.version135cSPButton = QRadioButton(self.trUtf8(u'Version 1.35c (2 lines + SecurePrint\u200b\u2122)'), self)
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

      self.lblSP = QRichLabel(self.trUtf8(u'SecurePrint\u200b\u2122 Code:'), doWrap=False)
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
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.verifyUserInput)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
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
         self.connect(self.chkEncrypt, SIGNAL(CLICKED), self.onEncryptCheckboxChange)

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
               'Encountered an unkonwn error when restoring this backup. Aborting.', \
               QMessageBox.Ok))

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
         msg.promptType == ClientProto_pb2.RestorePromptType.Value("Failure"):

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
            self.processCallback, payload, callerId)

      self.callbackId = TheBDM.registerCustomPrompt(callback)
      TheBridge.restoreWallet(root, chaincode, spPass, self.callbackId)
      return

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


# Class that will create the watch-only wallet data (root public key & chain
# code) restoration window.
################################################################################
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
      self.connect(self.btnLoad, SIGNAL(CLICKED), self.loadWODataFile)
      self.connect(self.btnAccept, SIGNAL(CLICKED), self.verifyUserInput)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
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
         self.rootIDLine.setText(QString(fileLines[1]))
         for curLineNum, curLine in enumerate(fileLines[2:6]):
            self.pkccList[curLineNum].setText(QString(curLine))


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
            fragData.append(SecureBinaryData(rawBin))
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



      if currType == '0':
         X = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(1, 5)]))
         Y = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(5, 9)]))
      elif currType == BACKUP_TYPE_135A:
         X = SecureBinaryData(int_to_binary(fnum + 1, widthBytes=64, endOut=BIGENDIAN))
         Y = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(1, 5)]))
      elif currType == BACKUP_TYPE_135C:
         X = SecureBinaryData(int_to_binary(fnum + 1, widthBytes=32, endOut=BIGENDIAN))
         Y = SecureBinaryData(''.join([fragData[i].toBinStr() for i in range(1, 3)]))

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
      if len(SECRET) == 64:
         priv = SecureBinaryData(SECRET[:32 ])
         chain = SecureBinaryData(SECRET[ 32:])
      elif len(SECRET) == 32:
         priv = SecureBinaryData(SECRET)
         chain = DeriveChaincodeFromRootKey(priv)


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
         if dlgPasswd.exec_():
            passwd = SecureBinaryData(str(dlgPasswd.edtPasswd1.text()))
         else:
            QMessageBox.critical(self, self.tr('Cannot Encrypt'), self.tr(
               'You requested your restored wallet be encrypted, but no '
               'valid passphrase was supplied.  Aborting wallet '
               'recovery.'), QMessageBox.Ok)
            return

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
         if len(secret) == 64:
            priv = SecureBinaryData(secret[:32 ])
            chain = SecureBinaryData(secret[ 32:])
            return (priv, chain)
         elif len(secret) == 32:
            priv = SecureBinaryData(secret)
            chain = DeriveChaincodeFromRootKey(priv)
            return (priv, chain)
         else:
            LOGERROR('Root secret is %s bytes ?!' % len(secret))
            raise KeyDataError

      results = [(row[0], privAndChainFromRow(row[1])) for row in results]
      subsAndIDs = [(row[0], calcWalletIDFromRoot(*row[1])) for row in results]

      DlgShowTestResults(self, isRandom, subsAndIDs, \
                                 M, len(fragMtrx), self.testWltID).exec_()


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

      lblSecurePrintCodeDescr = QRichLabel(self.trUtf8(
         u'This fragment file requires a SecurePrint\u200b\u2122 code. '
         'You will only have to enter this code once since it is the same '
         'on all fragments.'))
      lblSecurePrintCodeDescr.setMinimumWidth(440)
      self.lblSP = QRichLabel(self.trUtf8(u'SecurePrint\u200b\u2122 Code: '), doWrap=False)
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

      lblDescr = QRichLabel(self.trUtf8(
         '<b><u>Enter Another Fragment...</u></b> <br><br> %s '
         'The fragments can be entered in any order, as long as you provide '
         'enough of them to restore the wallet.  If any fragments use a '
         u'SecurePrint\u200b\u2122 code, please enter it once on the '
         'previous window, and it will be applied to all fragments that '
         'require it.' % already))

      self.version0Button = QRadioButton(self.tr( BACKUP_TYPE_0_TEXT), self)
      self.version135aButton = QRadioButton(self.tr( BACKUP_TYPE_135a_TEXT), self)
      self.version135aSPButton = QRadioButton(self.trUtf8( BACKUP_TYPE_135a_SP_TEXT), self)
      self.version135cButton = QRadioButton(self.tr( BACKUP_TYPE_135c_TEXT), self)
      self.version135cSPButton = QRadioButton(self.trUtf8( BACKUP_TYPE_135c_SP_TEXT), self)
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
      self.lblSP = QRichLabel(self.trUtf8(u'SecurePrint\u200b\u2122 Code:'), doWrap=False)
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

################################################################################
class DlgReplaceWallet(ArmoryDialog):

   #############################################################################
   def __init__(self, WalletID, parent, main):
      super(DlgReplaceWallet, self).__init__(parent, main)

      lblDesc = QLabel(self.tr(
                       '<b>You already have this wallet loaded!</b><br>'
                       'You can choose to:<br>'
                       '- Cancel wallet restore operation<br>'
                       '- Set new password and fix any errors<br>'
                       '- Overwrite old wallet (delete comments & labels)<br>'))

      self.WalletID = WalletID
      self.main = main
      self.Meta = None
      self.output = 0

      self.wltPath = main.walletMap[WalletID].walletPath

      self.btnAbort = QPushButton(self.tr('Cancel'))
      self.btnReplace = QPushButton(self.tr('Overwrite'))
      self.btnSaveMeta = QPushButton(self.tr('Merge'))

      self.connect(self.btnAbort, SIGNAL('clicked()'), self.reject)
      self.connect(self.btnReplace, SIGNAL('clicked()'), self.Replace)
      self.connect(self.btnSaveMeta, SIGNAL('clicked()'), self.SaveMeta)

      layoutDlg = QGridLayout()

      layoutDlg.addWidget(lblDesc,          0, 0, 4, 4)
      layoutDlg.addWidget(self.btnAbort,    4, 0, 1, 1)
      layoutDlg.addWidget(self.btnSaveMeta, 4, 1, 1, 1)
      layoutDlg.addWidget(self.btnReplace,  4, 2, 1, 1)

      self.setLayout(layoutDlg)
      self.setWindowTitle('Wallet already exists')

   #########
   def Replace(self):
      self.main.removeWalletFromApplication(self.WalletID)

      datestr = RightNowStr('%Y-%m-%d-%H%M')
      homedir = os.path.dirname(self.wltPath)

      oldpath = os.path.join(homedir, self.WalletID, datestr)
      try:
         if not os.path.exists(oldpath):
            os.makedirs(oldpath)
      except:
         LOGEXCEPT('Cannot create new folder in dataDir! Missing credentials?')
         self.reject()
         return

      oldname = os.path.basename(self.wltPath)
      self.newname = os.path.join(oldpath, '%s_old.wallet' % (oldname[0:-7]))

      os.rename(self.wltPath, self.newname)

      backup = '%s_backup.wallet' % (self.wltPath[0:-7])
      if os.path.exists(backup):
         os.remove(backup)

      self.output =1
      self.accept()

   #########
   def SaveMeta(self):
      from armoryengine.PyBtcWalletRecovery import PyBtcWalletRecovery

      metaProgress = DlgProgress(self, self.main, Title=self.tr('Ripping Meta Data'))
      getMeta = PyBtcWalletRecovery()
      self.Meta = metaProgress.exec_(getMeta.ProcessWallet,
                                     WalletPath=self.wltPath,
                                     Mode=RECOVERMODE.Meta,
                                     Progress=metaProgress.UpdateText)
      self.Replace()


###############################################################################
class DlgWltRecoverWallet(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgWltRecoverWallet, self).__init__(parent, main)

      self.edtWalletPath = QLineEdit()
      self.edtWalletPath.setFont(GETFONT('Fixed', 9))
      edtW,edtH = tightSizeNChar(self.edtWalletPath, 50)
      self.edtWalletPath.setMinimumWidth(edtW)
      self.btnWalletPath = QPushButton(self.tr('Browse File System'))

      self.connect(self.btnWalletPath, SIGNAL('clicked()'), self.selectFile)

      lblDesc = QRichLabel(self.tr(
         '<b>Wallet Recovery Tool: '
         '</b><br>'
         'This tool will recover data from damaged or inconsistent '
         'wallets.  Specify a wallet file and Armory will analyze the '
         'wallet and fix any errors with it. '
         '<br><br>'
         '<font color="%s">If any problems are found with the specified '
         'wallet, Armory will provide explanation and instructions to '
         'transition to a new wallet.' % htmlColor('TextWarn')))
      lblDesc.setScaledContents(True)

      lblWalletPath = QRichLabel(self.tr('Wallet Path:'))

      self.selectedWltID = None

      def doWltSelect():
         dlg = DlgWalletSelect(self, self.main, self.tr('Select Wallet...'), '')
         if dlg.exec_():
            self.selectedWltID = dlg.selectedID
            wlt = self.parent.walletMap[dlg.selectedID]
            self.edtWalletPath.setText(wlt.walletPath)

      self.btnWltSelect = QPushButton(self.tr("Select Loaded Wallet"))
      self.connect(self.btnWltSelect, SIGNAL(CLICKED), doWltSelect)

      layoutMgmt = QGridLayout()
      wltSltQF = QFrame()
      wltSltQF.setFrameStyle(STYLE_SUNKEN)

      layoutWltSelect = QGridLayout()
      layoutWltSelect.addWidget(lblWalletPath,      0,0, 1, 1)
      layoutWltSelect.addWidget(self.edtWalletPath, 0,1, 1, 3)
      layoutWltSelect.addWidget(self.btnWltSelect,  1,0, 1, 2)
      layoutWltSelect.addWidget(self.btnWalletPath, 1,2, 1, 2)
      layoutWltSelect.setColumnStretch(0, 0)
      layoutWltSelect.setColumnStretch(1, 1)
      layoutWltSelect.setColumnStretch(2, 1)
      layoutWltSelect.setColumnStretch(3, 0)

      wltSltQF.setLayout(layoutWltSelect)

      layoutMgmt.addWidget(makeHorizFrame([lblDesc], STYLE_SUNKEN), 0,0, 2,4)
      layoutMgmt.addWidget(wltSltQF, 2, 0, 3, 4)

      self.rdbtnStripped = QRadioButton('', parent=self)
      self.connect(self.rdbtnStripped, SIGNAL('event()'), self.rdClicked)
      lblStripped = QLabel(self.tr('<b>Stripped Recovery</b><br>Only attempts to \
                            recover the wallet\'s rootkey and chaincode'))
      layout_StrippedH = QGridLayout()
      layout_StrippedH.addWidget(self.rdbtnStripped, 0, 0, 1, 1)
      layout_StrippedH.addWidget(lblStripped, 0, 1, 2, 19)

      self.rdbtnBare = QRadioButton('')
      lblBare = QLabel(self.tr('<b>Bare Recovery</b><br>Attempts to recover all private key related data'))
      layout_BareH = QGridLayout()
      layout_BareH.addWidget(self.rdbtnBare, 0, 0, 1, 1)
      layout_BareH.addWidget(lblBare, 0, 1, 2, 19)

      self.rdbtnFull = QRadioButton('')
      self.rdbtnFull.setChecked(True)
      lblFull = QLabel(self.tr('<b>Full Recovery</b><br>Attempts to recover as much data as possible'))
      layout_FullH = QGridLayout()
      layout_FullH.addWidget(self.rdbtnFull, 0, 0, 1, 1)
      layout_FullH.addWidget(lblFull, 0, 1, 2, 19)

      self.rdbtnCheck = QRadioButton('')
      lblCheck = QLabel(self.tr('<b>Consistency Check</b><br>Checks wallet consistency. Works with both full and watch only<br> wallets.'
                         ' Unlocking of encrypted wallets is not mandatory'))
      layout_CheckH = QGridLayout()
      layout_CheckH.addWidget(self.rdbtnCheck, 0, 0, 1, 1)
      layout_CheckH.addWidget(lblCheck, 0, 1, 3, 19)


      layoutMode = QGridLayout()
      layoutMode.addLayout(layout_StrippedH, 0, 0, 2, 4)
      layoutMode.addLayout(layout_BareH, 2, 0, 2, 4)
      layoutMode.addLayout(layout_FullH, 4, 0, 2, 4)
      layoutMode.addLayout(layout_CheckH, 6, 0, 3, 4)


      #self.rdnGroup = QButtonGroup()
      #self.rdnGroup.addButton(self.rdbtnStripped)
      #self.rdnGroup.addButton(self.rdbtnBare)
      #self.rdnGroup.addButton(self.rdbtnFull)
      #self.rdnGroup.addButton(self.rdbtnCheck)


      layoutMgmt.addLayout(layoutMode, 5, 0, 9, 4)
      """
      wltModeQF = QFrame()
      wltModeQF.setFrameStyle(STYLE_SUNKEN)
      wltModeQF.setLayout(layoutMode)

      layoutMgmt.addWidget(wltModeQF, 5, 0, 9, 4)
      wltModeQF.setVisible(False)


      btnShowAllOpts = QLabelButton(self.tr("All Recovery Options>>>"))
      frmBtn = makeHorizFrame(['Stretch', btnShowAllOpts, 'Stretch'], STYLE_SUNKEN)
      layoutMgmt.addWidget(frmBtn, 5, 0, 9, 4)

      def expandOpts():
         wltModeQF.setVisible(True)
         btnShowAllOpts.setVisible(False)
      self.connect(btnShowAllOpts, SIGNAL('clicked()'), expandOpts)

      if not self.main.usermode==USERMODE.Expert:
         frmBtn.setVisible(False)
      """

      self.btnRecover = QPushButton(self.tr('Recover'))
      self.btnCancel  = QPushButton(self.tr('Cancel'))
      layout_btnH = QHBoxLayout()
      layout_btnH.addWidget(self.btnRecover, 1)
      layout_btnH.addWidget(self.btnCancel, 1)

      def updateBtn(qstr):
         if os.path.exists(str(qstr).strip()):
            self.btnRecover.setEnabled(True)
            self.btnRecover.setToolTip('')
         else:
            self.btnRecover.setEnabled(False)
            self.btnRecover.setToolTip(self.tr('The entered path does not exist'))

      updateBtn('')
      self.connect(self.edtWalletPath, SIGNAL('textChanged(QString)'), updateBtn)


      layoutMgmt.addLayout(layout_btnH, 14, 1, 1, 2)

      self.connect(self.btnRecover, SIGNAL('clicked()'), self.accept)
      self.connect(self.btnCancel , SIGNAL('clicked()'), self.reject)

      self.setLayout(layoutMgmt)
      self.layout().setSizeConstraint(QLayout.SetFixedSize)
      self.setWindowTitle(self.tr('Wallet Recovery Tool'))
      self.setMinimumWidth(550)

   def rdClicked(self):
      # TODO:  Why does this do nohting?  Was it a stub that was forgotten?
      LOGINFO("clicked")

   def promptWalletRecovery(self):
      """
      Prompts the user with a window asking for wallet path and recovery mode.
      Proceeds to Recover the wallet. Prompt for password if the wallet is locked
      """
      if self.exec_():
         path = unicode(self.edtWalletPath.text())
         mode = RECOVERMODE.Bare
         if self.rdbtnStripped.isChecked():
            mode = RECOVERMODE.Stripped
         elif self.rdbtnFull.isChecked():
            mode = RECOVERMODE.Full
         elif self.rdbtnCheck.isChecked():
            mode = RECOVERMODE.Check

         if mode==RECOVERMODE.Full and self.selectedWltID:
            # Funnel all standard, full recovery operations through the
            # inconsistent-wallet-dialog.
            wlt = self.main.walletMap[self.selectedWltID]
            dlgRecoveryUI = DlgCorruptWallet(wlt, [], self.main, self, False)
            dlgRecoveryUI.exec_(dlgRecoveryUI.doFixWallets())
         else:
            # This is goatpig's original behavior - preserved for any
            # non-loaded wallets or non-full recovery operations.
            if self.selectedWltID:
               wlt = self.main.walletMap[self.selectedWltID]
            else:
               wlt = path

            dlgRecoveryUI = DlgCorruptWallet(wlt, [], self.main, self, False)
            dlgRecoveryUI.exec_(dlgRecoveryUI.ProcessWallet(mode))
      else:
         return False

   def selectFile(self):
      # Had to reimplement the path selection here, because the way this was
      # implemented doesn't let me access self.main.getFileLoad
      ftypes = self.tr('Wallet files (*.wallet);; All files (*)')
      if not OS_MACOSX:
         pathSelect = unicode(QFileDialog.getOpenFileName(self, \
                                 self.tr('Recover Wallet'), \
                                 ARMORY_HOME_DIR, \
                                 ftypes))
      else:
         pathSelect = unicode(QFileDialog.getOpenFileName(self, \
                                 self.tr('Recover Wallet'), \
                                 ARMORY_HOME_DIR, \
                                 ftypes, \
                                 options=QFileDialog.DontUseNativeDialog))

      self.edtWalletPath.setText(pathSelect)


#################################################################################
'''
class DlgCorruptWallet(DlgProgress):
   def __init__(self, wallet, status, main=None, parent=None, alreadyFailed=True):
      super(DlgProgress, self).__init__(parent, main)

      self.connectDlg()

      self.main = main
      self.walletList = []
      self.logDirs = []

      self.running = 1
      self.status = 1
      self.isFixing = False
      self.needToSubmitLogs = False
      self.checkMode = RECOVERMODE.NotSet

      self.lock = threading.Lock()
      self.condVar = threading.Condition(self.lock)

      mainLayout = QVBoxLayout()

      self.connect(self, SIGNAL('UCF'), self.UCF)
      self.connect(self, SIGNAL('Show'), self.show)
      self.connect(self, SIGNAL('Exec'), self.run_lock)
      self.connect(self, SIGNAL('SNP'), self.setNewProgress)
      self.connect(self, SIGNAL('LFW'), self.LFW)
      self.connect(self, SIGNAL('SRD'), self.SRD)

      if alreadyFailed:
         titleStr = self.tr('Wallet Consistency Check Failed!')
      else:
         titleStr = self.tr('Perform Wallet Consistency Check')

      lblDescr = QRichLabel(self.tr(
         '<font color="%1" size=5><b><u>%2</u></b></font> '
         '<br><br>'
         'Armory software now detects and prevents certain kinds of '
         'hardware errors that could lead to problems with your wallet. '
         '<br>').arg(htmlColor('TextWarn'), titleStr))

      lblDescr.setAlignment(Qt.AlignCenter)


      if alreadyFailed:
         self.lblFirstMsg = QRichLabel(self.tr(
            'Armory has detected that wallet file <b>Wallet "%1" (%2)</b> '
            'is inconsistent and should be further analyzed to ensure that your '
            'funds are protected. '
            '<br><br>'
            '<font color="%3">This error will pop up every time you start '
            'Armory until the wallet has been analyzed and fixed!</font>').arg(wallet.labelName, wallet.uniqueIDB58, htmlColor('TextWarn')))
      elif isinstance(wallet, PyBtcWallet):
         self.lblFirstMsg = QRichLabel(self.tr(
            'Armory will perform a consistency check on <b>Wallet "%1" (%2)</b> '
            'and determine if any further action is required to keep your funds '
            'protected.  This check is normally performed on startup on all '
            'your wallets, but you can click below to force another '
            'check.').arg(wallet.labelName, wallet.uniqueIDB58))
      else:
         self.lblFirstMsg = QRichLabel('')

      self.QDS = QDialog()
      self.lblStatus = QLabel('')
      self.addStatus(wallet, status)
      self.QDSlo = QVBoxLayout()
      self.QDS.setLayout(self.QDSlo)

      self.QDSlo.addWidget(self.lblFirstMsg)
      self.QDSlo.addWidget(self.lblStatus)

      self.lblStatus.setVisible(False)
      self.lblFirstMsg.setVisible(True)

      saStatus = QScrollArea()
      saStatus.setWidgetResizable(True)
      saStatus.setWidget(self.QDS)
      saStatus.setMinimumHeight(250)
      saStatus.setMinimumWidth(500)


      layoutButtons = QGridLayout()
      layoutButtons.setColumnStretch(0, 1)
      layoutButtons.setColumnStretch(4, 1)
      self.btnClose = QPushButton(self.tr('Hide'))
      self.btnFixWallets = QPushButton(self.tr('Run Analysis and Recovery Tool'))
      self.btnFixWallets.setDisabled(True)
      self.connect(self.btnFixWallets, SIGNAL('clicked()'), self.doFixWallets)
      self.connect(self.btnClose, SIGNAL('clicked()'), self.hide)
      layoutButtons.addWidget(self.btnClose, 0, 1, 1, 1)
      layoutButtons.addWidget(self.btnFixWallets, 0, 2, 1, 1)

      self.lblDescr2 = QRichLabel('')
      self.lblDescr2.setAlignment(Qt.AlignCenter)

      self.lblFixRdy = QRichLabel(self.tr(
         '<u>Your wallets will be ready to fix once the scan is over</u><br> '
         'You can hide this window until then<br>'))

      self.lblFixRdy.setAlignment(Qt.AlignCenter)

      self.frmBottomMsg = makeVertFrame(['Space(5)',
                                         HLINE(),
                                         self.lblDescr2,
                                         self.lblFixRdy,
                                         HLINE()])

      self.frmBottomMsg.setVisible(False)


      mainLayout.addWidget(lblDescr)
      mainLayout.addWidget(saStatus)
      mainLayout.addWidget(self.frmBottomMsg)
      mainLayout.addLayout(layoutButtons)

      self.setLayout(mainLayout)
      self.layout().setSizeConstraint(QLayout.SetFixedSize)
      self.setWindowTitle(self.tr('Wallet Error'))

   def addStatus(self, wallet, status):
      if wallet:
         strStatus = ''.join(status) + str(self.lblStatus.text())
         self.lblStatus.setText(strStatus)

         self.walletList.append(wallet)

   def show(self):
      super(DlgCorruptWallet, self).show()
      self.activateWindow()

   def run_lock(self):
      self.btnClose.setVisible(False)
      self.hide()
      super(DlgProgress, self).exec_()
      self.walletList = None

   def UpdateCanFix(self, conditions, canFix=False):
      self.emit(SIGNAL('UCF'), conditions, canFix)

   def UCF(self, conditions, canFix=False):
      self.lblFixRdy.setText('')
      if canFix:
         self.btnFixWallets.setEnabled(True)
         self.btnClose.setText(self.tr('Close'))
         self.btnClose.setVisible(False)
         self.connect(self.btnClose, SIGNAL('clicked()'), self.reject)
         self.hide()

   def doFixWallets(self):
      self.lblFixRdy.hide()
      self.adjustSize()

      self.lblStatus.setVisible(True)
      self.lblFirstMsg.setVisible(False)
      self.frmBottomMsg.setVisible(False)

      from armoryengine.PyBtcWalletRecovery import FixWalletList
      self.btnClose.setDisabled(True)
      self.btnFixWallets.setDisabled(True)
      self.isFixing = True

      self.lblStatus.hide()
      self.QDSlo.removeWidget(self.lblStatus)

      for wlt in self.walletList:
         self.main.removeWalletFromApplication(wlt.uniqueIDB58)

      FixWalletList(self.walletList, self, Progress=self.UpdateText, async=True)
      self.adjustSize()

   def ProcessWallet(self, mode=RECOVERMODE.Full):
      #Serves as the entry point for non processing wallets that arent loaded
      #or fully processed. Only takes 1 wallet at a time

      if len(self.walletList) > 0:
         wlt = None
         wltPath = ''

         if isinstance(self.walletList[0], str) or \
            isinstance(self.walletList[0], unicode):
            wltPath = self.walletList[0]
         else:
            wlt = self.walletList[0]

      self.lblDesc = QLabel('')
      self.QDSlo.addWidget(self.lblDesc)

      self.lblFixRdy.hide()
      self.adjustSize()

      self.frmBottomMsg.setVisible(False)
      self.lblStatus.setVisible(True)
      self.lblFirstMsg.setVisible(False)

      from armoryengine.PyBtcWalletRecovery import ParseWallet
      self.btnClose.setDisabled(True)
      self.btnFixWallets.setDisabled(True)
      self.isFixing = True

      self.checkMode = mode
      ParseWallet(wltPath, wlt, mode, self,
                             Progress=self.UpdateText, async=True)

   def UpdateDlg(self, text=None, HBar=None, Title=None):
      if text is not None: self.lblDesc.setText(text)
      self.adjustSize()

   def accept(self):
      self.main.emit(SIGNAL('checkForNegImports'))
      super(DlgCorruptWallet, self).accept()

   def reject(self):
      if not self.isFixing:
         super(DlgProgress, self).reject()
         self.main.emit(SIGNAL('checkForNegImports'))

   def sigSetNewProgress(self, status):
      self.emit(SIGNAL('SNP'), status)

   def setNewProgress(self, status):
      self.lblDesc = QLabel('')
      self.QDSlo.addWidget(self.lblDesc)
      #self.QDS.adjustSize()
      status[0] = 1

   def setRecoveryDone(self, badWallets, goodWallets, fixedWallets, fixers):
      self.emit(SIGNAL('SRD'), badWallets, goodWallets, fixedWallets, fixers)

   def SRD(self, badWallets, goodWallets, fixedWallets, fixerObjs):
      self.btnClose.setEnabled(True)
      self.btnClose.setVisible(True)
      self.btnClose.setText(self.tr('Continue'))
      self.btnFixWallets.setVisible(False)
      self.btnClose.disconnect(self, SIGNAL('clicked()'), self.hide)
      self.btnClose.connect(self, SIGNAL('clicked()'), self.accept)
      self.isFixing = False
      self.frmBottomMsg.setVisible(True)

      anyNegImports = False
      for fixer in fixerObjs:
         if len(fixer.negativeImports) > 0:
            anyNegImports = True
            break


      if len(badWallets) > 0:
         self.lblDescr2.setText(self.tr(
            '<font size=4 color="%1"><b>Failed to fix wallets!</b></font>').arg(htmlColor('TextWarn')))
         self.main.statusBar().showMessage('Failed to fix wallets!', 150000)
      elif len(goodWallets) == len(fixedWallets) and not anyNegImports:
         self.lblDescr2.setText(self.tr(
            '<font size=4 color="%1"><b>Wallet(s) consistent, nothing to '
            'fix.</b></font>', "", len(goodWallets)).arg(htmlColor("TextBlue")))
         self.main.statusBar().showMessage( \
            self.tr("Wallet(s) consistent!", "", len(goodWallets)) % \
            15000)
      elif len(fixedWallets) > 0 or anyNegImports:
         if self.checkMode != RECOVERMODE.Check:
            self.lblDescr2.setText(self.tr(
               '<font color="%1"><b> '
               '<font size=4><b><u>There may still be issues with your '
               'wallet!</u></b></font> '
               '<br>'
               'It is important that you send us the recovery logs '
               'and an email address so the Armory team can check for '
               'further risk to your funds!</b></font>').arg(htmlColor('TextWarn')))
            #self.main.statusBar().showMessage('Wallets fixed!', 15000)
         else:
            self.lblDescr2.setText(self.tr('<h2 style="color: red;"> \
                                    Consistency check failed! </h2>'))
      self.adjustSize()


   def loadFixedWallets(self, wallets):
      self.emit(SIGNAL('LFW'), wallets)

   def LFW(self, wallets):
      for wlt in wallets:
         newWallet = PyBtcWallet().readWalletFile(wlt)
         self.main.addWalletToApplication(newWallet, False)

      self.main.emit(SIGNAL('checkForkedImport'))


   # Decided that we can just add all the logic to
   #def checkForkedSubmitLogs(self):
      #forkedImports = []
      #for wlt in self.walletMap:
         #if self.walletMap[wlt].hasForkedImports:
            #dlgIWR = DlgInconsistentWltReport(self, self.main, self.logDirs)
            #if dlgIWR.exec_():
            #return
         #return
'''

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
