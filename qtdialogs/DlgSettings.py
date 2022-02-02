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
import time
import os

from PySide2.QtCore import Qt, QLocale, SIGNAL
from PySide2.QtWidgets import QPushButton, QRadioButton, QLineEdit, \
   QCheckBox, QMessageBox, QGridLayout, QLabel, QTabWidget, QVBoxLayout, \
   QScrollArea, QFrame, QComboBox, QSlider

from armoryengine.ArmoryUtils import BTC_HOME_DIR, DEFAULT_ADDR_TYPE, \
   OS_MACOSX, OS_WINDOWS, ARMORY_DB_DIR, LANGUAGES, OS_VARIANT, \
   unixTimeToFormatStr, coin2str, str2coin, MIN_FEE_BYTE, \
   MIN_TX_FEE, DEFAULT_FEE_TYPE, FORMAT_SYMBOLS, \
   DEFAULT_DATE_FORMAT, DEFAULT_CHANGE_TYPE, DEFAULT_RECEIVE_TYPE

from armoryengine.CoinSelection import NBLOCKS_TO_CONFIRM

from qtdialogs.qtdefines import USERMODE, GETFONT, \
   HLINE, tightSizeStr, tightSizeNChar, STYLE_RAISED, \
   QRichLabel, createDirectorySelectButton, makeHorizFrame, \
   makeVertFrame

from qtdialogs.ArmoryDialog import ArmoryDialog

from ui.AddressTypeSelectDialog import AddressLabelFrame

MIN_PASSWD_WIDTH = lambda obj: tightSizeStr(obj, '*' * 16)[0]
NO_CHANGE = 'NoChange'
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


###############################################################################
class DlgSettings(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgSettings, self).__init__(parent, main)

      defaultWltID = self.main.walletIDList[0]
      self.wlt = self.main.walletMap[defaultWltID]
      self.addrType = self.main.getSettingOrSetDefault('Default_ReceiveType', self.wlt.getDefaultAddressType())
        #######################################################################
        # bitcoind-management settings
      self.chkManageSatoshi = QCheckBox(self.tr(
         'Let Armory run Bitcoin Core/bitcoind in the background'))
      self.edtSatoshiExePath = QLineEdit()
      self.edtSatoshiHomePath = QLineEdit()
      self.edtArmoryDbdir = QLineEdit()

      self.edtSatoshiExePath.setMinimumWidth(
              tightSizeNChar(GETFONT('Fixed', 10), 40)[0])
      self.connect(
              self.chkManageSatoshi, SIGNAL('clicked()'),
              self.clickChkManage)
      self.startChk = self.main.getSettingOrSetDefault(
              'ManageSatoshi', not OS_MACOSX)
      if self.startChk:
         self.chkManageSatoshi.setChecked(True)
      if OS_MACOSX:
         self.chkManageSatoshi.setEnabled(False)
         lblManageSatoshi = QRichLabel(self.tr(
              'Bitcoin Core/bitcoind management is not available on Mac/OSX')
              )
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

      self.connect(btnDefaultURI, SIGNAL('clicked()'), clickRegURI)

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
      self.connect(self.btnResetFormat, SIGNAL('clicked()'), doReset)

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
      self.connect(self.btnCancel, SIGNAL('clicked()'), self.reject)
      self.connect(self.btnAccept, SIGNAL('clicked()'), self.accept)

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

      self.changeType = self.main.getSettingOrSetDefault('Default_ChangeType', self.wlt.getDefaultAddressType())
      self.changeTypeFrame = AddressLabelFrame(self.main, setChangeType, self.wlt.getAddressTypes(), self.changeType)

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

      changeRadio(self.changeType)

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

      self.addrType = self.main.getSettingOrSetDefault('Default_ReceiveType', self.wlt.getDefaultAddressType())
      self.addrTypeFrame = AddressLabelFrame(self.main, setAddrType, self.wlt.getAddressTypes(), self.addrType)
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
         pathExe = str(self.edtSatoshiExePath.text()).strip()
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
      DEFAULT_ADDR_TYPE = self.addrType

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