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
from PySide2.QtGui import QPalette, QFont
from PySide2.QtWidgets import QFrame, QGridLayout, QPushButton, QLabel, \
   QLineEdit, QHBoxLayout, QDialogButtonBox, QTextEdit, QMessageBox, \
   QApplication

from armoryengine.ArmoryUtils import DEFAULT_RECEIVE_TYPE
from armoryengine.BDM import TheBDM, BDM_OFFLINE

from armorycolors import Colors
from qtdialogs.qtdefines import determineWalletType, STRETCH, \
   STYLE_RAISED, QRichLabel, tightSizeStr, makeHorizFrame, \
   makeVertFrame, WLTTYPES, tightSizeNChar, STYLE_SUNKEN, MSGBOX, \
   createToolTipWidget
from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.QRCodeWidget import QRCodeWidget
from qtdialogs.MsgBoxWithDNAA import MsgBoxWithDNAA


################################################################################
class DlgNewAddressDisp(ArmoryDialog):
   """
   We just generated a new address, let's show it to the user and let them
   a comment to it, if they want.
   """
   def __init__(self, wlt, parent, main, loading=None):
      super(DlgNewAddressDisp, self).__init__(parent, main)

      self.wlt = wlt
      if loading is not None:
         loading.setValue(20)
      self.addr = wlt.getNextUnusedAddress()
      if loading is not None:
         loading.setValue(80)

      self.addrStr = self.addr.getAddressString()
      wlttype = determineWalletType(self.wlt, self.main)[0]
      notMyWallet = (wlttype == WLTTYPES.WatchOnly)

      lblDescr = QLabel(self.tr('The following address can be used to receive bitcoins:'))
      self.edtNewAddr = QLineEdit()
      self.edtNewAddr.setReadOnly(True)
      self.edtNewAddr.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      btnClipboard = QPushButton(self.tr('Copy to Clipboard'))
      # lbtnClipboard.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      self.lblIsCopied = QLabel(self.tr(' or '))
      self.lblIsCopied.setTextFormat(Qt.RichText)
      btnClipboard.clicked.connect(self.setClipboard)

      def openPaymentRequest():
         msgTxt = str(self.edtComm.toPlainText())
         msgTxt = msgTxt.split('\n')[0][:128]
         addrTxt = str(self.edtNewAddr.text())
         dlg = DlgRequestPayment(self, self.main, addrTxt, msg=msgTxt)
         dlg.exec_()

      btnLink = QPushButton(self.tr('Create Clickable Link'))
      btnLink.clicked.connect(openPaymentRequest)


      tooltip1 = createToolTipWidget(self.tr(
            'You can securely use this address as many times as you want. '
            'However, all people to whom you give this address will '
            'be able to see the number and amount of bitcoins <b>ever</b> '
            'sent to it.  Therefore, using a new address for each transaction '
            'improves overall privacy, but there is no security issues '
            'with reusing any address.'))

      frmNewAddr = QFrame()
      frmNewAddr.setFrameStyle(STYLE_RAISED)
      frmNewAddrLayout = QGridLayout()
      frmNewAddrLayout.addWidget(lblDescr, 0, 0, 1, 2)
      frmNewAddrLayout.addWidget(self.edtNewAddr, 1, 0, 1, 1)
      frmNewAddrLayout.addWidget(tooltip1, 1, 1, 1, 1)

      if not notMyWallet:
         palette = QPalette()
         palette.setColor(QPalette.Base, Colors.TblWltMine)
         boldFont = self.edtNewAddr.font()
         boldFont.setWeight(QFont.Bold)
         self.edtNewAddr.setFont(boldFont)
         self.edtNewAddr.setPalette(palette)
         self.edtNewAddr.setAutoFillBackground(True)

      frmCopy = QFrame()
      frmCopy.setFrameShape(QFrame.NoFrame)
      frmCopyLayout = QHBoxLayout()
      frmCopyLayout.addStretch()
      frmCopyLayout.addWidget(btnClipboard)
      frmCopyLayout.addWidget(self.lblIsCopied)
      frmCopyLayout.addWidget(btnLink)
      frmCopyLayout.addStretch()
      frmCopy.setLayout(frmCopyLayout)

      frmNewAddrLayout.addWidget(frmCopy, 2, 0, 1, 2)
      frmNewAddr.setLayout(frmNewAddrLayout)

      lblCommDescr = QLabel(self.tr(
            '(Optional) Add a label to this address, which will '
            'be shown with any relevant transactions in the '
            '"Transactions" tab.'))
      lblCommDescr.setWordWrap(True)
      self.edtComm = QTextEdit()
      tightHeight = tightSizeNChar(self.edtComm, 1)[1]
      self.edtComm.setMaximumHeight(tightHeight * 3.2)

      frmComment = QFrame()
      frmComment.setFrameStyle(QFrame.Shape(STYLE_RAISED))
      frmCommentLayout = QGridLayout()
      frmCommentLayout.addWidget(lblCommDescr, 0, 0, 1, 2)
      frmCommentLayout.addWidget(self.edtComm, 1, 0, 2, 2)
      frmComment.setLayout(frmCommentLayout)


      lblRecvWlt = QRichLabel(self.tr('Bitcoins sent to this address will '
            'appear in the wallet:'), doWrap=False)

      lblRecvWlt.setWordWrap(True)
      lblRecvWlt.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
      lblRecvWlt.setMinimumWidth(tightSizeStr(lblRecvWlt, lblRecvWlt.text())[0])

      lblRecvWltID = QLabel(\
            '<b>"%s"</b>  (%s)' % (wlt.labelName, wlt.uniqueIDB58))
      lblRecvWltID.setWordWrap(True)
      lblRecvWltID.setTextFormat(Qt.RichText)
      lblRecvWltID.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      buttonBox = QDialogButtonBox()
      self.btnDone = QPushButton(self.tr("Done"))
      self.btnDone.clicked.connect(self.accept)
      buttonBox.addButton(self.btnDone, QDialogButtonBox.AcceptRole)

      frmWlt = QFrame()
      frmWlt.setFrameShape(QFrame.Shape(STYLE_RAISED))
      frmWltLayout = QGridLayout()
      frmWltLayout.addWidget(lblRecvWlt)
      frmWltLayout.addWidget(lblRecvWltID)
      frmWlt.setLayout(frmWltLayout)


      qrdescr = QRichLabel(self.tr(\
         '<b>Scan QR code with phone or other barcode reader</b>'
         '<br><br><font size=2>(Double-click to expand)</font>'))
      qrdescr.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      self.edtNewAddr.setText(self.addrStr)
      self.smLabel = QRichLabel('<font size=2>%s</font>' % self.addrStr)
      self.qrcode = QRCodeWidget(self.addrStr, parent=self)

      self.smLabel.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
      frmQRsub2 = makeHorizFrame([STRETCH, self.qrcode, STRETCH ])
      frmQRsub3 = makeHorizFrame([STRETCH, self.smLabel, STRETCH ])
      frmQR = makeVertFrame([STRETCH, qrdescr, frmQRsub2, frmQRsub3, STRETCH ], STYLE_SUNKEN)


      def setAddressType(addrType):
         self.addrType = addrType
         self.wlt.setAddressTypeFor(self.addr, addrType)
         self.addrStr = self.addr.getAddressString()

         self.edtNewAddr.setText(self.addrStr)
         self.smLabel.setText('<font size=2>%s</font>' % self.addrStr)
         self.qrcode.setAsciiData(self.addrStr)
         self.qrcode.repaint()

      #addr type selection frame
      from ui.AddressTypeSelectDialog import AddressLabelFrame
      self.addrType = self.wlt.getDefaultAddressType()
      self.addrTypeFrame = AddressLabelFrame(\
         main, setAddressType, self.wlt.getAddressTypes(), self.addrType)

      layout = QGridLayout()
      layout.addWidget(frmNewAddr, 0, 0, 1, 1)
      layout.addWidget(self.addrTypeFrame.getFrame(), 2, 0, 1, 1)
      layout.addWidget(frmComment, 4, 0, 1, 1)
      layout.addWidget(frmWlt, 5, 0, 1, 1)
      layout.addWidget(buttonBox, 6, 0, 1, 2)
      layout.addWidget(frmQR, 0, 1, 6, 1)
      if loading is not None:
         loading.reject()
      self.setLayout(layout)
      self.setWindowTitle(self.tr('New Receiving Address'))
      self.setFocus()

      try:
         self.parent.wltAddrModel.reset()
      except AttributeError:
         # Sometimes this is called from a dialog that doesn't have an addr model
         pass


   def acceptNewAddr(self):
      comm = str(self.edtComm.toPlainText())
      if len(comm) > 0:
         self.wlt.setComment(self.addr.getAddr160(), comm)

   def accept(self):
      self.acceptNewAddr()
      super(DlgNewAddressDisp, self).accept()

   def reject(self):
      self.acceptNewAddr()
      super(DlgNewAddressDisp, self).reject()

   def setClipboard(self):
      clipb = QApplication.clipboard()
      clipb.clear()
      clipb.setText(self.addrStr)
      self.lblIsCopied.setText(self.tr('<i>Copied!</i>'))

################################################################################
def ShowRecvCoinsWarningIfNecessary(wlt, parent, main):
   numTimesOnline = main.getSettingOrSetDefault("SyncSuccessCount", 0)
   if numTimesOnline < 1 and not TheBDM.getState() == BDM_OFFLINE:
      result = QMessageBox.warning(main, main.tr('Careful!'), main.tr(
         'Armory is not online yet, and will eventually need to be online to '
         'access any funds sent to your wallet.  Please <u><b>do not</b></u> '
         'receive Bitcoins to your Armory wallets until you have successfully '
         'gotten online <i>at least one time</i>. '
         '<br><br> '
         'Armory is still beta software, and some users report difficulty '
         'ever getting online. '
         '<br><br> '
         'Do you wish to continue? '), QMessageBox.Cancel | QMessageBox.Ok)
      if not result == QMessageBox.Ok:
         return False

   wlttype = determineWalletType(wlt, main)[0]
   notMyWallet = (wlttype == WLTTYPES.WatchOnly)
   offlineWallet = (wlttype == WLTTYPES.Offline)
   dnaaPropName = 'Wallet_%s_%s' % (wlt.uniqueIDB58, 'DNAA_RecvOther')
   dnaaThisWallet = main.getSettingOrSetDefault(dnaaPropName, False)
   if notMyWallet and not dnaaThisWallet:
      result = MsgBoxWithDNAA(parent, main, MSGBOX.Warning, parent.tr('This is not your wallet!'), parent.tr(
            'You are getting an address for a wallet that '
            'does not appear to belong to you.  Any money sent to this '
            'address will not appear in your total balance, and cannot '
            'be spent from this computer.'
            '<br><br>'
            'If this is actually your wallet (perhaps you maintain the full '
            'wallet on a separate computer), then please change the '
            '"Belongs To" field in the wallet-properties for this wallet.'), \
            parent.tr('Do not show this warning again'), wCancel=True)
      main.writeSetting(dnaaPropName, result[1])
      return result[0]

   if offlineWallet and not dnaaThisWallet:
      result = MsgBoxWithDNAA(parent, main, MSGBOX.Warning, parent.tr('This wallet has no private keys!'), parent.tr(
            'You are getting an address for a wallet that '
            'you have specified belongs to you, but you cannot actually '
            'spend the funds from this computer.  This is usually the case when '
            'you keep the full wallet on a separate computer for security '
            'purposes.'
            '<br><br>'
            'If this does not sound right, then please do not use the following '
            'address.  Instead, change the wallet properties "Belongs To" field '
            'to specify that this wallet is not actually yours.'), \
            parent.tr('Do not show this warning again'), wCancel=True)
      main.writeSetting(dnaaPropName, result[1])
      return result[0]
   return True