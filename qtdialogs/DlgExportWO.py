################################################################################
#                                                                              #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
# Copyright (C) 2016-2025, goatpig                                             #
#  Distributed under the MIT license                                           #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                      #
#                                                                              #
################################################################################

from qtpy import QtCore, QtWidgets

from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.qtdefines import QRichLabel, makeVertFrame, HLINE
from ui.QtExecuteSignal import TheSignalExecution

################################################################################
# Class that acts as a center where the user can decide what to do with the
# watch-only wallet. The data can be displayed, printed, or saved to a file as
# a wallet or as the watch-only data (i.e., root key & chain code).
class DlgExpWOWltData(ArmoryDialog):
   def __init__(self, wlt, parent, main):
      super().__init__(parent, main)
      self.wlt = wlt

      # Get the chain code and uncompressed public key of info from the wallet,
      # along with other useful info.
      wltRootIDConcat, pkccET16Lines = wlt.getRootPKCCBackupData(True)
      wltIDB58 = wlt.walletId

      # Create the data export buttons.
      expWltButton = QtWidgets.QPushButton(
         self.tr('Export Watching-Only Wallet File'))
      clipboardBtn = QtWidgets.QPushButton(
         self.tr('Copy to clipboard'))
      clipboardLbl = QRichLabel('', hAlign=QtCore.Qt.AlignHCenter)
      expDataButton = QtWidgets.QPushButton(
         self.tr('Save to Text File'))
      printWODataButton = QtWidgets.QPushButton(
         self.tr('Print Root Data'))

      expWltButton.clicked.connect(self.clickedExpWlt)
      expDataButton.clicked.connect(self.clickedExpData)
      printWODataButton.clicked.connect(self.clickedPrintWOData)

      # Let's put the window together.
      layout = QtWidgets.QVBoxLayout()
      self.dispText = self.tr(
         'Watch-Only Root ID:<br><b>%s</b>'
         '<br><br>'
         'Watch-Only Root Data:' % wltRootIDConcat)
      for j in pkccET16Lines:
         self.dispText += '<br><b>%s</b>' % (j)

      titleStr = self.tr('Watch-Only Wallet Export')
      self.txtLongDescr = QtWidgets.QTextBrowser()
      self.txtLongDescr.setFont(GETFONT('Fixed', 9))
      self.txtLongDescr.setHtml(self.dispText)
      w,h = tightSizeNChar(self.txtLongDescr, 20)
      self.txtLongDescr.setMaximumHeight(int(9.5*h))

      def clippy():
         clipb = QtWidgets.QApplication.clipboard()
         clipb.clear()
         clipb.setText(str(self.txtLongDescr.toPlainText()))
         clipboardLbl.setText(self.tr('<i>Copied!</i>'))
      clipboardBtn.clicked.connect(clippy)

      lblDescr = QRichLabel(self.tr(
         '<center><b><u><font size=4 color="%s">Export Watch-Only '
         'Wallet: %s</font></u></b></center> '
         '<br>'
         'Use a watching-only wallet on an online computer to distribute '
         'payment addresses, verify transactions and monitor balances, but '
         'without the ability to move the funds.' \
         % (htmlColor('TextBlue'), wlt.uniqueIDB58)))

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

      btnDone = QtWidgets.QPushButton(self.tr('Done'))
      btnDone.clicked.connect(self.accept)

      frmButtons = makeVertFrame([
         clipboardBtn,
         expDataButton,
         printWODataButton,
         clipboardLbl,
         'Stretch'])
      layoutBottom = QtWidgets.QHBoxLayout()
      layoutBottom.addWidget(frmButtons, 0)
      layoutBottom.addItem(QtWidgets.QSpacerItem(5,5))
      layoutBottom.addWidget(self.txtLongDescr, 1)
      layoutBottom.setSpacing(5)

      layout.addWidget(lblDescr)
      layout.addItem(QtWidgets.QSpacerItem(10, 10))
      layout.addWidget(HLINE())
      layout.addWidget(lblTopHalf, 1)
      layout.addWidget(makeHorizFrame(['Stretch', expWltButton, 'Stretch']))
      layout.addItem(QtWidgets.QSpacerItem(20, 20))
      layout.addWidget(HLINE())
      layout.addWidget(lblBotHalf, 1)
      layout.addLayout(layoutBottom)
      layout.addItem(QtWidgets.QSpacerItem(20, 20))
      layout.addWidget(HLINE())
      layout.addWidget(makeHorizFrame(['Stretch', btnDone]))
      layout.setSpacing(3)

      self.setLayout(layout)
      self.setMinimumWidth(600)

      # TODO:  Dear god this is terrible, but for my life I cannot figure
      #        out how to move the vbar, because you can't do it until
      #        the dialog is drawn which doesn't happen til after __init__.
      TheSignalExecution.executeMethod(self.resizeEvent)
      self.setWindowTitle(titleStr)

   def resizeEvent(self, ev=None):
      super().resizeEvent(ev)
      vbar = self.txtLongDescr.verticalScrollBar()
      vbar.setValue(vbar.minimum())

   # The function that is executed when the user wants to back up the full
   # watch-only wallet to a file.
   def clickedExpWlt(self):
      currPath = self.wlt.walletPath
      if not self.wlt.watchingOnly:
         pieces = os.path.splitext(currPath)
         currPath = pieces[0] + '_WatchOnly' + pieces[1]

      saveLoc = self.main.getFileSave('Save Watching-Only Copy',
         defaultFilename=currPath)
      if not saveLoc.endswith('.wallet'):
         saveLoc += '.wallet'

      if not self.wlt.watchingOnly:
         self.wlt.forkOnlineWallet(saveLoc, self.wlt.labelName,
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
      self.view = QtWidgets.QGraphicsView()
      self.view.setRenderHint(QtGui.QPainter.TextAntialiasing)
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
      self.btnPrint = QtWidgets.QPushButton('&Print...')
      self.btnPrint.setMinimumWidth(3 * tightSizeStr(self.btnPrint, 'Print...')[0])
      self.btnCancel = QtWidgets.QPushButton('&Cancel')
      self.connect(self.btnPrint, SIGNAL(CLICKED), self.print_)
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.reject)
      frmButtons = makeHorizFrame([self.btnCancel, STRETCH, self.btnPrint])

      # Draw the sheet for the first time.
      self.redrawBackup()

      # Lay out the dialog.
      layout = QtWidgets.QVBoxLayout()
      layout.addWidget(frmDescr)
      layout.addWidget(self.view)
      layout.addWidget(frmButtons)
      setLayoutStretch(layout, 0, 1, 0)
      self.setLayout(layout)
      self.setWindowIcon(QtGui.QIcon('./img/printer_icon.png'))
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
         painter = QtGui.QPainter(self.printer)
         painter.setRenderHint(QtGui.QPainter.TextAntialiasing)

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
                          fillColor=QtGui.QColor(255, 255, 255))
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
                          edgeColor=QtGui.QColor(0, 0, 0), fillColor=None)

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

def checkSecurePrintCode(context, SECPRINT, securePrintCode):
   result = True
   try:
      if len(securePrintCode) < 9:
         QtWidgets.QMessageBox.critical(context, context.tr('Invalid Code'), context.trUtf8(
            u'You didn\'t enter a full SecurePrint\u200b\u2122 code.  This '
            'code is needed to decrypt your backup file.'), QtWidgets.QMessageBox.Ok)
         result = False
      elif not SECPRINT['FUNC_CHKPWD'](securePrintCode):
         QtWidgets.QMessageBox.critical(context, context.trUtf8(u'Bad SecurePrint\u200b\u2122 Code'), context.trUtf8(
            u'The SecurePrint\u200b\u2122 code you entered has an error '
            'in it.  Note that the code is case-sensitive.  Please verify '
            'you entered it correctly and try again.'), QtWidgets.QMessageBox.Ok)
         result = False
   except NonBase58CharacterError as e:
      QtWidgets.QMessageBox.critical(context, context.trUtf8(u'Bad SecurePrint\u200b\u2122 Code'), context.trUtf8(
         u'The SecurePrint\u200b\u2122 code you entered has unrecognized characters '
         'in it.  %s Only the following characters are allowed: %s' % (e.message, BASE58CHARS)), QtWidgets.QMessageBox.Ok)
      result = False
   return result
