################################################################################
#                                                                              #
# Copyright (C) 2011-2021, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

from qtdialogs.qtdefines import ArmoryDialog

################################################################################
class DlgQRCodeDisplay(ArmoryDialog):
   def __init__(self, parent, main, dataToQR, descrUp='', descrDown=''):
      super(DlgQRCodeDisplay, self).__init__(parent, main)

      btnDone = QPushButton('Close')
      self.connect(btnDone, SIGNAL(CLICKED), self.accept)
      frmBtn = makeHorizFrame([STRETCH, btnDone, STRETCH])

      qrDisp = QRCodeWidget(dataToQR, parent=self)
      frmQR = makeHorizFrame([STRETCH, qrDisp, STRETCH])

      lblUp = QRichLabel(descrUp)
      lblUp.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter)
      lblDn = QRichLabel(descrDown)
      lblDn.setAlignment(Qt.AlignVCenter | Qt.AlignHCenter)



      layout = QVBoxLayout()
      layout.addWidget(lblUp)
      layout.addWidget(frmQR)
      layout.addWidget(lblDn)
      layout.addWidget(HLINE())
      layout.addWidget(frmBtn)

      self.setLayout(layout)

      w1, h1 = relaxedSizeStr(lblUp, descrUp)
      w2, h2 = relaxedSizeStr(lblDn, descrDown)
      self.setMinimumWidth(1.2 * max(w1, w2))