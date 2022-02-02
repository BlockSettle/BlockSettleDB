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

from PySide2.QtWidgets import QVBoxLayout

from qtdialogs.qtdefines import QRichLabel
from qtdialogs.ArmoryDialog import ArmoryDialog

# Create a very simple dialog and execute it
class DlgInflatedQR(ArmoryDialog):
   def __init__(self, parent, dataToQR):
      super(DlgInflatedQR, self).__init__(parent, parent.main)

      sz = QApplication.desktop().size()
      w,h = sz.width(), sz.height()
      qrSize = int(min(w,h)*0.8)
      qrDisp = QRCodeWidget(dataToQR, prefSize=qrSize)

      def closeDlg(*args):
         self.accept()
      qrDisp.mouseDoubleClickEvent = closeDlg
      self.mouseDoubleClickEvent = closeDlg

      lbl = QRichLabel(self.tr('<b>Double-click or press ESC to close</b>'))
      lbl.setAlignment(Qt.AlignTop | Qt.AlignHCenter)

      frmQR = makeHorizFrame(['Stretch', qrDisp, 'Stretch'])
      frmFull = makeVertFrame(['Stretch',frmQR, lbl, 'Stretch'])

      layout = QVBoxLayout()
      layout.addWidget(frmFull)

      self.setLayout(layout)
      self.showFullScreen()
