################################################################################
#                                                                              #
# Copyright (C) 2011-2021, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

from qtdialogs.qtdefines import ArmoryDialog

################################################################################
class DlgBrowserWarn(ArmoryDialog):
   def __init__(self, link, parent=None, main=None):
      super(DlgBrowserWarn, self).__init__(parent, main)

      self.link = link
      self.btnCancel = QPushButton("Cancel")
      self.connect(self.btnCancel, SIGNAL(CLICKED), self.cancel)
      self.btnContinue = QPushButton("Continue")
      self.connect(self.btnContinue, SIGNAL(CLICKED), self.accept)
      btnBox = makeHorizFrame([STRETCH, self.btnCancel, self.btnContinue])

      lblWarn = QRichLabel(self.tr('Your default browser will now open and go to the following link: %s. Are you sure you want to proceed?' % self.link))

      dlgLayout = QVBoxLayout()
      frmAll = makeVertFrame([lblWarn, btnBox])

      dlgLayout.addWidget(frmAll)
      self.setLayout(dlgLayout)
      self.setWindowTitle('Warning: Opening Browser')

   def cancel(self):
      super(DlgBrowserWarn, self).reject()

   def accept(self):
     import webbrowser
     webbrowser.open(self.link)
     super(DlgBrowserWarn, self).accept()
