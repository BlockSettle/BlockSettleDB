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

from PySide2.QtCore import Qt, QSize
from PySide2.QtGui import QIcon, QPixmap
from PySide2.QtWidgets import QLabel, QSpacerItem, QSizePolicy, QCheckBox, \
   QGridLayout, QDialogButtonBox, QPushButton

from qtdialogs.qtdefines import QRichLabel, GETFONT, \
   makeLayoutFrame, VERTICAL, HORIZONTAL, STRETCH
from qtdialogs.ArmoryDialog import ArmoryDialog

################################################################################
class DlgIntroMessage(ArmoryDialog):
   def __init__(self, parent=None, main=None):
      super(DlgIntroMessage, self).__init__(parent, main)

      lblInfoImg = QLabel()
      lblInfoImg.setPixmap(QPixmap('./img/MsgBox_info48.png'))
      lblInfoImg.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
      lblInfoImg.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
      lblInfoImg.setMaximumWidth(50)

      lblWelcome = QRichLabel(self.tr('<b>Welcome to Armory!</b>'))
      lblWelcome.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
      lblWelcome.setFont(GETFONT('Var', 14))
      lblSlogan = QRichLabel(\
         self.tr('<i>The most advanced Bitcoin Client on Earth!</i>'))
      lblSlogan.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

      lblDescr = QRichLabel(self.tr(
         '<b>You are about to use the most secure and feature-rich Bitcoin client '
         'software available!</b>  But please remember, this software '
         'is still <i>Beta</i> - Armory developers will not be held responsible '
         'for loss of bitcoins resulting from the use of this software!'
         '<br><br>'))
      lblDescr.setOpenExternalLinks(True)

      spacer = lambda: QSpacerItem(20, 20, QSizePolicy.Fixed, QSizePolicy.Expanding)
      frmText = makeLayoutFrame(VERTICAL, [lblWelcome, spacer(), lblDescr])


      self.chkDnaaIntroDlg = QCheckBox(self.tr('Do not show this window again'))

      self.requestCreate = False
      self.requestImport = False
      buttonBox = QDialogButtonBox()
      frmIcon = makeLayoutFrame(VERTICAL, [lblInfoImg, STRETCH])
      frmIcon.setMaximumWidth(60)

      if len(self.main.walletMap) == 0:
         self.btnCreate = QPushButton(self.tr("Create Your First Wallet!"))
         self.btnImport = QPushButton(self.tr("Import Existing Wallet"))
         self.btnCancel = QPushButton(self.tr("Skip"))
         self.btnCreate.clicked.connect(self.createClicked)
         self.btnImport.clicked.connect(self.importClicked)
         self.btnCancel.clicked.connect(self.reject)
         buttonBox.addButton(self.btnCreate, QDialogButtonBox.AcceptRole)
         buttonBox.addButton(self.btnImport, QDialogButtonBox.AcceptRole)
         buttonBox.addButton(self.btnCancel, QDialogButtonBox.RejectRole)
         self.chkDnaaIntroDlg.setVisible(False)
         frmBtn = makeLayoutFrame(HORIZONTAL, [self.chkDnaaIntroDlg, \
                                            self.btnCancel, \
                                            STRETCH, \
                                            self.btnImport, \
                                            self.btnCreate])
      else:
         self.btnOkay = QPushButton(self.tr("OK!"))
         self.connect(self.btnOkay, SIGNAL(CLICKED), self.accept)
         buttonBox.addButton(self.btnOkay, QDialogButtonBox.AcceptRole)
         frmBtn = makeLayoutFrame(HORIZONTAL, [self.chkDnaaIntroDlg, \
                                            STRETCH, \
                                            self.btnOkay])

      dlgLayout = QGridLayout()
      dlgLayout.addWidget(frmIcon, 0, 0, 1, 1)
      dlgLayout.addWidget(frmText, 0, 1, 1, 1)
      dlgLayout.addWidget(frmBtn, 1, 0, 1, 2)

      self.setLayout(dlgLayout)
      self.setWindowTitle(self.tr('Greetings!'))
      self.setWindowIcon(QIcon(self.main.iconfile))
      self.setMinimumWidth(750)


   def createClicked(self):
      self.requestCreate = True
      self.accept()

   def importClicked(self):
      self.requestImport = True
      self.accept()

   def sizeHint(self):
      return QSize(750, 500)