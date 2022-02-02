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

from PySide2.QtCore import Qt, SIGNAL
from PySide2.QtWidgets import QLabel, QDialogButtonBox, QPushButton, \
    QSpacerItem, QGridLayout, QSizePolicy
from PySide2.QtGui import QPixmap

from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.qtdefines import MSGBOX, tightSizeNChar

################################################################################
# The optionalMsg argument is not word wrapped so the caller is responsible for limiting
# the length of the longest line in the optionalMsg
def MsgBoxCustom(wtype, title, msg, wCancel=False, yesStr=None, noStr=None,
                                                     optionalMsg=None):
   """
   Creates a message box with custom button text and icon
   """

   class dlgWarn(ArmoryDialog):
      def __init__(self, dtype, dtitle, wmsg, withCancel=False, yesStr=None, noStr=None):
         super(dlgWarn, self).__init__(None)

         msgIcon = QLabel()
         fpix = ''
         if dtype==MSGBOX.Good:
            fpix = './img/MsgBox_good48.png'
         if dtype==MSGBOX.Info:
            fpix = './img/MsgBox_info48.png'
         if dtype==MSGBOX.Question:
            fpix = './img/MsgBox_question64.png'
         if dtype==MSGBOX.Warning:
            fpix = './img/MsgBox_warning48.png'
         if dtype==MSGBOX.Critical:
            fpix = './img/MsgBox_critical64.png'
         if dtype==MSGBOX.Error:
            fpix = './img/MsgBox_error64.png'


         if len(fpix)>0:
            msgIcon.setPixmap(QPixmap(fpix))
            msgIcon.setAlignment(Qt.AlignHCenter | Qt.AlignTop)

         lblMsg = QLabel(msg)
         lblMsg.setTextFormat(Qt.RichText)
         lblMsg.setWordWrap(True)
         lblMsg.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
         lblMsg.setOpenExternalLinks(True)
         w,h = tightSizeNChar(lblMsg, 70)
         lblMsg.setMinimumSize( w, 3.2*h )
         buttonbox = QDialogButtonBox()

         if dtype==MSGBOX.Question:
            if not yesStr: yesStr = self.tr('&Yes')
            if not noStr:  noStr = self.tr('&No')
            btnYes = QPushButton(yesStr)
            btnNo  = QPushButton(noStr)
            self.connect(btnYes, SIGNAL('clicked()'), self.accept)
            self.connect(btnNo,  SIGNAL('clicked()'), self.reject)
            buttonbox.addButton(btnYes,QDialogButtonBox.AcceptRole)
            buttonbox.addButton(btnNo, QDialogButtonBox.RejectRole)
         else:
            cancelStr = self.tr('&Cancel') if (noStr is not None or withCancel) else ''
            yesStr    = self.tr('&OK') if (yesStr is None) else yesStr
            btnOk     = QPushButton(yesStr)
            btnCancel = QPushButton(cancelStr)
            self.connect(btnOk,     SIGNAL('clicked()'), self.accept)
            self.connect(btnCancel, SIGNAL('clicked()'), self.reject)
            buttonbox.addButton(btnOk, QDialogButtonBox.AcceptRole)
            if cancelStr:
               buttonbox.addButton(btnCancel, QDialogButtonBox.RejectRole)

         spacer = QSpacerItem(20, 10, QSizePolicy.Fixed, QSizePolicy.Expanding)

         layout = QGridLayout()
         layout.addItem(  spacer,         0,0, 1,2)
         layout.addWidget(msgIcon,        1,0, 1,1)
         layout.addWidget(lblMsg,         1,1, 1,1)
         if optionalMsg:
            optionalTextLabel = QLabel(optionalMsg)
            optionalTextLabel.setTextFormat(Qt.RichText)
            optionalTextLabel.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            w,h = tightSizeNChar(optionalTextLabel, 70)
            optionalTextLabel.setMinimumSize( w, 3.2*h )
            layout.addWidget(optionalTextLabel, 2,0,1,2)
         layout.addWidget(buttonbox, 3,0, 1,2)
         layout.setSpacing(20)
         self.setLayout(layout)
         self.setWindowTitle(dtitle)

   dlg = dlgWarn(wtype, title, msg, wCancel, yesStr, noStr)
   result = dlg.exec_()

   return result