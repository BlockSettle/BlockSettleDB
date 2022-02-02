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
from PySide2.QtWidgets import QLabel, QMessageBox, QPushButton, QDialogButtonBox, \
        QCheckBox, QSpacerItem, QSizePolicy, QGridLayout
from PySide2.QtGui import QPixmap

from qtdialogs.qtdefines import MSGBOX, tightSizeNChar
from qtdialogs.ArmoryDialog import ArmoryDialog

def MsgBoxWithDNAA(parent, main, wtype, title, msg, dnaaMsg, wCancel=False, \
                  yesStr='Yes', noStr='No', dnaaStartChk=False):
   """
   Creates a warning/question/critical dialog, but with a "Do not ask again"
   checkbox.  Will return a pair  (response, DNAA-is-checked)
   """

   class dlgWarn(ArmoryDialog):
      def __init__(self, parent, main, dtype, dtitle, wmsg, dmsg=None, withCancel=False):
         super(dlgWarn, self).__init__(parent, main)

         msgIcon = QLabel()
         fpix = ''
         if dtype==MSGBOX.Info:
            fpix = './img/MsgBox_info48.png'
            if not dmsg:  dmsg = self.tr('Do not show this message again')
         if dtype==MSGBOX.Question:
            fpix = './img/MsgBox_question64.png'
            if not dmsg:  dmsg = self.tr('Do not ask again')
         if dtype==MSGBOX.Warning:
            fpix = './img/MsgBox_warning48.png'
            if not dmsg:  dmsg = self.tr('Do not show this warning again')
         if dtype==MSGBOX.Critical:
            fpix = './img/MsgBox_critical64.png'
            if not dmsg:  dmsg = None  # should always show crits
         if dtype==MSGBOX.Error:
            fpix = './img/MsgBox_error64.png'
            if not dmsg:  dmsg = None  # should always show errors


         if len(fpix)>0:
            msgIcon.setPixmap(QPixmap(fpix))
            msgIcon.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

         self.chkDnaa = QCheckBox(dmsg)
         self.chkDnaa.setChecked(dnaaStartChk)
         lblMsg = QLabel(msg)
         lblMsg.setTextFormat(Qt.RichText)
         lblMsg.setWordWrap(True)
         lblMsg.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
         w,h = tightSizeNChar(lblMsg, 50)
         lblMsg.setMinimumSize( w, 3.2*h )
         lblMsg.setOpenExternalLinks(True)

         buttonbox = QDialogButtonBox()

         if dtype==MSGBOX.Question:
            btnYes = QPushButton(yesStr)
            btnNo  = QPushButton(noStr)
            btnYes.clicked.connect(self.accept)
            btnNo.clicked.connect(self.reject)
            buttonbox.addButton(btnYes,QDialogButtonBox.AcceptRole)
            buttonbox.addButton(btnNo, QDialogButtonBox.RejectRole)
         else:
            btnOk = QPushButton('Ok')
            btnOk.clicked.connect(self.accept)
            buttonbox.addButton(btnOk, QDialogButtonBox.AcceptRole)
            if withCancel:
               btnCancel = QPushButton('Cancel')
               btnCancel.clicked.connect(self.reject)
               buttonbox.addButton(btnCancel, QDialogButtonBox.RejectRole)


         spacer = QSpacerItem(20, 10, QSizePolicy.Fixed, QSizePolicy.Expanding)


         layout = QGridLayout()
         layout.addItem(  spacer,         0,0, 1,2)
         layout.addWidget(msgIcon,        1,0, 1,1)
         layout.addWidget(lblMsg,         1,1, 1,1)
         layout.addWidget(self.chkDnaa,   2,0, 1,2)
         layout.addWidget(buttonbox,      3,0, 1,2)
         layout.setSpacing(20)
         self.setLayout(layout)
         self.setWindowTitle(dtitle)


   dlg = dlgWarn(parent, main, wtype, title, msg, dnaaMsg, wCancel)
   result = dlg.exec_()

   return (result, dlg.chkDnaa.isChecked())