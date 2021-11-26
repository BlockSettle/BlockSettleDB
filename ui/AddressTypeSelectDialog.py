from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
##############################################################################
#                                                                            #
# Copyright (C) 2016-2021, goatpig                                           #
#  Distributed under the MIT license                                         #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                    #
#                                                                            #
##############################################################################

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QPushButton, QGridLayout, QFrame, QLabel, \
   QRadioButton

from qtdialogs.qtdefines import ArmoryDialog, STYLE_RAISED, QLabelButton
from armoryengine.BDM import TheBDM
from armoryengine.CppBridge import TheBridge
from armoryengine.PyBtcAddress import AddressEntryType_P2PKH, \
   AddressEntryType_P2PK, AddressEntryType_P2WPKH, \
   AddressEntryType_Multisig, AddressEntryType_Uncompressed, \
   AddressEntryType_P2SH, AddressEntryType_P2WSH

selectorDescriptions = {}
selectorDescriptions[AddressEntryType_P2PKH] = str(
      'Legacy address type. Backwards compatible.'
   )

selectorDescriptions[(AddressEntryType_P2SH + AddressEntryType_P2WPKH)] = str(
      'P2WPKH (SegWit script) nested in P2SH script. Any wallet can pay to '
      'this address type. Only wallets supporting SegWit can spend from it.'
   )

selectorDescriptions[(AddressEntryType_P2SH + AddressEntryType_P2PK)] = str(
      'Compressed P2PK script nested in P2SH output. Any wallet can pay '
      'to this address. Only Armory 0.96+ can spend from it.<br><br>'

      'This format allows for more efficient transaction space use, '
      'resulting in smaller inputs and lower fees.'
   )

selectorDescriptions[AddressEntryType_P2WPKH] = str(
      'Native SegWit. Requires Armory 0.96.4+ to spend to these '
      'addresses, and Armory 0.97+ to generate them. Recommneded address '
      'type when available.'
   )

class AddressTypeSelectDialog(ArmoryDialog):

   def __init__(self, parent, main, addressTypes, currentType):
      super(AddressTypeSelectDialog, self).__init__(parent, main)
      self.radioFrames = {}
      self.type = currentType

      for addrType in addressTypes:
         self.addTypeFrame(addrType)

      #main layout
      layout = QGridLayout()
      n = 0
      for aType in self.radioFrames:
         frm = self.radioFrames[aType][0]
         layout.addWidget(frm, n, 0, 1, 4)
         n += 2

      self.btnOk = QPushButton(self.tr('Apply'))
      self.btnCancel = QPushButton(self.tr('Cancel'))

      self.btnOk.clicked.connect(self.accept)
      self.btnCancel.clicked.connect(self.reject)

      layout.addWidget(self.btnOk, 5, 2, 1, 1)
      layout.addWidget(self.btnCancel, 5, 3, 1, 1)

      self.setLayout(layout)
      self.setWindowTitle(self.tr('Select Address Type'))

      self.selectType(self.type)
      self.setFocus()

   def addTypeFrame(self, addrType):
      #radio button
      addrTypeStr = TheBridge.getNameForAddrType(addrType)
      radioBtn = QRadioButton(addrTypeStr)
      def setAddrType():
         self.selectType(addrType)
      radioBtn.clicked.connect(setAddrType)

      #label description
      if addrType in selectorDescriptions:
         descrStr = selectorDescriptions[addrType]
      else:
         descrStr = self.tr("N/A")
      descrLbl = QLabel(descrStr)

      #frame
      frm = QFrame()
      frm.setFrameStyle(STYLE_RAISED)
      layout = QGridLayout()
      layout.addWidget(radioBtn, 0, 0, 1, 1)
      layout.addWidget(descrLbl, 1, 0, 1, 1)
      frm.setLayout(layout)

      #add to dict
      self.radioFrames[addrType] = [frm, radioBtn]

   def selectType(self, _type):
      self.type = _type
      for addrType in self.radioFrames:
         radioBtn = self.radioFrames[addrType][1]
         if addrType != _type:
            radioBtn.setChecked(False)
         else:
            radioBtn.setChecked(True)

   def getType(self):
      return self.type

class AddressLabelFrame(object):
   def __init__(self, main, setAddressFunc, addressTypes, currentAddrType):
      self.main = main
      self.setAddressFunc = setAddressFunc
      self.addressTypes = addressTypes

      self.frmAddrType = QFrame()
      self.frmAddrType.setFrameStyle(STYLE_RAISED)
      frmAddrTypeLayout = QGridLayout()

      addrLabel = QLabel(self.main.tr('Address Type: '))
      addrLabel.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
      self.typeLabel = QLabelButton("")
      self.typeLabel.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
      self.setType(currentAddrType)

      self.typeLabel.linkActivated.connect(self.changeType)

      frmAddrTypeLayout.addWidget(addrLabel, 0, 0, 1, 1)
      frmAddrTypeLayout.addWidget(self.typeLabel, 0, 1, 1, 2)
      self.frmAddrType.setLayout(frmAddrTypeLayout)

   def setType(self, _type):
      self.addrType = _type
      addrTypeStr = TheBridge.getNameForAddrType(_type)
      self.typeLabel.setText(\
         self.main.tr("<u><font color='blue'>%s</font></u>" \
         % addrTypeStr))

   def getType(self):
      return self.addrType

   def changeType(self):
      dlg = AddressTypeSelectDialog(self.main, self.main, \
         self.addressTypes, self.addrType)
      if dlg.exec_():
         self.setType(dlg.getType())
         self.setAddressFunc(dlg.getType())

   def getFrame(self):
      return self.frmAddrType

