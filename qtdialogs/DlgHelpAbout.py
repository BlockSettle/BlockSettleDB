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
from PySide2.QtGui import QPixmap
from PySide2.QtWidgets import QHBoxLayout, QLabel

#from armoryengine.ArmoryBuild import BTCARMORY_BUILD
from armoryengine.ArmoryUtils import BTCARMORY_VERSION, getVersionString

from qtdialogs.ArmoryDialog import ArmoryDialog
from qtdialogs.qtdefines import QRichLabel, STRETCH, makeVertFrame

################################################################################
class DlgHelpAbout(ArmoryDialog):
   def __init__(self, putResultInWidget, defaultWltID=None, parent=None, main=None):
      super(DlgHelpAbout, self).__init__(parent, main)

      imgLogo = QLabel()
      imgLogo.setPixmap(QPixmap('./img/armory_logo_h56.png'))
      imgLogo.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)

#        if BTCARMORY_BUILD != None:
#            lblHead = QRichLabel(self.tr('Armory Bitcoin Wallet : Version %s-beta-%s' % (getVersionString(BTCARMORY_VERSION), BTCARMORY_BUILD)), doWrap=False)
#        else:
#            lblHead = QRichLabel(self.tr('Armory Bitcoin Wallet : Version %s-beta' % getVersionString(BTCARMORY_VERSION)), doWrap=False)
      lblHead = QRichLabel(self.tr('Armory Bitcoin Wallet : Version %s-beta' % getVersionString(BTCARMORY_VERSION)), doWrap=False)

      lblOldCopyright = QRichLabel(self.tr( u'Copyright &copy; 2011-2015 Armory Technologies, Inc.'))
      lblCopyright = QRichLabel(self.tr( u'Copyright &copy; 2016 Goatpig'))
      lblOldLicense = QRichLabel(self.tr( u'Licensed to Armory Technologies, Inc. under the '
                              '<a href="http://www.gnu.org/licenses/agpl-3.0.html">'
                              'Affero General Public License, Version 3</a> (AGPLv3)'))
      lblOldLicense.setOpenExternalLinks(True)
      lblLicense = QRichLabel(self.tr( u'Licensed to Goatpig under the '
                              '<a href="https://opensource.org/licenses/mit-license.php">'
                              'MIT License'))
      lblLicense.setOpenExternalLinks(True)

      lblHead.setAlignment(Qt.AlignHCenter)
      lblCopyright.setAlignment(Qt.AlignHCenter)
      lblOldCopyright.setAlignment(Qt.AlignHCenter)
      lblLicense.setAlignment(Qt.AlignHCenter)
      lblOldLicense.setAlignment(Qt.AlignHCenter)

      dlgLayout = QHBoxLayout()
      dlgLayout.addWidget(makeVertFrame([imgLogo, lblHead, lblCopyright, lblOldCopyright, STRETCH, lblLicense, lblOldLicense]))
      self.setLayout(dlgLayout)

      self.setMinimumWidth(450)

      self.setWindowTitle(self.tr('About Armory'))