##############################################################################
#                                                                            #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                         #
# Distributed under the GNU Affero General Public License (AGPL v3)          #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                       #
#                                                                            #
# Copyright (C) 2016-17, goatpig                                             #
#  Distributed under the MIT license                                         #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                    #
#                                                                            #
##############################################################################

from PySide2.QtCore import QSize
from PySide2.QtGui import QPainter, QColor
from PySide2.QtWidgets import QWidget

from ui.QrCodeMatrix import CreateQRMatrix

from armoryengine.ArmoryUtils import LOGERROR
from qtdialogs.DlgInflatedQR import DlgInflatedQR

class QRCodeWidget(QWidget):

   def __init__(self, asciiToEncode='', prefSize=160, errLevel='L', parent=None):
      super(QRCodeWidget, self).__init__()

      self.parent = parent
      self.qrmtrx = None
      self.setAsciiData(asciiToEncode, prefSize, errLevel, repaint=False)


   def setAsciiData(self, newAscii, prefSize=160, errLevel='L', repaint=True):
      if len(newAscii)==0:
         self.qrmtrx = [[0]]
         self.modCt  = 1
         self.pxScale= 1
         return

      self.theData = newAscii
      self.qrmtrx, self.modCt = CreateQRMatrix(self.theData, errLevel)
      self.setPreferredSize(prefSize)


   def getModuleCount1D(self):
      return self.modCt


   def setPreferredSize(self, px, policy='Approx'):
      self.pxScale,rem = divmod(int(px), int(self.modCt))

      if policy.lower().startswith('approx'):
         if rem>self.modCt/2.0:
            self.pxScale += 1
      elif policy.lower().startswith('atleast'):
         if rem>0:
            self.pxScale += 1
      elif policy.lower().startswith('max'):
         pass
      else:
         LOGERROR('Bad size policy in set qr size')
         return self.pxScale*self.modCt

      return


   def getSize(self):
      return self.pxScale*self.modCt


   def sizeHint(self):
      sz1d = self.pxScale*self.modCt
      return QSize(sz1d, sz1d)


   def paintEvent(self, e):
      qp = QPainter()
      qp.begin(self)
      self.drawWidget(qp)
      qp.end()



   def drawWidget(self, qp):
      # In case this is not a white background, draw the white boxes
      qp.setPen(QColor(255,255,255))
      qp.setBrush(QColor(255,255,255))
      for r in range(self.modCt):
         for c in range(self.modCt):
            if not self.qrmtrx[r][c]:
               qp.drawRect(*[a*self.pxScale for a in [r,c,1,1]])

      # Draw the black tiles
      qp.setPen(QColor(0,0,0))
      qp.setBrush(QColor(0,0,0))
      for r in range(self.modCt):
         for c in range(self.modCt):
            if self.qrmtrx[r][c]:
               qp.drawRect(*[a*self.pxScale for a in [r,c,1,1]])


   def mouseDoubleClickEvent(self, *args):
      DlgInflatedQR(self.parent, self.theData).exec_()
