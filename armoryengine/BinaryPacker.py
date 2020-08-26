from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
################################################################################
#
# Copyright (C) 2011-2015, Armory Technologies, Inc.                         
# Distributed under the GNU Affero General Public License (AGPL v3)
# See LICENSE or http://www.gnu.org/licenses/agpl.html
#
################################################################################
#
# Project:    Armory
# Author:     Alan Reiner
# Website:    www.bitcoinarmory.com
# Orig Date:  20 November, 2011
#
################################################################################
from armoryengine.ArmoryUtils import LITTLEENDIAN, int_to_binary, packVarInt
UINT8, UINT16, UINT32, UINT64, INT8, INT16, INT32, INT64, VAR_INT, VAR_STR, FLOAT, BINARY_CHUNK = range(12)
from binascii import hexlify
from io import BytesIO
from struct import pack, unpack

class PackerError(Exception): pass

class BinaryPacker(object):

   """
   Class for helping load binary data into a stream.  Typical usage is
      >> bp = BinaryPacker()
      >> bp.put(UINT32, 12)
      >> bp.put(VAR_INT, 78)
      >> bp.put(BINARY_CHUNK, '\x9f'*10)
      >> ...etc...
      >> result = bp.getBinaryString()
   """
   def __init__(self):
      self.binaryConcat = BytesIO()

   def getSize(self):
      return self.binaryConcat.tell()

   def getBinaryString(self):
      return self.binaryConcat.getvalue()

   def __str__(self):
      return hexlify(self.binaryConcat.getvalue()).decode('ascii')


   def put(self, varType, theData, width=None, endianness=LITTLEENDIAN):
      """
      Need to supply the argument type you are put'ing into the stream.
      Values of BINARY_CHUNK will automatically detect the size as necessary

      Use width=X to include padding of BINARY_CHUNKs w/ 0x00 bytes
      """
      E = endianness
      if   varType == UINT8:
         self.binaryConcat.write(int_to_binary(theData, 1, endianness))
      elif varType == UINT16:
         self.binaryConcat.write(int_to_binary(theData, 2, endianness))
      elif varType == UINT32:
         self.binaryConcat.write(int_to_binary(theData, 4, endianness))
      elif varType == UINT64:
         self.binaryConcat.write(int_to_binary(theData, 8, endianness))
      elif varType == INT8:
         self.binaryConcat.write(pack(E+'b', theData))
      elif varType == INT16:
         self.binaryConcat.write(pack(E+'h', theData))
      elif varType == INT32:
         self.binaryConcat.write(pack(E+'i', theData))
      elif varType == INT64:
         self.binaryConcat.write(pack(E+'q', theData))
      elif varType == VAR_INT:
         self.binaryConcat.write(packVarInt(theData))
      elif varType == VAR_STR:
         self.binaryConcat.write(packVarInt(len(theData)))
         self.binaryConcat.write(theData)
      elif varType == FLOAT:
         self.binaryConcat.write(pack(E+'f', theData))
      elif varType == BINARY_CHUNK:
         if width==None:
            self.binaryConcat.write(theData)
         else:
            if len(theData)>width:
               raise PackerError('Too much data to fit into fixed width field')
            self.binaryConcat.write(theData.ljust(width, b'\x00'))
      else:
         raise PackerError("Var type not recognized!  VarType="+str(varType))


