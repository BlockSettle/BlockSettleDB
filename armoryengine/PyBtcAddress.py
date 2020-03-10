from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
################################################################################
#                                                                              #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
from armoryengine.ArmoryUtils import ADDRBYTE, hash256, binary_to_base58, \
   KeyDataError, RightNow, LOGERROR, ChecksumError, convertKeyDataToAddress, \
   verifyChecksum, WalletLockError, createDERSigFromRS, binary_to_int, \
   computeChecksum, getVersionInt, PYBTCWALLET_VERSION, bitset_to_int, \
   LOGDEBUG, Hash160ToScrAddr, int_to_bitset, UnserializeError, \
   hash160_to_addrStr, int_to_binary, BIGENDIAN, \
   BadAddressError, checkAddrStrValid, binary_to_hex, ENABLE_DETSIGN
from armoryengine.BinaryPacker import BinaryPacker, UINT8, UINT16, UINT32, UINT64, \
   INT8, INT16, INT32, INT64, VAR_INT, VAR_STR, FLOAT, BINARY_CHUNK
from armoryengine.BinaryUnpacker import BinaryUnpacker
from armoryengine.Timer import TimeThisFunction

#address types
AddressEntryType_Default = 0
AddressEntryType_P2PKH = 1
AddressEntryType_P2PK = 2
AddressEntryType_P2WPKH = 3
AddressEntryType_Multisig = 4
AddressEntryType_Compressed = 0x10000000
AddressEntryType_P2SH = 0x40000000
AddressEntryType_P2WSH = 0x80000000

################################################################################
class PyBtcAddress(object):
   """
   PyBtcAddress --

   This class encapsulated EVERY kind of address object:
      -- Plaintext private-key-bearing addresses
      -- Encrypted private key addresses, with AES locking and unlocking
      -- Watching-only public-key addresses
      -- Address-only storage, representing someone else's key
      -- Deterministic address generation from previous addresses
      -- Serialization and unserialization of key data under all conditions
      -- Checksums on all serialized fields to protect against HDD byte errors

      For deterministic wallets, new addresses will be created from a chaincode
      and the previous address.  What is implemented here is a special kind of
      deterministic calculation that actually allows the user to securely
      generate new addresses even if they don't have the private key.  This
      method uses Diffie-Hellman shared-secret calculations to produce the new
      keys, and has the same level of security as all other ECDSA operations.
      There's a lot of fantastic benefits to doing this:

         (1) If all addresses in wallet are chained, then you only need to backup
             your wallet ONCE -- when you first create it.  Print it out, put it
             in a safety-deposit box, or tattoo the generator key to the inside
             of your eyelid:  it will never change.

         (2) You can keep your private keys on an offline machine, and keep a
             watching-only wallet online.  You will be able to generate new
             keys/addresses, and verify incoming transactions, without ever
             requiring your private key to touch the internet.

         (3) If your friend has the chaincode and your first public key, they
             too can generate new addresses for you -- allowing them to send
             you money multiple times, with different addresses, without ever
             needing to specifically request the addresses.
             (the downside to this is if the chaincode is compromised, all
             chained addresses become de-anonymized -- but is only a loss of
             privacy, not security)

      However, we do require some fairly complicated logic, due to the fact
      that a user with a full, private-key-bearing wallet, may try to generate
      a new key/address without supplying a passphrase.  If this happens, the
      wallet logic gets very complicated -- we don't want to reject the request
      to generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
   """

   #############################################################################
   def __init__(self, parentWallet=None):
      """
      We use SecureBinaryData objects to store pub, priv and IV objects,
      because that is what is required by the C++ code.  See EncryptionUtils.h
      to see that available methods.
      """
      self.prefixedHash          = []
      self.binPublicKey          = []  #33 or 65 bytes depending on address type
      self.precursorScript       = []
      self.isInitialized         = False
      self.chainIndex            = 0
      self.useEncryption         = False
      self.hasPrivKey            = False
      self.addrType              = AddressEntryType_Default
      self.txioCount             = 0
      self.parentWallet          = parentWallet
      self.addressString         = None

   #############################################################################
   def hasPubKey(self):
      return (len(self.binPublicKey) != 0)

   ##############################################################################
   def getPubKey(self):
      '''Return the public key of the address.'''
      if len(self.binPublicKey) == 0:
         raise KeyDataError('PyBtcAddress does not have a public key!')
      return self.binPublicKey

   #############################################################################
   def getAddressString(self):
      return self.addressString

   #############################################################################
   def getAddr160(self):
      if len(self.prefixedHash)!=21:
         raise KeyDataError('PyBtcAddress does not have an address string!')
      return self.prefixedHash[1:]

   #############################################################################
   def getPrefixedAddr(self):
      if len(self.prefixedHash)!=21:
         raise KeyDataError('PyBtcAddress does not have an address string!')
      return self.prefixedHash
     
   #############################################################################
   def getPrecursorScript(self):
      if len(self.precursorScript) == 0:
         raise KeyDataError('PyBtcAddress does not have a precursor!')
      return self.precursorScript

   #############################################################################
   def isCompressed(self):
      # Armory wallets (v1.35) do not support compressed keys
      return False 
   
   #############################################################################
   def createFromPlainKeyData(self, plainPrivKey, addr160=None, willBeEncr=False, \
                                    generateIVIfNecessary=False, IV16=None, \
                                    chksum=None, publicKey65=None, \
                                    skipCheck=False, skipPubCompute=False):

      assert(plainPrivKey.getSize()==32)

      if not addr160:
         addr160 = convertKeyDataToAddress(privKey=plainPrivKey)

      self.__init__()
      self.addrStr20 = addr160
      self.isInitialized = True
      self.binPrivKey32_Plain = SecureBinaryData(plainPrivKey)
      self.isLocked = False

      if willBeEncr:
         self.enableKeyEncryption(IV16, generateIVIfNecessary)
      elif IV16:
         self.binInitVect16 = IV16

      if chksum and not verifyChecksum(self.binPrivKey32_Plain.toBinStr(), chksum):
         raise ChecksumError("Checksum doesn't match plaintext priv key!")
      if publicKey65:
         self.binPublicKey65 = SecureBinaryData(publicKey65)
         if not self.binPublicKey65.getHash160()==self.addrStr20:
            raise KeyDataError("Public key does not match supplied address")
         if not skipCheck:
            if not CryptoECDSA().CheckPubPrivKeyMatch(self.binPrivKey32_Plain,\
                                                      self.binPublicKey65):
               raise KeyDataError('Supplied pub and priv key do not match!')
      elif not skipPubCompute:
         # No public key supplied, but we do want to calculate it
         self.binPublicKey65 = CryptoECDSA().ComputePublicKey(plainPrivKey)

      return self


   #############################################################################
   def createFromPublicKeyData(self, publicKey65, chksum=None):

      assert(publicKey65.getSize()==65)
      self.__init__()
      self.addrStr20 = publicKey65.getHash160()
      self.binPublicKey65 = publicKey65
      self.isInitialized = True
      self.isLocked = False
      self.useEncryption = False

      if chksum and not verifyChecksum(self.binPublicKey65.toBinStr(), chksum):
         raise ChecksumError("Checksum doesn't match supplied public key!")

      return self

   #############################################################################
   def markAsRootAddr(self):
      self.chainIndex = -1

   #############################################################################
   def isAddrChainRoot(self):
      return (self.chainIndex==-1)

   #############################################################################
   def loadFromProtobufPayload(self, payload):
      self.__init__()

      self.prefixedHash = payload.prefixedHash
      self.binPublicKey = payload.publicKey
      self.chainIndex = payload.id
      self.isInitialized = True
      self.addrType = payload.addrType
      self.addressString = payload.addressString

      self.precursorScript = payload.precursorScript

   #############################################################################
   def getTxioCount(self):
      return self.txioCount

   #############################################################################
   def getComment(self):
      if self.parentWallet is None:
         return ''

      return self.parentWallet.getCommentForAddr(self.getAddr160())

# Put the import at the end to avoid circular reference problem
from armoryengine.BDM import *
