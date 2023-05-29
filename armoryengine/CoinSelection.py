from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
################################################################################
#                                                                              #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
################################################################################
################################################################################
#
# SelectCoins algorithms
#
#   The following methods define multiple ways that one could select coins
#   for a given transaction.  However, the "best" solution is extremely
#   dependent on the variety of unspent outputs, and also the preferences
#   of the user.  Things to take into account when selecting coins:
#
#     - Number of inputs:  If we have a lot of inputs in this transaction
#                          from different addresses, then all those addresses
#                          have now been linked together.  We want to use
#                          as few outputs as possible
#
#     - Tx Fess/Size:      The bigger the transaction, in bytes, the more
#                          fee we're going to have to pay to the miners
#
#     - Priority:          Low-priority transactions might require higher
#                          fees and/or take longer to make it into the
#                          blockchain.  Priority is the sum of TxOut
#                          priorities:  (NumConfirm * NumBTC / SizeKB)
#                          We especially want to avoid 0-confirmation txs
#
#     - Output values:     In almost every transaction, we must return
#                          change to ourselves.  This means there will
#                          be two outputs, one to the recipient, one to
#                          us.  We prefer that both outputs be about the
#                          same size, so that it's not clear which is the
#                          recipient, which is the change.  But we don't
#                          want to use too many inputs to do this.
#
#     - Sustainability:    We should pick a strategy that tends to leave our
#                          wallet containing a variety of TxOuts that are
#                          well-suited for future transactions to benefit.
#                          For instance, always favoring the single TxOut
#                          with a value close to the target, will result
#                          in a future wallet full of tiny TxOuts.  This
#                          guarantees that in the future, we're going to
#                          have to do 10+ inputs for a single Tx.
#
#
#   The strategy is to execute a half dozen different types of SelectCoins
#   algorithms, each with a different goal in mind.  Then we examine each
#   of the results and evaluate a "select-score."  Use the one with the
#   best score.  In the future, we could make the scoring algorithm based
#   on user preferences.  We expect that depending on what the availble
#   list looks like, some of these algorithms could produce perfect results,
#   and in other instances *terrible* results.
#
################################################################################
################################################################################
import math
import random

from armoryengine.ArmoryUtils import binary_to_hex, coin2str, \
   ONE_BTC, CENT, int_to_binary, MIN_RELAY_TX_FEE, MIN_TX_FEE
from armoryengine.AddressUtils import CheckHash160, hash160_to_addrStr, \
   scrAddr_to_script
from armoryengine.Timer import TimeThisFunction
from armoryengine.Transaction import *
from armoryengine.BDM import TheBDM

################################################################################
# These would normally be defined by C++ and fed in, but I've recreated
# the C++ class here... it's really just a container, anyway
#
# TODO:  LevelDB upgrade: had to upgrade this class to use arbitrary 
#        ScrAddress "notation", even though everything else on the python
#        side expects pure hash160 values.  For now, it looks like it can
#        handle arbitrary scripts, but the CheckHash160() calls will 
#        (correctly) throw errors if you don't.  We can upgrade this in
#        the future.
class PyUnspentTxOut(object):
   def __init__(self, scrAddr=None, txHash=None, txoIdx=None, val=None,
      numConf=None, fullScript=None):

      self.initialize(scrAddr, txHash, None, None, None,
         txoIdx, val, numConf, fullScript)


   #############################################################################
   def createFromBridgeUtxo(self, bridgeUtxo):
      scrAddr= bridgeUtxo.scraddr
      val    = bridgeUtxo.value
      conf   = TheBDM.getTopBlockHeight() - bridgeUtxo.tx_height + 1
      txHash = bridgeUtxo.tx_hash
      txHashStr = binary_to_hex(bridgeUtxo.tx_hash)
      txoIdx = bridgeUtxo.txout_index
      script = bridgeUtxo.script
      txHeight = bridgeUtxo.tx_height
      txIndex = bridgeUtxo.tx_index
      sequence = 2**32-1

      self.initialize(scrAddr, txHash, txHashStr, txHeight, txIndex, 
                      txoIdx, val, conf, script, sequence)
      return self

   #############################################################################
   def initialize(self, scrAddr, txHash, txHashStr, txHeight, txIndex, 
                  txoIdx, val, numConf=None, fullScript=None, 
                  sequence=2**32-1):
      self.scrAddr    = scrAddr
      self.txHash     = txHash
      self.txHashStr  = txHashStr
      self.txOutIndex = txoIdx
      self.val        = val
      self.conf       = numConf
      self.txHeight   = txHeight
      self.txIndex    = txIndex
      self.sequence   = sequence

      if self.scrAddr and fullScript is None:
         self.binScript = scrAddr_to_script(self.scrAddr)
      else:
         self.binScript = fullScript
         
      self.checked = True

   def getTxHash(self):
      return self.txHash
   
   def getTxHashStr(self):
      return self.txHashStr
   
   def getTxHeight(self):
      return self.txHeight

   def getTxOutIndex(self):
      return self.txOutIndex
   
   def getTxIndex(self):
      return self.txIndex

   def getValue(self):
      return self.val

   def getNumConfirm(self):
      return self.conf

   def getScript(self):
      return self.binScript

   def getRecipientScrAddr(self):
      return self.scrAddr

   def getRecipientHash160(self):
      return CheckHash160(self.scrAddr)

   def prettyStr(self, indent=''):
      pstr = [indent]
      pstr.append(binary_to_hex(self.scrAddr[:8]))
      pstr.append(coin2str(self.val))
      pstr.append(str(self.conf).rjust(8,' '))
      return '  '.join(pstr)
   
   def shortLabel(self):
      return '%d|%d|%d' % (self.txHeight, self.txIndex, self.txOutIndex)
      
   def longLabel(self):
      return 'height: %d, txIndex: %d, txOutIndex: %d, txHash: %s' % \
         (self.txHeight, self.txIndex, self.txOutIndex, self.txHashStr)

   def pprint(self, indent=''):
      print(self.prettyStr(indent))

   def setChecked(self, val):
      self.checked = val

   def isChecked(self):
      return self.checked

   #############################################################################
   def toBridgeUtxo(self):
      from armoryengine import BridgeProto_pb2
      bridgeUtxo = BridgeProto_pb2.Utxo()

      bridgeUtxo.scraddr = self.scrAddr
      bridgeUtxo.value = self.val
      bridgeUtxo.tx_hash = self.txHash
      bridgeUtxo.txout_index = self.txOutIndex
      bridgeUtxo.script = self.binScript
      bridgeUtxo.tx_height = self.txHeight
      bridgeUtxo.tx_index = self.txIndex

      return bridgeUtxo

################################################################################
def sumTxOutList(txoutList):
   return sum([u.getValue() for u in txoutList])

################################################################################
# This is really just for viewing a TxOut list -- usually for debugging
def pprintUnspentTxOutList(utxoList, headerLine='Coin Selection: '):
   totalSum = sum([u.getValue() for u in utxoList])
   print(headerLine, '(Total = %s BTC)' % coin2str(totalSum))
   print('   ','Owner Address'.ljust(34), end=' ')
   print('   ','TxOutValue'.rjust(18), end=' ')
   print('   ','NumConf'.rjust(8), end=' ')
   print('   ','PriorityFactor'.rjust(16))
   for utxo in utxoList:
      a160 = CheckHash160(utxo.getRecipientScrAddr())
      print('   ',hash160_to_addrStr(a160).ljust(34), end=' ')
      print('   ',(coin2str(utxo.getValue()) + ' BTC').rjust(18), end=' ')
      print('   ',str(utxo.getNumConfirm()).rjust(8), end=' ')
      print('   ', ('%0.2f' % (utxo.getValue()*utxo.getNumConfirm()/(ONE_BTC*144.))).rjust(16))

################################################################################
# Now we try half a dozen different selection algorithms
################################################################################



################################################################################
def PySelectCoins_SingleInput_SingleValue( \
                                    unspentTxOutInfo, targetOutVal, minFee=0):
   """
   This method should usually be called with a small number added to target val
   so that a tx can be constructed that has room for user to add some extra fee
   if necessary.

   However, we must also try calling it with the exact value, in case the user
   is trying to spend exactly their remaining balance.
   """
   target = targetOutVal + minFee
   bestMatchVal  = 2**64
   bestMatchUtxo = None
   for utxo in unspentTxOutInfo:
      if target <= utxo.getValue() < bestMatchVal:
         bestMatchVal = utxo.getValue()
         bestMatchUtxo = utxo

   closeness = bestMatchVal - target
   if 0 < closeness <= CENT:
      # If we're going to have a change output, make sure it's above CENT
      # to avoid a mandatory fee
      try2Val  = 2**64
      try2Utxo = None
      for utxo in unspentTxOutInfo:
         if target+CENT < utxo.getValue() < try2Val:
            try2Val = utxo.getValue()
            try2Val = utxo
      if not try2Utxo==None:
         bestMatchUtxo = try2Utxo


   if bestMatchUtxo==None:
      return []
   else:
      return [bestMatchUtxo]

################################################################################
def PySelectCoins_MultiInput_SingleValue( \
                                    unspentTxOutInfo, targetOutVal, minFee=0):
   """
   This method should usually be called with a small number added to target val
   so that a tx can be constructed that has room for user to add some extra fee
   if necessary.

   However, we must also try calling it with the exact value, in case the user
   is trying to spend exactly their remaining balance.
   """
   target = targetOutVal + minFee
   outList = []
   sumVal = 0
   for utxo in unspentTxOutInfo:
      sumVal += utxo.getValue()
      outList.append(utxo)
      if sumVal>=target:
         break

   return outList



################################################################################
def PySelectCoins_SingleInput_DoubleValue( \
                                    unspentTxOutInfo, targetOutVal, minFee=0):
   """
   We will look for a single input that is within 30% of the target
   In case the tx value is tiny rel to the fee: the minTarget calc
   may fail to exceed the actual tx size needed, so we add an extra

   We restrain the search to 25%.  If there is no one output in this
   range, then we will return nothing, and the SingleInput_SingleValue
   method might return a usable result
   """
   idealTarget    = 2*targetOutVal + minFee

   # check to make sure we're accumulating enough
   minTarget   = long(0.75 * idealTarget)
   minTarget   = max(minTarget, targetOutVal+minFee)
   maxTarget   = long(1.25 * idealTarget)

   if sum([u.getValue() for u in unspentTxOutInfo]) < minTarget:
      return []

   bestMatch = 2**64-1
   bestUTXO   = None
   for txout in unspentTxOutInfo:
      if minTarget <= txout.getValue() <= maxTarget:
         if abs(txout.getValue()-idealTarget) < bestMatch:
            bestMatch = abs(txout.getValue()-idealTarget)
            bestUTXO = txout

   if bestUTXO==None:
      return []
   else:
      return [bestUTXO]

################################################################################
def PySelectCoins_MultiInput_DoubleValue( \
                                    unspentTxOutInfo, targetOutVal, minFee=0):

   idealTarget = 2.0 * targetOutVal
   minTarget   = long(0.80 * idealTarget)
   minTarget   = max(minTarget, targetOutVal+minFee)
   if sum([u.getValue() for u in unspentTxOutInfo]) < minTarget:
      return []

   outList   = []
   lastDiff  = 2**64-1
   sumVal    = 0
   for utxo in unspentTxOutInfo:
      sumVal += utxo.getValue()
      outList.append(utxo)
      currDiff = abs(sumVal - idealTarget)
      # should switch from decreasing to increasing when best match
      if sumVal>=minTarget and currDiff>lastDiff:
         del outList[-1]
         break
      lastDiff = currDiff

   return outList




################################################################################
# We define default preferences for weightings.  Weightings are used to
# determine the "priorities" for ranking various SelectCoins results
# By setting the weights to different orders of magnitude, you are essentially
# defining a sort-order:  order by FactorA, then sub-order by FactorB...
################################################################################
# TODO:  ADJUST WEIGHTING!
IDX_ALLOWFREE   = 0
IDX_NOZEROCONF  = 1
IDX_PRIORITY    = 2
IDX_NUMADDR     = 3
IDX_TXSIZE      = 4
IDX_OUTANONYM   = 5
WEIGHTS = [None]*6
WEIGHTS[IDX_ALLOWFREE]  =  100000
WEIGHTS[IDX_NOZEROCONF] = 1000000  # let's avoid zero-conf if possible
WEIGHTS[IDX_PRIORITY]   =      50
WEIGHTS[IDX_NUMADDR]    =  100000
WEIGHTS[IDX_TXSIZE]     =     100
WEIGHTS[IDX_OUTANONYM]  =      30


################################################################################
def PyEvalCoinSelect(utxoSelectList, targetOutVal, minFee, weights=WEIGHTS):
   """
   Use a specified set of weightings and sub-scores for a unspentTxOut list,
   to assign an absolute "fitness" of this particular selection.  The goal of
   getSelectCoinsScores() is to produce weighting-agnostic subscores -- then
   this method applies the weightings to these scores to get a final answer.

   If list A has a higher score than list B, then it's a better selection for
   that transaction.  If you the two scores don't look right to you, then you
   probably just need to adjust the weightings to your liking.

   These weightings may become user-configurable in the future -- likely as an
   option of coin-selection profiles -- such as "max anonymity", "min fee",
   "balanced", etc).
   """
   scores = getSelectCoinsScores(utxoSelectList, targetOutVal, minFee)
   if scores==-1:
      return -1

   # Combine all the scores
   theScore  = 0
   theScore += weights[IDX_NOZEROCONF] * scores[IDX_NOZEROCONF]
   theScore += weights[IDX_PRIORITY]   * scores[IDX_PRIORITY]
   theScore += weights[IDX_NUMADDR]    * scores[IDX_NUMADDR]
   theScore += weights[IDX_TXSIZE]     * scores[IDX_TXSIZE]
   theScore += weights[IDX_OUTANONYM]  * scores[IDX_OUTANONYM]

   # If we're already paying a fee, why bother including this weight?
   if minFee < 0.0005:
      theScore += weights[IDX_ALLOWFREE]  * scores[IDX_ALLOWFREE]

   return theScore


################################################################################
# https://bitcointalk.org/index.php?topic=92496.msg1126310#msg1126310 contains a
# description (possibly out-of-date?) of how this function works.
@TimeThisFunction
def PySelectCoins(unspentTxOutInfo, targetOutVal, minFee=0, numRand=10, margin=CENT):
   """
   Intense algorithm for coin selection:  computes about 30 different ways to
   select coins based on the desired target output and the min tx fee.  Then
   ranks the various solutions and picks the best one
   """

   if sum([u.getValue() for u in unspentTxOutInfo]) < targetOutVal:
      return []

   targExact  = targetOutVal
   targMargin = targetOutVal+margin

   selectLists = []

   # Start with the intelligent solutions with different sortings
   for sortMethod in range(8):
      diffSortList = PySortCoins(unspentTxOutInfo, sortMethod)
      selectLists.append(PySelectCoins_SingleInput_SingleValue( diffSortList, targExact,  minFee ))
      selectLists.append(PySelectCoins_MultiInput_SingleValue(  diffSortList, targExact,  minFee ))
      selectLists.append(PySelectCoins_SingleInput_SingleValue( diffSortList, targMargin, minFee ))
      selectLists.append(PySelectCoins_MultiInput_SingleValue(  diffSortList, targMargin, minFee ))
      selectLists.append(PySelectCoins_SingleInput_DoubleValue( diffSortList, targExact,  minFee ))
      selectLists.append(PySelectCoins_MultiInput_DoubleValue(  diffSortList, targExact,  minFee ))
      selectLists.append(PySelectCoins_SingleInput_DoubleValue( diffSortList, targMargin, minFee ))
      selectLists.append(PySelectCoins_MultiInput_DoubleValue(  diffSortList, targMargin, minFee ))

   # Throw in a couple random solutions, maybe we get lucky
   # But first, make a copy before in-place shuffling
   # NOTE:  using list[:] like below, really causes a swig::vector<type> to freak out!
   #utxos = unspentTxOutInfo[:]
   #utxos = list(unspentTxOutInfo)
   for method in range(8,10):
      for i in range(numRand):
         utxos = PySortCoins(unspentTxOutInfo, method)
         selectLists.append(PySelectCoins_MultiInput_SingleValue(utxos, targExact,  minFee))
         selectLists.append(PySelectCoins_MultiInput_DoubleValue(utxos, targExact,  minFee))
         selectLists.append(PySelectCoins_MultiInput_SingleValue(utxos, targMargin, minFee))
         selectLists.append(PySelectCoins_MultiInput_DoubleValue(utxos, targMargin, minFee))

   # Now we define PyEvalCoinSelect as our sorting metric, and find the best solution
   scoreFunc = lambda ulist: PyEvalCoinSelect(ulist, targetOutVal, minFee)
   finalSelection = max(selectLists, key=scoreFunc)
   SCORES = getSelectCoinsScores(finalSelection, targetOutVal, minFee)
   if len(finalSelection)==0:
      return []

   # If we selected a list that has only one or two inputs, and we have
   # other, tiny, unspent outputs from the same addresses, we should
   # throw one or two of them in to help clear them out.  However, we
   # only do so if a plethora of conditions exist:
   #
   # First, we only consider doing this if the tx has <5 inputs already.
   # Also, we skip this process if the current tx doesn't have excessive
   # priority already -- we don't want to risk de-prioritizing a tx for
   # this purpose.
   #
   # Next we sort by LOWEST value, because we really benefit from this most
   # by clearing out tiny outputs.  Along those lines, we don't even do
   # unless it has low priority -- don't want to take a high-priority utxo
   # and convert it to one that will be low-priority to start.
   #
   # Finally, we shouldn't do this if a high score was assigned to output
   # anonymity: this extra output may cause a tx with good output anonymity
   # to no longer possess this property
   IDEAL_NUM_INPUTS = 5
   if len(finalSelection) < IDEAL_NUM_INPUTS and \
          SCORES[IDX_OUTANONYM] == 0:

      utxoToScrAddr = lambda a: a.getRecipientScrAddr()
      getPriority   = lambda a: a.getValue() * a.getNumConfirm()
      getUtxoID     = lambda a: a.getTxHash() + int_to_binary(a.getTxOutIndex())

      alreadyUsedAddr = set( [utxoToScrAddr(utxo) for utxo in finalSelection] )
      utxoSmallToLarge = sorted(unspentTxOutInfo, key=getPriority)
      utxoSmToLgIDs = [getUtxoID(utxo) for utxo in utxoSmallToLarge]
      finalSelectIDs = [getUtxoID(utxo) for utxo in finalSelection]
      
      for other in utxoSmallToLarge:
         
         # Skip it if it is already selected
         if getUtxoID(other) in finalSelectIDs:
            continue

         # We only consider UTXOs that won't link any new addresses together
         if not utxoToScrAddr(other) in alreadyUsedAddr:
            continue
         
         # Avoid zero-conf inputs altogether
         if other.getNumConfirm() == 0:
            continue

         # Don't consider any inputs that are high priority already
         if getPriority(other) > ONE_BTC*144:
            continue

         finalSelection.append(other) 
         if len(finalSelection)>=IDEAL_NUM_INPUTS:
            break
   return finalSelection

NBLOCKS_TO_CONFIRM = 3
FEEBYTE_CONSERVATIVE = "CONSERVATIVE"
FEEBYTE_ECONOMICAL = "ECONOMICAL"
# ONE_BTC * 144 / 250
DEFAULT_PRIORITY = 57600000

################################################################################
# Call bitcoin core to get the priority estimate
def estimatePriority():
   return DEFAULT_PRIORITY

################################################################################
def calcMinSuggestedFeesHackMS(selectCoinsResult, targetOutVal, preSelectedFee, 
                                                         numRecipients):
   """
   This is a hack, because the calcMinSuggestedFees below assumes standard
   P2PKH inputs and outputs, not allowing us a way to modify it if we ne know
   that the inputs will be much larger, or the outputs.

   we just copy the original method with an update to the computation
   """

   numBytes = 0
   msInfo = [getMultisigScriptInfo(utxo.getScript()) for utxo in selectCoinsResult]
   for m,n,As,Ps in msInfo:
      numBytes += m*70 + 40

   numBytes += 200*numRecipients  # assume large lockbox outputs
   numKb = int(numBytes / 1000)
   suggestedFee = (1+numKb)*estimateFee()
   if numKb>10:
      return suggestedFee
   
   # Compute raw priority of tx
   prioritySum = 0
   for utxo in selectCoinsResult:
      prioritySum += utxo.getValue() * utxo.getNumConfirm()
   prioritySum = prioritySum / numBytes

   if(prioritySum >= estimatePriority() and numBytes < 10000):
      return 0

   return suggestedFee
   
################################################################################
def estimateTxSize(selectCoinsResult, targetOutVal, preSelectedFee,
                         numRecipients, autoChange = True):
     
   if len(selectCoinsResult)==0:
      return -1
   
   paid = targetOutVal + preSelectedFee
   change = False
   if autoChange == True:
      change = sum([u.getValue() for u in selectCoinsResult]) - paid

   # Calc approx tx size
   numBytes  =  10
   numBytes += 180 * len(selectCoinsResult)
   numBytes +=  35 * (numRecipients + (1 if change>0 else 0))
   
   return numBytes 

################################################################################
def calcMinSuggestedFees(selectCoinsResult, targetOutVal, preSelectedFee,
                         numRecipients, autoChange = True):

   # TODO: this should be updated to accommodate the non-constant 
   #       TxOut/TxIn size given that it now accepts P2SH and Multisig

   numBytes = estimateTxSize(selectCoinsResult, \
               targetOutVal, preSelectedFee, numRecipients, autoChange)
   if numBytes == -1:
      return -1
   
   try:
      suggestedFee = numBytes*estimateFee(2)
   except:
      suggestedFee = numBytes*MIN_RELAY_TX_FEE
      
   return suggestedFee

################################################################################
# I needed a new function that was going to be as accurate as possible for
# arbitrary coin selections (and recipient lists).  However, this doesn't
# work in all places tat the old coin selection algo was used, so I am 
# leaving those calls alone and simply defining this for new methods that
# have access to full UTXOs scripts and scriptValPairs.
def calcMinSuggestedFeesNew(selectCoinsResult, scriptValPairs, preSelectedFee,
                                          changeScript=None):
   """
   Returns two fee options:  one for relay, one for include-in-block.
   In general, relay fees are required to get your block propagated
   (since most nodes are Satoshi clients), but there's no guarantee
   it will be included in a block -- though I'm sure there's plenty
   of miners out there will include your tx for sub-standard fee.
   However, it's virtually guaranteed that a miner will accept a fee
   equal to the second return value from this method.

   We have to supply the fee that was used in the selection algorithm,
   so that we can figure out how much change there will be.  Without
   this information, we might accidentally declare a tx to be freeAllow
   when it actually is not.
   """

   # TODO: this should be updated to accommodate the non-constant 
   #       TxOut/TxIn size given that it now accepts P2SH and Multisig

   targetOutVal = long( sum([rv[1] for rv in scriptValPairs]) )
   if len(selectCoinsResult)==0:
      return [-1,-1]
   paid = targetOutVal + preSelectedFee
   change = sum([u.getValue() for u in selectCoinsResult]) - paid


   # Calc approx tx size
   numBytes  =  10
   numBytes +=  sum([len(sv[0])+9 for sv in scriptValPairs])
   if change>0:
      # If no changeScript is provided, we assume P2PKH or P2SH: approx 35 bytes
      numBytes += len(changeScript) if changeScript else 35

   numKb = int(numBytes / 1000)

   if numKb>10:
      return [(1+numKb)*MIN_RELAY_TX_FEE, (1+numKb)*MIN_TX_FEE]

   # Compute raw priority of tx
   prioritySum = 0
   for utxo in selectCoinsResult:
      prioritySum += utxo.getValue() * utxo.getNumConfirm()
   prioritySum = prioritySum / numBytes

   # Any tiny/dust outputs?
   haveDustOutputs = (0<change<CENT or targetOutVal<CENT)

   if((not haveDustOutputs) and \
      prioritySum >= ONE_BTC * 144 / 250. and \
      numBytes < 10000):
      return [0,0]

   # This cannot be a free transaction.
   minFeeMultiplier = (1 + numKb)

   # At the moment this condition never triggers
   if minFeeMultiplier<1.0 and haveDustOutputs:
      minFeeMultiplier = 1.0


   return [minFeeMultiplier * MIN_RELAY_TX_FEE, \
           minFeeMultiplier * MIN_TX_FEE]

