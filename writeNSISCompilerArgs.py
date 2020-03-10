'''
Created on Sep 24, 2013

@author: Andy
'''
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import sys
from string import join
sys.argv.append('--nologging')
from armoryengine.ArmoryUtils import BTCARMORY_VERSION 
# need back up 2 directories because this is run from 
# \cppForSwig\BitcoinArmory_SwigDLL and the output is
# expected in the base directory
f = open("../../CompilerArgs.nsi", 'w')
f.write('!define VERSION ')
f.write('.'.join(map(str, BTCARMORY_VERSION)))
f.close()
