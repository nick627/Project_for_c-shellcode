# ..\Immunity Debugger\PyCommands\example_for_immunity_plugin.py
# !example_for_immunity_plugin arg1 arg2 ...

#!/usr/bin/env python
"""
(c) Peter Van Eeckhoutte 2009
U{Peter Van Eeckhoutte - corelan.//www.corelan.be>}

peter.ve@corelan.be
corelanc0d3r

"""
__VERSION__ = '1.0'
import immlib
import getopt
import immutils
from immutils import *

imm = immlib.Debugger()

#""""""""""""
# Functions
#""""""""""""



#""""""""""""""""""
# Main application
#""""""""""""""""""
def main(args):
	print "Number of arguments : " + str(len(args))
	imm.Log("Number of arguments : %d " % len(args))
	cnt=0
	while (cnt < len(args)):
		imm.Log(" Argument %d : %s" % (cnt+1,args[cnt]))
		if (args[cnt] == "world"):
			imm.Log("  You said %s !" % (args[cnt]),focus=1, highlight=1)
		cnt=cnt+1
		