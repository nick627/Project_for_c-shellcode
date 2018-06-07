# put in: ..\Immunity Debugger\PyCommands\1modulesinfo.py
# start from immunity: !1modulesinfo

import immlib
import getopt
import immutils

from immutils import *

import struct
import binascii, re

from libstackanalyze import *

import urllib
import shutil
import sys
import time
import datetime

def tohex(n):
	return "%08X" % n

def main(args):
	imm = immlib.Debugger()
	imm.log("** [+] Gathering executable / loaded module info, please wait...")
	
	global g_modules
	g_modules 	= []
	allmodules 	= imm.getAllModules()

	global g_mods
	g_mods = allmodules

	global g_nsafelist
	g_nsafelist = []

	for key in allmodules.keys():
		issafeseh 	= 1
		isaslr 		= 1
		isnx 		= 1
		iscfg 		= 1
		rebased 	= 0

		mod 			= imm.getModule(key)
		mzbase 			= mod.getBaseAddress()
		mzrebase		= mod.getFixupbase()
		mzsize 			= mod.getSize()
		mversion 		= mod.getVersion()
		mversion 		= mversion.replace(", ", ".")
		mversionfields 	= mversion.split('(')
		mversion 		= mversionfields[0].replace(" ", "")

		if mversion == "":
			mversion = "-1.0-"

		path 	= mod.getPath()
		osmod 	= mod.getIssystemdll()

		if osmod == 0:
			if path.upper().find("WINDOWS") > -1:
				osmod = 1

		mztop = mzbase + mzsize

		if mzbase > 0:
			peoffset 		= struct.unpack('<L', imm.readMemory(mzbase + 0x3c, 4))[0]
			pebase 			= mzbase + peoffset
			flags 			= struct.unpack('<H', imm.readMemory(pebase + 0x5e, 2))[0]
			numberofentries = struct.unpack('<L', imm.readMemory(pebase + 0x74, 4))[0]

			#safeseh ?
			if (flags & 0x0400) != 0:
				issafeseh = 1
			else:
				if numberofentries > 10:
					sectionaddress, sectionsize = struct.unpack('<LL', imm.readMemory(pebase + 0x78 + 8 * 10, 8))
					sectionaddress += mzbase

					data = struct.unpack('<L', imm.readMemory(sectionaddress, 4))[0]
					condition = (sectionsize != 0) and ((sectionsize == 0x40) or (sectionsize == data))

					if condition == False:
						issafeseh = 0
						g_nsafelist.append(key)
					else:
						sehlistaddress, sehlistsize = struct.unpack('<LL', imm.readMemory(sectionaddress + 0x40, 8))

						if sehlistaddress != 0 and sehlistsize != 0:
							issafeseh = 1
			
			#aslr
			if (flags & 0x0040) == 0:  # 'IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
				isaslr = 0

			if (flags & 0x0100) == 0:
				isnx = 0

			if (flags & 0x4000) == 0:
				iscfg = 0

			if mzrebase <> mzbase:
				rebased = 1

			#       0         1             2               3                4                5                   6               7              8                 9                10              11
			curmod=key+'\t'+path+'\t'+str(mzbase)+'\t'+str(mzsize)+'\t'+str(mztop)+'\t'+str(issafeseh)+'\t'+str(isaslr)+'\t'+str(isnx)+'\t'+str(rebased)+'\t'+str(mversion)+'\t'+str(osmod)+'\t'+str(iscfg)

			g_modules.append(curmod)

		imm.updateLog()

	cnt = 0

	imm.log("----------------------------------------------------------------------------------------------------------------------------------")
	imm.log(" Loaded modules")
	imm.log("----------------------------------------------------------------------------------------------------------------------------------")
	imm.log("  Fixup  |   Base     |    Top     |    Size    | SafeSEH |  ASLR | NXCompat |  CFG | OS Dll | Version, Modulename & Path")
	imm.log("---------------------------------------------------------------------(DEP)--------------------------------------------------------")
	imm.log("----------------------------------------------------------------------------------------------------------------------------------")

	safeseh 	= "NO "
	aslr 		= "NO "
	nx 			= "NO "
	cfg         = "NO "
	rebased 	= "NO "
	osdll 		= "NO "

	for mods in g_modules:
		modrecord = mods.split('\t')

		if modrecord[8] == "1":
			rebased = "yes"
		else:
			rebased = "NO "

		if modrecord[5] == "1":
			safeseh = "yes"
		else:
			safeseh = "NO "

		if modrecord[6] == "1":
			aslr = "yes"
		else:
			aslr = "NO "

		if modrecord[7] == "1":
			nx = "yes"
		else:
			nx = "NO "

		if modrecord[11] == "1":
			cfg = "yes"
		else:
			cfg = "NO "

		if modrecord[10] == "1":
			osdll = "yes"
		else:
			osdll = "NO "

		imm.log("   "+rebased+"   | 0x"+tohex(int(modrecord[2]))+" | 0x"+tohex(int(modrecord[4]))+" | 0x"+tohex(int(modrecord[3]))+" |   "+safeseh+"   |  "+aslr+"  |    "+nx+"   |  "+cfg+" |  "+osdll+"   | "+modrecord[9]+" - "+modrecord[0]+" : "+modrecord[1])

	imm.log("----------------------------------------------------------------------------------------------------------------------------------")
	imm.log("** [+] Finished task, %d modules found" % len(g_modules))

	imm.updateLog()

	return "Finished, check the log."
