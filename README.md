# Project_for_c-shellcode
C-shellcode and srcipts for Immunity Debugger

Immunity Debugger v1.50 - https://exelab.ru/download.php?action=get&n=ODMw
Implemented a script for Immunity Debugger, which displays information about the loaded DLL (DEP (NXCompat), ASLR, CFG (Control Flow Guard)), and also search in them for the sequence of bytes corresponding to the opcodes of the required instruction.

modulesinfo.py
   https://github.com/cihatix/CorelanFiles/blob/master/tools/pvefindaddr.py

findinstraction.py:
   https://habrahabr.ru/post/134407/
      paragraph 5.3.1

Source for create shellcode with actual load and xor encoded/decoded
