import argparse
from datetime import datetime
import time
from pyDes import *
import os
import sys
 
# Lan Manger Hash Generator Class
class lmhash:
    def __init__(self):
        # nothing to do ...
        pass
    # PUBLIC
    def get_hash(self,sPW):
        sHASH = ""
        # cut password after 14 characters
        if len(sPW) > 14:
            print("-> cut the password to 14 characters")
            sPW = sPW[:14]
        # uppercase password
        sPW = sPW.upper()
        # cut password in 2 x 7 character strings
        aPW = [sPW[:7], sPW[7:]]
        # prepare each half
        aBYTES = [None]*2
        for count in range(len(aPW)):
            aBYTES[count] = self.__get_bytes(aPW[count])
        # encrypt each prepared half into hex-hash
        HexHash = [None]*2
        for count in range(len(aBYTES)):
            HexHash[count] = self.__get_deshash(aBYTES[count])
        sHASH = '-'.join(HexHash)
        return sHASH
    # PRIVATE
    def __get_bytes(self,sHALF):
        # transform every character into 8 bit string
        aBITS = ['00000000']*7
        for idx in range(len(sHALF)):
            bChar = str(bin(ord(sHALF[idx])))[2:]
            fillCount = 8 - len(bChar)
            bChar = '0'*fillCount + bChar
            aBITS[idx] = bChar
        sBITS = ''.join(aBITS)
        # add for every byte a non-parity bit at the end of the byte
        iLen = len(sBITS)
        for idx in range(8):
            pos = iLen - ((idx) * 7)
            sBITS = sBITS[:pos] + '0' + sBITS[pos:]
        # transform bitstring into bytes
        aBYTES = []
        for idx in range(8):
            iNum = int(sBITS[idx*8:idx*8+8],2)
            aBYTES.append(iNum)
        return aBYTES
    def __get_deshash(self, aBYTES):
        # crypt bytes with the lmhash string
        oDESDATA = des(aBYTES, CBC, "")
        oCRYPT = oDESDATA.encrypt("KGS!@#$%")
        # transform crypted data into hex string
        aHEX = []
        for aBYTE in oCRYPT:
            aHEX.append(str(hex(aBYTE))[2:].upper())
        return ''.join(aHEX)
 
# Initialize the Argument Parser
parser = argparse.ArgumentParser(description='Create a Lan Manager Hash Code of a give Password or Passwordlistfile.')
parser.add_argument('-p, --password', dest='pw', help='A Password which should be transformed.')
parser.add_argument('-f, --file', dest='pwfile', help='File with Passwords to be transformed.')
args = parser.parse_args()
# Check if Arguments are given
if args.pw==None and args.pwfile==None:
    print('ERROR: missing required option\nuse password or file\n-h for more information')
    exit()
# Check if Password-File exists if its passed
if args.pwfile!=None:
    if os.path.exists(args.pwfile)==False:
        print('ERROR: file not found')
        exit()
 
# Decide between Modes: Single Password String OR Password File
mode = 0
if args.pwfile!=None:
    mode = 2
if args.pw!=None:
    mode = 1
 
# Start Counting Time
print('start transforming ...')
calcstart = datetime.now()
 
pwlist = []
# Single Password String
if mode==1:
    pwlist.append(args.pw)
# Password File
if mode==2:
    pwf = open(args.pwfile,'r')
    pwlist = pwf.readlines()
    pwf.close()
    for i in range(len(pwlist)):
        pwlist[i] = pwlist[i].strip('\n')
 
# Transform Passwords to Lan Manger Hash
lmh = lmhash()
hashlist = []
for onepw in pwlist:
    pwhash = lmh.get_hash(onepw)
    print(pwhash, '=', onepw)
    hashlist.append(pwhash)
lmh = None
 
# Store Passwords and Hashes into file
if mode==2:
    pwf = open(args.pwfile + '.lmh','w')
    for i in range(len(pwlist)):
        pwf.write(hashlist[i] + ';' + pwlist[i] + '\n')
    pwf.close()
 
# Finish Time Counting
calcend = datetime.now()
calcdif = calcend - calcstart
print('finished after:', calcdif)
