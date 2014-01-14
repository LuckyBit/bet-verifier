# vim: ts=3 softtabstop=3 shiftwidth=3 expandtab ai
###########################################################################################
#
# Copyright (C) 2014 LuckyBit Online Games
# 
# Permission is hereby granted, free of charge, to any person obtaining a 
# copy of this software and associated documentation files (the "Software"), 
# to deal in the Software without restriction, including without limitation 
# the rights to use, copy, modify, merge, publish, distribute, sublicense, 
# and/or sell copies of the Software, and to permit persons to whom the 
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in 
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
# DEALINGS IN THE SOFTWARE.
#
###########################################################################################
#
#
#
#
#
#
###########################################################################################
import os
import sys
import re
import random
import time
import json
from urllib2 import urlopen
import hashlib
import base64
import random
import hmac
from datetime import datetime

# version of this script
VERSION = 0.3
# base URL for blockchain.info
BC_BASE_URL = 'https://blockchain.info'
# base URL for LuckyBit
LB_BASE_URL = 'http://luckyb.it'
# LuckyBit games and their addresses
LB_GAME_NAMES = {
      '1LuckyG4tMMZf64j6ea7JhCz7sDpk6vdcS' : 'green',
      '1LuckyY9fRzcJre7aou7ZhWVXktxjjBb9S' : 'yellow',
      '1LuckyR1fFHEsXYyx5QK4UFzv3PEAepPMK' : 'red'
   }


###########################################################################################
# Code taken from Pybitcointools.
# This is unchanged code from https://github.com/vbuterin/pybitcointools/blob/master/pybitcointools/main.py
# License: The MIT License (MIT) Copyright (c) 2013 Vitalik Buterin
# https://github.com/vbuterin/pybitcointools/blob/master/LICENSE
#
### Elliptic curve parameters
P = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx,Gy)

### Extended Euclidean Algorithm

def inv(a,n):
   lm, hm = 1,0
   low, high = a%n,n
   while low > 1:
      r = high/low
      nm, new = hm-lm*r, high-low*r
      lm, low, hm, high = nm, new, lm, low
   return lm % n

### Base switching

def get_code_string(base):
   if base == 2: return '01'
   elif base == 10: return '0123456789'
   elif base == 16: return "0123456789abcdef"
   elif base == 58: return "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   elif base == 256: return ''.join([chr(x) for x in range(256)])
   else: raise ValueError("Invalid base!")

def lpad(msg,symbol,length):
   if len(msg) >= length: return msg
   return symbol * (length - len(msg)) + msg

def encode(val,base,minlen=0):
   base, minlen = int(base), int(minlen)
   code_string = get_code_string(base)
   result = ""   
   while val > 0:
      result = code_string[val % base] + result
      val /= base
   return lpad(result,code_string[0],minlen)

def decode(string,base):
   base = int(base)
   code_string = get_code_string(base)
   result = 0
   if base == 16: string = string.lower()
   while len(string) > 0:
      result *= base
      result += code_string.find(string[0])
      string = string[1:]
   return result

def changebase(string,frm,to,minlen=0):
   if frm == to: return lpad(string,minlen)
   return encode(decode(string,frm),to,minlen)

### Elliptic Curve functions

def isinf(p): return p[0] == 0 and p[1] == 0

def base10_add(a,b):
   if isinf(a): return b[0],b[1]
   if isinf(b): return a[0],a[1]
   if a[0] == b[0]: 
      if a[1] == b[1]: return base10_double((a[0],a[1]))
      else: return (0,0)
   m = ((b[1]-a[1]) * inv(b[0]-a[0],P)) % P
   x = (m*m-a[0]-b[0]) % P
   y = (m*(a[0]-x)-a[1]) % P
   return (x,y)
  
def base10_double(a):
   if isinf(a): return (0,0)
   m = ((3*a[0]*a[0]+A)*inv(2*a[1],P)) % P
   x = (m*m-2*a[0]) % P
   y = (m*(a[0]-x)-a[1]) % P
   return (x,y)

def base10_multiply(a,n):
   if isinf(a) or n == 0: return (0,0)
   if n == 1: return a
   if n < 0 or n >= N: return base10_multiply(a,n%N)
   if (n%2) == 0: return base10_double(base10_multiply(a,n/2))
   if (n%2) == 1: return base10_add(base10_double(base10_multiply(a,n/2)),a)

# Functions for handling pubkey and privkey formats

def get_pubkey_format(pub):
   if isinstance(pub,(tuple,list)): return 'decimal'
   elif len(pub) == 65 and pub[0] == '\x04': return 'bin'
   elif len(pub) == 130 and pub[0:2] == '04': return 'hex'
   elif len(pub) == 33 and pub[0] in ['\x02','\x03']: return 'bin_compressed'
   elif len(pub) == 66 and pub[0:2] in ['02','03']: return 'hex_compressed'
   elif len(pub) == 64: return 'bin_electrum'
   elif len(pub) == 128: return 'hex_electrum'
   else: raise Exception("Pubkey not in recognized format")

def encode_pubkey(pub,formt):
   if not isinstance(pub,(tuple,list)):
      pub = decode_pubkey(pub)
   if formt == 'decimal': return pub
   elif formt == 'bin': return '\x04' + encode(pub[0],256,32) + encode(pub[1],256,32)
   elif formt == 'bin_compressed': return chr(2+(pub[1]%2)) + encode(pub[0],256,32)
   elif formt == 'hex': return '04' + encode(pub[0],16,64) + encode(pub[1],16,64)
   elif formt == 'hex_compressed': return '0'+str(2+(pub[1]%2)) + encode(pub[0],16,64)
   elif formt == 'bin_electrum': return encode(pub[0],256,32) + encode(pub[1],256,32)
   elif formt == 'hex_electrum': return encode(pub[0],16,64) + encode(pub[1],16,64)
   else: raise Exception("Invalid format!")

def decode_pubkey(pub,formt=None):
   if not formt: formt = get_pubkey_format(pub)
   if formt == 'decimal': return pub
   elif formt == 'bin': return (decode(pub[1:33],256),decode(pub[33:65],256))
   elif formt == 'bin_compressed':
      x = decode(pub[1:33],256)
      beta = pow(x*x*x+7,(P+1)/4,P)
      y = (P-beta) if ((beta + ord(pub[0])) % 2) else beta
      return (x,y)
   elif formt == 'hex': return (decode(pub[2:66],16),decode(pub[66:130],16))
   elif formt == 'hex_compressed':
      return decode_pubkey(pub.decode('hex'),'bin_compressed')
   elif formt == 'bin_electrum':
      return (decode(pub[:32],256),decode(pub[32:64],256))
   elif formt == 'hex_electrum':
      return (decode(pub[:64],16),decode(pub[64:128],16))
   else: raise Exception("Invalid format!")

def get_privkey_format(priv):
   if isinstance(priv,(int,long)): return 'decimal'
   elif len(priv) == 32: return 'bin'
   elif len(priv) == 33: return 'bin_compressed'
   elif len(priv) == 64: return 'hex'
   elif len(priv) == 66: return 'hex_compressed'
   else:
      bin_p = b58check_to_bin(priv)
      if len(bin_p) == 32: return 'wif'
      elif len(bin_p) == 33: return 'wif_compressed'
      else: raise Exception("WIF does not represent privkey")

def encode_privkey(priv,formt,vbyte=0):
   if not isinstance(priv,(int,long)):
      return encode_privkey(decode_privkey(priv),formt,vbyte)
   if formt == 'decimal': return priv
   elif formt == 'bin': return encode(priv,256,32)
   elif formt == 'bin_compressed': return encode(priv,256,32)+'\x01'
   elif formt == 'hex': return encode(priv,16,64)
   elif formt == 'hex_compressed': return encode(priv,16,64)+'01'
   elif formt == 'wif':
      return bin_to_b58check(encode(priv,256,32),128+int(vbyte))
   elif formt == 'wif_compressed':
      return bin_to_b58check(encode(priv,256,32)+'\x01',128+int(vbyte))
   else: raise Exception("Invalid format!")

def decode_privkey(priv,formt=None):
   if not formt: formt = get_privkey_format(priv)
   if formt == 'decimal': return priv
   elif formt == 'bin': return decode(priv,256)
   elif formt == 'bin_compressed': return decode(priv[:32],256)
   elif formt == 'hex': return decode(priv,16)
   elif formt == 'hex_compressed': return decode(priv[:64],16)
   else:
      bin_p = b58check_to_bin(priv)
      if len(bin_p) == 32: return decode(bin_p,256)
      elif len(bin_p) == 33: return decode(bin_p[:32],256)
      else: raise Exception("WIF does not represent privkey")

def add_pubkeys(p1,p2):
   f1,f2 = get_pubkey_format(p1), get_pubkey_format(p2)
   return encode_pubkey(base10_add(decode_pubkey(p1,f1),decode_pubkey(p2,f2)),f1)

def add_privkeys(p1,p2):
   f1,f2 = get_privkey_format(p1), get_privkey_format(p2)
   return encode_privkey((decode_privkey(p1,f1) + decode_privkey(p2,f2)) % N,f1)

def multiply(pubkey,privkey):
   f1,f2 = get_pubkey_format(pubkey), get_privkey_format(privkey)
   pubkey, privkey = decode_pubkey(pubkey,f1), decode_privkey(privkey,f2)
   # http://safecurves.cr.yp.to/twist.html
   if not isinf(pubkey) and (pubkey[0]**3+7-pubkey[1]*pubkey[1]) % P != 0: 
      raise Exception("Point not on curve")
   return encode_pubkey(base10_multiply(pubkey,privkey),f1)

def divide(pubkey,privkey):
   factor = inv(decode_privkey(privkey),N)
   return multiply(pubkey,factor)

def compress(pubkey):
   f = get_pubkey_format(pubkey)
   if 'compressed' in f: return pubkey
   elif f == 'bin': return encode_pubkey(decode_pubkey(pubkey,f),'bin_compressed')
   elif f == 'hex' or f == 'decimal':
      return encode_pubkey(decode_pubkey(pubkey,f),'hex_compressed')

def decompress(pubkey):
   f = get_pubkey_format(pubkey)
   if 'compressed' not in f: return pubkey
   elif f == 'bin_compressed': return encode_pubkey(decode_pubkey(pubkey,f),'bin')
   elif f == 'hex_compressed' or f == 'decimal':
      return encode_pubkey(decode_pubkey(pubkey,f),'hex')

def privkey_to_pubkey(privkey):
   f = get_privkey_format(privkey)
   privkey = decode_privkey(privkey,f)
   if privkey == 0 or privkey >= N:
      raise Exception("Invalid privkey")
   if f in ['bin','bin_compressed','hex','hex_compressed','decimal']:
      return encode_pubkey(base10_multiply(G,privkey),f)
   else:
      return encode_pubkey(base10_multiply(G,privkey),f.replace('wif','hex'))

privtopub = privkey_to_pubkey

def privkey_to_address(priv,magicbyte=0):
   return pubkey_to_address(privkey_to_pubkey(priv),magicbyte)
privtoaddr = privkey_to_address

def neg_pubkey(pubkey): 
   f = get_pubkey_format(pubkey)
   pubkey = decode_pubkey(pubkey,f)
   return encode_pubkey((pubkey[0],(P-pubkey[1]) % P),f)

def neg_privkey(privkey):
   f = get_privkey_format(privkey)
   privkey = decode_privkey(privkey,f)
   return encode_privkey((N - privkey) % N,f)

def subtract_pubkeys(p1, p2):
   f1,f2 = get_pubkey_format(p1), get_pubkey_format(p2)
   k2 = decode_pubkey(p2,f2)
   return encode_pubkey(base10_add(decode_pubkey(p1,f1),(k2[0],(P - k2[1]) % P)),f1)

def subtract_privkeys(p1, p2):
   f1,f2 = get_privkey_format(p1), get_privkey_format(p2)
   k2 = decode_privkey(p2,f2)
   return encode_privkey((decode_privkey(p1,f1) - k2) % N,f1)

### Hashes

def bin_hash160(string):
   intermed = hashlib.sha256(string).digest()
   return hashlib.new('ripemd160',intermed).digest()
def hash160(string):
   return bin_hash160(string).encode('hex')

def bin_sha256(string):
   return hashlib.sha256(string).digest()
def sha256(string):
   return bin_sha256(string).encode('hex')

def bin_dbl_sha256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()
def dbl_sha256(string):
   return bin_dbl_sha256(string).encode('hex')

def bin_slowsha(string):
   orig_input = string
   for i in range(100000):
      string = hashlib.sha256(string + orig_input).digest()
   return string
def slowsha(string):
   return bin_slowsha(string).encode('hex')

def hash_to_int(x):
   if len(x) in [40,64]: return decode(x,16)
   else: return decode(x,256)

def num_to_var_int(x):
   x = int(x)
   if x < 253: return chr(x)
   elif x < 65536: return chr(253) + encode(x,256,2)[::-1]
   elif x < 4294967296: return chr(254) + encode(x,256,4)[::-1]
   else: return chr(255) + encode(x,256,8)[::-1]

# WTF, Electrum?
def electrum_sig_hash(message):
   padded = "\x18Bitcoin Signed Message:\n" + num_to_var_int( len(message) ) + message
   return bin_dbl_sha256(padded)

def random_key():
   # Gotta be secure after that java.SecureRandom fiasco...
   entropy = os.urandom(32)+str(random.randrange(2**256))+str(int(time.time())**7)
   return sha256(entropy)

def random_electrum_seed():
   entropy = os.urandom(32)+str(random.randrange(2**256))+str(int(time.time())**7)
   return sha256(entropy)[:32]

### Encodings

def bin_to_b58check(inp,magicbyte=0):
   inp_fmtd = chr(int(magicbyte)) + inp
   leadingzbytes = len(re.match('^\x00*',inp_fmtd).group(0))
   checksum = bin_dbl_sha256(inp_fmtd)[:4]
   return '1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)

def b58check_to_bin(inp):
   leadingzbytes = len(re.match('^1*',inp).group(0))
   data = '\x00' * leadingzbytes + changebase(inp,58,256)
   assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
   return data[1:-4]

def get_version_byte(inp):
   leadingzbytes = len(re.match('^1*',inp).group(0))
   data = '\x00' * leadingzbytes + changebase(inp,58,256)
   assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
   return ord(data[0])

def hex_to_b58check(inp,magicbyte=0):
   return bin_to_b58check(inp.decode('hex'),magicbyte)

def b58check_to_hex(inp): return b58check_to_bin(inp).encode('hex')

def pubkey_to_address(pubkey,magicbyte=0):
   if isinstance(pubkey,(list,tuple)):
      pubkey = encode_pubkey(pubkey,'bin')
   if len(pubkey) in [66,130]:
      return bin_to_b58check(bin_hash160(pubkey.decode('hex')),magicbyte)
   return bin_to_b58check(bin_hash160(pubkey),magicbyte)

pubtoaddr = pubkey_to_address

### EDCSA

def encode_sig(v,r,s):
   vb, rb, sb = chr(v), encode(r,256), encode(s,256)
   return base64.b64encode(vb+'\x00'*(32-len(rb))+rb+'\x00'*(32-len(sb))+sb)

def decode_sig(sig):
   bytez = base64.b64decode(sig)
   return ord(bytez[0]), decode(bytez[1:33],256), decode(bytez[33:],256)

# https://tools.ietf.org/html/rfc6979#section-3.2
def deterministic_generate_k(msghash,priv):
   v = '\x01' * 32
   k = '\x00' * 32
   priv = encode_privkey(priv,'bin')
   msghash = encode(hash_to_int(msghash),256,32)
   k = hmac.new(k, v+'\x00'+priv+msghash, hashlib.sha256).digest()
   v = hmac.new(k, v, hashlib.sha256).digest()
   k = hmac.new(k, v+'\x01'+priv+msghash, hashlib.sha256).digest()
   v = hmac.new(k, v, hashlib.sha256).digest()
   return decode(hmac.new(k, v, hashlib.sha256).digest(),256)

def ecdsa_raw_sign(msghash,priv):

   z = hash_to_int(msghash)
   k = deterministic_generate_k(msghash,priv)

   r,y = base10_multiply(G,k)
   s = inv(k,N) * (z + r*decode_privkey(priv)) % N

   return 27+(y%2),r,s

def ecdsa_sign(msg,priv):
   return encode_sig(*ecdsa_raw_sign(electrum_sig_hash(msg),priv))

def ecdsa_raw_verify(msghash,vrs,pub):
   v,r,s = vrs

   w = inv(s,N)
   z = hash_to_int(msghash)
   
   u1, u2 = z*w % N, r*w % N
   x,y = base10_add(base10_multiply(G,u1), base10_multiply(decode_pubkey(pub),u2))

   return r == x

def ecdsa_verify(msg,sig,pub):
   return ecdsa_raw_verify(electrum_sig_hash(msg),decode_sig(sig),pub)

def ecdsa_raw_recover(msghash,vrs):
   v,r,s = vrs

   x = r
   beta = pow(x*x*x+7,(P+1)/4,P)
   y = beta if v%2 ^ beta%2 else (P - beta)
   z = hash_to_int(msghash)

   Qr = base10_add(neg_pubkey(base10_multiply(G,z)),base10_multiply((x,y),s))
   Q = base10_multiply(Qr,inv(r,N))

   if ecdsa_raw_verify(msghash,vrs,Q): return Q
   return False

def ecdsa_recover(msg,sig):
   return encode_pubkey(ecdsa_raw_recover(electrum_sig_hash(msg),decode_sig(sig)),'hex')

# Pybitcointools end
###########################################################################################


# converts satoshis to btc
def satoshisToFloatBtc(amount):
   return float(amount / 1e8)

# get commandline argument
if len(sys.argv) != 2 or not re.match('^[a-zA-Z0-9]{64}$', sys.argv[1]):
   sys.stderr.write("Usage  : python %s <transaction id of the bet(s) to verify\n" % sys.argv[0])
   sys.stderr.write("Example: python %s e9f65033e7d684143b7336429ef82fd5009a7decb72230dfc7d7e82a7e3092f8\n" % sys.argv[0]) 
   sys.stderr.write("Please specify a valid transaction id!\n")
   exit(1)

# set txit to check
txToCheck = sys.argv[1]

################################
# Downloads the list of key hashes from LuckyBit.
# The list contains the hash of the secret key of every day.
# The hashes can be used to verify that a give bet has been resolved in a fair manner.
# The list is available at http://luckyb.it/secret-key-hashes.txt
#
sys.stdout.write("Downloading list of key hashes .......................... ")
try:
   url = LB_BASE_URL + '/secret-key-hashes.txt'
   luckyBitKeyHashes = urlopen(LB_BASE_URL + '/secret-key-hashes.txt').readlines()
   sys.stdout.write("OK\n")
except URLError as e:
   sys.stdout.write("FAIL\n")
   sys.stderr.write("Failed to retrieve the list of secret key hashes from " + url + "\n") 
   exit(1)


#################################
# Verify the correctness of the list of hashes.
# Computes the hash of the list (SHA256) and converts this hash to a
# bitcoin address. We made a single transaction to this address on
# 2013-09-10 12:31:31, which proves that the list has not been modified
# since. This code checks that this is correct.
#
sys.stdout.write("Verifying list of key hashes ............................ ")
hashOfHashFile = hashlib.sha256()
hashOfHashFile.update(''.join(luckyBitKeyHashes))
addressOfHashFile = privkey_to_address(hashOfHashFile.hexdigest())
try:
   url = BC_BASE_URL + '/rawaddr/' + addressOfHashFile
   addrData = json.load(urlopen(url))
except URLError as e:
   sys.stdout.write("FAIL\n")
   sys.stderr.write("Failed to retrieve address details from " + url + "\n") 
   exit(1)
if 'txs' in addrData:
   txs = addrData['txs']
   txTime = datetime.utcfromtimestamp(txs[len(txs) - 1]['time'])
   sys.stdout.write("OK (not modified since %s)\n" % str(txTime))


#################################
# Get the data of the transaction to verify from blockchain.info.
# Get the sender address.
#
sys.stdout.write("Getting transaction ..................................... %s\n" % txToCheck)
try:
   url = BC_BASE_URL + '/rawtx/' + txToCheck
   txData = json.load(urlopen(url))
except URLError as e:
   sys.stderr.write("Failed to retrieve transaction from " + url + "\n") 
   exit(1)
senderAddress = txData['inputs'][0]['prev_out']['addr']
sys.stdout.write("Sender address is ....................................... %s" % senderAddress)


#################################
# Each transaction can contain multiple bets towards LuckyBit.
# Loop over every bet found.
#
allOk = True
for out in txData['out']:
   if out['addr'] in LB_GAME_NAMES:
      sys.stdout.write("Found a bet for LuckyBit\n")

      # Each bet is identified by the transaction id and its vout (txit:vout).
      betTxidVout = txToCheck + ":" + str(out['n'])      
      sys.stdout.write(" * Bet identifier ....................................... %s\n" %
            betTxidVout)

      # Get bet amount
      sys.stdout.write(" * Checking bet game/amount ............................. %s/%f BTC\n" % 
            (LB_GAME_NAMES[out['addr']], satoshisToFloatBtc(out['value'])))

      # Bets must be 24 hrs old to be verified - if they are younger, the associated secret key hasn't been published yet!
      betTime = datetime.utcfromtimestamp(txData['time'])
      if (datetime.now() - betTime).days == 0:
         sys.stdout.write(" * Warning: bet is too recent, cannot verify! Check again in 24 hours.\n")
         continue

      #################################
      # Check if the bet itself was valid (not too small or not too big)
      # For this, get the bet's data from the Luckybit API.
      # Bet type must be VALID_BET to continue.
      #
      sys.stdout.write(" * Checking if bet was valid ............................ ")
      betsOfTxData = None
      try:         
         url = LB_BASE_URL + '/api/getbetbytxidvout/' + betTxidVout
         bet = json.load(urlopen(url))[betTxidVout]
      except URLError as e:
         sys.stderr.write("Exception! %s\n" % repr(e))
         allOk = False
         continue 
      if 'type' in bet and bet['type'] == "VALID_BET":
         sys.stdout.write("OK\n")
      else:
         sys.stdout.write("FAIL\n")
         sys.stderr.write("Bet was either invalid or failed to retrieve bet from " + url + "\n") 
         allOk = False
         continue

      #################################
      sys.stdout.write(" * Retrieving secret key of bet day ..................... ")
      betDateString = betTime.strftime("%Y-%m-%d")
      try:
         url = LB_BASE_URL + '/api/getkeybydate/' + betDateString
         keyData = json.load(urlopen(url))
      except BaseException as e:
         # TODO: treat exception properly
         sys.stderr.write("Exception! %s\n" % repr(e))
         pass
      if keyData and betDateString in keyData:
         sys.stdout.write("OK\n")
         secretKey = keyData[betDateString]
      else:
         sys.stdout.write("FAIL\n")
         sys.stderr.write("Failed to retrieve secret key from " + url + "\n")
         allOk = False
         continue

      #################################
      hashOfSecretKey = hashlib.sha256()
      hashOfSecretKey.update(secretKey)
      hashOfSecretKey = hashOfSecretKey.hexdigest()

      hashOfDayFromFile = None
      for line in luckyBitKeyHashes:
         m = re.match("^%02d-%02d-%s:([A-Za-z0-9]+)\n$" % (betTime.day, betTime.month, str(betTime.year)[-2:]), line)
         if m:
            hashOfDayFromFile = m.group(1)

      #################################
      sys.stdout.write(" * Verifying secret key using hash ...................... ")
      if hashOfDayFromFile == hashOfSecretKey:
         sys.stdout.write("OK\n")
      else:
         sys.stdout.write("FAIL\n")
         sys.stderr.write("Computed hash of secret key does not match the recorded hash" + "\n") 
         allOk = False
         continue

      #################################
      sys.stdout.write(" * Computing movement of coin ........................... ")
      luckyString = (txData['hash'] + ':' + str(out['n']) + ':' + secretKey).lower()
      hashOfLuckyString = hashlib.sha256()
      hashOfLuckyString.update(luckyString)
      hashOfLuckyString = hashOfLuckyString.hexdigest()
      last2bytesOfLuckyString = hashOfLuckyString[-4:]
      luckyBinaryString = bin(int(last2bytesOfLuckyString, 16))[2:].zfill(16) 
      luckyMoves = ""
      for c in luckyBinaryString:
         luckyMoves += "left," if c == "0" else "right,"
      sys.stdout.write(luckyMoves[:-1] + "\n")

      #################################
      sys.stdout.write(" * Computing obtained multiplier ........................ ")
      betRank = abs(8 - luckyBinaryString.count('1'))
      try:
         url = LB_BASE_URL + '/api/getgamebyname/' + LB_GAME_NAMES[out['addr']]
         gameData = json.load(urlopen(url))
      except BaseException as e:
         # TODO: treat exception properly
         sys.stderr.write("Exception! %s\n" % repr(e))
         pass
      if gameData and LB_GAME_NAMES[out['addr']] in gameData:
         multiplierObtained = gameData[LB_GAME_NAMES[out['addr']]]['multipliers'][str(betRank)]
         sys.stdout.write("%f\n" % multiplierObtained)
      else:
         sys.stdout.write("FAIL\n")
         sys.stderr.write("Failed to retrieve multipliers from " + url + "\n") 
         allOk = False
         continue

      #################################
      sys.stdout.write(" * Computing payout amount .............................. ")
      payoutAmount = int(out['value'] * multiplierObtained) - 10000
      sys.stdout.write("%f BTC\n" % satoshisToFloatBtc(payoutAmount))

      #################################
      sys.stdout.write(" * Retrieving payout transaction ........................ ")
      payoutTx = bet['txout_id']
      payoutData = None
      try:
         url = BC_BASE_URL + '/rawtx/' + payoutTx
         payoutData = json.load(urlopen(url))
         sys.stdout.write(payoutTx + "\n")
      except BaseException as e:
         # TODO: treat exception properly
         #sys.stderr.write("Exception! %s\n" % repr(e))
         sys.stdout.write("FAIL\n")
         sys.stderr.write("Failed to retrieve multipliers from " + url + "\n") 
         allOk = False
         continue

      #################################
      sys.stdout.write(" * Checking if payout amount matches computed value ..... ")
      for payout in payoutData['out']:
         if payout['addr'] == senderAddress:
            break
      if payout and payout['addr'] == senderAddress and payout['value'] == payoutAmount:
         sys.stdout.write("OK\n")
      else:
         sys.stdout.write("FAIL\n")
         sys.stderr.write("Payout transaction not found or payout amount does not match comuted value\n")
         allOk = False
         continue
      
      sys.stdout.write(" * Bet verifyied ........................................ OK")

if allOk:
   sys.stdout.write("\nAll bets were successfully verified\n")
else:
   sys.stdout.write("\nProblems detected. Please contact support@luckyb.it\n")

