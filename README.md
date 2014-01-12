LuckyBit Bet Verifier
=====================

LuckyBit - http://luckyb.it

This repository contains a bet verifier for LuckyBit.

The bet verifier allows users to verify that their bets
are 100% provably fair. The bet verifyer uses external
3rd-party sources (http://blockchain.info) for verifying
a bet.

Prerequisites
-------------

No special prerequesites are required:

 * python version 2.6-2.7
 * python-json

The bet verifier is a command line script. 
Access to the command line is therefore required.

Usage
-----

 1. Open a command line terminal.
 1. Simply execute the script with a single parameter: the transaction ID of your bet.


Example (Windows):

    python.exe lb-bet-verifier.py e9f65033e7d684143b7336429ef82fd5009a7decb72230dfc7d7e82a7e3092f8


Example (Linux/Mac):

    python lb-bet-verifier.py e9f65033e7d684143b7336429ef82fd5009a7decb72230dfc7d7e82a7e3092f8


Example output:

    Downloading list of key hashes .......................... OK
    Verifying list of key hashes ............................ OK (not modified since 2013-09-10 12:31:31)
    Getting transaction ..................................... e9f65033e7d684143b7336429ef82fd5009a7decb72230dfc7d7e82a7e3092f8
    Sender address is ....................................... 17k2JFCpJ4CQRLiUQMhgW3RHuuVUVirv1uFound a bet for LuckyBit
     * Bet identifier ....................................... e9f65033e7d684143b7336429ef82fd5009a7decb72230dfc7d7e82a7e3092f8:0
     * Checking bet game/amount ............................. yellow/0.001000 BTC
     * Checking if bet was valid ............................ OK
     * Retrieving secret key of bet day ..................... OK
     * Verifying secret key using hash ...................... OK
     * Computing movement of coin ........................... left,right,right,left,left,right,right,left,right,right,left,right,left,right,left,left
     * Computing obtained multiplier ........................ 0.300000
     * Computing payout amount .............................. 0.000200 BTC
     * Retrieving payout transaction ........................ a3df25e58f37f0c74902e7dfb5cfde1f9b667655a54001edf2719a724d78f3db
     * Checking if payout amount matches computed value ..... OK
     * Bet verifyied ........................................ OK
    All bets were successfully verified


Acknowledgements
----------------

The bet verifier incorporates a chunk of code from Pybitcointools.
This code has been taken unmodified from 
https://github.com/vbuterin/pybitcointools/blob/master/pybitcointools/main.py
License: The MIT License (MIT) Copyright (c) 2013 Vitalik Buterin
https://github.com/vbuterin/pybitcointools/blob/master/LICENSE


License
-------
See LICENSE file.
The MIT License (MIT) Copyright (C) 2014 LuckyBit Online Games

