#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright © 2015 Timm Behner <behner@cs.uni-bonn.de>

import argparse
import hashlib
from radiusattr import *

def pad_with_zeros(barray, length):
    size = length - len(barray)
    if size > 0:
        pending_zeros = bytearray(size)
        return barray + pending_zeros 
    else:
        return barray

'''
I assume that 16 octets means 16 bytes
'''
def split_to_16bytes(bytestring):
    chunks = []
    if len(bytestring) % 16 != 0:
        pending_zeros = bytearray(16 - len(bytestring)%16)
        bytestring = bytestring + pending_zeros
    for i in range(0,len(bytestring),16):
        chunks.append(bytestring[i:i+16])
    return chunks

def calculate_password_attribute(password, shared_secret, requ_auth):
    # enforce every input to be a bytestring
    password = bytearray(password)
    shared_secret = bytearray(shared_secret)
    requ_auth = bytearray(requ_auth)

    password_attribute = None
    chunks = split_to_16bytes(password)
    b = hashlib.md5(shared_secret+requ_auth)
    for c in chunks:
        tmp_c = hashlib.md5(c + b)
        b = hashlib.md5(shared_secret+tmp_c)
        password_attribute = tmp_c
    '''
    Is the last tmp_c or the last b the password attribute?
    '''
    return password_attribute

def xor(a,b):
    return bytearray(x^y for x, y in zip(a,b))

def get_request_authentication():
    return os.urandom(16)

def calculate_short_password_attribute(password, shared_secret, requ_auth):
    # enforce every input to be a bytestring
    password = bytearray(password)
    shared_secret = bytearray(shared_secret)
    requ_auth = bytearray(requ_auth)

    b = bytearray(hashlib.md5(shared_secret + requ_auth).digest())
    c = xor(b, pad_with_zeros(password,16))
    return c

def brute_force_secret(password, authenticator, dictionary, encpassword):
    with open(dictionary, 'r') as d:
        for line in d:
            for word in re.compile("\w+").findall(line):
                word = bytearray(word)
                print(word)
                enc_w = calculate_short_password_attribute(password, word, authenticator)
                if RadiusAttr.Encrypt_Pass(password, authenticator, word) == encpassword:
                    return word

def bytearray_join(glue, list_of_barrays):
    res = list_of_barrays[0]
    for i in range(1,len(list_of_barrays)):
        res += glue + list_of_barrays[i]
    return res

def rm_colons(string):
    return ''.join(string.split(':'))
 #   return bytearray_join(b'', string.split(':'))

def main():
    options = _parse_args()
    passwd = options.password
    auth = rm_colons(options.authenticator)
    enc_pw = rm_colons(options.encrypted_password)
    print( passwd, auth, enc_pw)
    brute_force_secret(options.password, options.authenticator, './rfc7511.txt', options.encrypted_password)

def _parse_args():
    """
    Parses the command line arguments.

    :return: Namespace with arguments.
    :rtype: Namespace
    """
    parser = argparse.ArgumentParser(description="")
    parser.add_argument('password'           , type=str)
    parser.add_argument('authenticator'      , type=str)
    parser.add_argument('encrypted_password' , type=str)

    return parser.parse_args()


if __name__ == "__main__":
    main()
