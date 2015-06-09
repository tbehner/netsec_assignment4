#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright © 2015 Timm Behner <behner@cs.uni-bonn.de>

import argparse
import hashlib
import scapy
from scapy.all import *
from radiusattr import *
import socket

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

def send_package(password, shared_secret):
    msg_auth = get_request_authentication()
    enc_user_password = RadiusAttr.Encrypt_Pass(password,shared_secret,msg_auth)

    user_name_avp = RadiusAttr(type=1, value=b'behner')  
    # I think this is where the password attribute goes to
    user_pw_avp = RadiusAttr(type=2, value=enc_user_password)
    # basicaly I have no clue where this address comes from
    nas_ip_addr_avp = RadiusAttr(type=4, value=inet_pton(socket.AF_INET,'172.17.0.19'))
    nas_port_avp = RadiusAttr(type=5, value=socket.inet_aton('42'))
    msg_auth_avp = RadiusAttr(type=80, value=msg_auth)

    avp = str(user_name_avp)+str(user_pw_avp)+\
        str(nas_ip_addr_avp)+str(nas_port_avp)+\
        str(msg_auth_avp)

    send(IP(dst='10.0.0.10')/UDP(sport=33726,dport=1812)/Radius(code=1,authenticator=msg_auth,id=180)/avp)

# TODO: 
#   * antwort von orange abfragen
#   * automatisieren und shared secret herausfinden

def main():
    options = _parse_args()
    send_package(b'',b'testno42')

def _parse_args():
    """
    Parses the command line arguments.

    :return: Namespace with arguments.
    :rtype: Namespace
    """
    parser = argparse.ArgumentParser(description="")

    return parser.parse_args()


if __name__ == "__main__":
    main()
