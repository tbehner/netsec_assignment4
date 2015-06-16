#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright © 2015 Timm Behner <behner@cs.uni-bonn.de>

import argparse

def split_by_512bytes(bytestring):
    chunks = []
    chunk_length = 512
    if len(bytestring) % chunk_length != 0:
        pending_zeros = bytearray(chunk_length - len(bytestring)%chunk_length)
        bytestring = bytestring + pending_zeros
    for i in range(0,len(bytestring),chunk_length):
        chunks.append(bytestring[i:i+chunk_length])
    return chunks

def xor(a,b):
    return bytearray(x^y for x, y in zip(a,b))

def rot128(barray):
    ret = barray
    for idx, b in enumerate(ret):
        ret[idx] = (b + 128) % 256
    return ret

def bytetohex(bytestr):
    return ''.join('{:02x}'.format(x) for x in bytestr)

def read_document(filename):
    with open(filename, 'rb') as f:
        ret = f.read()
    return ret

def cbc_mac(chunks):
    # initialize c for first xor
    c = bytearray(512)
    for p in chunks:
        tmp = xor(c,p)
        c = rot128(tmp)
    return c

def main():
    options = _parse_args()
    #ret = rot128(bytearray(b'\xde\xad\xbe\xef'))
    #print(bytetohex(ret))
    content = read_document(options.filename)
    chunks = split_by_512bytes(content)
    mac = cbc_mac(chunks)
    print(bytetohex(mac))

def _parse_args():
    '''
    Parses the command line arguments.

    :return: Namespace with arguments.
    :rtype: Namespace
    '''
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('filename')
    options = parser.parse_args()

    return options

if __name__ == '__main__':
    main()
