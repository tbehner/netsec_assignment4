#!/usr/bin/python
# -*- coding: utf-8 -*-

from task_4 import * 
import unittest
import argparse
 
class SplitTest(unittest.TestCase):
    def test_short_input(self):
        inp = bytearray(5)
        res = split_to_16bytes(inp)
        self.assertEqual(res, [bytearray(16)])

    def test_with_exact_length(self):
        initial_str = bytearray(16)
        inp = initial_str * 2
        exp = [initial_str, initial_str]
        res = split_to_16bytes(inp)
        self.assertEqual(res, exp)

    def test_with_pending_zeros(self):
        inp = bytearray(b'\x01'*29)
        res = split_to_16bytes(inp)
        exp = [bytearray(b'\x01'*16), bytearray(b'\x01'*13 + b'\x00'*3)]
        self.assertEqual(res,exp)

class PeddingTest(unittest.TestCase):
    def test_shorter_length(self):
        inp = bytearray(b'\x01' * 10)
        res = pad_with_zeros(inp,16)
        self.assertEqual(res, bytearray(b'\x01' * 10) + bytearray(b'\x00' * 6))
    
    def test_exact_length(self):
        inp = bytearray(b'\x01' * 16)
        res = pad_with_zeros(inp,16)
        self.assertEqual(res, inp, msg = 'input length: {}\noutput length: {}'.format(len(inp), len(res)))

    def test_greater_length(self):
        inp = bytearray(b'\x01' * 10)
        res = pad_with_zeros(inp,8)
        self.assertEqual(res,inp)
        self.assertEqual(res, inp, msg = 'input length: {}\noutput length: {}'.format(len(inp), len(res)))

class XORTest(unittest.TestCase):
    def test_values(self):
        a = bytearray(b'\x00\x00\x01\x01')
        b = bytearray(b'\x00\x01\x00\x01')
        res = xor(a,b)
        self.assertEqual(res,bytearray('\x00\x01\x01\x00'))

class MD5Test(unittest.TestCase):
    def test_length(self):
        inp = bytearray(b'Hello World')
        res = hashlib.md5(inp).digest()
        self.assertEqual(len(res), 16)

# TODO: where do i get an example from?
class PasswordAttributeTest(unittest.TestCase):
    pass
