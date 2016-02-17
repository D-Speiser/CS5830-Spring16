# Homework 1 (CS5830) 
# Trying to implement a length preserving Encryption function.
# 

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import base64
import binascii
import random
from Crypto.Cipher import AES

def xor(a,b):
    """
    xors two raw byte streams.
    """
    assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
    return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

def rand_bitstring(n):
  return "".join([str(random.randint(0, 1)) for i in range(n)])

class MyFeistel:
    def __init__(self, key, num_rounds, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 16:
            raise ValueError(
                "Key must be 16 url-safe base64-encoded bytes. Got: {} ({})".format(key, len(key))
            )
        self._num_rounds = num_rounds
        self._encryption_key = key
        self._backend = backend
        self._round_keys = [self._encryption_key \
                            for _ in xrange(self._num_rounds)]
        for i  in xrange(self._num_rounds):
            if i==0: continue
            self._round_keys[i] = self._SHA256hash(self._round_keys[i-1])

    def _SHA256hash(self, data):
        h = hashes.Hash(hashes.SHA256(), self._backend)
        h.update(data)
        return h.finalize()

    def encrypt(self, data):
        assert len(data)%2 == 0, "Supports only balanced feistel at "\
            "this moment. So provide even length messages."
        new_data = data
        for i in range(self._num_rounds):
            new_data = self._feistel_round_enc(new_data, i)
        return new_data

    def decrypt(self, ctx):
            assert len(ctx)%2 == 0, "Supports only balanced feistel at "\
                "this moment. So provide even length ciphertext."
            new_ctx = ctx
            for i in range(self._num_rounds - 1, -1, -1):
                new_ctx = self._feistel_round_dec(new_ctx, i)
            return new_ctx

    def _prf(self, key, data, round_num):
        """Set up secure round function F
        """
        mid = len(data) / 2
        if round_num == 0:
            return data[mid:]
  
        xored = xor(data[:mid], data[mid:])
        ctx = AES.new(key, AES.MODE_CBC, 'This is an IV456').encrypt(xored)
        return ctx

    def _feistel_round_enc(self, data, round_num):
        """This function implements one round of Fiestel encryption block.
        """
        mid = len(data) / 2
        L, R = data[:mid], data[mid:]
        Ri = xor(L, self._prf(self._round_keys[round_num], data))
        
        print "ENC Round {0} key: {1}".format(round_num, binascii.b2a_hex(self._round_keys[round_num]))
        print "ENC Round {0} ctx: {1}".format(round_num, binascii.b2a_hex(Ri + R))
        
        return Ri + R
    
    def _feistel_round_dec(self, data, round_num):
        """This function implements one round of Fiestel decryption block.
        """
        # mid = len(data) / 2
        # Ri1, Li1 = data[:mid], data[mid:]
        # Li = xor(Ri1, self._prf(self._round_keys[round_num], Li1))

        # return Li + Li1

        mid = len(data) / 2
        Ri = data[mid:]
        Li = xor(data[:mid], self._prf(self._round_keys[round_num], data))

        print "DEC Round {0} key: {1}".format(round_num, binascii.b2a_hex(self._round_keys[round_num]))
        print "DEC Round {0} ctx: {1}".format(round_num, binascii.b2a_hex(Li + Ri))

        return Li + Ri

class LengthPreservingCipher(object):
    def __init__(self, key, length=40):
        self._length = 40
        #TODO 

    def encrypt(self, data):
        # TODO
        return data

    def decrypt(self, data):
        # TODO
        return data

    # TODO - add other functions if required
