# Homework 1 (CS5830) 
# Trying to implement a length preserving Encryption function.
# 

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import base64
import binascii

def xor(a,b):
    """
    xors two raw byte streams.
    """
    assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
    return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

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

    ################################################################################
    ## Below are some free utitlity functions. How/where to use them is up to you. ###

    def _pad_string(self, data):
        """Pad @data if required, returns a tuple containing a boolean
        (whether it is padded), and the padded string.

        """
        h_data = data.encode('hex')
        n = len(data)
        if n%2 == 0:
            return False, data
        l,r = h_data[:n], h_data[n:]
        l = '0' + l # I am padding at the beginning, you can do it in
                    # the end as well. Remember to update the unpad
                    # function accordingly.
        r = '0' + r
        return True, (l+r).decode('hex')

    def _unpad_string(self, is_padded, padded_str): # Not tested!
        if not is_padded:
            return padded_str
        n = len(padded_str)
        assert n%2 == 0, "Padded string must of even length. You are "\
            "probably sending something wrong. Note it contains both "\
            "left and right part. Otherwise, just do this unpadding in "\
            "your function"
        l, r = padded_str[:n/2], padded_str[n/2:]
        return (l.encode('hex')[1:] + r.encode('hex')[1:]).decode('hex')

    def _prf(self, key, data):
        """If you haven't figured this out already, this function instanctiate
        AES in CBC mode with static IV, to act as a round function,
        a.k.a. pseudorandom function generator.
        
        WARNING: I am leaving an intentional bug in the
        function. Figure that out, if you want to use this function.

        """
        padder = padding.PKCS7(ciphers.algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = ciphers.Cipher(ciphers.algorithms.AES(self._encryption_key),
                                   ciphers.modes.CBC(iv),
                                   self._backend).encryptor()
        return  (encryptor.update(padded_data) + encryptor.finalize())[:len(data)]
    
    def _prf_hash(self, key, data):
        """Just FYI, you can also instantiate round function ushig SHA256 hash
        function. You don't have to use this function.
        """
        out = self.SHA256hash(data+key) # TODO: SecCheck
        while len(out)<len(data):
            out += self.SHA256hash(out+key)
        return out[:len(data)]

    def _clear_most_significant_four_bits(self, s):
        """
        Clear the first four bits of s and set it to 0.
        e.g, 0xa1 --> 0x01, etc.
        """
        assert len(s) == 1, "You called _clear_most_significant_four_bits function, "\
            "and I only work with 1 byte"
        return ('0' + s.encode('hex')[1]).decode('hex')

    ## END-OF-FREE-LUNCH
    ################################################################################
    
    def encrypt(self, data):
        # TODO - Fill in
        return data

    def decrypt(self, ctx):
        #TODO - Fill in
        return ctx

    def _feistel_round_enc(self, data):
        """This function implements one round of Fiestel encryption block.
        """
        # TODO - Implement this function
        return data
    
    def _feistel_round_dec(self, data):
        """This function implements one round of Fiestel decryption block.
        """
        # TODO - Implement this function 
        return data

class LengthPreservingCipher(object):
    def __init__(self, key, length=5):
        self._length = length
        self._num_rounds = 10 # Hard code this. Don't leave this kind
                              # of parameter upto the developers.

        # TODO

    def encrypt(self, data):
        # TODO
        return data

    def decrypt(self, data):
        # TODO
        return data

    # TODO - add other functions if required
