from MyFeistel import MyFeistel, LengthPreservingCipher
import pytest
import base64
import os

class TestMyFeistel:
    def test_Functionality(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        feistel = MyFeistel(key, 10)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(20):
            msg = os.urandom(40)
            assert feistel.decrypt(feistel.encrypt(msg)) == msg
    
    def test_OddLengthMessage(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        feistel = MyFeistel(key, 10)

        for i in xrange(11, 51, 2):
            msg = os.urandom(i)
            assert feistel.decrypt(feistel.encrypt(msg)) == msg

    def test_zeroLengthMessage(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        feistel = MyFeistel(key, 10)

        msg = os.urandom(0)
        assert feistel.decrypt(feistel.encrypt(msg)) == msg

    def test_varyingRoundsFeistel(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        for i in xrange(4, 14):
            feistel = MyFeistel(key, i)
            msg = os.urandom(40)
            assert feistel.decrypt(feistel.encrypt(msg)) == msg

    # this test is expected to fail except for when the key length = 16
    def test_varyingLengthKey(self):
        for i in xrange(10, 20):
            key = base64.urlsafe_b64encode(os.urandom(i))
            feistel = MyFeistel(key, 10)
            msg = os.urandom(40)
            assert feistel.decrypt(feistel.encrypt(msg)) == msg

    def test_msgNotEqualCtx(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        feistel = MyFeistel(key, 10)
        for i in xrange(20):
            msg = os.urandom(40)
            assert feistel.encrypt(msg) != msg

    def test_randomnessOfCtx(self):
        ctxs = []
        for i in xrange(100):
            key = base64.urlsafe_b64encode(os.urandom(16))
            feistel = MyFeistel(key, 10)
            msg = os.urandom(40)
            ctx = feistel.encrypt(msg)
            assert ctx not in ctxs
            ctxs.append(ctx)


class TestLengthPreservingCipher:
    def test_Functionality(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        lpc = LengthPreservingCipher(key, 10)

        # decrypt(encrypt(msg)) == msg
        for i in xrange(20):
            msg = os.urandom(5)
            assert lpc.decrypt(lpc.encrypt(msg)) == msg

