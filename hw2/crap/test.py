"""
CS-5830: Homework 2
Padding Oracle Attack

Daniel Speiser and Haiwei Su
"""
from paddingoracle import PaddingOracle, PaddingOracleServer, xor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import binascii

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]

def po_attack_2blocks(po, ctx, padding=True):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    Don't unpad the message.
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))

    #initialize padding index and byte
    pad_idx = 16
    #initialize the plain we want to get
    msg = [''] * po.block_length

    if padding:
        for i in range(len(c0)):
            # increment current c0 index by 1 (modulo 255 so we deal with overflow issues) to find where padding begins
            new_c0 = c0[:i] + chr((ord(c0[i]) + 1) % 256) + c0[i + 1:]
            # if the decrypt fails, we know we've changed a padding value. Now we know where padding begins
            if not po.decrypt(new_c0 + c1):
                pad_idx = i # store padding index
                break

    else:
        for i in range(256):
            new_c0 = c0[:-1] + chr(ord(c0[-1]) ^ i ^ 1)
            if po.decrypt(new_c0 + c1):
                previous_byte = chr(ord(c0[-2]) ^ 1)
                new_c0 = c0[:-2] + previous_byte + new_c0[-1]
                if po.decrypt(new_c0 + c1):
                    msg += chr(i)
                    pad_idx -= 1
                    break

    pad_len = len(c1) - pad_idx
    # # we now try to get the plain text msg one byte at a time
    for i in reversed(xrange(pad_idx)):
        pad_byte = len(c1) - i
        new_iv = list(c0)
        old_iv = list(c0)

        for j in xrange(i + 1, len(c0)):
            if padding:
                new_iv[j] = chr(ord(old_iv[j]) ^ pad_byte ^ pad_len) # AND HERE + 1    
                print msg
            else:
                new_iv[j] = chr(ord(old_iv[j]) ^ ord(msg[j + 1]) ^ pad_byte) # AND HERE + 1
        #since we don't know which value is the correct one, we loop through all 256 possible
        #values
        for j in xrange(256):
            new_iv[i] = chr(ord(old_iv[i]) ^ j ^ pad_byte)
            IV2 = ''.join(new_iv)
            temp = IV2+c1
            res = po.decrypt(temp)

            if res:
                msg[i+1] = chr(j) ####CHANGED HERE
                break
    print ''.join(msg)
    return ''.join(msg)
    # we now try to get the plain text msg one byte at a time
    # for j in reversed(xrange(pad_idx)):
    #     actual_pad_length = len(c1) - j
    #     new_iv = list(c0)
    #     old_iv = list(c0)

    #     for k in xrange(j + 1, len(c0)):
    #         if k >= pad_idx:
    #             new_iv[k] = chr(ord(old_iv[k]) ^ pad_byte ^ actual_pad_length)
    #         else:
    #             new_iv[k] = chr(ord(old_iv[k]) ^ ord(msg[k]) ^ actual_pad_length)

    #     #since we don't know which value is the correct one, we loop through all 256 possible
    #     #values
    #     for i in xrange(256):
    #         new_iv[j] = chr(ord(old_iv[j]) ^ i ^ actual_pad_length)
    #         IV2 = ''.join(new_iv)
    #         temp = IV2+c1
    #         res = po.decrypt(temp)

    #         if res:
    #             msg[j] = chr(i)
    #             break
    # # print ''.join(msg)
    # return ''.join(msg)

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)

    msg = [''] * nblocks * po.block_length
    for i in range(nblocks - 2):
        msg += po_attack_2blocks(po, ctx_blocks[i] + ctx_blocks[i + 1], padding=False)
    msg += po_attack_2blocks(po, ctx_blocks[-2] + ctx_blocks[-1])
    return ''.join(msg)

################################################################################
##### Tests
################################################################################

def test_po_attack_2blocks():
    for i in xrange(1, 16):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack_2blocks(po, ctx)
        assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)

def test_po_attack():
    for i in xrange(1000):
        print i
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)

def test_poserver_attack():
    # You may want to put some print statement in the code to see the
    # progress. This attack might 10.218.176.10take upto an hour to complete. 

    po = PaddingOracleServer()
    ctx = po.ciphertext()
    print ctx
    msg = po_attack(po, ctx)
    print msg

test_po_attack()



# Recovered plaintext from server-side po attack:
# {"msg": "Congrats you have cracked a secret message!", "name": "Padding Oracle"}