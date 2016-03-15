from paddingoracle import PaddingOracle, PaddingOracleServer, xor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
import binascii
import base64
import os
import itertools

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


    
    for i in range(len(c0)):
        # increment current c0 index by 1 (modulo 255 so we deal with overflow issues) to find where padding begins
        new_c0 = c0[:i] + chr((ord(c0[i]) + 1) % 256) + c0[i + 1:]
        # if the decrypt fails, we know we've changed a padding value. Now we know where padding begins
        if not po.decrypt(new_c0 + c1):
            pad_idx, pad_byte = i, len(c0) - i # store padding index and the byte represented as an int
            break

    # msg = chr(pad_byte) * pad_byte
    # # now we must loop through the remainder of ctx (after padding in reverse order) to find plaintext of each byte
    # for i in reversed(range(pad_idx + 1)):
    #     # change c0 to force padding on plaintext
    #     for j in xrange(i + 1, len(c0)):
    #         if j >= pad_idx:
    #             new_c0 = c0[:i] + chr(ord(c0[j]) ^ pad_byte ^ (len(c0) - i)) + c0[i + 1:]
    #         else:
    #             new_c0 = c0[:i] + chr(ord(c0[j]) ^ ord(msg[j]) ^ (len(c0) - i)) + c0[i + 1:]
    #     # loop through all possible byte possibilities (from 0->255)
    #     for k in range(256):
    #         # create new c0 with new byte at current index and force padding +1
    #         # new_c0 = c0[:i] + chr((ord(c0[i])) ^ j ^ pad_byte) + c0[i + 1:]
    #         new_c0 = c0[:i] + chr((ord(c0[i])) ^ k ^ pad_byte) + "".join([chr(ord(x)+1) for x in c0[i + 1:]])
    #         # if it passes, we know what the plaintext byte is
    #         # THIS RETURNS TRUE EVERY TIME AT c0[0] FOR SOME REASON
    #         if po.decrypt(new_c0 + c1):
    #             msg += chr(k) # add it to current msg
    #             # SHOULD BREAK HERE, LEAVE COMMENTED TO SEE FREQUENCY OF TRUE RETURNED FROM DECRYPT
    #             # break
    # # reverse string (since bytes were determined from the highest index to lowest)
    # return msg[::-1]


    #initialize the plain we want to get
    msg = [''] * pad_idx

    #we now try to get the plain text msg one byte at a time
    for j in reversed(range(pad_idx)):
        new_iv = list(c0)
        old_iv = list(c0)
        for k in range(j + 1, len(c0)):
            if k >= pad_idx:
                new_iv[k] = chr(ord(old_iv[k]) ^ pad_byte ^ (len(c0) - j))
            else:
                new_iv[k] = chr(ord(old_iv[k]) ^ ord(msg[k]) ^ (len(c0) - j))

        for i in xrange(256):
            new_iv[j] = chr(ord(old_iv[j]) ^ i ^ (len(c1) - j))
            IV2 = ''.join(new_iv)
            temp = IV2+c1
            if po.decrypt(temp):
                msg[j] = chr(i)
                break
    return ''.join(msg)

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext generated using po.setup()
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.
    #case1: if nblocks is 2 then we directly call the po_attack2block function
    if nblocks == 2:
        return po_attack_2blocks(po, ctx)
    #case2: if nblocks is more than 2 then we need to loop it
    else:
        msg = [''] *  ((nblocks-1)* po.block_length)
        for block_index in range(nblocks-1):
            padding_byte = 1
            c0 = ctx_blocks[block_index]
            c1 = ctx_blocks[block_index+1]
            #we now try to get the plain text msg one byte at a time
            for j in reversed(xrange(len(c1))):
                new_iv = list(c0)
                old_iv = list(c0)

                message_index = (block_index * po.block_length) + j

                for k in xrange(j + 1, len(c0)):
                    new_message_index =  (block_index * po.block_length) + k
                    #reset the previous byte in c1
                    new_iv[k] = chr(ord(old_iv[k]) ^ ord(msg[k]) ^ padding_byte)

                #since we don't know which value is the correct one, we loop through all 256 possible
                #values
                for i in xrange(256):
                    new_iv[j] = chr(ord(old_iv[j]) ^ i ^ padding_byte)

                    IV2 = ''.join(new_iv)

                    temp = IV2 + c1
                    res = po.decrypt(temp)

                    if res:
                        msg[j] = chr(i)
                        break
                padding_byte += 1
            print block_index
            temp = ''.join(msg)
            print temp
            print "haha1"
        #when reading to the last two blocks, directly call po_attack2block
            if block_index == nblocks-2:
                c0 = ctx[block_index]
                c1 = ctx[block_index+1]
                # print type(ctx[block_index:])
                # print type(c0+c1)
                msg = po_attack_2blocks(po, ctx[block_index:])

        return temp

    
################################################################################
##### Tests
################################################################################

def test_po_attack_2blocks():
    for i in xrange(1, 16):
        po = PaddingOracle(msg_len=i)
        print "Input message: {0}".format(binascii.b2a_hex(po._msg))
        ctx = po.setup()
        print "CTX: {0}".format(binascii.b2a_hex(ctx))
        msg = po_attack_2blocks(po, ctx)
        print "MSG: {0}".format(binascii.b2a_hex(msg))
        assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)

def test_po_attack():
    for i in xrange(1000):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)

def test_poserver_attack():
    # You may want to put some print statement in the code to see the
    # progress. This attack might 10.218.176.10take upto an hour to complete. 

    po = PaddingOracleServer()
    ctx = po.ciphertext()
    msg = po_attack(po, ctx)
    print msg

test_po_attack()
