##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2016-2024 Hajime Nakagami<nakagami@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
##############################################################################
# https://wiki.apache.org/db-derby/SecurityMechanism

import random

# DH Key exchange
# https://en.wikipedia.org/wiki/Diffie-Hellman_key_exchange

# p
prime = 0xC62112D73EE613F0947AB31F0F6846A1BFF5B3A4CA0D60BC1E4C7A0D8C16B3E3
# g
base = 0x4690FA1F7B9E1D4442C86C9114603FDECF071EDCEC5F626E21E256AED9EA34E4


def get_private():
    return random.randrange(2, prime)


def calc_public(private):
    return pow(base, private, prime)


def calc_session_key(public, private):
    return pow(public, private, prime).to_bytes(32, byteorder='big')


# DES/CBC/PKCS5Padding encryption
def des(server_sectkn, client_private):
    import pyDes
    assert len(server_sectkn) == 32
    # calculate session key from server_sectkn and client_private
    # get des key (8bytes) from session key

    server_public = int.from_bytes(server_sectkn, byteorder='big')
    session_key = calc_session_key(server_public, client_private)

    iv = server_sectkn[12:20]
    key = session_key[12:20]
    return pyDes.des(key, pyDes.CBC, iv, None, pyDes.PAD_PKCS5)
