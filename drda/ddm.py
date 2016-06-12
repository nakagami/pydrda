##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2016 Hajime Nakagami
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

from drda import codepoint as cp

def _recv_from_sock(sock, nbytes):
    n = nbytes
    recieved = b''
    while n:
        bs = sock.recv(n)
        recieved += bs

        n -= len(bs)
    return recieved

def _send_to_sock(sock, b):
    sock.send(b)


def _pack_uint(code_point, v, size):
    return code_point.to_bytes(2, byteorder='big') + v.to_bytes(size, byteorder='big')


def _pack_str(code_point, v, enc):
    return code_point.to_bytes(2, byteorder='big') + v.encode(enc)


def _pack_binary(code_point, v):
    return code_point.to_bytes(2, byteorder='big') + v


def pack_dds_object(code_point, o):
    "pack to DDS packet"
    return (len(o)+4).to_bytes(2, byteorder='big') + code_point.to_bytes(2, byteorder='big') + o


def read_dds(sock):
    "Read one DDS packet from socket"
    _recv_from_sock(sock, 6)
    ln = int.from_bytes(b[:2], byteorder='big')
    assert b[2] == 0xD0
    dss_type = b[3] & 0b1111
    chained = b[3] & 0b01000000
    number = int.from_bytes(head[4:6],  byteorder='big')
    body = _recv_from_sock(sock, 4)
    obj = recv_from_sock(read_sock, ln-6)
    assert int.from_bytes(obj[:2]) == ln
    code_point = int.from_bytes(obj[2:4], byteorder='big')

    return dds_type, chained, number, code_point, obj


def write_requests_dds(sock, obj_list):
    "Write request DDS packets"
    for i in range(len(obj_list)):
        o = obj_list[i]
        _send_to_sock(sock, (len(o)+4).to_bytes(2, byteorder='big'))
        flag = 1    # DDS request
        if i == len(obj_list) -1:
            flag |= 0b01000000
        _send_to_sock(sock, bytes([0xD0, flag]))
        _send_to_sock(sock, (i+1).to_bytes(2, byteorder='big'))
        _send_to_sock(sock, o)


def packEXCSAT():
    return pack_dds_object(cp.EXCSAT, (
        _pack_str(cp.EXTNAM, 'pydrda', 'cp500') +
        _pack_str(cp.SRVNAM, 'pydrda', 'cp500') +
        _pack_str(cp.SRVRLSLV, 'pydrda', 'cp500') +
        _pack_binary(cp.MGRLVLLS,
            # AGENT=7 SQLAM=7 RDB=7 SECMGR=7 UNICODEMGR=1208
            b'\x14\x03\x00\x07\x24\x07\x00\x07\x24\x0f\x00\x07\x14\x40\x00\x07\x1c\x08\x04\xb8') +
        _pack_str(cp.SRVCLSNM, 'pydrda', 'cp500')
        )
    )


def packACCSEC(database):
    return pack_dds_object(cp.ACCSEC,
        _pack_uint(cp.SECMEC, 4, 2) + _pack_str(cp.RDBNAM, database, 'cp500'),
    )

