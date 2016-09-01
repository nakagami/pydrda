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
import binascii
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


def _pack_null_string(v, enc):
    if v is None:
        return b'\xff'
    b = v.encode(enc)
    return b'\x00' + len(b).to_bytes(4, byteorder='big') + b


def _pack_binary(code_point, v):
    b = code_point.to_bytes(2, byteorder='big') + v
    return (len(b) + 2).to_bytes(2, byteorder='big') + b


def _pack_uint(code_point, v, size):
    return _pack_binary(code_point, v.to_bytes(size, byteorder='big'))


def _pack_str(code_point, v, enc):
    return _pack_binary(code_point, v.encode(enc))


def pack_dds_object(code_point, o):
    "pack to DDS packet"
    return (len(o)+4).to_bytes(2, byteorder='big') + code_point.to_bytes(2, byteorder='big') + o


def parse_reply(obj):
    d = {}
    i = 0
    while i < len(obj):
        ln = int.from_bytes(obj[i:i+2], byteorder='big')
        d[int.from_bytes(obj[i+2:i+4], byteorder='big')] = obj[i+4:i+ln]
        i += ln

    assert i == len(obj)
    return d


def read_dds(sock):
    "Read one DDS packet from socket"
    b = _recv_from_sock(sock, 6)
    ln = int.from_bytes(b[:2], byteorder='big')
    assert b[2] == 0xD0
    dds_type = b[3] & 0b1111
    chained = b[3] & 0b01000000
    number = int.from_bytes(b[4:6],  byteorder='big')
    obj = _recv_from_sock(sock, ln-6)

    assert int.from_bytes(obj[:2], byteorder='big') == ln - 6
    code_point = int.from_bytes(obj[2:4], byteorder='big')

    return dds_type, chained, number, code_point, obj[4:]


def write_requests_dds(sock, obj_list):
    "Write request DDS packets"
    cur_id = 1
    for i in range(len(obj_list)):
        o = obj_list[i]
        code_point = int.from_bytes(o[2:4], byteorder='big')
        _send_to_sock(sock, (len(o)+6).to_bytes(2, byteorder='big'))
        if code_point in (cp.SQLSTT, cp.SQLATTR):
            flag = 3    # DSS object
        else:
            flag = 1    # DSS request
        if i < len(obj_list) -1:
            flag |= 0b01000000
        if code_point in (
            cp.EXCSQLIMM, cp.PRPSQLSTT, cp.SQLATTR,
        ):
            next_id = cur_id
            flag |= 0b00010000
        else:
            next_id = cur_id + 1
        _send_to_sock(sock, bytes([0xD0, flag]))
        _send_to_sock(sock, cur_id.to_bytes(2, byteorder='big'))
        _send_to_sock(sock, o)
        cur_id = next_id


def packEXCSAT():
    return pack_dds_object(cp.EXCSAT, (
        _pack_str(cp.EXTNAM, 'pydrda', 'cp500') +
        _pack_str(cp.SRVNAM, 'pydrda', 'cp500') +
        _pack_str(cp.SRVRLSLV, 'pydrda', 'cp500') +
        _pack_binary(cp.MGRLVLLS,
            # AGENT=7 SQLAM=7 RDB=7 SECMGR=7 UNICODEMGR=1208
            binascii.unhexlify(b'1403000724070007240f0007144000071c0804b8')) +
        _pack_str(cp.SRVCLSNM, 'pydrda', 'cp500')
        )
    )


def packSECCHK(secmec, database, user, password):
    secmec = int.from_bytes(secmec, byteorder='big')
    if secmec == cp.SECMEC_USRIDONL:
        return pack_dds_object(cp.SECCHK, (
                _pack_uint(cp.SECMEC, secmec, 2) +
                _pack_str(cp.RDBNAM, database, 'utf-8') +
                _pack_str(cp.USRID, user, 'utf-8')
            )
        )
    else:
        raise ValueError('Unknown SECMEC:%d' % secmec)


def packACCRDB(database):
    return pack_dds_object(cp.ACCRDB, (
            _pack_str(cp.RDBNAM, database, 'utf-8') +
            _pack_uint(cp.RDBACCCL, cp.SQLAM, 2) +
            _pack_str(cp.PRDID, 'DNC10130', 'utf-8') +
            _pack_str(cp.TYPDEFNAM, 'QTDSQLASC', 'utf-8') +
            _pack_binary(cp.CRRTKN,
                binascii.unhexlify(b'd5c6f0f0f0f0f0f12ec3f0c1f50155630d5a11')) +
            _pack_binary(cp.TYPDEFOVR,
                binascii.unhexlify(b'0006119c04b80006119d04b00006119e04b8'))
        )
    )


def packACCSEC(database):
    return pack_dds_object(cp.ACCSEC,
        _pack_uint(cp.SECMEC, 4, 2) + _pack_str(cp.RDBNAM, database, 'cp500'),
    )


def packRDBCMM():
    return pack_dds_object(cp.RDBCMM, bytes())
    return b

def _packPKGNAMCSN(database):
    pkgnamcsn = bytearray(binascii.a2b_hex('004421130000000000000000000000000000000000004e554c4c49442020202020202020202020205359534c48303030202020202020202020205359534c564c30310001'))
    dbnam = (database + ' ' * 18).encode('utf-8')[:18]
    pkgnamcsn[4:22] = dbnam
    return bytes(pkgnamcsn)

def packEXCSQLIMM(database):
    return pack_dds_object(cp.EXCSQLIMM,
        _packPKGNAMCSN(database) + _pack_binary(cp.RDBCMTOK, bytes([241]))
    )

def packPRPSQLSTT(database):
    return pack_dds_object(cp.PRPSQLSTT,
        _packPKGNAMCSN(database) +
        _pack_binary(cp.RTNSQLDA, bytes([241])) +
        _pack_binary(cp.TYPSQLDA, bytes([4]))
    )

def packOPNQRY(database):
    return pack_dds_object(cp.OPNQRY,
        _packPKGNAMCSN(database) +
        _pack_uint(cp.QRYBLKSZ, 32767, 4) +
        _pack_binary(cp.QRYCLSIMP, bytes([1]))
    )

def packSQLSTT(sql):
    return pack_dds_object(cp.SQLSTT,
        _pack_null_string(sql, 'utf-8') + _pack_null_string(None, 'utf-8')
    )

def packSQLATTR(attr):
    return pack_dds_object(cp.SQLATTR,
        _pack_null_string(attr, 'utf-8') + _pack_null_string(None, 'utf-8')
    )
