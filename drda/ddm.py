##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2016-2019 Hajime Nakagami<nakagami@gmail.com>
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
import platform
import binascii
import drda
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


def parse_string(b):
    "parse VCM"
    ln = int.from_bytes(b[:2], byteorder='big')
    if ln:
        s = b[2:2+ln].decode('utf-8')
    else:
        s = ''
    b = b[2+ln:]
    return s, b


def parse_name(b):
    "parse VCM or VCS"
    s1, b = parse_string(b)
    s2, b = parse_string(b)
    ln = int.from_bytes(b[:2], byteorder='big')
    return s1 or s2, b


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


def parse_sqlcard(obj, enc, endian):
    if obj[0] == 0xff:
        return None, b''
    assert obj[0] == 0       # SQLCAGRP FLAG
    sqlcode = int.from_bytes(obj[1:5], byteorder=endian, signed=True)
    sqlstate = obj[5:10]
    sqlerrproc = obj[10:18]

    assert obj[18] == 0     # SQLCAXGRP FLAG
    sqlerrd = obj[19:25]
    sqlwarn = obj[25:36]

    rest = obj[36+18:]
    ln = int.from_bytes(rest[:2], byteorder='big')
    sqlrdbname = rest[2:2+ln].decode('utf-8')
    rest = rest[2+ln:]

    ln = int.from_bytes(rest[:2], byteorder='big')
    sqlerrmsg_m = rest[2:2+ln]
    rest = rest[2+ln:]

    ln = int.from_bytes(rest[:2], byteorder='big')
    sqlerrmsg_s = rest[2:2+ln]
    rest = rest[2+ln:]

    message = sqlerrmsg_m or sqlerrmsg_s

    assert rest[0] == 0xFF  # SQLDIAGGRP
    rest = rest[1:]

    if sqlcode < 0:
        err = drda.OperationalError(sqlcode, sqlstate, message)
    else:
        err = None

    return err, rest


def _parse_column_db2(b, endian):
    precision = int.from_bytes(b[:2], byteorder=endian)
    scale = int.from_bytes(b[2:4], byteorder=endian)
    sqllength = int.from_bytes(b[4:12], byteorder=endian)
    sqltype = int.from_bytes(b[12:14], byteorder=endian)
    sqlccsid = int.from_bytes(b[14:16], byteorder='big')

    b = b[16:]

    b = b[6:]   # ?? skip 6 bytes

    # SQLDOPTGRP
    assert b[0] == 0x00  # not null
    b = b[3:]
    sqlname, b = parse_name(b)
    sqllabel, b = parse_name(b)
    sqlcomments, b = parse_name(b)

    b = b[7:]   # ?? skip 7 bytes

    return (sqllabel, sqltype, sqllength, sqllength, precision, scale, None), b


def _parse_column_derby(b, endian):
    precision = int.from_bytes(b[:2], byteorder=endian)
    scale = int.from_bytes(b[2:4], byteorder=endian)
    sqllength = int.from_bytes(b[4:12], byteorder=endian)
    sqltype = int.from_bytes(b[12:14], byteorder=endian)
    sqlccsid = int.from_bytes(b[14:16], byteorder='big')

    b = b[16:]

    # SQLDOPTGRP
    assert b[0] == 0x00  # not null
    b = b[3:]
    sqlname, b = parse_name(b)
    sqllabel, b = parse_name(b)
    sqlcomments, b = parse_name(b)

    # SQLUDTGRP
    if b[0] == 0x00:  # not null
        b = b[5:]
        sqludtrdb, b = parse_string(b)
        sqlschema, b = parse_name(b)
        sqludtname, b = parse_name(b)
    else:
        b = b[1:]

    # SQLDXGRP
    assert b[0] == 0x00  # not null
    b = b[9:]
    sqlxrdbnam, b = parse_string(b)
    sqlxcolname, b = parse_name(b)
    sqlxbasename, b = parse_name(b)
    sqlxschema, b = parse_name(b)
    sqlxname, b = parse_name(b)

    return (sqlname, sqltype, sqllength, sqllength, precision, scale, None), b


def parse_sqldard(obj, enc, endian, db_type):
    description = []
    err, rest = parse_sqlcard(obj, enc, endian)
    if not err:
        if rest[0] == 0x00:
            rest = rest[19:]
        else:
            rest = rest[1:]
        ln = int.from_bytes(rest[0:2], byteorder=endian)
        rest = rest[2:]
        for i in range(ln):
            if db_type == 'db2':
                d, rest = _parse_column_db2(rest, endian)
            elif db_type == 'derby':
                d, rest = _parse_column_derby(rest, endian)
            description.append(d)

    return err, description


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


def write_request_dds(sock, o, cur_id, next_dds_has_same_id, last_packet):
    "Write request DDS packets"
    code_point = int.from_bytes(o[2:4], byteorder='big')
    _send_to_sock(sock, (len(o)+6).to_bytes(2, byteorder='big'))
    if code_point in (cp.SQLSTT, cp.SQLATTR):
        flag = 3    # DSS object
    else:
        flag = 1    # DSS request
    if not last_packet:
        flag |= 0b01000000
    if next_dds_has_same_id:
        next_id = cur_id
        flag |= 0b00010000
    else:
        next_id = cur_id + 1
    _send_to_sock(sock, bytes([0xD0, flag]))
    _send_to_sock(sock, cur_id.to_bytes(2, byteorder='big'))
    _send_to_sock(sock, o)
    cur_id = next_id
    return cur_id


def packEXCSAT(conn, mgrlvlls):
    b = b''
    for p in mgrlvlls:
        b += p.to_bytes(2, byteorder='big')

    return pack_dds_object(cp.EXCSAT, (
        _pack_str(cp.EXTNAM, 'pydrda', 'cp500') +
        _pack_str(cp.SRVNAM, platform.node(), 'cp500') +
        _pack_str(cp.SRVRLSLV, 'pydrda', 'cp500') +
        _pack_binary(cp.MGRLVLLS, b) +
        _pack_str(cp.SRVCLSNM, 'pydrda', 'cp500')
        )
    )


def packEXCSAT_MGRLVLLS(mgrlvlls):
    b = b''
    for p in mgrlvlls:
        b += p.to_bytes(2, byteorder='big')

    return pack_dds_object(cp.EXCSAT, (_pack_binary(cp.MGRLVLLS, b)))


def packSECCHK(secmec, database, user, password, enc):
    return pack_dds_object(cp.SECCHK, (
            _pack_uint(cp.SECMEC, secmec, 2) +
            _pack_str(cp.RDBNAM, database, enc) +
            _pack_str(cp.USRID, user, enc) +
            _pack_str(cp.PASSWORD, password, enc)
        )
    )


def packACCRDB(prdid, rdbnam, enc):
    return pack_dds_object(cp.ACCRDB, (
            _pack_str(cp.RDBNAM, rdbnam, enc) +
            _pack_uint(cp.RDBACCCL, cp.SQLAM, 2) +
            _pack_str(cp.PRDID, prdid, enc) +
            _pack_str(cp.TYPDEFNAM, 'QTDSQLASC', enc) +
            _pack_binary(
                cp.CRRTKN,
                binascii.unhexlify(b'd5c6f0f0f0f0f0f12ec3f0c1f50155630d5a11')) +
            _pack_binary(
                cp.TYPDEFOVR,
                binascii.unhexlify(b'0006119c04b80006119d04b00006119e04b8'))
        )
    )


def packACCSEC(database, secmec):
    return pack_dds_object(
        cp.ACCSEC,
        _pack_uint(cp.SECMEC, secmec, 2) +
        _pack_str(cp.RDBNAM, database, 'cp500'),
    )


def packRDBCMM():
    return pack_dds_object(cp.RDBCMM, bytes())


def _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn):
    b = ("%-18s%-18s%-18s" % (database, "NULLID", pkgid)).encode('utf-8')
    if pkgcnstkn is None:
        b += b'\x01' * 8
    else:
        b += ("%8s" % (pkgcnstkn,)).encode('utf-8')
    return _pack_binary(
        cp.PKGNAMCSN,
        b + pkgsn.to_bytes(2, byteorder='big')
    )


def packEXCSQLIMM(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dds_object(
        cp.EXCSQLIMM,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_binary(cp.RDBCMTOK, bytes([241]))
    )


def packPRPSQLSTT(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dds_object(
        cp.PRPSQLSTT,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_binary(cp.RTNSQLDA, bytes([241]))
    )


def packDSCSQLSTT(database):
    return pack_dds_object(
        cp.DSCSQLSTT,
        _packPKGNAMCSN(database) + _pack_uint(cp.QRYINSID, 0, 8)
    )


def packEXCSQLSET(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dds_object(
        cp.EXCSQLSET,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn)
    )


def packOPNQRY(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dds_object(
        cp.OPNQRY,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_uint(cp.QRYBLKSZ, 65535, 4) +
        _pack_uint(cp.MAXBLKEXT, 65535, 2) +
        _pack_binary(cp.QRYCLSIMP, bytes([0x01]))
    )


def packSQLSTT(sql):
    return pack_dds_object(
        cp.SQLSTT,
        _pack_null_string(sql, 'utf-8') + _pack_null_string(None, 'utf-8')
    )


def packSQLATTR(attr):
    return pack_dds_object(
        cp.SQLATTR,
        _pack_null_string(attr, 'utf-8') + _pack_null_string(None, 'utf-8')
    )
