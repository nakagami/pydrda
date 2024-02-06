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
import platform
import binascii
import struct
import drda
from drda import codepoint as cp
from drda import consts
from drda import secmec9


def _recv_from_sock(sock, nbytes, max_attempts=16):
    n = nbytes
    attempts = 0
    received = bytearray() # mutable
    while n > 0 and attempts < max_attempts:
        bs = sock.recv(n)
        if len(bs) > 0:
            received += bs
            n -= len(bs)
            attempts = 0
        else:
            attempts += 1
    return received


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
    # int.from_bytes(b[:2], byteorder='big')
    return s1 or s2, b


def pack_dss_object(code_point, o):
    "pack to DSS packet"
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
        return None, obj[1:]

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


def _parse_column_db2(b, endian, has_name):
    precision = int.from_bytes(b[:2], byteorder=endian)
    scale = int.from_bytes(b[2:4], byteorder=endian)
    sqllength = int.from_bytes(b[4:12], byteorder=endian)
    sqltype = int.from_bytes(b[12:14], byteorder=endian)
    sqlccsid = int.from_bytes(b[14:16], byteorder='big')

    b = b[16:]
    if has_name:
        b = b[6:]   # ?? skip 6 bytes
        # SQLDOPTGRP
        assert b[0] == 0x00  # not null
        b = b[3:]
        sqlname, b = parse_name(b)
        sqllabel, b = parse_name(b)
        sqlcomments, b = parse_name(b)
        b = b[7:]   # ?? skip 7 bytes
    else:
        sqllabel = None
        b = b[29:]

    return (sqllabel, sqltype, sqllength, sqllength, precision, scale, None), b


def _parse_column_derby(b, endian, has_name):
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
    has_name = obj[0] == 0x00
    err, rest = parse_sqlcard(obj, enc, endian)
    if not err:
        if rest[0] == 0x00:
            rest = rest[13:]
            sqlrdbnam, rest = parse_string(rest)
            sqlschema, rest = parse_name(rest)
        else:
            rest = rest[1:]
        ln = int.from_bytes(rest[0:2], byteorder=endian)
        rest = rest[2:]
        for i in range(ln):
            if db_type == 'db2':
                d, rest = _parse_column_db2(rest, endian, has_name)
            elif db_type == 'derby':
                d, rest = _parse_column_derby(rest, endian, has_name)
            description.append(d)

    return err, description


def read_dss(sock, db_type):
    "Read one DSS packet from socket"
    b = _recv_from_sock(sock, 6)

    if len(b) != 6 or b[2] != 0xD0:
        raise ConnectionError(f"invalid DSS packet from socket:{binascii.hexlify(b).decode('utf-8')}")

    dss_ln = int.from_bytes(b[:2], byteorder='big')
    dss_type = b[3] & 0b1111
    chained = b[3] & 0b01000000
    correlation_id = int.from_bytes(b[4:6],  byteorder='big')
    obj_ln = int.from_bytes(_recv_from_sock(sock, 2), byteorder='big')
    code_point = int.from_bytes(_recv_from_sock(sock, 2), byteorder='big')
    more_data = False

    if dss_ln == 0xFFFF:
        assert code_point == 0x241B     # QRYDTA
        if db_type == 'db2':
            assert obj_ln == 32772      # 0x8004 protocol magic
            obj = _recv_from_sock(sock, 32757)   # 0x7fff - 6 - 4
            # !! assumes there is only 1 additional "page".. not sure what controls this
            # !! worried it depends on QRYBLKSZ (which is 65535 below)
            next_ln = int.from_bytes(_recv_from_sock(sock, 2), byteorder='big')
            extra = _recv_from_sock(sock, next_ln-2)
            obj += extra
            if next_ln == 0x7ffe:
                more_data = True
        elif db_type == 'derby':
            assert obj_ln == 32776      # ???
            ln = int.from_bytes(_recv_from_sock(sock, 4), byteorder='big')
            assert ln == 61515      # ???
            obj = _recv_from_sock(sock, 32753)   # ???
            next_ln = int.from_bytes(_recv_from_sock(sock, 2), byteorder='big')
            extra = _recv_from_sock(sock, next_ln - 2)
            obj += extra
    else:
        obj = _recv_from_sock(sock, obj_ln - 4)
        if (len(obj) != dss_ln - 10) or (obj_ln != dss_ln - 6):
            raise ConnectionError("invalid DSS packet from socket")
        assert len(obj) == (obj_ln - 4)

    return dss_type, chained, correlation_id, code_point, obj, more_data


def write_request_dss(sock, o, cur_id, next_dss_has_same_id, last_packet):
    "Write request DSS packets"
    code_point = int.from_bytes(o[2:4], byteorder='big')
    _send_to_sock(sock, (len(o)+6).to_bytes(2, byteorder='big'))
    if code_point in (cp.SQLSTT, cp.SQLATTR, cp.SQLDTA):
        flag = 3    # DSS object
    else:
        flag = 1    # DSS request
    if not last_packet:
        flag |= 0b01000000
    if next_dss_has_same_id:
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

    return pack_dss_object(cp.EXCSAT, (
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

    return pack_dss_object(cp.EXCSAT, (_pack_binary(cp.MGRLVLLS, b)))


def packSECCHK(secmec, sectkn, private_key, database, user, password, enc):
    if secmec == consts.SECMEC_EUSRIDPWD:
        des = secmec9.des(sectkn, private_key)
        return pack_dss_object(cp.SECCHK, (
                _pack_uint(cp.SECMEC, secmec, 2) +
                _pack_str(cp.RDBNAM, database, enc) +
                _pack_binary(cp.SECTKN, des.encrypt(user.encode(enc))) +
                _pack_binary(cp.SECTKN, des.encrypt(password.encode(enc)))
            )
        )
    else:
        return pack_dss_object(cp.SECCHK, (
                _pack_uint(cp.SECMEC, secmec, 2) +
                _pack_str(cp.RDBNAM, database, enc) +
                _pack_str(cp.USRID, user, enc) +
                _pack_str(cp.PASSWORD, password, enc)
            )
        )


def packACCRDB(prdid, rdbnam, enc):
    return pack_dss_object(cp.ACCRDB, (
            _pack_str(cp.RDBNAM, rdbnam, enc) +
            _pack_uint(cp.RDBACCCL, cp.SQLAM, 2) +
            _pack_str(cp.PRDID, prdid, enc) +
            _pack_str(cp.TYPDEFNAM, 'QTDSQLX86', enc) +
            _pack_binary(
                cp.CRRTKN,
                binascii.unhexlify(b'd5c6f0f0f0f0f0f12ec3f0c1f50155630d5a11')) +
            _pack_binary(
                cp.TYPDEFOVR,
                binascii.unhexlify(b'0006119c04b80006119d04b00006119e04b8'))
        )
    )


def packACCSEC(database, secmec, sectkn):
    body = _pack_uint(cp.SECMEC, secmec, 2) + _pack_str(cp.RDBNAM, database, 'cp500')
    if sectkn:
        body += _pack_binary(cp.SECTKN, sectkn)
    return pack_dss_object(cp.ACCSEC, body)


def packRDBCMM():
    return pack_dss_object(cp.RDBCMM, bytes())


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


def packEXCSQLSTT(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.EXCSQLSTT,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_binary(cp.RDBCMTOK, bytes([241]))
    )


def packEXCSQLIMM(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.EXCSQLIMM,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_binary(cp.RDBCMTOK, bytes([241]))
    )


def packPRPSQLSTT(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.PRPSQLSTT,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_binary(cp.RTNSQLDA, bytes([241]))
    )


def packDSCSQLSTT(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.DSCSQLSTT,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) + _pack_binary(cp.TYPSQLDA, bytes([1]))
    )


def packEXCSQLSET(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.EXCSQLSET,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn)
    )


def _fdodsc(description):
    _, sqltype, sqllength, _, precision, scale, _ = description
    if sqltype == consts.DB2_SQLTYPE_NVARCHAR:
        return binascii.unhexlify(b'393fff')
    elif sqltype == consts.DB2_SQLTYPE_NDECIMAL:
        return bytes([0x0f, precision, scale])
    elif sqltype == consts.DB2_SQLTYPE_NSMALL:
        return bytes([0x05, 0x00, sqllength])
    elif sqltype == consts.DB2_SQLTYPE_NINTEGER:
        return bytes([0x03, 0x00, sqllength])
    elif sqltype == consts.DB2_SQLTYPE_NBIGINT:
        return bytes([0x17, 0x00, sqllength])
    elif sqltype == consts.DB2_SQLTYPE_NFLOAT:
        return bytes([0x0d if sqllength == 4 else 0x0b, 0x00, sqllength])
    elif sqltype == consts.DB2_SQLTYPE_NDATE:
        return binascii.unhexlify(b'21000a')
    elif sqltype == consts.DB2_SQLTYPE_NTIME:
        return binascii.unhexlify(b'230008')
    elif sqltype == consts.DB2_SQLTYPE_NTIMESTAMP:
        return binascii.unhexlify(b'250020')
    else:
        raise ValueError("_fdodsc():Unknown type {}".format(sqltype))


def _fdodta(description, v):
    _, sqltype, sqllength, _, precision, scale, _ = description
    if sqltype == consts.DB2_SQLTYPE_NVARCHAR:
        v = str(v)
        return b'\x00' + len(v).to_bytes(2, byteorder='big') + v.encode('utf_16_be')
    elif sqltype == consts.DB2_SQLTYPE_NDECIMAL:
        sign, digits, exponent = v.as_tuple()
        d = bytes([ord(b'0') + n for n in digits])
        d = (b'0' * (precision + scale) + d)[-(precision + scale):]
        d += b"d" if sign else b"c"
        if len(d) % 2:
            v = b'0' + v
        v = binascii.unhexlify(d)
        if v[0] != 0:
            v = b'\x00' + v
        return v
    elif sqltype == consts.DB2_SQLTYPE_NSMALL:
        v = int(v)
        return b'\x00' + v.to_bytes(2, byteorder='little', signed=True)
    elif sqltype == consts.DB2_SQLTYPE_NINTEGER:
        v = int(v)
        return b'\x00' + v.to_bytes(4, byteorder='little', signed=True)
    elif sqltype == consts.DB2_SQLTYPE_NBIGINT:
        v = int(v)
        return b'\x00' + v.to_bytes(8, byteorder='little', signed=True)
    elif sqltype == consts.DB2_SQLTYPE_NFLOAT:
        v = float(v)
        if sqllength == 4:
            v = struct.pack("<f", v)
        elif sqllength == 8:
            v = struct.pack("<d", v)
        else:
            raise ValueError("Can't convert to FDODTA", v)
        return b'\x00' + v
    elif sqltype == consts.DB2_SQLTYPE_NDATE:
        v = v.strftime("%Y-%m-%d").encode('utf-8')
        return b'\x00' + v
    elif sqltype == consts.DB2_SQLTYPE_NTIME:
        v = v.strftime("%H:%M:%S").encode('utf-8')
        return b'\x00' + v
    elif sqltype == consts.DB2_SQLTYPE_NTIMESTAMP:
        v = v.strftime("%Y-%m-%d-%H.%M.%S.%f      ").encode('utf-8')
        return b'\x00' + v
    else:
        raise ValueError("_fdodta():Unknown type {}".format(sqltype))


def packSQLDTA(params_desc, params, endian):
    ln = len(params)
    assert ln == len(params_desc)

    fdodsc = bytes([(1 + ln) * 3]) + binascii.unhexlify(b'76d0')
    fdodta = b''

    for i in range(ln):
        fdodsc += _fdodsc(params_desc[i])
        fdodta += _fdodta(params_desc[i], params[i])

    if (len(fdodsc) + len(fdodta)) % 2:
        fdodta = b'\x00' + fdodta

    fdodsc += binascii.unhexlify(b'0671e4d00001')

    return pack_dss_object(
        cp.SQLDTA,
        pack_dss_object(cp.FDODSC, fdodsc) +
        pack_dss_object(cp.FDODTA, fdodta)
    )


def packOPNQRY_with_params(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.OPNQRY,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_uint(cp.QRYBLKSZ, 65535, 4) +
        _pack_uint(cp.MAXBLKEXT, 65535, 2) +
        _pack_binary(cp.QRYCLSIMP, bytes([0x01])) +
        _pack_binary(cp.DYNDTAFMT, bytes([0xf1]))
    )


def packOPNQRY(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.OPNQRY,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_uint(cp.QRYBLKSZ, 65535, 4) +
        _pack_uint(cp.MAXBLKEXT, 65535, 2) +
        _pack_binary(cp.QRYCLSIMP, bytes([0x01]))
    )


def packCNTQRY(pkgid, pkgcnstkn, pkgsn, database):
    return pack_dss_object(
        cp.CNTQRY,
        _packPKGNAMCSN(database, pkgid, pkgcnstkn, pkgsn) +
        _pack_uint(cp.QRYBLKSZ, 65535, 4) +
        _pack_uint(cp.QRYINSID, 0, 8) +
        _pack_binary(cp.RTNEXTDTA, bytes([0x02])) +
        _pack_binary(cp.FREPRVREF, bytes([0xf0]))
    )


def packSQLSTT(sql):
    return pack_dss_object(
        cp.SQLSTT,
        _pack_null_string(sql, 'utf-8') + _pack_null_string(None, 'utf-8')
    )


def packSQLATTR(attr):
    return pack_dss_object(
        cp.SQLATTR,
        _pack_null_string(attr, 'utf-8') + _pack_null_string(None, 'utf-8')
    )
