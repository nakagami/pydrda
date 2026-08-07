##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2016-2026 Hajime Nakagami<nakagami@gmail.com>
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
import io
import binascii
import platform
import locale
import collections

from drda import codepoint as cp
from drda import consts
from drda import ddm
from drda import secmec9
from drda import utils
from drda.connection import Connection, _replace_binary_params
from drda.aio.cursor import AsyncCursor
from drda.aio.stream import AsyncSocketStream


async def _read_dss(stream):
    "Read one DSS packet from async stream"
    b = await stream.recv(6)

    if len(b) != 6 or b[2] != 0xD0:
        raise ConnectionError(f"invalid DSS packet from socket:{binascii.hexlify(b).decode('utf-8')}")

    dss_ln = int.from_bytes(b[:2], byteorder='big')
    dss_type = b[3] & 0b1111
    chained = b[3] & 0b01000000
    correlation_id = int.from_bytes(b[4:6],  byteorder='big')
    obj_ln = int.from_bytes(await stream.recv(2), byteorder='big')
    code_point = int.from_bytes(await stream.recv(2), byteorder='big')
    more_data = False

    if dss_ln == 0xFFFF:
        assert code_point == 0x241B     # QRYDTA
        assert obj_ln == 32772      # 0x8004 protocol magic
        obj = await stream.recv(32757)   # 0x7fff - 6 - 4
        # !! assumes there is only 1 additional "page".. not sure what controls this
        # !! worried it depends on QRYBLKSZ (which is 65535 below)
        next_ln = int.from_bytes(await stream.recv(2), byteorder='big')
        extra = await stream.recv(next_ln-2)
        obj += extra
        if next_ln == 0x7ffe:
            more_data = True
    else:
        obj = await stream.recv(obj_ln - 4)
        if (len(obj) != dss_ln - 10) or (obj_ln != dss_ln - 6):
            raise ConnectionError("invalid DSS packet from socket")
        assert len(obj) == (obj_ln - 4)

    return dss_type, chained, correlation_id, code_point, obj, more_data


async def _write_request_dss(stream, o, cur_id, next_dss_has_same_id, last_packet):
    "Write request DSS packets to async stream"
    code_point = int.from_bytes(o[2:4], byteorder='big')
    if code_point in (cp.SQLSTT, cp.SQLATTR, cp.SQLDTA, cp.EXTDTA):
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
    b = (len(o)+6).to_bytes(2, byteorder='big')
    b += bytes([0xD0, flag])
    b += cur_id.to_bytes(2, byteorder='big')
    b += o
    await stream.send(b)
    return next_id


class AsyncConnection(Connection):
    async def _parse_response(self, continue_on_sqldard_only=False):
        results = collections.deque()
        params_description = None
        description = None
        err = qrydsc = None
        chained = True
        err_msg = None

        more_data = False
        need_cntqry = False  # set by OPNQRYRM; survives subsequent read_dss calls
        qryinsid = 0         # query instance ID from OPNQRYRM, needed for CNTQRY on LOB queries
        cntqry_cur_id = 1    # correlation ID to use for CNTQRY (matches the OPNQRY request)
        extdta_list = []     # accumulate EXTDTA objects for LOB columns
        while True:
            while chained:
                dss_type, chained, correlation_id, code_point, obj, more_data = await _read_dss(self.sock)
                _X_chained = False
                while more_data:
                    # server is waiting for us to request more query data
                    # may want to check code_point here
                    await _write_request_dss(
                        self.sock,
                        ddm.packCNTQRY(
                            self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz,
                        ),
                        1, False, True
                    )
                    _X_dss_type, _X_chained, _X_correlation_id, _X_xcode_point, extra_obj, more_data = await _read_dss(self.sock)
                    obj += extra_obj
                # Drain any chained packets (e.g. ENDQRYRM, SQLCARD) after the last page
                while _X_chained:
                    _X_dss_type, _X_chained, _X_correlation_id, _X_code_point, _drain_obj, _ = await _read_dss(self.sock)
                    if _X_code_point == cp.ENDQRYRM:
                        need_cntqry = False
                    elif _X_code_point == cp.SQLCARD:
                        if err is None:
                            err, _ = ddm.parse_sqlcard(_drain_obj, self.encoding, self.endian)
                if code_point == cp.SQLERRRM:
                    err_msg = ddm.parse_reply(obj).get(cp.SRVDGN)
                elif code_point == cp.SQLCARD:
                    if err is None:
                        err, _ = ddm.parse_sqlcard(obj, self.encoding, self.endian)
                elif code_point == cp.SQLDARD:
                    if obj[0] == 0xFF:
                        err, params_description = ddm.parse_sqldard(
                            obj, 'utf-8', self.endian
                        )
                    elif description is None:
                        # First SQLDARD (obj[0]=0x00): result column descriptions
                        err, description = ddm.parse_sqldard(
                            obj, 'utf-8', self.endian
                        )
                elif code_point == cp.OPNQRYRM:
                    cntqry_cur_id = correlation_id  # must match the OPNQRY request's ID
                    qryinsid_bytes = ddm.parse_reply(obj).get(cp.QRYINSID, bytes(8))
                    qryinsid = int.from_bytes(qryinsid_bytes, 'big')
                    # Db2 always requires CNTQRY after OPNQRYRM.
                    need_cntqry = True
                elif code_point in (cp.ENDQRYRM, cp.ENDUOWRM):
                    more_data = False
                    need_cntqry = False
                elif code_point == cp.EXTDTA:
                    extdta_list.append(obj)
                elif code_point == cp.QRYDSC:
                    ln = obj[0]
                    b = obj[1:ln]
                    assert b[:2] == b'\x76\xd0'
                    b = b[2:]
                    # [(DRDA_TYPE_xxxx, size_binary), ...]
                    qrydsc = [(c[0], c[1:]) for c in [b[i:i+3] for i in range(0, len(b), 3)]]
                elif code_point == cp.QRYDTA:
                    stream = io.BytesIO(obj)
                    try:
                        while b := utils.read_from_stream(stream, 2):
                            if b[0] != 0xff:
                                break
                            r = []
                            for t, ps in qrydsc:
                                v = utils.read_field(t, ps, stream, self.endian)
                                r.append(v)
                            results.append(tuple(r))
                    except Exception:
                        pass

            if need_cntqry:
                cntqry_pkt = ddm.packCNTQRY(
                    self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz,
                    qryinsid=qryinsid,
                )
                await _write_request_dss(self.sock, cntqry_pkt, cntqry_cur_id, False, True)
                chained = True  # must read the CNTQRY response
            elif continue_on_sqldard_only and description is not None and qrydsc is None:
                # The server sent SQLDARD(s) in chain 1 as the prepare response,
                # and is already sending chain 2 (OPNQRYRM+QRYDSC) for the OPNQRY we
                # included in the same request.  Keep reading without sending anything.
                chained = True
            else:
                break

        if extdta_list and qrydsc and results:
            _inline_lob_types = (
                utils.DRDA_TYPE_LOBBYTES, utils.DRDA_TYPE_NLOBBYTES,
                utils.DRDA_TYPE_LOBCSBCS, utils.DRDA_TYPE_NLOBCSBCS,
            )
            _lob_types = (
                utils.DRDA_TYPE_LOBLOC, utils.DRDA_TYPE_NLOBLOC,
                utils.DRDA_TYPE_CLOBLOC, utils.DRDA_TYPE_NCLOBLOC,
                utils.DRDA_TYPE_DBCSCLOBLOC, utils.DRDA_TYPE_NDBCSCLOBLOC,
            ) + _inline_lob_types
            _clob_types = (
                utils.DRDA_TYPE_CLOBLOC, utils.DRDA_TYPE_NCLOBLOC,
                utils.DRDA_TYPE_DBCSCLOBLOC, utils.DRDA_TYPE_NDBCSCLOBLOC,
                utils.DRDA_TYPE_LOBCSBCS, utils.DRDA_TYPE_NLOBCSBCS,
            )
            lob_col_indices = [i for i, (t, _) in enumerate(qrydsc) if t in _lob_types]
            extdta_idx = 0
            for row_idx in range(len(results)):
                row = list(results[row_idx])
                for col_idx in lob_col_indices:
                    if row[col_idx] is not None and extdta_idx < len(extdta_list):
                        data = extdta_list[extdta_idx]
                        if qrydsc[col_idx][0] in _inline_lob_types:
                            # EXTDTA for inline LOBs has a leading status byte (0x00 = valid)
                            data = data[1:]
                        if qrydsc[col_idx][0] in _clob_types:
                            if qrydsc[col_idx][0] in _inline_lob_types:
                                data = data.decode('utf-8')
                            else:
                                data = data.decode(self.encoding)
                        row[col_idx] = data
                        extdta_idx += 1
                results[row_idx] = tuple(row)

        if err:
            raise err
        return results, description, params_description

    async def _parse_accsecrd(self):
        secmec = sectkn = None
        chained = True
        while chained:
            dss_type, chained, correlation_id, code_point, obj, more_data = await _read_dss(self.sock)
            if code_point == cp.ACCSECRD:
                while len(obj):
                    ln = int.from_bytes(obj[:2], byteorder='big')
                    sub_cp = int.from_bytes(obj[2:4], byteorder='big')
                    v = obj[4:ln]
                    obj = obj[ln:]
                    if sub_cp == cp.SECMEC:
                        secmec = int.from_bytes(v[:2], byteorder='big')
                    elif sub_cp == cp.SECTKN:
                        sectkn = v
            elif code_point == cp.RDBNFNRM:
                from drda import DatabaseError
                raise DatabaseError(0, 0, "database not found")

        return secmec, sectkn

    def __init__(self, host, database, port, user, password, use_ssl, ssl_client_cert_path, timeout):
        self.host = host
        self.database = (database + ' ' * 18)[:18]
        self.port = port
        self.user = user
        self.password = password

        self.use_ssl = use_ssl
        self.ssl_client_cert_path = ssl_client_cert_path
        self.timeout = timeout

        self.secmec = consts.SECMEC_EUSRIDPWD
        self.encoding = 'cp500'
        self.endian = 'little'
        self.prdid = 'SQL12010'
        self.pkgid = 'SYSSH200'
        self.pkgcnstkn = 'SYSLVL01'
        self.pkgsn = 65
        self.qryblksz = 65535
        self.private_key = secmec9.get_private()

        self.sock = None

    async def _initialize(self):
        self.sock = AsyncSocketStream(
            self.host, self.port,
            timeout=self.timeout,
            use_ssl=self.use_ssl,
            ssl_client_cert_path=self.ssl_client_cert_path,
        )
        await self.sock.connect()

        cur_id = 1
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packEXCSAT(self, [
                cp.AGENT, 10,
                cp.SQLAM, 11,
                cp.CMNTCPIP, 5,
                cp.RDB, 12,
                cp.SECMGR, 9,
                cp.UNICODEMGR, 1208,
            ]),
            cur_id, False, False
        )

        cur_id = await _write_request_dss(
            self.sock,
            ddm.packACCSEC(
                self.database,
                self.secmec,
                secmec9.calc_public(self.private_key).to_bytes(32, byteorder='big')
                if self.secmec == consts.SECMEC_EUSRIDPWD else None
            ),
            cur_id, False, True
        )

        secmec, sectkn = await self._parse_accsecrd()

        cur_id = 1
        if secmec != self.secmec:
            self.secmec = secmec
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packACCSEC(
                    self.database,
                    self.secmec,
                    secmec9.calc_public(self.private_key).to_bytes(32, byteorder='big')
                    if self.secmec == consts.SECMEC_EUSRIDPWD else None
                ),
                cur_id, False, False
            )

        cur_id = await _write_request_dss(
            self.sock,
            ddm.packSECCHK(
                secmec,
                sectkn,
                self.private_key,
                self.database,
                self.user,
                self.password,
                self.encoding
            ),
            cur_id, False, False
        )
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packACCRDB(self.prdid, self.database, self.encoding),
            cur_id, False, True
        )

        await self._parse_response()

        await self._set_variables()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc, value, traceback):
        await self.close()

    async def _set_variables(self):
        lc_type = locale.getlocale()[0]
        if lc_type is None:
            lc_type = "en_US"
        cur_id = 1
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packEXCSAT_MGRLVLLS([cp.CCSIDMGR, 1208]),
            cur_id, False, False
        )
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packEXCSQLSET(self.pkgid, None, 1, self.database),
            cur_id, True, False
        )
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packSQLSTT("SET CLIENT WRKSTNNAME '{}'".format(platform.node())),
            cur_id, True, False
        )
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packSQLSTT("SET CURRENT LOCALE LC_CTYPE='{}'".format(lc_type)),
            cur_id, False, False
        )
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        await self._parse_response()

    async def _execute(self, query, args):
        if args:
            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packDSCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, False, True
            )
            _, _, params_description = await self._parse_response()

            replaced = _replace_binary_params(query, args, params_description)
            if replaced:
                return await self._execute(*replaced)

            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packEXCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packSQLDTA(params_description, args, self.endian),
                cur_id, False, False
            )

            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            await self._parse_response()
        else:
            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packEXCSQLIMM(
                    self.pkgid,
                    self.pkgcnstkn,
                    self.pkgsn,
                    self.database
                ),
                cur_id, True, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            await self._parse_response()

    async def _query(self, query, args):
        if args:
            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packDSCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, False, True
            )
            _, description, params_description = await self._parse_response()

            replaced = _replace_binary_params(query, args, params_description)
            if replaced:
                return await self._query(*replaced)

            sqldta = ddm.packSQLDTA(params_description, args, self.endian)

            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packOPNQRY_with_params(
                    self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz,
                ),
                cur_id, True, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                sqldta,
                cur_id, False, True
            )
            rows, _, _ = await self._parse_response()

            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            _, _, _ = await self._parse_response()

            return rows, description
        else:
            # Send all three together so Db2 includes EXTDTA (LOB data) in the
            # same response chain.  Sending OPNQRY separately causes Db2 to omit
            # EXTDTA, resulting in empty BLOB/CLOB/XML values.
            # continue_on_sqldard_only=True handles the rare case where Db2 sends
            # SQLDARD(s) in a separate chain before OPNQRYRM+QRYDSC.
            cur_id = 1
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = await _write_request_dss(
                self.sock,
                ddm.packOPNQRY(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database, self.qryblksz),
                cur_id, False, True
            )
            rows, description, _ = await self._parse_response(continue_on_sqldard_only=True)
            return rows, description

    def is_connect(self):
        return bool(self.sock)

    def cursor(self):
        return AsyncCursor(self)

    async def begin(self):
        await self._execute("START TRANSACTION", [])

    async def commit(self):
        await self._execute("COMMIT", [])

    async def rollback(self):
        await self._execute("ROLLBACK", [])

    async def close(self):
        cur_id = 1
        cur_id = await _write_request_dss(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        await self._parse_response()
        await self.sock.close()
