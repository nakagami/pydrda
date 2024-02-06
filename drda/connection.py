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
import io
import socket
import ssl
import platform
import locale
import collections

from drda import codepoint as cp
from drda import consts
from drda import ddm
from drda import secmec9
from drda import utils
from drda.cursor import Cursor


class Connection:
    def _parse_response(self):
        results = collections.deque()
        params_description = None
        description = None
        err = qrydsc = None
        chained = True
        err_msg = None

        more_data = False
        while True:
            while chained:
                dss_type, chained, correlation_id, code_point, obj, more_data = ddm.read_dss(self.sock, self.db_type)
                while more_data:
                    # server is waiting for us to request more query data
                    # may want to check code_point here
                    ddm.write_request_dss(
                        self.sock,
                        ddm.packCNTQRY(
                            self.pkgid, self.pkgcnstkn, self.pkgsn, self.database
                        ),
                        1, False, True
                    )
                    _X_dss_type, _X_chained, _X_correlation_id, _X_xcode_point, extra_obj, more_data = ddm.read_dss(self.sock,self.db_type)
                    obj += extra_obj
                if code_point == cp.SQLERRRM:
                    err_msg = ddm.parse_reply(obj).get(cp.SRVDGN)
                elif code_point == cp.SQLCARD:
                    if err is None:
                        err, _ = ddm.parse_sqlcard(obj, self.encoding, self.endian)
                    recieve_sqlcard = True
                elif code_point == cp.SQLDARD:
                    if obj[0] == 0xFF:
                        err, params_description = ddm.parse_sqldard(
                            obj, 'utf-8', self.endian, self.db_type
                        )
                    else:
                        err, description = ddm.parse_sqldard(
                            obj, 'utf-8', self.endian, self.db_type
                        )
                elif code_point == cp.OPNQRYRM:
                    if self.db_type == 'db2':
                        more_data = True
                elif code_point == cp.ENDQRYRM:
                    more_data = False
                elif code_point == cp.QRYDSC:
                    ln = obj[0]
                    b = obj[1:ln]
                    assert b[:2] == b'\x76\xd0'
                    b = b[2:]
                    # [(DRDA_TYPE_xxxx, size_binary), ...]
                    qrydsc = [(c[0], c[1:]) for c in [b[i:i+3] for i in range(0, len(b), 3)]]
                elif code_point == cp.QRYDTA:
                    stream = io.BytesIO(obj)
                    while b := utils.read_from_stream(stream, 2):
                        if (b[0], b[1]) != (0xff, 0x00):
                            break
                        r = []
                        for t, ps in qrydsc:
                            v = utils.read_field(t, ps, stream, self.endian)
                            r.append(v)
                        results.append(tuple(r))

            if more_data:
                ddm.write_request_dss(
                    self.sock,
                    ddm.packCNTQRY(
                        self.pkgid, self.pkgcnstkn, self.pkgsn, self.database
                    ),
                    1, False, True
                )
            else:
                break

        if err:
            raise err
        return results, description, params_description

    def _parse_accsecrd(self):
        secmec = sectkn = None
        chained = True
        while chained:
            dss_type, chained, correlation_id, code_point, obj, more_data = ddm.read_dss(self.sock, self.db_type)
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

    def __init__(self, host, database, port, user, password, use_ssl, ssl_ca_certs, db_type, timeout):
        self.host = host
        self.database = (database + ' ' * 18)[:18]
        self.port = port
        self.user = user
        self.password = password
        self.db_type = db_type
        if self.db_type is None:
            if self.user is None:
                self.db_type = 'derby'
            elif self.user is not None:
                self.db_type = 'db2'

        self.secmec = consts.SECMEC_EUSRIDPWD
        if self.db_type == 'derby':
            self.encoding = 'utf-8'
            self.endian = 'big'
            self.prdid = 'DNC10130'
            self.pkgid = 'SQLC2026'
            self.pkgcnstkn = 'AAAAAfAd'
            self.pkgsn = 201
            self.user = 'APP'
            self.password = ''
            self.secmec = consts.SECMEC_USRIDONL
            self.private_key = None
        elif self.db_type == 'db2':
            self.encoding = 'cp500'
            self.endian = 'little'
            self.prdid = 'SQL11014'
            self.pkgid = 'SYSSH200'
            self.pkgcnstkn = 'SYSLVL01'
            self.pkgsn = 65
            self.user = self.user
            self.password = self.password
            self.private_key = secmec9.get_private()
        else:
            raise ValueError('Unknown database type:{}'.format(self.db_type))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout is not None:
            self.sock.settimeout(timeout)
        if use_ssl:
            self.sock = ssl.wrap_socket(self.sock, ca_certs=ssl_ca_certs)
        self.sock.connect((self.host, self.port))

        cur_id = 1
        cur_id = ddm.write_request_dss(
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

        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packACCSEC(
                self.database,
                self.secmec,
                secmec9.calc_public(self.private_key).to_bytes(32, byteorder='big')
                if self.secmec == consts.SECMEC_EUSRIDPWD else None
            ),
            cur_id, False, True
        )

        secmec, sectkn = self._parse_accsecrd()

        cur_id = 1
        if secmec != self.secmec:
            self.secmec = secmec
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packACCSEC(
                    self.database,
                    self.secmec,
                    secmec9.calc_public(self.private_key).to_bytes(32, byteorder='big')
                    if self.secmec == consts.SECMEC_EUSRIDPWD else None
                ),
                cur_id, False, False
            )

        cur_id = ddm.write_request_dss(
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
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packACCRDB(self.prdid, self.database, self.encoding),
            cur_id, False, True
        )

        self._parse_response()

        self._set_variables()

    def __enter__(self):
        return self

    def __exit__(self, exc, value, traceback):
        self.close()

    def _set_variables(self):
        lc_type = locale.getlocale()[0]
        if lc_type is None:
            lc_type = "en_US"
        cur_id = 1
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packEXCSAT_MGRLVLLS([cp.CCSIDMGR, 1208]),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packEXCSQLSET(self.pkgid, None, 1, self.database),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packSQLSTT("SET CLIENT WRKSTNNAME '{}'".format(platform.node())),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packSQLSTT("SET CURRENT LOCALE LC_CTYPE='{}'".format(lc_type)),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        self._parse_response()

    def _execute(self, query, args):
        if args:
            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packDSCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, False, True
            )
            _, _, params_description = self._parse_response()

            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packEXCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLDTA(params_description, args, self.endian),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            self._parse_response()
        else:
            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packEXCSQLIMM(
                    self.pkgid,
                    self.pkgcnstkn,
                    self.pkgsn,
                    self.database
                ),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            self._parse_response()

    def _query(self, query, args):
        if args:
            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packDSCSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, False, True
            )
            _, description, params_description = self._parse_response()

            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packOPNQRY_with_params(
                    self.pkgid, self.pkgcnstkn, self.pkgsn, self.database
                ),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLDTA(params_description, args, self.endian),
                cur_id, False, True
            )
            rows, _, _ = self._parse_response()

            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packRDBCMM(),
                cur_id, False, True
            )
            _, _, _ = self._parse_response()

            return rows, description
        else:
            cur_id = 1
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, True, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packSQLSTT(query),
                cur_id, False, False
            )
            cur_id = ddm.write_request_dss(
                self.sock,
                ddm.packOPNQRY(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
                cur_id, False, True
            )
            rows, description, params_description = self._parse_response()
            return rows, description

    def is_connect(self):
        return bool(self.sock)

    def cursor(self):
        return Cursor(self)

    def begin(self):
        self._execute("START TRANSACTION", [])

    def commit(self):
        self._execute("COMMIT", [])

    def rollback(self):
        self._execute("ROLLBACK", [])

    def close(self):
        cur_id = 1
        cur_id = ddm.write_request_dss(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        self._parse_response()
        self.sock.close()
