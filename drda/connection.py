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
import socket
import platform
import locale
import collections

from drda import codepoint as cp
from drda import ddm
from drda import utils
from drda.cursor import Cursor


class Connection:
    def _parse_response(self):
        results = collections.deque()
        description = []
        err = qrydsc = None
        chained = True
        err_msg = None
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)
            if code_point == cp.SQLERRRM:
                err_msg = ddm.parse_reply(obj).get(cp.SRVDGN).decode('utf-8')
            elif code_point == cp.SQLCARD:
                if err is None:
                    err, _ = ddm.parse_sqlcard(obj, self.encoding, self.endian)
            elif code_point == cp.SQLDARD:
                err, description = ddm.parse_sqldard(obj, 'utf-8', self.endian, self.db_type)
            elif code_point == cp.QRYDSC:
                ln = obj[0]
                b = obj[1:ln]
                assert b[:2] == b'\x76\xd0'
                b = b[2:]
                # [(DRDA_TYPE_xxxx, size_binary), ...]
                qrydsc = [(c[0], c[1:]) for c in [b[i:i+3] for i in range(0, len(b), 3)]]
            elif code_point == cp.QRYDTA:
                b = obj
                while len(b):
                    if (b[0], b[1]) != (0xff, 0x00):
                        break
                    b = b[2:]
                    r = []
                    for t, ps in qrydsc:
                        v, b = utils.read_field(t, ps, b, self.endian)
                        r.append(v)
                    results.append(tuple(r))
        if err:
            raise err
        return results, description

    def __init__(self, host, database, port, user, password, db_type):
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

        if self.db_type == 'derby':
            self.encoding = 'utf-8'
            self.endian = 'big'
            self.prdid = 'DNC10130'
            self.pkgid = 'SQLC2026'
            self.pkgcnstkn = 'AAAAAfAd'
            self.pkgsn = 201
            self.user = 'APP'
            self.password = ''
            self.secmec = cp.SECMEC_USRIDONL
        elif self.db_type == 'db2':
            self.encoding = 'cp500'
            self.endian = 'little'
            self.prdid = 'SQL11014'
            self.pkgid = 'SYSSH200'
            self.pkgcnstkn = 'SYSLVL01'
            self.pkgsn = 65
            self.user = self.user
            self.password = self.password
            self.secmec = cp.SECMEC_USRIDPWD
        else:
            raise ValueError('Unknown database type:{}'.format(self.db_type))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        cur_id = 1
        cur_id = ddm.write_request_dds(
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
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packACCSEC(self.database, self.secmec),
            cur_id, False, True
        )

        self._parse_response()

        cur_id = 1
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packSECCHK(
                self.secmec,
                self.database,
                self.user,
                self.password,
                self.encoding
            ),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packACCRDB(self.prdid, self.database, self.encoding),
            cur_id, False, True
        )

        self._parse_response()

        self._set_valiables()

    def __enter__(self):
        return self

    def __exit__(self, exc, value, traceback):
        self.close()

    def _set_valiables(self):
        cur_id = 1
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packEXCSAT_MGRLVLLS([cp.CCSIDMGR, 1208]),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packEXCSQLSET(self.pkgid, None, 1, self.database),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packSQLSTT("SET CLIENT WRKSTNNAME '{}'".format(platform.node())),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packSQLSTT("SET CURRENT LOCALE LC_CTYPE='{}'".format(locale.getlocale()[0])),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        self._parse_response()

    def _execute(self, query):
        cur_id = 1
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packEXCSQLIMM(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packSQLSTT(query),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        self._parse_response()

    def _query(self, query):
        cur_id = 1
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packPRPSQLSTT(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
            cur_id, True, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packSQLSTT(query),
            cur_id, False, False
        )
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packOPNQRY(self.pkgid, self.pkgcnstkn, self.pkgsn, self.database),
            cur_id, False, True
        )

        return self._parse_response()

    def is_connect(self):
        return bool(self.sock)

    def cursor(self):
        return Cursor(self)

    def begin(self):
        self._execute("START TRANSACTION")

    def commit(self):
        self._execute("COMMIT")

    def rollback(self):
        self._execute("ROLLBACK")

    def close(self):
        cur_id = 1
        cur_id = ddm.write_request_dds(
            self.sock,
            ddm.packRDBCMM(),
            cur_id, False, True
        )
        self._parse_response()
        self.sock.close()
