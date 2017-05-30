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
import socket
import binascii
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
                    err, _ = ddm.parse_sqlcard(obj, self.db_type, err_msg, self._enc)
            elif code_point == cp.SQLDARD:
                err, description = ddm.parse_sqldard(obj, self.db_type, err_msg, 'utf-8')
            elif code_point == cp.QRYDSC:
                ln = obj[0]
                b = obj[1:ln]
                assert b[:2] == b'\x76\xd0'
                b = b[2:]
                # [(DRDA_TYPE_xxxx, size_binary), ...]
                qrydsc = [(c[0], c[1:]) for c in [b[i:i+3] for i in range(0, len(b), 3)]]
            elif code_point == cp.QRYDTA:
                b = obj
                while True:
                    if (b[0], b[1]) != (0xff, 0x00):
                        break
                    b = b[2:]
                    r = []
                    for t, ps in qrydsc:
                        v, b = utils.read_field(t, ps, b)
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
            self._enc = 'utf-8'
            user = 'APP'
            password = ''
            secmec = cp.SECMEC_USRIDONL
        elif self.db_type == 'db2':
            self._enc = 'cp500'
            user = self.user
            password = self.password
            secmec = cp.SECMEC_USRIDPWD
        else:
            raise ValueError('Unknown database type')
            

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        ddm.write_requests_dds(self.sock, [
            ddm.packEXCSAT(self, [
                cp.AGENT, 10,
                cp.SQLAM, 11,
                cp.CMNTCPIP, 5,
                cp.RDB, 12,
                cp.SECMGR, 9,
                cp.UNICODEMGR, 1208,
            ]),
            ddm.packACCSEC(self, self.database, secmec),
        ])
        self._parse_response()

        ddm.write_requests_dds(self.sock, [
            ddm.packSECCHK(self, secmec, self.database, user, password, self._enc),
            ddm.packACCRDB(self, self.database, self._enc),
        ])
        self._parse_response()

    def __enter__(self):
        return self

    def __exit__(self, exc, value, traceback):
        self.close()

    def _execute(self, query):
        ddm.write_requests_dds(self.sock, [
            ddm.packEXCSQLIMM(self, self.database),
            ddm.packSQLSTT(self, query),
            ddm.packRDBCMM(self, ),
        ])
        self._parse_response()

    def _query(self, query):
        if self.db_type == 'derby':
            ddm.write_requests_dds(self.sock, [
                ddm.packPRPSQLSTT(self, self.database),
    #            ddm.packSQLATTR(self, 'WITH HOLD '),
                ddm.packSQLSTT(self, query),
                ddm.packOPNQRY(self, self.database),
            ])
        elif self.db_type == 'db2':
            ddm.write_requests_dds(self.sock, [
                ddm.packEXCSAT_MGRLVLLS(self, [cp.CCSIDMGR, 1208]),
                ddm.packEXCSQLSET(self, self.database),
                ddm.packSQLSTT(self, query),
            ])
            self._parse_response()

            ddm.write_requests_dds(self.sock, [
                ddm.packOPNQRY(self, self.database),
            ])
        else:
            raise ValueError('Unknown database type')

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
        ddm.write_requests_dds(self.sock, [ddm.packRDBCMM(self)])
        self._parse_response()
        self.sock.close()
