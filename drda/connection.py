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
    def __init__(self, host, database, port, user, password):
        self.host = host
        self.database = (database + ' ' * 18)[:18]
        self.port = port
        self.user = user
        self.password = password

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        if self.is_derby:
            secmec = cp.SECMEC_USRIDONL
            user = 'APP'
        else:
            secmec = cp.SECMEC_USRIDPWD
            user = self.user
        ddm.write_requests_dds(self.sock, [
            ddm.packEXCSAT(self),
            ddm.packACCSEC(self, self.database, secmec),
            ddm.packSECCHK(self, secmec, self.database, user, self.password),
            ddm.packACCRDB(self, self.database),
        ])
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)
            if code_point == cp.ACCSECRD:
                secmec = ddm.parse_reply(obj).get(cp.SECMEC)

    def __enter__(self):
        return self

    def __exit__(self, exc, value, traceback):
        self.close()

    def _execute(self, query):
        err = None
        ddm.write_requests_dds(self.sock, [
            ddm.packEXCSQLIMM(self, self.database),
            ddm.packSQLSTT(self, query),
            ddm.packRDBCMM(self, ),
        ])
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)
            if code_point == cp.SQLCARD:
                if err is None:
                    err, _ = ddm.parse_sqlcard(obj)
        if err:
            raise err

    def _query(self, query):
        results = collections.deque()
        err = qrydsc = None
        ddm.write_requests_dds(self.sock, [
            ddm.packPRPSQLSTT(self, self.database),
            ddm.packSQLATTR(self, 'WITH HOLD '),
            ddm.packSQLSTT(self, query),
            ddm.packOPNQRY(self, self.database),
        ])
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)
            if code_point == cp.SQLDARD:
                err, description = ddm.parse_sqldard(obj)
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

    @property
    def is_derby(self):
        return self.user is None

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
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)
        self.sock.close()
