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
from drda import codepoint as cp
from drda import ddm
from drda.cursor import Cursor


class Connection:
    def __init__(self, host, database, port, user, password):
        self.host = host
        self.database = database
        self.port = port
        self.user = user
        self.password = password

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        ddm.write_requests_dds(self.sock, [
            ddm.packEXCSAT(),
            ddm.packACCSEC(self.database)
        ])
        secmec = binascii.unhexlify(b'0004')
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)
            if code_point == cp.ACCSECRD:
                secmec = ddm.parse_reply(obj).get(cp.SECMEC)

        ddm.write_requests_dds(self.sock, [
            ddm.packSECCHK(secmec, self.database, self.user, self.password),
            ddm.packACCRDB(self.database)
        ])
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)

    def __enter__(self):
        return self

    def __exit__(self, exc, value, traceback):
        self.close()

    def _execute(self, query):
        ddm.write_requests_dds(self.sock, [
            ddm.packEXCSQLIMM(self.database),
            ddm.packSQLSTT(query),
            ddm.packRDBCMM(),
        ])
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)

    def _query(self, query):
        pass

    def is_connect(self):
        return bool(self.sock)

    def cursor(self):
        return Cursor(self)

    def begin(self):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        ddm.write_requests_dds(self.sock, [ddm.packRDBCMM()])
        chained = True
        while chained:
            dds_type, chained, number, code_point, obj = ddm.read_dds(self.sock)
        self.sock.close()
