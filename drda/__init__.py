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

import datetime
import decimal
from . import utils
from .connection import Connection
from .cursor import Cursor, DictCursor

VERSION = (0, 6, 2)
__version__ = '%s.%s.%s' % VERSION
apilevel = '2.0'
threadsafety = 1
paramstyle = 'qmark'


Date = datetime.date
Time = datetime.time
TimeDelta = datetime.timedelta
Timestamp = datetime.datetime


def Binary(b):
    return bytearray(b)


class DBAPITypeObject:
    def __init__(self, *values):
        self.values = values

    def __eq__(self, other):
        if isinstance(other, DBAPITypeObject):
            return self.values == other.values
        return other in self.values

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.values)

    def __repr__(self):
        return f"<DBAPITypeObject {self.values}>"


STRING = DBAPITypeObject(
    str,
    utils.DRDA_TYPE_CHAR, utils.DRDA_TYPE_NCHAR,
    utils.DRDA_TYPE_VARCHAR, utils.DRDA_TYPE_NVARCHAR,
    utils.DRDA_TYPE_LONG, utils.DRDA_TYPE_NLONG,
    utils.DRDA_TYPE_CSTR, utils.DRDA_TYPE_NCSTR,
    utils.DRDA_TYPE_CLOBLOC, utils.DRDA_TYPE_NCLOBLOC,
    utils.DRDA_TYPE_DBCSCLOBLOC, utils.DRDA_TYPE_NDBCSCLOBLOC,
    utils.DRDA_TYPE_GRAPHIC, utils.DRDA_TYPE_NGRAPHIC,
    utils.DRDA_TYPE_VARGRAPH, utils.DRDA_TYPE_NVARGRAPH,
    utils.DRDA_TYPE_LONGRAPH, utils.DRDA_TYPE_NLONGRAPH,
    utils.DRDA_TYPE_MIX, utils.DRDA_TYPE_NMIX,
    utils.DRDA_TYPE_VARMIX, utils.DRDA_TYPE_NVARMIX,
    utils.DRDA_TYPE_LONGMIX, utils.DRDA_TYPE_NLONGMIX,
    utils.DRDA_TYPE_CSTRMIX, utils.DRDA_TYPE_NCSTRMIX,
    utils.DRDA_TYPE_LSTR, utils.DRDA_TYPE_NLSTR,
    utils.DRDA_TYPE_LSTRMIX, utils.DRDA_TYPE_NLSTRMIX,
    utils.DRDA_TYPE_LOBCSBCS, utils.DRDA_TYPE_NLOBCSBCS,
)
BINARY = DBAPITypeObject(
    bytes, bytearray, memoryview,
    utils.DRDA_TYPE_FIXBYTE, utils.DRDA_TYPE_NFIXBYTE,
    utils.DRDA_TYPE_VARBYTE, utils.DRDA_TYPE_NVARBYTE,
    utils.DRDA_TYPE_LONGVARBYTE, utils.DRDA_TYPE_NLONGVARBYTE,
    utils.DRDA_TYPE_LOBLOC, utils.DRDA_TYPE_NLOBLOC,
    utils.DRDA_TYPE_FIXBYTES, utils.DRDA_TYPE_NFIXBYTES,
    utils.DRDA_TYPE_VARBINARY, utils.DRDA_TYPE_NVARBINARY,
    utils.DRDA_TYPE_LOBBYTES, utils.DRDA_TYPE_NLOBBYTES,
)
NUMBER = DBAPITypeObject(
    int, float, decimal.Decimal,
    utils.DRDA_TYPE_INTEGER, utils.DRDA_TYPE_NINTEGER,
    utils.DRDA_TYPE_SMALL, utils.DRDA_TYPE_NSMALL,
    utils.DRDA_TYPE_1BYTE_INT, utils.DRDA_TYPE_N1BYTE_INT,
    utils.DRDA_TYPE_INTEGER8, utils.DRDA_TYPE_NINTEGER8,
    utils.DRDA_TYPE_FLOAT4, utils.DRDA_TYPE_NFLOAT4,
    utils.DRDA_TYPE_FLOAT8, utils.DRDA_TYPE_NFLOAT8,
    utils.DRDA_TYPE_FLOAT16, utils.DRDA_TYPE_NFLOAT16,
    utils.DRDA_TYPE_DECIMAL, utils.DRDA_TYPE_NDECIMAL,
    utils.DRDA_TYPE_ZDECIMAL, utils.DRDA_TYPE_NZDECIMAL,
    utils.DRDA_TYPE_NUMERIC_CHAR, utils.DRDA_TYPE_NNUMERIC_CHAR,
    utils.DRDA_TYPE_DECFLOAT, utils.DRDA_TYPE_NDECFLOAT,
)
DATETIME = DBAPITypeObject(
    datetime.datetime, datetime.date, datetime.time,
    utils.DRDA_TYPE_DATE, utils.DRDA_TYPE_NDATE,
    utils.DRDA_TYPE_TIME, utils.DRDA_TYPE_NTIME,
    utils.DRDA_TYPE_TIMESTAMP, utils.DRDA_TYPE_NTIMESTAMP,
)
DATE = DBAPITypeObject(
    datetime.date,
    utils.DRDA_TYPE_DATE, utils.DRDA_TYPE_NDATE,
)
TIME = DBAPITypeObject(
    datetime.time,
    utils.DRDA_TYPE_TIME, utils.DRDA_TYPE_NTIME,
)
ROWID = DBAPITypeObject(
    utils.DRDA_TYPE_ROWID, utils.DRDA_TYPE_NROWID,
)


class Error(Exception):
    def __init__(self, *args, **kwargs):
        if len(args) == 3:
            self.sqlcode, self.sqlstate, self.message = args
        elif len(args) == 2:
            self.sqlcode, self.message = args
            self.sqlstate = kwargs.get('sqlstate')
        elif len(args) == 1:
            self.sqlcode = kwargs.get('sqlcode')
            self.sqlstate = kwargs.get('sqlstate')
            self.message = args[0]
        elif len(args) == 0:
            self.sqlcode = kwargs.get('sqlcode')
            self.sqlstate = kwargs.get('sqlstate')
            self.message = kwargs.get('message', '')
        else:
            self.sqlcode = kwargs.get('sqlcode')
            self.sqlstate = kwargs.get('sqlstate')
            self.message = ' '.join(str(a) for a in args)
        super(Error, self).__init__(str(self))

    def __str__(self):
        parts = []
        if self.sqlcode is not None:
            parts.append("SQLCODE=%s" % self.sqlcode)
        if self.sqlstate is not None:
            parts.append("SQLSTATE=%s" % self.sqlstate)
        if self.message:
            parts.append(str(self.message))
        return " ".join(parts) if parts else str(self.message or '')


class Warning(Exception):
    pass


class InterfaceError(Error):
    pass


class DatabaseError(Error):
    pass


class DisconnectByPeer(Warning):
    pass


class InternalError(DatabaseError):
    def __init__(self, *args, **kwargs):
        if not args and not kwargs:
            args = (-1, 'InternalError')
        super(InternalError, self).__init__(*args, **kwargs)


class OperationalError(DatabaseError):
    pass


class ProgrammingError(DatabaseError):
    pass


class IntegrityError(DatabaseError):
    pass


class DataError(DatabaseError):
    pass


class NotSupportedError(DatabaseError):
    def __init__(self, *args, **kwargs):
        if not args and not kwargs:
            args = ('NotSupportedError',)
        super(NotSupportedError, self).__init__(*args, **kwargs)


def connect(host, database, port=50000, user=None, password=None, use_ssl=False, ssl_client_cert_path=None, timeout=None):
    return Connection(host, database, port, user, password, use_ssl, ssl_client_cert_path, timeout)


from drda import aio  # noqa: E402
