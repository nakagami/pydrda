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
from .connection import Connection

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

    def __cmp__(self, other):
        if other in self.values:
            return 0
        if other < self.values:
            return 1
        else:
            return -1


STRING = DBAPITypeObject(str)
BINARY = DBAPITypeObject(bytes)
NUMBER = DBAPITypeObject(int, decimal.Decimal)
DATETIME = DBAPITypeObject(datetime.datetime, datetime.date, datetime.time)
DATE = DBAPITypeObject(datetime.date)
TIME = DBAPITypeObject(datetime.time)
ROWID = DBAPITypeObject()


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
