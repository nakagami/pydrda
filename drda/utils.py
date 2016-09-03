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

import binascii
import decimal
from drda.consts import *

def read_field(t, ps, b):
    """
    read one field value from bytes.
    return value, rest bytes
    t: type
    ps:  precision and scale or length
    b: input bytes
    """
    (isnull, b) = (b[0] == 0xFF, b[1:])

    if isnull:
        v = None
    elif t == DRDA_TYPE_NVARCHAR:
        ln = int.from_bytes(b[:2], byteorder='big')
        v = b[2:2+ln].decode('utf-8')
        b = b[2+ln:]
    elif t == DRDA_TYPE_NINTEGER:
        ln = int.from_bytes(ps, byteorder='big')
        v = int.from_bytes(b[:ln], byteorder='big')
        b = b[ln:]
    elif t == DRDA_TYPE_NDECIMAL:
        (p, s) = (ps[0], ps[1])
        ln = p + 1
        if ln % 2:
            ln += 1
        ln //= 2
        v = binascii.b2a_hex(b[:ln]).decode('ascii')
        assert v[-1] == 'c'
        v = v[:-1]
        v = decimal.Decimal(v) / (10**s)

        b = b[ln:]
    return v, b


def escape_parameter(v):
    t = type(v)
    if v is None:
        return 'NULL'
    elif t == str:
        return "'" + v.replace(u"'", u"''") + "'"
    elif t == decimal.Decimal:
        return "'" + str(v) + "'"
    elif t == int or t == float:
        return str(v)
    else:
        return "'" + str(v) + "'"

