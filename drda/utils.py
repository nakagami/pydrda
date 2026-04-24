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

import binascii
import decimal
import datetime
import struct

DRDA_TYPE_INTEGER = 0x02
DRDA_TYPE_NINTEGER = 0x03
DRDA_TYPE_SMALL = 0x04
DRDA_TYPE_NSMALL = 0x05
DRDA_TYPE_1BYTE_INT = 0x06
DRDA_TYPE_N1BYTE_INT = 0x07
DRDA_TYPE_FLOAT16 = 0x08
DRDA_TYPE_NFLOAT16 = 0x09
DRDA_TYPE_FLOAT8 = 0x0A
DRDA_TYPE_NFLOAT8 = 0x0B
DRDA_TYPE_FLOAT4 = 0x0C
DRDA_TYPE_NFLOAT4 = 0x0D
DRDA_TYPE_DECIMAL = 0x0E
DRDA_TYPE_NDECIMAL = 0x0F
DRDA_TYPE_ZDECIMAL = 0x10
DRDA_TYPE_NZDECIMAL = 0x11
DRDA_TYPE_NUMERIC_CHAR = 0x12
DRDA_TYPE_NNUMERIC_CHAR = 0x13
DRDA_TYPE_RSET_LOC = 0x14
DRDA_TYPE_NRSET_LOC = 0x15
DRDA_TYPE_INTEGER8 = 0x16
DRDA_TYPE_NINTEGER8 = 0x17
DRDA_TYPE_LOBLOC = 0x18
DRDA_TYPE_NLOBLOC = 0x19
DRDA_TYPE_CLOBLOC = 0x1A
DRDA_TYPE_NCLOBLOC = 0x1B
DRDA_TYPE_DBCSCLOBLOC = 0x1C
DRDA_TYPE_NDBCSCLOBLOC = 0x1D
DRDA_TYPE_ROWID = 0x1E
DRDA_TYPE_NROWID = 0x1F
DRDA_TYPE_DATE = 0x20
DRDA_TYPE_NDATE = 0x21
DRDA_TYPE_TIME = 0x22
DRDA_TYPE_NTIME = 0x23
DRDA_TYPE_TIMESTAMP = 0x24
DRDA_TYPE_NTIMESTAMP = 0x25
DRDA_TYPE_FIXBYTE = 0x26
DRDA_TYPE_NFIXBYTE = 0x27
DRDA_TYPE_VARBYTE = 0x28
DRDA_TYPE_NVARBYTE = 0x29
DRDA_TYPE_LONGVARBYTE = 0x2A
DRDA_TYPE_NLONGVARBYTE = 0x2B
DRDA_TYPE_NTERMBYTE = 0x2C
DRDA_TYPE_NNTERMBYTE = 0x2D
DRDA_TYPE_CSTR = 0x2E
DRDA_TYPE_NCSTR = 0x2F
DRDA_TYPE_CHAR = 0x30
DRDA_TYPE_NCHAR = 0x31
DRDA_TYPE_VARCHAR = 0x32
DRDA_TYPE_NVARCHAR = 0x33
DRDA_TYPE_LONG = 0x34
DRDA_TYPE_NLONG = 0x35
DRDA_TYPE_GRAPHIC = 0x36
DRDA_TYPE_NGRAPHIC = 0x37
DRDA_TYPE_VARGRAPH = 0x38
DRDA_TYPE_NVARGRAPH = 0x39
DRDA_TYPE_LONGRAPH = 0x3A
DRDA_TYPE_NLONGRAPH = 0x3B
DRDA_TYPE_MIX = 0x3C
DRDA_TYPE_NMIX = 0x3D
DRDA_TYPE_VARMIX = 0x3E
DRDA_TYPE_NVARMIX = 0x3F
DRDA_TYPE_LONGMIX = 0x40
DRDA_TYPE_NLONGMIX = 0x41
DRDA_TYPE_CSTRMIX = 0x42
DRDA_TYPE_NCSTRMIX = 0x43
DRDA_TYPE_PSCLBYTE = 0x44
DRDA_TYPE_NPSCLBYTE = 0x45
DRDA_TYPE_LSTR = 0x46
DRDA_TYPE_NLSTR = 0x47
DRDA_TYPE_LSTRMIX = 0x48
DRDA_TYPE_NLSTRMIX = 0x49
DRDA_TYPE_SDATALINK = 0x4C
DRDA_TYPE_NSDATALINK = 0x4D
DRDA_TYPE_MDATALINK = 0x4E
DRDA_TYPE_NMDATALINK = 0x4F
DRDA_TYPE_BOOLEAN = 0xBE
DRDA_TYPE_NBOOLEAN = 0xBF
DRDA_TYPE_DECFLOAT = 0xBA
DRDA_TYPE_NDECFLOAT = 0xBB


def _decode_dfp(data):
    """Decode IEEE 754-2008 BID decimal floating-point bytes to Python Decimal."""
    n_bytes = len(data)
    if n_bytes == 8:
        bias, coeff_cont_bits, exp_cont_bits = 398, 50, 8
    else:  # 16 bytes (DECFLOAT(34))
        bias, coeff_cont_bits, exp_cont_bits = 6176, 110, 12
    total_bits = n_bytes * 8
    w = int.from_bytes(data, 'big')
    sign = (w >> (total_bits - 1)) & 1
    G = (w >> (total_bits - 6)) & 0x1F
    E = (w >> coeff_cont_bits) & ((1 << exp_cont_bits) - 1)
    T = w & ((1 << coeff_cont_bits) - 1)
    # Special: G[4:3]="11", G[2]="1" (G >= 28)
    if G >= 0x1C:
        if G & 0x02:  # G[1]=1 → NaN
            return decimal.Decimal('NaN')
        return decimal.Decimal('-Infinity') if sign else decimal.Decimal('Infinity')
    # Large coefficient: G[4:3]="11", G[2]="0" (G = 24-27)
    if G >= 0x18:
        biased_exp = ((G & 0x03) << exp_cont_bits) | E
        coeff = (1 << (coeff_cont_bits + 3)) | T
    else:
        biased_exp = ((G >> 3) << exp_cont_bits) | E
        coeff = ((G & 0x07) << coeff_cont_bits) | T
    exp = biased_exp - bias
    return decimal.Decimal((sign, tuple(int(d) for d in str(coeff)), exp))


def _encode_dfp(v, n_bytes):
    """Encode Python Decimal to IEEE 754-2008 BID decimal floating-point bytes."""
    if n_bytes == 8:
        bias, coeff_cont_bits, exp_cont_bits = 398, 50, 8
    else:  # 16 bytes (DECFLOAT(34))
        bias, coeff_cont_bits, exp_cont_bits = 6176, 110, 12
    total_bits = n_bytes * 8
    sign, digits, exp = v.as_tuple()
    if v.is_infinite():
        w = (sign << (total_bits - 1)) | (0x1C << (total_bits - 6))
        return w.to_bytes(n_bytes, 'big')
    if v.is_nan():
        w = (sign << (total_bits - 1)) | (0x1E << (total_bits - 6))
        return w.to_bytes(n_bytes, 'big')
    coeff = int(''.join(str(d) for d in digits)) if digits else 0
    biased_exp = exp + bias
    implicit_bit = 1 << (coeff_cont_bits + 3)
    if coeff >= implicit_bit:
        # Large coefficient form (G[4:3]="11", G[2]="0")
        T = coeff - implicit_bit
        exp_top = biased_exp >> exp_cont_bits
        exp_low = biased_exp & ((1 << exp_cont_bits) - 1)
        G = 0x18 | exp_top
    else:
        # Normal form
        coeff_top = coeff >> coeff_cont_bits
        T = coeff & ((1 << coeff_cont_bits) - 1)
        exp_top = biased_exp >> exp_cont_bits
        exp_low = biased_exp & ((1 << exp_cont_bits) - 1)
        G = (exp_top << 3) | coeff_top
    w = (sign << (total_bits - 1)) | (G << (total_bits - 6)) | (exp_low << coeff_cont_bits) | T
    return w.to_bytes(n_bytes, 'big')


def read_from_stream(stream, nbytes):
    return stream.read(nbytes)

def read_field(t, ps, stream, endian):
    """
    read one field value from bytes.
    return value, rest bytes
    t: type
    ps:  precision and scale or length
    stream: input bytes stream
    """
    if t in (
        DRDA_TYPE_NINTEGER, DRDA_TYPE_NSMALL, DRDA_TYPE_N1BYTE_INT, DRDA_TYPE_NFLOAT16,
        DRDA_TYPE_NFLOAT8, DRDA_TYPE_NFLOAT4, DRDA_TYPE_NDECIMAL, DRDA_TYPE_NNUMERIC_CHAR,
        DRDA_TYPE_NRSET_LOC, DRDA_TYPE_NINTEGER8, DRDA_TYPE_NLOBLOC, DRDA_TYPE_NCLOBLOC,
        DRDA_TYPE_NDBCSCLOBLOC, DRDA_TYPE_NROWID, DRDA_TYPE_NDATE, DRDA_TYPE_NTIME,
        DRDA_TYPE_NTIMESTAMP, DRDA_TYPE_NFIXBYTE, DRDA_TYPE_NVARBYTE, DRDA_TYPE_NLONGVARBYTE,
        DRDA_TYPE_NTERMBYTE, DRDA_TYPE_NNTERMBYTE, DRDA_TYPE_NCSTR, DRDA_TYPE_NCHAR,
        DRDA_TYPE_NVARCHAR, DRDA_TYPE_NLONG, DRDA_TYPE_NGRAPHIC, DRDA_TYPE_NVARGRAPH,
        DRDA_TYPE_NLONGRAPH, DRDA_TYPE_NMIX, DRDA_TYPE_NVARMIX, DRDA_TYPE_NLONGMIX,
        DRDA_TYPE_NCSTRMIX, DRDA_TYPE_NPSCLBYTE, DRDA_TYPE_NLSTR, DRDA_TYPE_NLSTRMIX,
        DRDA_TYPE_NSDATALINK, DRDA_TYPE_NMDATALINK, DRDA_TYPE_NBOOLEAN, DRDA_TYPE_NDECFLOAT,
    ):
        if read_from_stream(stream, 1) == b'\xFF':
            return None

    if t in (DRDA_TYPE_MIX, DRDA_TYPE_NMIX):
        ln = int.from_bytes(ps, byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8')
    elif t in (DRDA_TYPE_CHAR, DRDA_TYPE_NCHAR):
        ln = int.from_bytes(ps, byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8').rstrip(' ')
    elif t in (DRDA_TYPE_ROWID, DRDA_TYPE_NROWID):
        ln = int.from_bytes(ps, byteorder='big')
        v = bytes(read_from_stream(stream, ln))
    elif t in (DRDA_TYPE_VARBYTE, DRDA_TYPE_NVARBYTE, DRDA_TYPE_LONGVARBYTE, DRDA_TYPE_NLONGVARBYTE):
        ln = int.from_bytes(read_from_stream(stream, 4), byteorder='big')
        v = bytes(read_from_stream(stream, ln))
    elif t in (DRDA_TYPE_LOBLOC, DRDA_TYPE_NLOBLOC, DRDA_TYPE_CLOBLOC, DRDA_TYPE_NCLOBLOC,
               DRDA_TYPE_DBCSCLOBLOC, DRDA_TYPE_NDBCSCLOBLOC):
        ln = int.from_bytes(ps, byteorder='big')
        v = bytes(read_from_stream(stream, ln))
    elif t in (DRDA_TYPE_DECFLOAT, DRDA_TYPE_NDECFLOAT):
        ln = int.from_bytes(ps, byteorder='big')
        v = _decode_dfp(read_from_stream(stream, ln))
    elif t in (
        DRDA_TYPE_VARMIX, DRDA_TYPE_NVARMIX,
        DRDA_TYPE_LONGMIX, DRDA_TYPE_NLONGMIX,
        DRDA_TYPE_VARCHAR, DRDA_TYPE_NVARCHAR, DRDA_TYPE_LONG, DRDA_TYPE_NLONG,
    ):
        ln = int.from_bytes(read_from_stream(stream, 2), byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8')
    elif t in (
            DRDA_TYPE_SMALL, DRDA_TYPE_NSMALL, DRDA_TYPE_NINTEGER8,
            DRDA_TYPE_INTEGER8, DRDA_TYPE_INTEGER, DRDA_TYPE_NINTEGER):
        ln = int.from_bytes(ps, byteorder='big')
        v = int.from_bytes(read_from_stream(stream, ln), byteorder=endian, signed=True)
    elif t == DRDA_TYPE_NDECIMAL:
        (p, s) = (ps[0], ps[1])
        ln = p + 1
        if ln % 2:
            ln += 1
        ln //= 2
        digits_sign = binascii.b2a_hex(read_from_stream(stream, ln)).decode('ascii')
        sign = 0 if digits_sign[-1] == 'c' else 1
        v = decimal.Decimal(digits_sign[:-1])
        v = decimal.Decimal((sign, v.as_tuple()[1], -s))
    elif t in (DRDA_TYPE_TIMESTAMP, DRDA_TYPE_NTIMESTAMP):
        ln = int.from_bytes(ps, byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8')
        v = datetime.datetime.strptime(v[:26], "%Y-%m-%d-%H.%M.%S.%f")
    elif t in (DRDA_TYPE_DATE, DRDA_TYPE_NDATE):
        ln = int.from_bytes(ps, byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8')
        v = datetime.datetime.strptime(v, "%Y-%m-%d")
        v = datetime.date(v.year, v.month, v.day)
    elif t in (DRDA_TYPE_TIME, DRDA_TYPE_NTIME):
        ln = int.from_bytes(ps, byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8')
        try:
            v = datetime.datetime.strptime(v, "%H:%M:%S")
        except ValueError:
            v = datetime.datetime.strptime(v, "%H.%M.%S")
        v = datetime.time(v.hour, v.minute, v.second)
    elif t in (DRDA_TYPE_VARGRAPH, DRDA_TYPE_NVARGRAPH):
        ln = int.from_bytes(ps, byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8').rstrip(' ')
    elif t in (DRDA_TYPE_GRAPHIC, DRDA_TYPE_NGRAPHIC):
        ln = int.from_bytes(ps, byteorder='big')
        v = read_from_stream(stream, ln).decode('utf-8').rstrip(' ')
    elif t in (DRDA_TYPE_NFLOAT4, DRDA_TYPE_FLOAT4):
        ln = int.from_bytes(ps, byteorder='big')
        v = struct.unpack(">f" if endian == 'big' else "<f", read_from_stream(stream, ln))[0]
    elif t in (DRDA_TYPE_NFLOAT8, DRDA_TYPE_FLOAT8):
        ln = int.from_bytes(ps, byteorder='big')
        v = struct.unpack(">d" if endian == 'big' else "<d", read_from_stream(stream, ln))[0]
    elif t in (DRDA_TYPE_BOOLEAN, DRDA_TYPE_NBOOLEAN):
        ln = int.from_bytes(ps, byteorder='big')
        v = True if int.from_bytes(read_from_stream(stream, ln), byteorder='big') else False
    else:
        raise ValueError("UnknownType(%s)" % hex(t))
    return v


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
