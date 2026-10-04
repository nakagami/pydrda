#!/usr/bin/env python3
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
"""Offline unit tests for DRDA type decoding in drda.utils.read_field."""
import io
import struct
import decimal
import datetime
import unittest

from drda import utils


class TestDrdaTypeDecoding(unittest.TestCase):
    """Exhaustive tests for decoding all supported DRDA column data types."""

    def test_all_nullable_types_return_none_on_null_byte(self):
        """Verify that every type in _NULLABLE_TYPES returns None when null flag 0xFF is present."""
        for t in sorted(utils._NULLABLE_TYPES):
            stream = io.BytesIO(b'\xff')
            val = utils.read_field(t, b'\x00\x04', stream, 'big')
            self.assertIsNone(val, f"Type {hex(t)} failed to return None on null flag 0xFF")

    def test_integers(self):
        """Test integer decoding for SMALLINT (2B), INTEGER (4B), BIGINT (8B)."""
        # INTEGER (4 bytes, non-nullable)
        stream = io.BytesIO((12345678).to_bytes(4, 'big', signed=True))
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_INTEGER, b'\x00\x04', stream, 'big'), 12345678)

        # INTEGER (4 bytes, negative, little endian)
        stream = io.BytesIO((-12345678).to_bytes(4, 'little', signed=True))
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_INTEGER, b'\x00\x04', stream, 'little'), -12345678)

        # NINTEGER (4 bytes, nullable, not null)
        stream = io.BytesIO(b'\x00' + (42).to_bytes(4, 'big', signed=True))
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NINTEGER, b'\x00\x04', stream, 'big'), 42)

        # SMALL (2 bytes, non-nullable)
        stream = io.BytesIO((32767).to_bytes(2, 'big', signed=True))
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_SMALL, b'\x00\x02', stream, 'big'), 32767)

        # NSMALL (2 bytes, negative, nullable)
        stream = io.BytesIO(b'\x00' + (-32768).to_bytes(2, 'big', signed=True))
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NSMALL, b'\x00\x02', stream, 'big'), -32768)

        # INTEGER8 (8 bytes, non-nullable)
        stream = io.BytesIO((9223372036854775807).to_bytes(8, 'big', signed=True))
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_INTEGER8, b'\x00\x08', stream, 'big'), 9223372036854775807)

        # NINTEGER8 (8 bytes, negative, nullable)
        stream = io.BytesIO(b'\x00' + (-9223372036854775808).to_bytes(8, 'big', signed=True))
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NINTEGER8, b'\x00\x08', stream, 'big'), -9223372036854775808)

    def test_strings(self):
        """Test VARCHAR, NVARCHAR, CHAR, NCHAR, MIX, VARMIX, LONG, and GRAPHIC types."""
        # VARCHAR (2 bytes length prefix)
        stream = io.BytesIO(b'\x00\x0bHello World')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_VARCHAR, b'\x00\x20', stream, 'big'), "Hello World")

        # NVARCHAR (null byte + 2 bytes length prefix)
        stream = io.BytesIO(b'\x00\x00\x04Db2!')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NVARCHAR, b'\x00\x20', stream, 'big'), "Db2!")

        # VARMIX and NVARMIX
        stream = io.BytesIO(b'\x00\x03abc')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_VARMIX, b'\x00\x10', stream, 'big'), "abc")
        stream = io.BytesIO(b'\x00\x00\x03def')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NVARMIX, b'\x00\x10', stream, 'big'), "def")

        # LONG and NLONG
        stream = io.BytesIO(b'\x00\x04long')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_LONG, b'\x00\x10', stream, 'big'), "long")
        stream = io.BytesIO(b'\x00\x00\x05nlong')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NLONG, b'\x00\x10', stream, 'big'), "nlong")

        # CHAR and NCHAR (fixed length, trailing spaces stripped)
        stream = io.BytesIO(b'IBM       ')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_CHAR, b'\x00\x0a', stream, 'big'), "IBM")
        stream = io.BytesIO(b'\x00Db2       ')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NCHAR, b'\x00\x0a', stream, 'big'), "Db2")

        # MIX and NMIX
        stream = io.BytesIO(b'MIXDATA   ')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_MIX, b'\x00\x0a', stream, 'big'), "MIXDATA")
        stream = io.BytesIO(b'\x00MIXDATA2  ')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_NMIX, b'\x00\x0a', stream, 'big'), "MIXDATA2")

        # GRAPHIC and VARGRAPH
        stream = io.BytesIO(b'GRAPH     ')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_GRAPHIC, b'\x00\x0a', stream, 'big'), "GRAPH")
        stream = io.BytesIO(b'VARGRAPH')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_VARGRAPH, b'\x00\x08', stream, 'big'), "VARGRAPH")

    def test_floats(self):
        """Test FLOAT4 (single) and FLOAT8 (double) in both endiannesses."""
        # FLOAT4 Big Endian
        stream = io.BytesIO(struct.pack('>f', 123.5))
        self.assertAlmostEqual(utils.read_field(utils.DRDA_TYPE_FLOAT4, b'\x00\x04', stream, 'big'), 123.5, places=5)

        # FLOAT4 Little Endian
        stream = io.BytesIO(struct.pack('<f', -0.125))
        self.assertAlmostEqual(utils.read_field(utils.DRDA_TYPE_FLOAT4, b'\x00\x04', stream, 'little'), -0.125, places=5)

        # NFLOAT4 (nullable)
        stream = io.BytesIO(b'\x00' + struct.pack('>f', 42.0))
        self.assertAlmostEqual(utils.read_field(utils.DRDA_TYPE_NFLOAT4, b'\x00\x04', stream, 'big'), 42.0, places=5)

        # FLOAT8 Big Endian
        stream = io.BytesIO(struct.pack('>d', 3.141592653589793))
        self.assertAlmostEqual(utils.read_field(utils.DRDA_TYPE_FLOAT8, b'\x00\x08', stream, 'big'), 3.141592653589793)

        # FLOAT8 Little Endian
        stream = io.BytesIO(struct.pack('<d', -2.718281828459045))
        self.assertAlmostEqual(utils.read_field(utils.DRDA_TYPE_FLOAT8, b'\x00\x08', stream, 'little'), -2.718281828459045)

        # NFLOAT8 (nullable)
        stream = io.BytesIO(b'\x00' + struct.pack('>d', 1.41421356))
        self.assertAlmostEqual(utils.read_field(utils.DRDA_TYPE_NFLOAT8, b'\x00\x08', stream, 'big'), 1.41421356)

    def test_decimal(self):
        """Test packed decimal decoding (NDECIMAL)."""
        # decimal(5, 2) with value 12.34 -> digits '01234c' (positive)
        # precision=5, scale=2. ln = (5+1)/2 = 3 bytes.
        stream = io.BytesIO(b'\x00' + bytes.fromhex('01234c'))
        res = utils.read_field(utils.DRDA_TYPE_NDECIMAL, (5, 2), stream, 'big')
        self.assertEqual(res, decimal.Decimal('12.34'))

        # Negative decimal
        stream = io.BytesIO(b'\x00' + bytes.fromhex('05678d'))
        res = utils.read_field(utils.DRDA_TYPE_NDECIMAL, (5, 2), stream, 'big')
        self.assertEqual(res, decimal.Decimal('-56.78'))

    def test_decfloat(self):
        """Test DECFLOAT / NDECFLOAT using DPD encoding."""
        # Encode a Decimal via _encode_dfp and decode it via read_field
        d = decimal.Decimal('1234.5678')
        encoded = utils._encode_dfp(d, 8)
        stream = io.BytesIO(encoded)
        res = utils.read_field(utils.DRDA_TYPE_DECFLOAT, b'\x00\x08', stream, 'big')
        self.assertEqual(res, d)

        # Nullable decfloat
        d16 = decimal.Decimal('-9876543210.123456789')
        encoded16 = utils._encode_dfp(d16, 16)
        stream = io.BytesIO(b'\x00' + encoded16)
        res = utils.read_field(utils.DRDA_TYPE_NDECFLOAT, b'\x00\x10', stream, 'big')
        self.assertEqual(res, d16)

    def test_date_time_timestamp(self):
        """Test DATE, TIME, and TIMESTAMP decoding."""
        # DATE
        stream = io.BytesIO(b'2026-10-03')
        self.assertEqual(
            utils.read_field(utils.DRDA_TYPE_DATE, b'\x00\x0a', stream, 'big'),
            datetime.date(2026, 10, 3)
        )
        stream = io.BytesIO(b'\x002026-10-03')
        self.assertEqual(
            utils.read_field(utils.DRDA_TYPE_NDATE, b'\x00\x0a', stream, 'big'),
            datetime.date(2026, 10, 3)
        )

        # TIME (%H:%M:%S)
        stream = io.BytesIO(b'16:45:30')
        self.assertEqual(
            utils.read_field(utils.DRDA_TYPE_TIME, b'\x00\x08', stream, 'big'),
            datetime.time(16, 45, 30)
        )
        # TIME (%H.%M.%S)
        stream = io.BytesIO(b'16.45.30')
        self.assertEqual(
            utils.read_field(utils.DRDA_TYPE_TIME, b'\x00\x08', stream, 'big'),
            datetime.time(16, 45, 30)
        )

        # TIMESTAMP (base 19 chars)
        stream = io.BytesIO(b'2026-10-03-16.45.30')
        self.assertEqual(
            utils.read_field(utils.DRDA_TYPE_TIMESTAMP, b'\x00\x13', stream, 'big'),
            datetime.datetime(2026, 10, 3, 16, 45, 30)
        )

        # TIMESTAMP (with microseconds)
        stream = io.BytesIO(b'2026-10-03-16.45.30.654321')
        self.assertEqual(
            utils.read_field(utils.DRDA_TYPE_TIMESTAMP, b'\x00\x1a', stream, 'big'),
            datetime.datetime(2026, 10, 3, 16, 45, 30, 654321)
        )

    def test_boolean(self):
        """Test BOOLEAN and NBOOLEAN decoding."""
        stream = io.BytesIO(b'\x01')
        self.assertTrue(utils.read_field(utils.DRDA_TYPE_BOOLEAN, b'\x00\x01', stream, 'big'))
        stream = io.BytesIO(b'\x00')
        self.assertFalse(utils.read_field(utils.DRDA_TYPE_BOOLEAN, b'\x00\x01', stream, 'big'))

        # Nullable boolean
        stream = io.BytesIO(b'\x00\x01')
        self.assertTrue(utils.read_field(utils.DRDA_TYPE_NBOOLEAN, b'\x00\x01', stream, 'big'))

    def test_binary_and_rowid(self):
        """Test FIXBYTE, VARBINARY, LONGVARBYTE, and ROWID types."""
        # FIXBYTE (using _extract_length)
        raw_bin = b'\x01\x02\x03\x04\x05'
        # ps has high bit set (0x8005) -> length is 5
        stream = io.BytesIO(raw_bin)
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_FIXBYTE, b'\x80\x05', stream, 'big'), raw_bin)

        # VARBINARY (2 bytes length prefix)
        stream = io.BytesIO(b'\x00\x03\xaa\xbb\xcc')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_VARBINARY, b'\x00\x10', stream, 'big'), b'\xaa\xbb\xcc')

        # LONGVARBYTE (4 bytes length prefix)
        stream = io.BytesIO(b'\x00\x00\x00\x02\xde\xad')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_LONGVARBYTE, b'\x00\x10', stream, 'big'), b'\xde\xad')

        # ROWID
        rowid = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        stream = io.BytesIO(rowid)
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_ROWID, b'\x00\x08', stream, 'big'), rowid)

    def test_lob_placeholders(self):
        """Test that LOB placeholder bytes are properly consumed and sentinels returned."""
        # LOBBYTES consumes placeholder bytes (ps=4) and returns b''
        stream = io.BytesIO(b'1234')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_LOBBYTES, b'\x80\x04', stream, 'big'), b'')
        self.assertEqual(stream.tell(), 4)

        # LOBCSBCS consumes placeholder bytes and returns ''
        stream = io.BytesIO(b'1234')
        self.assertEqual(utils.read_field(utils.DRDA_TYPE_LOBCSBCS, b'\x80\x04', stream, 'big'), '')
        self.assertEqual(stream.tell(), 4)

    def test_unknown_type_raises_value_error(self):
        """Test that invalid DRDA type codes raise ValueError."""
        stream = io.BytesIO(b'\x00\x01\x02')
        with self.assertRaises(ValueError) as ctx:
            utils.read_field(0xFFEE, b'\x00\x02', stream, 'big')
        self.assertIn("UnknownType", str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
