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
"""Tests for db2 (asyncio)"""
import unittest
import asyncio
import os
import decimal
import datetime
import drda
import drda.aio
from drda import ddm
from drda import codepoint as cp
from drda.aio.stream import AsyncSocketStream
from drda.aio.connection import _read_dss, _write_request_dss

HOST = os.environ.get("DB2_HOST", "localhost")
DATABASE = os.environ.get("DB2_DATABASE", "testdb")
USER = os.environ.get("DB2_USER", "db2inst1")
PASSWORD = os.environ.get("DB2_PASSWORD", "password")
PORT = int(os.environ.get("DB2_PORT", 50000))
SSL_CLIENT_CERT_PATH = os.environ.get("SSL_CLIENT_CERT_PATH")


class FakeSock:
    "Synchronous fake socket for comparison with the async stream"
    def __init__(self, data=b''):
        self.data = bytearray(data)
        self.sent = bytearray()

    def recv(self, nbytes):
        r = bytes(self.data[:nbytes])
        del self.data[:nbytes]
        return r

    def send(self, b):
        self.sent += b


def _build_dss_frame(code_point, obj, cur_id=1, flag=1):
    obj_ln = len(obj) + 4
    dss_ln = obj_ln + 6
    return (
        dss_ln.to_bytes(2, byteorder='big') +
        bytes([0xD0, flag]) +
        cur_id.to_bytes(2, byteorder='big') +
        obj_ln.to_bytes(2, byteorder='big') +
        code_point.to_bytes(2, byteorder='big') +
        obj
    )


class TestAsyncDSS(unittest.TestCase):
    """DSS packet read/write parity tests (no database server required)."""

    def test_write_request_dss(self):
        "async _write_request_dss must emit the same bytes as ddm.write_request_dss"
        async def run():
            packet = ddm.packRDBCMM()
            expected = FakeSock()
            ddm.write_request_dss(expected, packet, 1, False, True)

            received = []

            async def handle(reader, writer):
                received.append(await reader.read(4096))
                writer.close()

            server = await asyncio.start_server(handle, '127.0.0.1', 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                stream = AsyncSocketStream('127.0.0.1', port)
                await stream.connect()
                next_id = await _write_request_dss(stream, packet, 1, False, True)
                self.assertEqual(next_id, 2)
                await stream.close()
            self.assertEqual(bytes(received[0]), bytes(expected.sent))

        asyncio.run(run())

    def test_read_dss(self):
        "async _read_dss must parse the same result as ddm.read_dss"
        async def run():
            obj = b'\x01\x02\x03\x04\x05'
            frame = _build_dss_frame(cp.SQLCARD, obj)
            expected = ddm.read_dss(FakeSock(frame))

            async def handle(reader, writer):
                writer.write(frame)
                await writer.drain()
                writer.close()

            server = await asyncio.start_server(handle, '127.0.0.1', 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                stream = AsyncSocketStream('127.0.0.1', port)
                await stream.connect()
                result = await _read_dss(stream)
                await stream.close()
            self.assertEqual(result, expected)
            self.assertEqual(result[3], cp.SQLCARD)
            self.assertEqual(result[4], obj)

        asyncio.run(run())

    def test_invalid_dss(self):
        "async _read_dss must reject invalid DSS packets"
        async def run():
            async def handle(reader, writer):
                writer.write(b'\x00\x06\xd1\x01\x00\x01')
                await writer.drain()
                writer.close()

            server = await asyncio.start_server(handle, '127.0.0.1', 0)
            port = server.sockets[0].getsockname()[1]
            async with server:
                stream = AsyncSocketStream('127.0.0.1', port)
                await stream.connect()
                with self.assertRaises(ConnectionError):
                    await _read_dss(stream)
                await stream.close()

        asyncio.run(run())


class TestAsyncBasic(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.connection = await drda.aio.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD,
            port=PORT,
            use_ssl=bool(SSL_CLIENT_CERT_PATH),
            ssl_client_cert_path=SSL_CLIENT_CERT_PATH,
        )
        cur = self.connection.cursor()
        try:
            await cur.execute("DROP TABLE test_basic")
        except drda.OperationalError:
            pass
        await cur.execute("""
            CREATE TABLE test_basic (
                s varchar(20),
                i int,
                d1 decimal(2, 1),
                d2 decimal(11, 2)
            )
            """)
        await self.connection.commit()

    async def asyncTearDown(self):
        await self.connection.close()

    async def test_basic(self):
        cur = self.connection.cursor()
        await cur.execute("SELECT * FROM test_basic")
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 0, 0, None),
            ('I', 497, 4, 4, 0, 0, None),
            ('D1', 485, 0, 0, 2, 1, None),
            ('D2', 485, 0, 0, 11, 2, None)
        ])
        self.assertEqual(await cur.fetchall(), [])

        await cur.execute("""
            INSERT INTO test_basic (s, i, d1, d2) VALUES
                ('abcdefghijklmnopq', 1, 1.1, 123456789.12),
                ('B', 2, 1.2, -2),
                ('C', 3, null, null)
        """)
        await cur.execute("SELECT * FROM test_basic")
        self.assertEqual(await cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
            ('B', 2, decimal.Decimal('1.2'), decimal.Decimal('-2.00')),
            ('C', 3, None, None)
        ])

        await cur.execute(
            "SELECT * FROM test_basic where s=?",
            ["abcdefghijklmnopq"]
        )
        self.assertEqual(await cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
        ])

        await cur.execute(
            "SELECT * FROM test_basic where s=? and i=?",
            ["abcdefghijklmnopq", 1]
        )
        self.assertEqual(await cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
        ])

        await cur.execute("UPDATE test_basic SET s='abc' WHERE i=?", [1])
        await cur.execute("SELECT * FROM test_basic where i=?", [1])
        self.assertEqual(await cur.fetchone(), (
            'abc', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12'),
        ))

    async def test_error(self):
        cur = self.connection.cursor()
        with self.assertRaises(drda.OperationalError):
            await cur.execute("invalid query")

    async def test_async_iterator(self):
        cur = self.connection.cursor()
        await cur.execute("""
            INSERT INTO test_basic (s, i, d1, d2) VALUES
                ('A', 1, 1.1, 1.11),
                ('B', 2, 2.2, 2.22)
        """)
        await cur.execute("SELECT * FROM test_basic ORDER BY i")
        rows = []
        async for row in cur:
            rows.append(row)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], 'A')
        self.assertEqual(rows[1][0], 'B')

    async def test_context_manager(self):
        async with self.connection.cursor() as cur:
            await cur.execute("SELECT * FROM test_basic")
            self.assertEqual(await cur.fetchall(), [])
        self.assertTrue(cur.closed)


class TestAsyncDataType(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.connection = await drda.aio.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD,
            port=PORT,
            use_ssl=bool(SSL_CLIENT_CERT_PATH),
            ssl_client_cert_path=SSL_CLIENT_CERT_PATH,
        )

    async def asyncTearDown(self):
        await self.connection.close()

    async def test_datetime(self):
        cur = self.connection.cursor()
        try:
            await cur.execute("DROP TABLE test_datetime")
        except drda.OperationalError:
            pass
        await cur.execute("""
            CREATE TABLE test_datetime (
                d date,
                t time,
                dt timestamp
            )
        """)
        await cur.execute("""
            INSERT INTO test_datetime (d, t, dt) VALUES (?, ?, ?)""", [
            datetime.date(2019, 4, 30),
            datetime.time(12, 34, 56),
            datetime.datetime(2019, 4, 30, 12, 34, 56, 123456)
        ])
        await cur.execute("SELECT * FROM test_datetime")
        self.assertEqual(await cur.fetchall(), [(
            datetime.date(2019, 4, 30),
            datetime.time(12, 34, 56),
            datetime.datetime(2019, 4, 30, 12, 34, 56, 123456)
        )])

    async def test_bool(self):
        cur = self.connection.cursor()
        try:
            await cur.execute("""
                CREATE TABLE test_bool (
                    b1 boolean,
                    b2 boolean not null,
                    b3 boolean
                )
            """)
        except drda.OperationalError:
            pass
        await cur.execute("DELETE FROM test_bool")
        await cur.execute("""
            INSERT INTO test_bool (b1, b2, b3) VALUES (TRUE, FALSE, NULL)
        """)
        await cur.execute("SELECT * FROM test_bool")
        self.assertEqual(await cur.fetchall(), [(True, False, None)])


if __name__ == "__main__":
    unittest.main()
