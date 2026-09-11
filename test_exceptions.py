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
"""Tests for PEP 249 compliance (offline, no database server required)"""
import asyncio
import collections
import datetime
import decimal
import unittest
import drda
import drda.cursor
import drda.aio.cursor
from drda import utils


class TestExceptions(unittest.TestCase):
    """PEP 249 compliance tests (exceptions, types, cursor methods; offline)."""

    def test_pep249_inheritance(self):
        self.assertTrue(issubclass(drda.Error, Exception))
        self.assertTrue(issubclass(drda.Warning, Exception))
        self.assertTrue(issubclass(drda.InterfaceError, drda.Error))
        self.assertTrue(issubclass(drda.DatabaseError, drda.Error))
        self.assertTrue(issubclass(drda.DataError, drda.DatabaseError))
        self.assertTrue(issubclass(drda.OperationalError, drda.DatabaseError))
        self.assertTrue(issubclass(drda.IntegrityError, drda.DatabaseError))
        self.assertTrue(issubclass(drda.InternalError, drda.DatabaseError))
        self.assertTrue(issubclass(drda.ProgrammingError, drda.DatabaseError))
        self.assertTrue(issubclass(drda.NotSupportedError, drda.DatabaseError))

    def test_instantiate_all_exceptions_no_args(self):
        for exc_cls in (
            drda.Error,
            drda.Warning,
            drda.InterfaceError,
            drda.DatabaseError,
            drda.DataError,
            drda.OperationalError,
            drda.IntegrityError,
            drda.InternalError,
            drda.ProgrammingError,
            drda.NotSupportedError,
        ):
            e = exc_cls()
            self.assertIsInstance(e, exc_cls)

    def test_instantiate_all_exceptions_one_arg(self):
        for exc_cls in (
            drda.Error,
            drda.InterfaceError,
            drda.DatabaseError,
            drda.DataError,
            drda.OperationalError,
            drda.IntegrityError,
            drda.InternalError,
            drda.ProgrammingError,
            drda.NotSupportedError,
        ):
            msg = f"{exc_cls.__name__} occurred"
            e = exc_cls(msg)
            self.assertIsInstance(e, exc_cls)
            self.assertEqual(e.message, msg)
            self.assertIsNone(e.sqlcode)
            self.assertIsNone(e.sqlstate)
            self.assertEqual(str(e), msg)

    def test_three_args_sqlcode_sqlstate_message(self):
        e = drda.OperationalError(-30081, "08001", "connection refused")
        self.assertEqual(e.sqlcode, -30081)
        self.assertEqual(e.sqlstate, "08001")
        self.assertEqual(e.message, "connection refused")
        self.assertEqual(str(e), "SQLCODE=-30081 SQLSTATE=08001 connection refused")

    def test_two_args_sqlcode_message(self):
        e = drda.DatabaseError(-1, "something failed")
        self.assertEqual(e.sqlcode, -1)
        self.assertIsNone(e.sqlstate)
        self.assertEqual(e.message, "something failed")
        self.assertEqual(str(e), "SQLCODE=-1 something failed")

    def test_keyword_args(self):
        e = drda.Error(sqlcode=-204, sqlstate="42704", message="table not found")
        self.assertEqual(e.sqlcode, -204)
        self.assertEqual(e.sqlstate, "42704")
        self.assertEqual(e.message, "table not found")
        self.assertEqual(str(e), "SQLCODE=-204 SQLSTATE=42704 table not found")

    def test_internal_error_defaults(self):
        e = drda.InternalError()
        self.assertEqual(e.sqlcode, -1)
        self.assertIsNone(e.sqlstate)
        self.assertEqual(e.message, "InternalError")
        self.assertEqual(str(e), "SQLCODE=-1 InternalError")

        e2 = drda.InternalError("custom internal error")
        self.assertEqual(e2.message, "custom internal error")

    def test_not_supported_error_defaults(self):
        e = drda.NotSupportedError()
        self.assertEqual(e.message, "NotSupportedError")
        self.assertEqual(str(e), "NotSupportedError")

        e2 = drda.NotSupportedError("feature X is not supported")
        self.assertEqual(e2.message, "feature X is not supported")
        self.assertEqual(str(e2), "feature X is not supported")

    def test_cursor_not_supported_error(self):
        cur = drda.cursor.Cursor(None)
        with self.assertRaises(drda.NotSupportedError):
            cur.callproc("test_proc")
        # Standard PEP 249: nextset() without arguments
        with self.assertRaises(drda.NotSupportedError):
            cur.nextset()
        # With optional arguments
        with self.assertRaises(drda.NotSupportedError):
            cur.nextset("test_proc")

    def test_cursor_setinputsizes_and_setoutputsize(self):
        cur = drda.cursor.Cursor(None)
        cur.setinputsizes([10, 20])
        cur.setoutputsize(100)
        cur.setoutputsize(100, 1)

    def test_async_cursor_methods(self):
        cur = drda.aio.cursor.AsyncCursor(None)
        with self.assertRaises(drda.NotSupportedError):
            cur.callproc("test_proc")
        with self.assertRaises(drda.NotSupportedError):
            cur.nextset()
        cur.setinputsizes([10, 20])
        cur.setoutputsize(100)
        cur.setoutputsize(100, 1)

    def test_cursor_lost_connection_operational_error(self):
        cur = drda.cursor.Cursor(None)
        with self.assertRaises(drda.OperationalError) as ctx:
            cur.fetchone()
        self.assertIn("08003:Lost connection", str(ctx.exception))
        self.assertIsNone(ctx.exception.sqlcode)
        self.assertIsNone(ctx.exception.sqlstate)

    def test_async_cursor_lost_connection_operational_error(self):
        cur = drda.aio.cursor.Cursor(None)
        with self.assertRaises(drda.OperationalError) as ctx:
            asyncio.run(cur.fetchone())
        self.assertIn("08003:Lost connection", str(ctx.exception))
        self.assertIsNone(ctx.exception.sqlcode)
        self.assertIsNone(ctx.exception.sqlstate)

    def test_fetchmany_respects_arraysize(self):
        class FakeConn:
            def is_connect(self):
                return True

        cur = drda.cursor.Cursor(FakeConn())
        cur._rows = collections.deque([(i,) for i in range(10)])
        self.assertEqual(cur.arraysize, 1)

        # Default size=None uses arraysize (1)
        self.assertEqual(cur.fetchmany(), [(0,)])

        # Setting arraysize changes default fetch quantity
        cur.arraysize = 3
        self.assertEqual(cur.fetchmany(), [(1,), (2,), (3,)])

        # Explicit size overrides arraysize
        self.assertEqual(cur.fetchmany(2), [(4,), (5,)])
        self.assertEqual(cur.fetchmany(), [(6,), (7,), (8,)])
        self.assertEqual(cur.fetchmany(), [(9,)])
        self.assertEqual(cur.fetchmany(), [])

    def test_async_fetchmany_respects_arraysize(self):
        class FakeConn:
            def is_connect(self):
                return True

        async def run():
            cur = drda.aio.cursor.AsyncCursor(FakeConn())
            cur._rows = collections.deque([(i,) for i in range(10)])
            self.assertEqual(cur.arraysize, 1)

            # Default size=None uses arraysize (1)
            self.assertEqual(await cur.fetchmany(), [(0,)])

            # Setting arraysize changes default fetch quantity
            cur.arraysize = 3
            self.assertEqual(await cur.fetchmany(), [(1,), (2,), (3,)])

            # Explicit size overrides arraysize
            self.assertEqual(await cur.fetchmany(2), [(4,), (5,)])
            self.assertEqual(await cur.fetchmany(), [(6,), (7,), (8,)])
            self.assertEqual(await cur.fetchmany(), [(9,)])
            self.assertEqual(await cur.fetchmany(), [])

        asyncio.run(run())

    def test_dbapi_type_objects_python_types(self):
        # Bidirectional equality for Python types
        self.assertEqual(drda.STRING, str)
        self.assertEqual(str, drda.STRING)
        self.assertNotEqual(drda.STRING, int)
        self.assertNotEqual(int, drda.STRING)

        self.assertEqual(drda.NUMBER, int)
        self.assertEqual(int, drda.NUMBER)
        self.assertEqual(drda.NUMBER, float)
        self.assertEqual(float, drda.NUMBER)
        self.assertEqual(drda.NUMBER, decimal.Decimal)
        self.assertEqual(decimal.Decimal, drda.NUMBER)
        self.assertNotEqual(drda.NUMBER, str)

        self.assertEqual(drda.DATETIME, datetime.datetime)
        self.assertEqual(datetime.datetime, drda.DATETIME)
        self.assertEqual(drda.DATETIME, datetime.date)
        self.assertEqual(drda.DATETIME, datetime.time)

        self.assertEqual(drda.DATE, datetime.date)
        self.assertEqual(datetime.date, drda.DATE)

        self.assertEqual(drda.TIME, datetime.time)
        self.assertEqual(datetime.time, drda.TIME)

        self.assertEqual(drda.BINARY, bytes)
        self.assertEqual(bytes, drda.BINARY)
        self.assertEqual(drda.BINARY, bytearray)
        self.assertEqual(drda.BINARY, memoryview)

    def test_dbapi_type_objects_drda_constants(self):
        # Bidirectional equality for DRDA internal types
        self.assertEqual(drda.STRING, utils.DRDA_TYPE_CHAR)
        self.assertEqual(utils.DRDA_TYPE_VARCHAR, drda.STRING)
        self.assertEqual(drda.STRING, utils.DRDA_TYPE_CLOBLOC)
        self.assertEqual(drda.STRING, utils.DRDA_TYPE_LOBCSBCS)

        self.assertEqual(drda.NUMBER, utils.DRDA_TYPE_INTEGER)
        self.assertEqual(utils.DRDA_TYPE_SMALL, drda.NUMBER)
        self.assertEqual(drda.NUMBER, utils.DRDA_TYPE_FLOAT8)
        self.assertEqual(drda.NUMBER, utils.DRDA_TYPE_DECIMAL)
        self.assertEqual(drda.NUMBER, utils.DRDA_TYPE_DECFLOAT)

        self.assertEqual(drda.DATETIME, utils.DRDA_TYPE_DATE)
        self.assertEqual(drda.DATETIME, utils.DRDA_TYPE_TIME)
        self.assertEqual(drda.DATETIME, utils.DRDA_TYPE_TIMESTAMP)

        self.assertEqual(drda.DATE, utils.DRDA_TYPE_DATE)
        self.assertEqual(drda.TIME, utils.DRDA_TYPE_TIME)

        self.assertEqual(drda.BINARY, utils.DRDA_TYPE_FIXBYTE)
        self.assertEqual(drda.BINARY, utils.DRDA_TYPE_VARBYTE)
        self.assertEqual(drda.BINARY, utils.DRDA_TYPE_LOBLOC)
        self.assertEqual(drda.BINARY, utils.DRDA_TYPE_LOBBYTES)

        self.assertEqual(drda.ROWID, utils.DRDA_TYPE_ROWID)
        self.assertEqual(drda.ROWID, utils.DRDA_TYPE_NROWID)

    def test_dbapi_type_objects_hashable(self):
        # Type objects can be used as dict keys (common in ORMs)
        type_mapping = {
            drda.STRING: "string",
            drda.NUMBER: "number",
            drda.DATETIME: "datetime",
            drda.BINARY: "binary",
            drda.ROWID: "rowid",
        }
        self.assertEqual(type_mapping[drda.STRING], "string")
        self.assertEqual(type_mapping[drda.NUMBER], "number")
        self.assertEqual(type_mapping[drda.DATETIME], "datetime")
        self.assertEqual(type_mapping[drda.BINARY], "binary")
        self.assertEqual(type_mapping[drda.ROWID], "rowid")

    def test_dbapi_type_objects_cursor_description(self):
        # Simulates checking cursor.description[i][1] == TYPE_OBJECT
        simulated_description = [
            ("ID", utils.DRDA_TYPE_INTEGER, None, None, None, None, None),
            ("NAME", utils.DRDA_TYPE_VARCHAR, None, None, None, None, None),
            ("CREATED_AT", utils.DRDA_TYPE_TIMESTAMP, None, None, None, None, None),
            ("DATA", utils.DRDA_TYPE_LOBBYTES, None, None, None, None, None),
            ("ROW_ID", utils.DRDA_TYPE_ROWID, None, None, None, None, None),
        ]
        self.assertEqual(simulated_description[0][1], drda.NUMBER)
        self.assertEqual(simulated_description[1][1], drda.STRING)
        self.assertEqual(simulated_description[2][1], drda.DATETIME)
        self.assertEqual(simulated_description[3][1], drda.BINARY)
        self.assertEqual(simulated_description[4][1], drda.ROWID)


if __name__ == "__main__":
    unittest.main()
