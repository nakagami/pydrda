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
"""Tests for PEP 249 exceptions"""
import asyncio
import unittest
import drda
import drda.cursor
import drda.aio.cursor


class TestExceptions(unittest.TestCase):
    """PEP 249 exception hierarchy and instantiation tests (offline, no server needed)."""

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
        with self.assertRaises(drda.NotSupportedError):
            cur.nextset("test_proc")

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


if __name__ == "__main__":
    unittest.main()
