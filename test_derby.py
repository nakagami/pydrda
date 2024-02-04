#!/usr/bin/env python3
##############################################################################
# The MIT License (MIT)
#
# Copyright (c) 2016-2019 Hajime Nakagami<nakagami@gmail.com>
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
"""Tests for derby"""
import unittest
import io
import decimal
import datetime
import decimal
import drda


HOST = 'localhost'
DATABASE = 'testdb;create=true'
PORT = 1527


class TestBasic(unittest.TestCase):
    def setUp(self):
        self.connection = drda.connect(
            host=HOST,
            database=DATABASE,
            port=PORT,
        )
        cur = self.connection.cursor()
        try:
            cur.execute("""
                CREATE TABLE test_basic (
                    s VARCHAR(20),
                    b clob,
                    c clob,
                    i int,
                    d1 decimal(2, 1),
                    d2 decimal(11, 2)
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test_basic")

    def tearDown(self):
        self.connection.close()

    def test_basic(self):
        cur = self.connection.cursor()
        cur.execute("SELECT * FROM test_basic")
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 20, 0, None),
            ('B', 409, 2147483647, 2147483647, 31, 0, None),
            ('C', 409, 2147483647, 2147483647, 31, 0, None),
            ('I', 497, 4, 4, 10, 0, None),
            ('D1', 485, 513, 513, 2, 1, None),
            ('D2', 485, 2818, 2818, 11, 2, None),
        ])
        self.assertEqual(cur.fetchall(), [])

        cur.execute("""
            INSERT INTO test_basic (s, b, c, i, d1, d2) VALUES
                ('abcdefghijklmnopq', 'AAAAA', 'aaaaa', 1, 1.1, 123456789.12),
                ('S2', 'BBBBB', 'bbbbb', 2, 1.2, 2),
                ('S3', 'CCCCC', 'ccccc', 3, null, null)
        """)

        # select without clob
        cur.execute("SELECT s, i, d1, d2 FROM test_basic")
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 20, 0, None),
            ('I', 497, 4, 4, 10, 0, None),
            ('D1', 485, 513, 513, 2, 1, None),
            ('D2', 485, 2818, 2818, 11, 2, None),
        ])
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
            ('S2', 2, decimal.Decimal('1.2'), decimal.Decimal('2')),
            ('S3', 3, None, None)
        ])

        # select with clob
        cur.execute("SELECT * FROM test_basic")
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 20, 0, None),
            ('B', 409, 2147483647, 2147483647, 31, 0, None),
            ('C', 409, 2147483647, 2147483647, 31, 0, None),
            ('I', 497, 4, 4, 10, 0, None),
            ('D1', 485, 513, 513, 2, 1, None),
            ('D2', 485, 2818, 2818, 11, 2, None),
        ])
        #self.assertEqual(cur.fetchall(), [
        #    ('abcdefghijklmnopq', 'AAAAA', 'aaaaa', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
        #    ('S2', 'BBBBB', 'bbbbb', 2, decimal.Decimal('1.2'), decimal.Decimal('2')),
        #    ('S3', 'CCCCC', 'ccccc', 3, None, None),
        #])

        with self.assertRaises(NotImplementedError):
            cur.execute(
                "SELECT * FROM test_basic where s=?",
                ["abcdefghijklmnopq"]
            )

    def test_error(self):
        cur = self.connection.cursor()
        with self.assertRaises(drda.OperationalError):
            cur.execute("invalid query")


class TestDataType(unittest.TestCase):
    def setUp(self):
        self.connection = drda.connect(
            host=HOST,
            database=DATABASE,
            port=PORT
        )

    def test_datetime(self):
        cur = self.connection.cursor()
        try:
            cur.execute("""
                CREATE TABLE test_datetime (
                    d date,
                    t time,
                    dt timestamp
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test_datetime")
        cur.execute("""
            INSERT INTO test_datetime (d, t, dt) VALUES
                ('2019-04-30', '12:34:56', '2019-04-30 12:34:56.123456789')
        """)
        cur.execute("SELECT * FROM test_datetime")
        self.assertEqual(cur.fetchall(), [(
            datetime.date(2019, 4, 30),
            datetime.time(12, 34, 56),
            datetime.datetime(2019, 4, 30, 12, 34, 56, 123456)
        )])

    def test_not_null(self):
        cur = self.connection.cursor()

        # VARCHAR
        try:
            cur.execute("""
                CREATE TABLE test_varchar_not_null (
                    s varchar(20) not null
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test_varchar_not_null")
        cur.execute("""
            INSERT INTO test_varchar_not_null (s) VALUES
            ('abcdefghijklmnopq'), ('B'), ('C')
        """)
        cur.execute("SELECT * FROM test_varchar_not_null")
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', ), ('B', ), ('C', )
        ])

        # LONG VARCHAR
        try:
            cur.execute("""
                CREATE TABLE test_long_varchar_not_null (
                    s long varchar not null
                )
            """)
        except drda.OperationalError as e:
            pass
        cur.execute("DELETE FROM test_long_varchar_not_null")
        cur.execute("""
            INSERT INTO test_long_varchar_not_null (s) VALUES
            ('abcdefghijklmnopq')
        """)
        cur.execute("SELECT * FROM test_long_varchar_not_null")
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', )
        ])

        # INTEGER8
        try:
            cur.execute("""
                CREATE TABLE test_bigint_not_null (
                    bi bigint not null
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test_bigint_not_null")
        cur.execute("""
            INSERT INTO test_bigint_not_null (bi) VALUES (-1)
        """)
        cur.execute("SELECT * FROM test_bigint_not_null")
        self.assertEqual(cur.fetchall(), [(-1, )])

        # FLOAT8
        try:
            cur.execute("""
                CREATE TABLE test_float8_not_null (
                    d double not null
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test_float8_not_null")
        cur.execute("""
            INSERT INTO test_float8_not_null (d) VALUES (-1)
        """)
        cur.execute("SELECT * FROM test_float8_not_null")
        self.assertEqual(cur.fetchall(), [(-1.0, )])

    def test_bool(self):
        cur = self.connection.cursor()
        try:
            cur.execute("""
                CREATE TABLE test_bool (
                    b1 boolean,
                    b2 boolean not null,
                    b3 boolean
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test_bool")
        cur.execute("""
            INSERT INTO test_bool (b1, b2, b3) VALUES (TRUE, FALSE, NULL)
        """)
        cur.execute("SELECT * FROM test_bool")
        self.assertEqual(cur.fetchall(), [(True, False, None)])

    def test_double(self):
        cur = self.connection.cursor()
        try:
            cur.execute("""
                CREATE TABLE test_double (
                    bi bigint,
                    si smallint,
                    r real,
                    d double
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test_double")
        cur.execute("""
            INSERT INTO test_double (bi, si, r, d) VALUES
                (-1, -1, -1, -1)
        """)
        cur.execute("SELECT * FROM test_double")
        self.assertEqual(cur.fetchall(), [(-1, -1, -1.0, -1.0)])

    @unittest.skip
    def test_issue18(self):
        cur = self.connection.cursor()
        try:
            cur.execute("DROP TABLE test_issue18")
        except drda.OperationalError:
            pass
        cur.execute("""
            CREATE TABLE test_issue18 (
                s varchar(4096)
            )
        """)
        s = "x" * 4096
        count = 20
        for _ in range(count):
            cur.execute(f"INSERT INTO test_issue18(s) values('{s}')")
        cur.execute("SELECT * FROM test_issue18")
        self.assertEqual(
            list(cur.fetchall()),
            [(s,) for _ in range(count)],
        )

    def tearDown(self):
        self.connection.close()


if __name__ == "__main__":
    import unittest
    unittest.main()
