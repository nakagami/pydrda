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
"""Tests for db2"""
import unittest
import os
import decimal
import datetime
import decimal
import drda

HOST = os.environ.get("DB2_HOST", "localhost")
DATABASE = os.environ.get("DB2_DATABASE", "testdb")
USER = os.environ.get("DB2_USER", "db2inst1")
PASSWORD = os.environ.get("DB2_PASSWORD", "password")
PORT = int(os.environ.get("DB2_PORT", 50000))
SSL_CA_CERTS = os.environ.get("DB2_SSL_CA_CERTS")

class TestBasic(unittest.TestCase):

    def setUp(self):
        self.connection = drda.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD,
            port=PORT,
            use_ssl=bool(SSL_CA_CERTS),
            ssl_ca_certs=SSL_CA_CERTS,
        )
        cur = self.connection.cursor()
        try:
            cur.execute("DROP TABLE test_basic")
        except drda.OperationalError:
            pass
        cur.execute("""
            CREATE TABLE test_basic (
                s varchar(20),
                i int,
                d1 decimal(2, 1),
                d2 decimal(11, 2)
            )
            """)
        self.connection.commit()

    def tearDown(self):
        self.connection.close()

    def test_basic(self):
        cur = self.connection.cursor()
        cur.execute("SELECT * FROM test_basic")
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 0, 0, None),
            ('I', 497, 4, 4, 0, 0, None),
            ('D1', 485, 0, 0, 2, 1, None),
            ('D2', 485, 0, 0, 11, 2, None)
        ])
        self.assertEqual(cur.fetchall(), [])

        cur.execute("""
            INSERT INTO test_basic (s, i, d1, d2) VALUES
                ('abcdefghijklmnopq', 1, 1.1, 123456789.12),
                ('B', 2, 1.2, -2),
                ('C', 3, null, null)
        """)
        cur.execute("SELECT * FROM test_basic")
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 0, 0, None),
            ('I', 497, 4, 4, 0, 0, None),
            ('D1', 485, 0, 0, 2, 1, None),
            ('D2', 485, 0, 0, 11, 2, None)
        ])
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
            ('B', 2, decimal.Decimal('1.2'), decimal.Decimal('-2.00')),
            ('C', 3, None, None)
        ])

        cur.execute(
            "SELECT * FROM test_basic where s=?",
            ["abcdefghijklmnopq"]
        )
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 0, 0, None),
            ('I', 497, 4, 4, 0, 0, None),
            ('D1', 485, 0, 0, 2, 1, None),
            ('D2', 485, 0, 0, 11, 2, None)
        ])
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
        ])

        cur.execute(
            "SELECT * FROM test_basic where s=? and i=?",
            ["abcdefghijklmnopq", 1]
        )
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
        ])

        cur.execute(
            "SELECT * FROM test_basic where i=? and d1=? and d2=?",
            [1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')]
        )
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
        ])

        cur.execute("UPDATE test_basic SET s='abc' WHERE i=?", [1])
        cur.execute(
            "SELECT * FROM test_basic where i=?",
            [1]
        )
        self.assertEqual(cur.fetchall(), [
            ('abc', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
        ])

    def test_error(self):
        cur = self.connection.cursor()
        with self.assertRaises(drda.OperationalError):
            cur.execute("invalid query"),

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
            cur.execute("INSERT INTO test_issue18(s) values(?)", [s])
        cur.execute("SELECT * FROM test_issue18")
        results = list(cur.fetchall())
        for r in results:
            self.assertEqual(r, (s,))
        self.assertEqual(len(results), count)


class TestDataType(unittest.TestCase):
    def setUp(self):
        self.connection = drda.connect(
            host=HOST,
            database=DATABASE,
            user=USER,
            password=PASSWORD,
            port=PORT,
            use_ssl=bool(SSL_CA_CERTS),
            ssl_ca_certs=SSL_CA_CERTS,
        )

    def test_datetime(self):
        cur = self.connection.cursor()
        try:
            cur.execute("DROP TABLE test_datetime")
        except drda.OperationalError:
            pass
        cur.execute("""
            CREATE TABLE test_datetime (
                d date,
                t time,
                dt timestamp
            )
        """)
        cur.execute("""
            INSERT INTO test_datetime (d, t, dt) VALUES (?, ?, ?)""", [
            datetime.date(2019, 4, 30),
            datetime.time(12, 34, 56),
            datetime.datetime(2019, 4, 30, 12, 34, 56, 123456)
        ])
        cur.execute("SELECT * FROM test_datetime")
        self.assertEqual(cur.fetchall(), [(
            datetime.date(2019, 4, 30),
            datetime.time(12, 34, 56),
            datetime.datetime(2019, 4, 30, 12, 34, 56, 123456)
        )])

        cur.execute("SELECT * FROM test_datetime where d=? and t=? and dt=?", [
            datetime.date(2019, 4, 30),
            datetime.time(12, 34, 56),
            datetime.datetime(2019, 4, 30, 12, 34, 56, 123456)
        ])
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
                (-2, -3, -4, -5)
        """)
        cur.execute("SELECT * FROM test_double")
        self.assertEqual(cur.fetchall(), [(-2, -3, -4.0, -5.0)])

        cur.execute(
            "SELECT * FROM test_double where bi=? and si=? and r=? and d=?",
            [-2, -3, -4.0, -5.0]
        )
        self.assertEqual(cur.fetchall(), [(-2, -3, -4.0, -5.0)])


    def test_string(self):
        cur = self.connection.cursor()
        try:
            cur.execute("""
                CREATE TABLE test_string (
                    a character(20),
                    b varchar(20),
                    c clob(20),
                    d graphic(20),
                    e vargraphic(20)
                )
            """)
        except drda.OperationalError:
            pass

    def test_issue15(self):
        cur = self.connection.cursor()
        try:
            cur.execute("DROP TABLE test_issue15")
        except drda.OperationalError:
            pass
        cur.execute("""
            CREATE TABLE test_issue15 (
                id int,
                s1 varchar(30),
                s2 varchar(30),
                d date
            )
        """)
        row = (121,'hello', 'world again', datetime.date.fromisoformat('2023-11-08'))
        cur.execute("INSERT INTO test_issue15(id,s1,s2,d) values(?,?,?,?)", row)
        cur.execute("SELECT * FROM test_issue15")
        self.assertEqual(cur.fetchall(), [row])

    def tearDown(self):
        self.connection.close()


class TestSecmec(unittest.TestCase):
    def test_secmec9(self):
        from drda import secmec9
        a = secmec9.get_private()
        b = secmec9.get_private()
        A = secmec9.calc_public(a)
        B = secmec9.calc_public(b)
        self.assertEqual(
            secmec9.calc_session_key(A, b),
            secmec9.calc_session_key(B, a)
        )


if __name__ == "__main__":
    import unittest
    unittest.main()
