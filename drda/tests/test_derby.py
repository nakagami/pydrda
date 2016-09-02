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
import unittest
import io
import decimal
import datetime
import decimal
import drda


class TestDerby(unittest.TestCase):
    host = 'localhost'
    database = 'testdb;create=true'
    port = 1527

    def setUp(self):
        self.connection = drda.connect(
            host=self.host,
            database=self.database,
            port=self.port,
        )
        cur = self.connection.cursor()
        try:
            cur.execute("""
                CREATE TABLE test (
                    s VARCHAR(20),
                    i int,
                    d1 decimal(2, 1),
                    d2 decimal(11, 2)
                )
            """)
        except drda.OperationalError:
            pass
        cur.execute("DELETE FROM test")

    def tearDown(self):
        self.connection.close()

    def test_basic(self):
        cur = self.connection.cursor()
        cur.execute("""
            INSERT INTO test (s, i, d1, d2) VALUES
                ('abcdefghijklmnopq', 1, 1.1, 123456789.12),
                ('B', 2, 1.2, 2),
                ('C', 3, null, null)
        """)
        cur.execute("SELECT * FROM test")
        self.assertEqual(cur.description, [
            ('S', 449, 20, 20, 20, 0, None),
            ('I', 497, 4, 4, 10, 0, None),
            ('D1', 485, 513, 513, 2, 1, None),
            ('D2', 485, 2818, 2818, 11, 2, None)
        ])
        self.assertEqual(cur.fetchall(), [
            ('abcdefghijklmnopq', 1, decimal.Decimal('1.1'), decimal.Decimal('123456789.12')),
            ('B', 2, decimal.Decimal('1.2'), decimal.Decimal('2')),
            ('C', 3, None, None)
        ])

    def test_error(self):
        cur = self.connection.cursor()
        with self.assertRaises(drda.OperationalError):
            cur.execute("invalid query")


if __name__ == "__main__":
    import unittest
    unittest.main()
