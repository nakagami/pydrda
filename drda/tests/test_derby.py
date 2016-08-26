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

    def tearDown(self):
        self.connection.close()

    def test_derby(self):
        cur = self.connection.cursor()
        cur.execute("""
            CREATE TABLE test (
                s VARCHAR(20),
                i int,
                d1 decimal(2, 1),
                d2 decimal(11, 2)
            )
        """)
        cur.execute("""
            INSERT INTO test (s, i, d1, d2) VALUES
                ('abcdefghijklmnopq', 1, 1.1, 123456789.12),
                ('B', 2, 1.2, 2),
                ('C', 3, null, null)
        """)
        cur.execute("SELECT * FROM test")

