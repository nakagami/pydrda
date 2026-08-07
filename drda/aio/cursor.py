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
from drda.cursor import Cursor


class AsyncCursor(Cursor):
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc, value, traceback):
        await self.close()

    async def execute(self, query, args=[]):
        self.query = query
        if query.strip().split()[0].upper() == 'SELECT':
            self._rows, self.description = await self.connection._query(self.query, args)
        else:
            await self.connection._execute(self.query, args)

    async def executemany(self, query, seq_of_params):
        for params in seq_of_params:
            await self.execute(query, params)

    async def fetchone(self):
        from drda import OperationalError
        if not self.connection or not self.connection.is_connect():
            raise OperationalError(u"08003:Lost connection")
        if len(self._rows):
            return self._rows.popleft()
        return None

    async def fetchmany(self, size=1):
        rs = []
        for i in range(size):
            r = await self.fetchone()
            if not r:
                break
            rs.append(r)
        return rs

    async def fetchall(self):
        r = list(self._rows)
        self._rows.clear()
        return r

    async def close(self):
        self.connection = None

    def __aiter__(self):
        return self

    async def __anext__(self):
        r = await self.fetchone()
        if not r:
            raise StopAsyncIteration()
        return r
