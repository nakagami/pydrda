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
from collections.abc import Sequence
from typing import Any
from drda.cursor import Cursor, _is_query


class AsyncCursor(Cursor):
    async def __aenter__(self) -> 'AsyncCursor':
        return self

    async def __aexit__(self, exc: Any, value: Any, traceback: Any) -> None:
        await self.close()

    async def execute(self, query: str, args: Sequence[Any] | None = None) -> None:
        self.query = query
        if _is_query(query):
            self._rows, self.description = await self.connection._query(self.query, args)
        else:
            await self.connection._execute(self.query, args)

    async def executemany(self, query: str, seq_of_params: Sequence[Sequence[Any]]) -> None:
        for params in seq_of_params:
            await self.execute(query, params)

    async def fetchone(self) -> tuple[Any, ...] | None:
        from drda import OperationalError
        if not self.connection or not self.connection.is_connect():
            raise OperationalError(u"08003:Lost connection")
        if len(self._rows):
            return self._rows.popleft()
        return None

    async def fetchmany(self, size: int | None = None) -> list[tuple[Any, ...]]:
        if size is None:
            size = self.arraysize
        rs = []
        for i in range(size):
            r = await self.fetchone()
            if not r:
                break
            rs.append(r)
        return rs

    async def fetchall(self) -> list[tuple[Any, ...]]:
        r = list(self._rows)
        self._rows.clear()
        return r

    async def close(self) -> None:
        self.connection = None

    def __aiter__(self) -> 'AsyncCursor':
        return self

    async def __anext__(self) -> tuple[Any, ...]:
        r = await self.fetchone()
        if not r:
            raise StopAsyncIteration()
        return r


class AsyncDictCursor(AsyncCursor):
    def _row_to_dict(self, row: tuple[Any, ...] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return {d[0]: val for d, val in zip(self.description, row)}

    async def fetchone(self) -> dict[str, Any] | None:
        row = await super().fetchone()
        return self._row_to_dict(row)

    async def fetchall(self) -> list[dict[str, Any]]:
        rows = await super().fetchall()
        return [self._row_to_dict(r) for r in rows]
