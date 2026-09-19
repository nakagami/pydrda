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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from drda.connection import Connection


def _is_query(query: str) -> bool:
    s = query.strip()
    while True:
        if s.startswith('/*'):
            end = s.find('*/')
            if end != -1:
                s = s[end + 2:].strip()
                continue
        elif s.startswith('--'):
            end = s.find('\n')
            if end != -1:
                s = s[end + 1:].strip()
                continue
            else:
                s = ''
        break
    s = s.lstrip('(').strip()
    first_word = s.split()[0].upper() if s.split() else ''
    return first_word in ('SELECT', 'WITH', 'VALUES')


class Cursor:
    def __init__(self, connection: 'Connection | None') -> None:
        self.connection: 'Connection | None' = connection
        self.description: list[tuple] = []
        self._rows: Any = []
        self._rowcount: int = -1
        self.arraysize: int = 1
        self.query: str | None = None

    def __enter__(self) -> 'Cursor':
        return self

    def __exit__(self, exc: Any, value: Any, traceback: Any) -> None:
        self.close()

    def callproc(self, procname: str, args: Sequence[Any] = ()) -> Any:
        from drda import NotSupportedError
        raise NotSupportedError()

    def nextset(self, *args: Any, **kwargs: Any) -> None:
        from drda import NotSupportedError
        raise NotSupportedError()

    def setinputsizes(self, sizes: Any) -> None:
        pass

    def setoutputsize(self, size: Any, column: Any | None = None) -> None:
        pass

    def execute(self, query: str, args: Sequence[Any] | None = None) -> None:
        self.query = query
        if _is_query(query):
            self._rows, self.description = self.connection._query(self.query, args)
        else:
            self.connection._execute(self.query, args)

    def executemany(self, query: str, seq_of_params: Sequence[Sequence[Any]]) -> None:
        rowcount = 0
        for params in seq_of_params:
            self.execute(query, params)
            rowcount += self._rowcount
        self._rowcount = rowcount

    def fetchone(self) -> tuple[Any, ...] | None:
        from drda import OperationalError
        if not self.connection or not self.connection.is_connect():
            raise OperationalError(u"08003:Lost connection")
        if len(self._rows):
            return self._rows.popleft()
        return None

    def fetchmany(self, size: int | None = None) -> list[tuple[Any, ...]]:
        if size is None:
            size = self.arraysize
        rs = []
        for i in range(size):
            r = self.fetchone()
            if not r:
                break
            rs.append(r)
        return rs

    def fetchall(self) -> list[tuple[Any, ...]]:
        r = list(self._rows)
        self._rows.clear()
        return r

    def close(self) -> None:
        self.connection = None

    @property
    def rowcount(self) -> int:
        return self._rowcount

    @property
    def closed(self) -> bool:
        return self.connection is None or not self.connection.is_connect()

    def __iter__(self) -> 'Cursor':
        return self

    def __next__(self) -> tuple[Any, ...]:
        r = self.fetchone()
        if not r:
            raise StopIteration()
        return r


class DictCursor(Cursor):
    def _row_to_dict(self, row: tuple[Any, ...] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return {d[0]: val for d, val in zip(self.description, row)}

    def fetchone(self) -> dict[str, Any] | None:
        row = super().fetchone()
        return self._row_to_dict(row)

    def fetchall(self) -> list[dict[str, Any]]:
        rows = super().fetchall()
        return [self._row_to_dict(r) for r in rows]
