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
import socket
import ssl
import asyncio


class AsyncSocketStream:
    "asyncio based asynchronous socket stream"
    def __init__(self, host, port, timeout=None, use_ssl=False, ssl_client_cert_path=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_ssl = use_ssl
        self.ssl_client_cert_path = ssl_client_cert_path
        self._reader = None
        self._writer = None

    async def connect(self):
        ssl_context = None
        server_hostname = None
        if self.use_ssl:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if self.ssl_client_cert_path:
                # Load the server's CA certificate to verify the server's identity.
                ssl_context.load_verify_locations(self.ssl_client_cert_path)
            # server_hostname enables SNI and hostname verification.
            server_hostname = self.host

        coro = asyncio.open_connection(
            self.host, self.port, ssl=ssl_context, server_hostname=server_hostname,
        )
        if self.timeout is not None:
            self._reader, self._writer = await asyncio.wait_for(coro, self.timeout)
        else:
            self._reader, self._writer = await coro

        sock = self._writer.get_extra_info('socket')
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    async def recv(self, nbytes):
        "Receive up to nbytes (may return less if the peer closed the connection)"
        received = bytearray()
        while len(received) < nbytes:
            chunk = await self._reader.read(nbytes - len(received))
            if not chunk:
                break
            received += chunk
        return bytes(received)

    async def send(self, b):
        self._writer.write(b)
        await self._writer.drain()

    async def close(self):
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._reader = None
            self._writer = None

    def __bool__(self):
        return self._writer is not None and not self._writer.is_closing()
