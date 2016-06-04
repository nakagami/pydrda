#!/usr/bin/env python3
##############################################################################
#The MIT License (MIT)
#
#Copyright (c) 2016 Hajime Nakagami
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
##############################################################################
import sys
import socket
import binascii

def asc_dump(bindata):
    r = ''
    for c in bindata:
        r += chr(c) if (c >= 32 and c < 128) else '.'
    if r:
        print('\t[' + r + ']')


def recv_from_sock(sock, nbytes):
    n = nbytes
    recieved = b''
    while n:
        bs = sock.recv(n)
        recieved += bs
        n -= len(bs)
    return recieved

def relay_packets(indicator, read_sock, write_sock):
    head = blen + recv_from_sock(read_sock, 6)
    print("%s %s" % (indicator, binascii.b2a_hex(head).decode('ascii')))
    body = recv_from_sock(read_sock, int.from_bytes(head[:2], byteorder='big'))

    rest = read_sock.recv(36635)

    write_sock.send(head)
    write_sock.send(body)
    write_sock.send(rest)

    print("\t%s\n\t%s\n" % (binascii.b2a_hex(body).decode('ascii'), binascii.b2a_hex(rest).decode('ascii')))
    asc_dump(body)
    asc_dump(rest)


def proxy_wire(server_name, server_port, listen_host, listen_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((listen_host, listen_port))
    sock.listen(1)
    client_sock, addr = sock.accept()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((server_name, server_port))

    while True:
        relay_packets('>>', client_sock, server_sock)

        relay_packets('<<', server_sock, client_sock)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage : ' + sys.argv[0] + ' server[:port] [listen_host:]listen_port')
        sys.exit()

    server = sys.argv[1].split(':')
    server_name = server[0]
    if len(server) == 1:
        server_port = 3050
    else:
        server_port = int(server[1])

    listen = sys.argv[2].split(':')
    if len(listen) == 1:
        listen_host = 'localhost'
        listen_port = int(listen[0])
    else:
        listen_host = listen[0]
        listen_port = int(listen[1])

    proxy_wire(server_name, server_port, listen_host, listen_port)
