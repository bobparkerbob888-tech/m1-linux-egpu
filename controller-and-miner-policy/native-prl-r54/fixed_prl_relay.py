#!/usr/bin/env python3
"""Fixed PRL SOCKS5 stdio relay. CLI cannot change proxy or destination."""
import argparse
import json
import os
import selectors
import socket
import stat
import sys
import time

PROXY = ('PROVISION_NETWORK_ENDPOINT', 11182)
TARGET = b'prl-hk.kryptex.network'
PORT = 8048
HANDSHAKE_TIMEOUT = 10.0
HALF_CLOSE_TIMEOUT = 30.0
IDLE_TIMEOUT = 300.0
BUFFER_LIMIT = 262144


def credentials_from_fd(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError('Credentials require an owner-only regular file')
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, 8193)
    if len(raw) > 8192:
        raise ValueError('Credentials too large')
    try:
        value = json.loads(raw)
        if set(value) != {'username', 'password'}:
            raise ValueError()
        user, password = value['username'].encode(), value['password'].encode()
        if not 1 <= len(user) <= 255 or not 1 <= len(password) <= 255:
            raise ValueError()
        return user, password
    except (ValueError, TypeError, AttributeError):
        raise ValueError('Invalid credential file') from None


def negotiate(sock, credentials=None):
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT
    def bound():
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('SOCKS handshake deadline')
        sock.settimeout(left)
    def send(data):
        bound()
        sock.sendall(data)
    def take(n):
        data = bytearray()
        while len(data) < n:
            bound()
            part = sock.recv(n - len(data))
            if not part:
                raise ConnectionError('Truncated SOCKS reply')
            data.extend(part)
        return bytes(data)
    method = 2 if credentials else 0
    send(bytes((5, 1, method)))
    if take(2) != bytes((5, method)):
        raise ConnectionError('SOCKS authentication method refused')
    if credentials:
        user, password = credentials
        send(bytes((1, len(user))) + user + bytes((len(password),)) + password)
        if take(2) != b'\x01\x00':
            raise ConnectionError('SOCKS authentication refused')
    # ATYP3 means proxy resolves the domain; never call getaddrinfo(target).
    send(b'\x05\x01\x00\x03' + bytes((len(TARGET),)) + TARGET + PORT.to_bytes(2, 'big'))
    version, reply, reserved, kind = take(4)
    if version != 5 or reply or reserved:
        raise ConnectionError('SOCKS CONNECT refused')
    if kind == 1:
        take(4)
    elif kind == 4:
        take(16)
    elif kind == 3:
        length = take(1)[0]
        if not length:
            raise ConnectionError('Empty SOCKS bound address')
        take(length)
    else:
        raise ConnectionError('Invalid SOCKS bound address')
    take(2)


def pump(sock, input_fd=0, output_fd=1, *, half_close=HALF_CLOSE_TIMEOUT, idle=IDLE_TIMEOUT):
    """Bounded buffers; flush each direction before its EOF/half-close."""
    pending_send, pending_out = bytearray(), bytearray()
    input_open = socket_open = True
    write_shutdown = False
    first_eof = None
    last_progress = time.monotonic()
    old_in, old_out = os.get_blocking(input_fd), os.get_blocking(output_fd)
    os.set_blocking(input_fd, False)
    os.set_blocking(output_fd, False)
    sock.setblocking(False)
    try:
        with selectors.DefaultSelector() as sel:
            while True:
                now = time.monotonic()
                if not socket_open and not input_open and not pending_out and not pending_send:
                    return
                if now - last_progress >= idle or (first_eof is not None and now - first_eof >= half_close):
                    raise TimeoutError('Relay inactivity/half-close deadline')
                if not input_open and not pending_send and not write_shutdown:
                    sock.shutdown(socket.SHUT_WR)
                    write_shutdown = True
                for key in list(sel.get_map().values()):
                    sel.unregister(key.fileobj)
                if input_open and len(pending_send) < BUFFER_LIMIT:
                    sel.register(input_fd, selectors.EVENT_READ, 'input')
                mask = (selectors.EVENT_READ if socket_open and len(pending_out) < BUFFER_LIMIT else 0)
                if pending_send:
                    mask |= selectors.EVENT_WRITE
                if mask:
                    sel.register(sock, mask, 'socket')
                if pending_out:
                    sel.register(output_fd, selectors.EVENT_WRITE, 'output')
                for key, events in sel.select(0.25):
                    if key.data == 'input':
                        data = os.read(input_fd, min(65536, BUFFER_LIMIT-len(pending_send)))
                        if data:
                            pending_send.extend(data)
                        else:
                            input_open = False
                            if first_eof is None:
                                first_eof = time.monotonic()
                    elif key.data == 'output':
                        try:
                            count = os.write(output_fd, pending_out)
                        except BlockingIOError:
                            continue
                        if count <= 0:
                            raise BrokenPipeError('Output closed')
                        del pending_out[:count]
                    else:
                        if events & selectors.EVENT_WRITE:
                            try:
                                count = sock.send(pending_send)
                            except BlockingIOError:
                                count = 0
                            if count:
                                del pending_send[:count]
                        if events & selectors.EVENT_READ:
                            try:
                                data = sock.recv(min(65536, BUFFER_LIMIT-len(pending_out)))
                            except BlockingIOError:
                                continue
                            if data:
                                pending_out.extend(data)
                            else:
                                socket_open = False
                                if first_eof is None:
                                    first_eof = time.monotonic()
                    last_progress = time.monotonic()
    finally:
        os.set_blocking(input_fd, old_in)
        os.set_blocking(output_fd, old_out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--credentials-file')
    group.add_argument('--credentials-fd', type=int)
    args = parser.parse_args()
    credentials = None
    if args.credentials_file:
        fd = os.open(args.credentials_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            credentials = credentials_from_fd(fd)
        finally:
            os.close(fd)
    elif args.credentials_fd is not None:
        credentials = credentials_from_fd(args.credentials_fd)
    # Numeric IPv4 only. No resolver and no alternate destination/fallback.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(HANDSHAKE_TIMEOUT)
        sock.connect(PROXY)
        negotiate(sock, credentials)
        pump(sock)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Do not print exception repr, server data, credentials or stream data.
        print('Fixed PRL relay failed closed', file=sys.stderr)
        sys.exit(1)
