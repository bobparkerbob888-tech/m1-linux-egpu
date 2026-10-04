#!/usr/bin/env python3
"""Fixed authenticated relay or one-connection private-loopback forwarder."""
import argparse, os, socket, sys
import fixed_prl_relay as R
from network import drop_privileges

def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['relay', 'forward'])
    p.add_argument('--parent', required=True, type=int)
    p.add_argument('--credentials-fd', type=int)
    p.add_argument('--ready-fd', type=int)
    p.add_argument('--listener-fd', type=int)
    a = p.parse_args()
    if a.mode == 'relay':
        if a.credentials_fd is None or a.ready_fd is None: raise ValueError()
        credentials = R.credentials_from_fd(a.credentials_fd)
        os.close(a.credentials_fd)
        drop_privileges(a.parent)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote:
            remote.settimeout(R.HANDSHAKE_TIMEOUT)
            remote.connect(R.PROXY)
            R.negotiate(remote, credentials)  # Credentials mandatory; no method0 fallback.
            del credentials
            os.write(a.ready_fd, b'R')
            os.close(a.ready_fd)
            R.pump(remote)
    else:
        if a.listener_fd is None: raise ValueError()
        drop_privileges(a.parent)
        with socket.socket(fileno=a.listener_fd) as listener:
            listener.settimeout(60)
            with listener.accept()[0] as client:
                listener.close()  # One TLS stream per admitted attempt, no reconnect loop.
                R.pump(client)

if __name__ == '__main__':
    try: main()
    except BaseException:
        print('Fixed native PRL stream stopped', file=sys.stderr)
        sys.exit(1)
