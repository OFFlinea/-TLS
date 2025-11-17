#!/usr/bin/env python3

import argparse
import socket
import sys
import select
import os
import time
import ssl
import threading

BUFFER = 4096


class KeyLogger:
    def __init__(self, keylog_file):
        self.keylog_file = keylog_file
        open(self.keylog_file, 'w').close()
    
    def __call__(self, ssl_sock, secret_name, secret_value):
        """Callback для логирования ключей в формате Wireshark"""
        if secret_name in ('CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0'):
            try:
                if hasattr(ssl_sock, 'client_random'):
                    client_random = ssl_sock.client_random().hex()
                else:
                    client_random = '0' * 64
                
                if client_random and len(client_random) == 64:
                    line = f"CLIENT_RANDOM {client_random} {secret_value.hex()}\n"
                    with open(self.keylog_file, 'a') as f:
                        f.write(line)
                    print(f"Logged TLS key for Wireshark")
            except Exception as e:
                print(f"Error logging key: {e}")


def setup_tls_context_server(certfile, keyfile):
    """Настройка TLS контекста для сервера"""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    
    if 'SSLKEYLOGFILE' in os.environ:
        keylog_file = os.environ['SSLKEYLOGFILE']
        key_logger = KeyLogger(keylog_file)
        context.keylog_cb = key_logger
        print(f"SSL key logging enabled: {keylog_file}")
    
    return context


def setup_tls_context_client(ca_file=None, no_verify=False):
    """Настройка TLS контекста для клиента"""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    if ca_file:
        context.load_verify_locations(ca_file)
    
    if no_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    if 'SSLKEYLOGFILE' in os.environ:
        keylog_file = os.environ['SSLKEYLOGFILE']
        key_logger = KeyLogger(keylog_file)
        context.keylog_cb = key_logger
        print(f"SSL key logging enabled: {keylog_file}")
    
    return context


def tcp_server(host, port, certfile=None, keyfile=None):
    context = None
    if certfile and keyfile:
        context = setup_tls_context_server(certfile, keyfile)
        print(f"TLS enabled with cert: {certfile}, key: {keyfile}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv:
        serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        serv.bind((host, port))
        serv.listen(1)
        mode = "TLS" if context else "plain TCP"
        print(f"{mode} server listening on {host}:{port}")

        while True:
            try:
                conn, addr = serv.accept()
            except KeyboardInterrupt:
                print('\nShutting down server')
                return
            
            if context:
                try:
                    conn = context.wrap_socket(conn, server_side=True)
                    print(f"TLS handshake completed with {addr}")
                except ssl.SSLError as e:
                    print(f"TLS handshake failed: {e}")
                    conn.close()
                    continue

            with conn:
                conn.setblocking(False)
                print(f"Accepted connection from {addr}")
                while True:
                    rlist = [conn, sys.stdin]
                    try:
                        ready_r, _, _ = select.select(rlist, [], [])
                    except ValueError:
                        break
                    for r in ready_r:
                        if r is conn:
                            try:
                                data = conn.recv(BUFFER)
                            except ssl.SSLWantReadError:
                                continue
                            except ssl.SSLZeroReturnError:
                                data = b''
                            except ConnectionResetError:
                                print("Client disconnected (reset)")
                                data = b''
                            except ssl.SSLError as e:
                                print(f"SSL error: {e}")
                                data = b''
                            
                            if not data:
                                print("Client disconnected")
                                break
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                        elif r is sys.stdin:
                            line = sys.stdin.buffer.readline()
                            if not line:
                                print("EOF on stdin, closing connection to client")
                                try:
                                    conn.shutdown(socket.SHUT_WR)
                                except (OSError, ssl.SSLError):
                                    pass
                                conn.close()
                                break
                            try:
                                conn.sendall(line)
                            except (BrokenPipeError, ssl.SSLError) as e:
                                print(f"Cannot send: {e}")
                                break
                    else:
                        continue
                    break
                print("Connection loop ended, server ready for next client")


def tcp_client(host, port, send_file=None, tls=False, ca_file=None, no_verify=False):
    context = None
    if tls:
        context = setup_tls_context_client(ca_file, no_verify)
        print(f"TLS enabled (verify: {not no_verify})")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if context:
            s = context.wrap_socket(s, server_hostname=host)
            print(f"Connecting with TLS to {host}:{port}")
        else:
            print(f"Connecting with plain TCP to {host}:{port}")
            
        s.connect((host, port))
        s.setblocking(False)

        if send_file:
            filesize = os.path.getsize(send_file)
            print(f"Sending file {send_file} ({filesize} bytes) ...")
            with open(send_file, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER)
                    if not chunk:
                        break
                    s.sendall(chunk)
            print("File sent; entering interactive mode")

        while True:
            rlist = [s, sys.stdin]
            try:
                ready_r, _, _ = select.select(rlist, [], [])
            except KeyboardInterrupt:
                print('\nInterrupted, closing')
                return
            for r in ready_r:
                if r is s:
                    try:
                        data = s.recv(BUFFER)
                    except ssl.SSLWantReadError:
                        continue
                    except ssl.SSLZeroReturnError:
                        data = b''
                    except ConnectionResetError:
                        print("Server closed connection")
                        return
                    except ssl.SSLError as e:
                        print(f"SSL error: {e}")
                        return
                    
                    if not data:
                        print("Server closed connection")
                        return
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                elif r is sys.stdin:
                    line = sys.stdin.buffer.readline()
                    if not line:
                        print("EOF on stdin, closing")
                        try:
                            s.shutdown(socket.SHUT_WR)
                        except (OSError, ssl.SSLError):
                            pass
                        return
                    try:
                        s.sendall(line)
                    except (BrokenPipeError, ssl.SSLError) as e:
                        print(f"Cannot send: {e}")
                        return


def udp_server(host, port):
    last_addr = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((host, port))
        s.setblocking(False)
        print(f"UDP server listening on {host}:{port}")
        while True:
            rlist = [s, sys.stdin]
            try:
                ready_r, _, _ = select.select(rlist, [], [])
            except KeyboardInterrupt:
                print('\nShutting down UDP server')
                return
            for r in ready_r:
                if r is s:
                    data, addr = s.recvfrom(65535)
                    last_addr = addr
                    print(f"From {addr}:", end=' ')
                    try:
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                    except Exception:
                        print(repr(data))
                elif r is sys.stdin:
                    if last_addr is None:
                        print("No client seen yet; cannot send")
                        _ = sys.stdin.readline()
                    else:
                        line = sys.stdin.buffer.readline()
                        if not line:
                            print("EOF on stdin, stopping")
                            return
                        s.sendto(line, last_addr)


def udp_client(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        server_addr = (host, port)
        print(f"UDP client ready to send to {host}:{port}")
        while True:
            rlist = [s, sys.stdin]
            try:
                ready_r, _, _ = select.select(rlist, [], [])
            except KeyboardInterrupt:
                print('\nInterrupted')
                return
            for r in ready_r:
                if r is s:
                    try:
                        data, addr = s.recvfrom(65535)
                    except BlockingIOError:
                        continue
                    if not data:
                        continue
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                elif r is sys.stdin:
                    line = sys.stdin.buffer.readline()
                    if not line:
                        print("EOF on stdin, exiting")
                        return
                    s.sendto(line, server_addr)


def main():
    parser = argparse.ArgumentParser(description='TCP/UDP client/server utility')
    sub = parser.add_subparsers(dest='mode', required=True)

    p = sub.add_parser('tcp-server')
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=12345)
    p.add_argument('--cert', help='Path to certificate file for TLS')
    p.add_argument('--key', help='Path to private key file for TLS')

    p = sub.add_parser('tcp-client')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=12345)
    p.add_argument('--send-file', help='Path to file to send immediately after connect (for large-transfer test)')
    p.add_argument('--tls', action='store_true', help='Enable TLS')
    p.add_argument('--ca-file', help='Path to CA certificate for verifying the server')
    p.add_argument('--no-verify', action='store_true', help='Disable certificate verification')

    p = sub.add_parser('udp-server')
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=12345)

    p = sub.add_parser('udp-client')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=12345)

    args = parser.parse_args()

    if args.mode == 'tcp-server':
        tcp_server(args.host, args.port, certfile=args.cert, keyfile=args.key)
    elif args.mode == 'tcp-client':
        tcp_client(args.host, args.port, send_file=args.send_file, 
                  tls=args.tls, ca_file=args.ca_file, no_verify=args.no_verify)
    elif args.mode == 'udp-server':
        udp_server(args.host, args.port)
    elif args.mode == 'udp-client':
        udp_client(args.host, args.port)


if __name__ == '__main__':
    main()
