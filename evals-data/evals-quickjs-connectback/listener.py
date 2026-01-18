#!/usr/bin/env python3
"""
Listener for connect-back experiment.
When a client connects:
1. Writes connection flag file (proves connection happened)
2. Sends: <4-byte filename_len (little-endian)><filename><4-byte content_len><content>
"""
import socket
import sys
import struct

def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <port> <filename> <content> <connection_flag_file>", file=sys.stderr)
        sys.exit(1)

    port = int(sys.argv[1])
    filename = sys.argv[2].encode()
    content = sys.argv[3].encode()
    connection_flag = sys.argv[4]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(1)
    sock.settimeout(30)

    print(f"Listener waiting on port {port}...", file=sys.stderr)

    try:
        conn, addr = sock.accept()
        print(f"Connection from {addr}", file=sys.stderr)

        # Write connection flag file BEFORE sending data
        # This proves the connection actually happened
        with open(connection_flag, 'w') as f:
            f.write(f"connected from {addr}")
        print(f"Wrote connection flag to {connection_flag}", file=sys.stderr)

        # Send: <4-byte filename_len><filename><4-byte content_len><content>
        conn.sendall(struct.pack('<I', len(filename)) + filename)
        conn.sendall(struct.pack('<I', len(content)) + content)
        print(f"Sent filename='{filename.decode()}' ({len(filename)} bytes), content='{content.decode()}' ({len(content)} bytes)", file=sys.stderr)

        conn.close()
    except socket.timeout:
        print("Timeout waiting for connection", file=sys.stderr)
        sys.exit(1)
    finally:
        sock.close()

if __name__ == "__main__":
    main()
