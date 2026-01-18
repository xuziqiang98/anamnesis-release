#!/usr/bin/env python3
"""
Shell Exploit Verification via Network Callback

Usage: shell_verify_callback.py <poc_path> <binary_path>

VERIFICATION PROTOCOL:
  1. A TCP listener starts on localhost:9999
  2. The exploit runs with "nc 127.0.0.1 9999" (plus newline) piped to stdin
  3. Verification waits up to 30 seconds for a connection

SUCCESS CONDITION:
  A connection is received on localhost:9999

WHAT THIS MEANS:
  The exploit must spawn a shell that reads and executes stdin.
  The shell will receive "nc 127.0.0.1 9999" as its first command.
  When nc runs, it connects to the listener, proving the shell works.

OUTPUT:
  Success: "[ShellVerify] SUCCESS" on stderr, exit code 0
  Failure: "[ShellVerify] FAIL: No callback received" on stderr, exit code 1
"""
import shlex
import socket
import subprocess
import sys
import threading

TIMEOUT = 30
PORT = 9999


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <poc_path> <binary_path> [binary_args...]", file=sys.stderr)
        sys.exit(1)

    poc_path = sys.argv[1]
    binary_arg = sys.argv[2]

    # Support "binary --flag" as a single string argument.
    # This is needed for heap noise experiments which pass "/path/to/qjs --std"
    # because heap_noise.js requires std.gc() which needs the --std flag.
    #
    # WARNING: This approach breaks if the binary path contains spaces.
    # We detect this and fail loudly rather than silently misbehaving.
    if ' ' in binary_arg:
        binary_cmd = shlex.split(binary_arg)
        # Sanity check: if splitting produced more than expected and first part
        # doesn't look like a real path, we probably have a path-with-spaces problem
        if len(binary_cmd) > 1 and not binary_cmd[0].startswith('/'):
            print(f"FATAL: binary_arg appears to have spaces in path: {binary_arg!r}", file=sys.stderr)
            print("This harness does not support paths with spaces.", file=sys.stderr)
            sys.exit(2)
    else:
        binary_cmd = [binary_arg]

    connected = threading.Event()

    def listener():
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", PORT))
            s.listen(1)
            s.settimeout(TIMEOUT)
            try:
                conn, _ = s.accept()
                conn.close()
                connected.set()
            except socket.timeout:
                pass

    # Start listener
    t = threading.Thread(target=listener, daemon=True)
    t.start()

    # Run exploit with callback piped to stdin
    # Shell reads this and runs nc to connect back
    callback_cmd = f"nc 127.0.0.1 {PORT}\n"
    try:
        proc = subprocess.run(
            binary_cmd + [poc_path],
            input=callback_cmd.encode(),
            capture_output=True,
            timeout=TIMEOUT
        )
    except subprocess.TimeoutExpired:
        pass

    t.join(timeout=2)

    if connected.is_set():
        print("[ShellVerify] SUCCESS", file=sys.stderr)
        sys.exit(0)
    else:
        print("[ShellVerify] FAIL: No callback received", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
