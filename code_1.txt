#!/usr/bin/env python3
"""
ssh_banner_test.py - Test server response to normal and malformed SSH client version strings.
Safe for lab use: it only sends banners, does not complete SSH key exchange.
"""

import socket, sys

# Test cases: normal + malformed banners
banners = [
    "SSH-2.0-ValidClient_1.0\r\n",             # valid
    "SSL-2.0-WrongPrefix\r\n",                 # wrong prefix
    "SSH-9.9-InvalidProto\r\n",                # invalid protocol version
    "SSH-2.0-BadChars_\x00\xffTest\r\n",       # illegal characters
    "SSH-2.0-NoCRLF",                          # missing CRLF
    "SSH-2.0-" + "A"*300 + "\r\n",             # oversized string
]

def test_banner(host, port, banner, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        # receive server banner
        server_banner = s.recv(512).decode(errors="replace").strip()
        print(f"[SERVER] {server_banner}")

        # send our test banner
        print(f"[CLIENT] {repr(banner)}")
        s.sendall(banner.encode(errors="replace"))

        # see if server responds with more data or closes
        try:
            resp = s.recv(512)
            if resp:
                print(f"[RESULT] Server responded: {resp!r}")
            else:
                print("[RESULT] Server closed connection (EOF).")
        except socket.timeout:
            print("[RESULT] No immediate response (timeout).")
        except Exception as e:
            print(f"[RESULT] Error: {e}")

        s.close()
    except Exception as e:
        print(f"[ERROR] Could not connect: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host, port = sys.argv[1], int(sys.argv[2])

    for b in banners:
        print("="*60)
        test_banner(host, port, b)
