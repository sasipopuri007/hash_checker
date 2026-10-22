"""
Tests for TCP protocol framing, length prefixes, recv_exact, and filename sanitization.
"""

import socket
import threading
import pytest

import protocol


def test_sanitize_filename_valid():
    """Sanitize filename should extract plain base filenames."""
    assert protocol.sanitize_filename("report.pdf") == "report.pdf"
    assert protocol.sanitize_filename("nested/dir/report.pdf") == "report.pdf"
    assert protocol.sanitize_filename("C:\\Windows\\System32\\calc.exe") == "calc.exe"
    assert protocol.sanitize_filename("../../../etc/passwd") == "passwd"
    assert protocol.sanitize_filename("  my document.docx  ") == "my document.docx"


def test_sanitize_filename_unsafe():
    """Sanitize filename must reject invalid, empty, or traversal-only names."""
    with pytest.raises(protocol.ProtocolError):
        protocol.sanitize_filename("")

    with pytest.raises(protocol.ProtocolError):
        protocol.sanitize_filename("..")

    with pytest.raises(protocol.ProtocolError):
        protocol.sanitize_filename(".")

    with pytest.raises(protocol.ProtocolError):
        protocol.sanitize_filename("   ")


def test_recv_exact_and_framing():
    """Test sending and receiving length-prefixed frames across socket pair."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    received_frames = []

    def server_thread():
        client, _ = server_sock.accept()
        try:
            f1 = protocol.recv_frame(client)
            f2 = protocol.recv_frame(client)
            received_frames.extend([f1, f2])
        finally:
            client.close()
            server_sock.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    try:
        protocol.send_frame(client_sock, b"Hello World")
        protocol.send_frame(client_sock, b"A" * 1000)
    finally:
        client_sock.close()

    t.join(timeout=3.0)
    assert received_frames[0] == b"Hello World"
    assert received_frames[1] == b"A" * 1000


def test_recv_exact_fragmentation():
    """Test recv_exact receives full payload even when sender fragments data byte-by-byte."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    payload = b"Fragmented-TCP-Stream-Data"
    result = []

    def server_thread():
        client, _ = server_sock.accept()
        try:
            data = protocol.recv_exact(client, len(payload), buffer_size=4)
            result.append(data)
        finally:
            client.close()
            server_sock.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    try:
        # Send byte by byte with tiny sleeps to force fragmentation
        for b in payload:
            client_sock.sendall(bytes([b]))
    finally:
        client_sock.close()

    t.join(timeout=3.0)
    assert result[0] == payload


def test_recv_exact_premature_eof():
    """recv_exact must raise IncompleteReadError if socket is closed before expected bytes."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    def server_thread():
        client, _ = server_sock.accept()
        try:
            client.sendall(b"12345")  # only sends 5 bytes
        finally:
            client.close()
            server_sock.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    try:
        with pytest.raises(protocol.IncompleteReadError) as exc_info:
            protocol.recv_exact(client_sock, 100)  # expects 100 bytes
        assert exc_info.value.expected == 100
        assert exc_info.value.received == 5
    finally:
        client_sock.close()
    t.join(timeout=3.0)
